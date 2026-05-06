"""
OpenSearch 서비스
얼굴 임베딩 벡터 저장 및 유사도 검색 (kNN)
"""

import hashlib
import hmac
import logging
from typing import Optional, List, Tuple
from opensearchpy import OpenSearch
from opensearchpy.helpers import bulk

from app.core.config import get_settings

logger = logging.getLogger(__name__)

# 얼굴 임베딩 인덱스 설정
FACE_INDEX = "face_embeddings"

# T-107: kNN/검색 리소스 상한
# - MAX_KNN_K: search_similar 의 k 를 이 값으로 clamp (DoS 방지)
# - RECLASSIFY_BATCH_SIZE / RECLASSIFY_MAX_TOTAL: reclassify_unmatched 의 페이지네이션 파라미터
#   기존에는 size=200 단건 호출이라 미분류가 200건을 넘으면 이후는 누락됐음
MAX_KNN_K = 100
RECLASSIFY_BATCH_SIZE = 200
RECLASSIFY_MAX_TOTAL = 5000

# T-004e: 마이그레이션 scroll 페이지 사이즈. RECLASSIFY 보다 크게 잡아도 안전 —
# embedding 필드를 안 가져오기 때문에 페이로드가 작음. 596 docs 가정 시 1 페이지로 끝남.
MIGRATE_SCROLL_PAGE_SIZE = 500
MIGRATE_MAX_TOTAL = 100_000


def _resolve_resident_id_from_hit(hit_source: dict) -> Optional[str]:
    """T-004e2: search hit 의 _source 에서 resident_id 를 결정한다.

    dual-read 정책:
      1) `resident_id_hash` 가 있고 hash→rid 역매핑 캐시에 있으면 그걸 사용.
      2) 없으면 옛 평문 `resident_id` 로 fallback.
      3) 둘 다 없거나 비어있으면 None.

    e2 시점엔 OpenSearchService._hash_to_rid 캐시가 비어있어 (1) 은 미스됨.
    → 항상 (2) 평문으로 fallback. 캐시 wiring 은 e4 에서 lifespan + residents
    create/restore 훅으로 채울 예정. e2 에선 dual-write 가 hash 를 채우고,
    migrate_resident_id_to_hash 가 옛 docs 의 hash 를 backfill 한다.
    """
    rid_hash = hit_source.get("resident_id_hash")
    if rid_hash:
        cache = OpenSearchService._hash_to_rid
        if rid_hash in cache:
            return cache[rid_hash]
    rid = hit_source.get("resident_id")
    if rid is not None:
        return rid
    return None


def hash_resident_id(rid: str) -> str:
    """T-004e: HMAC-SHA256(OPENSEARCH_LINK_KEY, rid) 의 hex digest.

    OPENSEARCH_LINK_KEY 는 backend-secret 에서만 노출되므로, OpenSearch dump
    단독 유출 시 vector 와 hash 만 노출돼서 어떤 vector 가 누구 얼굴인지
    식별 불가 (spec §8 / KISA compensating control).

    빈 문자열도 결정적으로 해시됨 — 미분류(resident_id="") 표시는 hash 로도
    동일하게 식별 가능. 키 미설정 시 명시적으로 RuntimeError — 무음 fallback 은
    안전성 약화이므로 즉시 fail-fast.
    """
    settings = get_settings()
    key = settings.OPENSEARCH_LINK_KEY
    if not key:
        raise RuntimeError(
            "OPENSEARCH_LINK_KEY 가 설정되지 않았습니다. "
            "T-004e1 의 SealedSecret 봉인 또는 .env 의 OPENSEARCH_LINK_KEY 를 확인하세요."
        )
    return hmac.new(
        key.encode("utf-8"), rid.encode("utf-8"), hashlib.sha256
    ).hexdigest()


class OpenSearchService:
    """OpenSearch 얼굴 임베딩 저장/검색 서비스"""

    _client: Optional[OpenSearch] = None
    # T-004e2: hash(resident_id_hash) → resident_id 역매핑 캐시.
    # e2 시점엔 비어있고 _resolve_resident_id_from_hit 이 평문 rid 로 fallback.
    # e4 에서 lifespan startup hook 이 residents 테이블을 enumerate 해서 채우게 됨.
    # 신규 resident 가 추가되면 별도 update API 로 한 줄씩 갱신 (예정).
    _hash_to_rid: dict = {}

    @classmethod
    def get_client(cls) -> OpenSearch:
        """싱글톤 클라이언트. T-004: TLS / basic auth 옵션 환경변수 주입."""
        if cls._client is None:
            settings = get_settings()
            client_kwargs: dict = {
                "hosts": [{
                    "host": settings.OPENSEARCH_HOST,
                    "port": settings.OPENSEARCH_PORT,
                }],
                "use_ssl": settings.OPENSEARCH_USE_SSL,
                "verify_certs": settings.OPENSEARCH_VERIFY_CERTS,
            }
            # ssl_show_warn 은 verify_certs=False 일 때만 의미 — 자체 서명 cert 운영
            # 환경에서 매 요청마다 InsecureRequestWarning 이 로그를 가득 채우는 걸 막음.
            if settings.OPENSEARCH_USE_SSL and not settings.OPENSEARCH_VERIFY_CERTS:
                client_kwargs["ssl_show_warn"] = False
            if settings.OPENSEARCH_USE_SSL and settings.OPENSEARCH_CA_CERT_PATH:
                client_kwargs["ca_certs"] = settings.OPENSEARCH_CA_CERT_PATH
            if settings.OPENSEARCH_USER and settings.OPENSEARCH_PASSWORD:
                client_kwargs["http_auth"] = (
                    settings.OPENSEARCH_USER,
                    settings.OPENSEARCH_PASSWORD,
                )

            cls._client = OpenSearch(**client_kwargs)
            scheme = "https" if settings.OPENSEARCH_USE_SSL else "http"
            auth_marker = "auth" if settings.OPENSEARCH_USER else "no-auth"
            verify_marker = "verify" if settings.OPENSEARCH_VERIFY_CERTS else "no-verify"
            logger.info(
                f"OpenSearch connected: {scheme}://{settings.OPENSEARCH_HOST}:{settings.OPENSEARCH_PORT} "
                f"({auth_marker}, {verify_marker})"
            )
        return cls._client

    @classmethod
    def _get_embedding_dim(cls) -> int:
        """FaceService에서 실제 모델의 임베딩 차원을 가져옴"""
        try:
            from app.services.face_recognition import FaceService
            dim = FaceService.get_embedding_dim()
            logger.info(f"Got embedding dimension from FaceService: {dim}")
            return dim
        except Exception as e:
            logger.warning(f"Could not get embedding dim from FaceService: {e}, defaulting to 512")
            return 512

    @classmethod
    def ensure_index(cls):
        """
        face_embeddings 인덱스 생성/재생성
        모델의 실제 임베딩 차원과 인덱스 차원이 다르면 인덱스를 재생성
        """
        client = cls.get_client()
        embedding_dim = cls._get_embedding_dim()

        if client.indices.exists(index=FACE_INDEX):
            # 기존 인덱스의 차원 확인
            try:
                mapping = client.indices.get_mapping(index=FACE_INDEX)
                existing_dim = (
                    mapping[FACE_INDEX]["mappings"]["properties"]["embedding"]["dimension"]
                )
                if existing_dim == embedding_dim:
                    logger.info(f"Index '{FACE_INDEX}' exists with correct dimension {embedding_dim}")
                    return
                else:
                    logger.warning(
                        f"Index dimension mismatch! Index={existing_dim}, Model={embedding_dim}. "
                        f"Recreating index..."
                    )
                    client.indices.delete(index=FACE_INDEX)
                    logger.info(f"Deleted old index '{FACE_INDEX}' (dim={existing_dim})")
            except Exception as e:
                logger.warning(f"Could not check index mapping: {e}. Recreating...")
                try:
                    client.indices.delete(index=FACE_INDEX)
                except Exception:
                    pass

        body = {
            "settings": {
                "index": {
                    "knn": True,
                    "number_of_shards": 1,
                    "number_of_replicas": 0,
                }
            },
            "mappings": {
                "properties": {
                    "resident_id": {"type": "keyword"},
                    # T-004e: HMAC(OPENSEARCH_LINK_KEY, resident_id) hex digest.
                    # e2 에서 신규 인덱싱은 dual-write, 기존 docs 는 admin
                    # migrate-resident-id-hash 엔드포인트가 backfill.
                    "resident_id_hash": {"type": "keyword"},
                    "facility_id": {"type": "keyword"},
                    "photo_id": {"type": "keyword"},
                    "face_id": {"type": "keyword"},
                    "is_reference": {"type": "boolean"},
                    "photo_url": {"type": "keyword"},
                    "embedding": {
                        "type": "knn_vector",
                        "dimension": embedding_dim,
                        "method": {
                            "name": "hnsw",
                            "space_type": "cosinesimil",
                            "engine": "lucene",
                            "parameters": {
                                "ef_construction": 128,
                                "m": 24,
                            },
                        },
                    },
                }
            },
        }

        client.indices.create(index=FACE_INDEX, body=body)
        logger.info(f"Created index '{FACE_INDEX}' with kNN dimension={embedding_dim}")

    @classmethod
    def store_embedding(
        cls,
        doc_id: str,
        embedding: list,
        resident_id: str,
        facility_id: str,
        photo_id: Optional[str] = None,
        face_id: Optional[str] = None,
        photo_url: Optional[str] = None,
        is_reference: bool = False,
    ) -> str:
        """임베딩 벡터를 OpenSearch에 저장.

        T-004e2: dual-write — 평문 `resident_id` 와 함께 `resident_id_hash` 도 색인.
        e4 에서 평문 필드를 제거할 때까지 두 필드 모두 유지된다.
        """
        client = cls.get_client()

        doc = {
            "resident_id": resident_id,
            "resident_id_hash": hash_resident_id(resident_id),
            "facility_id": facility_id,
            "photo_id": photo_id,
            "face_id": face_id,
            "photo_url": photo_url,
            "is_reference": is_reference,
            "embedding": embedding,
        }

        embedding_dim = len(embedding) if embedding else 0
        logger.info(f"Storing embedding {doc_id}: resident={resident_id}, facility={facility_id}, is_ref={is_reference}, dim={embedding_dim}")

        try:
            client.index(index=FACE_INDEX, id=doc_id, body=doc, refresh=True)
            logger.info(f"Successfully stored embedding {doc_id}")
        except Exception as e:
            logger.error(f"Failed to store embedding {doc_id}: {e}", exc_info=True)
            raise
        return doc_id

    @classmethod
    def search_similar(
        cls,
        embedding: list,
        facility_id: str,
        k: int = 5,
        threshold: float = 0.6,
    ) -> List[Tuple[str, float]]:
        """
        유사한 얼굴 검색 (kNN)
        OpenSearch kNN query format: filter는 knn 절 내부에 배치

        T-107: k 는 MAX_KNN_K 로 clamp — 호출자가 부주의하게 큰 값을 넘겨도
        OpenSearch 리소스 소모 상한이 걸림.

        Returns:
            [(resident_id, score), ...] 유사도 높은 순
        """
        if embedding is None:
            logger.warning("search_similar called with None embedding")
            return []

        if k < 1:
            k = 1
        elif k > MAX_KNN_K:
            logger.warning(f"search_similar: requested k={k} capped to {MAX_KNN_K}")
            k = MAX_KNN_K

        client = cls.get_client()

        # 먼저 reference embedding이 존재하는지 확인
        try:
            ref_count = client.count(
                index=FACE_INDEX,
                body={
                    "query": {
                        "bool": {
                            "must": [
                                {"term": {"facility_id": facility_id}},
                                {"term": {"is_reference": True}},
                            ]
                        }
                    }
                },
            )
            logger.info(
                f"Reference embeddings for facility {facility_id}: {ref_count['count']}"
            )
            if ref_count["count"] == 0:
                logger.warning("No reference embeddings found — cannot classify")
                return []
        except Exception as e:
            logger.warning(f"Could not count reference embeddings: {e}")

        # OpenSearch kNN 쿼리 — filter를 knn 절 안에 배치 (올바른 형식)
        query = {
            "size": k,
            "query": {
                "knn": {
                    "embedding": {
                        "vector": embedding,
                        "k": k,
                        "filter": {
                            "bool": {
                                "must": [
                                    {"term": {"facility_id": facility_id}},
                                    {"term": {"is_reference": True}},
                                ]
                            }
                        },
                    }
                }
            },
        }

        logger.info(f"kNN search: facility={facility_id}, k={k}, threshold={threshold}, embedding_dim={len(embedding)}")

        try:
            response = client.search(index=FACE_INDEX, body=query)
            hits = response["hits"]["hits"]
            logger.info(f"kNN raw results: {len(hits)} hits")

            results = []
            for hit in hits:
                score = hit["_score"]
                rid = _resolve_resident_id_from_hit(hit["_source"])
                if rid is None:
                    logger.warning(
                        f"  Hit skipped — neither resident_id nor resolvable resident_id_hash: {hit.get('_id')}"
                    )
                    continue
                logger.info(f"  Hit: resident_id={rid}, score={score}")

                # Lucene cosinesimil score = (1 + cosine_similarity) / 2
                # score >= 0.8 means cosine_sim >= 0.6
                # 사용자 threshold를 그대로 사용하되, 점수 해석에 주의
                if score >= threshold:
                    results.append((rid, score))

            logger.info(f"Found {len(results)} matches above threshold {threshold}")
            return results

        except Exception as e:
            logger.error(f"OpenSearch kNN search failed: {e}", exc_info=True)

            # 폴백: script_score 방식으로 재시도
            logger.info("Trying fallback script_score search...")
            try:
                fallback_query = {
                    "size": k,
                    "query": {
                        "script_score": {
                            "query": {
                                "bool": {
                                    "must": [
                                        {"term": {"facility_id": facility_id}},
                                        {"term": {"is_reference": True}},
                                    ]
                                }
                            },
                            "script": {
                                "source": "cosineSimilarity(params.query_vector, 'embedding') + 1.0",
                                "params": {"query_vector": embedding},
                            },
                        }
                    },
                }
                response = client.search(index=FACE_INDEX, body=fallback_query)
                hits = response["hits"]["hits"]
                logger.info(f"Fallback script_score results: {len(hits)} hits")

                results = []
                for hit in hits:
                    # script_score returns cosine_sim + 1.0, so range [0, 2]
                    raw_score = hit["_score"]
                    cosine_sim = raw_score - 1.0  # range [-1, 1]
                    rid = _resolve_resident_id_from_hit(hit["_source"])
                    if rid is None:
                        logger.warning(
                            f"  Fallback hit skipped — no resolvable resident_id: {hit.get('_id')}"
                        )
                        continue
                    logger.info(f"  Fallback hit: resident_id={rid}, raw_score={raw_score}, cosine_sim={cosine_sim}")

                    if cosine_sim >= threshold:
                        results.append((rid, cosine_sim))

                logger.info(f"Fallback found {len(results)} matches above threshold {threshold}")
                return results
            except Exception as e2:
                logger.error(f"Fallback search also failed: {e2}", exc_info=True)
                return []

    @classmethod
    def get_reference_faces(
        cls,
        resident_id: str,
        facility_id: str,
    ) -> list:
        """입소자의 등록된 기준 얼굴 목록 조회"""
        client = cls.get_client()

        query = {
            "size": 50,
            "query": {
                "bool": {
                    "must": [
                        {"term": {"resident_id": resident_id}},
                        {"term": {"facility_id": facility_id}},
                        {"term": {"is_reference": True}},
                    ]
                }
            },
            "_source": ["resident_id", "facility_id", "photo_url", "is_reference"],
        }

        try:
            response = client.search(index=FACE_INDEX, body=query)
            faces = []
            for hit in response["hits"]["hits"]:
                faces.append({
                    "doc_id": hit["_id"],
                    "photo_url": hit["_source"].get("photo_url"),
                    "resident_id": hit["_source"]["resident_id"],
                })
            return faces
        except Exception as e:
            logger.error(f"Failed to get reference faces: {e}")
            return []

    @classmethod
    def delete_embedding(cls, doc_id: str):
        """특정 임베딩 문서 삭제"""
        client = cls.get_client()
        try:
            client.delete(index=FACE_INDEX, id=doc_id, refresh=True)
            logger.info(f"Deleted embedding {doc_id}")
        except Exception as e:
            logger.error(f"Failed to delete embedding {doc_id}: {e}")
            raise

    @classmethod
    def delete_resident_embeddings(cls, resident_id: str):
        """입소자의 모든 임베딩 삭제.

        T-004e2: 평문 `resident_id` 또는 `resident_id_hash` 둘 중 하나만 가지고
        있는 docs 도 모두 잡히도록 OR query. 마이그 직후 등 한쪽이 없는 docs 가
        존재할 수 있는 transition 윈도우 대비.
        """
        client = cls.get_client()

        query = {
            "query": {
                "bool": {
                    "should": [
                        {"term": {"resident_id": resident_id}},
                        {"term": {"resident_id_hash": hash_resident_id(resident_id)}},
                    ],
                    "minimum_should_match": 1,
                }
            }
        }

        try:
            client.delete_by_query(index=FACE_INDEX, body=query)
            logger.info(f"Deleted embeddings for resident {resident_id}")
        except Exception as e:
            logger.error(f"Failed to delete embeddings: {e}")


    @classmethod
    def reclassify_unmatched(
        cls,
        facility_id: str,
        new_reference_embedding: list,
        new_resident_id: str,
        threshold: float = 0.6,
    ) -> List[dict]:
        """
        시설의 미분류(resident_id가 비어있는) 얼굴 임베딩을 새 기준 사진과 비교
        매칭되면 해당 임베딩의 resident_id 업데이트 + photo_id/face_id 반환

        Returns:
            [{"photo_id": ..., "face_id": ..., "doc_id": ..., "score": ...}, ...]
        """
        client = cls.get_client()

        # 1) 미분류 얼굴 임베딩 페이지네이션으로 수집 (T-107)
        # 기존에는 size=200 단건 호출이라 미분류가 200 건을 넘으면 나머지가 조용히 누락됨.
        # 이제 RECLASSIFY_BATCH_SIZE 씩 반복 조회하여 RECLASSIFY_MAX_TOTAL 까지 수집.
        unmatched: list = []
        unmatched_query_body = {
            "query": {
                "bool": {
                    "must": [
                        {"term": {"facility_id": facility_id}},
                        {"term": {"is_reference": False}},
                    ],
                    "should": [
                        {"term": {"resident_id": ""}},
                    ],
                    "minimum_should_match": 1,
                }
            },
            "_source": ["resident_id", "facility_id", "photo_id", "face_id", "embedding"],
        }
        try:
            from_offset = 0
            while from_offset < RECLASSIFY_MAX_TOTAL:
                page_size = min(RECLASSIFY_BATCH_SIZE, RECLASSIFY_MAX_TOTAL - from_offset)
                page_query = {
                    "size": page_size,
                    "from": from_offset,
                    **unmatched_query_body,
                }
                response = client.search(index=FACE_INDEX, body=page_query)
                hits = response["hits"]["hits"]
                if not hits:
                    break
                unmatched.extend(hits)
                if len(hits) < page_size:
                    break
                from_offset += len(hits)
            logger.info(
                f"Reclassify: collected {len(unmatched)} unmatched face embeddings "
                f"in facility {facility_id} (cap={RECLASSIFY_MAX_TOTAL})"
            )
            if len(unmatched) >= RECLASSIFY_MAX_TOTAL:
                # 운영 경보 트리거용 — 이 시점까지 오면 facility 가 비정상적으로 많은 미분류를 쌓아둔 것
                logger.warning(
                    f"Reclassify: hit safety cap RECLASSIFY_MAX_TOTAL={RECLASSIFY_MAX_TOTAL} "
                    f"for facility {facility_id}. 나머지 미분류는 다음 기준 사진 등록 시 처리됨."
                )

            if not unmatched:
                return []

        except Exception as e:
            logger.error(f"Reclassify: failed to fetch unmatched embeddings: {e}")
            return []

        # 2) 각 미분류 임베딩을 새 기준 사진과 비교
        import numpy as np

        ref_vec = np.array(new_reference_embedding)
        ref_norm = np.linalg.norm(ref_vec)
        if ref_norm == 0:
            logger.warning("Reclassify: reference embedding has zero norm")
            return []
        ref_vec = ref_vec / ref_norm

        matched = []
        actions = []
        for hit in unmatched:
            doc_id = hit["_id"]
            source = hit["_source"]
            emb = source.get("embedding")
            if not emb:
                continue

            # 코사인 유사도 직접 계산
            face_vec = np.array(emb)
            face_norm = np.linalg.norm(face_vec)
            if face_norm == 0:
                continue
            face_vec = face_vec / face_norm

            cosine_sim = float(np.dot(ref_vec, face_vec))

            if cosine_sim >= threshold:
                photo_id = source.get("photo_id")
                face_id = source.get("face_id")
                logger.info(
                    f"Reclassify match: doc={doc_id}, photo={photo_id}, face={face_id}, "
                    f"score={cosine_sim:.4f}"
                )

                actions.append({
                    "_op_type": "update",
                    "_index": FACE_INDEX,
                    "_id": doc_id,
                    # T-004e2: dual-write — hash 도 같이 set 해서
                    # transition 동안에도 hash 인덱스가 일관되게 유지됨.
                    "doc": {
                        "resident_id": new_resident_id,
                        "resident_id_hash": hash_resident_id(new_resident_id),
                    },
                })
                matched.append({
                    "photo_id": photo_id,
                    "face_id": face_id,
                    "doc_id": doc_id,
                    "score": cosine_sim,
                })

        if actions:
            try:
                success, errors = bulk(client, actions, raise_on_error=False)
                if errors:
                    logger.warning(
                        f"Reclassify: bulk update had {len(errors)} errors out of {len(actions)}"
                    )
                else:
                    logger.info(f"Reclassify: bulk updated {success} docs in one round-trip")
            except Exception as e:
                logger.error(f"Reclassify: bulk update failed: {e}")

        logger.info(f"Reclassify: {len(matched)} photos matched to resident {new_resident_id}")
        return matched

    @classmethod
    def migrate_resident_id_to_hash(
        cls,
        facility_id: Optional[str] = None,
        dry_run: bool = False,
    ) -> dict:
        """T-004e3: 옛 docs 의 `resident_id_hash` 필드를 평문 `resident_id` 로부터
        backfill 한다. e2 머지 + 이미지 배포 후 운영자가 1 회 호출.

        흐름:
          1) `resident_id` 가 있으면서 `resident_id_hash` 가 비어있는 docs 를
             페이지네이션으로 수집 (facility 필터 옵션 — 단계 배포 시 시설별 검증).
          2) 각 doc 의 평문 rid 로 hash 계산 → bulk update.
          3) dry_run=True 면 update 없이 카운트만 반환.

        반환:
            {
              "scanned": int,    # 검사한 docs 수
              "to_update": int,  # hash 가 비어있어 backfill 대상이 된 docs
              "updated": int,    # 실제 bulk 업데이트 성공 docs (dry_run 이면 0)
              "errors": int,     # bulk 업데이트 중 실패한 docs
              "capped": bool,    # MIGRATE_MAX_TOTAL 에 걸렸는지
            }
        """
        client = cls.get_client()

        must: list = [
            {"exists": {"field": "resident_id"}},
        ]
        must_not: list = [
            {"exists": {"field": "resident_id_hash"}},
        ]
        if facility_id is not None:
            must.append({"term": {"facility_id": facility_id}})

        query_body = {
            "query": {"bool": {"must": must, "must_not": must_not}},
            "_source": ["resident_id"],
        }

        scanned = 0
        actions: list = []
        capped = False
        from_offset = 0
        while from_offset < MIGRATE_MAX_TOTAL:
            page_size = min(MIGRATE_SCROLL_PAGE_SIZE, MIGRATE_MAX_TOTAL - from_offset)
            page_query = {"size": page_size, "from": from_offset, **query_body}
            try:
                response = client.search(index=FACE_INDEX, body=page_query)
            except Exception as e:
                logger.error(f"migrate_resident_id_to_hash: search failed at from={from_offset}: {e}")
                break
            hits = response["hits"]["hits"]
            if not hits:
                break

            for hit in hits:
                scanned += 1
                doc_id = hit["_id"]
                rid = hit["_source"].get("resident_id")
                if rid is None:
                    # 위 query 가 must=exists 인데도 들어오는 경우는 거의 없지만 방어적 skip
                    continue
                actions.append({
                    "_op_type": "update",
                    "_index": FACE_INDEX,
                    "_id": doc_id,
                    "doc": {"resident_id_hash": hash_resident_id(rid)},
                })

            if len(hits) < page_size:
                break
            from_offset += len(hits)
            if from_offset >= MIGRATE_MAX_TOTAL:
                capped = True
                logger.warning(
                    f"migrate_resident_id_to_hash: hit MIGRATE_MAX_TOTAL={MIGRATE_MAX_TOTAL}. "
                    "남은 docs 는 다음 호출로 처리. (facility 필터 권장)"
                )

        to_update = len(actions)
        updated = 0
        errors = 0

        if actions and not dry_run:
            try:
                success, errs = bulk(client, actions, raise_on_error=False)
                updated = success
                errors = len(errs) if isinstance(errs, list) else 0
                if errors:
                    logger.warning(
                        f"migrate_resident_id_to_hash: bulk had {errors} errors out of {to_update}"
                    )
                else:
                    logger.info(f"migrate_resident_id_to_hash: bulk updated {updated} docs")
            except Exception as e:
                logger.error(f"migrate_resident_id_to_hash: bulk failed: {e}")
                errors = to_update

        return {
            "scanned": scanned,
            "to_update": to_update,
            "updated": updated,
            "errors": errors,
            "capped": capped,
        }


def get_opensearch() -> OpenSearchService:
    return OpenSearchService
