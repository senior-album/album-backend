"""
T-124 PR2: app.services.opensearch_service.OpenSearchService 단위 테스트.

실제 OpenSearch 클러스터 없이도 비즈니스 로직 (k clamp, threshold 필터, 코사인
재분류, 페이지네이션 cap) 을 검증한다. `OpenSearchService._client` 를 가짜
client 로 갈아끼우는 방식.

T-107 의 `MAX_KNN_K` clamp + `RECLASSIFY_MAX_TOTAL` 페이지네이션 cap 이
이 파일의 핵심 회귀 방지 대상.
"""

from __future__ import annotations

# Settings 가 import 시점에 강제하는 secret 들 — 단독 실행에서도 동작하도록
# setdefault. CI 는 자체 env 가 먼저 들어오므로 no-op 처리됨.
import os as _os

_os.environ.setdefault("JWT_SECRET", "test-secret-value-for-jwt-32-bytes-min")
_os.environ.setdefault("JWT_REFRESH_SECRET", "test-refresh-secret-32bytes-minimum")
_os.environ.setdefault("RESIDENT_PII_KEK", "0" * 64)
_os.environ.setdefault("RESIDENT_NAME_HMAC_KEY", "1" * 64)
# T-004e2: hash_resident_id 가 사용. 테스트용 결정적 키.
_os.environ.setdefault("OPENSEARCH_LINK_KEY", "t004e2-test-link-key-deterministic-aaaa")

from typing import Any

import numpy as np
import pytest

from app.services import opensearch_service as os_module
from app.services.opensearch_service import (
    FACE_INDEX,
    MAX_KNN_K,
    OpenSearchService,
    RECLASSIFY_BATCH_SIZE,
    RECLASSIFY_MAX_TOTAL,
    hash_resident_id,
)


# ---------------------------------------------------------------------------
# 가짜 OpenSearch client
# ---------------------------------------------------------------------------


class _FakeIndices:
    def __init__(self):
        self.created = []
        self.deleted = []
        self.exists_map: dict[str, bool] = {}
        self.mapping_map: dict[str, Any] = {}

    def exists(self, index: str) -> bool:
        return self.exists_map.get(index, False)

    def get_mapping(self, index: str):
        return self.mapping_map[index]

    def create(self, index: str, body: dict):
        self.created.append((index, body))
        self.exists_map[index] = True

    def delete(self, index: str):
        self.deleted.append(index)
        self.exists_map[index] = False


class _FakeClient:
    """OpenSearchService 가 호출하는 메서드만 충실히 흉내."""

    def __init__(
        self,
        *,
        ref_count: int = 1,
        knn_hits: list | None = None,
        knn_raises: bool = False,
        unmatched_pages: list[list] | None = None,
    ):
        self.indices = _FakeIndices()
        self._ref_count = ref_count
        self._knn_hits = knn_hits if knn_hits is not None else []
        self._knn_raises = knn_raises
        self._unmatched_pages = unmatched_pages or []
        self._page_idx = 0

        self.indexed: list[tuple[str, str, dict]] = []
        self.deleted_ids: list[tuple[str, str]] = []
        self.delete_by_query_calls: list[tuple[str, dict]] = []
        self.search_calls: list[dict] = []

    # --- index / delete -----------------------------------------------------

    def index(self, *, index: str, id: str, body: dict, refresh: bool = False):
        self.indexed.append((index, id, body))

    def delete(self, *, index: str, id: str, refresh: bool = False):
        self.deleted_ids.append((index, id))

    def delete_by_query(self, *, index: str, body: dict):
        self.delete_by_query_calls.append((index, body))

    # --- count / search -----------------------------------------------------

    def count(self, *, index: str, body: dict):
        return {"count": self._ref_count}

    def search(self, *, index: str, body: dict):
        self.search_calls.append(body)

        # reclassify_unmatched 의 페이지네이션 호출 — body 에 'from' 이 있으면
        # 다음 페이지 반환. 없으면 일반 kNN.
        if "from" in body:
            idx = self._page_idx
            self._page_idx += 1
            page = self._unmatched_pages[idx] if idx < len(self._unmatched_pages) else []
            return {"hits": {"hits": page}}

        if self._knn_raises:
            raise RuntimeError("kNN search blew up")
        return {"hits": {"hits": self._knn_hits}}


@pytest.fixture(autouse=True)
def _reset_client():
    OpenSearchService._client = None
    yield
    OpenSearchService._client = None


def _install_client(monkeypatch, fake: _FakeClient):
    OpenSearchService._client = fake
    return fake


# ---------------------------------------------------------------------------
# get_client — 캐싱 동작
# ---------------------------------------------------------------------------


def test_get_client_caches_singleton(monkeypatch):
    calls = {"n": 0}

    def _factory(*args, **kwargs):
        calls["n"] += 1
        return _FakeClient()

    monkeypatch.setattr(os_module, "OpenSearch", _factory)
    a = OpenSearchService.get_client()
    b = OpenSearchService.get_client()
    assert a is b
    assert calls["n"] == 1


# ---------------------------------------------------------------------------
# search_similar — k clamp (T-107) + threshold 필터
# ---------------------------------------------------------------------------


def test_search_similar_returns_empty_when_no_reference_embeddings(monkeypatch):
    fake = _install_client(monkeypatch, _FakeClient(ref_count=0))
    out = OpenSearchService.search_similar(
        embedding=[0.1, 0.2], facility_id="fac-1", k=3, threshold=0.6
    )
    assert out == []
    # ref_count=0 면 search 자체를 호출하지 않는다.
    assert fake.search_calls == []


def test_search_similar_returns_empty_when_embedding_none():
    out = OpenSearchService.search_similar(
        embedding=None, facility_id="fac-1", k=3, threshold=0.6  # type: ignore[arg-type]
    )
    assert out == []


def test_search_similar_clamps_k_to_max_knn_k(monkeypatch):
    """T-107: 호출자가 k=10000 처럼 큰 값을 넘겨도 MAX_KNN_K 로 잘려야 한다."""
    fake = _install_client(monkeypatch, _FakeClient(ref_count=5, knn_hits=[]))
    OpenSearchService.search_similar(
        embedding=[0.1, 0.2], facility_id="fac-1", k=10_000, threshold=0.6
    )
    body = fake.search_calls[0]
    assert body["size"] == MAX_KNN_K
    assert body["query"]["knn"]["embedding"]["k"] == MAX_KNN_K


def test_search_similar_floors_k_to_one(monkeypatch):
    fake = _install_client(monkeypatch, _FakeClient(ref_count=5, knn_hits=[]))
    OpenSearchService.search_similar(
        embedding=[0.1], facility_id="fac-1", k=0, threshold=0.6
    )
    assert fake.search_calls[0]["size"] == 1


def test_search_similar_filters_below_threshold(monkeypatch):
    """threshold 이하 점수는 결과에서 빠져야 한다."""
    hits = [
        {"_score": 0.95, "_source": {"resident_id": "r-good"}},
        {"_score": 0.50, "_source": {"resident_id": "r-low"}},
        {"_score": 0.80, "_source": {"resident_id": "r-edge"}},
    ]
    _install_client(monkeypatch, _FakeClient(ref_count=3, knn_hits=hits))
    out = OpenSearchService.search_similar(
        embedding=[0.1, 0.2], facility_id="fac-1", k=10, threshold=0.8
    )
    rids = [r for r, _ in out]
    assert "r-good" in rids
    assert "r-edge" in rids  # 정확히 == threshold 는 통과
    assert "r-low" not in rids


def test_search_similar_falls_back_to_script_score_on_knn_failure(monkeypatch):
    """1차 kNN 이 죽으면 script_score 폴백을 시도. cosine_sim = raw - 1.0 으로 변환됨."""

    class _FallbackClient(_FakeClient):
        def __init__(self):
            super().__init__(ref_count=2, knn_hits=[], knn_raises=True)
            self._fallback_returned = False

        def search(self, *, index, body):  # type: ignore[override]
            self.search_calls.append(body)
            if "script_score" in body.get("query", {}):
                # script_score 응답 — raw_score = cosine_sim + 1.0
                return {
                    "hits": {
                        "hits": [
                            {"_score": 1.85, "_source": {"resident_id": "r-1"}},  # cos=0.85
                            {"_score": 1.40, "_source": {"resident_id": "r-2"}},  # cos=0.40
                        ]
                    }
                }
            raise RuntimeError("primary kNN dead")

    _install_client(monkeypatch, _FallbackClient())
    out = OpenSearchService.search_similar(
        embedding=[0.1, 0.2], facility_id="fac-1", k=5, threshold=0.6
    )
    assert ("r-1", pytest.approx(0.85, abs=1e-6)) in out
    assert all(rid != "r-2" for rid, _ in out)  # 0.40 < 0.6 임계값 컷


# ---------------------------------------------------------------------------
# store_embedding / delete_embedding / delete_resident_embeddings
# ---------------------------------------------------------------------------


def test_store_embedding_writes_doc_with_expected_fields(monkeypatch):
    fake = _install_client(monkeypatch, _FakeClient())
    OpenSearchService.store_embedding(
        doc_id="d1",
        embedding=[0.1, 0.2, 0.3],
        resident_id="r1",
        facility_id="f1",
        photo_id="p1",
        face_id="fc1",
        photo_url="s3://b/k",
        is_reference=True,
    )
    assert len(fake.indexed) == 1
    idx, doc_id, body = fake.indexed[0]
    assert idx == FACE_INDEX
    assert doc_id == "d1"
    assert body["resident_id"] == "r1"
    assert body["is_reference"] is True
    assert body["embedding"] == [0.1, 0.2, 0.3]


def test_store_embedding_propagates_indexing_failure(monkeypatch):
    class _BadClient(_FakeClient):
        def index(self, *, index, id, body, refresh=False):  # type: ignore[override]
            raise RuntimeError("write blocked")

    _install_client(monkeypatch, _BadClient())
    with pytest.raises(RuntimeError, match="write blocked"):
        OpenSearchService.store_embedding(
            doc_id="d", embedding=[0.0], resident_id="r", facility_id="f"
        )


def test_delete_embedding_calls_client_delete(monkeypatch):
    fake = _install_client(monkeypatch, _FakeClient())
    OpenSearchService.delete_embedding("d1")
    assert fake.deleted_ids == [(FACE_INDEX, "d1")]


def test_delete_resident_embeddings_uses_dual_query(monkeypatch):
    """T-004e2: 평문 resident_id OR resident_id_hash 둘 다 매칭하도록 bool/should."""
    fake = _install_client(monkeypatch, _FakeClient())
    OpenSearchService.delete_resident_embeddings("r-1")
    assert len(fake.delete_by_query_calls) == 1
    _, body = fake.delete_by_query_calls[0]
    bool_query = body["query"]["bool"]
    assert bool_query["minimum_should_match"] == 1
    should = bool_query["should"]
    assert {"term": {"resident_id": "r-1"}} in should
    expected_hash = hash_resident_id("r-1")
    assert {"term": {"resident_id_hash": expected_hash}} in should


# ---------------------------------------------------------------------------
# reclassify_unmatched — T-107 페이지네이션 + 코사인 매칭
# ---------------------------------------------------------------------------


def _hit(doc_id: str, embedding: list, photo_id: str = "p", face_id: str = "f") -> dict:
    return {
        "_id": doc_id,
        "_source": {
            "resident_id": "",
            "facility_id": "fac-1",
            "photo_id": photo_id,
            "face_id": face_id,
            "embedding": embedding,
        },
    }


def test_reclassify_returns_empty_when_no_unmatched(monkeypatch):
    fake = _install_client(monkeypatch, _FakeClient(unmatched_pages=[[]]))
    out = OpenSearchService.reclassify_unmatched(
        facility_id="fac-1",
        new_reference_embedding=[1.0, 0.0],
        new_resident_id="r-new",
    )
    assert out == []


def test_reclassify_zero_norm_reference_returns_empty(monkeypatch):
    _install_client(
        monkeypatch,
        _FakeClient(unmatched_pages=[[_hit("d1", [1.0, 0.0])]]),
    )
    out = OpenSearchService.reclassify_unmatched(
        facility_id="fac-1",
        new_reference_embedding=[0.0, 0.0, 0.0],  # zero vector
        new_resident_id="r-new",
    )
    assert out == []


def test_reclassify_matches_above_threshold(monkeypatch):
    """기준과 같은 방향의 임베딩(cosine~1) 만 매칭, 직각/반대는 제외."""
    pages = [
        [
            _hit("aligned", [2.0, 0.0]),  # cos=1.0
            _hit("orthogonal", [0.0, 1.0]),  # cos=0.0
            _hit("opposite", [-1.0, 0.0]),  # cos=-1.0
        ]
    ]
    fake = _install_client(monkeypatch, _FakeClient(unmatched_pages=pages))

    # bulk 호출도 가짜로 — 실제 import path 의 bulk 를 monkeypatch.
    bulk_calls = []

    def _fake_bulk(client, actions, raise_on_error=False):
        bulk_calls.append(list(actions))
        return len(bulk_calls[-1]), []

    monkeypatch.setattr(os_module, "bulk", _fake_bulk)

    out = OpenSearchService.reclassify_unmatched(
        facility_id="fac-1",
        new_reference_embedding=[1.0, 0.0],
        new_resident_id="r-new",
        threshold=0.6,
    )
    rids = [m["doc_id"] for m in out]
    assert rids == ["aligned"]
    # bulk 업데이트도 호출되었는지
    assert len(bulk_calls) == 1 and len(bulk_calls[0]) == 1
    # T-004e2 dual-write — resident_id 와 resident_id_hash 둘 다 set
    assert bulk_calls[0][0]["doc"] == {
        "resident_id": "r-new",
        "resident_id_hash": hash_resident_id("r-new"),
    }


def test_reclassify_skips_zero_norm_face_embeddings(monkeypatch):
    """미분류 임베딩 중 norm=0 짜리는 ZeroDivision 없이 건너뛴다."""
    pages = [[_hit("zero", [0.0, 0.0]), _hit("good", [1.0, 0.0])]]
    _install_client(monkeypatch, _FakeClient(unmatched_pages=pages))
    monkeypatch.setattr(os_module, "bulk", lambda *a, **k: (1, []))

    out = OpenSearchService.reclassify_unmatched(
        facility_id="fac-1",
        new_reference_embedding=[1.0, 0.0],
        new_resident_id="r-new",
        threshold=0.6,
    )
    assert [m["doc_id"] for m in out] == ["good"]


def test_reclassify_paginates_across_pages_until_short_page(monkeypatch):
    """페이지가 BATCH_SIZE 미만이 되면 fetch 종료 (T-107)."""
    page1 = [_hit(f"d-{i}", [1.0, 0.0]) for i in range(RECLASSIFY_BATCH_SIZE)]
    page2 = [_hit(f"d-extra", [1.0, 0.0])]
    fake = _install_client(monkeypatch, _FakeClient(unmatched_pages=[page1, page2, []]))
    monkeypatch.setattr(
        os_module, "bulk", lambda c, actions, raise_on_error=False: (len(list(actions)), [])
    )

    out = OpenSearchService.reclassify_unmatched(
        facility_id="fac-1",
        new_reference_embedding=[1.0, 0.0],
        new_resident_id="r-new",
        threshold=0.6,
    )
    # page1 (BATCH_SIZE) + page2 (1) 모두 매칭. page2 는 BATCH_SIZE 미만이라 거기서 stop.
    assert len(out) == RECLASSIFY_BATCH_SIZE + 1
    # 검색은 두 번 호출 (page1, page2). 세 번째 빈 페이지는 호출 안됨.
    assert len(fake.search_calls) == 2


# ---------------------------------------------------------------------------
# get_reference_faces
# ---------------------------------------------------------------------------


def test_get_reference_faces_returns_doc_summaries(monkeypatch):
    class _RefClient(_FakeClient):
        def search(self, *, index, body):  # type: ignore[override]
            return {
                "hits": {
                    "hits": [
                        {
                            "_id": "doc-1",
                            "_source": {
                                "resident_id": "r-1",
                                "facility_id": "f-1",
                                "photo_url": "s3://b/k1",
                                "is_reference": True,
                            },
                        },
                        {
                            "_id": "doc-2",
                            "_source": {
                                "resident_id": "r-1",
                                "facility_id": "f-1",
                                "is_reference": True,
                            },
                        },
                    ]
                }
            }

    _install_client(monkeypatch, _RefClient())
    out = OpenSearchService.get_reference_faces("r-1", "f-1")
    assert out == [
        {"doc_id": "doc-1", "photo_url": "s3://b/k1", "resident_id": "r-1"},
        {"doc_id": "doc-2", "photo_url": None, "resident_id": "r-1"},
    ]


def test_get_reference_faces_returns_empty_on_search_failure(monkeypatch):
    class _BadSearch(_FakeClient):
        def search(self, *, index, body):  # type: ignore[override]
            raise RuntimeError("boom")

    _install_client(monkeypatch, _BadSearch())
    assert OpenSearchService.get_reference_faces("r-1", "f-1") == []


# ---------------------------------------------------------------------------
# ensure_index — dimension mismatch → 재생성
# ---------------------------------------------------------------------------


def test_ensure_index_creates_when_missing(monkeypatch):
    fake = _install_client(monkeypatch, _FakeClient())
    fake.indices.exists_map[FACE_INDEX] = False
    monkeypatch.setattr(OpenSearchService, "_get_embedding_dim", classmethod(lambda cls: 512))

    OpenSearchService.ensure_index()
    assert len(fake.indices.created) == 1
    _, body = fake.indices.created[0]
    assert body["mappings"]["properties"]["embedding"]["dimension"] == 512


def test_ensure_index_recreates_on_dimension_mismatch(monkeypatch):
    fake = _install_client(monkeypatch, _FakeClient())
    fake.indices.exists_map[FACE_INDEX] = True
    fake.indices.mapping_map[FACE_INDEX] = {
        FACE_INDEX: {"mappings": {"properties": {"embedding": {"dimension": 128}}}}
    }
    monkeypatch.setattr(OpenSearchService, "_get_embedding_dim", classmethod(lambda cls: 512))

    OpenSearchService.ensure_index()
    assert FACE_INDEX in fake.indices.deleted
    assert len(fake.indices.created) == 1


def test_ensure_index_skips_when_dimension_matches(monkeypatch):
    fake = _install_client(monkeypatch, _FakeClient())
    fake.indices.exists_map[FACE_INDEX] = True
    fake.indices.mapping_map[FACE_INDEX] = {
        FACE_INDEX: {"mappings": {"properties": {"embedding": {"dimension": 512}}}}
    }
    monkeypatch.setattr(OpenSearchService, "_get_embedding_dim", classmethod(lambda cls: 512))

    OpenSearchService.ensure_index()
    assert fake.indices.deleted == []
    assert fake.indices.created == []


# ---------------------------------------------------------------------------
# get_opensearch — 모듈 레벨 헬퍼
# ---------------------------------------------------------------------------


def test_module_level_get_opensearch_returns_class():
    assert os_module.get_opensearch() is OpenSearchService


# ---------------------------------------------------------------------------
# T-004: TLS / auth 옵션 환경변수 주입
# ---------------------------------------------------------------------------


class _CaptureFactory:
    """OpenSearch 생성자에 들어온 kwargs 를 캡처. 실제 client 행위는 _FakeClient 위임."""

    def __init__(self):
        self.captured: dict = {}

    def __call__(self, **kwargs):
        self.captured = kwargs
        return _FakeClient()


def _reset_client_singleton():
    OpenSearchService._client = None


def test_get_client_default_no_ssl_no_auth(monkeypatch):
    """기본값(USE_SSL=False, USER/PASSWORD 빈 값) → 평문 + 인증 없음."""
    _reset_client_singleton()
    factory = _CaptureFactory()
    monkeypatch.setattr(os_module, "OpenSearch", factory)

    OpenSearchService.get_client()

    assert factory.captured["use_ssl"] is False
    assert factory.captured["verify_certs"] is False
    assert "http_auth" not in factory.captured
    assert "ca_certs" not in factory.captured
    assert "ssl_show_warn" not in factory.captured  # SSL off 에선 의미 없음


def test_get_client_ssl_with_self_signed(monkeypatch):
    """USE_SSL=True + VERIFY_CERTS=False → ssl_show_warn=False 로 경고 폭주 차단."""
    _reset_client_singleton()
    from app.core.config import get_settings

    settings = get_settings()
    monkeypatch.setattr(settings, "OPENSEARCH_USE_SSL", True)
    monkeypatch.setattr(settings, "OPENSEARCH_VERIFY_CERTS", False)

    factory = _CaptureFactory()
    monkeypatch.setattr(os_module, "OpenSearch", factory)

    OpenSearchService.get_client()

    assert factory.captured["use_ssl"] is True
    assert factory.captured["verify_certs"] is False
    assert factory.captured["ssl_show_warn"] is False
    assert "ca_certs" not in factory.captured  # path 미지정


def test_get_client_ssl_with_ca_cert_and_basic_auth(monkeypatch):
    """USE_SSL=True + VERIFY_CERTS=True + CA_CERT_PATH + USER/PASSWORD → 운영 케이스."""
    _reset_client_singleton()
    from app.core.config import get_settings

    settings = get_settings()
    monkeypatch.setattr(settings, "OPENSEARCH_USE_SSL", True)
    monkeypatch.setattr(settings, "OPENSEARCH_VERIFY_CERTS", True)
    monkeypatch.setattr(settings, "OPENSEARCH_CA_CERT_PATH", "/etc/ssl/opensearch-ca.pem")
    monkeypatch.setattr(settings, "OPENSEARCH_USER", "admin")
    monkeypatch.setattr(settings, "OPENSEARCH_PASSWORD", "s3cret")

    factory = _CaptureFactory()
    monkeypatch.setattr(os_module, "OpenSearch", factory)

    OpenSearchService.get_client()

    assert factory.captured["use_ssl"] is True
    assert factory.captured["verify_certs"] is True
    assert factory.captured["ca_certs"] == "/etc/ssl/opensearch-ca.pem"
    assert factory.captured["http_auth"] == ("admin", "s3cret")
    # verify_certs=True 면 ssl_show_warn 은 안 들어가도 됨 (의미 없는 경고 안 남)
    assert "ssl_show_warn" not in factory.captured


# ---------------------------------------------------------------------------
# T-004e2: hash_resident_id + dual-write/dual-read
# ---------------------------------------------------------------------------


def test_hash_resident_id_is_deterministic_and_distinct():
    """같은 rid → 같은 hash, 다른 rid → 다른 hash, 빈 문자열도 결정적."""
    h1 = hash_resident_id("r-1")
    h2 = hash_resident_id("r-1")
    h3 = hash_resident_id("r-2")
    assert h1 == h2
    assert h1 != h3
    # SHA-256 hex digest 는 64 chars
    assert len(h1) == 64
    # 빈 문자열 — 미분류 표시 — 도 결정적
    e1 = hash_resident_id("")
    e2 = hash_resident_id("")
    assert e1 == e2
    assert e1 != h1


def test_hash_resident_id_raises_when_key_missing(monkeypatch):
    """T-004e2: OPENSEARCH_LINK_KEY 미설정 시 fail-fast (무음 fallback 안 됨)."""
    from app.core.config import get_settings

    settings = get_settings()
    monkeypatch.setattr(settings, "OPENSEARCH_LINK_KEY", "")
    with pytest.raises(RuntimeError, match="OPENSEARCH_LINK_KEY"):
        hash_resident_id("r-1")


def test_store_embedding_dual_writes_resident_id_hash(monkeypatch):
    """T-004e2: store_embedding 은 평문 resident_id 와 resident_id_hash 둘 다 색인."""
    fake = _install_client(monkeypatch, _FakeClient())
    OpenSearchService.store_embedding(
        doc_id="d1",
        embedding=[0.1, 0.2, 0.3],
        resident_id="r-dual",
        facility_id="f1",
    )
    assert len(fake.indexed) == 1
    _, _, body = fake.indexed[0]
    assert body["resident_id"] == "r-dual"
    assert body["resident_id_hash"] == hash_resident_id("r-dual")


def test_search_similar_resolves_via_hash_cache_when_present(monkeypatch):
    """캐시에 hash→rid 가 있으면 hit 의 hash 로부터 rid 를 복원한다 (e4 시나리오 미리보기)."""
    rid = "r-hashed"
    rid_hash = hash_resident_id(rid)
    hits = [
        {"_score": 0.95, "_source": {"resident_id_hash": rid_hash}},  # 평문 없음
    ]
    _install_client(monkeypatch, _FakeClient(ref_count=1, knn_hits=hits))
    monkeypatch.setattr(OpenSearchService, "_hash_to_rid", {rid_hash: rid})

    out = OpenSearchService.search_similar(
        embedding=[0.1, 0.2], facility_id="fac-1", k=5, threshold=0.6
    )
    assert out == [(rid, 0.95)]


def test_search_similar_falls_back_to_plain_when_hash_not_in_cache(monkeypatch):
    """e2 기본 — 캐시 비어있어도 평문 resident_id fallback 으로 정상 동작."""
    hits = [
        {
            "_score": 0.90,
            "_source": {
                "resident_id": "r-plain",
                "resident_id_hash": hash_resident_id("r-plain"),
            },
        }
    ]
    _install_client(monkeypatch, _FakeClient(ref_count=1, knn_hits=hits))
    monkeypatch.setattr(OpenSearchService, "_hash_to_rid", {})  # 캐시 비어있음

    out = OpenSearchService.search_similar(
        embedding=[0.1, 0.2], facility_id="fac-1", k=5, threshold=0.6
    )
    assert out == [("r-plain", 0.90)]


def test_search_similar_skips_hit_with_no_resolvable_id(monkeypatch):
    """resident_id 도 없고 resident_id_hash 가 캐시에 없는 hit 은 결과에서 제외."""
    hits = [
        {"_score": 0.95, "_source": {"resident_id_hash": "deadbeef-not-in-cache"}},
        {"_score": 0.85, "_source": {"resident_id": "r-good"}},
    ]
    _install_client(monkeypatch, _FakeClient(ref_count=1, knn_hits=hits))
    monkeypatch.setattr(OpenSearchService, "_hash_to_rid", {})

    out = OpenSearchService.search_similar(
        embedding=[0.1, 0.2], facility_id="fac-1", k=5, threshold=0.6
    )
    rids = [r for r, _ in out]
    assert rids == ["r-good"]


def test_reclassify_bulk_action_writes_both_fields(monkeypatch):
    """T-004e2: reclassify_unmatched 의 bulk action 은 두 필드 다 set."""
    pages = [[_hit("aligned", [1.0, 0.0])]]
    _install_client(monkeypatch, _FakeClient(unmatched_pages=pages))

    captured: list = []

    def _fake_bulk(client, actions, raise_on_error=False):
        actions_list = list(actions)
        captured.append(actions_list)
        return len(actions_list), []

    monkeypatch.setattr(os_module, "bulk", _fake_bulk)

    OpenSearchService.reclassify_unmatched(
        facility_id="fac-1",
        new_reference_embedding=[1.0, 0.0],
        new_resident_id="r-new",
        threshold=0.6,
    )
    assert len(captured) == 1 and len(captured[0]) == 1
    doc = captured[0][0]["doc"]
    assert doc["resident_id"] == "r-new"
    assert doc["resident_id_hash"] == hash_resident_id("r-new")


def test_ensure_index_includes_resident_id_hash_mapping(monkeypatch):
    """T-004e2: 새 인덱스 mapping 에 resident_id_hash 가 keyword 로 등록돼야 함."""
    fake = _install_client(monkeypatch, _FakeClient())
    fake.indices.exists_map[FACE_INDEX] = False
    monkeypatch.setattr(OpenSearchService, "_get_embedding_dim", classmethod(lambda cls: 256))

    OpenSearchService.ensure_index()
    assert len(fake.indices.created) == 1
    _, body = fake.indices.created[0]
    props = body["mappings"]["properties"]
    assert props["resident_id_hash"] == {"type": "keyword"}


# ---------------------------------------------------------------------------
# T-004e3: migrate_resident_id_to_hash
# ---------------------------------------------------------------------------


class _MigrateFakeClient(_FakeClient):
    """migrate_resident_id_to_hash 가 호출하는 search/bulk 만 고정값으로 응답."""

    def __init__(self, pages: list[list[dict]]):
        super().__init__()
        self._pages = pages
        self._page_calls = 0
        self.search_bodies: list[dict] = []

    def search(self, *, index: str, body: dict):  # type: ignore[override]
        self.search_bodies.append(body)
        idx = self._page_calls
        self._page_calls += 1
        page = self._pages[idx] if idx < len(self._pages) else []
        return {"hits": {"hits": page}}


def _migrate_hit(doc_id: str, resident_id: str) -> dict:
    return {"_id": doc_id, "_source": {"resident_id": resident_id}}


def test_migrate_resident_id_to_hash_backfills_missing_docs(monkeypatch):
    """기존 docs (resident_id_hash 없음) 들이 모두 hash 로 backfill 되는지."""
    pages = [
        [_migrate_hit("d-1", "r-1"), _migrate_hit("d-2", "r-2")],
    ]
    _install_client(monkeypatch, _MigrateFakeClient(pages))

    captured: list = []

    def _fake_bulk(client, actions, raise_on_error=False):
        actions_list = list(actions)
        captured.append(actions_list)
        return len(actions_list), []

    monkeypatch.setattr(os_module, "bulk", _fake_bulk)

    out = OpenSearchService.migrate_resident_id_to_hash()
    assert out["scanned"] == 2
    assert out["to_update"] == 2
    assert out["updated"] == 2
    assert out["errors"] == 0
    assert out["capped"] is False

    assert len(captured) == 1
    actions = captured[0]
    assert {a["_id"] for a in actions} == {"d-1", "d-2"}
    by_id = {a["_id"]: a["doc"]["resident_id_hash"] for a in actions}
    assert by_id["d-1"] == hash_resident_id("r-1")
    assert by_id["d-2"] == hash_resident_id("r-2")


def test_migrate_resident_id_to_hash_dry_run_skips_bulk(monkeypatch):
    """dry_run=True 면 to_update 만 카운트하고 실제 bulk 는 호출 안함."""
    pages = [[_migrate_hit("d-1", "r-1")]]
    _install_client(monkeypatch, _MigrateFakeClient(pages))

    bulk_called = {"count": 0}

    def _fake_bulk(client, actions, raise_on_error=False):
        bulk_called["count"] += 1
        return 0, []

    monkeypatch.setattr(os_module, "bulk", _fake_bulk)

    out = OpenSearchService.migrate_resident_id_to_hash(dry_run=True)
    assert out["to_update"] == 1
    assert out["updated"] == 0
    assert out["errors"] == 0
    assert bulk_called["count"] == 0


def test_migrate_resident_id_to_hash_filters_by_facility(monkeypatch):
    """facility_id 인자가 query 의 must filter 에 포함돼야 함."""
    pages = [[]]
    fake = _install_client(monkeypatch, _MigrateFakeClient(pages))

    OpenSearchService.migrate_resident_id_to_hash(facility_id="fac-only")
    assert len(fake.search_bodies) == 1
    must_clauses = fake.search_bodies[0]["query"]["bool"]["must"]
    assert {"term": {"facility_id": "fac-only"}} in must_clauses
    # 여전히 resident_id 존재 + hash 부재 조건 유지
    assert {"exists": {"field": "resident_id"}} in must_clauses
    must_not = fake.search_bodies[0]["query"]["bool"]["must_not"]
    assert {"exists": {"field": "resident_id_hash"}} in must_not


def test_migrate_resident_id_to_hash_returns_zero_when_nothing_to_backfill(monkeypatch):
    """이미 마이그된 인덱스 — 조회 결과 0 → scanned/to_update 모두 0."""
    _install_client(monkeypatch, _MigrateFakeClient([[]]))
    monkeypatch.setattr(os_module, "bulk", lambda c, a, raise_on_error=False: (0, []))

    out = OpenSearchService.migrate_resident_id_to_hash()
    assert out == {
        "scanned": 0,
        "to_update": 0,
        "updated": 0,
        "errors": 0,
        "capped": False,
    }


# ---------------------------------------------------------------------------
# 기존 partial auth 회귀 (재진입 막기 위해 마지막에 둠)
# ---------------------------------------------------------------------------


def test_get_client_partial_auth_ignored(monkeypatch):
    """USER 만 있고 PASSWORD 비어있으면 http_auth 미주입 (불완전한 자격 정보 방어)."""
    _reset_client_singleton()
    from app.core.config import get_settings

    settings = get_settings()
    monkeypatch.setattr(settings, "OPENSEARCH_USER", "admin")
    monkeypatch.setattr(settings, "OPENSEARCH_PASSWORD", "")

    factory = _CaptureFactory()
    monkeypatch.setattr(os_module, "OpenSearch", factory)

    OpenSearchService.get_client()

    assert "http_auth" not in factory.captured
