"""
T-124 PR2: app.services.opensearch_service.OpenSearchService 단위 테스트.

실제 OpenSearch 클러스터 없이도 비즈니스 로직 (k clamp, threshold 필터, 코사인
재분류, 페이지네이션 cap) 을 검증한다. `OpenSearchService._client` 를 가짜
client 로 갈아끼우는 방식.

T-107 의 `MAX_KNN_K` clamp + `RECLASSIFY_MAX_TOTAL` 페이지네이션 cap 이
이 파일의 핵심 회귀 방지 대상.
"""

from __future__ import annotations

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


def test_delete_resident_embeddings_uses_term_query(monkeypatch):
    fake = _install_client(monkeypatch, _FakeClient())
    OpenSearchService.delete_resident_embeddings("r-1")
    assert len(fake.delete_by_query_calls) == 1
    _, body = fake.delete_by_query_calls[0]
    assert body == {"query": {"term": {"resident_id": "r-1"}}}


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
    assert bulk_calls[0][0]["doc"] == {"resident_id": "r-new"}


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
