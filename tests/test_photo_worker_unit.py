"""
T-124 PR2: app.services.photo_worker 단위 테스트.

워커는 (1) `process_single_photo` (단일 사진 분류) 와 (2) `poll_and_process`
(pending → processing → completed/failed/retry 상태 전이) 가 핵심. ML/스토리지/
OpenSearch 의존성을 mock 으로 떼고 비즈니스 로직만 본다.

DB 는 `:memory:` SQLite 로 진짜 ORM 세션을 띄운다 — 워커가 SQL 을 직접 쏘기
때문에 mock DB 로는 의미가 약하다.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime
from io import BytesIO

import numpy as np
import pytest
from PIL import Image as PILImage
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.models.models import (
    Base,
    Facility,
    Photo,
    PhotoFace,
    PhotoProcessingJob,
    PhotoResident,
)
from app.services import photo_worker as worker_module
from app.services.photo_worker import (
    poll_and_process,
    process_single_photo,
    start_worker,
    stop_worker,
)


# ---------------------------------------------------------------------------
# 가짜 의존성: 스토리지 / FaceService / OpenSearch
# ---------------------------------------------------------------------------


class _FakeStorage:
    def __init__(self, image_bytes: bytes):
        self._bytes = image_bytes

    async def download_file(self, _url: str):
        return self._bytes


def _make_jpeg_bytes(size=(64, 64)) -> bytes:
    """PILImage.open 이 RGB 로 디코딩할 수 있는 작은 이미지 바이트."""
    buf = BytesIO()
    PILImage.new("RGB", size, color=(180, 100, 80)).save(buf, format="JPEG")
    return buf.getvalue()


def _patch_runtime(
    monkeypatch,
    *,
    image_bytes: bytes | None = None,
    detect_faces=lambda arr: [],
    is_available: bool = True,
    knn_results: list | None = None,
    knn_raises: bool = False,
    store_raises: bool = False,
):
    """photo_worker 가 import 한 모듈 심볼들을 한 번에 갈아끼운다."""
    monkeypatch.setattr(
        worker_module, "get_storage", lambda: _FakeStorage(image_bytes or _make_jpeg_bytes())
    )

    fake_face = type("F", (), {})()
    fake_face.detect_faces = staticmethod(detect_faces)
    fake_face.is_available = staticmethod(lambda: is_available)
    monkeypatch.setattr(worker_module, "FaceService", fake_face)

    knn_results = knn_results if knn_results is not None else []

    def _search_similar(*, embedding, facility_id, k, threshold):
        if knn_raises:
            raise RuntimeError("opensearch down")
        return list(knn_results)

    def _store_embedding(**_kwargs):
        if store_raises:
            raise RuntimeError("os write fail")

    fake_os = type("O", (), {})()
    fake_os.search_similar = staticmethod(_search_similar)
    fake_os.store_embedding = staticmethod(_store_embedding)
    monkeypatch.setattr(worker_module, "OpenSearchService", fake_os)


# ---------------------------------------------------------------------------
# DB fixture
# ---------------------------------------------------------------------------


@pytest.fixture
async def db():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with SessionLocal() as s:
        yield s
    await engine.dispose()


async def _seed_facility(db: AsyncSession) -> Facility:
    f = Facility(id=str(uuid.uuid4()), code="FAC-W1", name="W", address="X")
    db.add(f)
    await db.commit()
    return f


async def _seed_photo(db: AsyncSession, facility_id: str) -> Photo:
    p = Photo(
        id=str(uuid.uuid4()),
        facility_id=facility_id,
        original_url="local://photo.jpg",
        thumbnail_url="local://thumb.jpg",
    )
    db.add(p)
    await db.commit()
    await db.refresh(p)
    return p


# ---------------------------------------------------------------------------
# process_single_photo — 얼굴 감지 / 매칭 / DB 레코드
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_process_single_photo_no_face(monkeypatch, db: AsyncSession):
    """얼굴이 하나도 안 잡히면 photo.processing_status='no_face', is_processed=False."""
    _patch_runtime(monkeypatch, detect_faces=lambda arr: [])
    fac = await _seed_facility(db)
    photo = await _seed_photo(db, fac.id)

    await process_single_photo(photo, fac.id, db)
    await db.commit()

    assert photo.is_processed is False
    assert photo.processing_status == "no_face"
    # PhotoFace / PhotoResident 도 안 만들어진다.
    assert (await db.execute(select(PhotoFace))).scalars().all() == []
    assert (await db.execute(select(PhotoResident))).scalars().all() == []


@pytest.mark.asyncio
async def test_process_single_photo_unmatched_face(monkeypatch, db: AsyncSession):
    """얼굴은 잡혔지만 매칭 X → status='detected_unmatched', PhotoFace 1건."""
    face = {"embedding": [0.1] * 4, "bbox": [0, 0, 10, 10], "det_score": 0.9}
    _patch_runtime(monkeypatch, detect_faces=lambda arr: [face], knn_results=[])
    fac = await _seed_facility(db)
    photo = await _seed_photo(db, fac.id)

    await process_single_photo(photo, fac.id, db)
    await db.commit()

    assert photo.is_processed is True
    assert photo.processing_status == "detected_unmatched"
    assert photo.resident_id is None

    pf = (await db.execute(select(PhotoFace))).scalars().all()
    assert len(pf) == 1
    assert pf[0].resident_id is None
    # 매칭 신뢰도 없음 → 기본 0.5, is_confirmed=False (< 0.8)
    assert pf[0].confidence == 0.5
    assert pf[0].is_confirmed is False


@pytest.mark.asyncio
async def test_process_single_photo_high_confidence_match(monkeypatch, db: AsyncSession):
    """confidence ≥ 0.8 매칭 → status='classified', resident_id 채워짐, is_confirmed=True."""
    face = {"embedding": [0.2] * 4, "bbox": [0, 0, 20, 20], "det_score": 0.95}
    _patch_runtime(
        monkeypatch,
        detect_faces=lambda arr: [face],
        knn_results=[("res-1", 0.92)],
    )
    fac = await _seed_facility(db)
    photo = await _seed_photo(db, fac.id)

    await process_single_photo(photo, fac.id, db)
    await db.commit()

    assert photo.processing_status == "classified"
    assert photo.resident_id == "res-1"

    pf = (await db.execute(select(PhotoFace))).scalars().all()
    assert pf[0].is_confirmed is True
    assert pf[0].confidence == pytest.approx(0.92)
    assert pf[0].resident_id == "res-1"

    # PhotoResident 다대다도 1건 (best confidence 보존).
    pr = (await db.execute(select(PhotoResident))).scalars().all()
    assert len(pr) == 1
    assert pr[0].resident_id == "res-1"
    assert pr[0].confidence == pytest.approx(0.92)


@pytest.mark.asyncio
async def test_process_single_photo_keeps_highest_confidence_per_resident(
    monkeypatch, db: AsyncSession
):
    """같은 입소자가 여러 얼굴에서 매칭되면 PhotoResident 에 최고 confidence 만 남는다."""
    face_a = {"embedding": [0.1] * 4, "bbox": [0, 0, 10, 10], "det_score": 0.8}
    face_b = {"embedding": [0.2] * 4, "bbox": [10, 10, 30, 30], "det_score": 0.9}

    # 두 얼굴 모두 같은 res-1 로 매칭, 두 번째가 더 높은 점수.
    call_idx = {"n": 0}
    sequences = [[("res-1", 0.65)], [("res-1", 0.95)]]

    def _search(**_):
        out = sequences[call_idx["n"]]
        call_idx["n"] += 1
        return out

    _patch_runtime(monkeypatch, detect_faces=lambda arr: [face_a, face_b])
    monkeypatch.setattr(worker_module.OpenSearchService, "search_similar", _search)

    fac = await _seed_facility(db)
    photo = await _seed_photo(db, fac.id)

    await process_single_photo(photo, fac.id, db)
    await db.commit()

    pr = (await db.execute(select(PhotoResident))).scalars().all()
    assert len(pr) == 1
    assert pr[0].confidence == pytest.approx(0.95)


@pytest.mark.asyncio
async def test_process_single_photo_swallows_opensearch_search_failure(
    monkeypatch, db: AsyncSession
):
    """OpenSearch search 가 죽어도 워커는 죽지 않고 unmatched 로 처리해야."""
    face = {"embedding": [0.1] * 4, "bbox": [0, 0, 10, 10], "det_score": 0.8}
    _patch_runtime(monkeypatch, detect_faces=lambda arr: [face], knn_raises=True)
    fac = await _seed_facility(db)
    photo = await _seed_photo(db, fac.id)

    await process_single_photo(photo, fac.id, db)
    await db.commit()

    assert photo.processing_status == "detected_unmatched"
    pf = (await db.execute(select(PhotoFace))).scalars().all()
    assert len(pf) == 1


@pytest.mark.asyncio
async def test_process_single_photo_swallows_opensearch_store_failure(
    monkeypatch, db: AsyncSession
):
    """임베딩 저장 실패도 비즈니스 흐름을 막지 않아야 (DB 레코드는 정상 생성)."""
    face = {"embedding": [0.1] * 4, "bbox": [0, 0, 10, 10], "det_score": 0.8}
    _patch_runtime(
        monkeypatch,
        detect_faces=lambda arr: [face],
        knn_results=[("res-1", 0.9)],
        store_raises=True,
    )
    fac = await _seed_facility(db)
    photo = await _seed_photo(db, fac.id)

    await process_single_photo(photo, fac.id, db)
    await db.commit()

    assert photo.processing_status == "classified"


@pytest.mark.asyncio
async def test_process_single_photo_skips_face_with_none_embedding(
    monkeypatch, db: AsyncSession
):
    """embedding=None 인 얼굴은 PhotoFace 에 안 쌓이고, 그래도 detected 로 카운트됨."""
    face_bad = {"embedding": None, "bbox": [0, 0, 5, 5], "det_score": 0.7}
    _patch_runtime(monkeypatch, detect_faces=lambda arr: [face_bad])
    fac = await _seed_facility(db)
    photo = await _seed_photo(db, fac.id)

    await process_single_photo(photo, fac.id, db)
    await db.commit()

    # detect_faces 가 1개 반환했으니 detected, 그러나 embedding=None 이라 PhotoFace 미생성.
    assert photo.is_processed is True
    assert photo.processing_status == "detected_unmatched"
    assert (await db.execute(select(PhotoFace))).scalars().all() == []


@pytest.mark.asyncio
async def test_process_single_photo_raises_when_storage_returns_none(
    monkeypatch, db: AsyncSession
):
    """원본 다운로드가 None 이면 호출자 (poll_and_process) 가 잡을 수 있게 예외 전파."""

    class _DeadStorage:
        async def download_file(self, _url):
            return None

    monkeypatch.setattr(worker_module, "get_storage", lambda: _DeadStorage())
    fac = await _seed_facility(db)
    photo = await _seed_photo(db, fac.id)

    with pytest.raises(Exception, match="Failed to download"):
        await process_single_photo(photo, fac.id, db)


# ---------------------------------------------------------------------------
# poll_and_process — 상태 전이 + retry 로직
# ---------------------------------------------------------------------------


def _patch_session_scope(monkeypatch, db: AsyncSession):
    """`Database.session_scope` 를 우리 db fixture 로 교체."""
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def _scope():
        # 워커가 commit 하면 fixture 의 같은 세션이 commit 되도록 그대로 yield.
        yield db

    monkeypatch.setattr(worker_module.Database, "session_scope", staticmethod(_scope))


async def _seed_pending_job(
    db: AsyncSession, *, photo: Photo | None = None, max_retries: int = 3
) -> PhotoProcessingJob:
    job = PhotoProcessingJob(
        id=str(uuid.uuid4()),
        photo_id=photo.id if photo else str(uuid.uuid4()),
        facility_id=photo.facility_id if photo else "ghost-fac",
        status="pending",
        max_retries=max_retries,
    )
    db.add(job)
    await db.commit()
    return job


@pytest.mark.asyncio
async def test_poll_and_process_returns_false_when_no_pending_jobs(
    monkeypatch, db: AsyncSession
):
    _patch_session_scope(monkeypatch, db)
    _patch_runtime(monkeypatch)
    assert await poll_and_process() is False


@pytest.mark.asyncio
async def test_poll_and_process_marks_completed_on_success(monkeypatch, db: AsyncSession):
    fac = await _seed_facility(db)
    photo = await _seed_photo(db, fac.id)
    job = await _seed_pending_job(db, photo=photo)

    _patch_session_scope(monkeypatch, db)
    _patch_runtime(monkeypatch, detect_faces=lambda arr: [])

    assert await poll_and_process() is True
    await db.refresh(job)
    assert job.status == "completed"
    assert job.completed_at is not None


@pytest.mark.asyncio
async def test_poll_and_process_fails_when_photo_missing(monkeypatch, db: AsyncSession):
    """photo_id 가 dangling 인 job → status='failed', error_message 설정."""
    job = await _seed_pending_job(db)  # photo 안 만들고

    _patch_session_scope(monkeypatch, db)
    _patch_runtime(monkeypatch)

    assert await poll_and_process() is True
    await db.refresh(job)
    assert job.status == "failed"
    assert job.error_message == "Photo not found"


@pytest.mark.asyncio
async def test_poll_and_process_fails_when_face_model_unavailable(
    monkeypatch, db: AsyncSession
):
    """FaceService.is_available()=False → job=failed, photo.processing_status='no_model'."""
    fac = await _seed_facility(db)
    photo = await _seed_photo(db, fac.id)
    job = await _seed_pending_job(db, photo=photo)

    _patch_session_scope(monkeypatch, db)
    _patch_runtime(monkeypatch, is_available=False)

    assert await poll_and_process() is True
    await db.refresh(job)
    await db.refresh(photo)
    assert job.status == "failed"
    assert "model not available" in (job.error_message or "")
    assert photo.processing_status == "no_model"


@pytest.mark.asyncio
async def test_poll_and_process_retries_when_under_max_retries(
    monkeypatch, db: AsyncSession
):
    """process_single_photo 가 터지고 retry_count < max_retries → status='pending', retry_count+=1."""
    fac = await _seed_facility(db)
    photo = await _seed_photo(db, fac.id)
    job = await _seed_pending_job(db, photo=photo, max_retries=3)

    _patch_session_scope(monkeypatch, db)

    def _boom(arr):
        raise RuntimeError("model exploded")

    _patch_runtime(monkeypatch, detect_faces=_boom)

    assert await poll_and_process() is True
    await db.refresh(job)
    assert job.status == "pending"
    assert job.retry_count == 1
    assert "Retry 1" in (job.error_message or "")


@pytest.mark.asyncio
async def test_poll_and_process_marks_failed_at_max_retries(monkeypatch, db: AsyncSession):
    """retry_count 가 max_retries 도달 직전이면 다음 실패에서 failed 로 전이."""
    fac = await _seed_facility(db)
    photo = await _seed_photo(db, fac.id)
    job = await _seed_pending_job(db, photo=photo, max_retries=3)
    job.retry_count = 2  # 이번 실패가 3 번째 — max 도달.
    await db.commit()

    _patch_session_scope(monkeypatch, db)
    _patch_runtime(monkeypatch, detect_faces=lambda arr: (_ for _ in ()).throw(RuntimeError("nope")))

    assert await poll_and_process() is True
    await db.refresh(job)
    assert job.status == "failed"
    assert job.retry_count == 3
    assert job.completed_at is not None


# ---------------------------------------------------------------------------
# start_worker / stop_worker — 태스크 라이프사이클
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_start_and_stop_worker_creates_then_cancels_task(monkeypatch):
    """start → asyncio.Task 생성, stop → cancel 요청."""
    # 실제 worker_loop 가 DB 를 만지지 않도록 가짜 코루틴으로 교체.
    sleep_event = asyncio.Event()

    async def _idle_loop():
        try:
            await sleep_event.wait()
        except asyncio.CancelledError:
            raise

    monkeypatch.setattr(worker_module, "worker_loop", _idle_loop)
    # 모듈 레벨 _worker_task 캐시 초기화.
    monkeypatch.setattr(worker_module, "_worker_task", None)

    start_worker()
    task = worker_module._worker_task
    assert task is not None and not task.done()

    stop_worker()
    # cancel 요청은 했지만 await 전에는 done 이 보장 안 됨 — 한 번 yield.
    try:
        await asyncio.wait_for(task, timeout=1.0)
    except (asyncio.CancelledError, asyncio.TimeoutError):
        pass
    assert task.cancelled() or task.done()


@pytest.mark.asyncio
async def test_start_worker_is_idempotent_when_task_running(monkeypatch):
    """이미 동작 중이면 새 태스크를 만들지 않는다."""
    sleep_event = asyncio.Event()

    async def _idle_loop():
        await sleep_event.wait()

    monkeypatch.setattr(worker_module, "worker_loop", _idle_loop)
    monkeypatch.setattr(worker_module, "_worker_task", None)

    start_worker()
    first = worker_module._worker_task
    start_worker()
    second = worker_module._worker_task
    assert first is second

    sleep_event.set()
    try:
        await asyncio.wait_for(first, timeout=1.0)
    except asyncio.TimeoutError:
        first.cancel()


def test_stop_worker_no_op_when_no_task(monkeypatch):
    """_worker_task 가 None / done 이면 stop 은 조용히 통과."""
    monkeypatch.setattr(worker_module, "_worker_task", None)
    stop_worker()  # raise 없이 통과.
