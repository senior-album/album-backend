"""
T-106: `_enforce_photo_queue_capacity` 가 pending 백로그 cap 을 넘을 때
429 / 503 을 던지는지 검증.
"""

import uuid
import pytest
from unittest.mock import patch
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

from app.api.photos import _enforce_photo_queue_capacity
from app.models.models import Base, Facility, PhotoProcessingJob, Photo


@pytest.fixture
async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with SessionLocal() as s:
        yield s
    await engine.dispose()


async def _seed_facility(session, code="FAC-Q1") -> str:
    fid = str(uuid.uuid4())
    session.add(Facility(id=fid, code=code, name="T", address="X"))
    await session.commit()
    return fid


async def _seed_pending(session, facility_id: str, n: int):
    for _ in range(n):
        pid = str(uuid.uuid4())
        # Photo FK — 최소 필드
        session.add(Photo(id=pid, facility_id=facility_id, original_url="k", thumbnail_url="k"))
        session.add(PhotoProcessingJob(
            id=str(uuid.uuid4()),
            photo_id=pid,
            facility_id=facility_id,
            status="pending",
        ))
    await session.commit()


@pytest.mark.asyncio
async def test_allows_under_cap(session):
    fid = await _seed_facility(session)
    await _seed_pending(session, fid, 3)
    # cap 이 훨씬 크니 통과.
    await _enforce_photo_queue_capacity(session, fid, pending_to_add=2)


@pytest.mark.asyncio
async def test_rejects_over_per_facility_cap(session):
    fid = await _seed_facility(session)
    await _seed_pending(session, fid, 10)
    # per-facility cap 을 5로 낮춰 초과 케이스 만들기.
    with patch("app.api.photos.get_settings") as mocked:
        mocked.return_value.PHOTO_QUEUE_MAX_PENDING_PER_FACILITY = 5
        mocked.return_value.PHOTO_QUEUE_MAX_PENDING_TOTAL = 10_000
        with pytest.raises(HTTPException) as exc:
            await _enforce_photo_queue_capacity(session, fid, pending_to_add=1)
        assert exc.value.status_code == 429
        assert exc.value.headers.get("Retry-After") == "60"


@pytest.mark.asyncio
async def test_rejects_over_total_cap(session):
    # 다른 시설 여러 개로 total 만 초과하도록 만든다.
    f1 = await _seed_facility(session, code="FAC-A")
    f2 = await _seed_facility(session, code="FAC-B")
    await _seed_pending(session, f1, 5)
    await _seed_pending(session, f2, 5)
    with patch("app.api.photos.get_settings") as mocked:
        # per-facility 는 후하게, total 만 10 으로 낮게.
        mocked.return_value.PHOTO_QUEUE_MAX_PENDING_PER_FACILITY = 1_000
        mocked.return_value.PHOTO_QUEUE_MAX_PENDING_TOTAL = 10
        with pytest.raises(HTTPException) as exc:
            await _enforce_photo_queue_capacity(session, f1, pending_to_add=1)
        assert exc.value.status_code == 503


@pytest.mark.asyncio
async def test_counts_only_pending(session):
    fid = await _seed_facility(session)
    # processing / completed 는 pending cap 계산에서 제외되어야.
    await _seed_pending(session, fid, 3)
    # pending 중 1개를 completed 로 변경해서 pending=2 가 되게.
    from sqlalchemy import select
    res = await session.execute(select(PhotoProcessingJob).limit(1))
    job = res.scalar_one()
    job.status = "completed"
    await session.commit()

    with patch("app.api.photos.get_settings") as mocked:
        mocked.return_value.PHOTO_QUEUE_MAX_PENDING_PER_FACILITY = 3
        mocked.return_value.PHOTO_QUEUE_MAX_PENDING_TOTAL = 100
        # pending=2, add=1 -> 3 == cap, 통과.
        await _enforce_photo_queue_capacity(session, fid, pending_to_add=1)
        # pending=2, add=2 -> 4 > cap, 거절.
        with pytest.raises(HTTPException) as exc:
            await _enforce_photo_queue_capacity(session, fid, pending_to_add=2)
        assert exc.value.status_code == 429
