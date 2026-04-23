"""
T-101: PhotoAuditLog 확장 — _audit_photo 헬퍼가 view / share_create 등 추가
action 을 안전하게 기록하는지 검증 (in-memory sqlite).
"""

import uuid
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

from app.api.photos import _audit_photo
from app.models.models import Base, Facility, User, Photo, PhotoAuditLog


@pytest.fixture
async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with SessionLocal() as s:
        yield s
    await engine.dispose()


async def _seed(session) -> tuple[str, str]:
    fid = str(uuid.uuid4())
    uid = str(uuid.uuid4())
    pid = str(uuid.uuid4())
    session.add(Facility(id=fid, code="FAC-A1", name="T", address="X"))
    session.add(User(id=uid, email=f"{uid}@t.io", name="U", role="staff", facility_id=fid))
    session.add(Photo(id=pid, facility_id=fid, original_url="k", thumbnail_url="k"))
    await session.commit()
    return uid, pid


@pytest.mark.asyncio
async def test_audit_view_persisted(session):
    uid, pid = await _seed(session)
    _audit_photo(session, photo_id=pid, action="view", performed_by=uid, detail="ip=1.2.3.4")
    await session.commit()

    rows = (await session.execute(select(PhotoAuditLog))).scalars().all()
    assert len(rows) == 1
    row = rows[0]
    assert row.photo_id == pid
    assert row.action == "view"
    assert row.performed_by == uid
    assert row.detail == "ip=1.2.3.4"


@pytest.mark.asyncio
async def test_audit_share_create_persisted(session):
    uid, pid = await _seed(session)
    _audit_photo(session, photo_id=pid, action="share_create", performed_by=uid, detail="token=abc12345...")
    await session.commit()

    row = (await session.execute(
        select(PhotoAuditLog).filter(PhotoAuditLog.action == "share_create")
    )).scalar_one()
    assert row.detail == "token=abc12345..."


@pytest.mark.asyncio
async def test_multiple_actions_per_photo(session):
    uid, pid = await _seed(session)
    for action in ("view", "view", "share_create"):
        _audit_photo(session, photo_id=pid, action=action, performed_by=uid)
    await session.commit()

    view_count = (await session.execute(
        select(PhotoAuditLog).filter(
            PhotoAuditLog.photo_id == pid, PhotoAuditLog.action == "view"
        )
    )).scalars().all()
    assert len(view_count) == 2


@pytest.mark.asyncio
async def test_detail_is_optional(session):
    uid, pid = await _seed(session)
    _audit_photo(session, photo_id=pid, action="view", performed_by=uid)
    await session.commit()
    row = (await session.execute(select(PhotoAuditLog))).scalar_one()
    assert row.detail is None
