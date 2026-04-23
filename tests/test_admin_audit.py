"""
T-102: admin_audit 헬퍼가 AdminAuditLog 를 안전하게 기록하는지 검증.
"""

import uuid
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

from app.core.audit import admin_audit
from app.models.models import Base, Facility, User, AdminAuditLog


@pytest.fixture
async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with SessionLocal() as s:
        yield s
    await engine.dispose()


async def _seed_user(session) -> tuple[str, str]:
    fid = str(uuid.uuid4())
    uid = str(uuid.uuid4())
    session.add(Facility(id=fid, code="FAC-AA", name="T", address="X"))
    session.add(User(id=uid, email=f"{uid}@t.io", name="U", role="staff", facility_id=fid))
    await session.commit()
    return uid, fid


@pytest.mark.asyncio
async def test_guardian_approve_logged(session):
    uid, fid = await _seed_user(session)
    admin_audit(
        session,
        action="guardian_approve",
        performed_by=uid,
        target_type="guardian",
        target_id="g-123",
        facility_id=fid,
        detail="resident_id=r-1",
    )
    await session.commit()

    row = (await session.execute(select(AdminAuditLog))).scalar_one()
    assert row.action == "guardian_approve"
    assert row.performed_by == uid
    assert row.target_type == "guardian"
    assert row.target_id == "g-123"
    assert row.facility_id == fid
    assert row.detail == "resident_id=r-1"
    assert row.created_at is not None


@pytest.mark.asyncio
async def test_invitation_create_logged(session):
    uid, fid = await _seed_user(session)
    admin_audit(
        session,
        action="invitation_create",
        performed_by=uid,
        target_type="invitation",
        target_id="i-1",
        facility_id=fid,
        detail="resident_id=r-1, channel=phone",
    )
    await session.commit()

    row = (await session.execute(
        select(AdminAuditLog).filter(AdminAuditLog.action == "invitation_create")
    )).scalar_one()
    assert row.detail == "resident_id=r-1, channel=phone"


@pytest.mark.asyncio
async def test_resident_update_records_changed_fields(session):
    uid, fid = await _seed_user(session)
    admin_audit(
        session,
        action="resident_update",
        performed_by=uid,
        target_type="resident",
        target_id="r-1",
        facility_id=fid,
        detail="fields=name,medical_notes",
    )
    await session.commit()

    row = (await session.execute(select(AdminAuditLog))).scalar_one()
    # PII 자체가 아니라 변경된 필드명만 남도록 확인.
    assert "fields=" in (row.detail or "")
    assert "name" in row.detail


@pytest.mark.asyncio
async def test_optional_facility_id_and_detail(session):
    uid, _ = await _seed_user(session)
    admin_audit(
        session,
        action="resident_face_delete",
        performed_by=uid,
        target_type="resident",
        target_id="r-1",
    )
    await session.commit()

    row = (await session.execute(select(AdminAuditLog))).scalar_one()
    assert row.facility_id is None
    assert row.detail is None


@pytest.mark.asyncio
async def test_multiple_actions_accumulate(session):
    uid, fid = await _seed_user(session)
    for act in ("guardian_approve", "guardian_reject", "invitation_create"):
        admin_audit(
            session, action=act, performed_by=uid,
            target_type="x", target_id="t-1", facility_id=fid,
        )
    await session.commit()

    rows = (await session.execute(select(AdminAuditLog))).scalars().all()
    assert {r.action for r in rows} == {"guardian_approve", "guardian_reject", "invitation_create"}
