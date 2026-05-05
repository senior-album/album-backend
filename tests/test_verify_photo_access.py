"""
verify_photo_access 역할별 분기 검증:
  - staff: 자기 시설 사진만 접근 가능
  - guardian: 승인된 자기 어르신의 공개 사진만 접근 가능
  - 다른 role: 차단
"""

import uuid
import pytest
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

from app.core.security import verify_photo_access
from app.models.models import (
    Base,
    User,
    Facility,
    Resident,
    Photo,
    PhotoResident,
    Guardian,
)


@pytest.fixture
async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with SessionLocal() as s:
        yield s
    await engine.dispose()


async def _facility(session, code="FAC-T"):
    f = Facility(id=str(uuid.uuid4()), code=code, name="T", address="X")
    session.add(f)
    await session.commit()
    return f


async def _resident(session, facility_id):
    from tests._pii_seed import make_resident
    hex6 = uuid.uuid4().hex[:6]
    r = make_resident(facility_id=facility_id, name=f"R-{hex6}", code=f"R-{hex6}")
    session.add(r)
    await session.commit()
    return r


async def _user(session, *, role, facility_id=None, is_active=True):
    u = User(
        id=str(uuid.uuid4()),
        email=f"u-{uuid.uuid4().hex[:6]}@t.io",
        name="U",
        role=role,
        facility_id=facility_id,
        is_active=is_active,
    )
    session.add(u)
    await session.commit()
    return u


async def _photo(session, *, facility_id, resident_id=None, is_public=True):
    p = Photo(
        id=str(uuid.uuid4()),
        facility_id=facility_id,
        resident_id=resident_id,
        original_url="key://x",
        thumbnail_url="key://x",
        is_public=is_public,
    )
    session.add(p)
    await session.commit()
    return p


async def _guardian(session, *, user_id, resident_id, is_approved=True):
    g = Guardian(
        id=str(uuid.uuid4()),
        user_id=user_id,
        resident_id=resident_id,
        is_approved=is_approved,
    )
    session.add(g)
    await session.commit()
    return g


# ─────────────────────────────── staff 경로 ───────────────────────────────

@pytest.mark.asyncio
async def test_staff_same_facility_allowed(session):
    f = await _facility(session)
    u = await _user(session, role="staff", facility_id=f.id)
    p = await _photo(session, facility_id=f.id)
    await verify_photo_access({"user_id": u.id, "role": "staff"}, p, session)


@pytest.mark.asyncio
async def test_staff_cross_facility_denied(session):
    f1 = await _facility(session, code="FAC-A")
    f2 = await _facility(session, code="FAC-B")
    staff = await _user(session, role="staff", facility_id=f1.id)
    p = await _photo(session, facility_id=f2.id)  # 시설 B 의 사진
    with pytest.raises(HTTPException) as exc:
        await verify_photo_access({"user_id": staff.id, "role": "staff"}, p, session)
    assert exc.value.status_code == 403


# ────────────────────────────── guardian 경로 ──────────────────────────────

@pytest.mark.asyncio
async def test_guardian_public_photo_of_own_resident_via_legacy_field(session):
    f = await _facility(session)
    r = await _resident(session, f.id)
    u = await _user(session, role="guardian")
    await _guardian(session, user_id=u.id, resident_id=r.id)
    p = await _photo(session, facility_id=f.id, resident_id=r.id, is_public=True)
    await verify_photo_access({"user_id": u.id, "role": "guardian"}, p, session)


@pytest.mark.asyncio
async def test_guardian_public_photo_of_own_resident_via_many_to_many(session):
    f = await _facility(session)
    r = await _resident(session, f.id)
    u = await _user(session, role="guardian")
    await _guardian(session, user_id=u.id, resident_id=r.id)
    p = await _photo(session, facility_id=f.id, resident_id=None, is_public=True)
    session.add(PhotoResident(photo_id=p.id, resident_id=r.id))
    await session.commit()
    await verify_photo_access({"user_id": u.id, "role": "guardian"}, p, session)


@pytest.mark.asyncio
async def test_guardian_private_photo_denied(session):
    """공개되지 않은 사진은 본인 어르신이어도 접근 불가."""
    f = await _facility(session)
    r = await _resident(session, f.id)
    u = await _user(session, role="guardian")
    await _guardian(session, user_id=u.id, resident_id=r.id)
    p = await _photo(session, facility_id=f.id, resident_id=r.id, is_public=False)
    with pytest.raises(HTTPException) as exc:
        await verify_photo_access({"user_id": u.id, "role": "guardian"}, p, session)
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_guardian_other_resident_denied(session):
    """다른 어르신 사진은 공개되어 있어도 접근 불가."""
    f = await _facility(session)
    r_mine = await _resident(session, f.id)
    r_other = await _resident(session, f.id)
    u = await _user(session, role="guardian")
    await _guardian(session, user_id=u.id, resident_id=r_mine.id)
    p = await _photo(session, facility_id=f.id, resident_id=r_other.id, is_public=True)
    with pytest.raises(HTTPException) as exc:
        await verify_photo_access({"user_id": u.id, "role": "guardian"}, p, session)
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_guardian_not_approved_denied(session):
    f = await _facility(session)
    r = await _resident(session, f.id)
    u = await _user(session, role="guardian")
    await _guardian(session, user_id=u.id, resident_id=r.id, is_approved=False)
    p = await _photo(session, facility_id=f.id, resident_id=r.id, is_public=True)
    with pytest.raises(HTTPException) as exc:
        await verify_photo_access({"user_id": u.id, "role": "guardian"}, p, session)
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_guardian_without_resident_denied(session):
    """시설 코드 요청만 하고 배정 전인 보호자는 사진 접근 불가."""
    f = await _facility(session)
    u = await _user(session, role="guardian")
    await _guardian(session, user_id=u.id, resident_id=None)
    p = await _photo(session, facility_id=f.id, is_public=True)
    with pytest.raises(HTTPException) as exc:
        await verify_photo_access({"user_id": u.id, "role": "guardian"}, p, session)
    assert exc.value.status_code == 403


# ────────────────────────────── 기타 role ──────────────────────────────

@pytest.mark.asyncio
async def test_unknown_role_denied(session):
    f = await _facility(session)
    p = await _photo(session, facility_id=f.id, is_public=True)
    with pytest.raises(HTTPException) as exc:
        await verify_photo_access({"user_id": "x", "role": "user"}, p, session)
    assert exc.value.status_code == 403
