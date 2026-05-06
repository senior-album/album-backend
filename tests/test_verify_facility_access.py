"""
T-105: verify_facility_access 가 JWT payload 가 아닌 DB 의 User.facility_id /
is_active 를 재확인하는지 검증.
"""

import uuid
import pytest
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

from app.core.security import verify_facility_access
from app.models.models import Base, User, Facility


@pytest.fixture
async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with SessionLocal() as s:
        yield s
    await engine.dispose()


async def _make_facility(session, code="FAC-T1") -> Facility:
    f = Facility(id=str(uuid.uuid4()), code=code, name="T", address="X")
    session.add(f)
    await session.commit()
    await session.refresh(f)
    return f


async def _make_user(session, *, facility_id: str | None, is_active: bool = True) -> User:
    u = User(
        id=str(uuid.uuid4()),
        email=f"u-{uuid.uuid4().hex[:6]}@t.io",
        name="U",
        role="staff",
        facility_id=facility_id,
        is_active=is_active,
        # T-056: verify_facility_access 가 미승인 staff 차단 — 기본 시드는 승인 완료 상태.
        is_staff_approved=True,
    )
    session.add(u)
    await session.commit()
    await session.refresh(u)
    return u


@pytest.mark.asyncio
async def test_allows_matching_facility(session):
    f = await _make_facility(session)
    u = await _make_user(session, facility_id=f.id)
    # JWT 클레임과 DB 모두 일치.
    await verify_facility_access({"user_id": u.id, "facility_id": f.id}, f.id, session)


@pytest.mark.asyncio
async def test_blocks_when_jwt_says_yes_but_db_says_no(session):
    """T-105 핵심: JWT 에는 facility_id 가 남아있지만 DB 에서 제거된 사용자."""
    f = await _make_facility(session)
    u = await _make_user(session, facility_id=None)  # DB 상 소속 해제
    stale_jwt = {"user_id": u.id, "facility_id": f.id}  # 탈취된 토큰엔 여전히 facility
    with pytest.raises(HTTPException) as exc:
        await verify_facility_access(stale_jwt, f.id, session)
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_blocks_when_user_deactivated(session):
    f = await _make_facility(session)
    u = await _make_user(session, facility_id=f.id, is_active=False)
    with pytest.raises(HTTPException) as exc:
        await verify_facility_access({"user_id": u.id, "facility_id": f.id}, f.id, session)
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_blocks_when_user_moved_to_different_facility(session):
    f1 = await _make_facility(session, code="FAC-A")
    f2 = await _make_facility(session, code="FAC-B")
    u = await _make_user(session, facility_id=f2.id)
    # JWT 는 f1 을 말하지만 DB 는 f2 로 이동함.
    with pytest.raises(HTTPException) as exc:
        await verify_facility_access({"user_id": u.id, "facility_id": f1.id}, f1.id, session)
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_blocks_when_user_not_found(session):
    with pytest.raises(HTTPException) as exc:
        await verify_facility_access({"user_id": "nonexistent"}, "any", session)
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_blocks_when_no_user_id(session):
    with pytest.raises(HTTPException) as exc:
        await verify_facility_access({}, "any", session)
    assert exc.value.status_code == 401
