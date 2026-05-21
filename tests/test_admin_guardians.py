"""
T-146: app/api/admin.py /admin/guardians — 보호자 요청 전체 시설 across 모니터링.

검증 대상:
- 권한 가드: 401 / 403
- 전체 시설 across 조회 + facility_name / user 정보 조인
- 상태(state) 필터: pending / approved / rejected / 잘못된 값 → 400
- facility_id 필터
- 페이지네이션
- resident 미배정 (시설코드 요청) row 도 포함되며 resident_name=None
"""

from __future__ import annotations

import os as _os
import platform as _platform
import sys as _sys
import types as _types

# Windows 전용 stub — 자세한 배경은 test_admin_users.py 상단 주석.
if _platform.system() == "Windows" and "magic" not in _sys.modules:
    _stub = _types.ModuleType("magic")
    _stub.from_buffer = lambda data, mime=False: "image/jpeg"  # type: ignore[attr-defined]
    _stub.from_file = lambda path, mime=False: "image/jpeg"  # type: ignore[attr-defined]
    _sys.modules["magic"] = _stub

_os.environ.setdefault("JWT_SECRET", "test-secret-value-for-jwt-32-bytes-min")
_os.environ.setdefault("JWT_REFRESH_SECRET", "test-refresh-secret-32bytes-minimum")
_os.environ.setdefault("RESIDENT_PII_KEK", "0" * 64)
_os.environ.setdefault("RESIDENT_NAME_HMAC_KEY", "1" * 64)

_os.environ.setdefault("USER_PHONE_HMAC_KEY", "2" * 64)
import uuid
from datetime import datetime

import pytest

from app.core.security import SecurityService
from app.models.models import Facility, Guardian, Resident, User


async def _seed_facility(session, *, code: str, name: str = "T") -> Facility:
    fac = Facility(id=str(uuid.uuid4()), code=code, name=name, address="X")
    session.add(fac)
    await session.commit()
    return fac


async def _seed_user(
    session, *, email: str, role: str = "guardian", is_operator: bool = False, facility_id=None
) -> User:
    u = User(
        id=str(uuid.uuid4()),
        email=email,
        name="이름",
        password_hash="$2b$12$dummy" + "x" * 50,
        role=role,
        is_admin=False,
        is_operator=is_operator,
        is_active=True,
        facility_id=facility_id,
    )
    session.add(u)
    await session.commit()
    return u


async def _seed_guardian(
    session, *, user_id: str, facility_id: str | None, resident_id: str | None,
    is_approved: bool = False, is_rejected: bool = False, message: str = "",
) -> Guardian:
    g = Guardian(
        id=str(uuid.uuid4()),
        user_id=user_id,
        facility_id=facility_id,
        resident_id=resident_id,
        is_approved=is_approved,
        is_rejected=is_rejected,
        request_message=message,
        relationship_type="자녀",
    )
    session.add(g)
    await session.commit()
    return g


def _auth_cookies(user: User) -> dict[str, str]:
    token = SecurityService.create_access_token(
        data={"sub": user.id, "email": user.email, "role": user.role, "facility_id": user.facility_id}
    )
    return {"access_token": token}


@pytest.mark.asyncio
async def test_list_guardians_requires_operator(integration_client, integration_db):
    _SessionLocal, session = integration_db
    fac = await _seed_facility(session, code="FAC-1")
    staff = await _seed_user(session, email="s@x.io", role="staff", facility_id=fac.id)
    resp = await integration_client.get("/admin/guardians", cookies=_auth_cookies(staff))
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_list_guardians_returns_all_with_joins(integration_client, integration_db):
    _SessionLocal, session = integration_db
    fac1 = await _seed_facility(session, code="FAC-1", name="A원")
    fac2 = await _seed_facility(session, code="FAC-2", name="B원")
    operator = await _seed_user(session, email="op@x.io", role="staff", is_operator=True, facility_id=fac1.id)

    g_user1 = await _seed_user(session, email="g1@x.io", role="guardian")
    g_user2 = await _seed_user(session, email="g2@x.io", role="guardian")
    from tests._pii_seed import make_resident
    res = make_resident(facility_id=fac1.id, name="할머니", code="RES-1")
    session.add(res)
    await session.commit()

    # 시설1+resident 매칭 / 시설2 시설코드 only (resident=None)
    await _seed_guardian(session, user_id=g_user1.id, facility_id=fac1.id, resident_id=res.id, message="m1")
    await _seed_guardian(session, user_id=g_user2.id, facility_id=fac2.id, resident_id=None, message="m2")

    resp = await integration_client.get("/admin/guardians", cookies=_auth_cookies(operator))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total"] == 2

    by_email = {item["user_email"]: item for item in body["items"]}
    g1 = by_email["g1@x.io"]
    assert g1["facility_name"] == "A원"
    assert g1["resident_name"] == "할머니"
    assert g1["request_message"] == "m1"
    assert g1["is_approved"] is False

    g2 = by_email["g2@x.io"]
    assert g2["facility_name"] == "B원"
    assert g2["resident_name"] is None  # 미배정


@pytest.mark.asyncio
async def test_list_guardians_state_filter(integration_client, integration_db):
    _SessionLocal, session = integration_db
    fac = await _seed_facility(session, code="FAC-1")
    operator = await _seed_user(session, email="op@x.io", role="staff", is_operator=True, facility_id=fac.id)

    u_pending = await _seed_user(session, email="p@x.io", role="guardian")
    u_approved = await _seed_user(session, email="a@x.io", role="guardian")
    u_rejected = await _seed_user(session, email="r@x.io", role="guardian")

    await _seed_guardian(session, user_id=u_pending.id, facility_id=fac.id, resident_id=None)
    await _seed_guardian(session, user_id=u_approved.id, facility_id=fac.id, resident_id=None, is_approved=True)
    await _seed_guardian(session, user_id=u_rejected.id, facility_id=fac.id, resident_id=None, is_rejected=True)

    for state, expected_email in [("pending", "p@x.io"), ("approved", "a@x.io"), ("rejected", "r@x.io")]:
        resp = await integration_client.get(
            f"/admin/guardians?state={state}", cookies=_auth_cookies(operator)
        )
        body = resp.json()
        assert body["total"] == 1, f"state={state} expected 1 row, got {body['total']}"
        assert body["items"][0]["user_email"] == expected_email


@pytest.mark.asyncio
async def test_list_guardians_invalid_state_400(integration_client, integration_db):
    _SessionLocal, session = integration_db
    fac = await _seed_facility(session, code="FAC-1")
    operator = await _seed_user(session, email="op@x.io", role="staff", is_operator=True, facility_id=fac.id)

    resp = await integration_client.get(
        "/admin/guardians?state=garbage", cookies=_auth_cookies(operator)
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_list_guardians_facility_filter(integration_client, integration_db):
    _SessionLocal, session = integration_db
    fac1 = await _seed_facility(session, code="FAC-1")
    fac2 = await _seed_facility(session, code="FAC-2")
    operator = await _seed_user(session, email="op@x.io", role="staff", is_operator=True, facility_id=fac1.id)
    u1 = await _seed_user(session, email="g1@x.io", role="guardian")
    u2 = await _seed_user(session, email="g2@x.io", role="guardian")
    await _seed_guardian(session, user_id=u1.id, facility_id=fac1.id, resident_id=None)
    await _seed_guardian(session, user_id=u2.id, facility_id=fac2.id, resident_id=None)

    resp = await integration_client.get(
        f"/admin/guardians?facility_id={fac1.id}", cookies=_auth_cookies(operator)
    )
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["user_email"] == "g1@x.io"
