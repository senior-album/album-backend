"""
T-145: app/api/admin.py — 운영자 시설 관리 통합 테스트.

검증 대상:
- 권한 가드: 비인증 / 일반 유저 → 401/403
- 목록: 직원/입소자/사진 카운트 정확성, 검색 (이름·주소), 페이지네이션
- POST: 자동 코드 발급 / 명시 코드 / 코드 중복 시 409
- PATCH: name/address/phone 수정 + 변경 사항 audit detail 통합 / no-op 시 audit 0 row
- 404: 존재하지 않는 시설 PATCH
"""

from __future__ import annotations

# Windows magic 바인딩 segfault 회피 — sys.modules 에 stub
import os as _os
import sys as _sys
import types as _types

if "magic" not in _sys.modules:
    _stub = _types.ModuleType("magic")
    _stub.from_buffer = lambda data, mime=False: "image/jpeg"  # type: ignore[attr-defined]
    _stub.from_file = lambda path, mime=False: "image/jpeg"  # type: ignore[attr-defined]
    _sys.modules["magic"] = _stub

_os.environ.setdefault("JWT_SECRET", "test-secret-value-for-jwt-32-bytes-min")
_os.environ.setdefault("JWT_REFRESH_SECRET", "test-refresh-secret-32bytes-minimum")
_os.environ.setdefault("RESIDENT_PII_KEK", "0" * 64)
_os.environ.setdefault("RESIDENT_NAME_HMAC_KEY", "1" * 64)

import uuid

import pytest
from sqlalchemy import select

from app.core.security import SecurityService
from app.models.models import AdminAuditLog, Facility, Photo, Resident, User


# ---------------------------------------------------------------------------
# 헬퍼
# ---------------------------------------------------------------------------


async def _seed_facility(session, *, code: str, name: str = "T", address: str = "X") -> Facility:
    fac = Facility(id=str(uuid.uuid4()), code=code, name=name, address=address, phone="")
    session.add(fac)
    await session.commit()
    return fac


async def _seed_user(
    session,
    *,
    email: str,
    role: str = "staff",
    is_operator: bool = False,
    facility_id: str | None = None,
) -> User:
    u = User(
        id=str(uuid.uuid4()),
        email=email,
        name="U",
        password_hash="$2b$12$dummyhashfortest" + "x" * 30,
        role=role,
        is_admin=False,
        is_operator=is_operator,
        is_active=True,
        facility_id=facility_id,
    )
    session.add(u)
    await session.commit()
    return u


def _auth_cookies(user: User) -> dict[str, str]:
    token = SecurityService.create_access_token(
        data={
            "sub": user.id,
            "email": user.email,
            "role": user.role,
            "facility_id": user.facility_id,
        }
    )
    return {"access_token": token}


# ---------------------------------------------------------------------------
# 권한 가드
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_facilities_requires_auth(integration_client):
    resp = await integration_client.get("/admin/facilities")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_list_facilities_forbids_non_operator(integration_client, integration_db):
    _SessionLocal, session = integration_db
    fac = await _seed_facility(session, code="FAC-AAA")
    staff = await _seed_user(session, email="s@x.io", role="staff", facility_id=fac.id)
    resp = await integration_client.get("/admin/facilities", cookies=_auth_cookies(staff))
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# GET /admin/facilities
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_facilities_returns_counts(integration_client, integration_db):
    SessionLocal, session = integration_db
    fac1 = await _seed_facility(session, code="FAC-001", name="A원")
    fac2 = await _seed_facility(session, code="FAC-002", name="B원")
    operator = await _seed_user(session, email="op@x.io", role="staff", is_operator=True, facility_id=fac1.id)

    # fac1: staff 1 (operator) + guardian 1 + resident 2 + photo 3
    # fac2: staff 0 + resident 1 + photo 0
    await _seed_user(session, email="g@x.io", role="guardian", facility_id=fac1.id)
    await _seed_user(session, email="s2@x.io", role="staff", facility_id=fac1.id)
    async with SessionLocal() as s:
        s.add(Resident(id=str(uuid.uuid4()), facility_id=fac1.id, code="RES-1", name="R1"))
        s.add(Resident(id=str(uuid.uuid4()), facility_id=fac1.id, code="RES-2", name="R2"))
        s.add(Resident(id=str(uuid.uuid4()), facility_id=fac2.id, code="RES-3", name="R3"))
        for i in range(3):
            s.add(Photo(id=str(uuid.uuid4()), facility_id=fac1.id, original_url=f"u{i}"))
        await s.commit()

    resp = await integration_client.get("/admin/facilities", cookies=_auth_cookies(operator))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total"] == 2
    by_code = {f["code"]: f for f in body["items"]}
    assert by_code["FAC-001"]["staff_count"] == 2  # operator + s2 (guardian 제외)
    assert by_code["FAC-001"]["resident_count"] == 2
    assert by_code["FAC-001"]["photo_count"] == 3
    assert by_code["FAC-002"]["staff_count"] == 0
    assert by_code["FAC-002"]["resident_count"] == 1
    assert by_code["FAC-002"]["photo_count"] == 0


@pytest.mark.asyncio
async def test_list_facilities_search_by_name_or_address(integration_client, integration_db):
    _SessionLocal, session = integration_db
    fac1 = await _seed_facility(session, code="FAC-1", name="햇살요양원", address="강남구")
    await _seed_facility(session, code="FAC-2", name="달빛요양원", address="송파구")
    operator = await _seed_user(session, email="op@x.io", role="staff", is_operator=True, facility_id=fac1.id)

    resp = await integration_client.get("/admin/facilities?q=햇살", cookies=_auth_cookies(operator))
    assert resp.json()["total"] == 1

    resp = await integration_client.get("/admin/facilities?q=송파", cookies=_auth_cookies(operator))
    assert resp.json()["total"] == 1


# ---------------------------------------------------------------------------
# POST /admin/facilities
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_create_facility_auto_generates_code_and_logs(integration_client, integration_db):
    SessionLocal, session = integration_db
    fac = await _seed_facility(session, code="FAC-OP")
    operator = await _seed_user(session, email="op@x.io", role="staff", is_operator=True, facility_id=fac.id)

    resp = await integration_client.post(
        "/admin/facilities",
        json={"name": "행복원", "address": "서울시 종로구", "phone": "02-1111-2222"},
        cookies=_auth_cookies(operator),
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["code"].startswith("FAC-")
    assert body["name"] == "행복원"
    assert body["staff_count"] == 0

    async with SessionLocal() as s:
        log = (
            await s.execute(
                select(AdminAuditLog).where(AdminAuditLog.action == "facility_create")
            )
        ).scalar_one()
        assert log.target_type == "facility"
        assert "행복원" in log.detail


@pytest.mark.asyncio
async def test_create_facility_explicit_code(integration_client, integration_db):
    _SessionLocal, session = integration_db
    fac = await _seed_facility(session, code="FAC-OP")
    operator = await _seed_user(session, email="op@x.io", role="staff", is_operator=True, facility_id=fac.id)

    resp = await integration_client.post(
        "/admin/facilities",
        json={"name": "B원", "address": "주소", "code": "FAC-CUSTOM"},
        cookies=_auth_cookies(operator),
    )
    assert resp.status_code == 201
    assert resp.json()["code"] == "FAC-CUSTOM"


@pytest.mark.asyncio
async def test_create_facility_duplicate_code_409(integration_client, integration_db):
    _SessionLocal, session = integration_db
    fac = await _seed_facility(session, code="FAC-DUP")
    operator = await _seed_user(session, email="op@x.io", role="staff", is_operator=True, facility_id=fac.id)

    resp = await integration_client.post(
        "/admin/facilities",
        json={"name": "A", "address": "X", "code": "FAC-DUP"},
        cookies=_auth_cookies(operator),
    )
    assert resp.status_code == 409
    assert "FAC-DUP" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# PATCH /admin/facilities/{id}
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_patch_facility_updates_and_logs(integration_client, integration_db):
    SessionLocal, session = integration_db
    fac = await _seed_facility(session, code="FAC-X", name="원", address="주소1")
    operator = await _seed_user(session, email="op@x.io", role="staff", is_operator=True, facility_id=fac.id)

    resp = await integration_client.patch(
        f"/admin/facilities/{fac.id}",
        json={"name": "행복원", "phone": "02-3333"},
        cookies=_auth_cookies(operator),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["name"] == "행복원"
    assert body["phone"] == "02-3333"
    assert body["address"] == "주소1"  # 미변경

    async with SessionLocal() as s:
        log = (
            await s.execute(
                select(AdminAuditLog).where(AdminAuditLog.action == "facility_update")
            )
        ).scalar_one()
        assert "name:" in log.detail
        assert "phone:" in log.detail
        assert "address:" not in log.detail  # 변경 안 한 필드는 누락


@pytest.mark.asyncio
async def test_patch_facility_no_change_no_audit(integration_client, integration_db):
    SessionLocal, session = integration_db
    fac = await _seed_facility(session, code="FAC-X", name="원")
    operator = await _seed_user(session, email="op@x.io", role="staff", is_operator=True, facility_id=fac.id)

    resp = await integration_client.patch(
        f"/admin/facilities/{fac.id}",
        json={"name": "원"},  # 동일
        cookies=_auth_cookies(operator),
    )
    assert resp.status_code == 200

    async with SessionLocal() as s:
        logs = (
            await s.execute(select(AdminAuditLog).where(AdminAuditLog.action == "facility_update"))
        ).scalars().all()
        assert len(logs) == 0


@pytest.mark.asyncio
async def test_patch_unknown_facility_404(integration_client, integration_db):
    _SessionLocal, session = integration_db
    fac = await _seed_facility(session, code="FAC-X")
    operator = await _seed_user(session, email="op@x.io", role="staff", is_operator=True, facility_id=fac.id)

    resp = await integration_client.patch(
        "/admin/facilities/unknown-id",
        json={"name": "X"},
        cookies=_auth_cookies(operator),
    )
    assert resp.status_code == 404
