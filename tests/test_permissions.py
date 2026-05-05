"""
T-150: 시설 직원 메뉴 권한 위임 인프라 테스트.

검증 대상:
- 가드: 비인증 / 일반 직원 / 보호자(role=guardian) / 운영자(is_operator) 가
  /facility-permissions/* 호출 시 401/403 (현재 정책: 시설장만 grant API 사용 가능).
- 시설장이 자기 시설 직원에게 grant/revoke + AdminAuditLog 1 row 기록.
- 다른 시설 직원 대상 grant/revoke 는 403.
- 카탈로그에 없는 키 grant 는 400.
- 중복 grant 는 멱등 (200, audit 추가 없음).
- has_permission: is_operator / is_admin (facility:* 키) 자동 통과, 명시 행 통과.
"""

from __future__ import annotations

# T-144 패턴: Windows 에서만 magic stub (libmagic native segfault 회피).
import os as _os
import platform as _platform
import sys as _sys
import types as _types

if _platform.system() == "Windows" and "magic" not in _sys.modules:
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

from app.core.permissions import FACILITY_STATS_VIEW, has_permission
from app.core.security import SecurityService
from app.models.models import AdminAuditLog, Facility, User, UserPermission


# ---------------------------------------------------------------------------
# seed 헬퍼
# ---------------------------------------------------------------------------


async def _seed_facility(session, *, code: str = "FAC-A", name: str = "행복원") -> Facility:
    fac = Facility(id=str(uuid.uuid4()), code=code, name=name, address="서울시")
    session.add(fac)
    await session.commit()
    return fac


async def _seed_user(
    session,
    *,
    email: str,
    name: str = "이름",
    role: str = "staff",
    is_admin: bool = False,
    is_operator: bool = False,
    is_active: bool = True,
    facility_id: str | None = None,
) -> User:
    u = User(
        id=str(uuid.uuid4()),
        email=email,
        name=name,
        password_hash="$2b$12$dummy" + "x" * 40,
        role=role,
        is_admin=is_admin,
        is_operator=is_operator,
        is_active=is_active,
        facility_id=facility_id,
    )
    session.add(u)
    await session.commit()
    return u


def _cookies(user: User) -> dict[str, str]:
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
# 가드 — 시설장 전용
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_grant_requires_auth(integration_client):
    resp = await integration_client.post(
        "/facility-permissions/grant",
        json={"user_id": "x", "permission_key": FACILITY_STATS_VIEW},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_grant_forbids_non_admin_staff(integration_client, integration_db):
    _, session = integration_db
    fac = await _seed_facility(session)
    staff = await _seed_user(session, email="s@x.io", role="staff", facility_id=fac.id)
    target = await _seed_user(session, email="t@x.io", role="staff", facility_id=fac.id)

    resp = await integration_client.post(
        "/facility-permissions/grant",
        json={"user_id": target.id, "permission_key": FACILITY_STATS_VIEW},
        cookies=_cookies(staff),
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_grant_forbids_operator_without_admin(integration_client, integration_db):
    """운영자(is_operator)는 본 API 의 actor 가 될 수 없다 — 시설장만."""
    _, session = integration_db
    fac = await _seed_facility(session)
    op = await _seed_user(
        session, email="op@x.io", role="staff", is_operator=True, facility_id=fac.id
    )
    target = await _seed_user(session, email="t@x.io", role="staff", facility_id=fac.id)

    resp = await integration_client.post(
        "/facility-permissions/grant",
        json={"user_id": target.id, "permission_key": FACILITY_STATS_VIEW},
        cookies=_cookies(op),
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_grant_forbids_guardian(integration_client, integration_db):
    _, session = integration_db
    g = await _seed_user(session, email="g@x.io", role="guardian")

    resp = await integration_client.post(
        "/facility-permissions/grant",
        json={"user_id": "x", "permission_key": FACILITY_STATS_VIEW},
        cookies=_cookies(g),
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 카탈로그 / 목록
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_keys_returns_catalog(integration_client, integration_db):
    _, session = integration_db
    fac = await _seed_facility(session)
    admin = await _seed_user(
        session, email="a@x.io", role="staff", is_admin=True, facility_id=fac.id
    )

    resp = await integration_client.get("/facility-permissions/keys", cookies=_cookies(admin))
    assert resp.status_code == 200
    keys = {item["key"] for item in resp.json()}
    assert FACILITY_STATS_VIEW in keys


@pytest.mark.asyncio
async def test_list_staff_only_in_own_facility(integration_client, integration_db):
    _, session = integration_db
    fac_a = await _seed_facility(session, code="FAC-A", name="A")
    fac_b = await _seed_facility(session, code="FAC-B", name="B")
    admin_a = await _seed_user(
        session, email="adm-a@x.io", role="staff", is_admin=True, facility_id=fac_a.id
    )
    in_a = await _seed_user(
        session, email="in-a@x.io", name="박직원", role="staff", facility_id=fac_a.id
    )
    in_b = await _seed_user(
        session, email="in-b@x.io", name="이직원", role="staff", facility_id=fac_b.id
    )

    resp = await integration_client.get(
        "/facility-permissions/staff", cookies=_cookies(admin_a)
    )
    assert resp.status_code == 200
    user_ids = {row["user_id"] for row in resp.json()["items"]}
    assert in_a.id in user_ids
    assert in_b.id not in user_ids
    assert admin_a.id in user_ids


# ---------------------------------------------------------------------------
# grant
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_grant_creates_row_and_audit(integration_client, integration_db):
    _, session = integration_db
    fac = await _seed_facility(session)
    admin = await _seed_user(
        session, email="a@x.io", role="staff", is_admin=True, facility_id=fac.id
    )
    target = await _seed_user(
        session, email="t@x.io", role="staff", facility_id=fac.id
    )

    resp = await integration_client.post(
        "/facility-permissions/grant",
        json={"user_id": target.id, "permission_key": FACILITY_STATS_VIEW},
        cookies=_cookies(admin),
    )
    assert resp.status_code == 201, resp.text

    rows = (
        await session.execute(select(UserPermission).where(UserPermission.user_id == target.id))
    ).scalars().all()
    assert len(rows) == 1
    assert rows[0].permission_key == FACILITY_STATS_VIEW
    assert rows[0].granted_by == admin.id

    audits = (
        await session.execute(
            select(AdminAuditLog).where(
                AdminAuditLog.action == "permission_grant",
                AdminAuditLog.target_id == target.id,
            )
        )
    ).scalars().all()
    assert len(audits) == 1
    assert audits[0].detail == FACILITY_STATS_VIEW


@pytest.mark.asyncio
async def test_grant_idempotent_same_key_twice(integration_client, integration_db):
    _, session = integration_db
    fac = await _seed_facility(session)
    admin = await _seed_user(
        session, email="a@x.io", role="staff", is_admin=True, facility_id=fac.id
    )
    target = await _seed_user(session, email="t@x.io", role="staff", facility_id=fac.id)

    for _ in range(2):
        resp = await integration_client.post(
            "/facility-permissions/grant",
            json={"user_id": target.id, "permission_key": FACILITY_STATS_VIEW},
            cookies=_cookies(admin),
        )
        assert resp.status_code in (200, 201)

    rows = (
        await session.execute(select(UserPermission).where(UserPermission.user_id == target.id))
    ).scalars().all()
    assert len(rows) == 1, "중복 grant 는 행이 1개만 남아야 한다"

    audits = (
        await session.execute(
            select(AdminAuditLog).where(
                AdminAuditLog.action == "permission_grant",
                AdminAuditLog.target_id == target.id,
            )
        )
    ).scalars().all()
    assert len(audits) == 1, "이미 부여된 키 재요청은 audit 추가 없이 멱등"


@pytest.mark.asyncio
async def test_grant_unknown_key_400(integration_client, integration_db):
    _, session = integration_db
    fac = await _seed_facility(session)
    admin = await _seed_user(
        session, email="a@x.io", role="staff", is_admin=True, facility_id=fac.id
    )
    target = await _seed_user(session, email="t@x.io", role="staff", facility_id=fac.id)

    resp = await integration_client.post(
        "/facility-permissions/grant",
        json={"user_id": target.id, "permission_key": "facility:bogus:view"},
        cookies=_cookies(admin),
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_grant_other_facility_user_403(integration_client, integration_db):
    _, session = integration_db
    fac_a = await _seed_facility(session, code="FAC-A")
    fac_b = await _seed_facility(session, code="FAC-B")
    admin_a = await _seed_user(
        session, email="a@x.io", role="staff", is_admin=True, facility_id=fac_a.id
    )
    target_b = await _seed_user(
        session, email="b@x.io", role="staff", facility_id=fac_b.id
    )

    resp = await integration_client.post(
        "/facility-permissions/grant",
        json={"user_id": target_b.id, "permission_key": FACILITY_STATS_VIEW},
        cookies=_cookies(admin_a),
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# revoke
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_revoke_deletes_row_and_audits(integration_client, integration_db):
    _, session = integration_db
    fac = await _seed_facility(session)
    admin = await _seed_user(
        session, email="a@x.io", role="staff", is_admin=True, facility_id=fac.id
    )
    target = await _seed_user(session, email="t@x.io", role="staff", facility_id=fac.id)

    # 사전 부여
    await integration_client.post(
        "/facility-permissions/grant",
        json={"user_id": target.id, "permission_key": FACILITY_STATS_VIEW},
        cookies=_cookies(admin),
    )

    resp = await integration_client.delete(
        f"/facility-permissions/{target.id}/{FACILITY_STATS_VIEW}",
        cookies=_cookies(admin),
    )
    assert resp.status_code == 204

    rows = (
        await session.execute(select(UserPermission).where(UserPermission.user_id == target.id))
    ).scalars().all()
    assert rows == []

    audits = (
        await session.execute(
            select(AdminAuditLog).where(
                AdminAuditLog.action == "permission_revoke",
                AdminAuditLog.target_id == target.id,
            )
        )
    ).scalars().all()
    assert len(audits) == 1
    assert audits[0].detail == FACILITY_STATS_VIEW


@pytest.mark.asyncio
async def test_revoke_nonexistent_404(integration_client, integration_db):
    _, session = integration_db
    fac = await _seed_facility(session)
    admin = await _seed_user(
        session, email="a@x.io", role="staff", is_admin=True, facility_id=fac.id
    )
    target = await _seed_user(session, email="t@x.io", role="staff", facility_id=fac.id)

    resp = await integration_client.delete(
        f"/facility-permissions/{target.id}/{FACILITY_STATS_VIEW}",
        cookies=_cookies(admin),
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_revoke_other_facility_user_403(integration_client, integration_db):
    _, session = integration_db
    fac_a = await _seed_facility(session, code="FAC-A")
    fac_b = await _seed_facility(session, code="FAC-B")
    admin_a = await _seed_user(
        session, email="a@x.io", role="staff", is_admin=True, facility_id=fac_a.id
    )
    target_b = await _seed_user(session, email="b@x.io", role="staff", facility_id=fac_b.id)

    resp = await integration_client.delete(
        f"/facility-permissions/{target_b.id}/{FACILITY_STATS_VIEW}",
        cookies=_cookies(admin_a),
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# has_permission — 자동 통과 / 명시 행
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_has_permission_operator_passes_any(integration_db):
    _, session = integration_db
    op = await _seed_user(session, email="op@x.io", role="staff", is_operator=True)
    assert await has_permission(session, op, FACILITY_STATS_VIEW) is True
    assert await has_permission(session, op, "facility:any:other") is True


@pytest.mark.asyncio
async def test_has_permission_admin_passes_facility_keys(integration_db):
    _, session = integration_db
    fac = await _seed_facility(session)
    admin = await _seed_user(
        session, email="a@x.io", role="staff", is_admin=True, facility_id=fac.id
    )
    assert await has_permission(session, admin, FACILITY_STATS_VIEW) is True


@pytest.mark.asyncio
async def test_has_permission_admin_without_facility_blocked(integration_db):
    """is_admin=True 인데 facility_id 빈 비정상 상태 — 행 없으면 차단."""
    _, session = integration_db
    admin = await _seed_user(
        session, email="a@x.io", role="staff", is_admin=True, facility_id=None
    )
    assert await has_permission(session, admin, FACILITY_STATS_VIEW) is False


@pytest.mark.asyncio
async def test_has_permission_explicit_row_passes(integration_db):
    _, session = integration_db
    fac = await _seed_facility(session)
    granter = await _seed_user(
        session, email="a@x.io", role="staff", is_admin=True, facility_id=fac.id
    )
    target = await _seed_user(session, email="t@x.io", role="staff", facility_id=fac.id)

    session.add(UserPermission(
        user_id=target.id,
        permission_key=FACILITY_STATS_VIEW,
        granted_by=granter.id,
    ))
    await session.commit()

    assert await has_permission(session, target, FACILITY_STATS_VIEW) is True


@pytest.mark.asyncio
async def test_has_permission_no_row_no_role_blocked(integration_db):
    _, session = integration_db
    fac = await _seed_facility(session)
    target = await _seed_user(session, email="t@x.io", role="staff", facility_id=fac.id)
    assert await has_permission(session, target, FACILITY_STATS_VIEW) is False
