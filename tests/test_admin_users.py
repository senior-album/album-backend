"""
T-144: app/api/admin.py — 운영자 유저 관리 통합 테스트.

검증 대상:
- 권한 가드: 비인증 / 일반 유저 / 시설장(is_admin) 모두 403
- 목록: role/facility_id/is_active 필터, q (이메일·이름) 검색, 페이지네이션
- PATCH: 권한·활성·시설 변경 + 변경된 필드별 AdminAuditLog 1 row
- 안전장치: 자기 자신 operator/active 해제 금지, is_admin=True 인데 facility_id 비면 400,
  존재하지 않는 facility_id 는 404
"""

from __future__ import annotations

# CLAUDE.md 알려진 이슈: Windows 에서 libmagic 로딩 시 access violation 으로 segfault.
# integration_client → app.main → photos.py → `import magic` 경로가 hang 을 유발.
# **Windows 에서만** stub 을 sys.modules 에 박아 실제 native 라이브러리 로드를 회피.
# CI(Linux) 에서는 절대 stub 으로 가리면 안 된다 — 다른 테스트
# (test_photos_validate_upload 등) 가 실제 magic.from_buffer 의 sniff 결과로
# MIME 검증 분기를 검증하므로, hardcoded 'image/jpeg' stub 이 sys.modules 에
# 남아있으면 그 테스트들이 모두 회귀.
import os as _os
import platform as _platform
import sys as _sys
import types as _types

if _platform.system() == "Windows" and "magic" not in _sys.modules:
    _stub = _types.ModuleType("magic")
    _stub.from_buffer = lambda data, mime=False: "image/jpeg"  # type: ignore[attr-defined]
    _stub.from_file = lambda path, mime=False: "image/jpeg"  # type: ignore[attr-defined]
    _sys.modules["magic"] = _stub

# Settings 가 import 시점에 .env 미설정 필드(JWT_REFRESH_SECRET 등) 를
# 강제하므로 테스트 전용 더미 값 주입. 실제 secret 검증 로직은 별도 테스트 영역.
# CI 는 자체 env 를 먼저 설정하므로 setdefault 가 no-op 로 처리됨.
_os.environ.setdefault("JWT_SECRET", "test-secret-value-for-jwt-32-bytes-min")
_os.environ.setdefault("JWT_REFRESH_SECRET", "test-refresh-secret-32bytes-minimum")
_os.environ.setdefault("RESIDENT_PII_KEK", "0" * 64)  # 32-byte hex
_os.environ.setdefault("RESIDENT_NAME_HMAC_KEY", "1" * 64)

import uuid

import pytest
from sqlalchemy import select

from app.core.security import SecurityService
from app.models.models import AdminAuditLog, Facility, User


# ---------------------------------------------------------------------------
# 헬퍼: seed + 인증된 client
# ---------------------------------------------------------------------------


async def _seed_facility(session, *, code: str = "FAC-AAA", name: str = "행복원") -> Facility:
    fac = Facility(id=str(uuid.uuid4()), code=code, name=name, address="서울시 강남구")
    session.add(fac)
    await session.commit()
    return fac


async def _seed_user(
    session,
    *,
    email: str,
    name: str = "이름",
    role: str = "guardian",
    is_admin: bool = False,
    is_operator: bool = False,
    is_active: bool = True,
    facility_id: str | None = None,
) -> User:
    u = User(
        id=str(uuid.uuid4()),
        email=email,
        name=name,
        password_hash="$2b$12$dummyhashfortest" + "x" * 30,
        role=role,
        is_admin=is_admin,
        is_operator=is_operator,
        is_active=is_active,
        facility_id=facility_id,
    )
    session.add(u)
    await session.commit()
    return u


def _auth_cookies(user: User) -> dict[str, str]:
    """SecurityService 로 access_token 발급해서 쿠키로 꽂아 보내기."""
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
async def test_list_users_requires_auth(integration_client):
    resp = await integration_client.get("/admin/users")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_list_users_forbids_non_operator(integration_client, integration_db):
    _SessionLocal, session = integration_db
    fac = await _seed_facility(session)
    admin_user = await _seed_user(
        session, email="staff@x.io", role="staff", is_admin=True, facility_id=fac.id
    )

    resp = await integration_client.get("/admin/users", cookies=_auth_cookies(admin_user))
    assert resp.status_code == 403
    assert "운영자" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_patch_user_requires_operator(integration_client, integration_db):
    _SessionLocal, session = integration_db
    guardian = await _seed_user(session, email="g@x.io", role="guardian")

    resp = await integration_client.patch(
        f"/admin/users/{guardian.id}",
        json={"is_active": False},
        cookies=_auth_cookies(guardian),
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# GET /admin/users — 목록·필터·검색·페이지네이션
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_users_returns_all_with_facility_name(integration_client, integration_db):
    _SessionLocal, session = integration_db
    fac = await _seed_facility(session, code="FAC-A", name="행복원")
    operator = await _seed_user(
        session, email="op@x.io", role="staff", is_operator=True, facility_id=fac.id
    )
    await _seed_user(session, email="g1@x.io", name="김보호", role="guardian")
    await _seed_user(
        session, email="staff1@x.io", name="박직원", role="staff", facility_id=fac.id
    )

    resp = await integration_client.get("/admin/users", cookies=_auth_cookies(operator))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total"] == 3
    assert body["page"] == 1
    emails = {item["email"] for item in body["items"]}
    assert {"op@x.io", "g1@x.io", "staff1@x.io"} == emails

    by_email = {i["email"]: i for i in body["items"]}
    assert by_email["staff1@x.io"]["facility_name"] == "행복원"
    assert by_email["g1@x.io"]["facility_name"] is None


@pytest.mark.asyncio
async def test_list_users_filters_by_role(integration_client, integration_db):
    _SessionLocal, session = integration_db
    fac = await _seed_facility(session)
    operator = await _seed_user(
        session, email="op@x.io", role="staff", is_operator=True, facility_id=fac.id
    )
    await _seed_user(session, email="g1@x.io", role="guardian")
    await _seed_user(session, email="g2@x.io", role="guardian")

    resp = await integration_client.get(
        "/admin/users?role=guardian", cookies=_auth_cookies(operator)
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 2
    assert all(i["role"] == "guardian" for i in body["items"])


@pytest.mark.asyncio
async def test_list_users_search_q_matches_email_and_name_case_insensitive(
    integration_client, integration_db
):
    _SessionLocal, session = integration_db
    fac = await _seed_facility(session)
    operator = await _seed_user(
        session, email="op@x.io", role="staff", is_operator=True, facility_id=fac.id
    )
    await _seed_user(session, email="alice@x.io", name="앨리스")
    await _seed_user(session, email="bob@x.io", name="박앨리스연")

    # 이메일 매칭
    resp = await integration_client.get(
        "/admin/users?q=alice", cookies=_auth_cookies(operator)
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["email"] == "alice@x.io"

    # 이름 매칭 (한국어)
    resp = await integration_client.get(
        "/admin/users?q=앨리스", cookies=_auth_cookies(operator)
    )
    assert resp.status_code == 200
    body = resp.json()
    emails = {i["email"] for i in body["items"]}
    assert emails == {"alice@x.io", "bob@x.io"}


@pytest.mark.asyncio
async def test_list_users_pagination(integration_client, integration_db):
    _SessionLocal, session = integration_db
    fac = await _seed_facility(session)
    operator = await _seed_user(
        session, email="op@x.io", role="staff", is_operator=True, facility_id=fac.id
    )
    for i in range(5):
        await _seed_user(session, email=f"g{i}@x.io", role="guardian")

    resp = await integration_client.get(
        "/admin/users?page=1&size=2", cookies=_auth_cookies(operator)
    )
    body = resp.json()
    assert body["total"] == 6  # operator + 5 guardians
    assert len(body["items"]) == 2

    resp = await integration_client.get(
        "/admin/users?page=4&size=2", cookies=_auth_cookies(operator)
    )
    body = resp.json()
    assert len(body["items"]) == 0


# ---------------------------------------------------------------------------
# PATCH /admin/users/{id} — 변경 + audit
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_patch_user_toggles_is_active_and_logs(
    integration_client, integration_db
):
    SessionLocal, session = integration_db
    fac = await _seed_facility(session)
    operator = await _seed_user(
        session, email="op@x.io", role="staff", is_operator=True, facility_id=fac.id
    )
    target = await _seed_user(session, email="g@x.io", role="guardian")

    resp = await integration_client.patch(
        f"/admin/users/{target.id}",
        json={"is_active": False},
        cookies=_auth_cookies(operator),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["is_active"] is False

    async with SessionLocal() as s:
        refreshed = await s.get(User, target.id)
        assert refreshed.is_active is False

        logs = (
            await s.execute(
                select(AdminAuditLog).where(AdminAuditLog.target_id == target.id)
            )
        ).scalars().all()
        assert len(logs) == 1
        assert logs[0].action == "user_set_active"
        assert logs[0].performed_by == operator.id
        assert logs[0].detail == "True -> False"


@pytest.mark.asyncio
async def test_patch_user_multiple_fields_creates_one_log_per_change(
    integration_client, integration_db
):
    SessionLocal, session = integration_db
    fac1 = await _seed_facility(session, code="FAC-1", name="A원")
    fac2 = await _seed_facility(session, code="FAC-2", name="B원")
    operator = await _seed_user(
        session, email="op@x.io", role="staff", is_operator=True, facility_id=fac1.id
    )
    target = await _seed_user(
        session, email="staff@x.io", role="staff", facility_id=fac1.id
    )

    resp = await integration_client.patch(
        f"/admin/users/{target.id}",
        json={"is_admin": True, "facility_id": fac2.id},
        cookies=_auth_cookies(operator),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["is_admin"] is True
    assert body["facility_id"] == fac2.id
    assert body["facility_name"] == "B원"

    async with SessionLocal() as s:
        logs = (
            await s.execute(
                select(AdminAuditLog).where(AdminAuditLog.target_id == target.id)
            )
        ).scalars().all()
        actions = sorted(l.action for l in logs)
        assert actions == ["user_set_admin", "user_set_facility"]


@pytest.mark.asyncio
async def test_patch_user_no_change_no_audit(integration_client, integration_db):
    SessionLocal, session = integration_db
    fac = await _seed_facility(session)
    operator = await _seed_user(
        session, email="op@x.io", role="staff", is_operator=True, facility_id=fac.id
    )
    target = await _seed_user(session, email="g@x.io", role="guardian", is_active=True)

    # 이미 True 인 값을 다시 True 로 — no-op
    resp = await integration_client.patch(
        f"/admin/users/{target.id}",
        json={"is_active": True},
        cookies=_auth_cookies(operator),
    )
    assert resp.status_code == 200

    async with SessionLocal() as s:
        logs = (
            await s.execute(
                select(AdminAuditLog).where(AdminAuditLog.target_id == target.id)
            )
        ).scalars().all()
        assert len(logs) == 0


@pytest.mark.asyncio
async def test_patch_user_empty_string_facility_detaches(
    integration_client, integration_db
):
    SessionLocal, session = integration_db
    fac = await _seed_facility(session)
    operator = await _seed_user(
        session, email="op@x.io", role="staff", is_operator=True, facility_id=fac.id
    )
    # is_admin=False staff — facility detach 가능 (admin 가드 안 걸림)
    target = await _seed_user(
        session, email="staff@x.io", role="staff", is_admin=False, facility_id=fac.id
    )

    resp = await integration_client.patch(
        f"/admin/users/{target.id}",
        json={"facility_id": ""},
        cookies=_auth_cookies(operator),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["facility_id"] is None
    assert resp.json()["facility_name"] is None


# ---------------------------------------------------------------------------
# 안전장치
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_patch_self_cannot_revoke_operator(integration_client, integration_db):
    _SessionLocal, session = integration_db
    fac = await _seed_facility(session)
    operator = await _seed_user(
        session, email="op@x.io", role="staff", is_operator=True, facility_id=fac.id
    )

    resp = await integration_client.patch(
        f"/admin/users/{operator.id}",
        json={"is_operator": False},
        cookies=_auth_cookies(operator),
    )
    assert resp.status_code == 400
    assert "운영자 권한" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_patch_self_cannot_deactivate(integration_client, integration_db):
    _SessionLocal, session = integration_db
    fac = await _seed_facility(session)
    operator = await _seed_user(
        session, email="op@x.io", role="staff", is_operator=True, facility_id=fac.id
    )

    resp = await integration_client.patch(
        f"/admin/users/{operator.id}",
        json={"is_active": False},
        cookies=_auth_cookies(operator),
    )
    assert resp.status_code == 400
    assert "비활성화" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_patch_admin_without_facility_rejected(
    integration_client, integration_db
):
    _SessionLocal, session = integration_db
    fac = await _seed_facility(session)
    operator = await _seed_user(
        session, email="op@x.io", role="staff", is_operator=True, facility_id=fac.id
    )
    # facility 없는 보호자 — is_admin=True 시도
    target = await _seed_user(session, email="g@x.io", role="guardian")

    resp = await integration_client.patch(
        f"/admin/users/{target.id}",
        json={"is_admin": True},
        cookies=_auth_cookies(operator),
    )
    assert resp.status_code == 400
    assert "시설" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_patch_unknown_facility_404(integration_client, integration_db):
    _SessionLocal, session = integration_db
    fac = await _seed_facility(session)
    operator = await _seed_user(
        session, email="op@x.io", role="staff", is_operator=True, facility_id=fac.id
    )
    target = await _seed_user(session, email="g@x.io", role="guardian")

    resp = await integration_client.patch(
        f"/admin/users/{target.id}",
        json={"facility_id": "facility-does-not-exist"},
        cookies=_auth_cookies(operator),
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_patch_unknown_user_404(integration_client, integration_db):
    _SessionLocal, session = integration_db
    fac = await _seed_facility(session)
    operator = await _seed_user(
        session, email="op@x.io", role="staff", is_operator=True, facility_id=fac.id
    )

    resp = await integration_client.patch(
        "/admin/users/no-such-user",
        json={"is_active": False},
        cookies=_auth_cookies(operator),
    )
    assert resp.status_code == 404
