"""
T-124 PR5: app.api.auth 풀 통합 테스트.

`integration_db` + `integration_client` (PR #82) 위에서:
- register_admin / register_guardian → DB 레코드 생성, 쿠키 발급
- login: 잘못된 비밀번호 / 미존재 사용자 / 정상 플로우
- refresh: 정상 rotation / reuse detection (family revoke) / 누락
- logout / logout-all: family revoke + 쿠키 클리어
- get_me: 인증된 사용자 조회

ConsentDocument 가 비어있으면 보호자 가입 시 필수 동의 검증을 우회한다 — 이
파일은 약관 시드 없이 동작하는 케이스만 다루고, 약관 강제 분기는 별도 테스트
파일 (test_consents) 영역.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from app.models.models import RefreshToken, User


# ---------------------------------------------------------------------------
# register_admin
# ---------------------------------------------------------------------------


def _admin_payload(email: str = "admin@x.io") -> dict:
    return {
        "email": email,
        "password": "VeryStrongPassword123!",
        "name": "Admin",
        "phone": "010-1111-2222",
        "facilityName": "행복 요양원",
        "facilityAddress": "서울시 강남구 1-2-3",
        "facilityPhone": "02-1234-5678",
    }


@pytest.mark.asyncio
async def test_register_admin_creates_facility_user_and_token(
    integration_client, integration_db
):
    SessionLocal, _seed = integration_db
    resp = await integration_client.post(
        "/auth/register/admin", json=_admin_payload()
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["user"]["email"] == "admin@x.io"
    assert body["user"]["role"] == "staff"
    assert body["user"]["is_admin"] is True
    assert body["facility"]["code"].startswith("FAC-")

    # 쿠키 두 개 (access + refresh) 발급
    cookies = resp.cookies
    assert "access_token" in cookies
    assert "refresh_token" in cookies

    # DB 검증 — User + RefreshToken row 정확히 1개씩
    async with SessionLocal() as s:
        users = (await s.execute(select(User))).scalars().all()
        assert len(users) == 1
        assert users[0].password_hash and users[0].password_hash != _admin_payload()["password"]

        tokens = (await s.execute(select(RefreshToken))).scalars().all()
        assert len(tokens) == 1
        assert tokens[0].user_id == users[0].id
        assert tokens[0].revoked_at is None


@pytest.mark.asyncio
async def test_register_admin_rejects_duplicate_email(integration_client):
    payload = _admin_payload()
    first = await integration_client.post("/auth/register/admin", json=payload)
    assert first.status_code == 200

    second = await integration_client.post("/auth/register/admin", json=payload)
    assert second.status_code == 400
    assert "이미 등록된" in second.json()["detail"]


@pytest.mark.asyncio
async def test_register_admin_rejects_missing_required_fields(integration_client):
    resp = await integration_client.post(
        "/auth/register/admin",
        json={"email": "x@x.io", "password": "p"},  # 다수 누락
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# register_guardian (consent 강제 X — 빈 DB)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_register_guardian_happy_path(integration_client, integration_db):
    SessionLocal, _ = integration_db
    resp = await integration_client.post(
        "/auth/register/guardian",
        json={
            "email": "g@x.io",
            "password": "GuardianPass123!",
            "name": "Park",
            "phone": "010-3333-4444",
        },
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["user"]["role"] == "guardian"
    assert body["user"]["facility_id"] is None
    assert "access_token" in resp.cookies and "refresh_token" in resp.cookies

    async with SessionLocal() as s:
        guardians = (
            await s.execute(select(User).filter(User.role == "guardian"))
        ).scalars().all()
        assert len(guardians) == 1


# ---------------------------------------------------------------------------
# login
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_login_with_correct_password_returns_cookies(integration_client):
    await integration_client.post("/auth/register/admin", json=_admin_payload())
    resp = await integration_client.post(
        "/auth/login",
        json={"email": "admin@x.io", "password": _admin_payload()["password"]},
    )
    assert resp.status_code == 200, resp.text
    assert "access_token" in resp.cookies
    assert "refresh_token" in resp.cookies
    body = resp.json()
    assert body["user"]["email"] == "admin@x.io"
    assert body["facility"]["code"].startswith("FAC-")


@pytest.mark.asyncio
async def test_login_rejects_wrong_password(integration_client):
    await integration_client.post("/auth/register/admin", json=_admin_payload())
    resp = await integration_client.post(
        "/auth/login",
        json={"email": "admin@x.io", "password": "wrong-password-xxx"},
    )
    assert resp.status_code == 401
    assert "올바르지 않습니다" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_login_rejects_unknown_email(integration_client):
    resp = await integration_client.post(
        "/auth/login",
        json={"email": "nobody@x.io", "password": "any"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_login_creates_new_refresh_family(integration_client, integration_db):
    """매 로그인은 새 family_id 의 refresh 토큰 — 디바이스/세션 분리."""
    SessionLocal, _ = integration_db
    await integration_client.post("/auth/register/admin", json=_admin_payload())
    # register 가 이미 1건 만든 상태. login 으로 추가 1건 생성.
    await integration_client.post(
        "/auth/login",
        json={"email": "admin@x.io", "password": _admin_payload()["password"]},
    )
    async with SessionLocal() as s:
        rows = (await s.execute(select(RefreshToken))).scalars().all()
        # 두 개의 서로 다른 family_id
        family_ids = {r.family_id for r in rows}
        assert len(family_ids) == 2


# ---------------------------------------------------------------------------
# refresh — rotation + reuse detection
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_refresh_rotation_marks_old_revoked(integration_client, integration_db):
    SessionLocal, _ = integration_db
    reg = await integration_client.post(
        "/auth/register/admin", json=_admin_payload()
    )
    old_refresh = reg.cookies["refresh_token"]

    # 같은 client 의 cookie jar 가 자동으로 refresh 토큰을 보내준다.
    resp = await integration_client.post("/auth/refresh")
    assert resp.status_code == 200
    new_refresh = resp.cookies["refresh_token"]
    assert new_refresh != old_refresh

    async with SessionLocal() as s:
        rows = (await s.execute(select(RefreshToken).order_by(RefreshToken.created_at))).scalars().all()
        # 첫 번째 row: rotation 됨, revoke_reason="rotated"
        # 두 번째 row: 새 활성
        assert rows[0].revoked_at is not None
        assert rows[0].revoke_reason == "rotated"
        assert rows[1].revoked_at is None
        # 같은 family
        assert rows[0].family_id == rows[1].family_id


@pytest.mark.asyncio
async def test_refresh_missing_cookie_returns_401(integration_client):
    resp = await integration_client.post("/auth/refresh")
    assert resp.status_code == 401
    assert "missing" in resp.json()["detail"].lower()


@pytest.mark.asyncio
async def test_refresh_invalid_token_returns_401(integration_client):
    integration_client.cookies.set("refresh_token", "garbage-not-a-jwt", path="/auth")
    resp = await integration_client.post("/auth/refresh")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_refresh_reuse_detection_revokes_family(
    integration_client, integration_db
):
    """
    회수된 refresh 를 재사용하면 reuse-detected — family 전체 revoke + 401.
    공격자가 토큰을 훔쳐 정상 사용자보다 먼저 refresh 했을 때의 시그널.
    """
    SessionLocal, _ = integration_db
    await integration_client.post("/auth/register/admin", json=_admin_payload())
    stolen_refresh = integration_client.cookies["refresh_token"]

    # 1차 refresh — rotation 성공
    first_refresh = await integration_client.post("/auth/refresh")
    assert first_refresh.status_code == 200

    # 같은 (이제는 회수된) refresh 를 다시 보낸다 — 공격자 흉내.
    integration_client.cookies.set("refresh_token", stolen_refresh, path="/auth")
    second_refresh = await integration_client.post("/auth/refresh")
    assert second_refresh.status_code == 401
    assert "compromised" in second_refresh.json()["detail"].lower()

    # family 의 모든 토큰이 revoked.
    async with SessionLocal() as s:
        rows = (await s.execute(select(RefreshToken))).scalars().all()
        assert all(r.revoked_at is not None for r in rows)


# ---------------------------------------------------------------------------
# logout / logout-all
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_logout_revokes_family_and_clears_cookies(
    integration_client, integration_db
):
    SessionLocal, _ = integration_db
    await integration_client.post("/auth/register/admin", json=_admin_payload())

    resp = await integration_client.post("/auth/logout")
    assert resp.status_code == 200

    # 응답에 쿠키 삭제 헤더 (max-age=0)
    set_cookie = resp.headers.get_list("set-cookie")
    assert any('access_token=""' in s and "Max-Age=0" in s for s in set_cookie)
    assert any('refresh_token=""' in s and "Max-Age=0" in s for s in set_cookie)

    async with SessionLocal() as s:
        rows = (await s.execute(select(RefreshToken))).scalars().all()
        assert len(rows) == 1
        assert rows[0].revoked_at is not None
        assert rows[0].revoke_reason == "logout"


@pytest.mark.asyncio
async def test_logout_without_refresh_cookie_still_succeeds(integration_client):
    """refresh 쿠키가 없어도 access 쿠키는 클리어해줘야."""
    resp = await integration_client.post("/auth/logout")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_logout_all_revokes_every_session(integration_client, integration_db):
    SessionLocal, _ = integration_db
    # 가입 + 같은 계정으로 추가 로그인 → 2 family
    await integration_client.post("/auth/register/admin", json=_admin_payload())
    await integration_client.post(
        "/auth/login",
        json={"email": "admin@x.io", "password": _admin_payload()["password"]},
    )

    resp = await integration_client.post("/auth/logout-all")
    assert resp.status_code == 200
    assert resp.json()["revoked_count"] >= 2

    async with SessionLocal() as s:
        rows = (await s.execute(select(RefreshToken))).scalars().all()
        assert all(r.revoked_at is not None for r in rows)
        assert all(r.revoke_reason == "logout-all" for r in rows)


@pytest.mark.asyncio
async def test_logout_all_requires_authentication(integration_client):
    resp = await integration_client.post("/auth/logout-all")
    assert resp.status_code in (401, 403)


# ---------------------------------------------------------------------------
# get_me
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_me_returns_user_info_when_authenticated(integration_client):
    await integration_client.post("/auth/register/admin", json=_admin_payload())
    resp = await integration_client.get("/auth/me")
    assert resp.status_code == 200
    body = resp.json()
    assert body["user"]["email"] == "admin@x.io"
    assert body["facility"]["code"].startswith("FAC-")


@pytest.mark.asyncio
async def test_get_me_after_logout_returns_unauthorized(integration_client):
    await integration_client.post("/auth/register/admin", json=_admin_payload())
    await integration_client.post("/auth/logout")
    # cookies 가 클리어돼서 access_token 없음
    resp = await integration_client.get("/auth/me")
    assert resp.status_code in (401, 403)
