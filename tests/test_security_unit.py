"""
T-124: app.core.security 의 JWT/auth 단위 테스트.

verify_facility_access / verify_photo_access 는 별도 파일에서 이미 커버되어 있어,
여기서는 SecurityService (토큰 발급·검증·jti 생성), 쿠키 헬퍼, get_current_user,
역할 가드 (require_role, get_current_staff/guardian) 의 분기를 채운다.

DB 가 필요 없는 순수 단위 테스트로 유지한다 — 통합 경로(시설/입소자 권한 등)는
test_verify_facility_access.py 등에서 다룬다.
"""

from datetime import datetime, timedelta

import pytest
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from jose import jwt

from app.core import security
from app.core.config import get_settings
from app.core.security import (
    COOKIE_NAME,
    REFRESH_COOKIE_NAME,
    REFRESH_COOKIE_PATH,
    SecurityService,
    clear_auth_cookie,
    clear_refresh_cookie,
    get_current_guardian,
    get_current_staff,
    get_current_user,
    require_role,
    set_auth_cookie,
    set_refresh_cookie,
)


def _build_request(*, cookies: dict | None = None, headers: dict | None = None) -> Request:
    """get_current_user 가 읽는 cookies / headers 만 채운 가짜 ASGI scope."""
    raw_headers = []
    if cookies:
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        raw_headers.append((b"cookie", cookie_str.encode()))
    for k, v in (headers or {}).items():
        raw_headers.append((k.lower().encode(), v.encode()))
    return Request({"type": "http", "headers": raw_headers})


# ---------------------------------------------------------------------------
# SecurityService.create_access_token / verify_token
# ---------------------------------------------------------------------------


def test_create_access_token_round_trip():
    token = SecurityService.create_access_token({"sub": "u1", "role": "staff"})
    payload = SecurityService.verify_token(token)
    assert payload["sub"] == "u1"
    assert payload["role"] == "staff"
    assert "exp" in payload


def test_create_access_token_default_expiry_uses_settings():
    settings = get_settings()
    before = datetime.utcnow()
    token = SecurityService.create_access_token({"sub": "u1"})
    payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
    exp = datetime.utcfromtimestamp(payload["exp"])
    delta = exp - before
    # 기본 만료는 settings.JWT_EXPIRE_MINUTES — 약간의 실행 지연 허용.
    assert timedelta(minutes=settings.JWT_EXPIRE_MINUTES - 1) <= delta <= timedelta(
        minutes=settings.JWT_EXPIRE_MINUTES + 1
    )


def test_create_access_token_explicit_expires_delta_overrides_default():
    token = SecurityService.create_access_token({"sub": "u1"}, expires_delta=timedelta(seconds=5))
    settings = get_settings()
    payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
    delta = datetime.utcfromtimestamp(payload["exp"]) - datetime.utcnow()
    assert timedelta(seconds=0) < delta <= timedelta(seconds=10)


def test_verify_token_rejects_wrong_signature():
    settings = get_settings()
    bogus = jwt.encode({"sub": "u1"}, "not-the-real-secret", algorithm=settings.JWT_ALGORITHM)
    with pytest.raises(HTTPException) as exc:
        SecurityService.verify_token(bogus)
    assert exc.value.status_code == 401
    assert exc.value.headers["WWW-Authenticate"] == "Bearer"


def test_verify_token_rejects_expired():
    expired = SecurityService.create_access_token(
        {"sub": "u1"}, expires_delta=timedelta(seconds=-1)
    )
    with pytest.raises(HTTPException) as exc:
        SecurityService.verify_token(expired)
    assert exc.value.status_code == 401


def test_verify_token_rejects_garbage():
    with pytest.raises(HTTPException) as exc:
        SecurityService.verify_token("not-a-jwt")
    assert exc.value.status_code == 401


# ---------------------------------------------------------------------------
# SecurityService.create_refresh_token / verify_refresh_token / generate_jti
# ---------------------------------------------------------------------------


def test_create_refresh_token_payload_and_expiry():
    jti = SecurityService.generate_jti()
    token, expires_at = SecurityService.create_refresh_token("user-1", jti)
    payload = SecurityService.verify_refresh_token(token)
    assert payload["sub"] == "user-1"
    assert payload["jti"] == jti
    assert payload["type"] == "refresh"
    # expires_at 은 settings.JWT_REFRESH_EXPIRE_MINUTES 후. 1분 마진.
    settings = get_settings()
    expected = datetime.utcnow() + timedelta(minutes=settings.JWT_REFRESH_EXPIRE_MINUTES)
    assert abs((expires_at - expected).total_seconds()) < 60


def test_verify_refresh_token_rejects_access_token_shape():
    """access secret 으로 서명된 토큰은 refresh 검증에서 떨어져야 한다."""
    access = SecurityService.create_access_token({"sub": "u1", "type": "access"})
    with pytest.raises(HTTPException) as exc:
        SecurityService.verify_refresh_token(access)
    assert exc.value.status_code == 401


def test_verify_refresh_token_rejects_missing_type_claim():
    """refresh secret 으로 서명되었어도 type=refresh 가 없으면 거부 (T-009 약속)."""
    settings = get_settings()
    forged = jwt.encode(
        {"sub": "u1", "jti": "x", "exp": datetime.utcnow() + timedelta(minutes=5)},
        settings.JWT_REFRESH_SECRET,
        algorithm=settings.JWT_ALGORITHM,
    )
    with pytest.raises(HTTPException) as exc:
        SecurityService.verify_refresh_token(forged)
    assert exc.value.status_code == 401


def test_verify_refresh_token_rejects_expired():
    settings = get_settings()
    expired = jwt.encode(
        {
            "sub": "u1",
            "jti": "x",
            "type": "refresh",
            "exp": datetime.utcnow() - timedelta(seconds=1),
        },
        settings.JWT_REFRESH_SECRET,
        algorithm=settings.JWT_ALGORITHM,
    )
    with pytest.raises(HTTPException) as exc:
        SecurityService.verify_refresh_token(expired)
    assert exc.value.status_code == 401


def test_generate_jti_random_and_url_safe():
    a = SecurityService.generate_jti()
    b = SecurityService.generate_jti()
    assert a != b
    # token_urlsafe(32) → 43자 base64url (패딩 없음).
    assert len(a) >= 32
    assert all(c.isalnum() or c in "-_" for c in a)


# ---------------------------------------------------------------------------
# verify_firebase_token (Firebase 비활성 상태에서 동작 확인)
# ---------------------------------------------------------------------------


def test_verify_firebase_token_returns_empty_when_disabled():
    # FIREBASE_AVAILABLE = False — 어떤 토큰이든 빈 dict 로 통과 (현재 미사용).
    assert SecurityService.verify_firebase_token("anything") == {}


# ---------------------------------------------------------------------------
# 쿠키 헬퍼 (set/clear access · refresh)
# ---------------------------------------------------------------------------


def _cookie_attrs(response: JSONResponse, name: str) -> dict:
    """set-cookie 헤더 중 name 으로 시작하는 첫 항목을 attr dict 로 파싱."""
    for header_name, header_val in response.raw_headers:
        if header_name.lower() != b"set-cookie":
            continue
        text = header_val.decode()
        if not text.startswith(f"{name}="):
            continue
        parts = [p.strip() for p in text.split(";")]
        attrs = {"value": parts[0].split("=", 1)[1]}
        for p in parts[1:]:
            if "=" in p:
                k, v = p.split("=", 1)
                attrs[k.lower()] = v
            else:
                attrs[p.lower()] = True
        return attrs
    raise AssertionError(f"set-cookie {name} not found")


def test_set_auth_cookie_sets_expected_attrs(monkeypatch):
    # DEBUG=False (production) → secure=True 분기.
    settings = get_settings()
    monkeypatch.setattr(settings, "DEBUG", False)
    get_settings.cache_clear()
    monkeypatch.setattr("app.core.security.get_settings", lambda: settings)

    resp = JSONResponse({})
    set_auth_cookie(resp, "tok-abc")
    attrs = _cookie_attrs(resp, COOKIE_NAME)
    assert attrs["value"] == "tok-abc"
    assert attrs.get("httponly") is True
    assert attrs.get("secure") is True
    assert attrs.get("samesite", "").lower() == "lax"
    assert attrs.get("path") == "/"


def test_set_refresh_cookie_uses_restricted_path(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr("app.core.security.get_settings", lambda: settings)
    resp = JSONResponse({})
    set_refresh_cookie(resp, "ref-abc")
    attrs = _cookie_attrs(resp, REFRESH_COOKIE_NAME)
    assert attrs["value"] == "ref-abc"
    assert attrs.get("path") == REFRESH_COOKIE_PATH  # /auth — 공격면 축소


def test_set_auth_cookie_in_debug_mode_disables_secure(monkeypatch):
    """로컬 개발(DEBUG=True, http) 에서는 secure 플래그가 떨어져야 쿠키가 박힌다."""
    settings = get_settings()
    monkeypatch.setattr(settings, "DEBUG", True)
    monkeypatch.setattr("app.core.security.get_settings", lambda: settings)

    resp = JSONResponse({})
    set_auth_cookie(resp, "tok")
    attrs = _cookie_attrs(resp, COOKIE_NAME)
    assert "secure" not in attrs


def test_clear_auth_cookie_emits_delete(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr("app.core.security.get_settings", lambda: settings)
    resp = JSONResponse({})
    clear_auth_cookie(resp)
    attrs = _cookie_attrs(resp, COOKIE_NAME)
    # delete_cookie 는 빈 값 + Max-Age=0 형태로 전송.
    assert attrs["value"] == '""'
    assert attrs.get("max-age") == "0"


def test_clear_refresh_cookie_emits_delete(monkeypatch):
    settings = get_settings()
    monkeypatch.setattr("app.core.security.get_settings", lambda: settings)
    resp = JSONResponse({})
    clear_refresh_cookie(resp)
    attrs = _cookie_attrs(resp, REFRESH_COOKIE_NAME)
    assert attrs.get("max-age") == "0"
    assert attrs.get("path") == REFRESH_COOKIE_PATH


# ---------------------------------------------------------------------------
# get_current_user — 쿠키 / Bearer / 누락 / payload 결함
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_current_user_reads_cookie_first():
    token = SecurityService.create_access_token(
        {"sub": "u-cookie", "email": "c@x.io", "role": "staff", "facility_id": "fac-1"}
    )
    req = _build_request(cookies={COOKIE_NAME: token})
    user = await get_current_user(req)
    assert user == {
        "user_id": "u-cookie",
        "email": "c@x.io",
        "role": "staff",
        "facility_id": "fac-1",
    }


@pytest.mark.asyncio
async def test_get_current_user_falls_back_to_bearer_header():
    token = SecurityService.create_access_token({"sub": "u-bearer"})
    req = _build_request(headers={"Authorization": f"Bearer {token}"})
    user = await get_current_user(req)
    assert user["user_id"] == "u-bearer"
    assert user["role"] == "user"  # default


@pytest.mark.asyncio
async def test_get_current_user_ignores_non_bearer_authorization_header():
    req = _build_request(headers={"Authorization": "Basic dXNlcjpwdw=="})
    with pytest.raises(HTTPException) as exc:
        await get_current_user(req)
    assert exc.value.status_code == 401
    assert exc.value.detail == "Not authenticated"


@pytest.mark.asyncio
async def test_get_current_user_no_token_anywhere():
    req = _build_request()
    with pytest.raises(HTTPException) as exc:
        await get_current_user(req)
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_get_current_user_rejects_payload_without_sub():
    settings = get_settings()
    no_sub = jwt.encode(
        {"email": "x@y.io", "exp": datetime.utcnow() + timedelta(minutes=5)},
        settings.JWT_SECRET,
        algorithm=settings.JWT_ALGORITHM,
    )
    req = _build_request(cookies={COOKIE_NAME: no_sub})
    with pytest.raises(HTTPException) as exc:
        await get_current_user(req)
    assert exc.value.status_code == 401
    assert exc.value.detail == "Invalid token payload"


@pytest.mark.asyncio
async def test_get_current_user_rejects_invalid_signature():
    settings = get_settings()
    bogus = jwt.encode(
        {"sub": "u1", "exp": datetime.utcnow() + timedelta(minutes=5)},
        "wrong-secret",
        algorithm=settings.JWT_ALGORITHM,
    )
    req = _build_request(cookies={COOKIE_NAME: bogus})
    with pytest.raises(HTTPException) as exc:
        await get_current_user(req)
    assert exc.value.status_code == 401


# ---------------------------------------------------------------------------
# require_role 데코레이터
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_require_role_allows_matching():
    @require_role("staff", "admin")
    async def handler(*, current_user):
        return current_user["user_id"]

    out = await handler(current_user={"user_id": "u1", "role": "admin"})
    assert out == "u1"


@pytest.mark.asyncio
async def test_require_role_blocks_mismatch():
    @require_role("staff")
    async def handler(*, current_user):
        return "ok"

    with pytest.raises(HTTPException) as exc:
        await handler(current_user={"user_id": "u1", "role": "guardian"})
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_require_role_requires_authenticated_user():
    @require_role("staff")
    async def handler(*, current_user):
        return "ok"

    with pytest.raises(HTTPException) as exc:
        await handler(current_user=None)
    assert exc.value.status_code == 401


# ---------------------------------------------------------------------------
# get_current_staff / get_current_guardian
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_current_staff_passes_for_staff():
    user = {"user_id": "u1", "role": "staff"}
    assert await get_current_staff(current_user=user) is user


@pytest.mark.asyncio
async def test_get_current_staff_blocks_non_staff():
    with pytest.raises(HTTPException) as exc:
        await get_current_staff(current_user={"user_id": "u1", "role": "guardian"})
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_get_current_guardian_passes_for_guardian():
    user = {"user_id": "u1", "role": "guardian"}
    assert await get_current_guardian(current_user=user) is user


@pytest.mark.asyncio
async def test_get_current_guardian_blocks_non_guardian():
    with pytest.raises(HTTPException) as exc:
        await get_current_guardian(current_user={"user_id": "u1", "role": "staff"})
    assert exc.value.status_code == 403


# ---------------------------------------------------------------------------
# require_operator — DB 재검증 (T-020 운영자 권한 게이트)
# ---------------------------------------------------------------------------


@pytest.fixture
async def operator_session():
    """require_operator 만 위해 가벼운 인메모리 SQLite 세션."""
    import uuid

    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

    from app.models.models import Base, User

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with SessionLocal() as s:
        yield s, User, uuid
    await engine.dispose()


@pytest.mark.asyncio
async def test_require_operator_allows_operator(operator_session):
    from app.core.security import require_operator

    db, User, uuid = operator_session
    u = User(
        id=str(uuid.uuid4()),
        email="op@x.io",
        name="O",
        role="staff",
        is_active=True,
        is_operator=True,
    )
    db.add(u)
    await db.commit()
    out = await require_operator(current_user={"user_id": u.id}, db=db)
    assert out["user_id"] == u.id


@pytest.mark.asyncio
async def test_require_operator_blocks_non_operator(operator_session):
    from app.core.security import require_operator

    db, User, uuid = operator_session
    u = User(
        id=str(uuid.uuid4()),
        email="staff@x.io",
        name="S",
        role="staff",
        is_active=True,
        is_operator=False,
    )
    db.add(u)
    await db.commit()
    with pytest.raises(HTTPException) as exc:
        await require_operator(current_user={"user_id": u.id}, db=db)
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_require_operator_blocks_inactive_user(operator_session):
    from app.core.security import require_operator

    db, User, uuid = operator_session
    u = User(
        id=str(uuid.uuid4()),
        email="dead@x.io",
        name="D",
        role="staff",
        is_active=False,
        is_operator=True,  # 비활성이면 운영자라도 막아야 한다.
    )
    db.add(u)
    await db.commit()
    with pytest.raises(HTTPException) as exc:
        await require_operator(current_user={"user_id": u.id}, db=db)
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_require_operator_blocks_unknown_user(operator_session):
    from app.core.security import require_operator

    db, _User, _uuid = operator_session
    with pytest.raises(HTTPException) as exc:
        await require_operator(current_user={"user_id": "nonexistent"}, db=db)
    assert exc.value.status_code == 401
