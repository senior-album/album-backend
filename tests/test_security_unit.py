"""
T-124: app.core.security 의 JWT/auth 단위 테스트.

verify_facility_access / verify_photo_access 는 별도 파일에서 이미 커버되어 있어,
여기서는 SecurityService (토큰 발급·검증·jti 생성), 쿠키 헬퍼, get_current_user,
역할 가드 (require_role, get_current_staff/guardian) 의 분기를 채운다.

DB 가 필요 없는 순수 단위 테스트로 유지한다 — 통합 경로(시설/입소자 권한 등)는
test_verify_facility_access.py 등에서 다룬다.
"""

import os
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
# T-055 rolling key — kid 헤더 + 다중 키 lookup
# ---------------------------------------------------------------------------


def _reload_settings_with_env(monkeypatch, env: dict[str, str | None]):
    """envvar 를 patch 한 뒤 `get_settings` cache 를 비워 재초기화시킨다.
    None 값이면 envvar 삭제. 호출 후 반환되는 settings 인스턴스가 새 keyset 보유."""
    for k, v in env.items():
        if v is None:
            monkeypatch.delenv(k, raising=False)
        else:
            monkeypatch.setenv(k, v)
    get_settings.cache_clear()
    return get_settings()


def test_legacy_single_key_mode_produces_no_kid_header():
    """기본(conftest) 환경 — JWT_SECRET 만 있으면 토큰 헤더에 kid 미포함."""
    token = SecurityService.create_access_token({"sub": "u1"})
    header = jwt.get_unverified_header(token)
    assert "kid" not in header  # legacy 호환 — 운영 토큰 형태 변경 없음
    payload = SecurityService.verify_token(token)
    assert payload["sub"] == "u1"


def test_active_kid_v1_embeds_kid_header_and_round_trips(monkeypatch):
    settings = _reload_settings_with_env(
        monkeypatch,
        {
            "JWT_KEY_V1": "kid-v1-secret-32bytes-padding-xxxxxxxxxxxxxx",
            "JWT_ACTIVE_KID": "v1",
        },
    )
    try:
        assert settings.JWT_ACTIVE_KID == "v1"
        assert "v1" in settings.jwt_keys

        token = SecurityService.create_access_token({"sub": "u1"})
        header = jwt.get_unverified_header(token)
        assert header["kid"] == "v1"

        payload = SecurityService.verify_token(token)
        assert payload["sub"] == "u1"
    finally:
        get_settings.cache_clear()


def test_old_kid_token_still_verifies_during_rotation_grace(monkeypatch):
    """v1 으로 발급된 토큰은 active 가 v2 로 바뀐 뒤에도 keyset 에 v1 이 남아있으면 검증 통과."""
    # Phase 1: v1 만 등록 + active=v1 로 토큰 발급.
    _reload_settings_with_env(
        monkeypatch,
        {
            "JWT_KEY_V1": "kid-v1-secret-32bytes-padding-xxxxxxxxxxxxxx",
            "JWT_ACTIVE_KID": "v1",
        },
    )
    try:
        old_token = SecurityService.create_access_token({"sub": "u-old"})

        # Phase 2: v2 추가 + active=v2 로 전환. v1 은 grace 동안 유지.
        _reload_settings_with_env(
            monkeypatch,
            {
                "JWT_KEY_V1": "kid-v1-secret-32bytes-padding-xxxxxxxxxxxxxx",
                "JWT_KEY_V2": "kid-v2-secret-32bytes-padding-yyyyyyyyyyyyyy",
                "JWT_ACTIVE_KID": "v2",
            },
        )
        # 옛 토큰 — v1 키로 자동 lookup 해서 검증 성공.
        payload = SecurityService.verify_token(old_token)
        assert payload["sub"] == "u-old"

        # 새 토큰은 v2 헤더로 발급.
        new_token = SecurityService.create_access_token({"sub": "u-new"})
        assert jwt.get_unverified_header(new_token)["kid"] == "v2"
        assert SecurityService.verify_token(new_token)["sub"] == "u-new"
    finally:
        get_settings.cache_clear()


def test_token_with_unknown_kid_is_rejected(monkeypatch):
    """우리 keyset 에 없는 kid 헤더 토큰은 401 — 외부 도메인 토큰 위조 방어."""
    settings = _reload_settings_with_env(
        monkeypatch,
        {
            "JWT_KEY_V1": "kid-v1-secret-32bytes-padding-xxxxxxxxxxxxxx",
            "JWT_ACTIVE_KID": "v1",
        },
    )
    try:
        # 'v99' kid 로 임의 키 서명 — keyset 에 없는 kid.
        forged = jwt.encode(
            {"sub": "attacker", "exp": datetime.utcnow() + timedelta(minutes=5)},
            "any-secret",
            algorithm=settings.JWT_ALGORITHM,
            headers={"kid": "v99"},
        )
        with pytest.raises(HTTPException) as exc:
            SecurityService.verify_token(forged)
        assert exc.value.status_code == 401
    finally:
        get_settings.cache_clear()


def test_token_after_legacy_purge_rejects_no_kid_tokens(monkeypatch):
    """회전 완료 후 legacy 키 제거 → kid 없는 옛 토큰은 더 이상 검증 안 됨."""
    # Phase 1: legacy 호환으로 발급된 토큰 (kid 헤더 없음).
    legacy_token = SecurityService.create_access_token({"sub": "u-legacy"})
    assert "kid" not in jwt.get_unverified_header(legacy_token)

    # Phase 2: legacy 제거, v1 만 운영. JWT_SECRET 도 비움.
    _reload_settings_with_env(
        monkeypatch,
        {
            "JWT_SECRET": "",  # legacy 키 환경 제거
            "JWT_KEY_V1": "kid-v1-secret-32bytes-padding-xxxxxxxxxxxxxx",
            "JWT_ACTIVE_KID": "v1",
        },
    )
    try:
        with pytest.raises(HTTPException) as exc:
            SecurityService.verify_token(legacy_token)
        assert exc.value.status_code == 401
    finally:
        get_settings.cache_clear()


def test_refresh_keyset_independent_from_access(monkeypatch):
    """access 와 refresh 의 키셋은 완전 분리 — access 키로 발급된 refresh 시도는 401."""
    _reload_settings_with_env(
        monkeypatch,
        {
            "JWT_KEY_V1": "access-v1-secret-padding-xxxxxxxxxxxxxxxxxxxxxx",
            "JWT_REFRESH_KEY_V1": "refresh-v1-secret-padding-yyyyyyyyyyyyyyyyy",
            "JWT_ACTIVE_KID": "v1",
            "JWT_REFRESH_ACTIVE_KID": "v1",
        },
    )
    try:
        # access 키로 위조된 refresh-shape 토큰 — refresh keyset 에 매칭되는 v1
        # 키가 있어도 secret 자체가 다르므로 signature 매치 실패.
        access_kid_v1 = "access-v1-secret-padding-xxxxxxxxxxxxxxxxxxxxxx"
        forged_refresh = jwt.encode(
            {
                "sub": "u1",
                "jti": "x",
                "type": "refresh",
                "exp": datetime.utcnow() + timedelta(minutes=5),
            },
            access_kid_v1,
            algorithm=get_settings().JWT_ALGORITHM,
            headers={"kid": "v1"},
        )
        with pytest.raises(HTTPException) as exc:
            SecurityService.verify_refresh_token(forged_refresh)
        assert exc.value.status_code == 401
    finally:
        get_settings.cache_clear()


def test_refresh_token_round_trip_with_active_kid(monkeypatch):
    _reload_settings_with_env(
        monkeypatch,
        {
            "JWT_REFRESH_KEY_V1": "refresh-v1-secret-padding-yyyyyyyyyyyyyyyyy",
            "JWT_REFRESH_ACTIVE_KID": "v1",
        },
    )
    try:
        token, _exp = SecurityService.create_refresh_token("u-1", "jti-1")
        header = jwt.get_unverified_header(token)
        assert header["kid"] == "v1"

        payload = SecurityService.verify_refresh_token(token)
        assert payload["sub"] == "u-1"
        assert payload["jti"] == "jti-1"
    finally:
        get_settings.cache_clear()


def test_settings_fail_when_active_kid_not_in_keyset(monkeypatch):
    """타이포 등으로 ACTIVE_KID 가 keyset 과 어긋나면 부트 실패."""
    monkeypatch.setenv("JWT_KEY_V1", "kid-v1-secret-padding-xxxxxxxxxxxxxxx")
    monkeypatch.setenv("JWT_ACTIVE_KID", "v9")  # keyset 에 없음
    monkeypatch.delenv("JWT_SECRET", raising=False)
    get_settings.cache_clear()
    try:
        with pytest.raises(ValueError, match="JWT_ACTIVE_KID"):
            get_settings()
    finally:
        # 다음 테스트 격리 — conftest 의 JWT_SECRET 시드로 복구되도록 클리어.
        get_settings.cache_clear()


def test_settings_fail_when_no_keys_provided(monkeypatch):
    """access 키 envvar 가 하나도 없으면 부트 시 ValueError. .env 파일은
    pydantic-settings 폴백 경로이므로 `_env_file=None` 으로 직접 차단해야
    로컬 dev 의 `.env` (JWT_SECRET 포함) 영향 없이 검증 가능."""
    from app.core.config import Settings

    monkeypatch.delenv("JWT_SECRET", raising=False)
    for k in list(os.environ.keys()):
        if k.startswith("JWT_KEY_"):
            monkeypatch.delenv(k, raising=False)

    with pytest.raises(ValueError, match="Access JWT 키"):
        Settings(_env_file=None)


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
