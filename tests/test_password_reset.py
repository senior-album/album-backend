"""
T-306: 비밀번호 재설정 통합 테스트.

- /auth/password/reset/request: 이메일/SMS 채널, 사용자 enum 방지 (항상 200),
  토큰 row 생성, 발송 시도
- /auth/password/reset/confirm: 만료/사용됨/잘못된 토큰 분기, 1회용 enforced
"""

from __future__ import annotations

import os as _os
import platform as _platform
import sys as _sys
import types as _types

# Windows magic 라이브러리 segfault 회피 (다른 통합 테스트와 동일 패턴)
if _platform.system() == "Windows" and "magic" not in _sys.modules:
    _stub = _types.ModuleType("magic")
    _stub.from_buffer = lambda data, mime=False: "image/jpeg"  # type: ignore[attr-defined]
    _stub.from_file = lambda path, mime=False: "image/jpeg"  # type: ignore[attr-defined]
    _sys.modules["magic"] = _stub

_os.environ.setdefault("JWT_SECRET", "test-secret-value-for-jwt-32-bytes-min")
_os.environ.setdefault("JWT_REFRESH_SECRET", "test-refresh-secret-32bytes-minimum")
_os.environ.setdefault("RESIDENT_PII_KEK", "0" * 64)
_os.environ.setdefault("RESIDENT_NAME_HMAC_KEY", "1" * 64)

import hashlib
import uuid
from datetime import datetime, timedelta

import pytest
from sqlalchemy import select

from app.api.auth import hash_password, verify_password
from app.models.models import PasswordResetToken, User


# ---------------------------------------------------------------------------
# 헬퍼
# ---------------------------------------------------------------------------


async def _seed_user(
    session,
    *,
    email: str,
    phone: str | None = None,
    name: str = "이름",
    password: str = "OldPassword123",
    is_active: bool = True,
) -> User:
    u = User(
        id=str(uuid.uuid4()),
        email=email,
        name=name,
        password_hash=hash_password(password),
        role="guardian",
        is_active=is_active,
        phone=phone,
    )
    session.add(u)
    await session.commit()
    return u


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# /auth/password/reset/request
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_password_reset_request_email_creates_token(
    integration_client, integration_db, monkeypatch
):
    """이메일 채널 — 매칭 사용자 있으면 token row 생성 + email provider 호출."""
    from app.api import auth as auth_module

    sent: list[dict] = []

    class _StubEmail:
        async def send(self, **kwargs):
            sent.append(kwargs)

    monkeypatch.setattr(auth_module, "get_email_provider", lambda: _StubEmail())

    _SL, session = integration_db
    user = await _seed_user(session, email="parent@example.com", name="박보호자")

    resp = await integration_client.post(
        "/auth/password/reset/request",
        json={"identifier": "parent@example.com", "channel": "email"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "message" in body  # generic 본문

    rows = (await session.execute(select(PasswordResetToken))).scalars().all()
    assert len(rows) == 1
    row = rows[0]
    assert row.user_id == user.id
    assert row.channel == "email"
    assert row.used_at is None
    assert row.expires_at > datetime.utcnow()

    # email stub 호출 검증 (subject/to/링크 포함)
    assert len(sent) == 1
    assert sent[0]["to"] == "parent@example.com"
    assert "비밀번호" in sent[0]["subject"]
    assert "/reset-password/" in sent[0]["html"]


@pytest.mark.asyncio
async def test_password_reset_request_sms_creates_token(
    integration_client, integration_db, monkeypatch
):
    """SMS 채널 — phone 매칭 사용자 있으면 token row 생성 + sms provider 호출."""
    from app.api import auth as auth_module

    sent: list[tuple[str, str]] = []

    class _StubSms:
        async def send(self, phone, message):
            sent.append((phone, message))

    monkeypatch.setattr(auth_module, "get_sms_provider", lambda: _StubSms())

    _SL, session = integration_db
    user = await _seed_user(session, email="x@y.io", phone="01012345678")

    resp = await integration_client.post(
        "/auth/password/reset/request",
        json={"identifier": "01012345678", "channel": "sms"},
    )
    assert resp.status_code == 200, resp.text

    rows = (await session.execute(select(PasswordResetToken))).scalars().all()
    assert len(rows) == 1
    assert rows[0].user_id == user.id
    assert rows[0].channel == "sms"

    assert len(sent) == 1
    phone_arg, msg_arg = sent[0]
    assert phone_arg == "01012345678"
    assert "/reset-password/" in msg_arg


@pytest.mark.asyncio
async def test_password_reset_request_unknown_user_returns_generic_200(
    integration_client, integration_db, monkeypatch
):
    """T-306 보안: 미매칭 사용자도 동일 200 (enumeration 방지). token row 안 생김."""
    from app.api import auth as auth_module

    sent: list[dict] = []

    class _StubEmail:
        async def send(self, **kwargs):
            sent.append(kwargs)

    monkeypatch.setattr(auth_module, "get_email_provider", lambda: _StubEmail())

    _SL, session = integration_db
    resp = await integration_client.post(
        "/auth/password/reset/request",
        json={"identifier": "nobody@nowhere.com", "channel": "email"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "message" in body

    rows = (await session.execute(select(PasswordResetToken))).scalars().all()
    assert rows == []
    assert sent == []  # provider 호출도 안 됨


@pytest.mark.asyncio
async def test_password_reset_request_invalid_channel_400(integration_client, integration_db):
    resp = await integration_client.post(
        "/auth/password/reset/request",
        json={"identifier": "a@b.io", "channel": "fax"},
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_password_reset_request_dispatch_failure_still_200(
    integration_client, integration_db, monkeypatch
):
    """발송 실패해도 토큰은 살아있고 응답은 generic 200 (다른 채널로 재시도 가능)."""
    from app.api import auth as auth_module

    class _FailingEmail:
        async def send(self, **kwargs):
            raise RuntimeError("Brevo down")

    monkeypatch.setattr(auth_module, "get_email_provider", lambda: _FailingEmail())

    _SL, session = integration_db
    await _seed_user(session, email="z@y.io")

    resp = await integration_client.post(
        "/auth/password/reset/request",
        json={"identifier": "z@y.io", "channel": "email"},
    )
    assert resp.status_code == 200, resp.text
    rows = (await session.execute(select(PasswordResetToken))).scalars().all()
    assert len(rows) == 1


# ---------------------------------------------------------------------------
# /auth/password/reset/confirm
# ---------------------------------------------------------------------------


async def _seed_token(session, *, user_id: str, token: str, **overrides) -> PasswordResetToken:
    base = dict(
        id=str(uuid.uuid4()),
        user_id=user_id,
        token_hash=_hash(token),
        channel="email",
        expires_at=datetime.utcnow() + timedelta(minutes=30),
        used_at=None,
    )
    base.update(overrides)
    row = PasswordResetToken(**base)
    session.add(row)
    await session.commit()
    return row


@pytest.mark.asyncio
async def test_password_reset_confirm_happy_path(integration_client, integration_db):
    _SL, session = integration_db
    user = await _seed_user(session, email="a@b.io", password="OldPass123!")
    token = "good-token-abc"
    await _seed_token(session, user_id=user.id, token=token)

    resp = await integration_client.post(
        "/auth/password/reset/confirm",
        json={"token": token, "new_password": "NewSecret456!"},
    )
    assert resp.status_code == 200, resp.text

    await session.refresh(user)
    assert verify_password("NewSecret456!", user.password_hash)
    assert not verify_password("OldPass123!", user.password_hash)

    # 토큰이 사용됨 (used_at) 으로 박힘
    rows = (await session.execute(select(PasswordResetToken))).scalars().all()
    assert rows[0].used_at is not None


@pytest.mark.asyncio
async def test_password_reset_confirm_invalid_token_400(integration_client, integration_db):
    resp = await integration_client.post(
        "/auth/password/reset/confirm",
        json={"token": "nonexistent", "new_password": "NewSecret456!"},
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_password_reset_confirm_expired_400(integration_client, integration_db):
    _SL, session = integration_db
    user = await _seed_user(session, email="exp@b.io")
    token = "expired-token"
    await _seed_token(
        session,
        user_id=user.id,
        token=token,
        expires_at=datetime.utcnow() - timedelta(minutes=1),
    )

    resp = await integration_client.post(
        "/auth/password/reset/confirm",
        json={"token": token, "new_password": "NewSecret456!"},
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_password_reset_confirm_already_used_400(integration_client, integration_db):
    """1회용 enforce — used_at 이 박힌 토큰은 재사용 불가."""
    _SL, session = integration_db
    user = await _seed_user(session, email="used@b.io")
    token = "used-once"
    await _seed_token(
        session,
        user_id=user.id,
        token=token,
        used_at=datetime.utcnow() - timedelta(seconds=10),
    )

    resp = await integration_client.post(
        "/auth/password/reset/confirm",
        json={"token": token, "new_password": "NewSecret456!"},
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_password_reset_confirm_short_password_400(integration_client, integration_db):
    _SL, session = integration_db
    user = await _seed_user(session, email="short@b.io")
    token = "short-pwd-token"
    await _seed_token(session, user_id=user.id, token=token)

    resp = await integration_client.post(
        "/auth/password/reset/confirm",
        json={"token": token, "new_password": "abc"},
    )
    assert resp.status_code == 400
