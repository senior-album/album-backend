"""
T-041: POST /admin/ops/test-alert — 운영 Discord 채널 헬스체크 엔드포인트.

검증 대상:
- 권한: 비인증/비-operator 는 차단, operator 만 통과
- 미설정: configured=False, sent=False, send_ops_alert 호출 없음
- 설정됨: send_ops_alert 호출 + 결과 그대로 반영
- AdminAuditLog: configured/sent 무관하게 1 row 항상 기록
"""

from __future__ import annotations

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

from app.api import admin as admin_module
from app.core.config import get_settings
from app.core.security import SecurityService
from app.models.models import AdminAuditLog, User


async def _seed_user(session, *, is_operator: bool, email: str) -> User:
    u = User(
        id=str(uuid.uuid4()),
        email=email,
        name="op",
        password_hash="$2b$12$dummyhashfortest" + "x" * 30,
        role="staff",
        is_operator=is_operator,
        is_active=True,
    )
    session.add(u)
    await session.commit()
    return u


def _auth_cookies(user: User) -> dict[str, str]:
    token = SecurityService.create_access_token(
        data={"sub": user.id, "email": user.email, "role": user.role, "facility_id": None}
    )
    return {"access_token": token}


@pytest.mark.asyncio
async def test_test_alert_requires_auth(integration_client):
    resp = await integration_client.post("/admin/ops/test-alert")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_test_alert_requires_operator(integration_client, integration_db):
    _, session = integration_db
    user = await _seed_user(session, is_operator=False, email="not-op@t.io")
    integration_client.cookies.update(_auth_cookies(user))

    resp = await integration_client.post("/admin/ops/test-alert")
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_test_alert_returns_unconfigured_when_url_unset(
    integration_client, integration_db, monkeypatch
):
    """webhook URL 비어있으면 configured=False, sent=False, notifier 미호출."""
    monkeypatch.setenv("DISCORD_OPS_WEBHOOK_URL", "")
    get_settings.cache_clear()

    called: list = []

    async def _spy(*args, **kwargs):
        called.append((args, kwargs))
        return True

    monkeypatch.setattr(admin_module, "send_ops_alert", _spy)

    _, session = integration_db
    op = await _seed_user(session, is_operator=True, email="op@t.io")
    integration_client.cookies.update(_auth_cookies(op))

    resp = await integration_client.post("/admin/ops/test-alert")
    assert resp.status_code == 200
    body = resp.json()
    assert body == {"configured": False, "sent": False}
    assert called == []  # notifier 호출 자체를 안 함

    # AdminAuditLog 1 row 기록 — 미설정 상태도 추적 가능해야 함
    rows = (await session.execute(select(AdminAuditLog))).scalars().all()
    assert len(rows) == 1
    assert rows[0].action == "ops_test_alert"
    assert rows[0].performed_by == op.id
    assert "configured=False" in (rows[0].detail or "")
    assert "sent=False" in (rows[0].detail or "")
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_test_alert_calls_notifier_when_configured(
    integration_client, integration_db, monkeypatch
):
    monkeypatch.setenv("DISCORD_OPS_WEBHOOK_URL", "https://discord.test/webhook/abc")
    get_settings.cache_clear()

    captured: list[dict] = []

    async def _spy(title, message, *, level="error", fields=None):
        captured.append(
            {"title": title, "message": message, "level": level, "fields": fields}
        )
        return True

    monkeypatch.setattr(admin_module, "send_ops_alert", _spy)

    _, session = integration_db
    op = await _seed_user(session, is_operator=True, email="op2@t.io")
    integration_client.cookies.update(_auth_cookies(op))

    resp = await integration_client.post("/admin/ops/test-alert")
    assert resp.status_code == 200
    body = resp.json()
    assert body == {"configured": True, "sent": True}

    assert len(captured) == 1
    call = captured[0]
    assert "test" in call["title"].lower()
    assert call["level"] == "info"
    # 호출자 이메일이 메시지 body 에 포함 (운영 채널에서 누가 핑 했는지 추적)
    assert "op2@t.io" in call["message"]

    rows = (await session.execute(select(AdminAuditLog))).scalars().all()
    assert len(rows) == 1
    assert "configured=True" in (rows[0].detail or "")
    assert "sent=True" in (rows[0].detail or "")
    get_settings.cache_clear()


@pytest.mark.asyncio
async def test_test_alert_records_send_failure(
    integration_client, integration_db, monkeypatch
):
    """notifier 가 False (송출 실패) 반환해도 200 + sent=False, 감사 로그는 그대로."""
    monkeypatch.setenv("DISCORD_OPS_WEBHOOK_URL", "https://discord.test/webhook/xyz")
    get_settings.cache_clear()

    async def _failing(*_args, **_kwargs):
        return False

    monkeypatch.setattr(admin_module, "send_ops_alert", _failing)

    _, session = integration_db
    op = await _seed_user(session, is_operator=True, email="op3@t.io")
    integration_client.cookies.update(_auth_cookies(op))

    resp = await integration_client.post("/admin/ops/test-alert")
    assert resp.status_code == 200
    assert resp.json() == {"configured": True, "sent": False}

    rows = (await session.execute(select(AdminAuditLog))).scalars().all()
    assert len(rows) == 1
    assert "configured=True" in (rows[0].detail or "")
    assert "sent=False" in (rows[0].detail or "")
    get_settings.cache_clear()
