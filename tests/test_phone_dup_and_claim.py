"""
PhoneOtp dup 충돌 (409) + PhoneClaimReport 신고 endpoint 통합 테스트.
"""

from __future__ import annotations

import os as _os
import platform as _platform
import sys as _sys
import types as _types

# Windows + libmagic segfault 회피 (test_admin_users.py 와 같은 패턴).
if _platform.system() == "Windows" and "magic" not in _sys.modules:
    _stub = _types.ModuleType("magic")
    _stub.from_buffer = lambda data, mime=False: "image/jpeg"  # type: ignore[attr-defined]
    _stub.from_file = lambda path, mime=False: "image/jpeg"  # type: ignore[attr-defined]
    _sys.modules["magic"] = _stub

# Settings 필수 env 더미 주입 — .env stale 우회.
_os.environ.setdefault("JWT_SECRET", "test-secret-value-for-jwt-32-bytes-min")
_os.environ.setdefault("JWT_REFRESH_SECRET", "test-refresh-secret-32bytes-minimum")
_os.environ.setdefault("RESIDENT_PII_KEK", "0" * 64)
_os.environ.setdefault("RESIDENT_NAME_HMAC_KEY", "1" * 64)

_os.environ.setdefault("USER_PHONE_HMAC_KEY", "2" * 64)
import uuid

import pytest
from sqlalchemy import select

from app.core.security import SecurityService
from app.models.models import PhoneClaimReport, User
from app.services.phone_otp import _inmemory_otp


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


async def _seed_user(session, *, email: str, role: str = "guardian") -> User:
    u = User(
        id=str(uuid.uuid4()),
        email=email,
        name="이름",
        password_hash="$2b$12$dummyhashfortest" + "x" * 30,
        role=role,
        is_admin=False,
        is_operator=False,
        is_active=True,
    )
    session.add(u)
    await session.commit()
    return u


def setup_function(_fn):
    _inmemory_otp.clear()


# ---------------------------------------------------------------------------
# OTP verify dup 충돌
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_returns_409_when_phone_already_owned_by_another_user(
    integration_client, integration_db
):
    _SessionLocal, session = integration_db
    user_a = await _seed_user(session, email="a@x.io")
    user_b = await _seed_user(session, email="b@x.io")
    phone = "01012345678"

    # A 가 phone 으로 send + verify → A.phone 등록 성공
    resp = await integration_client.post(
        "/auth/phone/otp/send",
        json={"phone": phone},
        cookies=_auth_cookies(user_a),
    )
    assert resp.status_code == 200, resp.text
    code_a = _inmemory_otp[phone][1]["code"]

    resp = await integration_client.post(
        "/auth/phone/otp/verify",
        json={"phone": phone, "code": code_a},
        cookies=_auth_cookies(user_a),
    )
    assert resp.status_code == 200, resp.text

    # B 가 같은 phone 으로 send + verify → 409
    resp = await integration_client.post(
        "/auth/phone/otp/send",
        json={"phone": phone},
        cookies=_auth_cookies(user_b),
    )
    assert resp.status_code == 200, resp.text
    code_b = _inmemory_otp[phone][1]["code"]

    resp = await integration_client.post(
        "/auth/phone/otp/verify",
        json={"phone": phone, "code": code_b},
        cookies=_auth_cookies(user_b),
    )
    assert resp.status_code == 409
    assert "이미" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_verify_succeeds_for_owner_reverification(
    integration_client, integration_db
):
    """이미 자기 phone 으로 인증된 사용자가 같은 phone 재인증해도 200."""
    _SessionLocal, session = integration_db
    user_a = await _seed_user(session, email="a@x.io")
    phone = "01012345678"

    for _ in range(2):
        await integration_client.post(
            "/auth/phone/otp/send",
            json={"phone": phone},
            cookies=_auth_cookies(user_a),
        )
        code = _inmemory_otp[phone][1]["code"]
        resp = await integration_client.post(
            "/auth/phone/otp/verify",
            json={"phone": phone, "code": code},
            cookies=_auth_cookies(user_a),
        )
        assert resp.status_code == 200, resp.text


# ---------------------------------------------------------------------------
# /support/phone-claim
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_phone_claim_requires_auth(integration_client):
    resp = await integration_client.post(
        "/support/phone-claim", json={"phone": "01012345678"}
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_phone_claim_creates_report(integration_client, integration_db):
    _SessionLocal, session = integration_db
    reporter = await _seed_user(session, email="r@x.io")

    resp = await integration_client.post(
        "/support/phone-claim",
        json={"phone": "010-1234-5678", "note": "내 번호 아닙니다"},
        cookies=_auth_cookies(reporter),
    )
    assert resp.status_code == 200, resp.text
    payload = resp.json()
    assert payload["id"]
    assert payload["created_at"]

    # DB 검증
    async with _SessionLocal() as s2:
        rows = (await s2.execute(select(PhoneClaimReport))).scalars().all()
    assert len(rows) == 1
    r = rows[0]
    assert r.reporter_user_id == reporter.id
    assert r.claimed_phone == "01012345678"  # 정규화됨
    assert r.note == "내 번호 아닙니다"
    assert r.status == "pending"


@pytest.mark.asyncio
async def test_phone_claim_normalizes_and_handles_empty(integration_client, integration_db):
    _SessionLocal, session = integration_db
    reporter = await _seed_user(session, email="r2@x.io")

    # 정규화 후 빈 문자열이면 400
    resp = await integration_client.post(
        "/support/phone-claim",
        json={"phone": "  ---  "},
        cookies=_auth_cookies(reporter),
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_phone_claim_note_optional(integration_client, integration_db):
    _SessionLocal, session = integration_db
    reporter = await _seed_user(session, email="r3@x.io")

    resp = await integration_client.post(
        "/support/phone-claim",
        json={"phone": "01099998888"},  # note 누락
        cookies=_auth_cookies(reporter),
    )
    assert resp.status_code == 200, resp.text
    async with _SessionLocal() as s2:
        rows = (await s2.execute(select(PhoneClaimReport))).scalars().all()
    assert rows and rows[0].note == ""
