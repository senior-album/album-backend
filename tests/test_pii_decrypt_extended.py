"""T-003-3b/-5b — residents.py 외 read 경로 (photos / guardians / invitations) 가
envelope decrypt 를 거치는지 검증.

T-003-5b 단계에선 평문 PII 컬럼이 모델/DB 양쪽에서 drop 됐으므로, ct 가 풀려
instance attribute 로 set 되지 않으면 응답에 평문이 전혀 안 나온다 — 본 테스트
들이 정상 평문을 받아낸다는 것 자체가 ct 경로로 정확히 흐르고 있음을 증명.
"""

from __future__ import annotations

import base64
import os as _os
import platform as _platform
import sys as _sys
import types as _types

# 유효한 32-byte base64 키 — 실제 decrypt 가 동작해야 의미 있는 검증.
_os.environ.setdefault("RESIDENT_PII_KEK", base64.b64encode(b"\x09" * 32).decode())
_os.environ.setdefault("RESIDENT_NAME_HMAC_KEY", base64.b64encode(b"\x0a" * 32).decode())
_os.environ.setdefault("JWT_SECRET", "test-secret-value-for-jwt-32-bytes-min")
_os.environ.setdefault("JWT_REFRESH_SECRET", "test-refresh-secret-32bytes-minimum")

# Windows 전용 magic stub (배경: test_admin_users.py 상단)
if _platform.system() == "Windows" and "magic" not in _sys.modules:
    _stub = _types.ModuleType("magic")
    _stub.from_buffer = lambda data, mime=False: "image/jpeg"  # type: ignore[attr-defined]
    _stub.from_file = lambda path, mime=False: "image/jpeg"  # type: ignore[attr-defined]
    _sys.modules["magic"] = _stub

import uuid

import pytest

from app.core.crypto import blind_index, encrypt_field, generate_dek, wrap_dek
from app.core.security import SecurityService
from app.models.models import Facility, Guardian, Invitation, Resident, User


def test_helper_imported_in_consumer_modules():
    """photos / guardians / invitations 가 canonical helper 를 정확히 import 했는지.

    NameError 는 라우트가 실제로 invoke 될 때만 터지므로, import 자체를 정적으로
    검증해 회귀를 빨리 잡는다.
    """
    from app.api import guardians, invitations, photos
    from app.api.residents import apply_pii_decryption as canonical

    assert photos.apply_pii_decryption is canonical
    assert guardians.apply_pii_decryption is canonical
    assert invitations.apply_pii_decryption is canonical


def _make_resident_ct_only(facility_id: str, *, real_name: str) -> Resident:
    """ct 에 real_name 을 박은 row. T-003-5b 로 평문 컬럼은 모델에서 제거됨 — 응답이
    제대로 평문으로 보이려면 라우터의 `apply_pii_decryption` 이 ct 를 풀어 instance
    attribute 에 set 해야 한다."""
    dek = generate_dek()
    return Resident(
        id=str(uuid.uuid4()),
        facility_id=facility_id,
        code=f"RES-{uuid.uuid4().hex[:6].upper()}",
        dek_wrapped=wrap_dek(dek),
        name_ct=encrypt_field(real_name, dek),
        name_blind_idx=blind_index(real_name),
        is_active=True,
    )


async def _seed_facility(session) -> Facility:
    fac = Facility(id=str(uuid.uuid4()), code="FAC-T1", name="테스트원", address="서울시")
    session.add(fac)
    await session.commit()
    return fac


async def _seed_staff(session, facility_id: str) -> User:
    u = User(
        id=str(uuid.uuid4()),
        email="staff@t.io",
        name="직원",
        password_hash="$2b$12$dummy" + "x" * 50,
        role="staff",
        is_admin=False,
        is_operator=False,
        is_active=True,
        facility_id=facility_id,
    )
    session.add(u)
    await session.commit()
    return u


async def _seed_guardian_user(session) -> User:
    u = User(
        id=str(uuid.uuid4()),
        email="g@t.io",
        name="보호자",
        password_hash="$2b$12$dummy" + "x" * 50,
        role="guardian",
        is_admin=False,
        is_operator=False,
        is_active=True,
        facility_id=None,
    )
    session.add(u)
    await session.commit()
    return u


def _auth_cookies(user: User) -> dict[str, str]:
    token = SecurityService.create_access_token(
        data={"sub": user.id, "email": user.email, "role": user.role, "facility_id": user.facility_id}
    )
    return {"access_token": token}


@pytest.mark.asyncio
async def test_guardians_pending_list_returns_decrypted_resident_name(integration_client, integration_db):
    """guardians.py `/facility/{id}/pending` 가 outerjoin 된 Resident 의 ct 를 decrypt 후 반환."""
    _SessionLocal, session = integration_db
    fac = await _seed_facility(session)
    staff = await _seed_staff(session, fac.id)
    guardian_user = await _seed_guardian_user(session)

    resident = _make_resident_ct_only(fac.id, real_name="진짜할머니")
    session.add(resident)
    await session.commit()

    g = Guardian(
        id=str(uuid.uuid4()),
        user_id=guardian_user.id,
        facility_id=fac.id,
        resident_id=resident.id,
        is_approved=False,
        is_rejected=False,
        relationship_type="자녀",
        request_message="",
    )
    session.add(g)
    await session.commit()

    resp = await integration_client.get(
        f"/guardians/facility/{fac.id}/pending", cookies=_auth_cookies(staff)
    )
    assert resp.status_code == 200, resp.text
    rows = resp.json()
    assert len(rows) == 1
    # ct 가 풀려 instance attribute 로 흐른 결과
    assert rows[0]["resident_name"] == "진짜할머니"


@pytest.mark.asyncio
async def test_invitation_accept_returns_decrypted_resident_name(integration_client, integration_db):
    """invitations.py `/{id}/accept` 응답의 resident_name 이 ct 경로로 흐르는지."""
    _SessionLocal, session = integration_db
    fac = await _seed_facility(session)
    guardian_user = await _seed_guardian_user(session)

    resident = _make_resident_ct_only(fac.id, real_name="할머니진짜")
    session.add(resident)
    await session.commit()

    # phone 매칭으로 accept 가능하도록 user.phone 셋팅 + invitation 만들기
    guardian_user.phone = "010-1111-2222"
    await session.commit()

    inv = Invitation(
        id=str(uuid.uuid4()),
        facility_id=fac.id,
        resident_id=resident.id,
        invited_by=guardian_user.id,  # FK 만족용 — 실제 의미는 staff 지만 테스트 목적
        phone="010-1111-2222",
        status="pending",
        relationship_type="자녀",
    )
    session.add(inv)
    await session.commit()

    resp = await integration_client.post(
        f"/invitations/{inv.id}/accept", cookies=_auth_cookies(guardian_user)
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["resident_name"] == "할머니진짜"
    assert "할머니진짜" in body["message"]
