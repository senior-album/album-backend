"""T-323: 보호자 본인 시설 연결 신청 취소 / 거부 이력 숨김 통합 테스트.

대상 엔드포인트:
- DELETE /guardians/me/connect/{guardian_id} — pending 만 본인 취소 (soft delete)
- POST   /guardians/me/{guardian_id}/dismiss — rejected 신청 본인 화면에서 숨김
- GET    /guardians/me/status — cancelled / hidden 둘 다 응답에서 제외
- GET    /guardians/facility/{id}/pending — cancelled 는 시설 pending 에서도 제외
- GET    /guardians/facility/{id}/all — cancelled / hidden 모두 시설 측엔 보존
- POST   /guardians/me/connect — 본인이 취소한 신청은 dup check 통과 (재신청 가능)
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
from datetime import datetime, timedelta

import pytest
from sqlalchemy import select

from app.core.security import SecurityService
from app.models.models import Facility, Guardian, User


async def _seed_facility(session, *, code: str = "FAC-T323", name: str = "햇살요양원") -> Facility:
    fac = Facility(id=str(uuid.uuid4()), code=code, name=name, address="서울시 어딘가")
    session.add(fac)
    await session.commit()
    return fac


async def _seed_guardian_user(
    session,
    *,
    email: str = "guardian@x.io",
    phone: str = "01099998888",
) -> User:
    u = User(
        id=str(uuid.uuid4()),
        email=email,
        name="보호자",
        password_hash="$2b$12$dummy" + "x" * 50,
        role="guardian",
        is_active=True,
        phone=phone,
        phone_verified_at=datetime.utcnow(),
    )
    session.add(u)
    await session.commit()
    return u


async def _seed_staff_user(session, *, facility_id: str, email: str = "staff@x.io") -> User:
    u = User(
        id=str(uuid.uuid4()),
        email=email,
        name="직원",
        password_hash="$2b$12$dummy" + "x" * 50,
        role="staff",
        is_active=True,
        is_staff_approved=True,
        facility_id=facility_id,
    )
    session.add(u)
    await session.commit()
    return u


async def _seed_guardian_request(
    session,
    *,
    user_id: str,
    facility_id: str,
    is_approved: bool = False,
    is_rejected: bool = False,
    reject_reason: str | None = None,
) -> Guardian:
    g = Guardian(
        id=str(uuid.uuid4()),
        user_id=user_id,
        resident_id=None,
        facility_id=facility_id,
        relationship_type="아들",
        is_approved=is_approved,
        is_rejected=is_rejected,
        reject_reason=reject_reason,
    )
    session.add(g)
    await session.commit()
    return g


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
# DELETE /me/connect/{guardian_id}
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cancel_pending_request_soft_deletes(integration_client, integration_db):
    _SL, session = integration_db
    fac = await _seed_facility(session)
    guardian_user = await _seed_guardian_user(session)
    req = await _seed_guardian_request(session, user_id=guardian_user.id, facility_id=fac.id)

    resp = await integration_client.delete(
        f"/guardians/me/connect/{req.id}",
        cookies=_auth_cookies(guardian_user),
    )
    assert resp.status_code == 200, resp.text

    # cancelled_at 박혀있고, row 는 보존됨.
    await session.refresh(req)
    assert req.cancelled_at is not None
    assert req.is_approved is False
    assert req.is_rejected is False


@pytest.mark.asyncio
async def test_cancel_request_rejects_approved(integration_client, integration_db):
    _SL, session = integration_db
    fac = await _seed_facility(session)
    guardian_user = await _seed_guardian_user(session)
    req = await _seed_guardian_request(
        session, user_id=guardian_user.id, facility_id=fac.id, is_approved=True
    )

    resp = await integration_client.delete(
        f"/guardians/me/connect/{req.id}",
        cookies=_auth_cookies(guardian_user),
    )
    assert resp.status_code == 400
    assert "승인" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_cancel_request_rejects_rejected(integration_client, integration_db):
    _SL, session = integration_db
    fac = await _seed_facility(session)
    guardian_user = await _seed_guardian_user(session)
    req = await _seed_guardian_request(
        session,
        user_id=guardian_user.id,
        facility_id=fac.id,
        is_rejected=True,
        reject_reason="입소자 정보 불일치",
    )

    resp = await integration_client.delete(
        f"/guardians/me/connect/{req.id}",
        cookies=_auth_cookies(guardian_user),
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_cancel_request_idempotent(integration_client, integration_db):
    _SL, session = integration_db
    fac = await _seed_facility(session)
    guardian_user = await _seed_guardian_user(session)
    req = await _seed_guardian_request(session, user_id=guardian_user.id, facility_id=fac.id)
    req.cancelled_at = datetime.utcnow() - timedelta(hours=1)
    await session.commit()
    original_cancelled_at = req.cancelled_at

    resp = await integration_client.delete(
        f"/guardians/me/connect/{req.id}",
        cookies=_auth_cookies(guardian_user),
    )
    assert resp.status_code == 200

    await session.refresh(req)
    # 멱등 — cancelled_at 덮어쓰지 않음.
    assert req.cancelled_at == original_cancelled_at


@pytest.mark.asyncio
async def test_cancel_request_rejects_other_users_guardian(integration_client, integration_db):
    """다른 보호자가 만든 신청을 취소하려 하면 404 (조회 자체 차단)."""
    _SL, session = integration_db
    fac = await _seed_facility(session)
    owner = await _seed_guardian_user(session, email="owner@x.io", phone="01011112222")
    attacker = await _seed_guardian_user(session, email="attacker@x.io", phone="01033334444")
    req = await _seed_guardian_request(session, user_id=owner.id, facility_id=fac.id)

    resp = await integration_client.delete(
        f"/guardians/me/connect/{req.id}",
        cookies=_auth_cookies(attacker),
    )
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# POST /me/{guardian_id}/dismiss
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dismiss_rejected_hides_from_user(integration_client, integration_db):
    _SL, session = integration_db
    fac = await _seed_facility(session)
    guardian_user = await _seed_guardian_user(session)
    req = await _seed_guardian_request(
        session,
        user_id=guardian_user.id,
        facility_id=fac.id,
        is_rejected=True,
        reject_reason="중복 등록",
    )

    resp = await integration_client.post(
        f"/guardians/me/{req.id}/dismiss",
        cookies=_auth_cookies(guardian_user),
    )
    assert resp.status_code == 200

    await session.refresh(req)
    assert req.hidden_from_user_at is not None
    # 거부 정보 자체는 보존.
    assert req.is_rejected is True
    assert req.reject_reason == "중복 등록"


@pytest.mark.asyncio
async def test_dismiss_rejects_non_rejected(integration_client, integration_db):
    """pending 또는 approved 신청은 dismiss 불가."""
    _SL, session = integration_db
    fac = await _seed_facility(session)
    guardian_user = await _seed_guardian_user(session)
    req = await _seed_guardian_request(session, user_id=guardian_user.id, facility_id=fac.id)

    resp = await integration_client.post(
        f"/guardians/me/{req.id}/dismiss",
        cookies=_auth_cookies(guardian_user),
    )
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# GET /me/status — 필터
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_me_status_excludes_cancelled_and_hidden(integration_client, integration_db):
    _SL, session = integration_db
    fac_a = await _seed_facility(session, code="FAC-A", name="A요양원")
    fac_b = await _seed_facility(session, code="FAC-B", name="B요양원")
    fac_c = await _seed_facility(session, code="FAC-C", name="C요양원")
    fac_d = await _seed_facility(session, code="FAC-D", name="D요양원")
    guardian_user = await _seed_guardian_user(session)

    # 활성 pending — 보임
    await _seed_guardian_request(session, user_id=guardian_user.id, facility_id=fac_a.id)
    # 활성 approved — 보임
    await _seed_guardian_request(
        session, user_id=guardian_user.id, facility_id=fac_b.id, is_approved=True
    )
    # 본인이 취소 — 안 보임
    cancelled = await _seed_guardian_request(
        session, user_id=guardian_user.id, facility_id=fac_c.id
    )
    cancelled.cancelled_at = datetime.utcnow()
    # 본인이 거부 후 숨김 — 안 보임
    hidden = await _seed_guardian_request(
        session,
        user_id=guardian_user.id,
        facility_id=fac_d.id,
        is_rejected=True,
        reject_reason="거부",
    )
    hidden.hidden_from_user_at = datetime.utcnow()
    await session.commit()

    resp = await integration_client.get(
        "/guardians/me/status",
        cookies=_auth_cookies(guardian_user),
    )
    assert resp.status_code == 200
    body = resp.json()
    facility_names = {g["facility_name"] for g in body["guardianships"]}
    assert facility_names == {"A요양원", "B요양원"}


# ---------------------------------------------------------------------------
# 시설 측 목록 필터
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_facility_pending_excludes_cancelled(integration_client, integration_db):
    _SL, session = integration_db
    fac = await _seed_facility(session)
    staff = await _seed_staff_user(session, facility_id=fac.id)
    guardian_user = await _seed_guardian_user(session)

    active = await _seed_guardian_request(session, user_id=guardian_user.id, facility_id=fac.id)
    cancelled = await _seed_guardian_request(session, user_id=guardian_user.id, facility_id=fac.id)
    cancelled.cancelled_at = datetime.utcnow()
    await session.commit()

    resp = await integration_client.get(
        f"/guardians/facility/{fac.id}/pending",
        cookies=_auth_cookies(staff),
    )
    assert resp.status_code == 200
    ids = {row["id"] for row in resp.json()}
    assert ids == {active.id}


@pytest.mark.asyncio
async def test_facility_all_keeps_cancelled_for_audit(integration_client, integration_db):
    """시설 측 '전체 보호자' 목록은 본인 취소 / 숨김 신청도 그대로 노출 — 감사 이력."""
    _SL, session = integration_db
    fac = await _seed_facility(session)
    staff = await _seed_staff_user(session, facility_id=fac.id)
    guardian_user = await _seed_guardian_user(session)

    cancelled = await _seed_guardian_request(session, user_id=guardian_user.id, facility_id=fac.id)
    cancelled.cancelled_at = datetime.utcnow()
    hidden = await _seed_guardian_request(
        session,
        user_id=guardian_user.id,
        facility_id=fac.id,
        is_rejected=True,
        reject_reason="r",
    )
    hidden.hidden_from_user_at = datetime.utcnow()
    await session.commit()

    resp = await integration_client.get(
        f"/guardians/facility/{fac.id}/all",
        cookies=_auth_cookies(staff),
    )
    assert resp.status_code == 200
    ids = {row["id"] for row in resp.json()}
    assert ids == {cancelled.id, hidden.id}


# ---------------------------------------------------------------------------
# 재신청 흐름
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_resubmit_after_self_cancel(integration_client, integration_db):
    """본인이 취소한 신청은 dup check 에서 제외 → 같은 시설로 재신청 가능."""
    _SL, session = integration_db
    fac = await _seed_facility(session)
    guardian_user = await _seed_guardian_user(session)

    first = await _seed_guardian_request(session, user_id=guardian_user.id, facility_id=fac.id)
    first.cancelled_at = datetime.utcnow()
    await session.commit()

    resp = await integration_client.post(
        "/guardians/me/connect",
        json={"facility_code": fac.code, "relationship_type": "딸"},
        cookies=_auth_cookies(guardian_user),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["guardian_id"] != first.id

    # 활성 신청은 새 row 하나뿐.
    q = await session.execute(
        select(Guardian).filter(
            Guardian.user_id == guardian_user.id,
            Guardian.facility_id == fac.id,
            Guardian.cancelled_at.is_(None),
        )
    )
    actives = q.scalars().all()
    assert len(actives) == 1
    assert actives[0].id == body["guardian_id"]


@pytest.mark.asyncio
async def test_resubmit_blocked_while_pending(integration_client, integration_db):
    """취소 안 한 pending 이 있으면 dup check 가 차단."""
    _SL, session = integration_db
    fac = await _seed_facility(session)
    guardian_user = await _seed_guardian_user(session)
    await _seed_guardian_request(session, user_id=guardian_user.id, facility_id=fac.id)

    resp = await integration_client.post(
        "/guardians/me/connect",
        json={"facility_code": fac.code},
        cookies=_auth_cookies(guardian_user),
    )
    assert resp.status_code == 400
    assert "대기" in resp.json()["detail"]
