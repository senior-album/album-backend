"""
T-056: 직원 가입 승인 게이트 테스트.

검증 대상:
- register_admin 자동승인 (is_staff_approved=True)
- register_staff 는 pending (is_staff_approved=False) — 응답에 명시
- verify_facility_access 가 미승인 staff 차단 (시설 데이터 endpoint 403)
- 시설장 본인 / is_operator 는 승인 절차 없이 통과
- /facility-approvals/* 가드 — 비-시설장 차단, facility:staff:approve 위임 직원 통과
- approve: 행 갱신 + AdminAuditLog staff_approve 1 row
- reject: soft delete (is_rejected=True, is_active=False) + audit + 옵셔널 reason
- 거부된 user 와 동일 email/phone 재신청 시 400/409 (UNIQUE 자동 차단)
- 시설 경계 위반 (다른 시설 직원 승인/거부 시도) → 403
"""

from __future__ import annotations

# T-144 패턴 — Windows magic stub 은 conftest 가 처리.
import os as _os
import uuid

_os.environ.setdefault("JWT_SECRET", "test-secret-value-for-jwt-32-bytes-min")
_os.environ.setdefault("JWT_REFRESH_SECRET", "test-refresh-secret-32bytes-minimum")

import pytest
from sqlalchemy import select

from app.core.permissions import FACILITY_STAFF_APPROVE
from app.core.security import SecurityService
from app.models.models import AdminAuditLog, Facility, User, UserPermission


_ADMIN_PAYLOAD = {
    "email": "owner@x.io",
    "password": "VeryStrongPassword123!",
    "name": "시설장",
    "phone": "010-1111-1111",
    "facilityName": "행복원",
    "facilityAddress": "서울시 강남구",
    "facilityPhone": "02-1234-5678",
}


def _staff_payload(facility_code: str, email="staff1@x.io", phone="010-2222-2222"):
    return {
        "email": email,
        "password": "VeryStrongPassword123!",
        "name": "직원1",
        "phone": phone,
        "facilityCode": facility_code,
    }


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
# register_admin / register_staff 자체 동작
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_register_admin_is_auto_approved(integration_client, integration_db):
    _, session = integration_db
    resp = await integration_client.post("/auth/register/admin", json=_ADMIN_PAYLOAD)
    assert resp.status_code == 200, resp.text

    body = resp.json()
    user = await session.get(User, body["user"]["id"])
    assert user.is_staff_approved is True
    assert user.staff_approved_by == user.id
    assert user.staff_approved_at is not None


@pytest.mark.asyncio
async def test_register_staff_is_pending_with_flag(integration_client, integration_db):
    _, session = integration_db
    admin_resp = await integration_client.post("/auth/register/admin", json=_ADMIN_PAYLOAD)
    code = admin_resp.json()["facility"]["code"]

    resp = await integration_client.post("/auth/register/staff", json=_staff_payload(code))
    assert resp.status_code == 200, resp.text

    body = resp.json()
    assert body["user"]["is_staff_approved"] is False

    user = await session.get(User, body["user"]["id"])
    assert user.is_staff_approved is False
    assert user.is_rejected is False


# ---------------------------------------------------------------------------
# verify_facility_access 차단 (시설 데이터 엔드포인트 호출로 검증)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pending_staff_blocked_by_verify_facility_access(integration_db):
    """미승인 staff 는 verify_facility_access 가 직접 차단."""
    from fastapi import HTTPException
    from app.core.security import verify_facility_access

    _, session = integration_db
    fac = Facility(id=str(uuid.uuid4()), code="FAC-PEND", name="P", address="x")
    session.add(fac)
    await session.commit()

    pending = User(
        id=str(uuid.uuid4()), email="p@x.io", name="P", role="staff",
        is_admin=False, is_operator=False, is_active=True,
        facility_id=fac.id, is_staff_approved=False,
    )
    session.add(pending)
    await session.commit()

    with pytest.raises(HTTPException) as exc:
        await verify_facility_access({"user_id": pending.id}, fac.id, session)
    assert exc.value.status_code == 403
    assert "승인 대기" in exc.value.detail


@pytest.mark.asyncio
async def test_approved_staff_passes_verify_facility_access(integration_db):
    from app.core.security import verify_facility_access

    _, session = integration_db
    fac = Facility(id=str(uuid.uuid4()), code="FAC-OK", name="O", address="x")
    session.add(fac)
    await session.commit()

    approved = User(
        id=str(uuid.uuid4()), email="ok@x.io", name="OK", role="staff",
        is_admin=False, is_operator=False, is_active=True,
        facility_id=fac.id, is_staff_approved=True,
    )
    session.add(approved)
    await session.commit()

    # 예외 없이 통과
    await verify_facility_access({"user_id": approved.id}, fac.id, session)


@pytest.mark.asyncio
async def test_admin_role_passes_without_explicit_approval_flag(integration_db):
    """is_admin=True 면 is_staff_approved 와 무관하게 통과 — 시설장 본인."""
    from app.core.security import verify_facility_access

    _, session = integration_db
    fac = Facility(id=str(uuid.uuid4()), code="FAC-ADM", name="A", address="x")
    session.add(fac)
    await session.commit()

    admin = User(
        id=str(uuid.uuid4()), email="adm@x.io", name="A", role="staff",
        is_admin=True, is_operator=False, is_active=True,
        facility_id=fac.id, is_staff_approved=False,  # 의도적으로 False — 가드가 is_admin 우선 통과해야 함
    )
    session.add(admin)
    await session.commit()

    await verify_facility_access({"user_id": admin.id}, fac.id, session)


# ---------------------------------------------------------------------------
# /facility-approvals/* 가드
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_approvals_endpoints_require_auth(integration_client):
    resp = await integration_client.get("/facility-approvals/pending")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_approvals_blocks_non_admin_staff_without_permission(
    integration_client, integration_db
):
    """승인 권한 없는 일반 직원 (facility:staff:approve 미보유) 차단."""
    _, session = integration_db
    admin_resp = await integration_client.post("/auth/register/admin", json=_ADMIN_PAYLOAD)
    code = admin_resp.json()["facility"]["code"]

    # 직원 가입 + 시설장이 승인 → 일반 직원이지만 권한 미위임
    staff_resp = await integration_client.post(
        "/auth/register/staff", json=_staff_payload(code)
    )
    staff_user = await session.get(User, staff_resp.json()["user"]["id"])
    staff_user.is_staff_approved = True
    await session.commit()

    resp = await integration_client.get(
        "/facility-approvals/pending", cookies=_cookies(staff_user)
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_approvals_allows_delegated_staff(integration_client, integration_db):
    """facility:staff:approve 위임 받은 직원은 통과."""
    _, session = integration_db
    admin_resp = await integration_client.post("/auth/register/admin", json=_ADMIN_PAYLOAD)
    code = admin_resp.json()["facility"]["code"]
    admin_user = await session.get(User, admin_resp.json()["user"]["id"])

    staff_resp = await integration_client.post(
        "/auth/register/staff", json=_staff_payload(code)
    )
    staff_user = await session.get(User, staff_resp.json()["user"]["id"])
    staff_user.is_staff_approved = True
    session.add(UserPermission(
        user_id=staff_user.id,
        permission_key=FACILITY_STAFF_APPROVE,
        granted_by=admin_user.id,
    ))
    await session.commit()

    resp = await integration_client.get(
        "/facility-approvals/pending", cookies=_cookies(staff_user)
    )
    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# pending 목록 / 승인 / 거부
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_pending_list_shows_only_unapproved_in_own_facility(
    integration_client, integration_db
):
    _, session = integration_db
    admin_resp = await integration_client.post("/auth/register/admin", json=_ADMIN_PAYLOAD)
    code = admin_resp.json()["facility"]["code"]
    admin_user = await session.get(User, admin_resp.json()["user"]["id"])

    s1 = await integration_client.post("/auth/register/staff", json=_staff_payload(code))
    assert s1.status_code == 200

    resp = await integration_client.get(
        "/facility-approvals/pending", cookies=_cookies(admin_user)
    )
    assert resp.status_code == 200
    items = resp.json()["items"]
    assert len(items) == 1
    assert items[0]["email"] == "staff1@x.io"


@pytest.mark.asyncio
async def test_approve_marks_user_and_writes_audit(integration_client, integration_db):
    _, session = integration_db
    admin_resp = await integration_client.post("/auth/register/admin", json=_ADMIN_PAYLOAD)
    code = admin_resp.json()["facility"]["code"]
    admin_user = await session.get(User, admin_resp.json()["user"]["id"])

    s_resp = await integration_client.post("/auth/register/staff", json=_staff_payload(code))
    staff_id = s_resp.json()["user"]["id"]

    resp = await integration_client.post(
        f"/facility-approvals/{staff_id}/approve", cookies=_cookies(admin_user)
    )
    assert resp.status_code == 200, resp.text

    user = await session.get(User, staff_id)
    assert user.is_staff_approved is True
    assert user.staff_approved_by == admin_user.id

    audits = (
        await session.execute(
            select(AdminAuditLog).where(
                AdminAuditLog.action == "staff_approve",
                AdminAuditLog.target_id == staff_id,
            )
        )
    ).scalars().all()
    assert len(audits) == 1


@pytest.mark.asyncio
async def test_reject_soft_deletes_with_optional_reason(integration_client, integration_db):
    _, session = integration_db
    admin_resp = await integration_client.post("/auth/register/admin", json=_ADMIN_PAYLOAD)
    code = admin_resp.json()["facility"]["code"]
    admin_user = await session.get(User, admin_resp.json()["user"]["id"])

    s_resp = await integration_client.post("/auth/register/staff", json=_staff_payload(code))
    staff_id = s_resp.json()["user"]["id"]

    resp = await integration_client.post(
        f"/facility-approvals/{staff_id}/reject",
        json={"reason": "신원 미확인"},
        cookies=_cookies(admin_user),
    )
    assert resp.status_code == 200, resp.text

    user = await session.get(User, staff_id)
    assert user.is_rejected is True
    assert user.is_active is False
    assert user.staff_reject_reason == "신원 미확인"
    assert user.staff_rejected_by == admin_user.id

    audits = (
        await session.execute(
            select(AdminAuditLog).where(
                AdminAuditLog.action == "staff_reject",
                AdminAuditLog.target_id == staff_id,
            )
        )
    ).scalars().all()
    assert len(audits) == 1
    assert audits[0].detail == "신원 미확인"


@pytest.mark.asyncio
async def test_reject_without_reason_keeps_null(integration_client, integration_db):
    _, session = integration_db
    admin_resp = await integration_client.post("/auth/register/admin", json=_ADMIN_PAYLOAD)
    code = admin_resp.json()["facility"]["code"]
    admin_user = await session.get(User, admin_resp.json()["user"]["id"])

    s_resp = await integration_client.post("/auth/register/staff", json=_staff_payload(code))
    staff_id = s_resp.json()["user"]["id"]

    resp = await integration_client.post(
        f"/facility-approvals/{staff_id}/reject",
        json={},
        cookies=_cookies(admin_user),
    )
    assert resp.status_code == 200

    user = await session.get(User, staff_id)
    assert user.is_rejected is True
    assert user.staff_reject_reason is None


@pytest.mark.asyncio
async def test_rejected_user_email_blocks_re_registration(
    integration_client, integration_db
):
    """soft delete 후 같은 email 재가입 시도 → email 중복 (400)."""
    _, session = integration_db
    admin_resp = await integration_client.post("/auth/register/admin", json=_ADMIN_PAYLOAD)
    code = admin_resp.json()["facility"]["code"]
    admin_user = await session.get(User, admin_resp.json()["user"]["id"])

    s_resp = await integration_client.post("/auth/register/staff", json=_staff_payload(code))
    staff_id = s_resp.json()["user"]["id"]

    await integration_client.post(
        f"/facility-approvals/{staff_id}/reject", json={}, cookies=_cookies(admin_user)
    )

    # 같은 email + 다른 phone 으로 재가입 시도
    retry = await integration_client.post(
        "/auth/register/staff",
        json=_staff_payload(code, email="staff1@x.io", phone="010-9999-9999"),
    )
    assert retry.status_code == 400
    assert "이메일" in retry.json()["detail"]


@pytest.mark.asyncio
async def test_approve_other_facility_user_403(integration_client, integration_db):
    _, session = integration_db
    # 첫 시설 + admin
    admin_resp = await integration_client.post("/auth/register/admin", json=_ADMIN_PAYLOAD)
    admin_user = await session.get(User, admin_resp.json()["user"]["id"])

    # 두 번째 시설 + 거기에 가입한 staff
    other_admin_payload = {**_ADMIN_PAYLOAD, "email": "other-admin@x.io", "phone": "010-3333-3333"}
    other_admin_resp = await integration_client.post(
        "/auth/register/admin", json=other_admin_payload
    )
    other_code = other_admin_resp.json()["facility"]["code"]
    other_staff_resp = await integration_client.post(
        "/auth/register/staff",
        json=_staff_payload(other_code, email="other-staff@x.io", phone="010-4444-4444"),
    )
    other_staff_id = other_staff_resp.json()["user"]["id"]

    # 첫 시설 admin 이 다른 시설 staff 승인 시도 → 403
    resp = await integration_client.post(
        f"/facility-approvals/{other_staff_id}/approve",
        cookies=_cookies(admin_user),
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_approve_already_approved_is_idempotent(integration_client, integration_db):
    _, session = integration_db
    admin_resp = await integration_client.post("/auth/register/admin", json=_ADMIN_PAYLOAD)
    code = admin_resp.json()["facility"]["code"]
    admin_user = await session.get(User, admin_resp.json()["user"]["id"])

    s_resp = await integration_client.post("/auth/register/staff", json=_staff_payload(code))
    staff_id = s_resp.json()["user"]["id"]

    for _ in range(2):
        resp = await integration_client.post(
            f"/facility-approvals/{staff_id}/approve", cookies=_cookies(admin_user)
        )
        assert resp.status_code == 200

    audits = (
        await session.execute(
            select(AdminAuditLog).where(
                AdminAuditLog.action == "staff_approve",
                AdminAuditLog.target_id == staff_id,
            )
        )
    ).scalars().all()
    assert len(audits) == 1, "재요청은 멱등 — audit 추가 없음"
