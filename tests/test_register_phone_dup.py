"""
T-150 회귀 fix: register endpoint phone 중복 시 500 → 409 변환.

이전 동작: `User.phone` UNIQUE 제약을 사전 검사 안 해서 DB IntegrityError 가
일반 예외 핸들러로 새어나가 500. 사용자 입장에선 "Internal server error" 만
보임 (T-104 generic 메시지).

수정 후: 사전 select + flush IntegrityError 양쪽 모두 잡아 409 + 통일된
detail (`이미 다른 계정에 등록된 번호입니다.`) 로 응답 — phone-otp/verify 의
정책과 호환.
"""

from __future__ import annotations

import pytest


_ADMIN_BASE = {
    "email": "admin1@x.io",
    "password": "VeryStrongPassword123!",
    "name": "관리자1",
    "phone": "010-1111-2222",
    "facilityName": "행복원",
    "facilityAddress": "서울시 강남구",
    "facilityPhone": "02-1234-5678",
}


@pytest.mark.asyncio
async def test_register_admin_phone_dup_returns_409(integration_client):
    """첫 번째 가입 OK, 같은 phone 으로 두 번째 가입 → 409."""
    resp1 = await integration_client.post("/auth/register/admin", json=_ADMIN_BASE)
    assert resp1.status_code == 200, resp1.text

    second = {**_ADMIN_BASE, "email": "admin2@x.io"}
    resp2 = await integration_client.post("/auth/register/admin", json=second)
    assert resp2.status_code == 409, resp2.text
    assert "이미 다른 계정에 등록된 번호" in resp2.json()["detail"]


@pytest.mark.asyncio
async def test_register_staff_phone_dup_returns_409(integration_client):
    # 시설 + 첫 번째 admin 시드 (phone 으로 점유)
    admin_resp = await integration_client.post("/auth/register/admin", json=_ADMIN_BASE)
    assert admin_resp.status_code == 200, admin_resp.text
    facility_code = admin_resp.json()["facility"]["code"]

    staff_payload = {
        "email": "staff@x.io",
        "password": "VeryStrongPassword123!",
        "name": "직원1",
        "phone": _ADMIN_BASE["phone"],  # 동일 phone — 중복
        "facilityCode": facility_code,
    }
    resp = await integration_client.post("/auth/register/staff", json=staff_payload)
    assert resp.status_code == 409, resp.text
    assert "이미 다른 계정에 등록된 번호" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_register_guardian_phone_dup_returns_409(integration_client):
    admin_resp = await integration_client.post("/auth/register/admin", json=_ADMIN_BASE)
    assert admin_resp.status_code == 200

    guardian_payload = {
        "email": "g@x.io",
        "password": "VeryStrongPassword123!",
        "name": "보호자1",
        "phone": _ADMIN_BASE["phone"],
        # 약관 강제 X (DB 빈 ConsentDocument 시 우회됨 — test_auth_integration 패턴)
    }
    resp = await integration_client.post("/auth/register/guardian", json=guardian_payload)
    assert resp.status_code == 409, resp.text
    assert "이미 다른 계정에 등록된 번호" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_register_staff_no_phone_does_not_collide(integration_client):
    """phone 없이 가입은 통과 — None 은 UNIQUE 충돌 대상 아님."""
    admin_resp = await integration_client.post("/auth/register/admin", json=_ADMIN_BASE)
    assert admin_resp.status_code == 200
    facility_code = admin_resp.json()["facility"]["code"]

    staff_payload = {
        "email": "staff-no-phone@x.io",
        "password": "VeryStrongPassword123!",
        "name": "직원무폰",
        "facilityCode": facility_code,
        # phone 누락 (Optional)
    }
    resp = await integration_client.post("/auth/register/staff", json=staff_payload)
    assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
async def test_register_admin_email_dup_still_400(integration_client):
    """email 중복은 400 그대로 (phone 분기와 충돌 안 남)."""
    resp1 = await integration_client.post("/auth/register/admin", json=_ADMIN_BASE)
    assert resp1.status_code == 200

    second = {**_ADMIN_BASE, "phone": "010-9999-9999"}
    resp2 = await integration_client.post("/auth/register/admin", json=second)
    assert resp2.status_code == 400
    assert "이메일" in resp2.json()["detail"]
