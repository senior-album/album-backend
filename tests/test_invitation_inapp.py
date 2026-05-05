"""
T-149: 가입 회원 초대 (in_app) 채널 + 사용자 검색 + 알림 API 통합 테스트.

검증 대상:
- /users/search: 정확 일치만 허용, 부분 매칭 거부, 마스킹된 결과
- /invitations 분기: invite_type 'sms' 회귀, 'in_app' 신규 흐름
- /invitations/me: in_app 초대도 invitee_user_id 매칭으로 노출
- /invitations/{id}/accept: in_app 초대 수락 → Guardian 자동 생성
- /notifications/me, /notifications/{id}/read: 본인만 조회/처리

테스트 인증은 test_admin_users.py 와 동일한 패턴 — SecurityService.create_access_token
+ access_token 쿠키 주입.
"""

from __future__ import annotations

import os as _os
import platform as _platform
import sys as _sys
import types as _types

# Windows 에서 magic 라이브러리 segfault 회피 (test_admin_users.py 동일 패턴)
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

from app.core.security import SecurityService
from app.models.models import (
    AdminAuditLog,
    Facility,
    Guardian,
    Invitation,
    Notification,
    Resident,
    User,
)


# ---------------------------------------------------------------------------
# 헬퍼
# ---------------------------------------------------------------------------


async def _seed_facility(session, *, code: str = "FAC-T149", name: str = "햇살요양원") -> Facility:
    fac = Facility(id=str(uuid.uuid4()), code=code, name=name, address="서울시 어딘가")
    session.add(fac)
    await session.commit()
    return fac


async def _seed_user(
    session,
    *,
    email: str,
    name: str = "이름",
    role: str = "guardian",
    phone: str | None = None,
    facility_id: str | None = None,
) -> User:
    u = User(
        id=str(uuid.uuid4()),
        email=email,
        name=name,
        password_hash="$2b$12$dummy" + "x" * 50,
        role=role,
        is_active=True,
        phone=phone,
        facility_id=facility_id,
    )
    session.add(u)
    await session.commit()
    return u


async def _seed_resident(session, *, facility_id: str, name: str = "김할머니") -> Resident:
    from tests._pii_seed import make_resident
    r = make_resident(facility_id=facility_id, name=name)
    session.add(r)
    await session.commit()
    return r


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
# /users/search
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_user_search_requires_staff(integration_client, integration_db):
    _SL, session = integration_db
    fac = await _seed_facility(session)
    guardian = await _seed_user(session, email="g@x.io", role="guardian")
    # 권한 없는 보호자 — 403
    resp = await integration_client.get(
        "/users/search", params={"query": "g@x.io"}, cookies=_auth_cookies(guardian)
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_user_search_by_email_exact_returns_masked(integration_client, integration_db):
    _SL, session = integration_db
    fac = await _seed_facility(session)
    staff = await _seed_user(session, email="s@x.io", role="staff", facility_id=fac.id)
    target = await _seed_user(session, email="alice@example.com", name="홍길동", phone="01012345678")

    resp = await integration_client.get(
        "/users/search",
        params={"query": "alice@example.com"},
        cookies=_auth_cookies(staff),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body is not None
    assert body["id"] == target.id
    assert body["name_masked"] == "홍O동"
    assert body["phone_masked"] == "010-****-5678"
    assert body["email_masked"] == "a****@example.com"


@pytest.mark.asyncio
async def test_user_search_by_phone_with_hyphens(integration_client, integration_db):
    _SL, session = integration_db
    fac = await _seed_facility(session)
    staff = await _seed_user(session, email="s2@x.io", role="staff", facility_id=fac.id)
    target = await _seed_user(session, email="bob@x.io", name="박", phone="01098765432")

    resp = await integration_client.get(
        "/users/search",
        params={"query": "010-9876-5432"},
        cookies=_auth_cookies(staff),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body is not None
    assert body["id"] == target.id


@pytest.mark.asyncio
async def test_user_search_partial_name_returns_null(integration_client, integration_db):
    """이름 부분 매칭은 의도적으로 막혀있음 — 회원 디렉터리화 방지."""
    _SL, session = integration_db
    fac = await _seed_facility(session)
    staff = await _seed_user(session, email="s3@x.io", role="staff", facility_id=fac.id)
    await _seed_user(session, email="charlie@x.io", name="홍길동")

    resp = await integration_client.get(
        "/users/search", params={"query": "홍길동"}, cookies=_auth_cookies(staff)
    )
    # query 에 @ 가 없고 숫자도 없으면 400 (전화번호 형식 아님)
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_user_search_no_match_returns_null(integration_client, integration_db):
    _SL, session = integration_db
    fac = await _seed_facility(session)
    staff = await _seed_user(session, email="s4@x.io", role="staff", facility_id=fac.id)

    resp = await integration_client.get(
        "/users/search",
        params={"query": "nobody@nowhere.com"},
        cookies=_auth_cookies(staff),
    )
    assert resp.status_code == 200
    assert resp.json() is None


# ---------------------------------------------------------------------------
# POST /invitations — invite_type 분기
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_invitation_create_sms_regression(integration_client, integration_db):
    """기존 sms 채널 (전화번호 입력) 동작 회귀 검증."""
    _SL, session = integration_db
    fac = await _seed_facility(session)
    staff = await _seed_user(session, email="staff-sms@x.io", role="staff", facility_id=fac.id)
    res = await _seed_resident(session, facility_id=fac.id)

    resp = await integration_client.post(
        "/invitations",
        json={
            "resident_id": res.id,
            "invite_type": "sms",
            "phone": "01011112222",
            "relationship_type": "딸",
        },
        cookies=_auth_cookies(staff),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["invite_type"] == "sms"
    assert body["phone"] == "01011112222"
    assert body["invitee_user_id"] is None

    # 감사 로그 channel='phone'
    log_q = await session.execute(select(AdminAuditLog).filter(AdminAuditLog.action == "invitation_create"))
    logs = log_q.scalars().all()
    assert len(logs) == 1
    assert "channel=phone" in (logs[0].detail or "")


@pytest.mark.asyncio
async def test_invitation_create_inapp_happy_path(integration_client, integration_db):
    """가입 회원 초대 → Invitation + Notification + AdminAuditLog(channel=in_app)."""
    _SL, session = integration_db
    fac = await _seed_facility(session)
    staff = await _seed_user(session, email="staff-in@x.io", role="staff", facility_id=fac.id)
    res = await _seed_resident(session, facility_id=fac.id)
    invitee = await _seed_user(session, email="parent@x.io", name="이보호자")

    resp = await integration_client.post(
        "/invitations",
        json={
            "resident_id": res.id,
            "invite_type": "in_app",
            "invitee_user_id": invitee.id,
            "relationship_type": "아들",
            "message": "안녕하세요",
        },
        cookies=_auth_cookies(staff),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["invite_type"] == "in_app"
    assert body["invitee_user_id"] == invitee.id
    assert body["invitee_name"] == "이보호자"
    assert body["phone"] is None and body["email"] is None

    # Notification 레코드 1개 생성 + 받는 사람 = invitee
    notif_q = await session.execute(select(Notification).filter(Notification.user_id == invitee.id))
    notifs = notif_q.scalars().all()
    assert len(notifs) == 1
    assert notifs[0].notification_type == "guardian_invitation"
    assert notifs[0].is_read is False

    # AdminAuditLog channel=in_app
    log_q = await session.execute(select(AdminAuditLog).filter(AdminAuditLog.action == "invitation_create"))
    logs = log_q.scalars().all()
    assert len(logs) == 1
    assert "channel=in_app" in (logs[0].detail or "")


@pytest.mark.asyncio
async def test_invitation_create_inapp_requires_invitee(integration_client, integration_db):
    _SL, session = integration_db
    fac = await _seed_facility(session)
    staff = await _seed_user(session, email="staff-noinv@x.io", role="staff", facility_id=fac.id)
    res = await _seed_resident(session, facility_id=fac.id)

    resp = await integration_client.post(
        "/invitations",
        json={"resident_id": res.id, "invite_type": "in_app"},
        cookies=_auth_cookies(staff),
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_invitation_create_inapp_self_invite_blocked(integration_client, integration_db):
    """직원이 본인을 보호자로 초대하는 시나리오는 막아야 한다."""
    _SL, session = integration_db
    fac = await _seed_facility(session)
    staff = await _seed_user(session, email="self@x.io", role="staff", facility_id=fac.id)
    res = await _seed_resident(session, facility_id=fac.id)

    resp = await integration_client.post(
        "/invitations",
        json={
            "resident_id": res.id,
            "invite_type": "in_app",
            "invitee_user_id": staff.id,
        },
        cookies=_auth_cookies(staff),
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_invitation_create_inapp_already_approved(integration_client, integration_db):
    """이미 승인된 보호자에게 다시 초대 → 400."""
    _SL, session = integration_db
    fac = await _seed_facility(session)
    staff = await _seed_user(session, email="staff-dup@x.io", role="staff", facility_id=fac.id)
    res = await _seed_resident(session, facility_id=fac.id)
    invitee = await _seed_user(session, email="dup@x.io", name="이미보호자")

    g = Guardian(
        id=str(uuid.uuid4()),
        user_id=invitee.id,
        resident_id=res.id,
        facility_id=fac.id,
        is_approved=True,
    )
    session.add(g)
    await session.commit()

    resp = await integration_client.post(
        "/invitations",
        json={
            "resident_id": res.id,
            "invite_type": "in_app",
            "invitee_user_id": invitee.id,
        },
        cookies=_auth_cookies(staff),
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_invitation_create_inapp_duplicate_pending(integration_client, integration_db):
    """같은 입소자·같은 회원 pending 초대 두 번 → 두 번째 400."""
    _SL, session = integration_db
    fac = await _seed_facility(session)
    staff = await _seed_user(session, email="staff-dup2@x.io", role="staff", facility_id=fac.id)
    res = await _seed_resident(session, facility_id=fac.id)
    invitee = await _seed_user(session, email="pending@x.io", name="대기")

    body = {
        "resident_id": res.id,
        "invite_type": "in_app",
        "invitee_user_id": invitee.id,
    }
    r1 = await integration_client.post("/invitations", json=body, cookies=_auth_cookies(staff))
    assert r1.status_code == 200
    r2 = await integration_client.post("/invitations", json=body, cookies=_auth_cookies(staff))
    assert r2.status_code == 400


# ---------------------------------------------------------------------------
# /invitations/me + /invitations/{id}/accept (in_app)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_my_invitations_includes_inapp(integration_client, integration_db):
    _SL, session = integration_db
    fac = await _seed_facility(session)
    staff = await _seed_user(session, email="staff-me@x.io", role="staff", facility_id=fac.id)
    res = await _seed_resident(session, facility_id=fac.id)
    invitee = await _seed_user(session, email="me@x.io", name="나")

    create = await integration_client.post(
        "/invitations",
        json={
            "resident_id": res.id,
            "invite_type": "in_app",
            "invitee_user_id": invitee.id,
        },
        cookies=_auth_cookies(staff),
    )
    assert create.status_code == 200

    me_resp = await integration_client.get("/invitations/me", cookies=_auth_cookies(invitee))
    assert me_resp.status_code == 200
    items = me_resp.json()
    assert len(items) == 1
    assert items[0]["invite_type"] == "in_app"
    assert items[0]["invitee_user_id"] == invitee.id


@pytest.mark.asyncio
async def test_accept_inapp_invitation_creates_guardian(integration_client, integration_db):
    _SL, session = integration_db
    fac = await _seed_facility(session)
    staff = await _seed_user(session, email="staff-accept@x.io", role="staff", facility_id=fac.id)
    res = await _seed_resident(session, facility_id=fac.id)
    invitee = await _seed_user(session, email="accept@x.io", name="수락")

    create = await integration_client.post(
        "/invitations",
        json={
            "resident_id": res.id,
            "invite_type": "in_app",
            "invitee_user_id": invitee.id,
            "relationship_type": "딸",
        },
        cookies=_auth_cookies(staff),
    )
    invitation_id = create.json()["id"]

    accept = await integration_client.post(
        f"/invitations/{invitation_id}/accept", cookies=_auth_cookies(invitee)
    )
    assert accept.status_code == 200

    # Guardian row 생성 + 자동 승인
    g_q = await session.execute(
        select(Guardian).filter(Guardian.user_id == invitee.id, Guardian.resident_id == res.id)
    )
    guardian = g_q.scalar_one_or_none()
    assert guardian is not None
    assert guardian.is_approved is True
    assert guardian.relationship_type == "딸"


# ---------------------------------------------------------------------------
# /notifications API
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_notifications_me_empty(integration_client, integration_db):
    _SL, session = integration_db
    user = await _seed_user(session, email="empty@x.io", role="guardian")

    resp = await integration_client.get("/notifications/me", cookies=_auth_cookies(user))
    assert resp.status_code == 200
    body = resp.json()
    assert body["items"] == []
    assert body["unread_count"] == 0


@pytest.mark.asyncio
async def test_notifications_me_lists_only_self(integration_client, integration_db):
    """본인 알림만 노출 — 다른 유저의 알림은 안 보여야 한다."""
    _SL, session = integration_db
    me = await _seed_user(session, email="me-n@x.io", role="guardian")
    other = await _seed_user(session, email="other-n@x.io", role="guardian")

    n_mine = Notification(
        id=str(uuid.uuid4()),
        user_id=me.id,
        title="내 알림",
        message="m",
        notification_type="guardian_invitation",
    )
    n_others = Notification(
        id=str(uuid.uuid4()),
        user_id=other.id,
        title="남 알림",
        message="m",
        notification_type="guardian_invitation",
    )
    session.add_all([n_mine, n_others])
    await session.commit()

    resp = await integration_client.get("/notifications/me", cookies=_auth_cookies(me))
    assert resp.status_code == 200
    body = resp.json()
    ids = [item["id"] for item in body["items"]]
    assert n_mine.id in ids
    assert n_others.id not in ids
    assert body["unread_count"] == 1


@pytest.mark.asyncio
async def test_notification_mark_read(integration_client, integration_db):
    _SL, session = integration_db
    user = await _seed_user(session, email="reader@x.io", role="guardian")
    notif = Notification(
        id=str(uuid.uuid4()),
        user_id=user.id,
        title="t",
        message="m",
        notification_type="guardian_invitation",
        is_read=False,
    )
    session.add(notif)
    await session.commit()

    resp = await integration_client.post(
        f"/notifications/{notif.id}/read", cookies=_auth_cookies(user)
    )
    assert resp.status_code == 200

    # 다시 조회 → unread_count 0
    me = await integration_client.get("/notifications/me", cookies=_auth_cookies(user))
    assert me.json()["unread_count"] == 0


@pytest.mark.asyncio
async def test_notification_mark_read_forbidden_for_others(integration_client, integration_db):
    _SL, session = integration_db
    me = await _seed_user(session, email="me-r@x.io", role="guardian")
    other = await _seed_user(session, email="other-r@x.io", role="guardian")
    notif = Notification(
        id=str(uuid.uuid4()),
        user_id=other.id,
        title="t",
        message="m",
        notification_type="guardian_invitation",
    )
    session.add(notif)
    await session.commit()

    resp = await integration_client.post(
        f"/notifications/{notif.id}/read", cookies=_auth_cookies(me)
    )
    assert resp.status_code == 403
