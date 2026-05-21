"""T-243-3/4: 생신 자동 발급 + D-7 알림 cron 단위 테스트.

검증 대상:
- 캘린더용 event 생성 (T-243-4): D-7 무관, 활성 입소자 모두 올해 birthday 이벤트
  idempotent 보유. D-7 일치 시에만 추가로 알림 발송.
- 같은 (resident, year) 알림 dedup: event.birthday_notified_at 으로 1회만 발송
- 멱등성: 같은 해 이미 birthday event 있으면 skip (생성)
- 윤일 출생자 (2/29): 1차 비대상 (event/알림 둘 다 skip)
- 알림 수신자: 승인된 보호자 + 시설 활성 staff 만 (rejected/미승인/타시설 staff 제외)
- created_by 결정: 시설장 우선, 없으면 운영자, 없으면 skip
"""

from __future__ import annotations

import base64 as _b64
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
_os.environ.setdefault("RESIDENT_PII_KEK", _b64.b64encode(b"\x11" * 32).decode())
_os.environ.setdefault("RESIDENT_NAME_HMAC_KEY", _b64.b64encode(b"\x22" * 32).decode())

_os.environ.setdefault("USER_PHONE_HMAC_KEY", _b64.b64encode(b"\x32" * 32).decode())
import uuid
from datetime import date, datetime

import pytest
from sqlalchemy import select

from app.models.models import Event, Facility, Guardian, Notification, Resident, User
from app.scripts.birthday_reminder import NOTIF_TYPE, run


# ---------------------------------------------------------------------------
# 시드 헬퍼 — wellness_logs / events 패턴 그대로
# ---------------------------------------------------------------------------


async def _seed_facility(session, *, code: str = "FAC-T243-3", name: str = "햇살") -> Facility:
    fac = Facility(id=str(uuid.uuid4()), code=code, name=name, address="서울시")
    session.add(fac)
    await session.commit()
    return fac


async def _seed_user(
    session,
    *,
    email: str,
    role: str = "staff",
    facility_id: str | None = None,
    is_admin: bool = False,
    is_operator: bool = False,
    is_active: bool = True,
) -> User:
    u = User(
        id=str(uuid.uuid4()),
        email=email,
        name="이름",
        password_hash="$2b$12$dummy" + "x" * 50,
        role=role,
        is_active=is_active,
        is_admin=is_admin,
        is_operator=is_operator,
        is_staff_approved=True,  # T-056 호환
        facility_id=facility_id,
    )
    session.add(u)
    await session.commit()
    return u


async def _seed_resident_with_bd(
    session, *, facility_id: str, name: str, birth_date: str
) -> Resident:
    """평문 birth_date (YYYY-MM-DD) 를 받아 ct/dek 컬럼 채워 시드."""
    from tests._pii_seed import make_resident
    r = make_resident(facility_id=facility_id, name=name, birth_date=birth_date)
    session.add(r)
    await session.commit()
    return r


async def _seed_guardian(
    session,
    *,
    user_id: str,
    resident_id: str,
    facility_id: str,
    approved: bool = True,
) -> Guardian:
    g = Guardian(
        id=str(uuid.uuid4()),
        user_id=user_id,
        resident_id=resident_id,
        facility_id=facility_id,
        is_approved=approved,
        is_rejected=False,
    )
    session.add(g)
    await session.commit()
    return g


# ---------------------------------------------------------------------------
# 매칭 / 멱등성
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_emits_event_for_d_minus_7_birthday(integration_db):
    _SL, session = integration_db
    fac = await _seed_facility(session)
    admin = await _seed_user(
        session, email="adm@x.io", role="staff", is_admin=True, facility_id=fac.id
    )
    # 생일 2026-05-13 → today=2026-05-06 + 7 = target=2026-05-13 매칭
    res = await _seed_resident_with_bd(
        session, facility_id=fac.id, name="김할머니", birth_date="1940-05-13"
    )

    summary = await run(today=date(2026, 5, 6), session=session)
    await session.commit()

    assert summary["events_created"] == 1
    assert summary["skipped_existing"] == 0

    rows = (
        await session.execute(
            select(Event).filter(Event.resident_id == res.id, Event.type == "birthday")
        )
    ).scalars().all()
    assert len(rows) == 1
    ev = rows[0]
    assert ev.start_at == datetime(2026, 5, 13)
    assert ev.all_day is True
    assert ev.created_by == admin.id
    assert "김할머니" in ev.title


@pytest.mark.asyncio
async def test_event_created_but_no_notif_when_not_d_minus_7(integration_db):
    """T-243-4: D-7 무관하게 캘린더용 event 는 매번 보장. 알림은 D-7 일치 시만."""
    _SL, session = integration_db
    fac = await _seed_facility(session)
    admin = await _seed_user(
        session, email="adm2@x.io", role="staff", is_admin=True, facility_id=fac.id
    )
    # 생일 10/28 — today=2026-05-10 기준 target=2026-05-17 과 어긋남.
    res = await _seed_resident_with_bd(
        session, facility_id=fac.id, name="박할머니", birth_date="1940-10-28"
    )

    summary = await run(today=date(2026, 5, 10), session=session)
    await session.commit()

    assert summary["scanned_residents"] == 1
    assert summary["events_created"] == 1  # event 는 생성
    assert summary["notifications_created"] == 0  # 알림은 발송 안 됨

    ev = (
        await session.execute(
            select(Event).filter(Event.resident_id == res.id, Event.type == "birthday")
        )
    ).scalar_one()
    assert ev.start_at == datetime(2026, 10, 28)
    assert ev.created_by == admin.id
    assert ev.birthday_notified_at is None  # 알림 안 갔으니 NULL

    notifs = (
        await session.execute(
            select(Notification).filter(Notification.notification_type == NOTIF_TYPE)
        )
    ).scalars().all()
    assert notifs == []


@pytest.mark.asyncio
async def test_idempotent_when_event_already_exists(integration_db):
    _SL, session = integration_db
    fac = await _seed_facility(session)
    admin = await _seed_user(
        session, email="adm3@x.io", role="staff", is_admin=True, facility_id=fac.id
    )
    res = await _seed_resident_with_bd(
        session, facility_id=fac.id, name="이할머니", birth_date="1940-05-13"
    )

    # 사전 수동 시드 — 같은 해 birthday event
    pre_existing = Event(
        id=str(uuid.uuid4()),
        facility_id=fac.id,
        resident_id=res.id,
        type="birthday",
        title="이미 등록된 이벤트",
        start_at=datetime(2026, 5, 13),
        all_day=True,
        created_by=admin.id,
    )
    session.add(pre_existing)
    await session.commit()

    summary = await run(today=date(2026, 5, 6), session=session)
    await session.commit()

    assert summary["events_created"] == 0
    assert summary["skipped_existing"] == 1

    rows = (
        await session.execute(
            select(Event).filter(Event.resident_id == res.id, Event.type == "birthday")
        )
    ).scalars().all()
    assert len(rows) == 1


@pytest.mark.asyncio
async def test_notification_idempotent_across_reruns_on_d_minus_7(integration_db):
    """T-243-4: 같은 D-7 날 cron 이 두 번 돌아도 알림은 1회만. event 도 1개만."""
    _SL, session = integration_db
    fac = await _seed_facility(session)
    admin = await _seed_user(
        session, email="adm_dedup@x.io", role="staff", is_admin=True, facility_id=fac.id
    )
    res = await _seed_resident_with_bd(
        session, facility_id=fac.id, name="정할머니", birth_date="1940-05-13"
    )
    g = await _seed_user(session, email="g_dedup@x.io", role="guardian")
    await _seed_guardian(
        session, user_id=g.id, resident_id=res.id, facility_id=fac.id, approved=True
    )

    # 1st run on D-7 — event + notif emit
    s1 = await run(today=date(2026, 5, 6), session=session)
    await session.commit()
    assert s1["events_created"] == 1
    assert s1["notifications_created"] >= 2  # admin staff + guardian

    # 2nd run 같은 날 — event 는 skipped_existing, 알림은 notifications_skipped_existing
    s2 = await run(today=date(2026, 5, 6), session=session)
    await session.commit()
    assert s2["events_created"] == 0
    assert s2["skipped_existing"] == 1
    assert s2["notifications_created"] == 0
    assert s2["notifications_skipped_existing"] == 1

    notifs = (
        await session.execute(
            select(Notification).filter(Notification.notification_type == NOTIF_TYPE)
        )
    ).scalars().all()
    # 1st run 발송분만 — 2 (admin + guardian)
    assert len(notifs) == 2


@pytest.mark.asyncio
async def test_pre_existing_event_without_notified_at_still_notifies_on_d_minus_7(
    integration_db,
):
    """T-243-4 마이그 대비: 기존 운영 데이터 (notified_at IS NULL) 도 D-7 매칭 1회는
    알림 발송. 다음 run 부터는 dedup. (014 마이그 이전에 만들어진 row 에 대한 시나리오)
    """
    _SL, session = integration_db
    fac = await _seed_facility(session)
    admin = await _seed_user(
        session, email="adm_legacy@x.io", role="staff", is_admin=True, facility_id=fac.id
    )
    res = await _seed_resident_with_bd(
        session, facility_id=fac.id, name="류할머니", birth_date="1940-05-13"
    )
    pre_existing = Event(
        id=str(uuid.uuid4()),
        facility_id=fac.id,
        resident_id=res.id,
        type="birthday",
        title="이미 등록된 이벤트",
        start_at=datetime(2026, 5, 13),
        all_day=True,
        created_by=admin.id,
        birthday_notified_at=None,
    )
    session.add(pre_existing)
    await session.commit()

    s = await run(today=date(2026, 5, 6), session=session)
    await session.commit()
    assert s["events_created"] == 0
    assert s["skipped_existing"] == 1
    assert s["notifications_created"] >= 1  # admin staff 한 명은 최소
    assert s["notifications_skipped_existing"] == 0

    # event 의 notified_at 이 채워졌는지 — 두 번째 run 에서 dedup 동작 보장
    refreshed = (
        await session.execute(
            select(Event).filter(Event.id == pre_existing.id)
        )
    ).scalar_one()
    assert refreshed.birthday_notified_at is not None


@pytest.mark.asyncio
async def test_leap_day_resident_skipped(integration_db):
    _SL, session = integration_db
    fac = await _seed_facility(session)
    await _seed_user(
        session, email="adm4@x.io", role="staff", is_admin=True, facility_id=fac.id
    )
    await _seed_resident_with_bd(
        session, facility_id=fac.id, name="윤할아버지", birth_date="1940-02-29"
    )

    # today=2026-02-22 → target=2026-03-01 (윤년 아님). 윤일 생일은 어떤 today 와도 매칭 X.
    summary = await run(today=date(2026, 2, 22), session=session)
    assert summary["skipped_leap_day"] == 1
    assert summary["events_created"] == 0


# ---------------------------------------------------------------------------
# 알림 수신자
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_notifies_approved_guardian_and_facility_staff(integration_db):
    _SL, session = integration_db
    fac = await _seed_facility(session)
    admin = await _seed_user(
        session, email="adm5@x.io", role="staff", is_admin=True, facility_id=fac.id
    )
    other_staff = await _seed_user(
        session, email="staff5@x.io", role="staff", facility_id=fac.id
    )
    rejected_staff = await _seed_user(
        session, email="rej@x.io", role="staff", facility_id=fac.id, is_active=False
    )
    other_facility = await _seed_facility(session, code="OTHER", name="다른시설")
    other_fac_staff = await _seed_user(
        session, email="other@x.io", role="staff", facility_id=other_facility.id
    )

    res = await _seed_resident_with_bd(
        session, facility_id=fac.id, name="최할머니", birth_date="1940-05-13"
    )

    approved_g = await _seed_user(session, email="g_ok@x.io", role="guardian")
    pending_g = await _seed_user(session, email="g_pending@x.io", role="guardian")
    await _seed_guardian(
        session, user_id=approved_g.id, resident_id=res.id, facility_id=fac.id, approved=True
    )
    await _seed_guardian(
        session,
        user_id=pending_g.id,
        resident_id=res.id,
        facility_id=fac.id,
        approved=False,
    )

    summary = await run(today=date(2026, 5, 6), session=session)
    await session.commit()

    assert summary["events_created"] == 1
    notifs = (
        await session.execute(
            select(Notification).filter(Notification.notification_type == NOTIF_TYPE)
        )
    ).scalars().all()
    recipient_ids = {n.user_id for n in notifs}

    # 포함되어야: 승인된 보호자 + 시설장 + 활성 staff
    assert approved_g.id in recipient_ids
    assert admin.id in recipient_ids
    assert other_staff.id in recipient_ids

    # 제외되어야: 미승인 보호자, 비활성 staff, 다른 시설 staff
    assert pending_g.id not in recipient_ids
    assert rejected_staff.id not in recipient_ids
    assert other_fac_staff.id not in recipient_ids

    # title / message 가 비어있지 않은지 sanity
    sample = notifs[0]
    assert "생신" in sample.title
    assert sample.message != ""


# ---------------------------------------------------------------------------
# created_by 결정
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_falls_back_to_operator_when_no_admin(integration_db):
    _SL, session = integration_db
    fac = await _seed_facility(session)
    operator = await _seed_user(
        session, email="op@x.io", role="staff", is_operator=True
    )
    # 시설에 시설장 (is_admin) 없음
    res = await _seed_resident_with_bd(
        session, facility_id=fac.id, name="강할머니", birth_date="1940-05-13"
    )

    summary = await run(today=date(2026, 5, 6), session=session)
    await session.commit()

    assert summary["events_created"] == 1
    ev = (
        await session.execute(
            select(Event).filter(Event.resident_id == res.id, Event.type == "birthday")
        )
    ).scalar_one()
    assert ev.created_by == operator.id


@pytest.mark.asyncio
async def test_skips_when_no_creator_available(integration_db):
    _SL, session = integration_db
    fac = await _seed_facility(session)
    # 어떤 admin / operator 도 없음
    await _seed_resident_with_bd(
        session, facility_id=fac.id, name="조할머니", birth_date="1940-05-13"
    )

    summary = await run(today=date(2026, 5, 6), session=session)
    assert summary["events_created"] == 0
    assert summary["skipped_no_creator"] == 1
