"""T-243: 이벤트 캘린더 API 통합 테스트.

검증 대상:
- write 권한: 직원만 (자기 시설). 다른 시설 직원·가디언 거부.
- read 권한: 직원 (자기 시설 모두) | 가디언 (자기 입소자 + 시설 전체) | 운영자 (across).
- 입력 검증: type 화이트리스트 (Literal), end_at >= start_at, resident 가 facility 소속.
- 기간/타입 필터, 가디언 응답 스코핑 (다른 입소자 이벤트 안 보임).
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

import uuid
from datetime import datetime, timedelta

import pytest
from sqlalchemy import select

from app.core.security import SecurityService
from app.models.models import Event, Facility, Guardian, Resident, User


# ---------------------------------------------------------------------------
# 시드 헬퍼
# ---------------------------------------------------------------------------


async def _seed_facility(session, *, code: str = "FAC-T243", name: str = "햇살요양원") -> Facility:
    fac = Facility(id=str(uuid.uuid4()), code=code, name=name, address="서울시 어딘가")
    session.add(fac)
    await session.commit()
    return fac


async def _seed_user(
    session,
    *,
    email: str,
    name: str = "이름",
    role: str = "staff",
    facility_id: str | None = None,
    is_operator: bool = False,
) -> User:
    u = User(
        id=str(uuid.uuid4()),
        email=email,
        name=name,
        password_hash="$2b$12$dummy" + "x" * 50,
        role=role,
        is_active=True,
        is_operator=is_operator,
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


async def _seed_guardian(
    session, *, user_id: str, resident_id: str, facility_id: str, approved: bool = True
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


def _payload(
    *,
    type: str = "outing",
    title: str = "5월 야유회",
    start_at: datetime | None = None,
    end_at: datetime | None = None,
    all_day: bool = True,
    resident_id: str | None = None,
    description: str | None = None,
) -> dict:
    if start_at is None:
        start_at = datetime(2026, 5, 15, 10, 0)
    body = {
        "type": type,
        "title": title,
        "start_at": start_at.isoformat(),
        "all_day": all_day,
    }
    if end_at is not None:
        body["end_at"] = end_at.isoformat()
    if resident_id is not None:
        body["resident_id"] = resident_id
    if description is not None:
        body["description"] = description
    return body


# ---------------------------------------------------------------------------
# write 권한
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_staff_creates_facility_wide_event(integration_client, integration_db):
    _SL, session = integration_db
    fac = await _seed_facility(session)
    staff = await _seed_user(session, email="s1@x.io", role="staff", facility_id=fac.id)

    resp = await integration_client.post(
        f"/facilities/{fac.id}/events",
        json=_payload(type="outing", title="5월 야유회"),
        cookies=_auth_cookies(staff),
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["facility_id"] == fac.id
    assert body["resident_id"] is None
    assert body["type"] == "outing"
    assert body["created_by"] == staff.id


@pytest.mark.asyncio
async def test_staff_creates_resident_event(integration_client, integration_db):
    _SL, session = integration_db
    fac = await _seed_facility(session)
    staff = await _seed_user(session, email="s2@x.io", role="staff", facility_id=fac.id)
    res = await _seed_resident(session, facility_id=fac.id)

    resp = await integration_client.post(
        f"/facilities/{fac.id}/events",
        json=_payload(type="birthday", title="김할머니 생신", resident_id=res.id),
        cookies=_auth_cookies(staff),
    )
    assert resp.status_code == 201, resp.text
    assert resp.json()["resident_id"] == res.id


@pytest.mark.asyncio
async def test_create_rejects_resident_from_other_facility(integration_client, integration_db):
    _SL, session = integration_db
    fac_a = await _seed_facility(session, code="FAC-A", name="A요양원")
    fac_b = await _seed_facility(session, code="FAC-B", name="B요양원")
    staff_a = await _seed_user(session, email="sa@x.io", role="staff", facility_id=fac_a.id)
    res_b = await _seed_resident(session, facility_id=fac_b.id)

    resp = await integration_client.post(
        f"/facilities/{fac_a.id}/events",
        json=_payload(type="birthday", title="잘못된 입소자", resident_id=res_b.id),
        cookies=_auth_cookies(staff_a),
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_create_rejects_invalid_type(integration_client, integration_db):
    _SL, session = integration_db
    fac = await _seed_facility(session)
    staff = await _seed_user(session, email="s3@x.io", role="staff", facility_id=fac.id)

    resp = await integration_client.post(
        f"/facilities/{fac.id}/events",
        json=_payload(type="visit", title="없는 타입"),  # visit 은 어휘에서 빠짐
        cookies=_auth_cookies(staff),
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_create_rejects_end_before_start(integration_client, integration_db):
    _SL, session = integration_db
    fac = await _seed_facility(session)
    staff = await _seed_user(session, email="s4@x.io", role="staff", facility_id=fac.id)

    resp = await integration_client.post(
        f"/facilities/{fac.id}/events",
        json=_payload(
            start_at=datetime(2026, 5, 15, 14, 0),
            end_at=datetime(2026, 5, 15, 10, 0),
            all_day=False,
        ),
        cookies=_auth_cookies(staff),
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_other_facility_staff_cannot_create(integration_client, integration_db):
    _SL, session = integration_db
    fac_a = await _seed_facility(session, code="FAC-A", name="A요양원")
    fac_b = await _seed_facility(session, code="FAC-B", name="B요양원")
    staff_b = await _seed_user(session, email="sb@x.io", role="staff", facility_id=fac_b.id)

    resp = await integration_client.post(
        f"/facilities/{fac_a.id}/events",
        json=_payload(),
        cookies=_auth_cookies(staff_b),
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_guardian_cannot_create(integration_client, integration_db):
    _SL, session = integration_db
    fac = await _seed_facility(session)
    res = await _seed_resident(session, facility_id=fac.id)
    guardian = await _seed_user(session, email="g1@x.io", role="guardian")
    await _seed_guardian(
        session, user_id=guardian.id, resident_id=res.id, facility_id=fac.id
    )

    resp = await integration_client.post(
        f"/facilities/{fac.id}/events",
        json=_payload(resident_id=res.id),
        cookies=_auth_cookies(guardian),
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# read / list
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_staff_lists_all_facility_events(integration_client, integration_db):
    _SL, session = integration_db
    fac = await _seed_facility(session)
    staff = await _seed_user(session, email="s5@x.io", role="staff", facility_id=fac.id)
    res1 = await _seed_resident(session, facility_id=fac.id, name="A입소자")
    res2 = await _seed_resident(session, facility_id=fac.id, name="B입소자")

    base = datetime(2026, 5, 1, 0, 0)
    for i, (rid, t) in enumerate(
        [
            (None, "outing"),
            (res1.id, "birthday"),
            (res2.id, "birthday"),
        ]
    ):
        session.add(
            Event(
                id=str(uuid.uuid4()),
                facility_id=fac.id,
                resident_id=rid,
                type=t,
                title=f"이벤트 {i}",
                start_at=base + timedelta(days=i),
                all_day=True,
                created_by=staff.id,
            )
        )
    await session.commit()

    resp = await integration_client.get(
        f"/facilities/{fac.id}/events", cookies=_auth_cookies(staff)
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert len(body) == 3
    # start_at asc
    starts = [r["start_at"] for r in body]
    assert starts == sorted(starts)


@pytest.mark.asyncio
async def test_list_filters_by_period_and_type(integration_client, integration_db):
    _SL, session = integration_db
    fac = await _seed_facility(session)
    staff = await _seed_user(session, email="s6@x.io", role="staff", facility_id=fac.id)

    base = datetime(2026, 5, 1, 0, 0)
    for i, t in enumerate(["outing", "birthday", "outing", "other"]):
        session.add(
            Event(
                id=str(uuid.uuid4()),
                facility_id=fac.id,
                type=t,
                title=f"e{i}",
                start_at=base + timedelta(days=i * 2),  # 5/1, 5/3, 5/5, 5/7
                all_day=True,
                created_by=staff.id,
            )
        )
    await session.commit()

    # period 만 — 5/3..5/5
    resp = await integration_client.get(
        f"/facilities/{fac.id}/events",
        params={
            "from": datetime(2026, 5, 3).isoformat(),
            "to": datetime(2026, 5, 5, 23, 59).isoformat(),
        },
        cookies=_auth_cookies(staff),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert {r["title"] for r in body} == {"e1", "e2"}

    # type=outing 만
    resp2 = await integration_client.get(
        f"/facilities/{fac.id}/events",
        params={"type": "outing"},
        cookies=_auth_cookies(staff),
    )
    assert resp2.status_code == 200
    titles = {r["title"] for r in resp2.json()}
    assert titles == {"e0", "e2"}


@pytest.mark.asyncio
async def test_guardian_list_scoped_to_own_resident_plus_facility_wide(
    integration_client, integration_db
):
    _SL, session = integration_db
    fac = await _seed_facility(session)
    staff = await _seed_user(session, email="s7@x.io", role="staff", facility_id=fac.id)
    mine = await _seed_resident(session, facility_id=fac.id, name="우리어머니")
    other = await _seed_resident(session, facility_id=fac.id, name="다른어르신")
    guardian = await _seed_user(session, email="g2@x.io", role="guardian")
    await _seed_guardian(
        session, user_id=guardian.id, resident_id=mine.id, facility_id=fac.id
    )

    base = datetime(2026, 5, 10)
    seeds = [
        (None, "facility-wide"),
        (mine.id, "mine-bday"),
        (other.id, "other-bday"),
    ]
    for i, (rid, title) in enumerate(seeds):
        session.add(
            Event(
                id=str(uuid.uuid4()),
                facility_id=fac.id,
                resident_id=rid,
                type="birthday" if rid else "outing",
                title=title,
                start_at=base + timedelta(days=i),
                all_day=True,
                created_by=staff.id,
            )
        )
    await session.commit()

    resp = await integration_client.get(
        f"/facilities/{fac.id}/events", cookies=_auth_cookies(guardian)
    )
    assert resp.status_code == 200, resp.text
    titles = {r["title"] for r in resp.json()}
    assert titles == {"facility-wide", "mine-bday"}


@pytest.mark.asyncio
async def test_guardian_with_no_facility_residents_blocked(
    integration_client, integration_db
):
    _SL, session = integration_db
    fac = await _seed_facility(session)
    guardian = await _seed_user(session, email="g3@x.io", role="guardian")
    # 가디언이지만 이 시설에 가디언십 없음

    resp = await integration_client.get(
        f"/facilities/{fac.id}/events", cookies=_auth_cookies(guardian)
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_guardian_pending_approval_blocked(integration_client, integration_db):
    _SL, session = integration_db
    fac = await _seed_facility(session)
    res = await _seed_resident(session, facility_id=fac.id)
    guardian = await _seed_user(session, email="g4@x.io", role="guardian")
    await _seed_guardian(
        session,
        user_id=guardian.id,
        resident_id=res.id,
        facility_id=fac.id,
        approved=False,
    )

    resp = await integration_client.get(
        f"/facilities/{fac.id}/events", cookies=_auth_cookies(guardian)
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_guardian_get_other_resident_event_blocked(
    integration_client, integration_db
):
    _SL, session = integration_db
    fac = await _seed_facility(session)
    staff = await _seed_user(session, email="s8@x.io", role="staff", facility_id=fac.id)
    mine = await _seed_resident(session, facility_id=fac.id, name="우리어머니")
    other = await _seed_resident(session, facility_id=fac.id, name="다른어르신")
    guardian = await _seed_user(session, email="g5@x.io", role="guardian")
    await _seed_guardian(
        session, user_id=guardian.id, resident_id=mine.id, facility_id=fac.id
    )

    other_event = Event(
        id=str(uuid.uuid4()),
        facility_id=fac.id,
        resident_id=other.id,
        type="birthday",
        title="다른어르신 생신",
        start_at=datetime(2026, 6, 1),
        all_day=True,
        created_by=staff.id,
    )
    session.add(other_event)
    await session.commit()

    resp = await integration_client.get(
        f"/events/{other_event.id}", cookies=_auth_cookies(guardian)
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_operator_can_read_across_facilities(integration_client, integration_db):
    _SL, session = integration_db
    fac_a = await _seed_facility(session, code="FAC-A", name="A요양원")
    fac_b = await _seed_facility(session, code="FAC-B", name="B요양원")
    staff_a = await _seed_user(session, email="sa@x.io", role="staff", facility_id=fac_a.id)
    operator = await _seed_user(
        session, email="op@x.io", role="staff", is_operator=True
    )

    session.add(
        Event(
            id=str(uuid.uuid4()),
            facility_id=fac_b.id,
            type="outing",
            title="B시설 행사",
            start_at=datetime(2026, 6, 1),
            all_day=True,
            created_by=staff_a.id,  # 시드 편의
        )
    )
    await session.commit()

    resp = await integration_client.get(
        f"/facilities/{fac_b.id}/events", cookies=_auth_cookies(operator)
    )
    assert resp.status_code == 200
    assert len(resp.json()) == 1


# ---------------------------------------------------------------------------
# update / delete
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_staff_patches_event_fields(integration_client, integration_db):
    _SL, session = integration_db
    fac = await _seed_facility(session)
    staff = await _seed_user(session, email="s9@x.io", role="staff", facility_id=fac.id)

    ev = Event(
        id=str(uuid.uuid4()),
        facility_id=fac.id,
        type="outing",
        title="제목 전",
        start_at=datetime(2026, 5, 20),
        all_day=True,
        created_by=staff.id,
    )
    session.add(ev)
    await session.commit()

    resp = await integration_client.patch(
        f"/events/{ev.id}",
        json={"title": "제목 후", "description": "비고 추가"},
        cookies=_auth_cookies(staff),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["title"] == "제목 후"
    assert body["description"] == "비고 추가"
    # 미전달 필드 보존
    assert body["type"] == "outing"


@pytest.mark.asyncio
async def test_patch_rejects_end_before_start(integration_client, integration_db):
    _SL, session = integration_db
    fac = await _seed_facility(session)
    staff = await _seed_user(session, email="s10@x.io", role="staff", facility_id=fac.id)

    ev = Event(
        id=str(uuid.uuid4()),
        facility_id=fac.id,
        type="outing",
        title="시간 변경",
        start_at=datetime(2026, 5, 20, 10, 0),
        end_at=datetime(2026, 5, 20, 14, 0),
        all_day=False,
        created_by=staff.id,
    )
    session.add(ev)
    await session.commit()

    # end_at 만 바꿔서 start 보다 빠르게
    resp = await integration_client.patch(
        f"/events/{ev.id}",
        json={"end_at": datetime(2026, 5, 20, 9, 0).isoformat()},
        cookies=_auth_cookies(staff),
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_other_facility_staff_cannot_patch(integration_client, integration_db):
    _SL, session = integration_db
    fac_a = await _seed_facility(session, code="FAC-A", name="A요양원")
    fac_b = await _seed_facility(session, code="FAC-B", name="B요양원")
    staff_a = await _seed_user(session, email="sa2@x.io", role="staff", facility_id=fac_a.id)
    staff_b = await _seed_user(session, email="sb2@x.io", role="staff", facility_id=fac_b.id)

    ev = Event(
        id=str(uuid.uuid4()),
        facility_id=fac_a.id,
        type="outing",
        title="A이벤트",
        start_at=datetime(2026, 5, 20),
        all_day=True,
        created_by=staff_a.id,
    )
    session.add(ev)
    await session.commit()

    resp = await integration_client.patch(
        f"/events/{ev.id}",
        json={"title": "탈취 시도"},
        cookies=_auth_cookies(staff_b),
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_staff_deletes_event(integration_client, integration_db):
    _SL, session = integration_db
    fac = await _seed_facility(session)
    staff = await _seed_user(session, email="s11@x.io", role="staff", facility_id=fac.id)

    ev = Event(
        id=str(uuid.uuid4()),
        facility_id=fac.id,
        type="outing",
        title="삭제 대상",
        start_at=datetime(2026, 5, 20),
        all_day=True,
        created_by=staff.id,
    )
    session.add(ev)
    await session.commit()

    resp = await integration_client.delete(
        f"/events/{ev.id}", cookies=_auth_cookies(staff)
    )
    assert resp.status_code == 204

    rows = (
        await session.execute(select(Event).filter(Event.id == ev.id))
    ).scalars().all()
    assert rows == []
