"""T-241: 입소자 안부 일지 API 통합 테스트.

검증 대상:
- write 권한: 직원만, 같은 시설만.
- read 권한: 직원 (같은 시설) / 가디언 (승인된 본인 입소자만).
- upsert 멱등성: 같은 (resident, date) PUT 재호출은 같은 row 갱신, 새 row 생성 X.
- 기간 조회: start_date / end_date 필터 + log_date desc 정렬.
- 입력 검증: mobility_status / meal_* 화이트리스트 외 값은 422.
"""

from __future__ import annotations

import base64 as _b64
import os as _os
import platform as _platform
import sys as _sys
import types as _types

# Windows 에서 magic 라이브러리 로드 시 segfault 회피 (test_invitation_inapp.py 동일 패턴)
if _platform.system() == "Windows" and "magic" not in _sys.modules:
    _stub = _types.ModuleType("magic")
    _stub.from_buffer = lambda data, mime=False: "image/jpeg"  # type: ignore[attr-defined]
    _stub.from_file = lambda path, mime=False: "image/jpeg"  # type: ignore[attr-defined]
    _sys.modules["magic"] = _stub

_os.environ.setdefault("JWT_SECRET", "test-secret-value-for-jwt-32-bytes-min")
_os.environ.setdefault("JWT_REFRESH_SECRET", "test-refresh-secret-32bytes-minimum")
# RESIDENT_PII_KEK: base64 디코드 후 32바이트여야 함 — "0"*64 는 디코드 후 48바이트라 단독 실행 시 실패.
_os.environ.setdefault("RESIDENT_PII_KEK", _b64.b64encode(b"\x11" * 32).decode())
_os.environ.setdefault("RESIDENT_NAME_HMAC_KEY", _b64.b64encode(b"\x22" * 32).decode())

_os.environ.setdefault("USER_PHONE_HMAC_KEY", _b64.b64encode(b"\x32" * 32).decode())
import uuid
from datetime import date

import pytest
from sqlalchemy import select

from app.core.security import SecurityService
from app.models.models import Facility, Guardian, Resident, ResidentWellnessLog, User


# ---------------------------------------------------------------------------
# 헬퍼
# ---------------------------------------------------------------------------


async def _seed_facility(session, *, code: str = "FAC-T241", name: str = "햇살요양원") -> Facility:
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
) -> User:
    u = User(
        id=str(uuid.uuid4()),
        email=email,
        name=name,
        password_hash="$2b$12$dummy" + "x" * 50,
        role=role,
        is_active=True,
        facility_id=facility_id,
        # T-056: 미승인 staff 차단 가드 — 기본 시드는 승인 완료.
        is_staff_approved=True,
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


# ---------------------------------------------------------------------------
# write 권한
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_upsert_creates_then_updates_idempotent(integration_client, integration_db):
    _SL, session = integration_db
    fac = await _seed_facility(session)
    staff = await _seed_user(session, email="s1@x.io", role="staff", facility_id=fac.id)
    res = await _seed_resident(session, facility_id=fac.id)

    # 1차 PUT — 새로 생성
    resp1 = await integration_client.put(
        f"/residents/{res.id}/wellness-logs/2026-05-05",
        json={
            "mobility_status": "walker",
            "meal_breakfast": "full",
            "meal_lunch": "partial",
            "meal_dinner": "skipped",
            "notes": "오전 기침 잦음",
        },
        cookies=_auth_cookies(staff),
    )
    assert resp1.status_code == 200, resp1.text
    body1 = resp1.json()
    assert body1["resident_id"] == res.id
    assert body1["log_date"] == "2026-05-05"
    assert body1["mobility_status"] == "walker"
    assert body1["meal_lunch"] == "partial"
    assert body1["created_by"] == staff.id
    log_id_first = body1["id"]

    # 2차 PUT — 같은 키, 다른 값. 같은 row 갱신.
    resp2 = await integration_client.put(
        f"/residents/{res.id}/wellness-logs/2026-05-05",
        json={
            "mobility_status": "wheelchair",
            "meal_breakfast": "refused",
            "notes": "오후 회복",
        },
        cookies=_auth_cookies(staff),
    )
    assert resp2.status_code == 200, resp2.text
    body2 = resp2.json()
    assert body2["id"] == log_id_first  # 같은 row
    assert body2["mobility_status"] == "wheelchair"
    assert body2["meal_breakfast"] == "refused"
    # 미전달 필드는 None 으로 덮어쓰기 (PUT replace 시맨틱)
    assert body2["meal_lunch"] is None
    assert body2["meal_dinner"] is None

    # DB 에 row 1개만 있어야 함
    rows = (
        await session.execute(
            select(ResidentWellnessLog).filter(ResidentWellnessLog.resident_id == res.id)
        )
    ).scalars().all()
    assert len(rows) == 1


@pytest.mark.asyncio
async def test_upsert_blocked_for_guardian(integration_client, integration_db):
    _SL, session = integration_db
    fac = await _seed_facility(session)
    res = await _seed_resident(session, facility_id=fac.id)
    guardian_user = await _seed_user(session, email="g1@x.io", role="guardian")
    await _seed_guardian(
        session, user_id=guardian_user.id, resident_id=res.id, facility_id=fac.id
    )

    resp = await integration_client.put(
        f"/residents/{res.id}/wellness-logs/2026-05-05",
        json={"mobility_status": "walker"},
        cookies=_auth_cookies(guardian_user),
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_upsert_blocked_for_other_facility_staff(integration_client, integration_db):
    _SL, session = integration_db
    fac_a = await _seed_facility(session, code="FAC-A", name="A요양원")
    fac_b = await _seed_facility(session, code="FAC-B", name="B요양원")
    res_a = await _seed_resident(session, facility_id=fac_a.id)
    staff_b = await _seed_user(session, email="sb@x.io", role="staff", facility_id=fac_b.id)

    resp = await integration_client.put(
        f"/residents/{res_a.id}/wellness-logs/2026-05-05",
        json={"mobility_status": "walker"},
        cookies=_auth_cookies(staff_b),
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_upsert_invalid_enum_rejected(integration_client, integration_db):
    _SL, session = integration_db
    fac = await _seed_facility(session)
    staff = await _seed_user(session, email="s2@x.io", role="staff", facility_id=fac.id)
    res = await _seed_resident(session, facility_id=fac.id)

    resp = await integration_client.put(
        f"/residents/{res.id}/wellness-logs/2026-05-05",
        json={"mobility_status": "flying"},  # 화이트리스트 외
        cookies=_auth_cookies(staff),
    )
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# read 권한
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_guardian_can_read_own_resident_logs(integration_client, integration_db):
    _SL, session = integration_db
    fac = await _seed_facility(session)
    staff = await _seed_user(session, email="s3@x.io", role="staff", facility_id=fac.id)
    res = await _seed_resident(session, facility_id=fac.id)
    guardian_user = await _seed_user(session, email="g2@x.io", role="guardian")
    await _seed_guardian(
        session, user_id=guardian_user.id, resident_id=res.id, facility_id=fac.id
    )

    # 직원이 일지 작성
    await integration_client.put(
        f"/residents/{res.id}/wellness-logs/2026-05-05",
        json={"mobility_status": "walker", "notes": "양호"},
        cookies=_auth_cookies(staff),
    )

    # 가디언이 list 조회
    resp = await integration_client.get(
        f"/residents/{res.id}/wellness-logs",
        cookies=_auth_cookies(guardian_user),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1
    assert body[0]["mobility_status"] == "walker"

    # 가디언이 단건 조회
    resp_one = await integration_client.get(
        f"/residents/{res.id}/wellness-logs/2026-05-05",
        cookies=_auth_cookies(guardian_user),
    )
    assert resp_one.status_code == 200
    assert resp_one.json()["notes"] == "양호"


@pytest.mark.asyncio
async def test_guardian_other_resident_blocked(integration_client, integration_db):
    _SL, session = integration_db
    fac = await _seed_facility(session)
    res_mine = await _seed_resident(session, facility_id=fac.id, name="우리어머니")
    res_other = await _seed_resident(session, facility_id=fac.id, name="다른어르신")
    guardian_user = await _seed_user(session, email="g3@x.io", role="guardian")
    # 본인은 res_mine 의 가디언만
    await _seed_guardian(
        session,
        user_id=guardian_user.id,
        resident_id=res_mine.id,
        facility_id=fac.id,
    )

    resp = await integration_client.get(
        f"/residents/{res_other.id}/wellness-logs",
        cookies=_auth_cookies(guardian_user),
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_guardian_pending_approval_blocked(integration_client, integration_db):
    _SL, session = integration_db
    fac = await _seed_facility(session)
    res = await _seed_resident(session, facility_id=fac.id)
    guardian_user = await _seed_user(session, email="g4@x.io", role="guardian")
    # 승인 X
    await _seed_guardian(
        session,
        user_id=guardian_user.id,
        resident_id=res.id,
        facility_id=fac.id,
        approved=False,
    )

    resp = await integration_client.get(
        f"/residents/{res.id}/wellness-logs",
        cookies=_auth_cookies(guardian_user),
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# 기간 필터
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_filters_by_date_range_and_orders_desc(integration_client, integration_db):
    _SL, session = integration_db
    fac = await _seed_facility(session)
    staff = await _seed_user(session, email="s4@x.io", role="staff", facility_id=fac.id)
    res = await _seed_resident(session, facility_id=fac.id)

    # 직접 시드 — API 가 아닌 ORM 으로 빠르게.
    for d in ["2026-05-01", "2026-05-03", "2026-05-05", "2026-05-10"]:
        log = ResidentWellnessLog(
            id=str(uuid.uuid4()),
            resident_id=res.id,
            log_date=date.fromisoformat(d),
            mobility_status="independent",
            created_by=staff.id,
        )
        session.add(log)
    await session.commit()

    # start=05-03, end=05-05 → 2건, desc 정렬
    resp = await integration_client.get(
        f"/residents/{res.id}/wellness-logs",
        params={"start_date": "2026-05-03", "end_date": "2026-05-05"},
        cookies=_auth_cookies(staff),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert [r["log_date"] for r in body] == ["2026-05-05", "2026-05-03"]


@pytest.mark.asyncio
async def test_list_rejects_inverted_range(integration_client, integration_db):
    _SL, session = integration_db
    fac = await _seed_facility(session)
    staff = await _seed_user(session, email="s5@x.io", role="staff", facility_id=fac.id)
    res = await _seed_resident(session, facility_id=fac.id)

    resp = await integration_client.get(
        f"/residents/{res.id}/wellness-logs",
        params={"start_date": "2026-05-10", "end_date": "2026-05-01"},
        cookies=_auth_cookies(staff),
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_get_single_returns_404_when_missing(integration_client, integration_db):
    _SL, session = integration_db
    fac = await _seed_facility(session)
    staff = await _seed_user(session, email="s6@x.io", role="staff", facility_id=fac.id)
    res = await _seed_resident(session, facility_id=fac.id)

    resp = await integration_client.get(
        f"/residents/{res.id}/wellness-logs/2026-05-05",
        cookies=_auth_cookies(staff),
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_resident_not_found_returns_404(integration_client, integration_db):
    _SL, session = integration_db
    fac = await _seed_facility(session)
    staff = await _seed_user(session, email="s7@x.io", role="staff", facility_id=fac.id)

    resp = await integration_client.get(
        "/residents/nonexistent-id/wellness-logs",
        cookies=_auth_cookies(staff),
    )
    assert resp.status_code == 404
