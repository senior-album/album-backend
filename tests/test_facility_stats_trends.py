"""
T-143: 시설 사용 지표 트렌드 그래프 엔드포인트 테스트.

검증 대상:
- 가드: 권한 없는 staff → 403, 비인증 → 401
- 자기 시설만 — 다른 시설 facility_id 로 호출 시 403 (시설장이라도)
- 운영자는 다른 시설도 허용
- 위임 받은 직원 (UserPermission 행) 는 통과
- 월 버킷 길이 = range 파라미터 / 잘못된 range → 400
- 데이터 집계: photos_uploaded / photos_classified / matching_rate /
  active_guardians (PhotoLike) / photos_unprocessed_eom (pending/failed)
"""

from __future__ import annotations

# T-144 패턴 — Windows magic stub
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

from app.core.permissions import FACILITY_STATS_VIEW
from app.core.security import SecurityService
from app.models.models import (
    Facility,
    Photo,
    PhotoLike,
    PhotoProcessingJob,
    User,
    UserPermission,
)


async def _seed_facility(session, *, code: str = "FAC-A", name: str = "행복원") -> Facility:
    fac = Facility(id=str(uuid.uuid4()), code=code, name=name, address="서울시")
    session.add(fac)
    await session.commit()
    return fac


async def _seed_user(session, **kw) -> User:
    u = User(
        id=str(uuid.uuid4()),
        email=kw["email"],
        name=kw.get("name", "이름"),
        password_hash="$2b$12$dummy" + "x" * 40,
        role=kw.get("role", "staff"),
        is_admin=kw.get("is_admin", False),
        is_operator=kw.get("is_operator", False),
        is_active=kw.get("is_active", True),
        facility_id=kw.get("facility_id"),
    )
    session.add(u)
    await session.commit()
    return u


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
# 가드
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_trends_requires_auth(integration_client):
    resp = await integration_client.get("/facilities/00000000-0000-0000-0000-000000000000/stats/trends")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_trends_blocks_staff_without_permission(integration_client, integration_db):
    _, session = integration_db
    fac = await _seed_facility(session)
    staff = await _seed_user(session, email="s@x.io", role="staff", facility_id=fac.id)

    resp = await integration_client.get(
        f"/facilities/{fac.id}/stats/trends",
        cookies=_cookies(staff),
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_trends_admin_passes_via_role(integration_client, integration_db):
    _, session = integration_db
    fac = await _seed_facility(session)
    admin = await _seed_user(
        session, email="a@x.io", role="staff", is_admin=True, facility_id=fac.id
    )

    resp = await integration_client.get(
        f"/facilities/{fac.id}/stats/trends?range=3m",
        cookies=_cookies(admin),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["range"] == "3m"
    assert len(body["items"]) == 3


@pytest.mark.asyncio
async def test_trends_delegated_staff_passes(integration_client, integration_db):
    _, session = integration_db
    fac = await _seed_facility(session)
    admin = await _seed_user(
        session, email="a@x.io", role="staff", is_admin=True, facility_id=fac.id
    )
    staff = await _seed_user(session, email="s@x.io", role="staff", facility_id=fac.id)
    session.add(UserPermission(
        user_id=staff.id, permission_key=FACILITY_STATS_VIEW, granted_by=admin.id,
    ))
    await session.commit()

    resp = await integration_client.get(
        f"/facilities/{fac.id}/stats/trends",
        cookies=_cookies(staff),
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_trends_admin_blocked_for_other_facility(integration_client, integration_db):
    _, session = integration_db
    fac_a = await _seed_facility(session, code="FAC-A")
    fac_b = await _seed_facility(session, code="FAC-B")
    admin_a = await _seed_user(
        session, email="a@x.io", role="staff", is_admin=True, facility_id=fac_a.id
    )

    resp = await integration_client.get(
        f"/facilities/{fac_b.id}/stats/trends",
        cookies=_cookies(admin_a),
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_trends_operator_can_see_other_facility(integration_client, integration_db):
    _, session = integration_db
    fac_a = await _seed_facility(session, code="FAC-A")
    fac_b = await _seed_facility(session, code="FAC-B")
    op = await _seed_user(
        session, email="op@x.io", role="staff", is_operator=True, facility_id=fac_a.id
    )

    resp = await integration_client.get(
        f"/facilities/{fac_b.id}/stats/trends",
        cookies=_cookies(op),
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_trends_invalid_range_400(integration_client, integration_db):
    _, session = integration_db
    fac = await _seed_facility(session)
    admin = await _seed_user(
        session, email="a@x.io", role="staff", is_admin=True, facility_id=fac.id
    )

    resp = await integration_client.get(
        f"/facilities/{fac.id}/stats/trends?range=99m",
        cookies=_cookies(admin),
    )
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# 집계
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_trends_aggregates_photos_and_matching(integration_client, integration_db):
    _, session = integration_db
    fac = await _seed_facility(session)
    admin = await _seed_user(
        session, email="a@x.io", role="staff", is_admin=True, facility_id=fac.id
    )

    # 현재 월 사진 5개 — 이중 3개 is_processed=True
    now = datetime.utcnow()
    for i in range(5):
        session.add(Photo(
            id=str(uuid.uuid4()),
            facility_id=fac.id,
            original_url=f"http://x/p{i}.jpg",
            is_processed=(i < 3),
            created_at=now - timedelta(days=i),
        ))
    await session.commit()

    resp = await integration_client.get(
        f"/facilities/{fac.id}/stats/trends?range=3m",
        cookies=_cookies(admin),
    )
    assert resp.status_code == 200
    items = resp.json()["items"]
    cur = items[-1]  # 가장 최근 (현재) 월
    assert cur["photos_uploaded"] == 5
    assert cur["photos_classified"] == 3
    assert cur["matching_rate"] == 60.0


@pytest.mark.asyncio
async def test_trends_active_guardians_distinct_likes(integration_client, integration_db):
    _, session = integration_db
    fac = await _seed_facility(session)
    admin = await _seed_user(
        session, email="a@x.io", role="staff", is_admin=True, facility_id=fac.id
    )
    g1 = await _seed_user(session, email="g1@x.io", role="guardian")
    g2 = await _seed_user(session, email="g2@x.io", role="guardian")

    photo_id = str(uuid.uuid4())
    session.add(Photo(
        id=photo_id,
        facility_id=fac.id,
        original_url="http://x/p.jpg",
        is_processed=True,
    ))
    await session.commit()

    # 같은 사진에 g1 좋아요 2회 (멱등 효과 X — 모델은 별 행으로 들어감), g2 좋아요 1회
    now = datetime.utcnow()
    session.add(PhotoLike(photo_id=photo_id, user_id=g1.id, created_at=now))
    session.add(PhotoLike(photo_id=photo_id, user_id=g1.id, created_at=now))
    session.add(PhotoLike(photo_id=photo_id, user_id=g2.id, created_at=now))
    await session.commit()

    resp = await integration_client.get(
        f"/facilities/{fac.id}/stats/trends?range=3m",
        cookies=_cookies(admin),
    )
    assert resp.status_code == 200
    cur = resp.json()["items"][-1]
    assert cur["active_guardians"] == 2  # distinct user


@pytest.mark.asyncio
async def test_trends_unprocessed_eom_counts_pending_failed(integration_client, integration_db):
    _, session = integration_db
    fac = await _seed_facility(session)
    admin = await _seed_user(
        session, email="a@x.io", role="staff", is_admin=True, facility_id=fac.id
    )

    photo_id = str(uuid.uuid4())
    session.add(Photo(id=photo_id, facility_id=fac.id, original_url="http://x/p.jpg"))
    await session.commit()

    for st in ("pending", "failed", "completed"):
        session.add(PhotoProcessingJob(
            photo_id=photo_id, facility_id=fac.id, status=st,
        ))
    await session.commit()

    resp = await integration_client.get(
        f"/facilities/{fac.id}/stats/trends?range=3m",
        cookies=_cookies(admin),
    )
    assert resp.status_code == 200
    cur = resp.json()["items"][-1]
    # pending + failed = 2, completed 제외
    assert cur["photos_unprocessed_eom"] == 2


@pytest.mark.asyncio
async def test_trends_empty_facility_returns_zeros(integration_client, integration_db):
    _, session = integration_db
    fac = await _seed_facility(session)
    admin = await _seed_user(
        session, email="a@x.io", role="staff", is_admin=True, facility_id=fac.id
    )

    resp = await integration_client.get(
        f"/facilities/{fac.id}/stats/trends?range=3m",
        cookies=_cookies(admin),
    )
    assert resp.status_code == 200
    items = resp.json()["items"]
    assert all(it["photos_uploaded"] == 0 for it in items)
    assert all(it["matching_rate"] == 0.0 for it in items)
