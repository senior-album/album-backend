"""T-148: /admin/stats — 통계 대시보드 집계 검증."""

from __future__ import annotations

import os as _os
import platform as _platform
import sys as _sys
import types as _types

# Windows 전용 stub — 자세한 배경은 test_admin_users.py 상단 주석.
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

from app.core.security import SecurityService
from app.models.models import (
    Facility,
    Guardian,
    Photo,
    PhotoProcessingJob,
    Resident,
    User,
)


def _auth_cookies(user: User) -> dict[str, str]:
    token = SecurityService.create_access_token(
        data={"sub": user.id, "email": user.email, "role": user.role, "facility_id": user.facility_id}
    )
    return {"access_token": token}


@pytest.mark.asyncio
async def test_stats_requires_operator(integration_client, integration_db):
    _SessionLocal, session = integration_db
    fac = Facility(id=str(uuid.uuid4()), code="FAC-1", name="A", address="X")
    session.add(fac)
    staff = User(
        id=str(uuid.uuid4()), email="s@x.io", name="S",
        password_hash="$2b$12$d" + "x" * 50, role="staff",
        is_admin=False, is_operator=False, is_active=True, facility_id=fac.id,
    )
    session.add(staff)
    await session.commit()
    resp = await integration_client.get("/admin/stats", cookies=_auth_cookies(staff))
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_stats_aggregates_correctly(integration_client, integration_db):
    SessionLocal, session = integration_db
    fac1 = Facility(id=str(uuid.uuid4()), code="FAC-1", name="A", address="X")
    fac2 = Facility(id=str(uuid.uuid4()), code="FAC-2", name="B", address="Y")
    session.add(fac1)
    session.add(fac2)
    await session.commit()

    operator = User(
        id=str(uuid.uuid4()), email="op@x.io", name="OP",
        password_hash="$2b$12$d" + "x" * 50, role="staff",
        is_admin=False, is_operator=True, is_active=True, facility_id=fac1.id,
    )
    session.add(operator)
    # staff 1 더, guardian 2, 비활성 1
    session.add(User(id=str(uuid.uuid4()), email="s2@x.io", name="S2", password_hash="x", role="staff",
                     is_active=True, is_operator=False, facility_id=fac1.id))
    session.add(User(id=str(uuid.uuid4()), email="g1@x.io", name="G1", password_hash="x", role="guardian",
                     is_active=True, is_operator=False))
    session.add(User(id=str(uuid.uuid4()), email="g2@x.io", name="G2", password_hash="x", role="guardian",
                     is_active=False, is_operator=False))

    # residents: active 2, inactive 1
    session.add(Resident(id=str(uuid.uuid4()), facility_id=fac1.id, code="R-1", name="R1", is_active=True))
    session.add(Resident(id=str(uuid.uuid4()), facility_id=fac1.id, code="R-2", name="R2", is_active=True))
    session.add(Resident(id=str(uuid.uuid4()), facility_id=fac2.id, code="R-3", name="R3", is_active=False))

    # photos: 3 total (1 today, 2 processed, 1 public)
    now = datetime.utcnow()
    session.add(Photo(id=str(uuid.uuid4()), facility_id=fac1.id, original_url="u1", is_processed=True, is_public=True, created_at=now))
    session.add(Photo(id=str(uuid.uuid4()), facility_id=fac1.id, original_url="u2", is_processed=True, is_public=False, created_at=now - timedelta(days=2)))
    session.add(Photo(id=str(uuid.uuid4()), facility_id=fac2.id, original_url="u3", is_processed=False, is_public=False, created_at=now - timedelta(days=10)))

    # jobs: pending 1, failed 2, completed 1
    for st in ("pending", "failed", "failed", "completed"):
        session.add(PhotoProcessingJob(
            id=str(uuid.uuid4()), photo_id=str(uuid.uuid4()), facility_id=fac1.id,
            status=st, retry_count=0, max_retries=3,
        ))

    # guardians: 1 pending, 1 approved, 1 rejected
    for state_kwargs in [{}, {"is_approved": True}, {"is_rejected": True}]:
        u = User(
            id=str(uuid.uuid4()), email=f"gx{uuid.uuid4().hex[:6]}@x.io", name="X",
            password_hash="x", role="guardian", is_active=True, is_operator=False,
        )
        session.add(u)
        await session.commit()
        session.add(Guardian(id=str(uuid.uuid4()), user_id=u.id, facility_id=fac1.id, **state_kwargs))

    await session.commit()

    resp = await integration_client.get("/admin/stats", cookies=_auth_cookies(operator))
    assert resp.status_code == 200, resp.text
    body = resp.json()

    # users: total 1(op) + 1(s2) + 2(g1,g2) + 3(guardians block) = 7
    assert body["users"]["total"] == 7
    assert body["users"]["by"]["staff"] == 2
    assert body["users"]["by"]["guardian"] == 5
    assert body["users"]["by"]["operator"] == 1
    assert body["users"]["by"]["active"] == 6  # g2 만 비활성

    assert body["facilities"]["total"] == 2
    assert body["residents"]["total"] == 2  # active 만

    assert body["photos"]["total"] == 3
    assert body["photos"]["by"]["today"] == 1
    assert body["photos"]["by"]["processed"] == 2
    assert body["photos"]["by"]["public"] == 1

    assert body["photo_jobs"]["total"] == 4
    assert body["photo_jobs"]["by"]["pending"] == 1
    assert body["photo_jobs"]["by"]["failed"] == 2
    assert body["photo_jobs"]["by"]["completed"] == 1

    assert body["guardians"]["total"] == 3
    assert body["guardians"]["by"]["pending"] == 1
    assert body["guardians"]["by"]["approved"] == 1
    assert body["guardians"]["by"]["rejected"] == 1

    # 7일 추세 — 항상 7개 row, 합이 일치
    assert len(body["user_signups_7d"]) == 7
    assert len(body["photo_uploads_7d"]) == 7
    # 사진 추세: 1 today + 1 (-2d) = 2 (오늘 포함 7일 안), 10일전 1개는 빠짐
    assert sum(b["count"] for b in body["photo_uploads_7d"]) == 2


@pytest.mark.asyncio
async def test_stats_empty_db_returns_zeros(integration_client, integration_db):
    _SessionLocal, session = integration_db
    fac = Facility(id=str(uuid.uuid4()), code="FAC-1", name="A", address="X")
    session.add(fac)
    operator = User(
        id=str(uuid.uuid4()), email="op@x.io", name="OP",
        password_hash="x", role="staff", is_active=True, is_operator=True, facility_id=fac.id,
    )
    session.add(operator)
    await session.commit()

    resp = await integration_client.get("/admin/stats", cookies=_auth_cookies(operator))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["users"]["total"] == 1  # operator
    assert body["residents"]["total"] == 0
    assert body["photos"]["total"] == 0
    assert body["photo_jobs"]["total"] == 0
    assert body["guardians"]["total"] == 0
    assert sum(b["count"] for b in body["user_signups_7d"]) == 1  # operator
    assert sum(b["count"] for b in body["photo_uploads_7d"]) == 0
