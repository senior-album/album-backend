"""T-147: /admin/photo-jobs — 사진 처리 큐 모니터링 + 실패 작업 재큐."""

from __future__ import annotations

import os as _os
import sys as _sys
import types as _types

if "magic" not in _sys.modules:
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
    Photo,
    PhotoProcessingJob,
    User,
)


async def _seed_facility(session, *, code: str, name: str = "T") -> Facility:
    fac = Facility(id=str(uuid.uuid4()), code=code, name=name, address="X")
    session.add(fac)
    await session.commit()
    return fac


async def _seed_user(session, *, email: str, role: str = "staff", is_operator: bool = False, facility_id=None) -> User:
    u = User(
        id=str(uuid.uuid4()),
        email=email,
        name="이름",
        password_hash="$2b$12$dummy" + "x" * 50,
        role=role,
        is_admin=False,
        is_operator=is_operator,
        is_active=True,
        facility_id=facility_id,
    )
    session.add(u)
    await session.commit()
    return u


async def _seed_job(
    session, *, facility_id: str, status: str = "pending", error: str | None = None,
    retry: int = 0, photo_id: str | None = None,
) -> PhotoProcessingJob:
    if photo_id is None:
        p = Photo(id=str(uuid.uuid4()), facility_id=facility_id, original_url="u", thumbnail_url="t", processing_status="pending")
        session.add(p)
        await session.commit()
        photo_id = p.id
    j = PhotoProcessingJob(
        id=str(uuid.uuid4()),
        photo_id=photo_id,
        facility_id=facility_id,
        status=status,
        error_message=error,
        retry_count=retry,
        max_retries=3,
    )
    session.add(j)
    await session.commit()
    return j


def _auth_cookies(user: User) -> dict[str, str]:
    token = SecurityService.create_access_token(
        data={"sub": user.id, "email": user.email, "role": user.role, "facility_id": user.facility_id}
    )
    return {"access_token": token}


@pytest.mark.asyncio
async def test_list_photo_jobs_requires_operator(integration_client, integration_db):
    _SessionLocal, session = integration_db
    fac = await _seed_facility(session, code="FAC-1")
    staff = await _seed_user(session, email="s@x.io", role="staff", facility_id=fac.id)
    resp = await integration_client.get("/admin/photo-jobs", cookies=_auth_cookies(staff))
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_list_photo_jobs_returns_with_facility_name(integration_client, integration_db):
    _SessionLocal, session = integration_db
    fac1 = await _seed_facility(session, code="FAC-1", name="A원")
    fac2 = await _seed_facility(session, code="FAC-2", name="B원")
    operator = await _seed_user(session, email="op@x.io", role="staff", is_operator=True, facility_id=fac1.id)
    await _seed_job(session, facility_id=fac1.id, status="pending")
    await _seed_job(session, facility_id=fac1.id, status="failed", error="boom")
    await _seed_job(session, facility_id=fac2.id, status="completed")

    resp = await integration_client.get("/admin/photo-jobs", cookies=_auth_cookies(operator))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total"] == 3
    by_status = {item["status"]: item for item in body["items"]}
    assert by_status["pending"]["facility_name"] == "A원"
    assert by_status["failed"]["error_message"] == "boom"
    assert by_status["completed"]["facility_name"] == "B원"


@pytest.mark.asyncio
async def test_list_photo_jobs_status_filter(integration_client, integration_db):
    _SessionLocal, session = integration_db
    fac = await _seed_facility(session, code="FAC-1")
    operator = await _seed_user(session, email="op@x.io", role="staff", is_operator=True, facility_id=fac.id)
    await _seed_job(session, facility_id=fac.id, status="pending")
    await _seed_job(session, facility_id=fac.id, status="failed")
    await _seed_job(session, facility_id=fac.id, status="completed")

    resp = await integration_client.get("/admin/photo-jobs?status=failed", cookies=_auth_cookies(operator))
    body = resp.json()
    assert body["total"] == 1
    assert body["items"][0]["status"] == "failed"


@pytest.mark.asyncio
async def test_list_photo_jobs_invalid_status_400(integration_client, integration_db):
    _SessionLocal, session = integration_db
    fac = await _seed_facility(session, code="FAC-1")
    operator = await _seed_user(session, email="op@x.io", role="staff", is_operator=True, facility_id=fac.id)
    resp = await integration_client.get("/admin/photo-jobs?status=garbage", cookies=_auth_cookies(operator))
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_retry_resets_failed_job_and_audits(integration_client, integration_db):
    SessionLocal, session = integration_db
    fac = await _seed_facility(session, code="FAC-1")
    operator = await _seed_user(session, email="op@x.io", role="staff", is_operator=True, facility_id=fac.id)
    job = await _seed_job(session, facility_id=fac.id, status="failed", error="prev_boom", retry=3)

    resp = await integration_client.post(f"/admin/photo-jobs/{job.id}/retry", cookies=_auth_cookies(operator))
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["status"] == "pending"
    assert body["retry_count"] == 0
    assert body["error_message"] is None

    async with SessionLocal() as s:
        refreshed = await s.get(PhotoProcessingJob, job.id)
        assert refreshed.status == "pending"
        assert refreshed.error_message is None
        assert refreshed.retry_count == 0
        assert refreshed.started_at is None
        assert refreshed.completed_at is None

        log = (
            await s.execute(select(AdminAuditLog).where(AdminAuditLog.action == "photo_job_retry"))
        ).scalar_one()
        assert log.target_id == job.id
        assert "prev_boom" in log.detail


@pytest.mark.asyncio
async def test_retry_non_failed_job_409(integration_client, integration_db):
    _SessionLocal, session = integration_db
    fac = await _seed_facility(session, code="FAC-1")
    operator = await _seed_user(session, email="op@x.io", role="staff", is_operator=True, facility_id=fac.id)
    job = await _seed_job(session, facility_id=fac.id, status="processing")

    resp = await integration_client.post(f"/admin/photo-jobs/{job.id}/retry", cookies=_auth_cookies(operator))
    assert resp.status_code == 409
    assert "processing" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_retry_unknown_job_404(integration_client, integration_db):
    _SessionLocal, session = integration_db
    fac = await _seed_facility(session, code="FAC-1")
    operator = await _seed_user(session, email="op@x.io", role="staff", is_operator=True, facility_id=fac.id)

    resp = await integration_client.post("/admin/photo-jobs/unknown/retry", cookies=_auth_cookies(operator))
    assert resp.status_code == 404
