"""T-182 Phase 2: 보관기간 초과 row 자동 파기 cron 단위 테스트.

검증 대상:
- 각 테이블의 cutoff 경계: 정확히 cutoff 직전 row 만 살아남는다
- `--dry-run` 은 카운트만, 실제 row 는 그대로
- pending/processing 상태의 photo_processing_jobs 는 60일 넘어도 보존
- kakao 타입 photo_shares 는 expires_at 무관하게 보존
- consent / 법적 보관 테이블은 절대 건드리지 않음 (no-op 검증)
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

from app.models.models import (
    AdminAuditLog,
    ConsentDocument,
    Facility,
    Notification,
    Photo,
    PhotoAuditLog,
    PhotoProcessingJob,
    PhotoShare,
    RefreshToken,
    User,
    UserConsent,
)
from app.scripts.purge_expired_logs import (
    AUDIT_LOG_RETENTION_DAYS,
    NOTIFICATION_RETENTION_DAYS,
    PROCESSING_JOB_RETENTION_DAYS,
    SHARE_LINK_RETENTION_DAYS,
    run,
)


# 모든 테스트가 같은 기준 시각을 쓰면 cutoff 경계 검증이 단순해진다.
NOW = datetime(2026, 5, 6, 12, 0, 0)


# ---------------------------------------------------------------------------
# 시드 헬퍼
# ---------------------------------------------------------------------------


async def _seed_user(session, *, email: str = "u@x.io") -> User:
    u = User(
        id=str(uuid.uuid4()),
        email=email,
        name="이름",
        password_hash="$2b$12$dummy" + "x" * 50,
        role="staff",
        is_active=True,
        is_staff_approved=True,
    )
    session.add(u)
    await session.commit()
    return u


async def _seed_facility(session, *, code: str = "FAC-T182") -> Facility:
    fac = Facility(id=str(uuid.uuid4()), code=code, name="햇살", address="서울")
    session.add(fac)
    await session.commit()
    return fac


async def _seed_photo(session, *, facility_id: str) -> Photo:
    p = Photo(
        id=str(uuid.uuid4()),
        facility_id=facility_id,
        original_url="s3://bucket/x.jpg",
    )
    session.add(p)
    await session.commit()
    return p


def _make_refresh_token(*, user_id: str, expires_at: datetime) -> RefreshToken:
    return RefreshToken(
        id=str(uuid.uuid4()),
        user_id=user_id,
        jti=str(uuid.uuid4()),
        family_id=str(uuid.uuid4()),
        expires_at=expires_at,
    )


# ---------------------------------------------------------------------------
# refresh_tokens — 만료 즉시
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_refresh_tokens_expired_removed_active_kept(integration_db):
    _SL, session = integration_db
    u = await _seed_user(session)

    expired = _make_refresh_token(user_id=u.id, expires_at=NOW - timedelta(seconds=1))
    active = _make_refresh_token(user_id=u.id, expires_at=NOW + timedelta(days=14))
    session.add_all([expired, active])
    await session.commit()

    summary = await run(now=NOW, session=session)
    await session.commit()

    assert summary["refresh_tokens_expired"] == 1

    rows = (await session.execute(select(RefreshToken))).scalars().all()
    assert {r.id for r in rows} == {active.id}


# ---------------------------------------------------------------------------
# photo_shares — link 30일 cutoff, kakao 무관
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_photo_shares_link_cutoff_and_kakao_preserved(integration_db):
    _SL, session = integration_db
    u = await _seed_user(session)
    fac = await _seed_facility(session)
    photo = await _seed_photo(session, facility_id=fac.id)

    cutoff = NOW - timedelta(days=SHARE_LINK_RETENTION_DAYS)

    old_link = PhotoShare(
        photo_id=photo.id,
        user_id=u.id,
        share_type="link",
        share_token="tok-old",
        expires_at=cutoff - timedelta(seconds=1),  # 직전 = 삭제
    )
    fresh_link = PhotoShare(
        photo_id=photo.id,
        user_id=u.id,
        share_type="link",
        share_token="tok-fresh",
        expires_at=cutoff + timedelta(seconds=1),  # 직후 = 보존
    )
    unexpired_link = PhotoShare(
        photo_id=photo.id,
        user_id=u.id,
        share_type="link",
        share_token="tok-future",
        expires_at=NOW + timedelta(days=10),
    )
    kakao_old = PhotoShare(
        photo_id=photo.id,
        user_id=u.id,
        share_type="kakao",
        share_token=None,
        expires_at=None,  # kakao 는 expires_at 없음 — 보존
    )
    session.add_all([old_link, fresh_link, unexpired_link, kakao_old])
    await session.commit()

    summary = await run(now=NOW, session=session)
    await session.commit()

    assert summary["photo_shares_expired_link"] == 1

    remaining_tokens = {
        r.share_token
        for r in (await session.execute(select(PhotoShare))).scalars().all()
    }
    assert remaining_tokens == {"tok-fresh", "tok-future", None}


# ---------------------------------------------------------------------------
# photo_processing_jobs — 60일 + status 화이트리스트
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_photo_processing_jobs_done_only_purged(integration_db):
    _SL, session = integration_db
    fac = await _seed_facility(session)
    photo = await _seed_photo(session, facility_id=fac.id)

    cutoff = NOW - timedelta(days=PROCESSING_JOB_RETENTION_DAYS)

    old_completed = PhotoProcessingJob(
        photo_id=photo.id,
        facility_id=fac.id,
        status="completed",
        created_at=cutoff - timedelta(seconds=1),
    )
    old_failed = PhotoProcessingJob(
        photo_id=photo.id,
        facility_id=fac.id,
        status="failed",
        created_at=cutoff - timedelta(days=10),
    )
    # status pending/processing 은 60일 넘어도 절대 건드리지 않음 — 워커가
    # 잡고 있을 가능성. (실 운영에선 그런 일이 없어야 하지만 cron 이 멋대로
    # 인플라잇 작업을 지우면 안 됨.)
    old_pending = PhotoProcessingJob(
        photo_id=photo.id,
        facility_id=fac.id,
        status="pending",
        created_at=cutoff - timedelta(days=10),
    )
    fresh_completed = PhotoProcessingJob(
        photo_id=photo.id,
        facility_id=fac.id,
        status="completed",
        created_at=cutoff + timedelta(seconds=1),
    )
    session.add_all([old_completed, old_failed, old_pending, fresh_completed])
    await session.commit()

    summary = await run(now=NOW, session=session)
    await session.commit()

    assert summary["photo_processing_jobs_done"] == 2

    remaining = (
        await session.execute(select(PhotoProcessingJob))
    ).scalars().all()
    statuses = sorted([(r.status, r.created_at) for r in remaining])
    assert len(remaining) == 2
    assert any(s == "pending" for s, _ in statuses)
    assert any(s == "completed" and at > cutoff for s, at in statuses)


# ---------------------------------------------------------------------------
# notifications — 90일 cutoff
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_notifications_old_purged(integration_db):
    _SL, session = integration_db
    u = await _seed_user(session)

    cutoff = NOW - timedelta(days=NOTIFICATION_RETENTION_DAYS)

    old = Notification(
        id=str(uuid.uuid4()),
        user_id=u.id,
        title="old",
        message="msg",
        notification_type="x",
        is_read=False,  # 읽음 여부 무관 — 90일 지나면 삭제
        created_at=cutoff - timedelta(seconds=1),
    )
    fresh = Notification(
        id=str(uuid.uuid4()),
        user_id=u.id,
        title="fresh",
        message="msg",
        notification_type="x",
        created_at=cutoff + timedelta(seconds=1),
    )
    session.add_all([old, fresh])
    await session.commit()

    summary = await run(now=NOW, session=session)
    await session.commit()

    assert summary["notifications_old"] == 1
    titles = {n.title for n in (await session.execute(select(Notification))).scalars().all()}
    assert titles == {"fresh"}


# ---------------------------------------------------------------------------
# audit logs — 3년 cutoff (둘 다)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_audit_logs_three_year_cutoff(integration_db):
    _SL, session = integration_db
    u = await _seed_user(session)
    fac = await _seed_facility(session)
    photo = await _seed_photo(session, facility_id=fac.id)

    cutoff = NOW - timedelta(days=AUDIT_LOG_RETENTION_DAYS)

    old_photo = PhotoAuditLog(
        photo_id=photo.id,
        action="view",
        performed_by=u.id,
        created_at=cutoff - timedelta(seconds=1),
    )
    fresh_photo = PhotoAuditLog(
        photo_id=photo.id,
        action="view",
        performed_by=u.id,
        created_at=cutoff + timedelta(seconds=1),
    )
    old_admin = AdminAuditLog(
        action="guardian_approve",
        performed_by=u.id,
        target_type="guardian",
        target_id="t-1",
        facility_id=fac.id,
        created_at=cutoff - timedelta(seconds=1),
    )
    fresh_admin = AdminAuditLog(
        action="guardian_approve",
        performed_by=u.id,
        target_type="guardian",
        target_id="t-2",
        facility_id=fac.id,
        created_at=cutoff + timedelta(seconds=1),
    )
    session.add_all([old_photo, fresh_photo, old_admin, fresh_admin])
    await session.commit()

    summary = await run(now=NOW, session=session)
    await session.commit()

    assert summary["photo_audit_logs_old"] == 1
    assert summary["admin_audit_logs_old"] == 1

    photo_remaining = (await session.execute(select(PhotoAuditLog))).scalars().all()
    admin_remaining = (await session.execute(select(AdminAuditLog))).scalars().all()
    assert {r.id for r in photo_remaining} == {fresh_photo.id}
    assert {r.id for r in admin_remaining} == {fresh_admin.id}


# ---------------------------------------------------------------------------
# dry-run
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dry_run_counts_but_keeps_rows(integration_db):
    _SL, session = integration_db
    u = await _seed_user(session)

    expired = _make_refresh_token(user_id=u.id, expires_at=NOW - timedelta(days=1))
    session.add(expired)
    old_notif = Notification(
        id=str(uuid.uuid4()),
        user_id=u.id,
        title="old",
        message="m",
        notification_type="x",
        created_at=NOW - timedelta(days=NOTIFICATION_RETENTION_DAYS + 1),
    )
    session.add(old_notif)
    await session.commit()

    summary = await run(now=NOW, session=session, dry_run=True)
    await session.commit()

    assert summary["dry_run"] is True
    assert summary["refresh_tokens_expired"] == 1
    assert summary["notifications_old"] == 1
    # 실제 row 는 그대로
    assert (await session.execute(select(RefreshToken))).scalars().all()
    assert (await session.execute(select(Notification))).scalars().all()


# ---------------------------------------------------------------------------
# 법적 보관 테이블은 절대 건드리지 않음
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_consent_tables_never_purged(integration_db):
    """user_consents / consent_documents 는 정책 §3.2 (전상법 3년~5년 + 분쟁
    대응) 으로 본 cron 의 범위 밖. 매우 오래된 row 라도 보존돼야 한다."""
    _SL, session = integration_db
    u = await _seed_user(session)

    very_old = NOW - timedelta(days=AUDIT_LOG_RETENTION_DAYS * 2)

    doc = ConsentDocument(
        id=str(uuid.uuid4()),
        type="terms_guardian",
        version="v0.1",
        title="옛 약관",
        content="...",
        is_mandatory=True,
        effective_from=very_old,
        created_at=very_old,
    )
    session.add(doc)
    await session.commit()
    consent = UserConsent(
        id=str(uuid.uuid4()),
        user_id=u.id,
        document_id=doc.id,
        agreed=True,
        agreed_at=very_old,
    )
    session.add(consent)
    await session.commit()

    await run(now=NOW, session=session)
    await session.commit()

    assert (await session.execute(select(ConsentDocument))).scalars().all()
    assert (await session.execute(select(UserConsent))).scalars().all()


# ---------------------------------------------------------------------------
# empty case — 아무 row 없을 때 깔끔히 0 반환
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_empty_db_returns_all_zero(integration_db):
    _SL, session = integration_db
    summary = await run(now=NOW, session=session)
    assert summary["total_rows"] == 0
    assert summary["dry_run"] is False
