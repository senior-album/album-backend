"""T-182 Phase 2 — 보관기간 초과 로그/만료 row 자동 파기.

`roadmap/docs/log-retention-policy.md` 의 §2-3, §2-4, §2-8 을 구현. 매주
일요일 19:00 UTC k8s CronJob 으로 실행된다 (album-deploy 별도 매니페스트).

대상 테이블 + cutoff:

  - `refresh_tokens`           : `expires_at < now`        (정책: 만료 즉시)
  - `photo_shares` (link 만)   : `expires_at < now - 30d`  (정책 §2-8)
  - `photo_processing_jobs`    : `status in (completed,failed) AND created_at < now - 60d`
  - `notifications`            : `created_at < now - 90d`
  - `photo_audit_logs`         : `created_at < now - 3y`
  - `admin_audit_logs`         : `created_at < now - 3y`

`--dry-run` 옵션 시 SELECT COUNT 만 돌리고 DELETE 는 안 함. 운영자가 cutoff
처음 적용할 때 영향 받는 row 수를 미리 보기 위함.

각 테이블 처리 결과는 `summary` dict 로 반환되고 stdout 에 JSON 한 줄
(uvicorn 와 동일 포맷) 로 찍힌다 — Loki 가 그걸 잡아 운영자가 추세 확인.

`user_consents` / `consent_documents` / `legal_settings` 는 정책 §3.2 (전상법
3년~5년 + 분쟁 대응) 으로 본 스크립트가 절대 건드리지 않는다.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import and_, delete, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import Database
from app.models.models import (
    AdminAuditLog,
    Notification,
    PhotoAuditLog,
    PhotoProcessingJob,
    PhotoShare,
    RefreshToken,
)


logger = logging.getLogger(__name__)


# 보관기간 — 정책 문서 §2-3, §2-4, §2-8 과 동기화. 변경 시 정책 문서 같이 갱신.
SHARE_LINK_RETENTION_DAYS = 30
PROCESSING_JOB_RETENTION_DAYS = 60
NOTIFICATION_RETENTION_DAYS = 90
AUDIT_LOG_RETENTION_DAYS = 365 * 3   # 3년


async def _count(session: AsyncSession, stmt) -> int:
    """SELECT COUNT(*) 헬퍼 — dry-run 에서 영향 row 개수 보기용."""
    return (await session.execute(stmt)).scalar_one()


async def _purge_refresh_tokens(
    session: AsyncSession, *, now: datetime, dry_run: bool
) -> int:
    """만료된 refresh token row 즉시 삭제.

    revoke_reason 무관 — 만료된 토큰은 인증 가치가 없다. 만료 안 된 revoke
    토큰(rotated/logout) 은 reuse detection 윈도우 동안 보관 필요하므로 본
    cron 은 expires_at 만 본다.
    """
    cnt_stmt = select(func.count()).select_from(RefreshToken).where(
        RefreshToken.expires_at < now
    )
    n = await _count(session, cnt_stmt)
    if dry_run or n == 0:
        return n
    await session.execute(delete(RefreshToken).where(RefreshToken.expires_at < now))
    return n


async def _purge_photo_shares(
    session: AsyncSession, *, now: datetime, dry_run: bool
) -> int:
    """`link` 타입 공유 중 expires_at + 30일이 지난 row 만 삭제.

    - kakao 타입은 expires_at 이 의미 없고 (즉발 발송) 삭제 대상 아님.
    - share_token 자체는 만료 후에도 검증 단계에서 거부되므로 보안 이슈 없음.
      30일 유예는 "누가 만든 링크였나" 를 짧게 추적할 수 있게 함.
    """
    cutoff = now - timedelta(days=SHARE_LINK_RETENTION_DAYS)
    cond = and_(
        PhotoShare.share_type == "link",
        PhotoShare.expires_at.isnot(None),
        PhotoShare.expires_at < cutoff,
    )
    cnt_stmt = select(func.count()).select_from(PhotoShare).where(cond)
    n = await _count(session, cnt_stmt)
    if dry_run or n == 0:
        return n
    await session.execute(delete(PhotoShare).where(cond))
    return n


async def _purge_photo_processing_jobs(
    session: AsyncSession, *, now: datetime, dry_run: bool
) -> int:
    """완료/실패 상태로 60일 지난 job row 삭제.

    pending/processing 은 절대 건드리지 않음 — 워커가 살아 잡고 있을 수 있음.
    failed 60일은 운영자가 retry 하거나 포기 결정을 내릴 충분한 기간.
    """
    cutoff = now - timedelta(days=PROCESSING_JOB_RETENTION_DAYS)
    cond = and_(
        PhotoProcessingJob.status.in_(["completed", "failed"]),
        PhotoProcessingJob.created_at < cutoff,
    )
    cnt_stmt = select(func.count()).select_from(PhotoProcessingJob).where(cond)
    n = await _count(session, cnt_stmt)
    if dry_run or n == 0:
        return n
    await session.execute(delete(PhotoProcessingJob).where(cond))
    return n


async def _purge_notifications(
    session: AsyncSession, *, now: datetime, dry_run: bool
) -> int:
    """90일 지난 알림 삭제 — 읽음 여부 무관.

    정책 §2-8: 사용자에게 도달한 후 가치 저하. 안 읽은 90일 전 알림도
    제때 도달 못 했으면 더 보관해도 의미 없음.
    """
    cutoff = now - timedelta(days=NOTIFICATION_RETENTION_DAYS)
    cnt_stmt = select(func.count()).select_from(Notification).where(
        Notification.created_at < cutoff
    )
    n = await _count(session, cnt_stmt)
    if dry_run or n == 0:
        return n
    await session.execute(delete(Notification).where(Notification.created_at < cutoff))
    return n


async def _purge_audit_logs(
    session: AsyncSession,
    *,
    now: datetime,
    dry_run: bool,
) -> tuple[int, int]:
    """photo_audit_logs / admin_audit_logs 둘 다 3년 cutoff.

    정책 §2-4 — 개인정보보호법 §30 처리 이력 3년 + T-181 유출 조사 의존성.
    이 cutoff 는 단축 금지 (정책 문서 §2-4 주석 참조).
    """
    cutoff = now - timedelta(days=AUDIT_LOG_RETENTION_DAYS)

    photo_cnt_stmt = select(func.count()).select_from(PhotoAuditLog).where(
        PhotoAuditLog.created_at < cutoff
    )
    admin_cnt_stmt = select(func.count()).select_from(AdminAuditLog).where(
        AdminAuditLog.created_at < cutoff
    )
    photo_n = await _count(session, photo_cnt_stmt)
    admin_n = await _count(session, admin_cnt_stmt)

    if not dry_run:
        if photo_n:
            await session.execute(
                delete(PhotoAuditLog).where(PhotoAuditLog.created_at < cutoff)
            )
        if admin_n:
            await session.execute(
                delete(AdminAuditLog).where(AdminAuditLog.created_at < cutoff)
            )

    return photo_n, admin_n


async def run(
    *,
    now: datetime | None = None,
    session: AsyncSession | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """크론 진입점.

    Args:
        now: 테스트 주입용 cutoff 기준 시각. 미지정 시 `datetime.utcnow()`.
        session: 테스트 주입용 (호출자가 commit 책임). 미지정 시 본 함수가
                 `Database.session_scope()` 로 자체 commit/rollback.
        dry_run: True 면 카운트만 — DELETE 안 함.

    Returns:
        테이블별 삭제 row 수 dict. CronJob 로그/Discord 알림 (T-041) 활용.
    """
    if now is None:
        now = datetime.utcnow()

    if session is not None:
        return await _run_all(session, now=now, dry_run=dry_run)

    async with Database.session_scope() as s:
        return await _run_all(s, now=now, dry_run=dry_run)


async def _run_all(
    session: AsyncSession, *, now: datetime, dry_run: bool
) -> dict[str, Any]:
    refresh_n = await _purge_refresh_tokens(session, now=now, dry_run=dry_run)
    share_n = await _purge_photo_shares(session, now=now, dry_run=dry_run)
    job_n = await _purge_photo_processing_jobs(session, now=now, dry_run=dry_run)
    notif_n = await _purge_notifications(session, now=now, dry_run=dry_run)
    photo_audit_n, admin_audit_n = await _purge_audit_logs(
        session, now=now, dry_run=dry_run
    )

    return {
        "now": now.isoformat(),
        "dry_run": dry_run,
        "refresh_tokens_expired": refresh_n,
        "photo_shares_expired_link": share_n,
        "photo_processing_jobs_done": job_n,
        "notifications_old": notif_n,
        "photo_audit_logs_old": photo_audit_n,
        "admin_audit_logs_old": admin_audit_n,
        "total_rows": (
            refresh_n + share_n + job_n + notif_n + photo_audit_n + admin_audit_n
        ),
    }


def _main() -> int:
    parser = argparse.ArgumentParser(description="Purge expired logs / tokens (T-182)")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="SELECT COUNT 만 — 실제 DELETE 없이 영향 row 수만 출력",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format='{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","message":"%(message)s"}',
    )

    async def _go() -> dict[str, Any]:
        await Database.initialize()
        try:
            return await run(dry_run=args.dry_run)
        finally:
            await Database.close()

    summary = asyncio.run(_go())
    # Loki 가 잡기 좋은 단일 JSON line.
    print(json.dumps({"event": "purge_expired_logs", **summary}, ensure_ascii=False))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(_main())
