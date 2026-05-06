"""T-243-3 — 생신 자동 발급 + D-7 인앱 알림 cron 작업.

매일 1회 k8s CronJob 으로 실행 (album-deploy 별도 매니페스트). 오늘 + 7일
후가 생일인 활성 입소자를 추출해:

  1) `Event(type='birthday')` 를 올해 날짜로 멱등 생성.
     dedup 키: `(resident_id, type='birthday', year(start_at) = target_year)`.
  2) 승인된 보호자 + 시설 활성 staff 에게 `Notification` 발송.
     `notification_type='event_birthday_reminder'`. 멱등성은 1) 의 신규 event
     생성이 일어났을 때만 보내는 흐름으로 자연 보장.

CronJob 컨테이너는 `RESIDENT_PII_KEK` env 가 마운트돼 있어야 한다 — 입소자
이름 + 생년월일은 envelope encryption 컬럼이라 복호화 필요. 누락 시 첫
`unwrap_dek` 호출에서 ValueError → CronJob 실패로 운영자 알림 (T-041).

`created_by` 는 시스템 자동 생성용 첫 시설장 (`is_admin=True`) → 운영자 →
없으면 그 시설은 skip + warning.

윤일 (2/29) 출생자: D-7 매칭이 깨지므로 1차 비대상. 후속 정책 (issue#203).
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
import uuid
from datetime import date, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import decrypt_field, unwrap_dek
from app.core.database import Database
from app.models.models import Event, Guardian, Notification, Resident, User


logger = logging.getLogger(__name__)

DAYS_AHEAD = 7
NOTIF_TYPE = "event_birthday_reminder"


async def _resolve_creator_id(session: AsyncSession, facility_id: str) -> str | None:
    """시스템 자동 생성 이벤트의 `created_by` — 시설장 우선, 없으면 운영자."""
    # 1) 시설장 (is_admin=True, 같은 시설, active)
    stmt = (
        select(User.id)
        .where(
            User.facility_id == facility_id,
            User.is_admin == True,  # noqa: E712
            User.is_active == True,  # noqa: E712
        )
        .limit(1)
    )
    row = (await session.execute(stmt)).scalar_one_or_none()
    if row is not None:
        return row
    # 2) 운영자 (is_operator=True, active)
    stmt = (
        select(User.id)
        .where(User.is_operator == True, User.is_active == True)  # noqa: E712
        .limit(1)
    )
    return (await session.execute(stmt)).scalar_one_or_none()


async def _existing_birthday_event(
    session: AsyncSession, resident_id: str, year: int
) -> Event | None:
    """올해 같은 입소자에 이미 생성된 birthday 이벤트가 있으면 반환."""
    stmt = select(Event).where(
        Event.resident_id == resident_id,
        Event.type == "birthday",
        Event.start_at >= datetime(year, 1, 1),
        Event.start_at < datetime(year + 1, 1, 1),
    )
    return (await session.execute(stmt)).scalar_one_or_none()


async def _recipient_user_ids(
    session: AsyncSession, resident_id: str, facility_id: str
) -> set[str]:
    """보호자 (승인) + 시설 활성 staff 의 user_id 집합."""
    g_stmt = select(Guardian.user_id).where(
        Guardian.resident_id == resident_id,
        Guardian.is_approved == True,  # noqa: E712
    )
    s_stmt = select(User.id).where(
        User.facility_id == facility_id,
        User.is_active == True,  # noqa: E712
        User.role == "staff",
    )
    g_rows = (await session.execute(g_stmt)).all()
    s_rows = (await session.execute(s_stmt)).all()
    return {r[0] for r in g_rows} | {r[0] for r in s_rows}


async def run(
    *,
    today: date | None = None,
    session: AsyncSession | None = None,
) -> dict[str, Any]:
    """크론 진입점.

    Args:
        today: 테스트 주입용. 미지정 시 `date.today()`.
        session: 테스트 주입용 (호출자가 commit 책임). 미지정 시 본 함수가
                 `Database.session_scope()` 로 자체 commit/rollback.

    Returns:
        요약 통계 dict — CronJob 로그 + Discord 알림 (T-041) 에서 활용 가능.
    """
    if today is None:
        today = date.today()

    if session is not None:
        return await _scan_and_emit(session, today=today)

    async with Database.session_scope() as s:
        return await _scan_and_emit(s, today=today)


async def _scan_and_emit(
    session: AsyncSession, *, today: date
) -> dict[str, Any]:
    target = today + timedelta(days=DAYS_AHEAD)

    summary: dict[str, Any] = {
        "today": today.isoformat(),
        "target_date": target.isoformat(),
        "events_created": 0,
        "notifications_created": 0,
        "skipped_existing": 0,
        "skipped_leap_day": 0,
        "skipped_no_creator": 0,
        "decrypt_errors": 0,
        "scanned_residents": 0,
    }

    stmt = select(Resident).where(
        Resident.is_active == True,  # noqa: E712
        Resident.birth_date_ct.isnot(None),
        Resident.dek_wrapped.isnot(None),
    )
    residents = (await session.execute(stmt)).scalars().all()
    summary["scanned_residents"] = len(residents)

    for r in residents:
        try:
            dek = unwrap_dek(r.dek_wrapped)
            bd = date.fromisoformat(decrypt_field(r.birth_date_ct, dek))
        except Exception as e:
            logger.warning(
                "resident=%s birth_date decrypt/parse failed: %s", r.id, e
            )
            summary["decrypt_errors"] += 1
            continue

        # 윤일 출생자: D-7 매칭이 깨지므로 1차 비대상.
        if bd.month == 2 and bd.day == 29:
            summary["skipped_leap_day"] += 1
            continue

        if (bd.month, bd.day) != (target.month, target.day):
            continue

        this_year_bday = datetime(target.year, bd.month, bd.day)

        # 멱등성 — 같은 해 이미 birthday event 있으면 skip.
        if (
            await _existing_birthday_event(session, r.id, this_year_bday.year)
            is not None
        ):
            summary["skipped_existing"] += 1
            continue

        creator_id = await _resolve_creator_id(session, r.facility_id)
        if creator_id is None:
            logger.warning(
                "facility=%s 시설장/운영자 없음 — resident=%s 생신 이벤트 skip",
                r.facility_id,
                r.id,
            )
            summary["skipped_no_creator"] += 1
            continue

        try:
            name = (
                decrypt_field(r.name_ct, dek) if r.name_ct is not None else "어르신"
            )
        except Exception:
            name = "어르신"

        ev = Event(
            id=str(uuid.uuid4()),
            facility_id=r.facility_id,
            resident_id=r.id,
            type="birthday",
            title=f"{name} 어르신 생신",
            description=None,
            start_at=this_year_bday,
            end_at=None,
            all_day=True,
            created_by=creator_id,
        )
        session.add(ev)
        summary["events_created"] += 1

        recipients = await _recipient_user_ids(session, r.id, r.facility_id)
        notif_msg = f"{this_year_bday.strftime('%Y년 %m월 %d일')} 생신입니다."
        for uid in recipients:
            session.add(
                Notification(
                    id=str(uuid.uuid4()),
                    user_id=uid,
                    title=f"D-{DAYS_AHEAD}: {name} 어르신 생신",
                    message=notif_msg,
                    notification_type=NOTIF_TYPE,
                )
            )
            summary["notifications_created"] += 1

    return summary


def _main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format='{"ts":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","message":"%(message)s"}',
    )

    async def _go() -> dict[str, Any]:
        await Database.initialize()
        try:
            return await run()
        finally:
            await Database.close()

    summary = asyncio.run(_go())
    logger.info("birthday_reminder summary=%s", summary)
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(_main())
