"""T-241: 입소자 안부 일지 API.

엔드포인트:
- GET  /residents/{resident_id}/wellness-logs?start_date=&end_date= : 기간 목록.
- GET  /residents/{resident_id}/wellness-logs/{log_date}            : 단건.
- PUT  /residents/{resident_id}/wellness-logs/{log_date}            : upsert (직원만).

권한:
- write : 시설 직원 (해당 입소자가 속한 시설 소속 직원만).
- read  : 시설 직원 OR 본인이 승인된 입소자의 가디언.
"""

from __future__ import annotations

import logging
import uuid
from datetime import date

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import get_current_user, verify_facility_access
from app.models.models import Guardian, Resident, ResidentWellnessLog
from app.schemas.schemas import WellnessLogResponse, WellnessLogUpsert

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/residents", tags=["wellness-logs"])


async def _load_resident(db: AsyncSession, resident_id: str) -> Resident:
    stmt = select(Resident).filter(Resident.id == resident_id)
    result = await db.execute(stmt)
    resident = result.scalar_one_or_none()
    if not resident:
        raise HTTPException(status_code=404, detail="Resident not found")
    return resident


async def _verify_resident_log_read(
    current_user: dict,
    resident: Resident,
    db: AsyncSession,
) -> None:
    """안부 일지 read 권한 — 직원(같은 시설) 또는 가디언(승인된 본인 입소자)."""
    role = current_user.get("role")
    if role == "staff":
        await verify_facility_access(current_user, resident.facility_id, db)
        return
    if role == "guardian":
        stmt = select(Guardian.id).filter(
            Guardian.user_id == current_user["user_id"],
            Guardian.resident_id == resident.id,
            Guardian.is_approved == True,  # noqa: E712
        ).limit(1)
        result = await db.execute(stmt)
        if result.scalar_one_or_none() is not None:
            return
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="해당 입소자 일지에 접근 권한이 없습니다.",
    )


@router.get(
    "/{resident_id}/wellness-logs",
    response_model=list[WellnessLogResponse],
)
async def list_wellness_logs(
    resident_id: str,
    start_date: date | None = Query(None),
    end_date: date | None = Query(None),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """입소자 안부 일지 목록 — log_date desc 정렬.

    start_date / end_date 는 양쪽 inclusive. 둘 다 None 이면 전체 기간 (단,
    response 폭주 방지로 최근 90일 제한).
    """
    resident = await _load_resident(db, resident_id)
    await _verify_resident_log_read(current_user, resident, db)

    if start_date and end_date and start_date > end_date:
        raise HTTPException(
            status_code=400, detail="start_date 가 end_date 보다 클 수 없습니다."
        )

    stmt = select(ResidentWellnessLog).filter(
        ResidentWellnessLog.resident_id == resident_id
    )
    if start_date is not None:
        stmt = stmt.filter(ResidentWellnessLog.log_date >= start_date)
    if end_date is not None:
        stmt = stmt.filter(ResidentWellnessLog.log_date <= end_date)
    stmt = stmt.order_by(ResidentWellnessLog.log_date.desc()).limit(90)

    result = await db.execute(stmt)
    logs = result.scalars().all()
    return [WellnessLogResponse.model_validate(log) for log in logs]


@router.get(
    "/{resident_id}/wellness-logs/{log_date}",
    response_model=WellnessLogResponse,
)
async def get_wellness_log(
    resident_id: str,
    log_date: date,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """입소자 안부 일지 단건 조회."""
    resident = await _load_resident(db, resident_id)
    await _verify_resident_log_read(current_user, resident, db)

    stmt = select(ResidentWellnessLog).filter(
        ResidentWellnessLog.resident_id == resident_id,
        ResidentWellnessLog.log_date == log_date,
    )
    result = await db.execute(stmt)
    log = result.scalar_one_or_none()
    if not log:
        raise HTTPException(status_code=404, detail="Wellness log not found")
    return WellnessLogResponse.model_validate(log)


@router.put(
    "/{resident_id}/wellness-logs/{log_date}",
    response_model=WellnessLogResponse,
)
async def upsert_wellness_log(
    resident_id: str,
    log_date: date,
    payload: WellnessLogUpsert,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """안부 일지 upsert — 같은 (resident_id, log_date) 재호출은 같은 row 갱신.

    write 는 시설 직원만. role check + verify_facility_access 로 시설 일치 확인.
    """
    if current_user.get("role") != "staff":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="직원만 안부 일지를 작성할 수 있습니다.",
        )
    resident = await _load_resident(db, resident_id)
    await verify_facility_access(current_user, resident.facility_id, db)

    stmt = select(ResidentWellnessLog).filter(
        ResidentWellnessLog.resident_id == resident_id,
        ResidentWellnessLog.log_date == log_date,
    )
    result = await db.execute(stmt)
    log = result.scalar_one_or_none()

    if log is None:
        log = ResidentWellnessLog(
            id=str(uuid.uuid4()),
            resident_id=resident_id,
            log_date=log_date,
            mobility_status=payload.mobility_status,
            meal_breakfast=payload.meal_breakfast,
            meal_lunch=payload.meal_lunch,
            meal_dinner=payload.meal_dinner,
            notes=payload.notes,
            created_by=current_user["user_id"],
        )
        db.add(log)
    else:
        log.mobility_status = payload.mobility_status
        log.meal_breakfast = payload.meal_breakfast
        log.meal_lunch = payload.meal_lunch
        log.meal_dinner = payload.meal_dinner
        log.notes = payload.notes

    await db.commit()
    await db.refresh(log)
    return WellnessLogResponse.model_validate(log)
