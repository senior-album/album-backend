"""T-243: 이벤트 캘린더 API.

엔드포인트:
- GET    /facilities/{facility_id}/events?from&to&resident_id&type : 시설 단위 목록.
- POST   /facilities/{facility_id}/events                          : 생성 (직원).
- GET    /events/{event_id}                                        : 단건 조회.
- PATCH  /events/{event_id}                                        : 부분 갱신 (직원).
- DELETE /events/{event_id}                                        : 삭제 (직원).

권한:
- write : 시설 직원 (이벤트의 facility 와 직원 facility 일치).
- read  : 직원 (자기 시설 모두) | 가디언 (자기 입소자 + 시설 전체 행사) | 운영자.

생신 자동 발급 / 면회 RSVP / 알림 연동은 본 PR 범위 밖 (T-243-2/3 후속).
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import get_current_user, verify_facility_access
from app.models.models import Event, Guardian, Resident
from app.schemas.schemas import EventCreate, EventResponse, EventUpdate

logger = logging.getLogger(__name__)

router = APIRouter(tags=["events"])


# ---------------------------------------------------------------------------
# 헬퍼
# ---------------------------------------------------------------------------

async def _load_event(db: AsyncSession, event_id: str) -> Event:
    stmt = select(Event).filter(Event.id == event_id)
    result = await db.execute(stmt)
    event = result.scalar_one_or_none()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    return event


async def _guardian_resident_ids_in_facility(
    db: AsyncSession, user_id: str, facility_id: str
) -> set[str]:
    """가디언이 특정 시설에서 승인된 입소자 id 집합."""
    stmt = (
        select(Guardian.resident_id)
        .join(Resident, Resident.id == Guardian.resident_id)
        .filter(
            Guardian.user_id == user_id,
            Guardian.is_approved == True,  # noqa: E712
            Resident.facility_id == facility_id,
        )
    )
    result = await db.execute(stmt)
    return {row[0] for row in result.all()}


async def _is_operator(db: AsyncSession, user_id: str | None) -> bool:
    """user_id 의 is_operator 플래그 확인. role 은 staff/guardian 그대로 두고 별도 부울로
    운영자 권한을 표현하는 게 senior-album 패턴 (T-144/T-145)."""
    if not user_id:
        return False
    from app.models.models import User
    user = await db.get(User, user_id)
    return bool(user and user.is_operator)


async def _verify_event_read(
    current_user: dict, event: Event, db: AsyncSession
) -> None:
    """단건 read 권한 — 운영자 통과 | 직원(같은 시설) | 가디언(자기 입소자 OR 시설 전체 행사)."""
    role = current_user.get("role")
    user_id = current_user.get("user_id")

    # 운영자 우선 — role 과 무관하게 통과.
    if await _is_operator(db, user_id):
        return

    if role == "staff":
        await verify_facility_access(current_user, event.facility_id, db)
        return

    if role == "guardian":
        # 시설 전체 행사 (resident_id null) 는 자기 가디언십이 그 시설에 하나라도 있으면 허용.
        # 특정 입소자 이벤트는 그 입소자가 자기 가디언십 대상일 때만.
        approved_rids = await _guardian_resident_ids_in_facility(
            db, user_id, event.facility_id
        )
        if not approved_rids:
            raise HTTPException(status_code=403, detail="해당 시설 이벤트에 접근 권한이 없습니다.")
        if event.resident_id is None or event.resident_id in approved_rids:
            return

    raise HTTPException(status_code=403, detail="해당 이벤트에 접근 권한이 없습니다.")


async def _verify_event_write(
    current_user: dict, facility_id: str, db: AsyncSession
) -> None:
    """write 권한 — 운영자 통과 | 시설 직원 (해당 시설)."""
    role = current_user.get("role")
    user_id = current_user.get("user_id")
    if await _is_operator(db, user_id):
        return
    if role == "staff":
        await verify_facility_access(current_user, facility_id, db)
        return
    raise HTTPException(status_code=403, detail="이벤트는 시설 직원만 작성할 수 있습니다.")


async def _validate_resident_in_facility(
    db: AsyncSession, resident_id: str, facility_id: str
) -> None:
    """resident_id 가 해당 facility 의 입소자인지 확인 — 다른 시설 입소자 끼워넣기 방지."""
    stmt = select(Resident.id).filter(
        Resident.id == resident_id, Resident.facility_id == facility_id
    )
    result = await db.execute(stmt)
    if result.scalar_one_or_none() is None:
        raise HTTPException(
            status_code=400,
            detail="해당 시설의 입소자가 아닙니다.",
        )


# ---------------------------------------------------------------------------
# 라우트
# ---------------------------------------------------------------------------

@router.get(
    "/facilities/{facility_id}/events",
    response_model=list[EventResponse],
)
async def list_facility_events(
    facility_id: str,
    from_: Optional[datetime] = Query(None, alias="from"),
    to: Optional[datetime] = Query(None),
    resident_id: Optional[str] = Query(None),
    type: Optional[str] = Query(None),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """시설 단위 이벤트 목록 — start_at 오름차순.

    `from`/`to` 는 양쪽 inclusive (start_at 기준). 가디언은 자기 입소자 이벤트
    + 시설 전체 행사만 응답에 포함된다.
    """
    if from_ and to and from_ > to:
        raise HTTPException(status_code=400, detail="from 이 to 보다 클 수 없습니다.")

    role = current_user.get("role")
    user_id = current_user.get("user_id")

    # 권한 + 가디언 응답 필터링용 resident set 결정. 운영자는 role 과 무관하게
    # 우선 통과 (role="staff" + is_operator=True 인 경우 facility 일치 검증을
    # 우회해야 한다 — T-144/T-145 패턴).
    guardian_resident_ids: Optional[set[str]] = None
    if await _is_operator(db, user_id):
        pass  # 전 시설 read 허용
    elif role == "staff":
        await verify_facility_access(current_user, facility_id, db)
    elif role == "guardian":
        guardian_resident_ids = await _guardian_resident_ids_in_facility(
            db, user_id, facility_id
        )
        if not guardian_resident_ids:
            raise HTTPException(status_code=403, detail="해당 시설 이벤트에 접근 권한이 없습니다.")
    else:
        raise HTTPException(status_code=403, detail="해당 시설 이벤트에 접근 권한이 없습니다.")

    stmt = select(Event).filter(Event.facility_id == facility_id)
    if from_ is not None:
        stmt = stmt.filter(Event.start_at >= from_)
    if to is not None:
        stmt = stmt.filter(Event.start_at <= to)
    if resident_id is not None:
        stmt = stmt.filter(Event.resident_id == resident_id)
    if type is not None:
        stmt = stmt.filter(Event.type == type)

    if guardian_resident_ids is not None:
        # 가디언: 자기 입소자 이벤트 + 시설 전체 (resident_id IS NULL).
        stmt = stmt.filter(
            (Event.resident_id.is_(None))
            | (Event.resident_id.in_(guardian_resident_ids))
        )

    stmt = stmt.order_by(Event.start_at.asc()).limit(500)
    result = await db.execute(stmt)
    events = result.scalars().all()
    return [EventResponse.model_validate(ev) for ev in events]


@router.post(
    "/facilities/{facility_id}/events",
    response_model=EventResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_facility_event(
    facility_id: str,
    payload: EventCreate,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """이벤트 생성 — 직원만. resident_id 가 들어오면 시설 일치 검증."""
    await _verify_event_write(current_user, facility_id, db)

    if payload.end_at is not None and payload.end_at < payload.start_at:
        raise HTTPException(status_code=400, detail="end_at 이 start_at 보다 빠를 수 없습니다.")

    if payload.resident_id is not None:
        await _validate_resident_in_facility(db, payload.resident_id, facility_id)

    event = Event(
        id=str(uuid.uuid4()),
        facility_id=facility_id,
        resident_id=payload.resident_id,
        type=payload.type,
        title=payload.title,
        description=payload.description,
        start_at=payload.start_at,
        end_at=payload.end_at,
        all_day=payload.all_day,
        created_by=current_user["user_id"],
    )
    db.add(event)
    await db.commit()
    await db.refresh(event)
    return EventResponse.model_validate(event)


@router.get("/events/{event_id}", response_model=EventResponse)
async def get_event(
    event_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """이벤트 단건 조회 — read 권한 검사."""
    event = await _load_event(db, event_id)
    await _verify_event_read(current_user, event, db)
    return EventResponse.model_validate(event)


@router.patch("/events/{event_id}", response_model=EventResponse)
async def update_event(
    event_id: str,
    payload: EventUpdate,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """이벤트 부분 갱신 — write 권한 검사 (이벤트 facility 기준)."""
    event = await _load_event(db, event_id)
    await _verify_event_write(current_user, event.facility_id, db)

    update_fields = payload.model_dump(exclude_unset=True)

    # resident_id 시설 일치 검증 — 명시적으로 들어왔을 때만.
    if "resident_id" in update_fields and update_fields["resident_id"] is not None:
        await _validate_resident_in_facility(
            db, update_fields["resident_id"], event.facility_id
        )

    # start_at / end_at 일관성 — 둘 중 하나만 들어와도 합산해서 검증.
    new_start = update_fields.get("start_at", event.start_at)
    new_end = (
        update_fields["end_at"]
        if "end_at" in update_fields
        else event.end_at
    )
    if new_end is not None and new_end < new_start:
        raise HTTPException(status_code=400, detail="end_at 이 start_at 보다 빠를 수 없습니다.")

    for k, v in update_fields.items():
        setattr(event, k, v)

    await db.commit()
    await db.refresh(event)
    return EventResponse.model_validate(event)


@router.delete("/events/{event_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_event(
    event_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """이벤트 삭제 — write 권한 검사. hard delete (audit 미포함, MVP)."""
    event = await _load_event(db, event_id)
    await _verify_event_write(current_user, event.facility_id, db)
    await db.delete(event)
    await db.commit()
