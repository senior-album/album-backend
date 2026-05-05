"""
알림 조회/읽음 표시 API.

T-149 에서 신설 — 가입 회원 초대(in_app) 가 들어왔을 때 보호자가 알림 화면에서
확인할 수 있어야 한다. 기존 NotificationService 가 레코드를 만들기는 했으나
사용자에게 노출하는 엔드포인트가 없어 데이터가 사실상 묻혀 있었다.

본인 알림만 조회/수정 가능 (보안 게이트는 user_id == current_user.user_id).
"""

import logging
from datetime import datetime
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy import select, desc, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.models import Notification
from app.schemas.schemas import NotificationListResponse, NotificationResponse

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/notifications", tags=["notifications"])


@router.get("/me", response_model=NotificationListResponse)
async def get_my_notifications(
    limit: int = 50,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """내 알림 목록 + 미읽음 카운트.

    `limit` 은 클라이언트가 무한 스크롤로 키울 수 있도록 노출, 기본 50.
    """
    if limit <= 0 or limit > 200:
        raise HTTPException(status_code=400, detail="limit 은 1~200 범위여야 합니다.")

    user_id = current_user["user_id"]

    list_stmt = (
        select(Notification)
        .filter(Notification.user_id == user_id)
        .order_by(desc(Notification.created_at))
        .limit(limit)
    )
    list_result = await db.execute(list_stmt)
    items = list_result.scalars().all()

    unread_stmt = select(func.count()).select_from(Notification).filter(
        Notification.user_id == user_id,
        Notification.is_read == False,
    )
    unread_result = await db.execute(unread_stmt)
    unread_count = int(unread_result.scalar() or 0)

    return NotificationListResponse(
        items=[NotificationResponse.model_validate(n) for n in items],
        unread_count=unread_count,
    )


@router.post("/{notification_id}/read")
async def mark_notification_read(
    notification_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """알림 읽음 표시 (본인 것만)."""
    stmt = select(Notification).filter(Notification.id == notification_id)
    result = await db.execute(stmt)
    notif = result.scalar_one_or_none()
    if notif is None:
        raise HTTPException(status_code=404, detail="알림을 찾을 수 없습니다.")
    if notif.user_id != current_user["user_id"]:
        raise HTTPException(status_code=403, detail="본인의 알림만 처리할 수 있습니다.")

    if not notif.is_read:
        notif.is_read = True
        notif.read_at = datetime.utcnow()
        await db.commit()

    return {"id": notif.id, "is_read": True}


@router.post("/me/read-all")
async def mark_all_notifications_read(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """내 모든 미읽음 알림을 한 번에 읽음 처리."""
    stmt = select(Notification).filter(
        Notification.user_id == current_user["user_id"],
        Notification.is_read == False,
    )
    result = await db.execute(stmt)
    notifs = result.scalars().all()

    now = datetime.utcnow()
    for n in notifs:
        n.is_read = True
        n.read_at = now
    await db.commit()

    return {"updated": len(notifs)}
