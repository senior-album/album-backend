"""T-056: 시설 직원 가입 승인 API.

시설장 (또는 `facility:staff:approve` 위임 받은 직원) 이 자기 시설 신규 staff
가입 요청을 승인/거부.

엔드포인트:
- GET    /facility-approvals/pending          : 자기 시설 미승인·미거부 staff 목록
- POST   /facility-approvals/{user_id}/approve : 승인
- POST   /facility-approvals/{user_id}/reject  : 거부 (옵셔널 reason). soft delete

거부는 영구 — `is_rejected=True` + `is_active=False` 동시 박아 같은 email/phone 으로
재신청 시 UNIQUE 제약이 차단. 운영자가 unreject 가 필요하면 운영자 어드민 영역
에서 직접 DB 또는 별도 API (현재 없음).
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import admin_audit
from app.core.database import get_db
from app.core.permissions import FACILITY_STAFF_APPROVE, has_permission
from app.core.security import get_current_user
from app.models.models import User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/facility-approvals", tags=["facility-approvals"])


# ---- 스키마 ----


class PendingStaffOut(BaseModel):
    user_id: str
    email: str
    name: str
    phone: Optional[str] = None
    created_at: Optional[datetime] = None


class PendingStaffListResponse(BaseModel):
    items: list[PendingStaffOut]


class RejectRequest(BaseModel):
    # 옵셔널 — 빈 문자열 / None 허용. 길이만 제한.
    reason: Optional[str] = Field(default=None, max_length=500)


class StaffApprovalActionResponse(BaseModel):
    user_id: str
    is_staff_approved: bool
    is_rejected: bool


# ---- 가드 — 시설장 또는 facility:staff:approve 위임 ----


async def _require_staff_approver(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> User:
    user = await db.get(User, current_user.get("user_id"))
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="계정이 비활성화되었거나 존재하지 않습니다.",
        )
    if not user.facility_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="시설에 소속되지 않은 사용자입니다.",
        )
    if not await has_permission(db, user, FACILITY_STAFF_APPROVE):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="직원 승인 권한이 없습니다.",
        )
    return user


# ---- 엔드포인트 ----


@router.get("/pending", response_model=PendingStaffListResponse)
async def list_pending_staff(
    actor: User = Depends(_require_staff_approver),
    db: AsyncSession = Depends(get_db),
) -> PendingStaffListResponse:
    """자기 시설의 미승인·미거부 직원 목록. 거부된 행은 제외."""
    stmt = (
        select(User)
        .where(
            User.facility_id == actor.facility_id,
            User.role == "staff",
            User.is_staff_approved == False,  # noqa: E712
            User.is_rejected == False,  # noqa: E712
            User.is_active == True,  # noqa: E712
        )
        .order_by(User.created_at.desc())
    )
    rows = (await db.execute(stmt)).scalars().all()
    return PendingStaffListResponse(items=[
        PendingStaffOut(
            user_id=u.id,
            email=u.email,
            name=u.name,
            phone=u.phone,
            created_at=u.created_at,
        )
        for u in rows
    ])


def _verify_target_in_facility(target: Optional[User], actor: User) -> User:
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="대상 직원을 찾을 수 없습니다.")
    if target.facility_id != actor.facility_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="다른 시설 직원입니다.",
        )
    if target.role != "staff":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="대상이 직원이 아닙니다.")
    return target


@router.post(
    "/{user_id}/approve",
    response_model=StaffApprovalActionResponse,
)
async def approve_staff(
    user_id: str,
    actor: User = Depends(_require_staff_approver),
    db: AsyncSession = Depends(get_db),
) -> StaffApprovalActionResponse:
    target = _verify_target_in_facility(await db.get(User, user_id), actor)

    if target.is_rejected:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="이미 거부된 계정입니다.")
    if target.is_staff_approved:
        # 멱등 — 이미 승인됨. audit 추가 안 함.
        return StaffApprovalActionResponse(
            user_id=target.id,
            is_staff_approved=True,
            is_rejected=False,
        )

    target.is_staff_approved = True
    target.staff_approved_by = actor.id
    target.staff_approved_at = datetime.utcnow()

    admin_audit(
        db,
        action="staff_approve",
        performed_by=actor.id,
        target_type="user",
        target_id=target.id,
        facility_id=actor.facility_id,
    )
    await db.commit()
    return StaffApprovalActionResponse(
        user_id=target.id, is_staff_approved=True, is_rejected=False
    )


@router.post(
    "/{user_id}/reject",
    response_model=StaffApprovalActionResponse,
)
async def reject_staff(
    user_id: str,
    body: RejectRequest,
    actor: User = Depends(_require_staff_approver),
    db: AsyncSession = Depends(get_db),
) -> StaffApprovalActionResponse:
    """
    거부 — soft delete. is_rejected=True + is_active=False 박아 로그인·재신청
    모두 차단. UNIQUE(email/phone) 가 같은 정보 재등록 자동 차단.
    """
    target = _verify_target_in_facility(await db.get(User, user_id), actor)

    if target.is_staff_approved:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="이미 승인된 계정은 거부할 수 없습니다.")
    if target.is_rejected:
        # 멱등 — 이미 거부. audit 추가 안 함.
        return StaffApprovalActionResponse(
            user_id=target.id, is_staff_approved=False, is_rejected=True
        )

    target.is_rejected = True
    target.is_active = False
    target.staff_rejected_by = actor.id
    target.staff_rejected_at = datetime.utcnow()
    target.staff_reject_reason = (body.reason or "").strip() or None

    admin_audit(
        db,
        action="staff_reject",
        performed_by=actor.id,
        target_type="user",
        target_id=target.id,
        facility_id=actor.facility_id,
        detail=target.staff_reject_reason,
    )
    await db.commit()
    return StaffApprovalActionResponse(
        user_id=target.id, is_staff_approved=False, is_rejected=True
    )
