"""
T-144: 운영자(`is_operator`) 어드민 — 전체 유저 관리.

기존 `/admin/legal-settings` 는 법무 KV/약관 본문 전용. 이 라우터는 운영자가
플랫폼 전체 유저를 가로질러 보고/조정하기 위함.

엔드포인트:
- GET /admin/users   — 목록 + 필터(role/facility_id/is_active) + 검색(이메일·이름) + 페이지네이션
- PATCH /admin/users/{user_id} — `is_active`/`is_admin`/`is_operator`/`facility_id` 부분 업데이트

설계:
- hard delete 미지원. User 에는 입소자/사진/동의/감사 로그가 FK 로 매달려 있어
  cascade 위험. 비활성화 토글로만 처리.
- 모든 변경 — `admin_audit` 으로 AdminAuditLog 에 기록 (action 어휘:
  `user_set_active`, `user_set_admin`, `user_set_operator`, `user_set_facility`).
  변경된 필드 1개당 1 row — 사후 추적 시 어떤 권한이 언제 토글됐는지 분리해 보기 쉬움.
- self-lockout 방지: 운영자가 자기 자신의 `is_operator` 를 False 로 끄거나
  `is_active` 를 False 로 끄는 시도는 400. 두 명 이상 운영자 환경에서는
  서로 강등 가능 — 단일 운영자 자해만 막음.
- `is_admin=True` 인데 `facility_id` 가 없으면 400. 시설장은 시설 소속이 필수.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import admin_audit
from app.core.database import get_db
from app.core.security import require_operator
from app.models.models import Facility, User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin", tags=["admin"])


# ---------------------------------------------------------------------------
# 응답/요청 스키마
# ---------------------------------------------------------------------------


class AdminUserOut(BaseModel):
    id: str
    email: str
    name: str
    role: str
    is_admin: bool
    is_operator: bool
    is_active: bool
    facility_id: Optional[str] = None
    facility_name: Optional[str] = None
    provider: Optional[str] = None
    phone: Optional[str] = None
    created_at: Optional[datetime] = None


class AdminUserListResponse(BaseModel):
    items: list[AdminUserOut]
    total: int
    page: int
    size: int


class AdminUserPatchRequest(BaseModel):
    """부분 업데이트 — 보낸 필드만 반영. 한 요청에 여러 필드 동시 가능."""

    is_active: Optional[bool] = None
    is_admin: Optional[bool] = None
    is_operator: Optional[bool] = None
    facility_id: Optional[str] = None  # 빈 문자열 "" → null 로 해석 (시설 detach)


# ---------------------------------------------------------------------------
# GET /admin/users
# ---------------------------------------------------------------------------


@router.get("/users", response_model=AdminUserListResponse)
async def list_users(
    role: Optional[str] = Query(None, description="staff | guardian"),
    facility_id: Optional[str] = Query(None),
    is_active: Optional[bool] = Query(None),
    q: Optional[str] = Query(None, description="이메일/이름 부분 일치 (대소문자 무시)"),
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    _operator: dict = Depends(require_operator),
    db: AsyncSession = Depends(get_db),
) -> AdminUserListResponse:
    """전체 유저 페이지네이션 목록 + facility_name 조인."""
    # User 와 Facility.name 을 LEFT JOIN — facility 미배정 유저(보호자 등) 도 보여야 함
    base = (
        select(User, Facility.name.label("facility_name"))
        .outerjoin(Facility, User.facility_id == Facility.id)
    )
    count_base = select(func.count(User.id))

    if role:
        base = base.where(User.role == role)
        count_base = count_base.where(User.role == role)
    if facility_id is not None:
        base = base.where(User.facility_id == facility_id)
        count_base = count_base.where(User.facility_id == facility_id)
    if is_active is not None:
        base = base.where(User.is_active == is_active)
        count_base = count_base.where(User.is_active == is_active)
    if q:
        like = f"%{q.lower()}%"
        cond = or_(func.lower(User.email).like(like), func.lower(User.name).like(like))
        base = base.where(cond)
        count_base = count_base.where(cond)

    total = (await db.execute(count_base)).scalar_one()

    base = base.order_by(User.created_at.desc()).offset((page - 1) * size).limit(size)
    rows = (await db.execute(base)).all()

    items = [
        AdminUserOut(
            id=u.id,
            email=u.email,
            name=u.name,
            role=u.role,
            is_admin=bool(u.is_admin),
            is_operator=bool(u.is_operator),
            is_active=bool(u.is_active),
            facility_id=u.facility_id,
            facility_name=fname,
            provider=u.provider,
            phone=u.phone,
            created_at=u.created_at,
        )
        for u, fname in rows
    ]
    return AdminUserListResponse(items=items, total=total, page=page, size=size)


# ---------------------------------------------------------------------------
# PATCH /admin/users/{user_id}
# ---------------------------------------------------------------------------


def _user_to_admin_out(user: User, facility_name: Optional[str]) -> AdminUserOut:
    return AdminUserOut(
        id=user.id,
        email=user.email,
        name=user.name,
        role=user.role,
        is_admin=bool(user.is_admin),
        is_operator=bool(user.is_operator),
        is_active=bool(user.is_active),
        facility_id=user.facility_id,
        facility_name=facility_name,
        provider=user.provider,
        phone=user.phone,
        created_at=user.created_at,
    )


@router.patch("/users/{user_id}", response_model=AdminUserOut)
async def patch_user(
    user_id: str,
    body: AdminUserPatchRequest,
    operator: dict = Depends(require_operator),
    db: AsyncSession = Depends(get_db),
) -> AdminUserOut:
    """운영자가 다른 유저의 권한/활성/시설을 수정. 변경된 필드만 audit 에 기록."""
    target = await db.get(User, user_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="유저를 찾을 수 없습니다.")

    operator_id = operator.get("user_id")
    is_self = operator_id == target.id

    # 빈 문자열 → null normalize (프론트에서 "시설 해제" 의미로 빈 문자열 보냄)
    new_facility_id: Optional[str] = body.facility_id
    if new_facility_id == "":
        new_facility_id = None

    # ---- 검증 ----
    if is_self and body.is_operator is False:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="자기 자신의 운영자 권한은 해제할 수 없습니다.",
        )
    if is_self and body.is_active is False:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="자기 자신의 계정은 비활성화할 수 없습니다.",
        )

    # is_admin=True 로 켜는데 facility_id 가 비어있으면 (현재도, 변경 후에도) 400
    will_be_admin = body.is_admin if body.is_admin is not None else target.is_admin
    will_have_facility = (
        new_facility_id if body.facility_id is not None else target.facility_id
    )
    if will_be_admin and not will_have_facility:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="시설 관리자(is_admin) 는 소속 시설(facility_id) 이 필요합니다.",
        )

    # facility_id 가 실존하는지 확인
    if body.facility_id is not None and new_facility_id is not None:
        fac = await db.get(Facility, new_facility_id)
        if fac is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="시설을 찾을 수 없습니다.")

    # ---- 변경 적용 + audit (필드별 1 row) ----
    changes: list[tuple[str, str, str]] = []  # (action, before, after)
    if body.is_active is not None and body.is_active != target.is_active:
        changes.append(("user_set_active", str(target.is_active), str(body.is_active)))
        target.is_active = body.is_active
    if body.is_admin is not None and body.is_admin != target.is_admin:
        changes.append(("user_set_admin", str(target.is_admin), str(body.is_admin)))
        target.is_admin = body.is_admin
    if body.is_operator is not None and body.is_operator != target.is_operator:
        changes.append(("user_set_operator", str(target.is_operator), str(body.is_operator)))
        target.is_operator = body.is_operator
    if body.facility_id is not None and new_facility_id != target.facility_id:
        before = target.facility_id or ""
        changes.append(("user_set_facility", before, new_facility_id or ""))
        target.facility_id = new_facility_id

    for action, before, after in changes:
        admin_audit(
            db,
            action=action,
            performed_by=operator_id,
            target_type="user",
            target_id=target.id,
            facility_id=target.facility_id,
            detail=f"{before} -> {after}",
        )

    if changes:
        await db.commit()
        await db.refresh(target)

    # facility_name 조회 (변경 후)
    facility_name: Optional[str] = None
    if target.facility_id:
        fac = await db.get(Facility, target.facility_id)
        facility_name = fac.name if fac else None

    return _user_to_admin_out(target, facility_name)
