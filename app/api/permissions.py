"""T-150: 시설 직원 메뉴 권한 위임 API.

시설장(`is_admin=True`) 이 같은 시설 직원에게 메뉴 단위 권한을 부여/회수.

엔드포인트:
- GET    /facility-permissions/staff           : 자기 시설 직원별 보유 키 목록
- GET    /facility-permissions/keys            : 위임 가능한 키 카탈로그 (UI 가 토글 렌더링용)
- POST   /facility-permissions/grant           : {user_id, permission_key} 부여
- DELETE /facility-permissions/{user_id}/{key} : 회수

자동 통과 규칙(`has_permission` 참조):
- `is_operator=True` — 모든 키, 모든 시설
- `is_admin=True` — 자기 시설의 `facility:*` 키
양쪽 모두 UserPermission 행 없이 통과하므로 GET staff 응답에서 별도 표기.
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
from app.core.permissions import ALL_PERMISSION_KEYS, is_known_permission_key
from app.core.security import get_current_user
from app.models.models import User, UserPermission

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/facility-permissions", tags=["permissions"])


# ---- 스키마 ----


class PermissionKeyOut(BaseModel):
    key: str
    description: str


class StaffPermissionRow(BaseModel):
    user_id: str
    name: str
    email: str
    is_admin: bool
    permission_keys: list[str]
    # 시설장 본인이거나 운영자라 모든 키를 행 없이 자동 통과하는 경우 True.
    # UI 는 이 경우 토글을 비활성화하고 "자동 부여" 표시.
    has_all_via_role: bool


class StaffPermissionListResponse(BaseModel):
    items: list[StaffPermissionRow]


class GrantRequest(BaseModel):
    user_id: str = Field(min_length=1)
    permission_key: str = Field(min_length=1, max_length=64)


class GrantResponse(BaseModel):
    user_id: str
    permission_key: str
    granted_at: datetime


class MyPermissionsResponse(BaseModel):
    """
    현재 로그인 유저가 보유한 메뉴 권한.

    `permission_keys` 는 명시적으로 부여된 행만 포함. 시설장(`is_admin`) /
    운영자(`is_operator`) 는 키 행이 없어도 자동 통과하므로 프론트는
    `has_all_via_role` 도 함께 봐야 한다.
    """
    permission_keys: list[str]
    has_all_via_role: bool


# ---- 공통 가드 ----


async def _require_facility_admin(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    호출자 = 시설장 검증.

    is_admin + is_active + facility_id 보유. 운영자(is_operator) 도 동일 API 를
    쓰고 싶다면 별도 엔드포인트가 필요하지만 본 이슈는 "시설장이 자기 시설
    직원에게 위임" 한정 — 운영자 채널은 향후 별도.
    """
    user = await db.get(User, current_user.get("user_id"))
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="계정이 비활성화되었거나 존재하지 않습니다.",
        )
    if not user.is_admin or not user.facility_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="시설 관리자 권한이 필요합니다.",
        )
    return user


# ---- 엔드포인트 ----


_KEY_DESCRIPTIONS: dict[str, str] = {
    "facility:stats:view": "시설 사용 지표 그래프 페이지 조회",
}


@router.get("/keys", response_model=list[PermissionKeyOut])
async def list_permission_keys(
    _: User = Depends(_require_facility_admin),
) -> list[PermissionKeyOut]:
    """위임 가능한 키 카탈로그. 시설장 UI 가 토글 컬럼 렌더링용으로 사용."""
    return [
        PermissionKeyOut(key=k, description=_KEY_DESCRIPTIONS.get(k, k))
        for k in sorted(ALL_PERMISSION_KEYS)
    ]


@router.get("/me", response_model=MyPermissionsResponse)
async def my_permissions(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> MyPermissionsResponse:
    """
    현재 유저 본인이 보유한 메뉴 권한.

    프론트엔드 useFacilityPermission hook 이 메뉴 가시성 결정용으로 호출.
    별도 시설장 권한 불요 — 누구나 자기 권한 조회는 가능.
    """
    user = await db.get(User, current_user.get("user_id"))
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="계정이 비활성화되었거나 존재하지 않습니다.",
        )

    rows = (
        await db.execute(
            select(UserPermission.permission_key).where(UserPermission.user_id == user.id)
        )
    ).all()
    keys = sorted({k for (k,) in rows})

    has_all = bool(user.is_operator) or (bool(user.is_admin) and bool(user.facility_id))
    return MyPermissionsResponse(permission_keys=keys, has_all_via_role=has_all)


@router.get("/staff", response_model=StaffPermissionListResponse)
async def list_staff_permissions(
    admin_user: User = Depends(_require_facility_admin),
    db: AsyncSession = Depends(get_db),
) -> StaffPermissionListResponse:
    """자기 시설 직원별 보유 키 목록."""
    stmt = (
        select(User)
        .where(
            User.facility_id == admin_user.facility_id,
            User.role == "staff",
            User.is_active == True,  # noqa: E712
        )
        .order_by(User.name)
    )
    staff_rows = (await db.execute(stmt)).scalars().all()

    staff_ids = [s.id for s in staff_rows]
    perm_map: dict[str, list[str]] = {sid: [] for sid in staff_ids}
    if staff_ids:
        perm_stmt = select(UserPermission.user_id, UserPermission.permission_key).where(
            UserPermission.user_id.in_(staff_ids)
        )
        for uid, key in (await db.execute(perm_stmt)).all():
            perm_map[uid].append(key)

    items = []
    for s in staff_rows:
        auto = s.is_admin or s.is_operator
        items.append(
            StaffPermissionRow(
                user_id=s.id,
                name=s.name,
                email=s.email,
                is_admin=bool(s.is_admin),
                permission_keys=sorted(perm_map.get(s.id, [])),
                has_all_via_role=auto,
            )
        )
    return StaffPermissionListResponse(items=items)


@router.post("/grant", response_model=GrantResponse, status_code=status.HTTP_201_CREATED)
async def grant_permission(
    body: GrantRequest,
    admin_user: User = Depends(_require_facility_admin),
    db: AsyncSession = Depends(get_db),
) -> GrantResponse:
    """직원에게 권한 부여. 같은 시설 + 카탈로그 키 + 활성 직원만 허용."""
    if not is_known_permission_key(body.permission_key):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"알 수 없는 권한 키: {body.permission_key}",
        )

    target = await db.get(User, body.user_id)
    if not target or not target.is_active:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="대상 유저를 찾을 수 없습니다.")
    if target.facility_id != admin_user.facility_id:
        # 다른 시설 직원에게 부여 시도 — 존재 여부 노출 회피하려 404 대신 403.
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="다른 시설 소속 유저에게 부여할 수 없습니다.",
        )

    existing_stmt = select(UserPermission).where(
        UserPermission.user_id == target.id,
        UserPermission.permission_key == body.permission_key,
    )
    existing: Optional[UserPermission] = (await db.execute(existing_stmt)).scalar_one_or_none()
    if existing is not None:
        # 멱등 — 이미 부여돼 있으면 기존 행 그대로 응답. audit 도 추가하지 않음.
        return GrantResponse(
            user_id=existing.user_id,
            permission_key=existing.permission_key,
            granted_at=existing.granted_at,
        )

    row = UserPermission(
        user_id=target.id,
        permission_key=body.permission_key,
        granted_by=admin_user.id,
        granted_at=datetime.utcnow(),
    )
    db.add(row)

    admin_audit(
        db,
        action="permission_grant",
        performed_by=admin_user.id,
        target_type="user",
        target_id=target.id,
        facility_id=admin_user.facility_id,
        detail=body.permission_key,
    )

    await db.commit()
    await db.refresh(row)
    return GrantResponse(
        user_id=row.user_id,
        permission_key=row.permission_key,
        granted_at=row.granted_at,
    )


@router.delete(
    "/{user_id}/{permission_key:path}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def revoke_permission(
    user_id: str,
    permission_key: str,
    admin_user: User = Depends(_require_facility_admin),
    db: AsyncSession = Depends(get_db),
):
    """직원의 권한 회수. 같은 시설 + 행 존재할 때만. 멱등하지 않음 (없으면 404)."""
    target = await db.get(User, user_id)
    if not target:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="대상 유저를 찾을 수 없습니다.")
    if target.facility_id != admin_user.facility_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="다른 시설 소속 유저의 권한을 회수할 수 없습니다.",
        )

    stmt = select(UserPermission).where(
        UserPermission.user_id == target.id,
        UserPermission.permission_key == permission_key,
    )
    row = (await db.execute(stmt)).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="해당 권한이 존재하지 않습니다.")

    await db.delete(row)
    admin_audit(
        db,
        action="permission_revoke",
        performed_by=admin_user.id,
        target_type="user",
        target_id=target.id,
        facility_id=admin_user.facility_id,
        detail=permission_key,
    )
    await db.commit()
