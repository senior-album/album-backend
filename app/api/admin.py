"""
T-144 / T-145 / T-146: 운영자(`is_operator`) 어드민 — 유저·시설·보호자 모니터링.

기존 `/admin/legal-settings` 는 법무 KV/약관 본문 전용. 이 라우터는 운영자가
플랫폼 전체 유저·시설·보호자 승인 흐름을 가로질러 보고/조정하기 위함.

엔드포인트:
- GET   /admin/users               — 유저 목록 + 필터/검색/페이지네이션 (T-144)
- PATCH /admin/users/{user_id}     — 권한·활성·시설 부분 업데이트 (T-144)
- GET   /admin/facilities          — 시설 목록 + 직원/입소자/사진 수 (T-145)
- POST  /admin/facilities          — 시설 생성 (코드 자동 발급) (T-145)
- PATCH /admin/facilities/{fac_id} — 시설 정보 수정 (코드 변경 불가) (T-145)
- GET   /admin/guardians           — 보호자 요청 전체 시설 across 모니터링 (T-146)
- GET   /admin/photo-jobs          — 사진 처리 큐 모니터링 (T-147)
- POST  /admin/photo-jobs/{id}/retry — 실패한 작업 재큐 (T-147)

설계:
- hard delete 미지원. User/Facility 에는 입소자/사진/동의/감사 로그가 FK 로
  매달려 있어 cascade 위험. 비활성화 토글로만 처리 (시설은 별도 비활성 컬럼이
  없어 일단 PATCH 미허용 — 필요 시 추후 `is_active` 컬럼 추가).
- 모든 변경 — `admin_audit` 으로 AdminAuditLog 에 기록.
  유저: `user_set_active|admin|operator|facility` (필드별 1 row)
  시설: `facility_create`, `facility_update` (변경 필드 detail 에 통합 기록)
- self-lockout 방지: 운영자가 자기 자신의 `is_operator` 를 False 로 끄거나
  `is_active` 를 False 로 끄는 시도는 400.
- `is_admin=True` 인데 `facility_id` 가 없으면 400. 시설장은 시설 소속이 필수.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import admin_audit
from app.core.database import get_db
from app.core.security import require_operator
from app.models.models import Facility, Guardian, Photo, PhotoProcessingJob, Resident, User

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


# ===========================================================================
# T-145: 시설 관리
# ===========================================================================


class AdminFacilityOut(BaseModel):
    id: str
    code: str
    name: str
    address: str
    phone: str
    staff_count: int
    resident_count: int
    photo_count: int
    created_at: Optional[datetime] = None


class AdminFacilityListResponse(BaseModel):
    items: list[AdminFacilityOut]
    total: int
    page: int
    size: int


class AdminFacilityCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    address: str = Field(min_length=1, max_length=500)
    phone: str = Field(default="", max_length=20)
    code: Optional[str] = Field(default=None, max_length=20)


class AdminFacilityPatch(BaseModel):
    """name/address/phone 만 수정 가능. code 는 시설 식별자라 변경 금지."""

    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    address: Optional[str] = Field(default=None, min_length=1, max_length=500)
    phone: Optional[str] = Field(default=None, max_length=20)


def _generate_facility_code() -> str:
    return f"FAC-{uuid.uuid4().hex[:6].upper()}"


@router.get("/facilities", response_model=AdminFacilityListResponse)
async def list_facilities(
    q: Optional[str] = Query(None, description="이름/주소 부분 일치 (대소문자 무시)"),
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    _operator: dict = Depends(require_operator),
    db: AsyncSession = Depends(get_db),
) -> AdminFacilityListResponse:
    """시설 목록 + 직원/입소자/사진 수.

    카운트는 시설별 별도 집계 쿼리로 묶어서 N+1 방지. launch target 규모(시설 1~수십)
    에서는 한 번에 전부 끌어와도 충분.
    """
    base = select(Facility)
    count_base = select(func.count(Facility.id))

    if q:
        like = f"%{q.lower()}%"
        cond = or_(func.lower(Facility.name).like(like), func.lower(Facility.address).like(like))
        base = base.where(cond)
        count_base = count_base.where(cond)

    total = (await db.execute(count_base)).scalar_one()

    base = base.order_by(Facility.created_at.desc()).offset((page - 1) * size).limit(size)
    facilities = list((await db.execute(base)).scalars().all())

    facility_ids = [f.id for f in facilities]
    counts: dict[str, dict[str, int]] = {fid: {"staff": 0, "resident": 0, "photo": 0} for fid in facility_ids}

    if facility_ids:
        # 직원 수 (시설 소속이면서 role=staff. 보호자는 facility_id 가 채워질 수 있어도 직원이 아님)
        staff_rows = (
            await db.execute(
                select(User.facility_id, func.count(User.id))
                .where(User.facility_id.in_(facility_ids), User.role == "staff")
                .group_by(User.facility_id)
            )
        ).all()
        for fid, cnt in staff_rows:
            counts[fid]["staff"] = cnt

        resident_rows = (
            await db.execute(
                select(Resident.facility_id, func.count(Resident.id))
                .where(Resident.facility_id.in_(facility_ids), Resident.is_active == True)
                .group_by(Resident.facility_id)
            )
        ).all()
        for fid, cnt in resident_rows:
            counts[fid]["resident"] = cnt

        photo_rows = (
            await db.execute(
                select(Photo.facility_id, func.count(Photo.id))
                .where(Photo.facility_id.in_(facility_ids))
                .group_by(Photo.facility_id)
            )
        ).all()
        for fid, cnt in photo_rows:
            counts[fid]["photo"] = cnt

    items = [
        AdminFacilityOut(
            id=f.id,
            code=f.code,
            name=f.name,
            address=f.address,
            phone=f.phone or "",
            staff_count=counts.get(f.id, {}).get("staff", 0),
            resident_count=counts.get(f.id, {}).get("resident", 0),
            photo_count=counts.get(f.id, {}).get("photo", 0),
            created_at=f.created_at,
        )
        for f in facilities
    ]
    return AdminFacilityListResponse(items=items, total=total, page=page, size=size)


@router.post("/facilities", response_model=AdminFacilityOut, status_code=status.HTTP_201_CREATED)
async def create_facility(
    body: AdminFacilityCreate,
    operator: dict = Depends(require_operator),
    db: AsyncSession = Depends(get_db),
) -> AdminFacilityOut:
    """신규 시설 생성. code 미지정 시 자동 발급. code 중복 시 409."""
    code = (body.code or _generate_facility_code()).strip()
    existing = (await db.execute(select(Facility).where(Facility.code == code))).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"시설 코드 '{code}' 가 이미 사용 중입니다.",
        )

    fac = Facility(
        id=str(uuid.uuid4()),
        code=code,
        name=body.name.strip(),
        address=body.address.strip(),
        phone=(body.phone or "").strip(),
    )
    db.add(fac)

    admin_audit(
        db,
        action="facility_create",
        performed_by=operator.get("user_id"),
        target_type="facility",
        target_id=fac.id,
        facility_id=fac.id,
        detail=f"code={fac.code}, name={fac.name}",
    )
    await db.commit()
    await db.refresh(fac)

    return AdminFacilityOut(
        id=fac.id,
        code=fac.code,
        name=fac.name,
        address=fac.address,
        phone=fac.phone or "",
        staff_count=0,
        resident_count=0,
        photo_count=0,
        created_at=fac.created_at,
    )


@router.patch("/facilities/{facility_id}", response_model=AdminFacilityOut)
async def patch_facility(
    facility_id: str,
    body: AdminFacilityPatch,
    operator: dict = Depends(require_operator),
    db: AsyncSession = Depends(get_db),
) -> AdminFacilityOut:
    """시설 정보(name/address/phone) 부분 업데이트. 변경 사항을 audit detail 에 통합 기록."""
    fac = await db.get(Facility, facility_id)
    if fac is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="시설을 찾을 수 없습니다.")

    diffs: list[str] = []
    if body.name is not None and body.name.strip() != fac.name:
        diffs.append(f"name: {fac.name!r} -> {body.name.strip()!r}")
        fac.name = body.name.strip()
    if body.address is not None and body.address.strip() != fac.address:
        diffs.append(f"address: {fac.address!r} -> {body.address.strip()!r}")
        fac.address = body.address.strip()
    if body.phone is not None and (body.phone or "").strip() != (fac.phone or ""):
        diffs.append(f"phone: {fac.phone or ''!r} -> {(body.phone or '').strip()!r}")
        fac.phone = (body.phone or "").strip()

    if diffs:
        admin_audit(
            db,
            action="facility_update",
            performed_by=operator.get("user_id"),
            target_type="facility",
            target_id=fac.id,
            facility_id=fac.id,
            detail="; ".join(diffs),
        )
        await db.commit()
        await db.refresh(fac)

    # 카운트 재계산 (PATCH 응답에서도 일관 표시)
    staff_cnt = (
        await db.execute(
            select(func.count(User.id)).where(User.facility_id == fac.id, User.role == "staff")
        )
    ).scalar_one()
    resident_cnt = (
        await db.execute(
            select(func.count(Resident.id)).where(
                Resident.facility_id == fac.id, Resident.is_active == True
            )
        )
    ).scalar_one()
    photo_cnt = (
        await db.execute(select(func.count(Photo.id)).where(Photo.facility_id == fac.id))
    ).scalar_one()

    return AdminFacilityOut(
        id=fac.id,
        code=fac.code,
        name=fac.name,
        address=fac.address,
        phone=fac.phone or "",
        staff_count=staff_cnt,
        resident_count=resident_cnt,
        photo_count=photo_cnt,
        created_at=fac.created_at,
    )


# ===========================================================================
# T-146: 보호자 승인 현황 (전체 시설 across)
# ===========================================================================


class AdminGuardianOut(BaseModel):
    id: str
    user_id: str
    user_name: str
    user_email: str
    user_phone: Optional[str] = None
    facility_id: Optional[str] = None
    facility_name: Optional[str] = None
    resident_id: Optional[str] = None
    resident_name: Optional[str] = None
    relationship_type: Optional[str] = None
    request_message: Optional[str] = None
    is_approved: bool
    is_rejected: bool
    reject_reason: Optional[str] = None
    approved_at: Optional[datetime] = None
    created_at: Optional[datetime] = None


class AdminGuardianListResponse(BaseModel):
    items: list[AdminGuardianOut]
    total: int
    page: int
    size: int


@router.get("/guardians", response_model=AdminGuardianListResponse)
async def list_guardians(
    facility_id: Optional[str] = Query(None),
    state: Optional[str] = Query(None, description="pending | approved | rejected"),
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    _operator: dict = Depends(require_operator),
    db: AsyncSession = Depends(get_db),
) -> AdminGuardianListResponse:
    """보호자 요청 전체 시설 across 모니터링 — 운영자가 승인 적체/반려 패턴 조감.

    상태(state) 필터:
    - pending : is_approved=False AND is_rejected=False
    - approved: is_approved=True
    - rejected: is_rejected=True
    """
    base = (
        select(Guardian, User, Resident, Facility)
        .join(User, Guardian.user_id == User.id)
        .outerjoin(Resident, Guardian.resident_id == Resident.id)
        .outerjoin(Facility, Guardian.facility_id == Facility.id)
    )
    count_base = select(func.count(Guardian.id))

    if facility_id is not None:
        base = base.where(Guardian.facility_id == facility_id)
        count_base = count_base.where(Guardian.facility_id == facility_id)

    if state == "pending":
        cond = (Guardian.is_approved == False) & (Guardian.is_rejected == False)
        base = base.where(cond)
        count_base = count_base.where(cond)
    elif state == "approved":
        base = base.where(Guardian.is_approved == True)
        count_base = count_base.where(Guardian.is_approved == True)
    elif state == "rejected":
        base = base.where(Guardian.is_rejected == True)
        count_base = count_base.where(Guardian.is_rejected == True)
    elif state is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="state 는 pending | approved | rejected 중 하나여야 합니다.",
        )

    total = (await db.execute(count_base)).scalar_one()

    base = base.order_by(Guardian.created_at.desc()).offset((page - 1) * size).limit(size)
    rows = (await db.execute(base)).all()

    items = [
        AdminGuardianOut(
            id=g.id,
            user_id=g.user_id,
            user_name=u.name,
            user_email=u.email,
            user_phone=u.phone,
            facility_id=g.facility_id,
            facility_name=fac.name if fac else None,
            resident_id=g.resident_id,
            resident_name=res.name if res else None,
            relationship_type=g.relationship_type,
            request_message=g.request_message,
            is_approved=bool(g.is_approved),
            is_rejected=bool(g.is_rejected),
            reject_reason=g.reject_reason,
            approved_at=g.approved_at,
            created_at=g.created_at,
        )
        for g, u, res, fac in rows
    ]
    return AdminGuardianListResponse(items=items, total=total, page=page, size=size)


# ===========================================================================
# T-147: 사진 처리 큐 모니터링
# ===========================================================================


class AdminPhotoJobOut(BaseModel):
    id: str
    photo_id: str
    facility_id: str
    facility_name: Optional[str] = None
    status: str
    error_message: Optional[str] = None
    retry_count: int
    max_retries: int
    photo_processing_status: Optional[str] = None
    photo_thumbnail_url: Optional[str] = None
    created_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


class AdminPhotoJobListResponse(BaseModel):
    items: list[AdminPhotoJobOut]
    total: int
    page: int
    size: int


@router.get("/photo-jobs", response_model=AdminPhotoJobListResponse)
async def list_photo_jobs(
    job_status: Optional[str] = Query(
        None,
        alias="status",
        description="pending | processing | completed | failed",
    ),
    facility_id: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    size: int = Query(50, ge=1, le=200),
    _operator: dict = Depends(require_operator),
    db: AsyncSession = Depends(get_db),
) -> AdminPhotoJobListResponse:
    """PhotoProcessingJob 목록 — 큐 적체/실패 패턴 조감.

    `status` (쿼리 파라미터) 는 FastAPI 키워드 충돌 회피로 alias 사용.
    """
    base = (
        select(PhotoProcessingJob, Photo, Facility.name)
        .outerjoin(Photo, PhotoProcessingJob.photo_id == Photo.id)
        .outerjoin(Facility, PhotoProcessingJob.facility_id == Facility.id)
    )
    count_base = select(func.count(PhotoProcessingJob.id))

    if job_status:
        if job_status not in {"pending", "processing", "completed", "failed"}:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="status 는 pending|processing|completed|failed 중 하나여야 합니다.",
            )
        base = base.where(PhotoProcessingJob.status == job_status)
        count_base = count_base.where(PhotoProcessingJob.status == job_status)

    if facility_id is not None:
        base = base.where(PhotoProcessingJob.facility_id == facility_id)
        count_base = count_base.where(PhotoProcessingJob.facility_id == facility_id)

    total = (await db.execute(count_base)).scalar_one()

    base = base.order_by(PhotoProcessingJob.created_at.desc()).offset((page - 1) * size).limit(size)
    rows = (await db.execute(base)).all()

    items = [
        AdminPhotoJobOut(
            id=job.id,
            photo_id=job.photo_id,
            facility_id=job.facility_id,
            facility_name=fname,
            status=job.status,
            error_message=job.error_message,
            retry_count=job.retry_count,
            max_retries=job.max_retries,
            photo_processing_status=(photo.processing_status if photo else None),
            photo_thumbnail_url=(photo.thumbnail_url if photo else None),
            created_at=job.created_at,
            started_at=job.started_at,
            completed_at=job.completed_at,
        )
        for job, photo, fname in rows
    ]
    return AdminPhotoJobListResponse(items=items, total=total, page=page, size=size)


class PhotoJobRetryResponse(BaseModel):
    id: str
    status: str
    retry_count: int
    error_message: Optional[str] = None


@router.post("/photo-jobs/{job_id}/retry", response_model=PhotoJobRetryResponse)
async def retry_photo_job(
    job_id: str,
    operator: dict = Depends(require_operator),
    db: AsyncSession = Depends(get_db),
) -> PhotoJobRetryResponse:
    """failed 상태 작업을 다시 pending 으로 돌려서 워커가 재처리하게 한다.

    재처리 시점:
    - error_message / completed_at / started_at 클리어
    - retry_count 는 0 으로 리셋 — 운영자 개입한 fresh attempt 라 worker 의
      자동 재시도 카운트와 분리. (이전 실패 이력은 audit log 에 남음)
    - max_retries 는 그대로

    failed 가 아닌 상태(processing/completed/pending) 는 409 — 운영자가 진행
    중인 작업을 강제로 흔들지 않도록.
    """
    job = await db.get(PhotoProcessingJob, job_id)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="작업을 찾을 수 없습니다.")

    if job.status != "failed":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"failed 상태인 작업만 재시도할 수 있습니다. (현재: {job.status})",
        )

    prev_error = job.error_message
    job.status = "pending"
    job.error_message = None
    job.started_at = None
    job.completed_at = None
    job.retry_count = 0

    admin_audit(
        db,
        action="photo_job_retry",
        performed_by=operator.get("user_id"),
        target_type="photo_job",
        target_id=job.id,
        facility_id=job.facility_id,
        detail=f"prev_error={prev_error[:200] if prev_error else ''}",
    )
    await db.commit()
    await db.refresh(job)

    return PhotoJobRetryResponse(
        id=job.id,
        status=job.status,
        retry_count=job.retry_count,
        error_message=job.error_message,
    )
