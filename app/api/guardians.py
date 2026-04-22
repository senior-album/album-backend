"""
보호자 API 엔드포인트
- 보호자: 승인된 경우만 사진/입소자 조회 가능 (다중 시설/다중 입소자 지원)
- 직원/관리자: 보호자 승인/거부 관리
"""

import uuid
from datetime import datetime, timedelta
from fastapi import APIRouter, HTTPException, status, Depends
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import get_current_user, get_current_guardian, get_current_staff
from app.models.models import Guardian, Photo, PhotoResident, Resident, User, Facility
from app.services.phone_otp import normalize_phone
from app.schemas.schemas import (
    PhotoResponse,
    ResidentResponse,
    UserResponse,
    GuardianDetailResponse,
    GuardianApprovalRequest,
    FacilityConnectionRequest,
)

router = APIRouter(prefix="/guardians", tags=["guardians"])


# ==================== 직원/관리자용 API ====================

@router.get("/facility/{facility_id}/pending", response_model=list[GuardianDetailResponse])
async def get_pending_guardians(
    facility_id: str,
    current_user: dict = Depends(get_current_staff),
    db: AsyncSession = Depends(get_db),
):
    """승인 대기 중인 보호자 목록 (직원/관리자용)"""
    from sqlalchemy.orm import aliased
    stmt = (
        select(Guardian, User, Resident)
        .join(User, Guardian.user_id == User.id)
        .outerjoin(Resident, Guardian.resident_id == Resident.id)  # 시설코드 요청은 resident 없음
        .filter(
            Guardian.facility_id == facility_id,
            Guardian.is_approved == False,
            Guardian.is_rejected == False,
        )
        .order_by(desc(Guardian.created_at))
    )
    result = await db.execute(stmt)
    rows = result.all()

    return [
        GuardianDetailResponse(
            id=guardian.id,
            user_id=guardian.user_id,
            resident_id=guardian.resident_id,
            relationship_type=guardian.relationship_type,
            request_message=guardian.request_message,
            is_approved=guardian.is_approved,
            is_rejected=guardian.is_rejected,
            reject_reason=guardian.reject_reason,
            approved_at=guardian.approved_at,
            created_at=guardian.created_at,
            user_name=user.name,
            user_email=user.email,
            user_phone=user.phone,
            resident_name=resident.name if resident else "미배정",
        )
        for guardian, user, resident in rows
    ]


@router.get("/facility/{facility_id}/all", response_model=list[GuardianDetailResponse])
async def get_all_guardians(
    facility_id: str,
    current_user: dict = Depends(get_current_staff),
    db: AsyncSession = Depends(get_db),
):
    """모든 보호자 목록 (직원/관리자용)"""
    stmt = (
        select(Guardian, User, Resident)
        .join(User, Guardian.user_id == User.id)
        .outerjoin(Resident, Guardian.resident_id == Resident.id)
        .filter(Guardian.facility_id == facility_id)
        .order_by(desc(Guardian.created_at))
    )
    result = await db.execute(stmt)
    rows = result.all()

    return [
        GuardianDetailResponse(
            id=guardian.id,
            user_id=guardian.user_id,
            resident_id=guardian.resident_id,
            relationship_type=guardian.relationship_type,
            request_message=guardian.request_message,
            is_approved=guardian.is_approved,
            is_rejected=guardian.is_rejected,
            reject_reason=guardian.reject_reason,
            approved_at=guardian.approved_at,
            created_at=guardian.created_at,
            user_name=user.name,
            user_email=user.email,
            user_phone=user.phone,
            resident_name=resident.name if resident else "미배정",
        )
        for guardian, user, resident in rows
    ]


@router.post("/{guardian_id}/approve")
async def approve_or_reject_guardian(
    guardian_id: str,
    request: GuardianApprovalRequest,
    current_user: dict = Depends(get_current_staff),
    db: AsyncSession = Depends(get_db),
):
    """보호자 승인 또는 거부 (직원/관리자용)"""
    stmt = select(Guardian).filter(Guardian.id == guardian_id)
    result = await db.execute(stmt)
    guardian = result.scalar_one_or_none()

    if not guardian:
        raise HTTPException(status_code=404, detail="보호자 요청을 찾을 수 없습니다.")

    if request.approved:
        # 시설코드 요청 승인 시 resident_id가 필수
        if not guardian.resident_id and not request.resident_id:
            raise HTTPException(
                status_code=400,
                detail="시설코드 요청 승인 시 입소자를 배정해야 합니다. resident_id를 포함해주세요.",
            )
        if request.resident_id:
            # 입소자 유효성 확인
            res_stmt = select(Resident).filter(
                Resident.id == request.resident_id,
                Resident.facility_id == guardian.facility_id,
                Resident.is_active == True,
            )
            res_result = await db.execute(res_stmt)
            if not res_result.scalar_one_or_none():
                raise HTTPException(status_code=404, detail="해당 입소자를 찾을 수 없습니다.")
            guardian.resident_id = request.resident_id

        guardian.is_approved = True
        guardian.is_rejected = False
        guardian.approved_by = current_user["user_id"]
        guardian.approved_at = datetime.utcnow()
        guardian.reject_reason = None
        message = "보호자가 승인되었습니다."
    else:
        guardian.is_approved = False
        guardian.is_rejected = True
        guardian.approved_by = current_user["user_id"]
        guardian.reject_reason = request.reject_reason
        message = "보호자 요청이 거부되었습니다."

    await db.commit()

    return {"message": message, "guardian_id": guardian_id, "approved": request.approved}


# ==================== 보호자 본인용 API ====================

@router.post("/me/connect")
async def request_facility_connection(
    req: FacilityConnectionRequest,
    current_user: dict = Depends(get_current_guardian),
    db: AsyncSession = Depends(get_db),
):
    """보호자가 시설 코드로 연결 요청 (시설 직원이 승인). 전화 OTP 인증 통과가 선행돼야 함."""
    # 전화번호 OTP 인증 게이트 — 인증 후 FRESH_WINDOW_SECONDS 이내여야 함
    settings = get_settings()
    user_stmt = select(User).filter(User.id == current_user["user_id"])
    user_result = await db.execute(user_stmt)
    user = user_result.scalar_one_or_none()
    if not user or not user.phone_verified_at or not user.phone:
        raise HTTPException(status_code=400, detail="휴대폰 인증이 필요합니다.")
    if user.phone_verified_at < datetime.utcnow() - timedelta(seconds=settings.OTP_FRESH_WINDOW_SECONDS):
        raise HTTPException(status_code=400, detail="휴대폰 인증이 만료되었습니다. 다시 인증해주세요.")

    # 시설 코드로 시설 조회
    fac_stmt = select(Facility).filter(Facility.code == req.facility_code)
    fac_result = await db.execute(fac_stmt)
    facility = fac_result.scalar_one_or_none()
    if not facility:
        raise HTTPException(status_code=404, detail="유효하지 않은 시설 코드입니다.")

    # 이미 해당 시설에 대기/승인 중인 요청이 있는지 확인
    dup_stmt = select(Guardian).filter(
        Guardian.user_id == current_user["user_id"],
        Guardian.facility_id == facility.id,
        Guardian.is_rejected == False,
    )
    dup_result = await db.execute(dup_stmt)
    existing = dup_result.scalar_one_or_none()
    if existing:
        if existing.is_approved:
            raise HTTPException(status_code=400, detail="이미 해당 시설과 연결되어 있습니다.")
        else:
            raise HTTPException(status_code=400, detail="이미 연결 요청이 대기 중입니다.")

    # Guardian 레코드 생성 (승인 대기 — resident 미지정)
    guardian = Guardian(
        id=str(uuid.uuid4()),
        user_id=current_user["user_id"],
        resident_id=None,  # 시설에서 입소자 배정
        facility_id=facility.id,
        relationship_type=req.relationship_type,
        request_message=req.message,
        is_approved=False,
        is_rejected=False,
    )
    db.add(guardian)
    await db.commit()

    return {
        "message": f"{facility.name}에 연결 요청을 보냈습니다. 시설 직원의 승인을 기다려주세요.",
        "facility_name": facility.name,
        "guardian_id": guardian.id,
    }


@router.get("/me/status")
async def get_my_approval_status(
    current_user: dict = Depends(get_current_guardian),
    db: AsyncSession = Depends(get_db),
):
    """보호자 승인 상태 확인 (다중 시설/입소자 지원)"""
    stmt = (
        select(Guardian, Resident, Facility)
        .outerjoin(Resident, Guardian.resident_id == Resident.id)
        .join(Facility, Guardian.facility_id == Facility.id)
        .filter(Guardian.user_id == current_user["user_id"])
    )
    result = await db.execute(stmt)
    rows = result.all()

    if not rows:
        return {"status": "no_link", "message": "연결된 시설이 없습니다.", "guardianships": []}

    statuses = []
    for guardian, resident, facility in rows:
        statuses.append({
            "guardian_id": guardian.id,
            "facility_id": facility.id,
            "facility_name": facility.name,
            "resident_id": resident.id if resident else None,
            "resident_name": resident.name if resident else "미배정",
            "relationship_type": guardian.relationship_type,
            "request_message": guardian.request_message,
            "is_approved": guardian.is_approved,
            "is_rejected": guardian.is_rejected,
            "reject_reason": guardian.reject_reason,
        })

    return {"status": "linked", "guardianships": statuses}


@router.get("/me/photos")
async def get_my_photos(
    current_user: dict = Depends(get_current_guardian),
    facility_id: str = None,
    resident_id: str = None,
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
):
    """
    보호자의 사진 조회 (승인된 관계만).
    - facility_id 필터: 특정 시설 사진만
    - resident_id 필터: 특정 입소자 사진만
    - 둘 다 없으면 전체 사진
    """
    guardian_stmt = select(Guardian).filter(
        Guardian.user_id == current_user["user_id"],
        Guardian.is_approved == True,
    )
    if facility_id:
        guardian_stmt = guardian_stmt.filter(Guardian.facility_id == facility_id)
    if resident_id:
        guardian_stmt = guardian_stmt.filter(Guardian.resident_id == resident_id)

    result = await db.execute(guardian_stmt)
    guardianships = result.scalars().all()

    resident_ids = [g.resident_id for g in guardianships]
    if not resident_ids:
        return []

    # PhotoResident 다대다 테이블을 통해 사진 조회 (다중 입소자 사진 지원)
    # 기존 Photo.resident_id도 fallback으로 포함
    from sqlalchemy import union_all, literal_column

    # 방법1: PhotoResident를 통한 조회 (공개된 사진만)
    pr_stmt = (
        select(Photo.id)
        .join(PhotoResident, Photo.id == PhotoResident.photo_id)
        .filter(PhotoResident.resident_id.in_(resident_ids), Photo.is_public == True)
    )
    # 방법2: 기존 Photo.resident_id를 통한 조회 (하위 호환, 공개된 사진만)
    legacy_stmt = (
        select(Photo.id)
        .filter(Photo.resident_id.in_(resident_ids), Photo.is_public == True)
    )

    # 두 결과를 합쳐서 중복 제거
    combined = union_all(pr_stmt, legacy_stmt).subquery()

    photo_stmt = (
        select(Photo)
        .filter(Photo.id.in_(select(combined.c.id)))
        .order_by(desc(Photo.created_at))
        .offset(skip)
        .limit(limit)
    )
    result = await db.execute(photo_stmt)
    photos = result.scalars().all()

    # 각 사진에 대해 매칭된 입소자 이름 + ID 조회
    photo_results = []
    for photo in photos:
        # PhotoResident에서 이 사진에 매칭된 입소자 ID + 이름
        pr_stmt = (
            select(Resident.id, Resident.name)
            .join(PhotoResident, Resident.id == PhotoResident.resident_id)
            .filter(
                PhotoResident.photo_id == photo.id,
                PhotoResident.resident_id.in_(resident_ids),
            )
        )
        pr_result = await db.execute(pr_stmt)
        matched_pairs = [(rid, rname) for rid, rname in pr_result.all()]

        # fallback: Photo.resident_id에서 이름
        if not matched_pairs and photo.resident_id:
            r_stmt = select(Resident.id, Resident.name).filter(Resident.id == photo.resident_id)
            r_result = await db.execute(r_stmt)
            row = r_result.first()
            if row:
                matched_pairs = [(row[0], row[1])]

        matched_resident_ids = [rid for rid, _ in matched_pairs]
        matched_names = [rname for _, rname in matched_pairs]

        from app.core.storage import get_storage
        storage = get_storage()

        photo_results.append({
            "id": photo.id,
            "facility_id": photo.facility_id,
            "resident_id": photo.resident_id,
            "resident_name": ", ".join(matched_names) if matched_names else None,
            "matched_residents": matched_names,
            "matched_resident_ids": matched_resident_ids,
            "original_url": storage.to_presigned(photo.original_url),
            "thumbnail_url": storage.to_presigned(photo.thumbnail_url) if photo.thumbnail_url else None,
            "is_processed": photo.is_processed,
            "processing_status": photo.processing_status,
            "created_at": photo.created_at.isoformat(),
            "updated_at": photo.updated_at.isoformat() if photo.updated_at else None,
        })

    return photo_results


@router.get("/me/residents")
async def get_my_residents(
    current_user: dict = Depends(get_current_guardian),
    db: AsyncSession = Depends(get_db),
):
    """보호자가 담당하는 입소자 목록 (시설별 그룹핑, 승인된 관계만)"""
    stmt = (
        select(Guardian, Resident, Facility)
        .join(Resident, Guardian.resident_id == Resident.id)
        .join(Facility, Guardian.facility_id == Facility.id)
        .filter(
            Guardian.user_id == current_user["user_id"],
            Guardian.is_approved == True,
        )
        .order_by(Facility.name, Resident.name)
    )
    result = await db.execute(stmt)
    rows = result.all()

    # 시설별로 그룹핑
    facilities_map: dict = {}
    for guardian, resident, facility in rows:
        if facility.id not in facilities_map:
            facilities_map[facility.id] = {
                "facility_id": facility.id,
                "facility_name": facility.name,
                "residents": [],
            }
        facilities_map[facility.id]["residents"].append({
            "id": resident.id,
            "name": resident.name,
            "code": resident.code,
            "room_number": resident.room_number,
            "relationship_type": guardian.relationship_type,
            "guardian_id": guardian.id,
        })

    return list(facilities_map.values())


@router.put("/me/settings")
async def update_notification_settings(
    notification_enabled: bool = True,
    notification_settings: dict = None,
    current_user: dict = Depends(get_current_guardian),
    db: AsyncSession = Depends(get_db),
):
    """보호자 알림 설정 변경"""
    stmt = select(User).filter(User.id == current_user["user_id"])
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.notification_enabled = notification_enabled
    if notification_settings:
        user.notification_settings = notification_settings

    await db.commit()
    await db.refresh(user)

    return {
        "message": "Notification settings updated",
        "notification_enabled": user.notification_enabled,
        "notification_settings": user.notification_settings,
    }


@router.get("/me", response_model=UserResponse)
async def get_my_info(
    current_user: dict = Depends(get_current_guardian),
    db: AsyncSession = Depends(get_db),
):
    """보호자 자신의 정보 조회"""
    stmt = select(User).filter(User.id == current_user["user_id"])
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return UserResponse.model_validate(user)


@router.put("/me/profile")
async def update_my_profile(
    name: str = None,
    phone: str = None,
    current_user: dict = Depends(get_current_guardian),
    db: AsyncSession = Depends(get_db),
):
    """보호자 프로필 수정 (이름, 전화번호)"""
    stmt = select(User).filter(User.id == current_user["user_id"])
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if name is not None:
        user.name = name
    if phone is not None:
        # 전화번호가 실제로 바뀌면 이전 OTP 인증을 무효화 — 시설 연결 요청 게이트 우회 방지
        if normalize_phone(user.phone or "") != normalize_phone(phone):
            user.phone_verified_at = None
        user.phone = phone

    await db.commit()
    await db.refresh(user)

    return {
        "message": "프로필이 수정되었습니다.",
        "name": user.name,
        "phone": user.phone,
    }
