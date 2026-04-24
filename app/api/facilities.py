"""
시설 관리 API 엔드포인트
시설 CRUD, 입소자 및 사진 조회, 대시보드 통계
"""

import re
import uuid
import logging
from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, HTTPException, Query, Request, status, Depends
from fastapi.responses import JSONResponse
from sqlalchemy import select, func, desc, text, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.redis import check_rate_limit
from app.core.security import get_current_user, get_current_staff
from app.models.models import (
    Facility,
    User,
    Resident,
    Photo,
    PhotoResident,
    PhotoLike,
    Guardian,
    Invitation,
)
from app.services.opensearch_service import OpenSearchService, FACE_INDEX
from app.schemas.schemas import (
    FacilityCreate,
    FacilityUpdate,
    FacilityResponse,
    FacilitySearchResult,
    ResidentResponse,
    PhotoResponse,
    MatchedResidentInfo,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/facilities", tags=["facilities"])


async def _resolve_facility_id(facility_id_or_code: str, db: AsyncSession) -> str:
    """
    facility_id가 UUID가 아니라 시설 코드(FAC-XXXX)로 들어온 경우
    실제 UUID로 변환하여 반환한다.
    """
    # UUID 형식이면 그대로 반환
    if len(facility_id_or_code) == 36 and '-' in facility_id_or_code:
        return facility_id_or_code

    # 시설 코드로 간주하고 조회
    logger.warning(f"[resolve] facility_id appears to be a code: {facility_id_or_code}, looking up UUID...")
    stmt = select(Facility.id).filter(Facility.code == facility_id_or_code)
    result = await db.execute(stmt)
    real_id = result.scalar_one_or_none()
    if real_id:
        logger.info(f"[resolve] Resolved facility code {facility_id_or_code} → {real_id}")
        return real_id

    # 찾지 못하면 원래 값 그대로 반환
    return facility_id_or_code


def _mask_phone_tail(phone: Optional[str]) -> Optional[str]:
    if not phone:
        return None
    digits = re.sub(r"\D", "", phone)
    return digits[-4:] if len(digits) >= 4 else None


@router.get("/search", response_model=list[FacilitySearchResult])
async def search_facilities(
    req: Request,
    q: str = Query(..., min_length=2, max_length=100, description="시설명/주소/전화 부분일치 검색어"),
    limit: int = Query(20, ge=1, le=20),
    db: AsyncSession = Depends(get_db),
):
    """
    회원가입 전 시설 피커용 검색. 인증 불필요.
    - name / address : ILIKE 부분일치
    - phone : 숫자만 추출해 부분일치
    - IP 기반 rate limit (열거 공격 방어)
    """
    client_ip = req.client.host if req.client else "unknown"
    is_blocked, remaining = await check_rate_limit(
        key=f"facility_search:{client_ip}",
        max_attempts=60,
        window_seconds=60,
    )
    if is_blocked:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"검색 요청이 많습니다. {remaining}초 후 다시 시도해주세요.",
        )

    q_trim = q.strip()
    like = f"%{q_trim}%"
    digits = re.sub(r"\D", "", q_trim)

    filters = [
        Facility.name.ilike(like),
        Facility.address.ilike(like),
    ]
    if digits:
        filters.append(Facility.phone.like(f"%{digits}%"))

    stmt = (
        select(Facility)
        .filter(or_(*filters))
        .order_by(Facility.name)
        .limit(limit)
    )
    result = await db.execute(stmt)
    facilities = result.scalars().all()

    return [
        FacilitySearchResult(
            id=f.id,
            name=f.name,
            address=f.address,
            phone_last4=_mask_phone_tail(f.phone),
            code=f.code,
        )
        for f in facilities
    ]


@router.get("/{facility_id}", response_model=FacilityResponse)
async def get_facility(
    facility_id: str,
    db: AsyncSession = Depends(get_db),
):
    """시설 상세 조회"""
    facility_id = await _resolve_facility_id(facility_id, db)
    stmt = select(Facility).filter(Facility.id == facility_id)
    result = await db.execute(stmt)
    facility = result.scalar_one_or_none()

    if not facility:
        raise HTTPException(status_code=404, detail="시설을 찾을 수 없습니다.")

    return FacilityResponse.model_validate(facility)


@router.put("/{facility_id}", response_model=FacilityResponse)
async def update_facility(
    facility_id: str,
    facility_update: FacilityUpdate,
    current_user: dict = Depends(get_current_staff),
    db: AsyncSession = Depends(get_db),
):
    """시설 정보 수정"""
    facility_id = await _resolve_facility_id(facility_id, db)
    stmt = select(Facility).filter(Facility.id == facility_id)
    result = await db.execute(stmt)
    facility = result.scalar_one_or_none()

    if not facility:
        raise HTTPException(status_code=404, detail="시설을 찾을 수 없습니다.")

    if facility_update.name is not None:
        facility.name = facility_update.name
    if facility_update.address is not None:
        facility.address = facility_update.address
    if facility_update.phone is not None:
        facility.phone = facility_update.phone

    await db.flush()

    return FacilityResponse.model_validate(facility)


@router.get("/{facility_id}/residents", response_model=list[ResidentResponse])
async def get_facility_residents(
    facility_id: str,
    db: AsyncSession = Depends(get_db),
):
    """시설의 모든 입소자 조회"""
    facility_id = await _resolve_facility_id(facility_id, db)
    stmt = select(Resident).filter(
        Resident.facility_id == facility_id,
        Resident.is_active == True,
    )
    result = await db.execute(stmt)
    residents = result.scalars().all()

    return [ResidentResponse.model_validate(r) for r in residents]


@router.get("/{facility_id}/photos")
async def get_facility_photos(
    facility_id: str,
    skip: int = 0,
    limit: int = 50,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """시설의 모든 사진 조회 (최신순, 다대다 입소자 매핑 + 좋아요 포함)"""
    logger.info(f"[facility_photos] Request: facility_id={facility_id}, user={current_user.get('user_id')}")

    # facility_id가 코드(FAC-XXXX)로 들어온 경우 UUID로 변환
    facility_id = await _resolve_facility_id(facility_id, db)

    try:
        stmt = (
            select(Photo)
            .filter(Photo.facility_id == facility_id)
            .order_by(desc(Photo.created_at))
            .offset(skip)
            .limit(limit)
        )
        result = await db.execute(stmt)
        photos = list(result.scalars().all())

        logger.info(f"[facility_photos] Found {len(photos)} photos for facility {facility_id}")

        if not photos:
            # 추가 진단: 해당 시설에 사진이 진짜 없는지 COUNT로 확인
            count_stmt = select(func.count(Photo.id)).filter(Photo.facility_id == facility_id)
            total = (await db.execute(count_stmt)).scalar() or 0
            logger.info(f"[facility_photos] Total photo count for facility {facility_id}: {total}")

            # 모든 시설의 사진 수도 확인
            all_count = (await db.execute(select(func.count(Photo.id)))).scalar() or 0
            logger.info(f"[facility_photos] Total photos in DB (all facilities): {all_count}")

            return []

        try:
            from app.api.photos import _enrich_photos_with_residents
            enriched = await _enrich_photos_with_residents(photos, db, current_user["user_id"])
            logger.info(f"[facility_photos] Enriched {len(enriched)} photos successfully")
            return enriched
        except Exception as e:
            logger.error(f"[facility_photos] _enrich_photos_with_residents failed: {e}", exc_info=True)
            # fallback: 기본 dict로 반환 (response_model 없으므로 안전)
            from app.core.storage import get_storage
            storage = get_storage()
            fallback = []
            for p in photos:
                try:
                    resp = PhotoResponse.model_validate(p).model_dump()
                    resp["original_url"] = storage.to_presigned(resp["original_url"])
                    if resp.get("thumbnail_url"):
                        resp["thumbnail_url"] = storage.to_presigned(resp["thumbnail_url"])
                    fallback.append(resp)
                except Exception as ve:
                    logger.error(f"[facility_photos] PhotoResponse validation failed for photo {p.id}: {ve}")
                    fallback.append({
                        "id": p.id,
                        "facility_id": p.facility_id,
                        "original_url": storage.to_presigned(p.original_url),
                        "thumbnail_url": storage.to_presigned(p.thumbnail_url or p.original_url),
                        "is_processed": getattr(p, 'is_processed', False),
                        "processing_status": getattr(p, 'processing_status', 'unknown'),
                        "created_at": p.created_at.isoformat() if p.created_at else None,
                        "matched_residents": [],
                        "is_public": getattr(p, 'is_public', False),
                        "like_count": 0,
                        "liked_by_me": False,
                    })
            return fallback
    except Exception as e:
        logger.error(f"[facility_photos] Unexpected error: {e}", exc_info=True)
        return []


@router.get("/{facility_id}/debug")
async def debug_facility_photos(
    facility_id: str,
    db: AsyncSession = Depends(get_db),
):
    """시설 사진 디버그 - 인증 없이 DB 상태 확인"""
    try:
        # facility_id가 코드(FAC-XXXX)로 들어온 경우 UUID로 변환
        resolved_id = await _resolve_facility_id(facility_id, db)
        if resolved_id != facility_id:
            logger.info(f"[debug] Resolved {facility_id} → {resolved_id}")
            facility_id = resolved_id

        # 시설 존재 확인
        fac = await db.execute(select(Facility).filter(Facility.id == facility_id))
        facility = fac.scalar_one_or_none()

        # 모든 시설 목록
        all_fac = await db.execute(select(Facility.id, Facility.name, Facility.code))
        facilities_list = [{"id": r[0], "name": r[1], "code": r[2]} for r in all_fac.all()]

        # 이 시설의 사진 수
        photo_count = (await db.execute(
            select(func.count(Photo.id)).filter(Photo.facility_id == facility_id)
        )).scalar() or 0

        # 전체 사진 수
        total_photos = (await db.execute(select(func.count(Photo.id)))).scalar() or 0

        # 최근 5개 사진 ID
        recent = await db.execute(
            select(Photo.id, Photo.facility_id, Photo.created_at)
            .order_by(desc(Photo.created_at))
            .limit(5)
        )
        recent_photos = [
            {"id": r[0], "facility_id": r[1], "created_at": r[2].isoformat() if r[2] else None}
            for r in recent.all()
        ]

        # 사진이 있는 시설별 카운트
        fac_counts = await db.execute(
            select(Photo.facility_id, func.count(Photo.id))
            .group_by(Photo.facility_id)
        )
        photos_per_facility = {r[0]: r[1] for r in fac_counts.all()}

        # ORM 전체 select 테스트 (photos 엔드포인트와 동일한 쿼리)
        orm_test = {"success": False, "count": 0, "error": None}
        try:
            orm_stmt = (
                select(Photo)
                .filter(Photo.facility_id == facility_id)
                .order_by(desc(Photo.created_at))
                .limit(5)
            )
            orm_result = await db.execute(orm_stmt)
            orm_photos = list(orm_result.scalars().all())
            orm_test["success"] = True
            orm_test["count"] = len(orm_photos)
            if orm_photos:
                orm_test["first_photo"] = {
                    "id": orm_photos[0].id,
                    "original_url": orm_photos[0].original_url[:80],
                    "processing_status": getattr(orm_photos[0], 'processing_status', 'N/A'),
                    "is_public": getattr(orm_photos[0], 'is_public', 'N/A'),
                }
        except Exception as orm_err:
            orm_test["error"] = str(orm_err)

        return {
            "orm_full_select_test": orm_test,
            "facility_exists": facility is not None,
            "facility_name": facility.name if facility else None,
            "requested_facility_id": facility_id,
            "all_facilities": facilities_list,
            "photo_count_for_facility": photo_count,
            "total_photos_in_db": total_photos,
            "photos_per_facility": photos_per_facility,
            "recent_photos_any_facility": recent_photos,
        }
    except Exception as e:
        logger.error(f"[debug] Error: {e}", exc_info=True)
        return {"error": str(e)}


@router.get("/{facility_id}/stats")
async def get_facility_stats(
    facility_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """대시보드 통계 조회"""
    # facility_id가 코드(FAC-XXXX)로 들어온 경우 UUID로 변환
    facility_id = await _resolve_facility_id(facility_id, db)

    # 시설 조회
    fac_stmt = select(Facility).filter(Facility.id == facility_id)
    fac_result = await db.execute(fac_stmt)
    facility = fac_result.scalar_one_or_none()
    if not facility:
        raise HTTPException(status_code=404, detail="시설을 찾을 수 없습니다.")

    # 총 사진 수
    total_photos_stmt = select(func.count(Photo.id)).filter(Photo.facility_id == facility_id)
    total_photos = (await db.execute(total_photos_stmt)).scalar() or 0

    # 오늘 업로드 사진 수
    today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    today_photos_stmt = select(func.count(Photo.id)).filter(
        Photo.facility_id == facility_id,
        Photo.created_at >= today,
    )
    photos_today = (await db.execute(today_photos_stmt)).scalar() or 0

    # 총 입소자 수
    total_residents_stmt = select(func.count(Resident.id)).filter(
        Resident.facility_id == facility_id,
        Resident.is_active == True,
    )
    total_residents = (await db.execute(total_residents_stmt)).scalar() or 0

    # 분류 완료 사진 수
    classified_stmt = select(func.count(Photo.id)).filter(
        Photo.facility_id == facility_id,
        Photo.is_processed == True,
    )
    classified_photos = (await db.execute(classified_stmt)).scalar() or 0

    classification_rate = round((classified_photos / total_photos * 100), 1) if total_photos > 0 else 0

    # T-031: 시설장 조치 항목 4 종 — 보호자 초대 / 미연결 어르신 / 미처리 사진 / 얼굴 미등록

    # 1) 보호자 초대 현황 — status 별 GROUP BY
    invite_stmt = (
        select(Invitation.status, func.count(Invitation.id))
        .filter(Invitation.facility_id == facility_id)
        .group_by(Invitation.status)
    )
    invite_rows = (await db.execute(invite_stmt)).all()
    invite_counts = {row[0]: row[1] for row in invite_rows}
    invitations_summary = {
        "pending": invite_counts.get("pending", 0),
        "accepted": invite_counts.get("accepted", 0),
        "rejected": invite_counts.get("rejected", 0),
    }

    # 2) 미연결 어르신 — 승인된(is_approved=True, is_rejected=False) Guardian 이 한 명도 없는 active Resident.
    # Guardian.resident_id 는 초기 요청 시 null 이었다가 승인+배정 후 채워지므로 notin 비교 대상에서 null 은 자동 제외됨.
    approved_resident_ids_subq = (
        select(Guardian.resident_id)
        .filter(
            Guardian.resident_id.isnot(None),
            Guardian.is_approved == True,
            Guardian.is_rejected == False,
        )
        .scalar_subquery()
    )
    no_guardian_stmt = (
        select(Resident)
        .filter(
            Resident.facility_id == facility_id,
            Resident.is_active == True,
            Resident.id.notin_(approved_resident_ids_subq),
        )
        .order_by(Resident.created_at.desc())
    )
    no_guardian_residents = (await db.execute(no_guardian_stmt)).scalars().all()
    residents_without_guardian = {
        "count": len(no_guardian_residents),
        "topNames": [r.name for r in no_guardian_residents[:3]],
    }

    # 3) 미처리 사진 — detected_unmatched / no_model / no_face.
    # pending/queued 는 진행 중이라 제외, classified/completed 는 성공이라 제외.
    UNPROCESSED_STATUSES = ["detected_unmatched", "no_model", "no_face"]
    unprocessed_stmt = select(func.count(Photo.id)).filter(
        Photo.facility_id == facility_id,
        Photo.processing_status.in_(UNPROCESSED_STATUSES),
    )
    photos_unprocessed = (await db.execute(unprocessed_stmt)).scalar() or 0

    # 4) 얼굴 미등록 — OpenSearch 에서 is_reference=True 레코드가 없는 active Resident.
    # OpenSearch 장애 시 집계 0 으로 fallback (로그만 남김, 응답은 200 유지).
    all_residents_stmt = (
        select(Resident)
        .filter(
            Resident.facility_id == facility_id,
            Resident.is_active == True,
        )
        .order_by(Resident.created_at.desc())
    )
    all_residents = (await db.execute(all_residents_stmt)).scalars().all()
    residents_with_face_ids: set[str] = set()
    try:
        client = OpenSearchService.get_client()
        resp = client.search(
            index=FACE_INDEX,
            body={
                "size": 0,
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"facility_id": facility_id}},
                            {"term": {"is_reference": True}},
                        ]
                    }
                },
                "aggs": {
                    "residents": {
                        "terms": {"field": "resident_id", "size": 10000},
                    }
                },
            },
        )
        buckets = resp.get("aggregations", {}).get("residents", {}).get("buckets", [])
        residents_with_face_ids = {b["key"] for b in buckets if b.get("key")}
    except Exception as e:
        logger.warning(f"[stats] OpenSearch reference aggregation failed: {e}")
    no_face_residents = [r for r in all_residents if r.id not in residents_with_face_ids]
    residents_without_face = {
        "count": len(no_face_residents),
        "topNames": [r.name for r in no_face_residents[:3]],
    }

    return {
        "totalPhotos": total_photos,
        "photosToday": photos_today,
        "totalResidents": total_residents,
        "classifiedPhotos": classified_photos,
        "classificationRate": classification_rate,
        "facilityName": facility.name,
        "facilityCode": facility.code,
        # T-031
        "invitations": invitations_summary,
        "residentsWithoutGuardian": residents_without_guardian,
        "photosUnprocessed": photos_unprocessed,
        "residentsWithoutFace": residents_without_face,
    }
