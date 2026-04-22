"""
사진 관리 API 엔드포인트
업로드 시 얼굴 감지 → OpenSearch kNN 검색 → 자동 분류
"""

import os
import uuid
import secrets
import logging
from io import BytesIO
import numpy as np
import magic
from PIL import Image as PILImage

from fastapi import APIRouter, HTTPException, status, Depends, UploadFile, File, Query, Request
from sqlalchemy import select, desc, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import get_db
from app.core.redis import check_rate_limit
from app.core.security import get_current_user, get_current_guardian, get_current_staff, verify_facility_access
from app.core.storage import get_storage
from app.models.models import Photo, PhotoFace, PhotoResident, PhotoLike, PhotoShare, PhotoProcessingJob, PhotoAuditLog, Resident, Guardian, User
from app.schemas.schemas import (
    PhotoResponse,
    PhotoDetailResponse,
    FaceReviewRequest,
    MatchedResidentInfo,
)
from app.services.face_recognition import FaceService
from app.services.opensearch_service import OpenSearchService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/photos", tags=["photos"])


async def _enforce_rate_limit(key: str, max_per_minute: int) -> None:
    """Redis 기반 rate limit 체크. 초과 시 429 + Retry-After."""
    blocked, retry_after = await check_rate_limit(key, max_per_minute, 60)
    if blocked:
        raise HTTPException(
            status_code=429,
            detail=f"요청이 너무 많습니다. {retry_after}초 후 다시 시도해주세요.",
            headers={"Retry-After": str(retry_after or 60)},
        )

# 업로드 검증 상수
MAX_UPLOAD_SIZE = 20 * 1024 * 1024  # 20MB
ALLOWED_MIME = {"image/jpeg", "image/png", "image/webp", "image/heic", "image/heif"}
ALLOWED_EXT = {".jpg", ".jpeg", ".png", ".webp", ".heic", ".heif"}


def _validate_upload(filename: str, data: bytes) -> tuple[str, str]:
    """크기/확장자/MIME(magic bytes)/Pillow 디코딩 4단계 검증."""
    if len(data) > MAX_UPLOAD_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"파일이 너무 큽니다 (최대 {MAX_UPLOAD_SIZE // 1024 // 1024}MB).",
        )

    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_EXT:
        raise HTTPException(status_code=415, detail=f"허용되지 않는 확장자: {ext or '(없음)'}")

    try:
        sniffed = magic.from_buffer(data[:4096], mime=True)
    except Exception as e:
        logger.warning(f"magic sniff failed: {e}")
        sniffed = None
    if sniffed not in ALLOWED_MIME:
        raise HTTPException(status_code=415, detail=f"허용되지 않는 파일 타입: {sniffed or '(unknown)'}")

    try:
        PILImage.open(BytesIO(data)).verify()
    except Exception:
        raise HTTPException(status_code=422, detail="손상되었거나 유효하지 않은 이미지입니다.")

    return ext, sniffed


async def _enrich_photos_with_residents(
    photos: list[Photo], db: AsyncSession, current_user_id: str = None
) -> list[PhotoResponse]:
    """Photo 목록에 matched_residents + like 정보를 채워서 PhotoResponse 리스트로 반환"""
    if not photos:
        return []

    photo_ids = [p.id for p in photos]

    # PhotoResident + Resident join으로 한번에 조회
    stmt = (
        select(PhotoResident, Resident.name)
        .join(Resident, PhotoResident.resident_id == Resident.id)
        .filter(PhotoResident.photo_id.in_(photo_ids))
    )
    result = await db.execute(stmt)
    rows = result.all()

    # photo_id별 매칭된 입소자 그룹핑
    photo_residents_map: dict[str, list[MatchedResidentInfo]] = {}
    for pr, resident_name in rows:
        if pr.photo_id not in photo_residents_map:
            photo_residents_map[pr.photo_id] = []
        photo_residents_map[pr.photo_id].append(
            MatchedResidentInfo(
                resident_id=pr.resident_id,
                resident_name=resident_name,
                confidence=pr.confidence,
            )
        )

    # 좋아요 수 한번에 조회
    like_counts_stmt = (
        select(PhotoLike.photo_id, func.count(PhotoLike.id))
        .filter(PhotoLike.photo_id.in_(photo_ids))
        .group_by(PhotoLike.photo_id)
    )
    like_counts_result = await db.execute(like_counts_stmt)
    like_counts_map = dict(like_counts_result.all())

    # 내가 좋아요한 사진 목록
    my_likes_set: set[str] = set()
    if current_user_id:
        my_likes_stmt = (
            select(PhotoLike.photo_id)
            .filter(PhotoLike.photo_id.in_(photo_ids), PhotoLike.user_id == current_user_id)
        )
        my_likes_result = await db.execute(my_likes_stmt)
        my_likes_set = {row[0] for row in my_likes_result.all()}

    # presigned URL 변환용 storage
    from app.core.storage import get_storage
    storage = get_storage()

    responses = []
    for p in photos:
        resp = PhotoResponse.model_validate(p)
        resp.matched_residents = photo_residents_map.get(p.id, [])
        resp.like_count = like_counts_map.get(p.id, 0)
        resp.liked_by_me = p.id in my_likes_set
        # PhotoResident가 없는 경우 기존 resident_id에서 fallback
        if not resp.matched_residents and p.resident_id:
            r_stmt = select(Resident.name).filter(Resident.id == p.resident_id)
            r_result = await db.execute(r_stmt)
            r_name = r_result.scalar_one_or_none()
            resp.matched_residents = [
                MatchedResidentInfo(
                    resident_id=p.resident_id,
                    resident_name=r_name,
                )
            ]
        # URL을 presigned URL로 변환
        resp.original_url = storage.to_presigned(resp.original_url)
        if resp.thumbnail_url:
            resp.thumbnail_url = storage.to_presigned(resp.thumbnail_url)
        responses.append(resp)

    return responses


@router.post("/upload")
async def upload_photos(
    facility_id: str,
    files: list[UploadFile] = File(...),
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    다중 사진 업로드 (비동기 처리)
    1. MinIO에 원본 + 섬네일 저장
    2. DB에 사진 레코드 + 처리 작업(job) 생성
    3. 실제 얼굴 감지/분류는 백그라운드 워커가 처리
    """
    # Rate limit: 사용자당 100회/분 (멀티 업로드 버스트 허용)
    await _enforce_rate_limit(f"upload:{current_user['user_id']}", 100)

    # facility_id가 코드(FAC-XXXX)로 들어온 경우 UUID로 변환
    from app.models.models import Facility as FacilityModel
    if len(facility_id) != 36 or '-' not in facility_id:
        logger.warning(f"[upload] facility_id appears to be a code: {facility_id}")
        fac_stmt = select(FacilityModel.id).filter(FacilityModel.code == facility_id)
        fac_result = await db.execute(fac_stmt)
        real_id = fac_result.scalar_one_or_none()
        if real_id:
            logger.info(f"[upload] Resolved facility code {facility_id} → {real_id}")
            facility_id = real_id

    # 시설 소속 검증
    verify_facility_access(current_user, facility_id)

    uploaded_photos = []
    created_jobs = []
    storage = get_storage()

    for file in files:
        try:
            file_data = await file.read()

            # 업로드 검증 (크기/확장자/MIME/디코딩)
            ext, sniffed_mime = _validate_upload(file.filename or "", file_data)
            content_type = sniffed_mime
            filename = file.filename or f"photo{ext}"

            # 1) MinIO에 원본 업로드 → object key만 저장
            object_key = await storage.upload_file(
                file_data=file_data,
                filename=filename,
                content_type=content_type,
                facility_id=facility_id,
            )

            # 2) 섬네일 생성 및 업로드 → object key만 저장
            thumb_key = object_key  # 섬네일 실패 시 원본 키 사용
            try:
                img = PILImage.open(BytesIO(file_data)).convert("RGB")
                img_thumb = img.copy()
                img_thumb.thumbnail((300, 300))
                thumb_buf = BytesIO()
                img_thumb.save(thumb_buf, format="JPEG", quality=80)
                thumb_data = thumb_buf.getvalue()

                thumb_key = await storage.upload_file(
                    file_data=thumb_data,
                    filename=f"thumb_{filename}",
                    content_type="image/jpeg",
                    facility_id=f"{facility_id}/thumbnails",
                )
            except Exception as e:
                logger.warning(f"Thumbnail generation failed: {e}")

            # 3) DB에 사진 레코드 저장 (object key만 저장)
            photo = Photo(
                id=str(uuid.uuid4()),
                facility_id=facility_id,
                original_url=object_key,
                thumbnail_url=thumb_key,
                is_processed=False,
                processing_status="queued",
                upload_source="api",
                uploaded_by=current_user["user_id"],
            )
            db.add(photo)
            await db.flush()

            # 4) 처리 작업(Job) 생성 (테이블 없으면 skip)
            try:
                job = PhotoProcessingJob(
                    id=str(uuid.uuid4()),
                    photo_id=photo.id,
                    facility_id=facility_id,
                    status="pending",
                )
                db.add(job)
                await db.flush()
                created_jobs.append(job)
                logger.info(f"Photo queued for processing: {photo.id} (job: {job.id})")
            except Exception as job_err:
                logger.warning(f"Job creation failed (will process inline): {job_err}")
                # Job 테이블이 없으면 즉시 동기 처리 시도
                await db.rollback()
                # 사진만 다시 저장
                db.add(photo)
                await db.flush()

            uploaded_photos.append(photo)

        except Exception as e:
            logger.error(f"Photo upload failed for {file.filename}: {e}", exc_info=True)
            try:
                await db.rollback()
            except Exception:
                pass
            # 개별 사진 실패는 건너뛰고 나머지 계속 처리
            continue

    try:
        await db.commit()
    except Exception as commit_err:
        logger.error(f"Commit failed: {commit_err}", exc_info=True)
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"사진 저장 실패: {str(commit_err)}")

    return {
        "message": f"{len(uploaded_photos)}장의 사진이 업로드되었습니다. 분류 처리 중...",
        "photos": [
            {
                "id": p.id,
                "original_url": storage.to_presigned(p.original_url),
                "thumbnail_url": storage.to_presigned(p.thumbnail_url) if p.thumbnail_url else None,
                "processing_status": p.processing_status,
            }
            for p in uploaded_photos
        ],
        "jobs": [{"job_id": j.id, "status": j.status} for j in created_jobs],
    }


@router.get("/jobs/status")
async def get_processing_jobs_status(
    facility_id: str = None,
    current_user: dict = Depends(get_current_staff),
    db: AsyncSession = Depends(get_db),
):
    """처리 작업 상태 조회"""
    stmt = select(PhotoProcessingJob).order_by(desc(PhotoProcessingJob.created_at)).limit(50)
    if facility_id:
        stmt = stmt.filter(PhotoProcessingJob.facility_id == facility_id)
    result = await db.execute(stmt)
    jobs = result.scalars().all()

    return [
        {
            "job_id": j.id,
            "photo_id": j.photo_id,
            "status": j.status,
            "error_message": j.error_message,
            "retry_count": j.retry_count,
            "created_at": j.created_at.isoformat(),
            "started_at": j.started_at.isoformat() if j.started_at else None,
            "completed_at": j.completed_at.isoformat() if j.completed_at else None,
        }
        for j in jobs
    ]


@router.get("/{photo_id}", response_model=PhotoDetailResponse)
async def get_photo(
    photo_id: str,
    db: AsyncSession = Depends(get_db),
):
    """사진 상세 조회 (얼굴 감지 결과 포함)"""
    stmt = select(Photo).filter(Photo.id == photo_id)
    result = await db.execute(stmt)
    photo = result.scalar_one_or_none()
    if not photo:
        raise HTTPException(status_code=404, detail="Photo not found")
    return PhotoDetailResponse.model_validate(photo)


@router.get("/facility/{facility_id}", response_model=list[PhotoResponse])
async def get_facility_photos(
    facility_id: str,
    skip: int = 0,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
):
    """시설의 사진 목록 (최신순, 다대다 입소자 매핑 포함)"""
    # facility_id가 코드(FAC-XXXX)로 들어온 경우 UUID로 변환
    from app.models.models import Facility as FacilityModel
    if len(facility_id) != 36 or '-' not in facility_id:
        fac_stmt = select(FacilityModel.id).filter(FacilityModel.code == facility_id)
        fac_result = await db.execute(fac_stmt)
        real_id = fac_result.scalar_one_or_none()
        if real_id:
            facility_id = real_id

    stmt = (
        select(Photo)
        .filter(Photo.facility_id == facility_id)
        .order_by(desc(Photo.created_at))
        .offset(skip)
        .limit(limit)
    )
    result = await db.execute(stmt)
    photos = result.scalars().all()
    return await _enrich_photos_with_residents(list(photos), db)


@router.get("/guardian/my-photos", response_model=list[PhotoResponse])
async def get_guardian_photos(
    current_user: dict = Depends(get_current_guardian),
    db: AsyncSession = Depends(get_db),
):
    """보호자 자신의 어르신 사진만 조회 (다대다 지원)"""
    from sqlalchemy import union_all

    guardian_stmt = select(Guardian).filter(Guardian.user_id == current_user["user_id"])
    result = await db.execute(guardian_stmt)
    guardianships = result.scalars().all()
    resident_ids = [g.resident_id for g in guardianships]

    if not resident_ids:
        return []

    # PhotoResident 다대다 + 기존 Photo.resident_id 모두 조회 (공개된 사진만)
    pr_ids = (
        select(Photo.id)
        .join(PhotoResident, Photo.id == PhotoResident.photo_id)
        .filter(PhotoResident.resident_id.in_(resident_ids), Photo.is_public == True)
    )
    legacy_ids = select(Photo.id).filter(
        Photo.resident_id.in_(resident_ids), Photo.is_public == True
    )
    combined = union_all(pr_ids, legacy_ids).subquery()

    photo_stmt = (
        select(Photo)
        .filter(Photo.id.in_(select(combined.c.id)))
        .order_by(desc(Photo.created_at))
        .limit(100)
    )
    result = await db.execute(photo_stmt)
    photos = result.scalars().all()
    return [PhotoResponse.model_validate(p) for p in photos]


@router.get("/debug/opensearch-status")
async def debug_opensearch_status(
    facility_id: str = None,
    current_user: dict = Depends(get_current_staff),
):
    """OpenSearch 인덱스 상태 확인 (디버그용)"""
    try:
        client = OpenSearchService.get_client()

        # 모델 임베딩 차원
        model_dim = None
        try:
            model_dim = FaceService.get_embedding_dim()
        except Exception:
            pass

        # 인덱스 차원
        index_dim = None
        try:
            mapping = client.indices.get_mapping(index="face_embeddings")
            index_dim = mapping["face_embeddings"]["mappings"]["properties"]["embedding"]["dimension"]
        except Exception:
            pass

        dim_match = model_dim == index_dim if model_dim and index_dim else None

        # 인덱스 문서 수
        count = client.count(index="face_embeddings")
        total = count["count"]

        # reference embedding 수
        ref_query = {"query": {"term": {"is_reference": True}}}
        if facility_id:
            ref_query = {
                "query": {
                    "bool": {
                        "must": [
                            {"term": {"is_reference": True}},
                            {"term": {"facility_id": facility_id}},
                        ]
                    }
                }
            }
        ref_count = client.count(index="face_embeddings", body=ref_query)

        # reference 목록
        ref_search = client.search(
            index="face_embeddings",
            body={**ref_query, "size": 50, "_source": ["resident_id", "facility_id", "is_reference", "photo_url"]},
        )
        refs = [
            {
                "doc_id": h["_id"],
                "resident_id": h["_source"]["resident_id"],
                "facility_id": h["_source"]["facility_id"],
                "photo_url": h["_source"].get("photo_url"),
            }
            for h in ref_search["hits"]["hits"]
        ]

        return {
            "model_embedding_dim": model_dim,
            "index_embedding_dim": index_dim,
            "dimension_match": dim_match,
            "face_model_available": FaceService.is_available(),
            "total_embeddings": total,
            "reference_embeddings": ref_count["count"],
            "references": refs,
        }
    except Exception as e:
        logger.error(f"Debug endpoint error: {e}")
        return {"error": str(e)}


@router.get("/debug/photo-residents")
async def debug_photo_residents(
    facility_id: str = None,
    current_user: dict = Depends(get_current_staff),
    db: AsyncSession = Depends(get_db),
):
    """PhotoResident 다대다 매핑 상태 디버그"""
    try:
        # 최근 사진별 PhotoResident 레코드 확인
        stmt = select(Photo).order_by(desc(Photo.created_at)).limit(10)
        if facility_id:
            stmt = stmt.filter(Photo.facility_id == facility_id)
        result = await db.execute(stmt)
        photos = result.scalars().all()

        photo_debug = []
        for p in photos:
            # PhotoResident 레코드
            pr_stmt = (
                select(PhotoResident, Resident.name)
                .join(Resident, PhotoResident.resident_id == Resident.id)
                .filter(PhotoResident.photo_id == p.id)
            )
            pr_result = await db.execute(pr_stmt)
            pr_rows = pr_result.all()

            # PhotoFace 레코드
            pf_stmt = select(PhotoFace).filter(PhotoFace.photo_id == p.id)
            pf_result = await db.execute(pf_stmt)
            pf_rows = pf_result.scalars().all()

            photo_debug.append({
                "photo_id": p.id,
                "resident_id_legacy": p.resident_id,
                "processing_status": p.processing_status,
                "created_at": p.created_at.isoformat(),
                "photo_residents": [
                    {"resident_id": pr.resident_id, "resident_name": name, "confidence": pr.confidence}
                    for pr, name in pr_rows
                ],
                "photo_faces": [
                    {"face_id": pf.id, "resident_id": pf.resident_id, "confidence": pf.confidence}
                    for pf in pf_rows
                ],
            })

        # PhotoResident 테이블 총 레코드 수
        total_pr = await db.execute(select(PhotoResident))
        total_pr_count = len(total_pr.scalars().all())

        return {
            "total_photo_resident_records": total_pr_count,
            "recent_photos": photo_debug,
        }
    except Exception as e:
        logger.error(f"Debug photo-residents error: {e}", exc_info=True)
        return {"error": str(e)}


@router.post("/{photo_id}/review")
async def review_photo_face(
    photo_id: str,
    face_id: str,
    review: FaceReviewRequest,
    current_user: dict = Depends(get_current_staff),
    db: AsyncSession = Depends(get_db),
):
    """사진의 얼굴 분류 결과 검토 (직원이 오분류 수정)"""
    stmt = select(PhotoFace).filter(PhotoFace.id == face_id)
    result = await db.execute(stmt)
    face = result.scalar_one_or_none()
    if not face:
        raise HTTPException(status_code=404, detail="Face not found")

    face.resident_id = review.resident_id
    face.is_confirmed = review.is_confirmed
    face.is_rejected = review.resident_id is None

    await db.commit()
    await db.refresh(face)

    return {
        "message": "Face review completed",
        "face_id": face.id,
        "resident_id": face.resident_id,
        "is_confirmed": face.is_confirmed,
    }


# ==================== 수동 분류 (태그 수정) API ====================


@router.post("/{photo_id}/tag")
async def add_resident_tag(
    photo_id: str,
    resident_id: str = Query(..., description="태그할 입소자 ID"),
    current_user: dict = Depends(get_current_staff),
    db: AsyncSession = Depends(get_db),
):
    """사진에 입소자 태그 추가 (수동 분류)"""
    # 사진 존재 확인
    photo_result = await db.execute(select(Photo).filter(Photo.id == photo_id))
    photo = photo_result.scalar_one_or_none()
    if not photo:
        raise HTTPException(status_code=404, detail="사진을 찾을 수 없습니다.")

    # 입소자 존재 + 같은 시설 확인
    resident_result = await db.execute(select(Resident).filter(Resident.id == resident_id))
    resident = resident_result.scalar_one_or_none()
    if not resident:
        raise HTTPException(status_code=404, detail="입소자를 찾을 수 없습니다.")
    if resident.facility_id != photo.facility_id:
        raise HTTPException(status_code=400, detail="다른 시설의 입소자입니다.")

    # 이미 태그되어 있는지 확인
    existing = await db.execute(
        select(PhotoResident).filter(
            PhotoResident.photo_id == photo_id,
            PhotoResident.resident_id == resident_id,
        )
    )
    if existing.scalar_one_or_none():
        return {"message": "이미 태그된 입소자입니다.", "photo_id": photo_id, "resident_id": resident_id}

    # PhotoResident 생성 (수동 분류는 confidence=1.0)
    pr = PhotoResident(
        photo_id=photo_id,
        resident_id=resident_id,
        confidence=1.0,
    )
    db.add(pr)

    # 사진이 미분류 상태면 분류됨으로 변경
    if not photo.is_processed:
        photo.is_processed = True
        photo.processing_status = "completed"

    await db.commit()

    logger.info(f"[manual-tag] Photo {photo_id} tagged with resident {resident_id} by {current_user['user_id']}")

    return {
        "message": f"'{resident.name}' 태그가 추가되었습니다.",
        "photo_id": photo_id,
        "resident_id": resident_id,
        "resident_name": resident.name,
    }


@router.delete("/{photo_id}/tag/{resident_id}")
async def remove_resident_tag(
    photo_id: str,
    resident_id: str,
    current_user: dict = Depends(get_current_staff),
    db: AsyncSession = Depends(get_db),
):
    """사진에서 입소자 태그 제거"""
    result = await db.execute(
        select(PhotoResident).filter(
            PhotoResident.photo_id == photo_id,
            PhotoResident.resident_id == resident_id,
        )
    )
    pr = result.scalar_one_or_none()
    if not pr:
        raise HTTPException(status_code=404, detail="해당 태그를 찾을 수 없습니다.")

    await db.delete(pr)

    # 남은 태그가 없으면 미분류로 변경
    remaining = await db.execute(
        select(PhotoResident).filter(PhotoResident.photo_id == photo_id)
    )
    if not remaining.scalars().first():
        photo_result = await db.execute(select(Photo).filter(Photo.id == photo_id))
        photo = photo_result.scalar_one_or_none()
        if photo and not photo.resident_id:
            photo.is_processed = False
            photo.processing_status = "pending"

    await db.commit()

    logger.info(f"[manual-tag] Photo {photo_id} untagged resident {resident_id} by {current_user['user_id']}")

    return {"message": "태그가 제거되었습니다.", "photo_id": photo_id, "resident_id": resident_id}


# ==================== 사진 삭제 API ====================


async def _delete_photo(photo: Photo, db: AsyncSession, user_id: str):
    """사진 1건 삭제 — 스토리지 파일 + 관련 DB 레코드 모두 정리"""
    storage = get_storage()

    # 스토리지에서 파일 삭제 (DB에 object key 직접 저장됨)
    for key in [photo.original_url, photo.thumbnail_url]:
        if key:
            try:
                # 기존 full URL 호환: URL이면 key 추출, 아니면 그대로 사용
                actual_key = storage.extract_object_key(key) or key
                await storage.delete_file(actual_key)
            except Exception as e:
                logger.warning(f"[delete] Failed to delete file {key}: {e}")

    # 관련 레코드 삭제 (PhotoResident, PhotoFace, PhotoLike, PhotoShare)
    for model in [PhotoResident, PhotoFace, PhotoLike, PhotoShare]:
        stmt = select(model).filter(model.photo_id == photo.id)
        result = await db.execute(stmt)
        for row in result.scalars().all():
            await db.delete(row)

    # 감사 로그 (삭제 이력)
    db.add(PhotoAuditLog(
        photo_id=photo.id,
        action="delete",
        performed_by=user_id,
    ))

    # 사진 레코드 삭제
    await db.delete(photo)


@router.delete("/{photo_id}")
async def delete_photo(
    photo_id: str,
    current_user: dict = Depends(get_current_staff),
    db: AsyncSession = Depends(get_db),
):
    """사진 단건 삭제 (직원만, 스토리지 파일 + DB 레코드 모두 삭제)"""
    result = await db.execute(select(Photo).filter(Photo.id == photo_id))
    photo = result.scalar_one_or_none()
    if not photo:
        raise HTTPException(status_code=404, detail="사진을 찾을 수 없습니다.")

    verify_facility_access(current_user, photo.facility_id)

    await _delete_photo(photo, db, current_user["user_id"])
    await db.commit()

    logger.info(f"[delete] Photo {photo_id} deleted by {current_user['user_id']}")
    return {"message": "사진이 삭제되었습니다.", "photo_id": photo_id}


@router.post("/bulk-delete")
async def bulk_delete_photos(
    photo_ids: list[str],
    current_user: dict = Depends(get_current_staff),
    db: AsyncSession = Depends(get_db),
):
    """사진 일괄 삭제 (직원만)"""
    deleted = 0
    for pid in photo_ids:
        result = await db.execute(select(Photo).filter(Photo.id == pid))
        photo = result.scalar_one_or_none()
        if photo:
            verify_facility_access(current_user, photo.facility_id)
            await _delete_photo(photo, db, current_user["user_id"])
            deleted += 1

    await db.commit()

    logger.info(f"[bulk-delete] {deleted} photos deleted by {current_user['user_id']}")
    return {"message": f"{deleted}장의 사진이 삭제되었습니다.", "deleted": deleted}


# ==================== 사진 공개/비공개 API ====================


@router.post("/bulk-publish")
async def bulk_publish_photos(
    photo_ids: list[str],
    is_public: bool = True,
    current_user: dict = Depends(get_current_staff),
    db: AsyncSession = Depends(get_db),
):
    """사진 일괄 공개/비공개 처리 (직원만, 감사 로그 포함)"""
    from datetime import datetime as dt

    updated = 0
    action = "publish" if is_public else "unpublish"
    for pid in photo_ids:
        result = await db.execute(select(Photo).filter(Photo.id == pid))
        photo = result.scalar_one_or_none()
        if photo:
            photo.is_public = is_public
            if is_public:
                photo.published_by = current_user["user_id"]
                photo.published_at = dt.utcnow()
            else:
                photo.published_by = None
                photo.published_at = None
            updated += 1

            # 감사 로그
            db.add(PhotoAuditLog(
                photo_id=pid,
                action=action,
                performed_by=current_user["user_id"],
                detail=f"bulk_{action}: {len(photo_ids)} photos",
            ))

    await db.commit()
    return {"message": f"{'공개' if is_public else '비공개'} 처리 완료", "updated": updated}


@router.post("/{photo_id}/publish")
async def toggle_publish(
    photo_id: str,
    current_user: dict = Depends(get_current_staff),
    db: AsyncSession = Depends(get_db),
):
    """사진 공개/비공개 토글 (직원만, 감사 로그 포함)"""
    from datetime import datetime as dt

    result = await db.execute(select(Photo).filter(Photo.id == photo_id))
    photo = result.scalar_one_or_none()
    if not photo:
        raise HTTPException(status_code=404, detail="Photo not found")

    photo.is_public = not photo.is_public
    if photo.is_public:
        photo.published_by = current_user["user_id"]
        photo.published_at = dt.utcnow()
    else:
        photo.published_by = None
        photo.published_at = None

    # 감사 로그
    db.add(PhotoAuditLog(
        photo_id=photo_id,
        action="publish" if photo.is_public else "unpublish",
        performed_by=current_user["user_id"],
    ))

    await db.commit()
    return {"photo_id": photo_id, "is_public": photo.is_public}


# ==================== 좋아요 API ====================


@router.post("/{photo_id}/like")
async def toggle_like(
    photo_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """사진 좋아요 토글 (좋아요 ↔ 취소)"""
    # Rate limit: 사용자당 60회/분 (스팸 좋아요 방지)
    await _enforce_rate_limit(f"like:{current_user['user_id']}", 60)

    # 사진 존재 확인
    photo = await db.execute(select(Photo).filter(Photo.id == photo_id))
    if not photo.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Photo not found")

    # 기존 좋아요 확인
    existing = await db.execute(
        select(PhotoLike).filter(
            PhotoLike.photo_id == photo_id,
            PhotoLike.user_id == current_user["user_id"],
        )
    )
    existing_like = existing.scalar_one_or_none()

    if existing_like:
        # 이미 좋아요 → 취소
        await db.delete(existing_like)
        await db.commit()
        liked = False
    else:
        # 좋아요 추가
        new_like = PhotoLike(
            id=str(uuid.uuid4()),
            photo_id=photo_id,
            user_id=current_user["user_id"],
        )
        db.add(new_like)
        await db.commit()
        liked = True

    # 현재 좋아요 수
    count_result = await db.execute(
        select(func.count(PhotoLike.id)).filter(PhotoLike.photo_id == photo_id)
    )
    like_count = count_result.scalar() or 0

    return {"liked": liked, "like_count": like_count}


@router.get("/{photo_id}/likes")
async def get_photo_likes(
    photo_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """사진의 좋아요 정보 조회"""
    count_result = await db.execute(
        select(func.count(PhotoLike.id)).filter(PhotoLike.photo_id == photo_id)
    )
    like_count = count_result.scalar() or 0

    # 내가 좋아요 했는지
    my_like = await db.execute(
        select(PhotoLike).filter(
            PhotoLike.photo_id == photo_id,
            PhotoLike.user_id == current_user["user_id"],
        )
    )
    liked = my_like.scalar_one_or_none() is not None

    return {"like_count": like_count, "liked": liked}


# ==================== 공유 API ====================


@router.post("/{photo_id}/share")
async def create_share_link(
    photo_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """사진 공유 링크 생성 (만료 시간 포함)"""
    # Rate limit: 사용자당 10회/분 (공유 링크 남발 방지)
    await _enforce_rate_limit(f"share:{current_user['user_id']}", 10)

    from datetime import datetime as dt, timedelta

    photo = await db.execute(select(Photo).filter(Photo.id == photo_id))
    photo_obj = photo.scalar_one_or_none()
    if not photo_obj:
        raise HTTPException(status_code=404, detail="Photo not found")

    settings = get_settings()

    # 공유 토큰 생성 (만료 시간 포함)
    share_token = secrets.token_urlsafe(32)
    expires_at = dt.utcnow() + timedelta(hours=settings.SHARE_LINK_EXPIRE_HOURS)

    share = PhotoShare(
        id=str(uuid.uuid4()),
        photo_id=photo_id,
        user_id=current_user["user_id"],
        share_type="link",
        share_token=share_token,
        expires_at=expires_at,
    )
    db.add(share)
    await db.commit()

    share_url = f"{settings.FRONTEND_URL}/shared/{share_token}"

    # 주의: presigned URL(1h)은 여기서 발급하지 않는다.
    # 공유 수신자는 share_url → /shared/{token}에서 매번 새 presigned URL을 받는다.
    # 발급자에게 1h URL을 돌려주면 클라이언트가 캐싱·노출할 위험 + 72h 공유와 정책 불일치.
    return {
        "share_token": share_token,
        "share_url": share_url,
        "expires_at": expires_at.isoformat(),
    }


@router.get("/shared/{share_token}")
async def get_shared_photo(
    share_token: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """공유 링크로 사진 조회 (인증 불필요, 만료 체크)"""
    # Rate limit: IP당 30회/분 (익명 엔드포인트 — 무작위 토큰 대입 방지)
    client_ip = request.client.host if request.client else "unknown"
    await _enforce_rate_limit(f"share-view:{client_ip}", 30)

    from datetime import datetime as dt

    share_result = await db.execute(
        select(PhotoShare).filter(PhotoShare.share_token == share_token)
    )
    share = share_result.scalar_one_or_none()
    if not share:
        raise HTTPException(status_code=404, detail="공유 링크를 찾을 수 없습니다.")

    # 만료 체크
    if share.expires_at and dt.utcnow() > share.expires_at:
        raise HTTPException(status_code=410, detail="공유 링크가 만료되었습니다.")

    photo_result = await db.execute(
        select(Photo).filter(Photo.id == share.photo_id)
    )
    photo = photo_result.scalar_one_or_none()
    if not photo:
        raise HTTPException(status_code=404, detail="Photo not found")

    # 좋아요 수
    like_count_result = await db.execute(
        select(func.count(PhotoLike.id)).filter(PhotoLike.photo_id == photo.id)
    )
    like_count = like_count_result.scalar() or 0

    from app.core.storage import get_storage
    storage = get_storage()

    return {
        "photo_id": photo.id,
        "original_url": storage.to_presigned(photo.original_url),
        "thumbnail_url": storage.to_presigned(photo.thumbnail_url) if photo.thumbnail_url else None,
        "like_count": like_count,
        "created_at": photo.created_at.isoformat(),
    }
