"""
입소자 관리 API 엔드포인트
CRUD 및 얼굴 등록 (OpenSearch 임베딩 저장)
"""

import uuid
import os
import logging
from io import BytesIO
import numpy as np
from PIL import Image as PILImage

from fastapi import APIRouter, HTTPException, status, Depends, UploadFile, File
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import get_current_user, get_current_staff, verify_facility_access
from app.core.storage import get_storage
from app.models.models import Resident, Photo, PhotoFace, PhotoResident
from app.schemas.schemas import (
    ResidentCreate,
    ResidentUpdate,
    ResidentResponse,
    ResidentDetailResponse,
    PhotoResponse,
    MatchedResidentInfo,
)
from app.services.face_recognition import FaceService
from app.services.opensearch_service import OpenSearchService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/residents", tags=["residents"])


def generate_resident_code() -> str:
    """입소자 코드 생성 (RES-XXXXXX)"""
    return f"RES-{uuid.uuid4().hex[:6].upper()}"


@router.get("", response_model=list[ResidentResponse])
async def list_residents(
    facility_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """시설의 모든 입소자 목록"""
    verify_facility_access(current_user, facility_id)
    stmt = select(Resident).filter(
        Resident.facility_id == facility_id,
        Resident.is_active == True,
    ).order_by(Resident.name)
    result = await db.execute(stmt)
    residents = result.scalars().all()
    return [ResidentResponse.model_validate(r) for r in residents]


@router.post("", response_model=ResidentResponse)
async def create_resident(
    resident: ResidentCreate,
    current_user: dict = Depends(get_current_staff),
    db: AsyncSession = Depends(get_db),
):
    """새 입소자 등록 (직원만)"""
    verify_facility_access(current_user, resident.facility_id)
    new_resident = Resident(
        id=str(uuid.uuid4()),
        facility_id=resident.facility_id,
        code=generate_resident_code(),
        name=resident.name,
        birth_date=resident.birth_date,
        gender=resident.gender,
        room_number=resident.room_number,
        medical_notes=resident.medical_notes,
    )
    db.add(new_resident)
    await db.commit()
    await db.refresh(new_resident)
    return ResidentResponse.model_validate(new_resident)


@router.get("/{resident_id}", response_model=ResidentDetailResponse)
async def get_resident(
    resident_id: str,
    db: AsyncSession = Depends(get_db),
):
    """입소자 상세 조회"""
    stmt = select(Resident).filter(Resident.id == resident_id)
    result = await db.execute(stmt)
    resident = result.scalar_one_or_none()
    if not resident:
        raise HTTPException(status_code=404, detail="Resident not found")
    return ResidentDetailResponse.model_validate(resident)


@router.put("/{resident_id}", response_model=ResidentResponse)
async def update_resident(
    resident_id: str,
    resident_update: ResidentUpdate,
    current_user: dict = Depends(get_current_staff),
    db: AsyncSession = Depends(get_db),
):
    """입소자 정보 수정 (직원만)"""
    stmt = select(Resident).filter(Resident.id == resident_id)
    result = await db.execute(stmt)
    resident = result.scalar_one_or_none()
    if not resident:
        raise HTTPException(status_code=404, detail="Resident not found")

    if resident_update.name is not None:
        resident.name = resident_update.name
    if resident_update.birth_date is not None:
        resident.birth_date = resident_update.birth_date
    if resident_update.gender is not None:
        resident.gender = resident_update.gender
    if resident_update.room_number is not None:
        resident.room_number = resident_update.room_number
    if resident_update.medical_notes is not None:
        resident.medical_notes = resident_update.medical_notes

    await db.commit()
    await db.refresh(resident)
    return ResidentResponse.model_validate(resident)


@router.post("/{resident_id}/register-face")
async def register_face(
    resident_id: str,
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_staff),
    db: AsyncSession = Depends(get_db),
):
    """
    입소자 기준 사진(얼굴) 등록
    1. 사진에서 얼굴 임베딩 추출
    2. OpenSearch에 reference embedding으로 저장
    3. 이후 사진 업로드 시 이 임베딩과 비교하여 자동 분류
    """
    # 입소자 확인
    stmt = select(Resident).filter(Resident.id == resident_id)
    result = await db.execute(stmt)
    resident = result.scalar_one_or_none()
    if not resident:
        raise HTTPException(status_code=404, detail="Resident not found")

    if not FaceService.is_available():
        raise HTTPException(
            status_code=503,
            detail="Face recognition service not available. Install: pip install face_recognition",
        )

    # 파일 읽기 + 얼굴 임베딩 추출
    file_content = await file.read()
    image = PILImage.open(BytesIO(file_content)).convert("RGB")
    image_array = np.array(image)

    embedding = FaceService.extract_single_embedding(image_array)
    if embedding is None:
        raise HTTPException(
            status_code=400,
            detail="No face detected in the image. Please upload a clear face photo.",
        )

    # 사진을 MinIO에 저장 (고유 파일명 사용)
    storage = get_storage()
    file_ext = os.path.splitext(file.filename)[1] if file.filename else ".jpg"
    unique_id = uuid.uuid4().hex[:8]
    object_key = await storage.upload_file(
        file_data=file_content,
        filename=f"face_{resident_id}_{unique_id}{file_ext}",
        content_type=file.content_type or "image/jpeg",
        facility_id=f"{resident.facility_id}/faces",
    )
    photo_url = storage.get_url(object_key)

    # OpenSearch에 reference embedding 저장 (photo_url 포함)
    doc_id = str(uuid.uuid4())
    OpenSearchService.store_embedding(
        doc_id=doc_id,
        embedding=embedding,
        resident_id=resident_id,
        facility_id=resident.facility_id,
        photo_url=photo_url,
        is_reference=True,
    )

    # 자동 재분류: 미분류 사진들을 새 기준 사진과 비교
    settings = get_settings()
    reclassified_count = 0
    try:
        matched = OpenSearchService.reclassify_unmatched(
            facility_id=resident.facility_id,
            new_reference_embedding=embedding,
            new_resident_id=resident_id,
            threshold=settings.FACE_SIMILARITY_THRESHOLD,
        )

        if matched:
            # DB에서 Photo, PhotoFace, PhotoResident 레코드 업데이트
            for m in matched:
                photo_id = m.get("photo_id")
                face_id = m.get("face_id")

                if face_id:
                    face_stmt = select(PhotoFace).filter(PhotoFace.id == face_id)
                    face_result = await db.execute(face_stmt)
                    photo_face = face_result.scalar_one_or_none()
                    if photo_face and not photo_face.resident_id:
                        photo_face.resident_id = resident_id
                        photo_face.confidence = m["score"]
                        photo_face.is_confirmed = m["score"] >= 0.8

                if photo_id:
                    photo_stmt = select(Photo).filter(Photo.id == photo_id)
                    photo_result = await db.execute(photo_stmt)
                    photo = photo_result.scalar_one_or_none()
                    if photo:
                        # 하위 호환: Photo.resident_id 설정
                        if not photo.resident_id:
                            photo.resident_id = resident_id
                        photo.processing_status = "classified"
                        reclassified_count += 1

                        # PhotoResident 다대다 레코드 생성 (중복 방지)
                        existing_pr = await db.execute(
                            select(PhotoResident).filter(
                                PhotoResident.photo_id == photo_id,
                                PhotoResident.resident_id == resident_id,
                            )
                        )
                        if not existing_pr.scalar_one_or_none():
                            pr = PhotoResident(
                                id=str(uuid.uuid4()),
                                photo_id=photo_id,
                                resident_id=resident_id,
                                confidence=m["score"],
                            )
                            db.add(pr)

            await db.commit()
            logger.info(f"Auto-reclassified {reclassified_count} photos for resident {resident.name}")
    except Exception as e:
        logger.error(f"Auto-reclassification failed: {e}", exc_info=True)
        # 재분류 실패해도 기준 사진 등록 자체는 성공

    return {
        "message": "Face registered successfully",
        "resident_id": resident_id,
        "resident_name": resident.name,
        "embedding_id": doc_id,
        "photo_url": photo_url,
        "reclassified_photos": reclassified_count,
    }


@router.get("/{resident_id}/faces")
async def get_resident_faces(
    resident_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """입소자의 등록된 기준 사진(얼굴) 목록 조회"""
    # 입소자 확인
    stmt = select(Resident).filter(Resident.id == resident_id)
    result = await db.execute(stmt)
    resident = result.scalar_one_or_none()
    if not resident:
        raise HTTPException(status_code=404, detail="Resident not found")

    try:
        faces = OpenSearchService.get_reference_faces(
            resident_id=resident_id,
            facility_id=resident.facility_id,
        )
        return {
            "resident_id": resident_id,
            "resident_name": resident.name,
            "face_count": len(faces),
            "faces": faces,
        }
    except Exception as e:
        logger.error(f"Failed to get reference faces: {e}")
        return {
            "resident_id": resident_id,
            "resident_name": resident.name,
            "face_count": 0,
            "faces": [],
        }


@router.delete("/{resident_id}/faces/{doc_id}")
async def delete_resident_face(
    resident_id: str,
    doc_id: str,
    current_user: dict = Depends(get_current_staff),
):
    """등록된 기준 사진 삭제"""
    try:
        OpenSearchService.delete_embedding(doc_id)
        return {"message": "Face deleted successfully", "doc_id": doc_id}
    except Exception as e:
        logger.error(f"Failed to delete face: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to delete face: {str(e)}")


@router.get("/{resident_id}/photos", response_model=list[PhotoResponse])
async def get_resident_photos(
    resident_id: str,
    skip: int = 0,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
):
    """입소자의 모든 사진 조회 (다대다 지원, 최신순)"""
    from sqlalchemy import union_all

    # PhotoResident 다대다 + 기존 Photo.resident_id 모두 조회
    pr_ids = (
        select(Photo.id)
        .join(PhotoResident, Photo.id == PhotoResident.photo_id)
        .filter(PhotoResident.resident_id == resident_id)
    )
    legacy_ids = select(Photo.id).filter(Photo.resident_id == resident_id)
    combined = union_all(pr_ids, legacy_ids).subquery()

    stmt = (
        select(Photo)
        .filter(Photo.id.in_(select(combined.c.id)))
        .order_by(desc(Photo.created_at))
        .offset(skip)
        .limit(limit)
    )
    result = await db.execute(stmt)
    photos = result.scalars().all()
    return [PhotoResponse.model_validate(p) for p in photos]
