"""
입소자 관리 API 엔드포인트
CRUD 및 얼굴 등록 (OpenSearch 임베딩 저장)
"""

import uuid
import os
import csv
import io
import logging
from io import BytesIO
import numpy as np
from PIL import Image as PILImage

from fastapi import APIRouter, HTTPException, status, Depends, UploadFile, File
from fastapi.responses import StreamingResponse
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


CSV_IMPORT_MAX_ROWS = 100
CSV_TEMPLATE_HEADERS = ["name", "birth_date", "gender", "room_number", "medical_notes"]
_VALID_GENDERS = {"M", "F", "남", "여", "남성", "여성"}


def _normalize_gender(raw: str | None) -> str | None:
    """성별 표기 정규화 — 'M'/'F'로 통일. 값이 없으면 None."""
    if not raw:
        return None
    s = raw.strip().upper()
    if s in {"M", "남", "남성"}:
        return "M"
    if s in {"F", "여", "여성"}:
        return "F"
    return None


def _normalize_birth_date(raw: str | None) -> str | None:
    """생년월일 정규화 — 'YYYY-MM-DD' 또는 'YYYY' 허용. 잘못된 형식은 ValueError."""
    if not raw:
        return None
    s = raw.strip()
    if not s:
        return None
    # 주민번호 뒷자리 포함 방지 — '-'로 시작하는 2번째 그룹이 7자리면 거부
    if "-" in s:
        parts = s.split("-")
        if len(parts) == 2 and len(parts[1]) >= 7:
            raise ValueError("주민등록번호 형식은 허용되지 않습니다. 생년월일만 입력하세요.")
    # YYYY 단독
    if len(s) == 4 and s.isdigit():
        return s
    # YYYY-MM-DD
    if len(s) == 10 and s[4] == "-" and s[7] == "-":
        try:
            from datetime import date
            y, m, d = int(s[:4]), int(s[5:7]), int(s[8:10])
            date(y, m, d)
            return s
        except Exception:
            raise ValueError(f"올바른 날짜 형식이 아닙니다: {s}")
    # YYYYMMDD
    if len(s) == 8 and s.isdigit():
        try:
            from datetime import date
            y, m, d = int(s[:4]), int(s[4:6]), int(s[6:8])
            date(y, m, d)
            return f"{y:04d}-{m:02d}-{d:02d}"
        except Exception:
            raise ValueError(f"올바른 날짜 형식이 아닙니다: {s}")
    raise ValueError(f"지원하지 않는 생년월일 형식: {s} (허용: YYYY-MM-DD, YYYYMMDD, YYYY)")


@router.get("/import/template")
async def download_csv_template(
    current_user: dict = Depends(get_current_staff),
):
    """입소자 일괄 import용 CSV 템플릿 다운로드 (주민번호 뒷자리 제외, UTF-8 BOM for Excel)."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(CSV_TEMPLATE_HEADERS)
    writer.writerow(["홍길동", "1940-03-15", "M", "101호", "고혈압"])
    writer.writerow(["김순자", "1945", "F", "102호", ""])
    writer.writerow(["박철수", "", "M", "", "당뇨"])
    # Excel 호환을 위해 UTF-8 BOM 삽입
    payload = "﻿" + buf.getvalue()
    return StreamingResponse(
        iter([payload.encode("utf-8")]),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="residents_template.csv"'},
    )


@router.post("/import")
async def import_residents_csv(
    facility_id: str,
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_staff),
    db: AsyncSession = Depends(get_db),
):
    """
    입소자 CSV 일괄 등록 (최대 100명/요청).
    헤더: name, birth_date, gender, room_number, medical_notes
    - name: 필수
    - birth_date: YYYY-MM-DD / YYYYMMDD / YYYY (선택)
    - gender: M, F, 남, 여 (선택)
    - 주민등록번호 뒷자리는 저장하지 않습니다 — 뒷자리 포함 시 해당 행은 거부됩니다.
    """
    verify_facility_access(current_user, facility_id)

    # 파일 크기 제한 (1MB — 100명 넉넉히 수용)
    raw = await file.read()
    if len(raw) > 1 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="CSV 파일은 1MB 이하만 허용됩니다.")

    # BOM 및 인코딩 처리
    text: str
    for enc in ("utf-8-sig", "utf-8", "cp949", "euc-kr"):
        try:
            text = raw.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    else:
        raise HTTPException(status_code=400, detail="CSV 인코딩을 해석할 수 없습니다. UTF-8 또는 CP949로 저장해주세요.")

    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise HTTPException(status_code=400, detail="CSV 헤더가 없습니다.")

    normalized_headers = [h.strip().lower() for h in reader.fieldnames]
    if "name" not in normalized_headers:
        raise HTTPException(status_code=400, detail="헤더에 'name' 컬럼이 반드시 있어야 합니다.")

    created: list[dict] = []
    errors: list[dict] = []
    rows_seen = 0

    for idx, row in enumerate(reader, start=2):  # row 1은 헤더
        rows_seen += 1
        if rows_seen > CSV_IMPORT_MAX_ROWS:
            errors.append({"row": idx, "reason": f"최대 {CSV_IMPORT_MAX_ROWS}명까지만 등록 가능합니다. 초과분 무시."})
            break

        cleaned = {k.strip().lower(): (v or "").strip() for k, v in row.items() if k}
        name = cleaned.get("name", "")
        if not name:
            errors.append({"row": idx, "reason": "name 누락"})
            continue

        try:
            birth_date = _normalize_birth_date(cleaned.get("birth_date"))
        except ValueError as e:
            errors.append({"row": idx, "name": name, "reason": str(e)})
            continue

        gender_raw = cleaned.get("gender")
        if gender_raw and gender_raw not in _VALID_GENDERS:
            # 정규화 시도
            pass
        gender = _normalize_gender(gender_raw)
        if gender_raw and gender is None:
            errors.append({"row": idx, "name": name, "reason": f"성별 값이 유효하지 않음: {gender_raw}"})
            continue

        new_resident = Resident(
            id=str(uuid.uuid4()),
            facility_id=facility_id,
            code=generate_resident_code(),
            name=name,
            birth_date=birth_date,
            gender=gender,
            room_number=cleaned.get("room_number") or None,
            medical_notes=cleaned.get("medical_notes") or None,
        )
        db.add(new_resident)
        created.append({"row": idx, "name": name, "id": new_resident.id, "code": new_resident.code})

    try:
        await db.commit()
    except Exception as e:
        await db.rollback()
        logger.error(f"CSV import commit failed: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"DB 저장 실패: {e}")

    logger.info(
        f"[csv-import] facility={facility_id} created={len(created)} errors={len(errors)} by={current_user['user_id']}"
    )
    return {
        "message": f"{len(created)}명 등록 완료 · {len(errors)}건 오류",
        "created_count": len(created),
        "error_count": len(errors),
        "created": created,
        "errors": errors,
    }


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
    # OpenSearch에 reference embedding 저장 (object key 저장)
    doc_id = str(uuid.uuid4())
    OpenSearchService.store_embedding(
        doc_id=doc_id,
        embedding=embedding,
        resident_id=resident_id,
        facility_id=resident.facility_id,
        photo_url=object_key,
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
            # 매치 전체의 face/photo id 를 한 번에 조회해 N+1 제거
            face_ids = {m["face_id"] for m in matched if m.get("face_id")}
            photo_ids = {m["photo_id"] for m in matched if m.get("photo_id")}

            photo_faces: dict = {}
            if face_ids:
                face_result = await db.execute(
                    select(PhotoFace).filter(PhotoFace.id.in_(face_ids))
                )
                photo_faces = {pf.id: pf for pf in face_result.scalars().all()}

            photos: dict = {}
            existing_pr_photo_ids: set = set()
            if photo_ids:
                photo_result = await db.execute(
                    select(Photo).filter(Photo.id.in_(photo_ids))
                )
                photos = {p.id: p for p in photo_result.scalars().all()}

                existing_pr_result = await db.execute(
                    select(PhotoResident.photo_id).filter(
                        PhotoResident.photo_id.in_(photo_ids),
                        PhotoResident.resident_id == resident_id,
                    )
                )
                existing_pr_photo_ids = set(existing_pr_result.scalars().all())

            for m in matched:
                photo_id = m.get("photo_id")
                face_id = m.get("face_id")
                score = m["score"]

                if face_id:
                    photo_face = photo_faces.get(face_id)
                    if photo_face and not photo_face.resident_id:
                        photo_face.resident_id = resident_id
                        photo_face.confidence = score
                        photo_face.is_confirmed = score >= 0.8

                if photo_id:
                    photo = photos.get(photo_id)
                    if photo:
                        # 하위 호환: Photo.resident_id 설정
                        if not photo.resident_id:
                            photo.resident_id = resident_id
                        photo.processing_status = "classified"
                        reclassified_count += 1

                        # PhotoResident 다대다 레코드 생성 (중복 방지, 배치 내 중복도 차단)
                        if photo_id not in existing_pr_photo_ids:
                            pr = PhotoResident(
                                id=str(uuid.uuid4()),
                                photo_id=photo_id,
                                resident_id=resident_id,
                                confidence=score,
                            )
                            db.add(pr)
                            existing_pr_photo_ids.add(photo_id)

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
        "photo_url": storage.to_presigned(object_key),
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
        # face의 photo_url을 presigned URL로 변환
        storage = get_storage()
        for face in faces:
            if face.get("photo_url"):
                face["photo_url"] = storage.to_presigned(face["photo_url"])
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

    from app.core.storage import get_storage
    storage = get_storage()
    responses = []
    for p in photos:
        resp = PhotoResponse.model_validate(p)
        resp.original_url = storage.to_presigned(resp.original_url)
        if resp.thumbnail_url:
            resp.thumbnail_url = storage.to_presigned(resp.thumbnail_url)
        responses.append(resp)
    return responses
