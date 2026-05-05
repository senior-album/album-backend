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

from fastapi import APIRouter, HTTPException, status, Depends, UploadFile, File, BackgroundTasks
from fastapi.responses import StreamingResponse
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import set_committed_value

from app.core.audit import admin_audit
from app.core.config import get_settings
from app.core.crypto import (
    blind_index,
    decrypt_field,
    encrypt_field,
    generate_dek,
    unwrap_dek,
    wrap_dek,
)
from app.core.database import Database, get_db
from app.core.images import reencode_strip_metadata
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


def _apply_pii_encryption(
    resident: Resident,
    *,
    name: str | None = None,
    birth_date: str | None = None,
    medical_notes: str | None = None,
) -> None:
    """T-003-5a write 경로 — 평문은 인자로 받아 ct / blind-index / DEK 컬럼만 채운다.

    DEK 가 row 에 없으면 새로 생성 + wrap, 있으면 unwrap 해서 재사용. 인자가 None 이면
    해당 ct 컬럼은 손대지 않음 (PUT 의 부분 갱신 / POST 의 옵션 필드 None 보존).

    평문 컬럼 (`resident.name` 등) 은 더 이상 set 하지 않는다 — 호출자가 컬럼에 직접
    값을 넣으면 안 된다는 뜻 (T-003-5b 에서 컬럼 자체 drop 예정). dual-write 시기엔
    `resident.name = ...` 후 이 함수가 호출됐지만, 본 단계부터는 ct-only.
    """
    if resident.dek_wrapped is None:
        dek = generate_dek()
        resident.dek_wrapped = wrap_dek(dek)
    else:
        dek = unwrap_dek(resident.dek_wrapped)
    if name is not None:
        resident.name_ct = encrypt_field(name, dek)
        resident.name_blind_idx = blind_index(name)
    if birth_date is not None:
        resident.birth_date_ct = encrypt_field(birth_date, dek)
    if medical_notes is not None:
        resident.medical_notes_ct = encrypt_field(medical_notes, dek)


def apply_pii_decryption(resident: Resident) -> None:
    """T-003-3 read 경로 — ct 컬럼이 있으면 decrypt 결과로 평문 attribute 를 덮어써서
    응답이 ciphertext 기반으로 흐르게 한다. 백필 전 row (`dek_wrapped` 가 None) 는
    no-op — 평문 컬럼이 그대로 응답으로 흐른다.

    `set_committed_value` 로 ORM dirty flag 를 우회 — 이후 같은 세션에서 commit 이
    일어나도 의도치 않게 평문 컬럼이 재기록되지 않는다 (read 호출이 write 를 유발해선
    안 됨).

    photos / guardians / invitations 모듈에서도 import 해 쓰므로 public (no underscore).
    """
    if resident.dek_wrapped is None:
        return
    dek = unwrap_dek(resident.dek_wrapped)
    if resident.name_ct is not None:
        set_committed_value(resident, "name", decrypt_field(resident.name_ct, dek))
    if resident.birth_date_ct is not None:
        set_committed_value(resident, "birth_date", decrypt_field(resident.birth_date_ct, dek))
    if resident.medical_notes_ct is not None:
        set_committed_value(resident, "medical_notes", decrypt_field(resident.medical_notes_ct, dek))


@router.get("", response_model=list[ResidentResponse])
async def list_residents(
    facility_id: str,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """시설의 모든 입소자 목록"""
    await verify_facility_access(current_user, facility_id, db)
    # T-003-5a: plaintext 컬럼은 새 row 부터 NULL — `ORDER BY Resident.name` 으로
    # 정렬하면 모두 NULL 이라 의미 없음. SELECT 후 decrypt → Python 정렬.
    stmt = select(Resident).filter(
        Resident.facility_id == facility_id,
        Resident.is_active == True,
    )
    result = await db.execute(stmt)
    residents = result.scalars().all()
    for r in residents:
        apply_pii_decryption(r)
    residents = sorted(residents, key=lambda r: r.name or "")
    return [ResidentResponse.model_validate(r) for r in residents]


@router.post("", response_model=ResidentResponse)
async def create_resident(
    resident: ResidentCreate,
    current_user: dict = Depends(get_current_staff),
    db: AsyncSession = Depends(get_db),
):
    """새 입소자 등록 (직원만)"""
    await verify_facility_access(current_user, resident.facility_id, db)
    # T-003-5a: 평문 컬럼은 set 하지 않고 ct 만 채운다.
    new_resident = Resident(
        id=str(uuid.uuid4()),
        facility_id=resident.facility_id,
        code=generate_resident_code(),
        gender=resident.gender,
        room_number=resident.room_number,
    )
    _apply_pii_encryption(
        new_resident,
        name=resident.name,
        birth_date=resident.birth_date,
        medical_notes=resident.medical_notes,
    )
    db.add(new_resident)
    await db.commit()
    await db.refresh(new_resident)
    apply_pii_decryption(new_resident)
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
    await verify_facility_access(current_user, facility_id, db)

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

        # T-003-5a: 평문 컬럼은 set 하지 않고 ct 만 채운다.
        medical_notes = cleaned.get("medical_notes") or None
        new_resident = Resident(
            id=str(uuid.uuid4()),
            facility_id=facility_id,
            code=generate_resident_code(),
            gender=gender,
            room_number=cleaned.get("room_number") or None,
        )
        _apply_pii_encryption(
            new_resident,
            name=name,
            birth_date=birth_date,
            medical_notes=medical_notes,
        )
        db.add(new_resident)
        created.append({"row": idx, "name": name, "id": new_resident.id, "code": new_resident.code})

    try:
        await db.commit()
    except Exception as e:
        await db.rollback()
        logger.error(f"CSV import commit failed: {e}", exc_info=True)
        # T-104: 예외 메시지는 스택/SQL 단편 유출 위험 — 일반 문구만 반환
        raise HTTPException(status_code=500, detail="입소자 저장 중 서버 오류가 발생했습니다.")

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
    apply_pii_decryption(resident)
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

    # T-003-5a: 평문 컬럼은 set 하지 않고 ct 만 갱신한다 (gender / room_number 는
    # 암호화 대상 아니라 모델 컬럼에 직접 set).
    changed_fields: list[str] = []
    if resident_update.name is not None:
        changed_fields.append("name")
    if resident_update.birth_date is not None:
        changed_fields.append("birth_date")
    if resident_update.gender is not None:
        resident.gender = resident_update.gender
        changed_fields.append("gender")
    if resident_update.room_number is not None:
        resident.room_number = resident_update.room_number
        changed_fields.append("room_number")
    if resident_update.medical_notes is not None:
        changed_fields.append("medical_notes")

    _apply_pii_encryption(
        resident,
        name=resident_update.name,
        birth_date=resident_update.birth_date,
        medical_notes=resident_update.medical_notes,
    )

    # T-102: 입소자 정보 수정 — 이름/의료 메모 등 PII 변경. 실제 값 대신
    # 변경된 필드명만 기록 (로그에 PII 재-저장 회피).
    admin_audit(
        db,
        action="resident_update",
        performed_by=current_user["user_id"],
        target_type="resident",
        target_id=resident.id,
        facility_id=resident.facility_id,
        detail=f"fields={','.join(changed_fields) or 'none'}",
    )

    await db.commit()
    await db.refresh(resident)
    apply_pii_decryption(resident)
    return ResidentResponse.model_validate(resident)


async def _reclassify_after_register_face(
    resident_id: str,
    resident_name: str,
    facility_id: str,
    new_reference_embedding: list,
) -> None:
    """
    백그라운드 실행: 새로 등록된 기준 사진으로 facility 내 미분류 얼굴 재분류.

    register-face 요청 응답을 차단하지 않기 위해 BackgroundTasks 로 호출된다.
    실패해도 기준 사진 등록 자체는 이미 커밋된 상태이므로 여기서 raise 하지 않고 로그만 남긴다.
    """
    settings = get_settings()
    try:
        matched = OpenSearchService.reclassify_unmatched(
            facility_id=facility_id,
            new_reference_embedding=new_reference_embedding,
            new_resident_id=resident_id,
            threshold=settings.FACE_SIMILARITY_THRESHOLD,
        )
    except Exception as e:
        logger.error(
            f"[reclassify-bg] resident={resident_id} OpenSearch reclassify failed: {e}",
            exc_info=True,
        )
        return

    if not matched:
        logger.info(f"[reclassify-bg] resident={resident_id} no unmatched faces matched")
        return

    try:
        async with Database.session_scope() as db:
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

            reclassified_count = 0
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

            # session_scope 의 __aexit__ 에서 commit
        logger.info(
            f"[reclassify-bg] resident={resident_id} ({resident_name}) "
            f"reclassified {reclassified_count} photos from {len(matched)} matches"
        )
    except Exception as e:
        logger.error(
            f"[reclassify-bg] resident={resident_id} DB update failed: {e}",
            exc_info=True,
        )


@router.post("/{resident_id}/register-face", status_code=status.HTTP_202_ACCEPTED)
async def register_face(
    resident_id: str,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_staff),
    db: AsyncSession = Depends(get_db),
):
    """
    입소자 기준 사진(얼굴) 등록.

    1. 사진에서 얼굴 임베딩 추출
    2. MinIO 저장 + OpenSearch reference embedding 등록 — 여기까지가 동기 처리
    3. 기존 미분류 사진 재분류는 BackgroundTasks 로 비동기 처리 (202 반환 후 실행)

    이후 사진 업로드 시 이 임베딩과 비교되어 자동 분류됨.
    """
    # 입소자 확인
    stmt = select(Resident).filter(Resident.id == resident_id)
    result = await db.execute(stmt)
    resident = result.scalar_one_or_none()
    if not resident:
        raise HTTPException(status_code=404, detail="Resident not found")
    apply_pii_decryption(resident)

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

    # T-051 재인코딩 + EXIF/메타데이터 strip — 저장 전에 원본 정화
    sanitized_data, sanitized_ext, sanitized_mime = reencode_strip_metadata(file_content)

    # 사진을 MinIO에 저장 (고유 파일명 사용)
    storage = get_storage()
    unique_id = uuid.uuid4().hex[:8]
    object_key = await storage.upload_file(
        file_data=sanitized_data,
        filename=f"face_{resident_id}_{unique_id}.{sanitized_ext}",
        content_type=sanitized_mime,
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

    # 미분류 사진 재분류는 백그라운드에서 — 응답을 차단하지 않는다
    background_tasks.add_task(
        _reclassify_after_register_face,
        resident_id=resident_id,
        resident_name=resident.name,
        facility_id=resident.facility_id,
        new_reference_embedding=embedding,
    )

    return {
        "message": "Face registered successfully",
        "resident_id": resident_id,
        "resident_name": resident.name,
        "embedding_id": doc_id,
        "photo_url": storage.to_presigned(object_key),
        # 재분류는 비동기 — 응답 시점엔 결과를 알 수 없음. 하위 호환을 위해 null 유지.
        "reclassified_photos": None,
        "reclassification_status": "scheduled",
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
    apply_pii_decryption(resident)

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
    db: AsyncSession = Depends(get_db),
):
    """등록된 기준 사진 삭제"""
    try:
        OpenSearchService.delete_embedding(doc_id)
    except Exception as e:
        logger.error(f"Failed to delete face: {e}", exc_info=True)
        # T-104: OpenSearch 예외 메시지(인덱스명/쿼리 등) 유출 방지
        raise HTTPException(status_code=500, detail="얼굴 삭제 중 서버 오류가 발생했습니다.")

    # T-102: 기준 사진 삭제는 분류 결과 전체에 영향을 줄 수 있어 감사 대상.
    admin_audit(
        db,
        action="resident_face_delete",
        performed_by=current_user["user_id"],
        target_type="resident",
        target_id=resident_id,
        facility_id=current_user.get("facility_id"),
        detail=f"embedding_doc_id={doc_id}",
    )
    await db.commit()

    return {"message": "Face deleted successfully", "doc_id": doc_id}


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
