"""
사진 처리 백그라운드 워커
- photo_processing_jobs 테이블에서 pending 작업을 폴링
- 얼굴 감지 → OpenSearch kNN 검색 → 자동 분류
- 주기적으로 실행 (asyncio.create_task)
"""

import uuid
import asyncio
import logging
from io import BytesIO
from datetime import datetime

import numpy as np
from PIL import Image as PILImage
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import Database
from app.core.storage import get_storage
from app.models.models import Photo, PhotoFace, PhotoResident, PhotoProcessingJob
from app.services.discord_notifier import send_ops_alert
from app.services.face_recognition import FaceService
from app.services.opensearch_service import OpenSearchService

logger = logging.getLogger(__name__)

# 워커 상태
_worker_task: asyncio.Task | None = None
POLL_INTERVAL = 3  # 초


async def process_single_photo(photo: Photo, facility_id: str, db: AsyncSession):
    """단일 사진 얼굴 감지 + 분류 처리"""
    settings = get_settings()
    storage = get_storage()

    # 사진 원본 데이터 다운로드
    file_data = await storage.download_file(photo.original_url)
    if file_data is None:
        raise Exception(f"Failed to download photo: {photo.original_url}")

    image_array = np.array(PILImage.open(BytesIO(file_data)).convert("RGB"))
    logger.info(f"[Worker] Processing photo {photo.id}, image shape: {image_array.shape}")

    faces_data = FaceService.detect_faces(image_array)
    logger.info(f"[Worker] Detected {len(faces_data)} faces in photo {photo.id}")

    matched_resident_id = None
    resident_confidence: dict[str, float] = {}

    for i, face in enumerate(faces_data):
        embedding = face["embedding"]
        bbox = face["bbox"]

        if embedding is None:
            logger.warning(f"[Worker] Face {i}: embedding is None, skipping")
            continue

        # OpenSearch kNN 검색
        try:
            matches = OpenSearchService.search_similar(
                embedding=embedding,
                facility_id=facility_id,
                k=3,
                threshold=settings.FACE_SIMILARITY_THRESHOLD,
            )
        except Exception as e:
            logger.error(f"[Worker] Face {i}: OpenSearch search failed: {e}")
            matches = []

        face_resident_id = None
        confidence = 0.0

        if matches:
            face_resident_id = matches[0][0]
            confidence = matches[0][1]
            if face_resident_id not in resident_confidence or confidence > resident_confidence[face_resident_id]:
                resident_confidence[face_resident_id] = confidence
            if matched_resident_id is None:
                matched_resident_id = face_resident_id

        # PhotoFace 레코드
        face_id = str(uuid.uuid4())
        embedding_doc_id = str(uuid.uuid4())

        photo_face = PhotoFace(
            id=face_id,
            photo_id=photo.id,
            resident_id=face_resident_id,
            bbox_x1=bbox[0],
            bbox_y1=bbox[1],
            bbox_x2=bbox[2],
            bbox_y2=bbox[3],
            embedding_id=embedding_doc_id,
            confidence=confidence if confidence > 0 else 0.5,
            is_confirmed=confidence >= 0.8,
            is_rejected=False,
        )
        db.add(photo_face)

        # OpenSearch에 임베딩 저장
        try:
            OpenSearchService.store_embedding(
                doc_id=embedding_doc_id,
                embedding=embedding,
                resident_id=face_resident_id or "",
                facility_id=facility_id,
                photo_id=photo.id,
                face_id=face_id,
                is_reference=False,
            )
        except Exception as e:
            logger.warning(f"[Worker] Failed to store embedding: {e}")

    # Photo 업데이트
    photo.is_processed = len(faces_data) > 0
    if matched_resident_id:
        photo.resident_id = matched_resident_id
        photo.processing_status = "classified"
    elif len(faces_data) > 0:
        photo.processing_status = "detected_unmatched"
    else:
        photo.processing_status = "no_face"

    # PhotoResident 다대다 레코드
    for rid, conf in resident_confidence.items():
        pr = PhotoResident(
            id=str(uuid.uuid4()),
            photo_id=photo.id,
            resident_id=rid,
            confidence=conf,
        )
        db.add(pr)

    logger.info(
        f"[Worker] Photo {photo.id} processed: "
        f"faces={len(faces_data)}, residents={len(resident_confidence)}, "
        f"status={photo.processing_status}"
    )


async def poll_and_process():
    """pending 작업을 하나씩 가져와서 처리"""
    async with Database.session_scope() as db:
        # pending 작업 1개 가져오기 (FIFO)
        stmt = (
            select(PhotoProcessingJob)
            .filter(PhotoProcessingJob.status == "pending")
            .order_by(PhotoProcessingJob.created_at)
            .limit(1)
        )
        result = await db.execute(stmt)
        job = result.scalar_one_or_none()

        if not job:
            return False  # 처리할 작업 없음

        # 상태를 processing으로 변경
        job.status = "processing"
        job.started_at = datetime.utcnow()
        await db.commit()

        failure_reason: str | None = None

        try:
            # 사진 조회
            photo_result = await db.execute(
                select(Photo).filter(Photo.id == job.photo_id)
            )
            photo = photo_result.scalar_one_or_none()

            if not photo:
                job.status = "failed"
                job.error_message = "Photo not found"
                job.completed_at = datetime.utcnow()
                failure_reason = "Photo not found"
                await db.commit()
                await _notify_job_failed(job, failure_reason)
                return True

            if not FaceService.is_available():
                job.status = "failed"
                job.error_message = "Face recognition model not available"
                job.completed_at = datetime.utcnow()
                photo.processing_status = "no_model"
                failure_reason = "Face recognition model not available"
                await db.commit()
                await _notify_job_failed(job, failure_reason)
                return True

            # 실제 처리
            await process_single_photo(photo, job.facility_id, db)

            job.status = "completed"
            job.completed_at = datetime.utcnow()
            await db.commit()

        except Exception as e:
            logger.error(f"[Worker] Job {job.id} failed: {e}", exc_info=True)
            job.retry_count += 1
            if job.retry_count >= job.max_retries:
                job.status = "failed"
                job.error_message = str(e)[:500]
                job.completed_at = datetime.utcnow()
                failure_reason = f"retry exhausted ({job.retry_count}/{job.max_retries}): {str(e)[:200]}"
            else:
                job.status = "pending"  # 재시도
                job.error_message = f"Retry {job.retry_count}: {str(e)[:300]}"
            await db.commit()
            if failure_reason:
                await _notify_job_failed(job, failure_reason)

        return True


async def _notify_job_failed(job: PhotoProcessingJob, reason: str) -> None:
    """T-041: 사진 처리 작업이 영구 실패 했을 때 운영 채널로 알림.

    Discord 미설정이면 no-op. 알림 자체 실패는 swallow (notifier 가 raise 안 함).
    """
    await send_ops_alert(
        title="Photo processing job failed",
        message=f"Job {job.id} dropped after retries.",
        level="error",
        fields={
            "job_id": job.id,
            "photo_id": job.photo_id,
            "facility_id": job.facility_id,
            "retry_count": f"{job.retry_count}/{job.max_retries}",
            "reason": reason,
        },
    )


async def worker_loop():
    """메인 워커 루프"""
    logger.info("[Worker] Photo processing worker started")

    while True:
        try:
            had_work = await poll_and_process()
            if not had_work:
                await asyncio.sleep(POLL_INTERVAL)
            else:
                # 작업이 있었으면 바로 다음 작업 확인
                await asyncio.sleep(0.1)
        except asyncio.CancelledError:
            logger.info("[Worker] Worker loop cancelled")
            break
        except Exception as e:
            logger.error(f"[Worker] Unexpected error in worker loop: {e}", exc_info=True)
            await asyncio.sleep(POLL_INTERVAL * 2)


def start_worker():
    """워커를 asyncio 태스크로 시작"""
    global _worker_task
    if _worker_task is None or _worker_task.done():
        _worker_task = asyncio.create_task(worker_loop())
        logger.info("[Worker] Photo processing worker task created")


def stop_worker():
    """워커 중지"""
    global _worker_task
    if _worker_task and not _worker_task.done():
        _worker_task.cancel()
        logger.info("[Worker] Photo processing worker task cancelled")
