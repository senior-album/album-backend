"""
사진 처리 서비스
S3 업로드, 썸네일 생성, 얼굴 감지
"""

import logging
import uuid
from typing import Optional, Tuple
from io import BytesIO
import numpy as np

from app.core.config import get_settings

logger = logging.getLogger(__name__)

# AWS S3 클라이언트 (선택적)
try:
    import boto3
    S3_AVAILABLE = True
except ImportError:
    S3_AVAILABLE = False
    logger.warning("boto3 not available - S3 upload disabled")

# Pillow 이미지 처리
try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    logger.warning("Pillow not available - image processing disabled")


class PhotoService:
    """사진 처리 서비스"""

    def __init__(self):
        """서비스 초기화"""
        self.settings = get_settings()
        self.s3_client = None

        if S3_AVAILABLE and self.settings.AWS_ACCESS_KEY_ID:
            try:
                self.s3_client = boto3.client(
                    "s3",
                    aws_access_key_id=self.settings.AWS_ACCESS_KEY_ID,
                    aws_secret_access_key=self.settings.AWS_SECRET_ACCESS_KEY,
                    region_name=self.settings.AWS_REGION,
                )
                logger.info("S3 client initialized")
            except Exception as e:
                logger.error(f"Failed to initialize S3 client: {e}")
                self.s3_client = None
        else:
            logger.warning("S3 credentials not configured - using local storage")

    async def upload_to_s3(
        self,
        file_content: bytes,
        key: str,
    ) -> str:
        """
        S3에 파일 업로드

        Args:
            file_content: 파일 바이트
            key: S3 객체 키 (경로)

        Returns:
            S3 URL 또는 로컬 경로
        """
        if not self.s3_client:
            logger.warning("S3 client not available, using mock URL")
            return f"s3://{self.settings.AWS_S3_BUCKET}/{key}"

        try:
            self.s3_client.put_object(
                Bucket=self.settings.AWS_S3_BUCKET,
                Key=key,
                Body=file_content,
                ContentType="image/jpeg",
            )

            # URL 생성
            url = f"https://{self.settings.AWS_S3_BUCKET}.s3.{self.settings.AWS_REGION}.amazonaws.com/{key}"
            logger.info(f"File uploaded to S3: {url}")
            return url

        except Exception as e:
            logger.error(f"S3 upload failed: {e}")
            raise

    async def generate_thumbnail(
        self,
        image_content: bytes,
        size: Tuple[int, int] = (200, 200),
    ) -> Optional[bytes]:
        """
        이미지 썸네일 생성

        Args:
            image_content: 원본 이미지 바이트
            size: 썸네일 크기 (너비, 높이)

        Returns:
            썸네일 이미지 바이트 또는 None
        """
        if not PIL_AVAILABLE:
            logger.warning("PIL not available - thumbnail generation skipped")
            return None

        try:
            # 이미지 열기
            image = Image.open(BytesIO(image_content))

            # RGBA → RGB 변환
            if image.mode in ("RGBA", "LA", "P"):
                rgb_image = Image.new("RGB", image.size, (255, 255, 255))
                rgb_image.paste(image, mask=image.split()[-1] if image.mode == "RGBA" else None)
                image = rgb_image

            # 썸네일 생성
            image.thumbnail(size, Image.Resampling.LANCZOS)

            # 바이트로 변환
            thumbnail_io = BytesIO()
            image.save(thumbnail_io, format="JPEG", quality=85)
            thumbnail_io.seek(0)

            logger.debug(f"Thumbnail generated: {size}")
            return thumbnail_io.getvalue()

        except Exception as e:
            logger.error(f"Thumbnail generation failed: {e}")
            return None

    def convert_pil_to_numpy(self, image: Image.Image) -> np.ndarray:
        """
        PIL Image를 numpy 배열로 변환

        Args:
            image: PIL Image 객체

        Returns:
            BGR numpy 배열 (InsightFace 호환)
        """
        try:
            array = np.array(image)

            # RGB → BGR 변환
            if len(array.shape) == 3 and array.shape[2] == 3:
                array = array[..., ::-1]

            return array

        except Exception as e:
            logger.error(f"Image conversion failed: {e}")
            return None

    async def process_uploaded_file(
        self,
        file_content: bytes,
        facility_id: str,
    ) -> Tuple[str, Optional[str]]:
        """
        업로드된 파일 처리 (S3 저장, 썸네일 생성)

        Args:
            file_content: 파일 바이트
            facility_id: 시설 ID

        Returns:
            (original_url, thumbnail_url) 튜플
        """
        try:
            # 파일명 생성
            file_id = str(uuid.uuid4())
            file_key = f"photos/{facility_id}/{file_id}.jpg"

            # S3 업로드
            original_url = await self.upload_to_s3(file_content, file_key)

            # 썸네일 생성 및 업로드
            thumbnail_content = await self.generate_thumbnail(file_content)
            thumbnail_url = None

            if thumbnail_content:
                thumbnail_key = f"thumbnails/{facility_id}/{file_id}.jpg"
                thumbnail_url = await self.upload_to_s3(thumbnail_content, thumbnail_key)

            return original_url, thumbnail_url

        except Exception as e:
            logger.error(f"File processing failed: {e}")
            raise


class LocalStorageService:
    """로컬 저장소 서비스 (S3 대체용)"""

    def __init__(self, base_path: str = "/tmp/senior-album"):
        """
        로컬 저장소 초기화

        Args:
            base_path: 로컬 저장 경로
        """
        self.base_path = base_path

    async def upload_file(
        self,
        file_content: bytes,
        key: str,
    ) -> str:
        """
        로컬 파일 저장

        Args:
            file_content: 파일 바이트
            key: 파일 경로

        Returns:
            로컬 파일 경로
        """
        try:
            import os

            full_path = os.path.join(self.base_path, key)
            os.makedirs(os.path.dirname(full_path), exist_ok=True)

            with open(full_path, "wb") as f:
                f.write(file_content)

            logger.info(f"File saved locally: {full_path}")
            return full_path

        except Exception as e:
            logger.error(f"Local file save failed: {e}")
            raise
