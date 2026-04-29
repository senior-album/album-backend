"""
MinIO (S3-compatible) object storage service.
Uses boto3 which is already a dependency.
"""

import asyncio
import re
import uuid
import logging
from io import BytesIO

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError

from app.core.config import get_settings


# T-100: object key 생성에 들어가는 prefix/ext 화이트리스트
# facility_id 는 DB 가 보증한 UUID 지만, `{facility}/thumbnails` 같이 조합해서
# 넘기는 호출부가 있어 storage 레이어에서 한 번 더 검증 — defense in depth.
_SAFE_PREFIX_SEGMENT = re.compile(r"^[a-zA-Z0-9_-]+$")
_SAFE_EXT = re.compile(r"^[a-zA-Z0-9]{1,8}$")


def _sanitize_object_prefix(prefix: str) -> str:
    """
    object key prefix 를 정규화·검증한다.

    허용: 알파뉴메릭 + `_` + `-` 로 구성된 세그먼트를 `/` 로 결합한 형태
    (예: `fac_abc123`, `fac_abc123/thumbnails`, `fac_abc123/faces`).

    차단: `..`, 절대경로(`/x`), 백슬래시, null 바이트, 빈 세그먼트, 제어문자.

    Raises: ValueError — 호출부에서 400 으로 매핑하거나 내부 assertion 처럼 사용.
    """
    if not prefix or not isinstance(prefix, str):
        raise ValueError("Invalid storage prefix: empty or non-string")
    if "\0" in prefix or "\\" in prefix:
        raise ValueError("Invalid characters in storage prefix")
    segments = [s for s in prefix.split("/") if s]  # 연속/선후행 슬래시 제거
    if not segments:
        raise ValueError("Empty storage prefix after normalization")
    for s in segments:
        if s in (".", "..") or not _SAFE_PREFIX_SEGMENT.match(s):
            raise ValueError(f"Unsafe path segment in storage prefix: {s!r}")
    return "/".join(segments)


def _sanitize_extension(ext: str) -> str:
    """확장자 sanitize — 알파뉴메릭만, 길이 제한. 실패 시 기본 'jpg'."""
    if not ext:
        return "jpg"
    ext = ext.lstrip(".").lower()
    return ext if _SAFE_EXT.match(ext) else "jpg"

logger = logging.getLogger(__name__)


class StorageService:
    def __init__(self):
        settings = get_settings()
        endpoint_url = f"{'https' if settings.MINIO_USE_SSL else 'http'}://{settings.MINIO_ENDPOINT}"

        self.client = boto3.client(
            "s3",
            endpoint_url=endpoint_url,
            aws_access_key_id=settings.MINIO_ACCESS_KEY,
            aws_secret_access_key=settings.MINIO_SECRET_KEY,
            config=BotoConfig(signature_version="s3v4"),
            region_name="us-east-1",
        )
        self.bucket = settings.MINIO_BUCKET
        self.endpoint_url = endpoint_url

        # 외부 접근용 presigned URL 클라이언트
        if settings.MINIO_EXTERNAL_ENDPOINT:
            external_url = settings.MINIO_EXTERNAL_ENDPOINT
            if not external_url.startswith("http"):
                external_url = f"https://{external_url}"
            self.external_client = boto3.client(
                "s3",
                endpoint_url=external_url,
                aws_access_key_id=settings.MINIO_ACCESS_KEY,
                aws_secret_access_key=settings.MINIO_SECRET_KEY,
                config=BotoConfig(signature_version="s3v4"),
                region_name="us-east-1",
            )
        else:
            self.external_client = self.client

        self._ensure_bucket()

    def _ensure_bucket(self):
        try:
            self.client.head_bucket(Bucket=self.bucket)
        except ClientError:
            try:
                self.client.create_bucket(Bucket=self.bucket)
                logger.info(f"Created bucket: {self.bucket}")
            except Exception as e:
                logger.warning(f"Could not create bucket: {e}")
        # Set public read policy so images are accessible via URL
        self._set_public_read_policy()

    def _set_public_read_policy(self):
        """Set bucket policy to allow public read access for images."""
        import json
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": ["*"]},
                    "Action": ["s3:GetObject"],
                    "Resource": [f"arn:aws:s3:::{self.bucket}/*"],
                }
            ],
        }
        try:
            self.client.put_bucket_policy(
                Bucket=self.bucket,
                Policy=json.dumps(policy),
            )
            logger.info(f"Public read policy set for bucket: {self.bucket}")
        except Exception as e:
            logger.warning(f"Could not set bucket policy: {e}")

    async def upload_file(self, file_data: bytes, filename: str, content_type: str, facility_id: str) -> str:
        """
        Upload a file and return the object key.

        T-100: `facility_id` 는 object key prefix 로 직접 들어가므로 path
        traversal 방어를 위해 sanitize. 동일하게 filename 확장자도 제한.

        boto3 client.put_object 는 sync — 함수가 async 로 선언돼 있어도 호출
        시점에 event loop 를 막아 동시 업로드가 직렬화됨. asyncio.to_thread 로
        래핑해 진짜 동시 실행 가능하게 함 (T-030 후속 perf 개선).
        """
        raw_ext = filename.rsplit(".", 1)[-1] if "." in filename else ""
        safe_prefix = _sanitize_object_prefix(facility_id)
        safe_ext = _sanitize_extension(raw_ext)
        object_key = f"{safe_prefix}/{uuid.uuid4().hex}.{safe_ext}"

        await asyncio.to_thread(
            self.client.put_object,
            Bucket=self.bucket,
            Key=object_key,
            Body=BytesIO(file_data),
            ContentLength=len(file_data),
            ContentType=content_type,
        )
        logger.info(f"Uploaded: {object_key}")
        return object_key

    def get_url(self, object_key: str) -> str:
        """Get the public URL for an object."""
        return f"{self.endpoint_url}/{self.bucket}/{object_key}"

    def extract_object_key(self, url: str) -> str | None:
        """URL에서 object key 추출"""
        if not url:
            return None
        bucket_prefix = f"{self.endpoint_url}/{self.bucket}/"
        if url.startswith(bucket_prefix):
            return url[len(bucket_prefix):]
        # http://minio:9000/bucket/key 등 다양한 내부 URL 처리
        parts = url.split(f"/{self.bucket}/", 1)
        if len(parts) == 2:
            return parts[1]
        # 이미 object key인 경우
        if not url.startswith("http"):
            return url
        return None

    def to_presigned(self, url: str, expires_in: int = 3600) -> str:
        """기존 URL을 presigned URL로 변환. 변환 실패 시 원본 반환."""
        key = self.extract_object_key(url)
        if key:
            try:
                return self.get_presigned_url(key, expires_in)
            except Exception:
                pass
        return url

    def get_presigned_url(self, object_key: str, expires_in: int = 3600) -> str:
        """Get a presigned URL for temporary access (외부 클라이언트 사용)."""
        return self.external_client.generate_presigned_url(
            "get_object",
            Params={"Bucket": self.bucket, "Key": object_key},
            ExpiresIn=expires_in,
        )

    async def download_file(self, url_or_key: str) -> bytes | None:
        """Download a file from storage. Accepts either a full URL or object key."""
        try:
            key = self.extract_object_key(url_or_key) or url_or_key
            response = self.client.get_object(Bucket=self.bucket, Key=key)
            return response["Body"].read()
        except Exception as e:
            logger.error(f"Failed to download file {url_or_key}: {e}")
            return None

    async def delete_file(self, object_key: str):
        """Delete an object."""
        self.client.delete_object(Bucket=self.bucket, Key=object_key)


# Singleton
_storage: StorageService | None = None


def get_storage() -> StorageService:
    global _storage
    if _storage is None:
        _storage = StorageService()
    return _storage
