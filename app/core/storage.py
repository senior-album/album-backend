"""
MinIO (S3-compatible) object storage service.
Uses boto3 which is already a dependency.
"""

import uuid
import logging
from io import BytesIO

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError

from app.core.config import get_settings

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
        """Upload a file and return the object key."""
        ext = filename.rsplit(".", 1)[-1] if "." in filename else "jpg"
        object_key = f"{facility_id}/{uuid.uuid4().hex}.{ext}"

        self.client.put_object(
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
