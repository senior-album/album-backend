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

    def get_presigned_url(self, object_key: str, expires_in: int = 3600) -> str:
        """Get a presigned URL for temporary access."""
        return self.client.generate_presigned_url(
            "get_object",
            Params={"Bucket": self.bucket, "Key": object_key},
            ExpiresIn=expires_in,
        )

    async def download_file(self, url_or_key: str) -> bytes | None:
        """Download a file from storage. Accepts either a full URL or object key."""
        try:
            # URL에서 object key 추출
            key = url_or_key
            bucket_prefix = f"{self.endpoint_url}/{self.bucket}/"
            if url_or_key.startswith(bucket_prefix):
                key = url_or_key[len(bucket_prefix):]
            elif url_or_key.startswith("http"):
                # 다른 형태의 URL인 경우 bucket/key 부분 추출
                parts = url_or_key.split(f"/{self.bucket}/", 1)
                if len(parts) == 2:
                    key = parts[1]

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
