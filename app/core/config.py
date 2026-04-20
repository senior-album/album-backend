"""
환경 변수 및 애플리케이션 설정
"""

from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    PROJECT_NAME: str = "Senior Album API"
    VERSION: str = "0.2.0"
    DEBUG: bool = True

    # PostgreSQL (로컬)
    DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/senior_album"

    # Redis (로컬)
    REDIS_URL: str = "redis://localhost:6379/0"

    # JWT
    JWT_SECRET: str = "your-secret-key-change-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7일
    JWT_REFRESH_THRESHOLD_MINUTES: int = 60 * 24  # 남은 시간이 1일 미만이면 갱신

    # MinIO / S3 (로컬 or 나중에 AWS)
    MINIO_ENDPOINT: str = "localhost:9000"
    MINIO_ACCESS_KEY: str = "minioadmin"
    MINIO_SECRET_KEY: str = "minioadmin"
    MINIO_BUCKET: str = "senior-album-photos"
    MINIO_USE_SSL: bool = False
    MINIO_EXTERNAL_ENDPOINT: str = ""  # 외부 접근용 (presigned URL), 비어있으면 MINIO_ENDPOINT 사용

    # 사진 로컬 저장 (MinIO 없을 때 fallback)
    UPLOAD_DIR: str = "./uploads"

    # 얼굴 인식
    FACE_SIMILARITY_THRESHOLD: float = 0.6
    FACE_DETECTION_CONFIDENCE: float = 0.9

    # OpenSearch (벡터 검색용 - 기존 인프라)
    OPENSEARCH_HOST: str = "localhost"
    OPENSEARCH_PORT: int = 9200

    # DDL 자동 관리 (JPA의 ddl-auto 같은 역할)
    DDL_AUTO: str = "create"

    # 카카오 OAuth
    KAKAO_CLIENT_ID: str = ""
    KAKAO_CLIENT_SECRET: str = ""
    KAKAO_REDIRECT_URI: str = "http://localhost:5173/auth/kakao/callback"
    KAKAO_SCOPES: str = "openid"  # 비즈앱 전환 후: "openid,profile_nickname,account_email,phone_number"

    # 카카오 비즈톡 (알림톡)
    BIZZTALK_SENDER_KEY: str = ""
    BIZZTALK_TEMPLATE_CODE_INVITE: str = ""
    BIZZTALK_TEMPLATE_CODE_PHOTO: str = ""

    # 프론트엔드 / 외부 URL
    FRONTEND_URL: str = "http://localhost:5173"
    API_BASE_URL: str = "http://localhost:8000"

    # 공유 링크 만료 시간 (시간 단위)
    SHARE_LINK_EXPIRE_HOURS: int = 72  # 3일

    # 로그인 시도 제한
    LOGIN_MAX_ATTEMPTS: int = 5
    LOGIN_LOCKOUT_MINUTES: int = 15

    # CORS
    ALLOWED_ORIGINS: list = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://localhost:19006",
    ]

    class Config:
        env_file = ".env"
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    return Settings()
