"""
환경 변수 및 애플리케이션 설정
"""

from pydantic import Field, computed_field
from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    PROJECT_NAME: str = "Senior Album API"
    VERSION: str = "0.2.0"
    # T-104: prod 기본은 False. 로컬 개발은 .env 에 DEBUG=true 로 opt-in.
    # True 일 때만 /docs /redoc /openapi.json 및 SQL echo 활성화.
    DEBUG: bool = False

    # PostgreSQL — 부분 env 로 분해 (roadmap#87 구조 변경).
    # POSTGRES_PASSWORD 만 SealedSecret, 나머지는 ConfigMap.
    # DATABASE_URL 을 명시적으로 주면 우선 사용 (로컬 .env 호환).
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_USER: str = "postgres"
    POSTGRES_PASSWORD: str = "postgres"
    POSTGRES_DB: str = "senior_album"
    DATABASE_URL: str = ""

    @computed_field
    @property
    def database_url(self) -> str:
        if self.DATABASE_URL:
            return self.DATABASE_URL
        return (
            f"postgresql+asyncpg://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}"
            f"@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"
        )

    # Redis (로컬)
    REDIS_URL: str = "redis://localhost:6379/0"

    # JWT (T-009 refresh token 도입)
    # JWT_SECRET / JWT_REFRESH_SECRET 둘 다 .env 또는 K8s Secret으로 주입 필수
    # 생성: python -c "import secrets; print(secrets.token_urlsafe(48))"
    JWT_SECRET: str = Field(...)
    JWT_REFRESH_SECRET: str = Field(...)  # access와 분리 (탈취 시 영향 격리)
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 60  # access: 60분 (T-009 이전엔 7일)
    JWT_REFRESH_EXPIRE_MINUTES: int = 60 * 24 * 14  # refresh: 14일 (B1 rotation)

    # T-003 envelope encryption — Resident PII (name / birth_date / medical_notes).
    # 둘 다 base64 로 인코딩된 32바이트 키 (`openssl rand -base64 32` 결과 그대로).
    # SealedSecret backend-secret 에 박혀있어야 하며, 누락 시 startup fail.
    RESIDENT_PII_KEK: str = Field(...)  # AES-256-GCM KEK
    RESIDENT_NAME_HMAC_KEY: str = Field(...)  # HMAC-SHA256 blind-index 키

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

    # T-106: 사진 처리 pending 큐 상한 (DoS / 메모리 보호)
    PHOTO_QUEUE_MAX_PENDING_PER_FACILITY: int = 500
    PHOTO_QUEUE_MAX_PENDING_TOTAL: int = 5000

    # OpenSearch (벡터 검색용 - 기존 인프라)
    OPENSEARCH_HOST: str = "localhost"
    OPENSEARCH_PORT: int = 9200

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

    # 전화번호 OTP
    OTP_TTL_SECONDS: int = 300  # 5분 유효
    OTP_FRESH_WINDOW_SECONDS: int = 600  # 시설 연결 요청 게이트 — 인증 후 10분 이내
    OTP_MAX_VERIFY_ATTEMPTS: int = 5  # 한 코드당 검증 시도 횟수
    OTP_SEND_RATE_PER_PHONE_PER_HOUR: int = 5
    OTP_SEND_RATE_PER_PHONE_PER_MINUTE: int = 1
    OTP_SEND_RATE_PER_IP_PER_HOUR: int = 20

    # SMS 프로바이더 (log | coolsms)
    SMS_PROVIDER: str = "log"
    COOLSMS_API_KEY: str = ""
    COOLSMS_API_SECRET: str = ""
    COOLSMS_FROM_NUMBER: str = ""

    # CORS
    ALLOWED_ORIGINS: list = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://localhost:19006",
    ]

    class Config:
        env_file = ".env"
        case_sensitive = True
        # 제거된 env 가 환경/configmap 에 남아있어도 기동을 막지 않게 한다.
        # 예: Alembic Phase 2 에서 DDL_AUTO 를 제거했지만 클러스터 configmap 에
        #     아직 남아있을 때.
        extra = "ignore"


@lru_cache()
def get_settings() -> Settings:
    return Settings()
