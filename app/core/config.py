"""
환경 변수 및 애플리케이션 설정
"""

import os
from typing import Dict

from pydantic import Field, PrivateAttr, computed_field
from pydantic_settings import BaseSettings
from functools import lru_cache


def _scan_kid_env(prefix: str) -> Dict[str, str]:
    """`{prefix}<KID>` 형태 환경변수를 모아 `{kid: secret}` 맵 반환. kid 는 소문자 정규화.

    예: prefix='JWT_KEY_' 일 때 `JWT_KEY_V1=abc` 와 `JWT_KEY_V2=def` 가 있으면
    `{'v1': 'abc', 'v2': 'def'}`. 빈 값 envvar 는 무시.
    """
    out: Dict[str, str] = {}
    plen = len(prefix)
    for k, v in os.environ.items():
        if k.startswith(prefix) and v:
            kid = k[plen:].lower()
            if kid:
                out[kid] = v
    return out


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

    # JWT (T-009 refresh token 도입, T-055 rolling key 인프라)
    # 두 가지 주입 방식 지원:
    # 1) 단일 키 (legacy 호환): `JWT_SECRET` / `JWT_REFRESH_SECRET` 만 주입.
    #    토큰은 kid 헤더 없이 발급되고 검증 시 자동으로 'legacy' 키 사용.
    # 2) Rolling key (T-055): `JWT_KEY_<KID>` / `JWT_REFRESH_KEY_<KID>` 다수
    #    + `JWT_ACTIVE_KID` / `JWT_REFRESH_ACTIVE_KID` 로 발급용 kid 지정.
    #    토큰 헤더에 kid 가 박혀 검증 시 해당 키 lookup. 회전 = 새 kid 추가 후
    #    ACTIVE 전환, grace 후 옛 kid 환경변수 제거.
    # 둘 다 비면 startup fail (`model_post_init` 에서 검증).
    # 생성: python -c "import secrets; print(secrets.token_urlsafe(48))"
    JWT_SECRET: str = ""
    JWT_REFRESH_SECRET: str = ""  # access와 분리 (탈취 시 영향 격리)
    JWT_ACTIVE_KID: str = ""  # 비면 'legacy' 또는 첫 등록 kid
    JWT_REFRESH_ACTIVE_KID: str = ""
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 60  # access: 60분 (T-009 이전엔 7일)
    JWT_REFRESH_EXPIRE_MINUTES: int = 60 * 24 * 14  # refresh: 14일 (B1 rotation)

    # T-055: kid → secret 맵. `model_post_init` 이 환경변수 스캔으로 채움.
    # 호출자는 `settings.jwt_keys` / `settings.jwt_refresh_keys` 프로퍼티로 읽는다.
    _jwt_keys: Dict[str, str] = PrivateAttr(default_factory=dict)
    _jwt_refresh_keys: Dict[str, str] = PrivateAttr(default_factory=dict)

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

    # 얼굴 인식
    FACE_SIMILARITY_THRESHOLD: float = 0.6
    FACE_DETECTION_CONFIDENCE: float = 0.9

    # T-106: 사진 처리 pending 큐 상한 (DoS / 메모리 보호)
    PHOTO_QUEUE_MAX_PENDING_PER_FACILITY: int = 500
    PHOTO_QUEUE_MAX_PENDING_TOTAL: int = 5000

    # OpenSearch (벡터 검색용 - 기존 인프라)
    OPENSEARCH_HOST: str = "localhost"
    OPENSEARCH_PORT: int = 9200
    # T-004: 전송 암호화 (TLS) + 기본 인증 옵션. 운영(K8s)에선 SealedSecret 으로
    # USE_SSL=true / VERIFY_CERTS=true / CA_CERT_PATH 와 USER/PASSWORD 를 주입.
    # dev 는 기본값(False) 으로 평문 9200. self-signed 면 VERIFY_CERTS=false +
    # CA_CERT_PATH 비워두기.
    OPENSEARCH_USE_SSL: bool = False
    OPENSEARCH_VERIFY_CERTS: bool = False
    OPENSEARCH_CA_CERT_PATH: str = ""  # PEM 파일 경로. VERIFY_CERTS=true 시 필요
    OPENSEARCH_USER: str = ""  # security 플러그인 활성 시
    OPENSEARCH_PASSWORD: str = ""  # security 플러그인 활성 시

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
    # 인증된 phone_verified_at 의 유효기간. 1년 지나면 시설 연결 등 게이트가 재인증 요구.
    # 한 번 인증하면 끝낸다는 UX 정책 (사용자 결정) + 장기 신뢰 한도.
    OTP_REVERIFY_AFTER_DAYS: int = 365
    OTP_MAX_VERIFY_ATTEMPTS: int = 5  # 한 코드당 검증 시도 횟수
    OTP_SEND_RATE_PER_PHONE_PER_HOUR: int = 5
    OTP_SEND_RATE_PER_PHONE_PER_MINUTE: int = 1
    OTP_SEND_RATE_PER_IP_PER_HOUR: int = 20

    # SMS 프로바이더 (log | coolsms)
    SMS_PROVIDER: str = "log"
    COOLSMS_API_KEY: str = ""
    COOLSMS_API_SECRET: str = ""
    COOLSMS_FROM_NUMBER: str = ""

    # T-041: 운영 장애 알림 Discord 웹훅. 비어있으면 알림 미전송 (no-op).
    # SealedSecret backend-secret 으로 주입. URL 자체가 시크릿(토큰 path 포함)
    # 이라 로그/에러 메시지에 절대 노출하지 말 것.
    DISCORD_OPS_WEBHOOK_URL: str = ""

    # T-020: 운영자 부트스트랩. 앱 시작 시 이 이메일을 가진 활성 유저가 있으면
    # is_operator=True 로 promote. 빈 값이면 부트스트랩 스킵 (이미 promote 된 유저가
    # 있다고 가정). 콤마 구분 다중 이메일도 지원 — 예: "a@x,b@x".
    OPERATOR_EMAIL: str = ""

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

    def model_post_init(self, __context) -> None:
        # T-055: rolling key 키셋 빌드 + 활성 kid 결정. 부트 시 한 번만 실행됨
        # (`get_settings` 가 lru_cache 라 인스턴스도 한 개).
        access_keys = _scan_kid_env("JWT_KEY_")
        refresh_keys = _scan_kid_env("JWT_REFRESH_KEY_")

        # 단일 키 호환 — JWT_SECRET 이 있으면 'legacy' kid 로 등록.
        if self.JWT_SECRET:
            access_keys.setdefault("legacy", self.JWT_SECRET)
        if self.JWT_REFRESH_SECRET:
            refresh_keys.setdefault("legacy", self.JWT_REFRESH_SECRET)

        if not access_keys:
            raise ValueError(
                "Access JWT 키가 하나도 설정되지 않았습니다. "
                "JWT_SECRET 또는 JWT_KEY_<KID> 형태 환경변수를 주입해야 합니다."
            )
        if not refresh_keys:
            raise ValueError(
                "Refresh JWT 키가 하나도 설정되지 않았습니다. "
                "JWT_REFRESH_SECRET 또는 JWT_REFRESH_KEY_<KID> 형태 환경변수를 주입해야 합니다."
            )

        active = self.JWT_ACTIVE_KID or (
            "legacy" if "legacy" in access_keys else next(iter(access_keys))
        )
        active_refresh = self.JWT_REFRESH_ACTIVE_KID or (
            "legacy" if "legacy" in refresh_keys else next(iter(refresh_keys))
        )
        if active not in access_keys:
            raise ValueError(
                f"JWT_ACTIVE_KID={active!r} 가 등록된 access 키 "
                f"{sorted(access_keys.keys())} 에 없습니다."
            )
        if active_refresh not in refresh_keys:
            raise ValueError(
                f"JWT_REFRESH_ACTIVE_KID={active_refresh!r} 가 등록된 refresh 키 "
                f"{sorted(refresh_keys.keys())} 에 없습니다."
            )

        self._jwt_keys = access_keys
        self._jwt_refresh_keys = refresh_keys
        # 빈 문자열로 들어왔던 ACTIVE_KID 를 실제 결정값으로 덮어쓰기.
        # frozen 모델이 아니므로 일반 setattr 가능.
        if not self.JWT_ACTIVE_KID:
            self.JWT_ACTIVE_KID = active
        if not self.JWT_REFRESH_ACTIVE_KID:
            self.JWT_REFRESH_ACTIVE_KID = active_refresh

    @property
    def jwt_keys(self) -> Dict[str, str]:
        return self._jwt_keys

    @property
    def jwt_refresh_keys(self) -> Dict[str, str]:
        return self._jwt_refresh_keys


@lru_cache()
def get_settings() -> Settings:
    return Settings()
