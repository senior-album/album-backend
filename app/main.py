"""
FastAPI 메인 애플리케이션
라우터 등록, 미들웨어 설정, 라이프사이클 관리
"""

import os
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from app.core.config import get_settings
from app.core.database import Database
from app.core.logging_config import configure_logging
from app.core.redis import get_redis, close_redis
from app.api import auth, facilities, residents, photos, guardians, invitations, kakao_auth, phone_otp, consents, legal

configure_logging()
logger = logging.getLogger(__name__)

settings = get_settings()


async def _bootstrap_operators(operator_emails: str) -> None:
    """OPERATOR_EMAIL (콤마 구분) 매칭 활성 유저를 is_operator=True 로 promote."""
    from sqlalchemy import select
    from app.models.models import User

    emails = [e.strip().lower() for e in operator_emails.split(",") if e.strip()]
    if not emails:
        return

    async with Database.session_scope() as session:
        rows = (
            await session.execute(select(User).where(User.email.in_(emails)))
        ).scalars().all()
        promoted = 0
        for u in rows:
            if not u.is_operator:
                u.is_operator = True
                promoted += 1
        if promoted:
            await session.commit()
            logger.info(f"Promoted {promoted} user(s) to operator")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    애플리케이션 라이프사이클 관리
    시작: DB 초기화, AI 모델 로드
    종료: DB 연결 종료
    """
    # 시작
    logger.info("Starting Senior Album API server...")

    try:
        # 데이터베이스 초기화
        await Database.initialize()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        raise

    # T-020 운영자 부트스트랩 — OPERATOR_EMAIL 매칭 유저를 is_operator=True 로 promote.
    # 운영자가 이미 가입돼 있을 때만 효력. 빈 env / 매칭 없음 / 이미 운영자 모두 silent skip.
    try:
        if settings.OPERATOR_EMAIL:
            await _bootstrap_operators(settings.OPERATOR_EMAIL)
    except Exception as e:
        logger.warning(f"Operator bootstrap failed (continuing): {e}")

    # Redis 연결
    try:
        redis = await get_redis()
        if redis:
            logger.info("Redis connected successfully")
        else:
            logger.warning("Redis not available — using in-memory fallback for rate limiting")
    except Exception as e:
        logger.warning(f"Redis connection failed: {e} — using in-memory fallback")

    # 얼굴 인식 모델 사전 로드 (임베딩 차원 결정을 위해 OpenSearch보다 먼저)
    try:
        from app.services.face_recognition import FaceService
        if FaceService.is_available():
            dim = FaceService.get_embedding_dim()
            logger.info(f"Face recognition model loaded (embedding_dim={dim})")
        else:
            logger.warning("Face recognition not available")
    except Exception as e:
        logger.warning(f"Face recognition model load failed: {e}")

    # OpenSearch 인덱스 초기화 (모델 차원에 맞춰 인덱스 생성/재생성)
    try:
        from app.services.opensearch_service import OpenSearchService
        OpenSearchService.ensure_index()
        logger.info("OpenSearch index initialized successfully")
    except Exception as e:
        logger.warning(f"OpenSearch initialization failed (will retry on first use): {e}")

    # 사진 처리 백그라운드 워커 시작
    try:
        from app.services.photo_worker import start_worker
        start_worker()
        logger.info("Photo processing worker started")
    except Exception as e:
        logger.warning(f"Photo processing worker failed to start: {e}")

    logger.info("Senior Album API server started successfully")

    yield

    # 종료
    logger.info("Shutting down Senior Album API server...")

    # 워커 중지
    try:
        from app.services.photo_worker import stop_worker
        stop_worker()
    except Exception:
        pass

    # Redis 종료
    try:
        await close_redis()
    except Exception:
        pass

    try:
        await Database.close()
        logger.info("Database connection closed")
    except Exception as e:
        logger.error(f"Error closing database: {e}")

    logger.info("Senior Album API server shut down")


# FastAPI 애플리케이션 생성
# T-104: DEBUG=false (프로덕션 기본) 에서는 OpenAPI/docs 엔드포인트 비공개.
# 스키마 자체가 정보 노출이라 인증 없이 프로덕션에 열어두지 않음.
app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="요양원 사진 AI 분류 및 공유 플랫폼 API",
    lifespan=lifespan,
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
    openapi_url="/openapi.json" if settings.DEBUG else None,
)

# CORS 미들웨어 설정
# allow_credentials=True와 allow_origins=["*"]는 동시 사용 불가 (RFC 준수)
# method/header 화이트리스트: I-05 위협 차단
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "Accept",
        "Origin",
        "X-Requested-With",
    ],
    expose_headers=["Content-Disposition"],
    max_age=600,
)


# 예외 처리기
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """HTTP 예외 처리"""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "detail": exc.detail,
            "status_code": exc.status_code,
        },
    )


@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    """일반 예외 처리"""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "Internal server error",
            "status_code": status.HTTP_500_INTERNAL_SERVER_ERROR,
        },
    )


# 라우터 등록
app.include_router(auth.router)
app.include_router(facilities.router)
app.include_router(residents.router)
app.include_router(photos.router)
app.include_router(guardians.router)
app.include_router(invitations.router)
app.include_router(kakao_auth.router)
app.include_router(phone_otp.router)
app.include_router(consents.router)
app.include_router(legal.router)


# 로컬 업로드 디렉토리 정적 파일 서빙
upload_dir = os.path.join(os.getcwd(), "uploads")
os.makedirs(upload_dir, exist_ok=True)
app.mount("/uploads", StaticFiles(directory=upload_dir), name="uploads")


# 헬스 체크 엔드포인트
@app.get("/health", tags=["system"])
async def health_check():
    """
    헬스 체크
    서버 상태 확인용
    """
    return {
        "status": "healthy",
        "version": settings.VERSION,
        "project": settings.PROJECT_NAME,
    }


@app.get("/", tags=["system"])
async def root():
    """
    루트 엔드포인트
    API 정보 반환
    """
    return {
        "name": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "description": "Senior Album API - 요양원 사진 AI 분류 및 공유 플랫폼",
        "docs": "/docs",
        "openapi": "/openapi.json",
    }


# 애플리케이션 메타데이터
app.openapi_tags = [
    {
        "name": "system",
        "description": "시스템 상태 및 정보 조회",
    },
    {
        "name": "auth",
        "description": "인증 (로그인, 회원가입)",
    },
    {
        "name": "facilities",
        "description": "시설 관리",
    },
    {
        "name": "residents",
        "description": "입소자 관리",
    },
    {
        "name": "photos",
        "description": "사진 관리",
    },
    {
        "name": "guardians",
        "description": "보호자 기능",
    },
]


if __name__ == "__main__":
    import uvicorn

    # 로컬 개발용 실행
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
        log_level="info",
    )
