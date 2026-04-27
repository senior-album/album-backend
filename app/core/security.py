"""
인증 및 보안 관련 함수
Firebase 토큰 검증, JWT 생성/검증, 역할 기반 접근 제어
"""

from datetime import datetime, timedelta
from typing import Optional, Callable, Tuple
from functools import wraps
import logging
import secrets

from jose import JWTError, jwt
from fastapi import Depends, HTTPException, status, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import get_db

logger = logging.getLogger(__name__)

# 쿠키 설정 상수
COOKIE_NAME = "access_token"
REFRESH_COOKIE_NAME = "refresh_token"
REFRESH_COOKIE_PATH = "/auth"  # /auth/refresh, /auth/logout 에만 전달 (공격면 축소)

# Firebase 인증 (현재 미사용 - 나중에 필요시 활성화)
FIREBASE_AVAILABLE = False


class SecurityService:
    """인증 및 보안 처리"""

    @staticmethod
    def create_access_token(
        data: dict,
        expires_delta: Optional[timedelta] = None,
    ) -> str:
        """JWT 액세스 토큰 생성"""
        settings = get_settings()

        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=settings.JWT_EXPIRE_MINUTES)

        to_encode.update({"exp": expire})

        encoded_jwt = jwt.encode(
            to_encode,
            settings.JWT_SECRET,
            algorithm=settings.JWT_ALGORITHM,
        )
        return encoded_jwt

    @staticmethod
    def verify_token(token: str) -> dict:
        """JWT access 토큰 검증 및 payload 반환"""
        settings = get_settings()

        try:
            payload = jwt.decode(
                token,
                settings.JWT_SECRET,
                algorithms=[settings.JWT_ALGORITHM],
            )
            return payload
        except JWTError as e:
            logger.error(f"Token verification failed: {e}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token",
                headers={"WWW-Authenticate": "Bearer"},
            )

    @staticmethod
    def create_refresh_token(user_id: str, jti: str) -> Tuple[str, datetime]:
        """
        Refresh 토큰 생성. jti는 호출자가 미리 생성해서 DB에 저장한 후 전달.
        Returns (jwt_token, expires_at).
        """
        settings = get_settings()
        expires_at = datetime.utcnow() + timedelta(minutes=settings.JWT_REFRESH_EXPIRE_MINUTES)
        payload = {
            "sub": user_id,
            "jti": jti,
            "type": "refresh",
            "exp": expires_at,
        }
        token = jwt.encode(payload, settings.JWT_REFRESH_SECRET, algorithm=settings.JWT_ALGORITHM)
        return token, expires_at

    @staticmethod
    def verify_refresh_token(token: str) -> dict:
        """Refresh 토큰 서명·만료 검증 (DB 조회는 호출자가 별도 수행)"""
        settings = get_settings()
        try:
            payload = jwt.decode(
                token,
                settings.JWT_REFRESH_SECRET,
                algorithms=[settings.JWT_ALGORITHM],
            )
            if payload.get("type") != "refresh":
                raise JWTError("not a refresh token")
            return payload
        except JWTError as e:
            logger.warning(f"Refresh token verification failed: {e}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token",
            )

    @staticmethod
    def generate_jti() -> str:
        """Refresh 토큰 jti — URL-safe 32바이트 랜덤"""
        return secrets.token_urlsafe(32)

    @staticmethod
    def verify_firebase_token(token: str) -> dict:
        """Firebase 토큰 검증"""
        if not FIREBASE_AVAILABLE:
            logger.warning("Firebase not configured, skipping verification")
            return {}

        try:
            decoded_token = auth.verify_id_token(token)
            return decoded_token
        except Exception as e:
            logger.error(f"Firebase token verification failed: {e}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Firebase token",
            )


def set_auth_cookie(response: JSONResponse, token: str) -> JSONResponse:
    """응답에 httpOnly 쿠키로 access JWT 설정"""
    settings = get_settings()
    is_production = not settings.DEBUG

    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        max_age=settings.JWT_EXPIRE_MINUTES * 60,
        httponly=True,
        secure=is_production,          # 프로덕션에서만 Secure (HTTPS)
        samesite="lax",                # CSRF 방지
        path="/",
    )
    return response


def clear_auth_cookie(response: JSONResponse) -> JSONResponse:
    """응답에서 access 쿠키 삭제"""
    settings = get_settings()
    is_production = not settings.DEBUG

    response.delete_cookie(
        key=COOKIE_NAME,
        httponly=True,
        secure=is_production,
        samesite="lax",
        path="/",
    )
    return response


def set_refresh_cookie(response: JSONResponse, token: str) -> JSONResponse:
    """응답에 httpOnly 쿠키로 refresh 토큰 설정 (path=/auth로 전달 범위 제한)"""
    settings = get_settings()
    is_production = not settings.DEBUG

    response.set_cookie(
        key=REFRESH_COOKIE_NAME,
        value=token,
        max_age=settings.JWT_REFRESH_EXPIRE_MINUTES * 60,
        httponly=True,
        secure=is_production,
        samesite="lax",
        path=REFRESH_COOKIE_PATH,
    )
    return response


def clear_refresh_cookie(response: JSONResponse) -> JSONResponse:
    """응답에서 refresh 쿠키 삭제"""
    settings = get_settings()
    is_production = not settings.DEBUG

    response.delete_cookie(
        key=REFRESH_COOKIE_NAME,
        httponly=True,
        secure=is_production,
        samesite="lax",
        path=REFRESH_COOKIE_PATH,
    )
    return response


async def get_current_user(request: Request) -> dict:
    """현재 사용자 정보 조회 — 쿠키 우선, Authorization 헤더 fallback"""
    token = None

    # 1. 쿠키에서 토큰 읽기
    token = request.cookies.get(COOKIE_NAME)

    # 2. Authorization 헤더 fallback (API 클라이언트 등)
    if not token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header[7:]

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    payload = SecurityService.verify_token(token)

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
        )

    return {
        "user_id": user_id,
        "email": payload.get("email"),
        "role": payload.get("role", "user"),
        "facility_id": payload.get("facility_id"),
    }


def require_role(*allowed_roles: str) -> Callable:
    """역할 기반 접근 제어 데코레이터"""

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            current_user = kwargs.get("current_user")

            if not current_user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User not authenticated",
                )

            if current_user.get("role") not in allowed_roles:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"This operation requires one of these roles: {', '.join(allowed_roles)}",
                )

            return await func(*args, **kwargs)

        return wrapper

    return decorator


async def get_current_staff(
    current_user: dict = Depends(get_current_user),
) -> dict:
    """현재 직원 조회 (staff 역할만)"""
    if current_user.get("role") != "staff":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Staff access required",
        )
    return current_user


async def get_current_guardian(
    current_user: dict = Depends(get_current_user),
) -> dict:
    """현재 보호자 조회 (guardian 역할만)"""
    if current_user.get("role") != "guardian":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Guardian access required",
        )
    return current_user


async def verify_facility_access(
    current_user: dict,
    facility_id: str,
    db: AsyncSession,
):
    """
    직원이 해당 시설에 소속되어 있는지 검증.

    T-105: JWT payload 만 신뢰하지 않고 DB 에서 현재 사용자의 시설 소속·활성
    상태를 재확인한다. 시설에서 제거되거나 비활성화된 사용자의 access token 이
    만료되기 전까지 유효하게 먹히는 창(기본 60분) 동안 데이터 접근을 차단한다.

    `db.get(User, uid)` 를 쓰기 때문에 동일 요청(세션) 안에서 반복 호출 시
    identity map 캐시에서 해결되어 추가 쿼리가 발생하지 않는다 — 예: bulk
    delete 의 사진당 호출.
    """
    user_id = current_user.get("user_id")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="유효하지 않은 인증 컨텍스트입니다.",
        )

    # 순환 import 회피 — 함수 내부에서 모델 로드.
    from app.models.models import User

    user = await db.get(User, user_id)
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="계정이 비활성화되었거나 존재하지 않습니다.",
        )
    if not user.facility_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="시설에 소속되지 않은 사용자입니다.",
        )
    if user.facility_id != facility_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="해당 시설에 접근 권한이 없습니다.",
        )


async def verify_photo_access(
    current_user: dict,
    photo,
    db: AsyncSession,
):
    """
    사진 단건에 대한 접근 권한 검증 — 역할별 경로 분기.

    - staff: verify_facility_access 위임 (자기 시설 사진만).
    - guardian: 본인이 승인된 어르신의 공개 사진만. PhotoResident 다대다 + Photo.resident_id 레거시 모두 조회.
    - 기타 role: 차단 (일반 user는 현재 직접 사진 접근 경로 없음).

    존재 자체 노출을 피하려 권한 실패는 403, 미존재는 호출 측에서 404.
    """
    role = current_user.get("role")

    if role == "staff":
        await verify_facility_access(current_user, photo.facility_id, db)
        return

    if role == "guardian":
        from app.models.models import Guardian, PhotoResident

        if not photo.is_public:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="해당 사진에 접근 권한이 없습니다.",
            )

        stmt = select(Guardian.resident_id).filter(
            Guardian.user_id == current_user["user_id"],
            Guardian.is_approved == True,  # noqa: E712
            Guardian.resident_id.isnot(None),
        )
        result = await db.execute(stmt)
        resident_ids = [rid for (rid,) in result.all()]
        if not resident_ids:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="해당 사진에 접근 권한이 없습니다.",
            )

        if photo.resident_id in resident_ids:
            return

        pr_stmt = select(PhotoResident.id).filter(
            PhotoResident.photo_id == photo.id,
            PhotoResident.resident_id.in_(resident_ids),
        ).limit(1)
        pr_result = await db.execute(pr_stmt)
        if pr_result.scalar_one_or_none() is not None:
            return

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="해당 사진에 접근 권한이 없습니다.",
        )

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="해당 사진에 접근 권한이 없습니다.",
    )


async def require_operator(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    T-020: 운영자 (Senior Album) 권한 검사. 약관/처리방침 publish, legal_settings 편집용.
    JWT 에 is_operator 클레임이 없어 DB 재확인 — 토큰 발급 후 권한 박탈된 사용자가
    토큰 만료 전까지 작업하는 창을 막기 위함 (verify_facility_access 와 동일 정책).
    """
    from app.models.models import User

    user = await db.get(User, current_user.get("user_id"))
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="계정이 비활성화되었거나 존재하지 않습니다.",
        )
    if not user.is_operator:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="운영자 권한이 필요합니다.",
        )
    return current_user
