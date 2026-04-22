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

from app.core.config import get_settings

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


def verify_facility_access(current_user: dict, facility_id: str):
    """
    직원이 해당 시설에 소속되어 있는지 검증.
    다른 시설의 데이터에 접근하는 것을 방지.
    """
    user_facility = current_user.get("facility_id")
    if not user_facility:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="시설에 소속되지 않은 사용자입니다.",
        )
    if user_facility != facility_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="해당 시설에 접근 권한이 없습니다.",
        )
