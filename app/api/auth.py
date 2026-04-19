"""
인증 API 엔드포인트
이메일/비밀번호 로그인, 3가지 역할 회원가입, 토큰 갱신
"""

import uuid
import logging
from datetime import datetime, timedelta
from collections import defaultdict
import time

from fastapi import APIRouter, HTTPException, status, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from passlib.context import CryptContext

from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import SecurityService, get_current_user
from app.core.redis import check_rate_limit, clear_rate_limit
from app.models.models import User, Facility, Resident, Guardian
from app.schemas.schemas import (
    LoginRequest,
    LoginResponse,
    UserResponse,
    RegisterAdminRequest,
    RegisterStaffRequest,
    RegisterGuardianRequest,
    FacilityResponse,
    DashboardStatsResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

# 비밀번호 해싱
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# 인메모리 fallback (Redis 연결 실패 시)
_login_attempts: dict[str, list[float]] = defaultdict(list)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def generate_facility_code() -> str:
    """시설 코드 생성 (FAC-XXXXXX)"""
    return f"FAC-{uuid.uuid4().hex[:6].upper()}"


def _check_rate_limit_inmemory(identifier: str):
    """인메모리 fallback Rate Limiting"""
    settings = get_settings()
    now = time.time()
    window = settings.LOGIN_LOCKOUT_MINUTES * 60

    _login_attempts[identifier] = [
        t for t in _login_attempts[identifier] if now - t < window
    ]

    if len(_login_attempts[identifier]) >= settings.LOGIN_MAX_ATTEMPTS:
        remaining = int(window - (now - _login_attempts[identifier][0]))
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"로그인 시도가 너무 많습니다. {remaining // 60}분 후에 다시 시도해주세요.",
        )


def _record_login_attempt_inmemory(identifier: str):
    """인메모리 fallback 시도 기록"""
    _login_attempts[identifier].append(time.time())


def _clear_login_attempts_inmemory(identifier: str):
    """인메모리 fallback 시도 초기화"""
    _login_attempts.pop(identifier, None)


async def _check_rate_limit_redis(identifier: str):
    """Redis 우선, 실패 시 인메모리 fallback Rate Limiting"""
    settings = get_settings()
    is_blocked, remaining_seconds = await check_rate_limit(
        key=identifier,
        max_attempts=settings.LOGIN_MAX_ATTEMPTS,
        window_seconds=settings.LOGIN_LOCKOUT_MINUTES * 60,
    )
    if is_blocked:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"로그인 시도가 너무 많습니다. {remaining_seconds // 60}분 후에 다시 시도해주세요.",
        )


@router.post("/login", response_model=LoginResponse)
async def login(request: LoginRequest, req: Request, db: AsyncSession = Depends(get_db)):
    """이메일/비밀번호 로그인 (시도 횟수 제한 포함)"""
    # IP + 이메일 기반 Rate Limiting (Redis 우선, fallback 인메모리)
    client_ip = req.client.host if req.client else "unknown"
    rate_key = f"{client_ip}:{request.email}"
    await _check_rate_limit_redis(rate_key)

    stmt = select(User).filter(User.email == request.email)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        _record_login_attempt_inmemory(rate_key)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="이메일 또는 비밀번호가 올바르지 않습니다.",
        )

    # 소셜 로그인 전용 계정은 비밀번호 로그인 불가
    if user.provider and not user.password_hash:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"이 계정은 {user.provider} 로그인으로 가입되었습니다. {user.provider} 로그인을 이용해주세요.",
        )

    if not verify_password(request.password, user.password_hash):
        _record_login_attempt_inmemory(rate_key)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="이메일 또는 비밀번호가 올바르지 않습니다.",
        )

    # 성공 시 시도 기록 초기화 (Redis + 인메모리 둘 다)
    await clear_rate_limit(rate_key)
    _clear_login_attempts_inmemory(rate_key)

    # 시설 정보 조회
    facility_data = None
    if user.facility_id:
        fac_stmt = select(Facility).filter(Facility.id == user.facility_id)
        fac_result = await db.execute(fac_stmt)
        facility = fac_result.scalar_one_or_none()
        if facility:
            facility_data = {
                "id": facility.id,
                "name": facility.name,
                "address": facility.address,
                "phone": facility.phone or "",
                "code": facility.code,
            }

    access_token = SecurityService.create_access_token(
        data={
            "sub": user.id,
            "email": user.email,
            "role": user.role,
            "facility_id": user.facility_id,
        }
    )

    user_resp = {
        "id": user.id,
        "email": user.email,
        "name": user.name,
        "role": user.role,
        "is_admin": user.is_admin,
        "facility_id": user.facility_id,
        "phone": user.phone,
        "is_active": user.is_active,
        "created_at": user.created_at,
    }

    return {
        "accessToken": access_token,
        "user": user_resp,
        "facility": facility_data,
    }


@router.post("/register/admin")
async def register_admin(request: RegisterAdminRequest, db: AsyncSession = Depends(get_db)):
    """
    시설 관리자 등록
    1. 시설 생성 (코드 자동 발급)
    2. 관리자 계정 생성
    """
    # 이메일 중복 확인
    stmt = select(User).filter(User.email == request.email)
    result = await db.execute(stmt)
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="이미 등록된 이메일입니다.")

    # 시설 생성
    facility_id = str(uuid.uuid4())
    facility_code = generate_facility_code()

    facility = Facility(
        id=facility_id,
        name=request.facilityName,
        address=request.facilityAddress,
        phone=request.facilityPhone or "",
        code=facility_code,
    )
    db.add(facility)

    # 관리자 사용자 생성
    user_id = str(uuid.uuid4())
    user = User(
        id=user_id,
        email=request.email,
        name=request.name,
        password_hash=hash_password(request.password),
        role="staff",
        is_admin=True,
        facility_id=facility_id,
        phone=request.phone,
    )
    db.add(user)
    await db.flush()

    access_token = SecurityService.create_access_token(
        data={"sub": user_id, "email": request.email, "role": "staff", "facility_id": facility_id}
    )

    logger.info(f"Admin registered: {request.email}, facility: {request.facilityName} ({facility_code})")

    return {
        "accessToken": access_token,
        "user": {
            "id": user_id,
            "email": request.email,
            "name": request.name,
            "role": "staff",
            "is_admin": True,
            "facility_id": facility_id,
            "phone": request.phone,
            "is_active": True,
            "created_at": user.created_at.isoformat() if user.created_at else None,
        },
        "facility": {
            "id": facility_id,
            "name": request.facilityName,
            "address": request.facilityAddress,
            "phone": request.facilityPhone or "",
            "code": facility_code,
        },
    }


@router.post("/register/staff")
async def register_staff(request: RegisterStaffRequest, db: AsyncSession = Depends(get_db)):
    """
    시설 직원 등록 — 시설 코드로 기존 시설에 합류
    """
    # 이메일 중복 확인
    stmt = select(User).filter(User.email == request.email)
    result = await db.execute(stmt)
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="이미 등록된 이메일입니다.")

    # 시설 코드로 시설 조회
    fac_stmt = select(Facility).filter(Facility.code == request.facilityCode)
    fac_result = await db.execute(fac_stmt)
    facility = fac_result.scalar_one_or_none()

    if not facility:
        raise HTTPException(status_code=404, detail="유효하지 않은 시설 코드입니다.")

    user_id = str(uuid.uuid4())
    user = User(
        id=user_id,
        email=request.email,
        name=request.name,
        password_hash=hash_password(request.password),
        role="staff",
        is_admin=False,
        facility_id=facility.id,
        phone=request.phone,
    )
    db.add(user)
    await db.flush()

    access_token = SecurityService.create_access_token(
        data={"sub": user_id, "email": request.email, "role": "staff", "facility_id": facility.id}
    )

    logger.info(f"Staff registered: {request.email}, facility: {facility.name}")

    return {
        "accessToken": access_token,
        "user": {
            "id": user_id,
            "email": request.email,
            "name": request.name,
            "role": "staff",
            "is_admin": False,
            "facility_id": facility.id,
            "phone": request.phone,
            "is_active": True,
            "created_at": user.created_at.isoformat() if user.created_at else None,
        },
        "facility": {
            "id": facility.id,
            "name": facility.name,
            "address": facility.address,
            "phone": facility.phone or "",
            "code": facility.code,
        },
    }


@router.post("/register/guardian")
async def register_guardian(request: RegisterGuardianRequest, db: AsyncSession = Depends(get_db)):
    """
    보호자 가입 — 단순 계정 생성만 (시설/입소자 연결은 별도 요청)
    """
    # 이메일 중복 확인
    stmt = select(User).filter(User.email == request.email)
    result = await db.execute(stmt)
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="이미 등록된 이메일입니다.")

    user_id = str(uuid.uuid4())
    user = User(
        id=user_id,
        email=request.email,
        name=request.name,
        password_hash=hash_password(request.password),
        role="guardian",
        is_admin=False,
        facility_id=None,  # 시설 연결 없이 가입
        phone=request.phone,
    )
    db.add(user)
    await db.flush()

    access_token = SecurityService.create_access_token(
        data={"sub": user_id, "email": request.email, "role": "guardian"}
    )

    logger.info(f"Guardian registered: {request.email}")

    return {
        "accessToken": access_token,
        "user": {
            "id": user_id,
            "email": request.email,
            "name": request.name,
            "role": "guardian",
            "is_admin": False,
            "facility_id": None,
            "phone": request.phone,
            "is_active": True,
            "created_at": user.created_at.isoformat() if user.created_at else None,
        },
    }


@router.post("/refresh")
async def refresh_token(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    토큰 갱신 — 만료 전에 새 토큰 발급
    프론트엔드에서 주기적으로 호출하여 세션 유지
    """
    stmt = select(User).filter(User.id == current_user["user_id"])
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="유효하지 않은 사용자입니다.")

    new_token = SecurityService.create_access_token(
        data={
            "sub": user.id,
            "email": user.email,
            "role": user.role,
            "facility_id": user.facility_id,
        }
    )

    return {"accessToken": new_token}


@router.get("/me")
async def get_me(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """현재 사용자 정보 조회"""
    stmt = select(User).filter(User.id == current_user["user_id"])
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail="사용자를 찾을 수 없습니다.")

    # 시설 정보
    facility_data = None
    if user.facility_id:
        fac_stmt = select(Facility).filter(Facility.id == user.facility_id)
        fac_result = await db.execute(fac_stmt)
        facility = fac_result.scalar_one_or_none()
        if facility:
            facility_data = {
                "id": facility.id,
                "name": facility.name,
                "address": facility.address,
                "phone": facility.phone or "",
                "code": facility.code,
            }

    return {
        "user": {
            "id": user.id,
            "email": user.email,
            "name": user.name,
            "role": user.role,
            "is_admin": user.is_admin,
            "facility_id": user.facility_id,
            "phone": user.phone,
            "is_active": user.is_active,
            "created_at": user.created_at.isoformat() if user.created_at else None,
        },
        "facility": facility_data,
    }
