"""
인증 API 엔드포인트
이메일/비밀번호 로그인, 3가지 역할 회원가입, refresh 토큰 rotation (T-009)
"""

import uuid
import logging
from datetime import datetime, timedelta
from collections import defaultdict
import time

from fastapi import APIRouter, HTTPException, status, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, and_, or_
from sqlalchemy.exc import IntegrityError
from passlib.context import CryptContext

from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import (
    SecurityService,
    get_current_user,
    set_auth_cookie,
    clear_auth_cookie,
    set_refresh_cookie,
    clear_refresh_cookie,
    REFRESH_COOKIE_NAME,
)
from app.core.redis import check_rate_limit, clear_rate_limit
from app.models.models import (
    User, Facility, Resident, Guardian, RefreshToken,
    ConsentDocument, UserConsent,
)
from app.schemas.schemas import (
    LoginRequest,
    RegisterAdminRequest,
    RegisterStaffRequest,
    RegisterGuardianRequest,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

# 비밀번호 해싱 — bcrypt rounds=12 명시 (T-054)
# deprecated="auto" + bcrypt__rounds=12 조합으로 rounds<12 해시는 needs_update()에서 True
# → 로그인 성공 시점에 점진 재해싱 (아래 /login 엔드포인트 참조)
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=12,
)

# 인메모리 fallback (Redis 연결 실패 시)
_login_attempts: dict[str, list[float]] = defaultdict(list)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def generate_facility_code() -> str:
    """시설 코드 생성 (FAC-XXXXXX)"""
    return f"FAC-{uuid.uuid4().hex[:6].upper()}"


# T-009/phone-otp 와 동일 메시지 — 클라이언트가 통일된 detail 로 분기 (claim 안내).
_PHONE_DUP_DETAIL = "이미 다른 계정에 등록된 번호입니다."


async def _ensure_phone_available(db: AsyncSession, phone: str | None) -> None:
    """
    회원가입 흐름의 phone 사전 검사. None/빈 값은 통과 (User.phone nullable).
    이미 다른 활성 계정에 등록돼 있으면 409 — 동일 메시지로 phone-otp 의
    claim 신고 흐름과 호환.
    """
    if not phone:
        return
    stmt = select(User.id).filter(User.phone == phone).limit(1)
    if (await db.execute(stmt)).scalar_one_or_none() is not None:
        raise HTTPException(status_code=409, detail=_PHONE_DUP_DETAIL)


async def _issue_token_pair(
    db: AsyncSession,
    user: User,
    family_id: str,
    request: Request,
) -> tuple[str, str]:
    """
    Access + Refresh 토큰 쌍 발급 + RefreshToken row 삽입.
    family_id: 신규 로그인이면 새 uuid, rotation이면 기존 family 유지.
    Returns (access_token, refresh_token).
    호출자가 db.commit() 책임.
    """
    access_token = SecurityService.create_access_token(
        data={
            "sub": user.id,
            "email": user.email,
            "role": user.role,
            "facility_id": user.facility_id,
        }
    )

    jti = SecurityService.generate_jti()
    refresh_token, refresh_expires = SecurityService.create_refresh_token(user.id, jti)

    db.add(RefreshToken(
        user_id=user.id,
        jti=jti,
        family_id=family_id,
        expires_at=refresh_expires,
        user_agent=(request.headers.get("user-agent") or "")[:500],
        ip_address=(request.client.host if request.client else "unknown")[:45],
    ))

    return access_token, refresh_token


async def _revoke_family(db: AsyncSession, family_id: str, reason: str) -> int:
    """family_id에 속한 모든 활성 refresh row를 일괄 회수. 반환: 회수된 row 수"""
    stmt = (
        update(RefreshToken)
        .where(RefreshToken.family_id == family_id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=datetime.utcnow(), revoke_reason=reason)
    )
    result = await db.execute(stmt)
    return result.rowcount or 0


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


@router.post("/login")
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

    # 점진 재해싱 — 저장된 해시가 현재 rounds(12)보다 낮으면 갱신 (T-054)
    # 실패해도 로그인은 성공 처리 (opportunistic upgrade)
    if pwd_context.needs_update(user.password_hash):
        try:
            user.password_hash = hash_password(request.password)
            await db.commit()
            logger.info(f"password rehashed (rounds upgrade) for user {user.id}")
        except Exception as e:
            logger.warning(f"password rehash failed for user {user.id}: {e}")
            await db.rollback()

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

    # 신규 로그인 → 새 family_id (T-009)
    family_id = str(uuid.uuid4())
    access_token, refresh_token = await _issue_token_pair(db, user, family_id, req)
    await db.commit()

    user_resp = {
        "id": user.id,
        "email": user.email,
        "name": user.name,
        "role": user.role,
        "is_admin": user.is_admin,
        "is_operator": user.is_operator,
        "facility_id": user.facility_id,
        "phone": user.phone,
        "is_active": user.is_active,
        # T-056: 프론트가 미승인 staff 를 /pending-approval 로 redirect 하기 위함.
        "is_staff_approved": user.is_staff_approved,
        "created_at": user.created_at.isoformat() if user.created_at else None,
    }

    response = JSONResponse(content={
        "user": user_resp,
        "facility": facility_data,
    })
    set_auth_cookie(response, access_token)
    set_refresh_cookie(response, refresh_token)
    return response


@router.post("/register/admin")
async def register_admin(request: RegisterAdminRequest, req: Request, db: AsyncSession = Depends(get_db)):
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

    await _ensure_phone_available(db, request.phone)

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
        # T-056: 시설을 본인이 만드는 admin 은 자기 자신 자동 승인.
        is_staff_approved=True,
        staff_approved_at=datetime.utcnow(),
    )
    db.add(user)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        # pre-check 와 flush 사이의 race — phone-otp/verify 와 동일 정책 (409).
        raise HTTPException(status_code=409, detail=_PHONE_DUP_DETAIL)

    # 자기 자신 staff_approved_by 박음 — flush 후 PK 확정된 상태에서.
    user.staff_approved_by = user.id

    family_id = str(uuid.uuid4())
    access_token, refresh_jwt = await _issue_token_pair(db, user, family_id, req)

    logger.info(f"Admin registered: {request.email}, facility: {request.facilityName} ({facility_code})")

    response = JSONResponse(content={
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
    })
    set_auth_cookie(response, access_token)
    set_refresh_cookie(response, refresh_jwt)
    return response


@router.post("/register/staff")
async def register_staff(request: RegisterStaffRequest, req: Request, db: AsyncSession = Depends(get_db)):
    """
    시설 직원 등록 — 시설 코드로 기존 시설에 합류
    """
    # 이메일 중복 확인
    stmt = select(User).filter(User.email == request.email)
    result = await db.execute(stmt)
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="이미 등록된 이메일입니다.")

    await _ensure_phone_available(db, request.phone)

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
        # T-056: 시설장 승인 전엔 pending. verify_facility_access 가 차단.
        is_staff_approved=False,
    )
    db.add(user)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=409, detail=_PHONE_DUP_DETAIL)

    family_id = str(uuid.uuid4())
    access_token, refresh_jwt = await _issue_token_pair(db, user, family_id, req)

    logger.info(f"Staff registered (pending): {request.email}, facility: {facility.name}")

    # T-056: pending 응답 — 프론트가 is_staff_approved=False 면 /pending-approval 로 redirect.
    # 토큰은 발급해서 /auth/me 가 호출 가능하지만 verify_facility_access 가 데이터 API 를 차단.
    response = JSONResponse(content={
        "user": {
            "id": user_id,
            "email": request.email,
            "name": request.name,
            "role": "staff",
            "is_admin": False,
            "facility_id": facility.id,
            "phone": request.phone,
            "is_active": True,
            "is_staff_approved": False,
            "created_at": user.created_at.isoformat() if user.created_at else None,
        },
        "facility": {
            "id": facility.id,
            "name": facility.name,
            "address": facility.address,
            "phone": facility.phone or "",
            "code": facility.code,
        },
    })
    set_auth_cookie(response, access_token)
    set_refresh_cookie(response, refresh_jwt)
    return response


async def _validate_and_record_consents(
    db: AsyncSession,
    user_id: str,
    consents,
    req: Request,
) -> None:
    """
    T-020: 활성 ConsentDocument 와 사용자 입력 consents 를 대조해
    필수 약관 동의 여부를 검증하고, 동의/거부 모두 user_consents 에 기록.
    필수 미동의 시 HTTPException(400) 을 던진다.
    호출자 측 db.flush() 이후, 토큰 발급 전에 호출.
    """
    now = datetime.utcnow()
    active_stmt = select(ConsentDocument).where(
        and_(
            ConsentDocument.effective_from <= now,
            or_(
                ConsentDocument.effective_until.is_(None),
                ConsentDocument.effective_until > now,
            ),
        )
    )
    active_docs = (await db.execute(active_stmt)).scalars().all()

    by_type_latest: dict[str, ConsentDocument] = {}
    for d in active_docs:
        if d.type not in by_type_latest or d.effective_from > by_type_latest[d.type].effective_from:
            by_type_latest[d.type] = d

    active_doc_ids = {d.id for d in by_type_latest.values()}
    consent_map = {c.document_id: c.agreed for c in consents}

    for t, doc in by_type_latest.items():
        if doc.is_mandatory and not consent_map.get(doc.id, False):
            raise HTTPException(
                status_code=400,
                detail=f"필수 약관 동의가 필요합니다: {t} ({doc.version})",
            )

    ip = req.client.host if req.client else None
    ua = (req.headers.get("user-agent", "") or "")[:500]
    for c in consents:
        if c.document_id not in active_doc_ids:
            # 비활성/존재하지 않는 문서 ID 는 무시 (오래된 폼 캐시 방어)
            continue
        db.add(UserConsent(
            user_id=user_id,
            document_id=c.document_id,
            agreed=c.agreed,
            agreed_at=now,
            ip_address=ip,
            user_agent=ua,
        ))


@router.post("/register/guardian")
async def register_guardian(request: RegisterGuardianRequest, req: Request, db: AsyncSession = Depends(get_db)):
    """
    보호자 가입 — 단순 계정 생성만 (시설/입소자 연결은 별도 요청).
    T-020: 활성 필수 약관 (이용약관·처리방침·민감정보) 동의 검증 + 동의 로그 저장.
    """
    # 이메일 중복 확인
    stmt = select(User).filter(User.email == request.email)
    result = await db.execute(stmt)
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="이미 등록된 이메일입니다.")

    await _ensure_phone_available(db, request.phone)

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
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=409, detail=_PHONE_DUP_DETAIL)

    # T-020: 동의 검증 및 기록 — 필수 미동의 시 400
    await _validate_and_record_consents(db, user_id, request.consents, req)

    family_id = str(uuid.uuid4())
    access_token, refresh_jwt = await _issue_token_pair(db, user, family_id, req)

    logger.info(f"Guardian registered: {request.email}")

    response = JSONResponse(content={
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
    })
    set_auth_cookie(response, access_token)
    set_refresh_cookie(response, refresh_jwt)
    return response


@router.post("/refresh")
async def refresh_token(req: Request, db: AsyncSession = Depends(get_db)):
    """
    Refresh 토큰으로 access + refresh 쌍 갱신 (rotation, T-009).
    - DB jti 조회 → 회수됐으면 reuse → family 일괄 revoke
    - 활성이면 새 access+refresh 발급, 기존 row revoke (rotated)
    """
    refresh_jwt = req.cookies.get(REFRESH_COOKIE_NAME)
    if not refresh_jwt:
        raise HTTPException(status_code=401, detail="Refresh token missing")

    payload = SecurityService.verify_refresh_token(refresh_jwt)  # 401 raise on invalid/expired
    jti = payload.get("jti")
    user_id = payload.get("sub")
    if not jti or not user_id:
        raise HTTPException(status_code=401, detail="Malformed refresh token")

    # DB row 조회
    db_row = (await db.execute(
        select(RefreshToken).filter(RefreshToken.jti == jti)
    )).scalar_one_or_none()

    if db_row is None:
        # DB에 없는 jti — 위조 또는 정리됨
        raise HTTPException(status_code=401, detail="Refresh token not recognized")

    # 만료 (DB 기준 — JWT exp로도 잡히지만 이중 안전)
    if db_row.expires_at < datetime.utcnow():
        raise HTTPException(status_code=401, detail="Refresh token expired")

    # ★ Reuse detection (C): 회수된 토큰 재사용 → family 전체 revoke
    if db_row.revoked_at is not None:
        revoked_count = await _revoke_family(db, db_row.family_id, "reuse-detected")
        await db.commit()
        logger.warning(
            f"REFRESH REUSE DETECTED for user={user_id} family={db_row.family_id} "
            f"jti={jti[:8]} — revoked {revoked_count} tokens. 강제 로그아웃."
        )
        raise HTTPException(
            status_code=401,
            detail="Session compromised — please log in again.",
        )

    # 활성 사용자 확인
    user = (await db.execute(select(User).filter(User.id == user_id))).scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="유효하지 않은 사용자입니다.")

    # Rotation: 새 토큰 쌍 발급 + 기존 row 회수
    access_token, new_refresh_token = await _issue_token_pair(db, user, db_row.family_id, req)
    db_row.revoked_at = datetime.utcnow()
    db_row.revoke_reason = "rotated"
    await db.commit()

    response = JSONResponse(content={"message": "Token refreshed"})
    set_auth_cookie(response, access_token)
    set_refresh_cookie(response, new_refresh_token)
    return response


@router.post("/logout")
async def logout(req: Request, db: AsyncSession = Depends(get_db)):
    """
    로그아웃 — 현재 family의 모든 refresh 토큰 revoke + 양쪽 쿠키 삭제.
    Refresh 쿠키 없어도 access 쿠키는 클리어.
    """
    refresh_jwt = req.cookies.get(REFRESH_COOKIE_NAME)
    if refresh_jwt:
        try:
            payload = SecurityService.verify_refresh_token(refresh_jwt)
            jti = payload.get("jti")
            db_row = (await db.execute(
                select(RefreshToken).filter(RefreshToken.jti == jti)
            )).scalar_one_or_none()
            if db_row:
                await _revoke_family(db, db_row.family_id, "logout")
                await db.commit()
        except HTTPException:
            # refresh 토큰이 invalid해도 로그아웃은 진행
            pass

    response = JSONResponse(content={"message": "Logged out"})
    clear_auth_cookie(response)
    clear_refresh_cookie(response)
    return response


@router.post("/logout-all")
async def logout_all(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """현재 사용자의 모든 family revoke — 전 디바이스 로그아웃 (T-009)"""
    stmt = (
        update(RefreshToken)
        .where(
            RefreshToken.user_id == current_user["user_id"],
            RefreshToken.revoked_at.is_(None),
        )
        .values(revoked_at=datetime.utcnow(), revoke_reason="logout-all")
    )
    result = await db.execute(stmt)
    await db.commit()

    response = JSONResponse(content={
        "message": "Logged out from all devices",
        "revoked_count": result.rowcount or 0,
    })
    clear_auth_cookie(response)
    clear_refresh_cookie(response)
    return response


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
            "is_operator": user.is_operator,
            "facility_id": user.facility_id,
            "phone": user.phone,
            "is_active": user.is_active,
            # T-056: pending staff 가 본인 상태 확인 가능. 프론트는 이 값으로 게이트.
            "is_staff_approved": user.is_staff_approved,
            "created_at": user.created_at.isoformat() if user.created_at else None,
        },
        "facility": facility_data,
    }
