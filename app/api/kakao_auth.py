"""
카카오 OIDC 인증 API
카카오 로그인 (OpenID Connect) → 사용자 생성/로그인 → JWT 발급
"""

import uuid
import logging
import httpx

from fastapi import APIRouter, HTTPException, Depends, Query
from fastapi.responses import JSONResponse
from jose import jwt as jose_jwt, JWTError
from sqlalchemy import select, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import SecurityService, get_current_user, set_auth_cookie
from app.models.models import User, Facility

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth/kakao", tags=["auth"])

KAKAO_AUTH_URL = "https://kauth.kakao.com"
KAKAO_API_URL = "https://kapi.kakao.com"
KAKAO_JWKS_URL = "https://kauth.kakao.com/.well-known/jwks.json"
KAKAO_ISSUER = "https://kauth.kakao.com"

# JWKS 캐시
_kakao_jwks: dict | None = None


async def get_kakao_jwks() -> dict:
    """카카오 JWKS 가져오기 (캐시 사용)"""
    global _kakao_jwks
    if _kakao_jwks is None:
        async with httpx.AsyncClient() as client:
            resp = await client.get(KAKAO_JWKS_URL)
            if resp.status_code != 200:
                raise HTTPException(status_code=500, detail="카카오 JWKS를 가져올 수 없습니다.")
            _kakao_jwks = resp.json()
    return _kakao_jwks


async def verify_kakao_id_token(id_token: str) -> dict:
    """카카오 id_token 서명 검증 및 payload 반환"""
    settings = get_settings()
    jwks = await get_kakao_jwks()

    # id_token 헤더에서 kid 추출
    try:
        header = jose_jwt.get_unverified_header(id_token)
    except JWTError:
        raise HTTPException(status_code=400, detail="유효하지 않은 ID 토큰입니다.")

    kid = header.get("kid")
    if not kid:
        raise HTTPException(status_code=400, detail="ID 토큰에 kid가 없습니다.")

    # kid에 맞는 공개키 찾기
    rsa_key = None
    for key in jwks.get("keys", []):
        if key["kid"] == kid:
            rsa_key = key
            break

    if not rsa_key:
        # JWKS 캐시 갱신 후 재시도
        global _kakao_jwks
        _kakao_jwks = None
        jwks = await get_kakao_jwks()
        for key in jwks.get("keys", []):
            if key["kid"] == kid:
                rsa_key = key
                break

    if not rsa_key:
        raise HTTPException(status_code=400, detail="ID 토큰 검증에 사용할 키를 찾을 수 없습니다.")

    # 서명 검증 + payload 추출
    try:
        payload = jose_jwt.decode(
            id_token,
            rsa_key,
            algorithms=["RS256"],
            audience=settings.KAKAO_CLIENT_ID,
            issuer=KAKAO_ISSUER,
        )
        return payload
    except JWTError as e:
        logger.error(f"Kakao ID token verification failed: {e}")
        raise HTTPException(status_code=400, detail="ID 토큰 검증에 실패했습니다.")


@router.get("/login-url")
async def get_kakao_login_url():
    """프론트에서 사용할 카카오 로그인 URL 반환"""
    settings = get_settings()

    if not settings.KAKAO_CLIENT_ID:
        raise HTTPException(status_code=503, detail="카카오 로그인이 설정되지 않았습니다.")

    url = (
        f"{KAKAO_AUTH_URL}/oauth/authorize"
        f"?client_id={settings.KAKAO_CLIENT_ID}"
        f"&redirect_uri={settings.KAKAO_REDIRECT_URI}"
        f"&response_type=code"
        f"&scope=openid,profile_nickname,account_email,phone_number"
    )
    return {"login_url": url}


@router.post("/callback")
async def kakao_callback(
    code: str,
    db: AsyncSession = Depends(get_db),
):
    """
    카카오 인증 코드 → 토큰 교환 → 사용자 정보 조회 → JWT 발급

    프론트가 카카오 redirect에서 code를 받아 이 API로 전송
    """
    settings = get_settings()

    if not settings.KAKAO_CLIENT_ID:
        raise HTTPException(status_code=503, detail="카카오 로그인이 설정되지 않았습니다.")

    # 1) 인증 코드 → 액세스 토큰 교환
    token_data = {
        "grant_type": "authorization_code",
        "client_id": settings.KAKAO_CLIENT_ID,
        "redirect_uri": settings.KAKAO_REDIRECT_URI,
        "code": code,
    }
    if settings.KAKAO_CLIENT_SECRET:
        token_data["client_secret"] = settings.KAKAO_CLIENT_SECRET

    async with httpx.AsyncClient() as client:
        token_resp = await client.post(
            f"{KAKAO_AUTH_URL}/oauth/token",
            data=token_data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

    if token_resp.status_code != 200:
        logger.error(f"Kakao token exchange failed: {token_resp.text}")
        raise HTTPException(status_code=400, detail="카카오 인증에 실패했습니다.")

    token_json = token_resp.json()

    # 2) id_token 검증 및 사용자 정보 추출 (OIDC)
    id_token = token_json.get("id_token")
    if not id_token:
        raise HTTPException(status_code=400, detail="ID 토큰이 응답에 없습니다. OpenID Connect가 활성화되어 있는지 확인하세요.")

    id_payload = await verify_kakao_id_token(id_token)

    kakao_id = str(id_payload["sub"])
    kakao_name = id_payload.get("nickname", "카카오사용자")
    kakao_email = id_payload.get("email")
    kakao_phone = id_payload.get("phone_number")  # +82 10-xxxx-xxxx 형식
    kakao_profile_image = id_payload.get("picture")

    # 전화번호 정규화 (+82 10-1234-5678 → 010-1234-5678)
    if kakao_phone:
        kakao_phone = normalize_phone(kakao_phone)

    logger.info(
        f"Kakao login: id={kakao_id}, name={kakao_name}, "
        f"email={kakao_email}, phone={kakao_phone}"
    )

    # 3) 기존 사용자 조회 (카카오 ID 또는 이메일로)
    stmt = select(User).filter(
        or_(
            User.provider_id == kakao_id,
            User.email == kakao_email if kakao_email else False,
        )
    )
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    is_new_user = False

    if user:
        # 기존 사용자 — provider 정보 업데이트
        if not user.provider:
            user.provider = "kakao"
            user.provider_id = kakao_id
        if kakao_profile_image:
            user.profile_image = kakao_profile_image
        if kakao_phone and not user.phone:
            user.phone = kakao_phone
        await db.commit()
        await db.refresh(user)
    else:
        # 신규 사용자 — role 없이 임시 생성 (프론트에서 역할 선택)
        is_new_user = True

        if not kakao_email:
            # 이메일 동의 안 한 경우 가짜 이메일 생성
            kakao_email = f"kakao_{kakao_id}@kakao.local"

        user = User(
            id=str(uuid.uuid4()),
            email=kakao_email,
            name=kakao_name,
            password_hash=None,
            role="pending",  # 역할 미정 → 프론트에서 선택
            is_admin=False,
            provider="kakao",
            provider_id=kakao_id,
            profile_image=kakao_profile_image,
            phone=kakao_phone,
        )
        db.add(user)
        await db.commit()
        await db.refresh(user)

    # 4) JWT 발급
    access_token = SecurityService.create_access_token(
        data={
            "sub": user.id,
            "email": user.email,
            "role": user.role,
            "facility_id": user.facility_id,
        }
    )

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

    response = JSONResponse(content={
        "isNewUser": is_new_user,
        "user": {
            "id": user.id,
            "email": user.email,
            "name": user.name,
            "role": user.role,
            "is_admin": user.is_admin,
            "facility_id": user.facility_id,
            "phone": user.phone,
            "profile_image": user.profile_image,
            "is_active": user.is_active,
            "created_at": user.created_at.isoformat() if user.created_at else None,
        },
        "facility": facility_data,
    })
    set_auth_cookie(response, access_token)
    return response


@router.post("/set-role")
async def set_role_after_kakao(
    role: str,
    facility_code: str = None,
    facility_name: str = None,
    facility_address: str = None,
    facility_phone: str = None,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    카카오 최초 로그인 후 역할 설정
    role="pending"인 사용자만 호출 가능
    """
    stmt = select(User).filter(User.id == current_user["user_id"])
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail="사용자를 찾을 수 없습니다.")

    if user.role != "pending":
        raise HTTPException(status_code=400, detail="이미 역할이 설정되어 있습니다.")

    if role == "admin":
        # 시설 생성
        if not facility_name or not facility_address:
            raise HTTPException(status_code=400, detail="시설 이름과 주소가 필요합니다.")

        facility_id = str(uuid.uuid4())
        facility_code_gen = f"FAC-{uuid.uuid4().hex[:6].upper()}"
        facility = Facility(
            id=facility_id,
            name=facility_name,
            address=facility_address,
            phone=facility_phone or "",
            code=facility_code_gen,
        )
        db.add(facility)

        user.role = "staff"
        user.is_admin = True
        user.facility_id = facility_id

    elif role == "staff":
        if not facility_code:
            raise HTTPException(status_code=400, detail="시설 코드가 필요합니다.")

        fac_stmt = select(Facility).filter(Facility.code == facility_code)
        fac_result = await db.execute(fac_stmt)
        facility = fac_result.scalar_one_or_none()
        if not facility:
            raise HTTPException(status_code=404, detail="유효하지 않은 시설 코드입니다.")

        user.role = "staff"
        user.facility_id = facility.id

    elif role == "guardian":
        user.role = "guardian"

    else:
        raise HTTPException(status_code=400, detail="유효하지 않은 역할입니다.")

    await db.commit()
    await db.refresh(user)

    # 새 JWT (역할 반영)
    access_token = SecurityService.create_access_token(
        data={
            "sub": user.id,
            "email": user.email,
            "role": user.role,
            "facility_id": user.facility_id,
        }
    )

    # 시설 정보
    facility_data = None
    if user.facility_id:
        fac_stmt = select(Facility).filter(Facility.id == user.facility_id)
        fac_result = await db.execute(fac_stmt)
        fac = fac_result.scalar_one_or_none()
        if fac:
            facility_data = {
                "id": fac.id,
                "name": fac.name,
                "address": fac.address,
                "phone": fac.phone or "",
                "code": fac.code,
            }

    response = JSONResponse(content={
        "user": {
            "id": user.id,
            "email": user.email,
            "name": user.name,
            "role": user.role,
            "is_admin": user.is_admin,
            "facility_id": user.facility_id,
            "phone": user.phone,
            "profile_image": user.profile_image,
            "is_active": user.is_active,
            "created_at": user.created_at.isoformat() if user.created_at else None,
        },
        "facility": facility_data,
    })
    set_auth_cookie(response, access_token)
    return response


def normalize_phone(phone: str) -> str:
    """카카오 전화번호 정규화: +82 10-1234-5678 → 010-1234-5678"""
    if not phone:
        return phone
    phone = phone.replace(" ", "")
    if phone.startswith("+82"):
        phone = "0" + phone[3:]
    return phone
