"""
카카오 OIDC 인증 API
카카오 로그인 (OpenID Connect) → 사용자 생성/로그인 → JWT 발급
"""

import uuid
import secrets
import logging
from datetime import datetime
import httpx

from fastapi import APIRouter, HTTPException, Depends, Query, Request
from fastapi.responses import JSONResponse
from jose import jwt as jose_jwt, JWTError
from sqlalchemy import select, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import SecurityService, get_current_user, set_auth_cookie, set_refresh_cookie
from app.api.auth import _issue_token_pair
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


OAUTH_STATE_COOKIE = "kakao_oauth_state"
OAUTH_STATE_MAX_AGE = 600  # 10분


@router.get("/login-url")
async def get_kakao_login_url():
    """프론트에서 사용할 카카오 로그인 URL 반환 (CSRF 방지용 state 포함)"""
    settings = get_settings()

    if not settings.KAKAO_CLIENT_ID:
        raise HTTPException(status_code=503, detail="카카오 로그인이 설정되지 않았습니다.")

    state = secrets.token_urlsafe(32)
    url = (
        f"{KAKAO_AUTH_URL}/oauth/authorize"
        f"?client_id={settings.KAKAO_CLIENT_ID}"
        f"&redirect_uri={settings.KAKAO_REDIRECT_URI}"
        f"&response_type=code"
        f"&scope={settings.KAKAO_SCOPES}"
        f"&state={state}"
    )
    resp = JSONResponse({"login_url": url})
    resp.set_cookie(
        OAUTH_STATE_COOKIE,
        state,
        max_age=OAUTH_STATE_MAX_AGE,
        httponly=True,
        secure=not settings.DEBUG,
        samesite="lax",
        path="/",
    )
    return resp


@router.post("/callback")
async def kakao_callback(
    request: Request,
    code: str,
    state: str = Query(..., description="login-url에서 발급받은 CSRF state"),
    db: AsyncSession = Depends(get_db),
):
    """
    카카오 인증 코드 → 토큰 교환 → 사용자 정보 조회 → JWT 발급

    프론트가 카카오 redirect에서 code/state를 받아 이 API로 전송.
    쿠키에 저장된 state와 쿼리 state를 비교해 CSRF 차단.
    """
    settings = get_settings()

    if not settings.KAKAO_CLIENT_ID:
        raise HTTPException(status_code=503, detail="카카오 로그인이 설정되지 않았습니다.")

    # 0) CSRF state 검증 (쿼리 state ↔ 쿠키 state)
    cookie_state = request.cookies.get(OAUTH_STATE_COOKIE)
    if not cookie_state or not secrets.compare_digest(cookie_state, state):
        logger.warning(f"Kakao OAuth state mismatch: cookie={bool(cookie_state)}, match={cookie_state == state if cookie_state else False}")
        raise HTTPException(status_code=400, detail="유효하지 않은 state — CSRF 공격으로 의심됩니다.")

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
    kakao_name = id_payload.get("nickname")
    kakao_email = id_payload.get("email")
    kakao_phone = id_payload.get("phone_number")  # +82 10-xxxx-xxxx 형식 (비즈앱 필요)
    kakao_profile_image = id_payload.get("picture")

    # openid만 있으면 nickname이 없을 수 있음 → 카카오 사용자 API로 보충
    if not kakao_name:
        access_token_str = token_json.get("access_token")
        if access_token_str:
            try:
                async with httpx.AsyncClient() as client:
                    user_resp = await client.get(
                        f"{KAKAO_API_URL}/v2/user/me",
                        headers={"Authorization": f"Bearer {access_token_str}"},
                    )
                    if user_resp.status_code == 200:
                        user_info = user_resp.json()
                        props = user_info.get("properties", {})
                        account = user_info.get("kakao_account", {})
                        kakao_name = props.get("nickname") or account.get("profile", {}).get("nickname")
                        if not kakao_email:
                            kakao_email = account.get("email")
                        if not kakao_profile_image:
                            kakao_profile_image = props.get("profile_image") or account.get("profile", {}).get("profile_image_url")
            except Exception as e:
                logger.warning(f"Failed to fetch Kakao user info as fallback: {e}")

    kakao_name = kakao_name or "카카오사용자"

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

    # 4) JWT 쌍 발급 (T-009: access + refresh, 신규 family)
    family_id = str(uuid.uuid4())
    access_token, refresh_jwt = await _issue_token_pair(db, user, family_id, request)
    await db.commit()

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
            "is_operator": user.is_operator,
            "facility_id": user.facility_id,
            "phone": user.phone,
            "profile_image": user.profile_image,
            "is_active": user.is_active,
            "created_at": user.created_at.isoformat() if user.created_at else None,
        },
        "facility": facility_data,
    })
    set_auth_cookie(response, access_token)
    set_refresh_cookie(response, refresh_jwt)
    response.delete_cookie(OAUTH_STATE_COOKIE, path="/")
    return response


@router.post("/set-role")
async def set_role_after_kakao(
    req: Request,
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
        # T-056: 시설장 본인은 자기 자신 자동 승인.
        user.is_staff_approved = True
        user.staff_approved_by = user.id
        user.staff_approved_at = datetime.utcnow()

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
        # T-056: 시설장 승인 전엔 pending — verify_facility_access 가 차단.
        user.is_staff_approved = False

    elif role == "guardian":
        user.role = "guardian"

    else:
        raise HTTPException(status_code=400, detail="유효하지 않은 역할입니다.")

    await db.commit()
    await db.refresh(user)

    # 새 JWT 쌍 (역할 반영, T-009: 신규 family로 발급)
    family_id = str(uuid.uuid4())
    access_token, refresh_jwt = await _issue_token_pair(db, user, family_id, req)
    await db.commit()

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
            "is_operator": user.is_operator,
            "facility_id": user.facility_id,
            "phone": user.phone,
            "profile_image": user.profile_image,
            "is_active": user.is_active,
            "created_at": user.created_at.isoformat() if user.created_at else None,
        },
        "facility": facility_data,
    })
    set_auth_cookie(response, access_token)
    set_refresh_cookie(response, refresh_jwt)
    return response


def normalize_phone(phone: str) -> str:
    """카카오 전화번호 정규화: +82 10-1234-5678 → 010-1234-5678"""
    if not phone:
        return phone
    phone = phone.replace(" ", "")
    if phone.startswith("+82"):
        phone = "0" + phone[3:]
    return phone
