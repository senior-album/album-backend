"""
전화번호 OTP 엔드포인트 — 시설 연결 요청 등 "값비싼 액션" 앞에 붙는 game/gate.
"""

import logging
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import get_current_user
from app.models.models import User
from app.schemas.schemas import PhoneOtpSendRequest, PhoneOtpVerifyRequest
from app.services.phone_otp import (
    OtpVerifyError,
    _load_code,
    check_send_rate_limits,
    normalize_phone,
    send_otp,
    verify_otp,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth/phone/otp", tags=["phone_otp"])


def _validate_phone(phone: str) -> str:
    digits = normalize_phone(phone)
    # 한국 휴대폰 번호 기본 검증: 10~11자리, 010 / 011 / 016 / 017 / 018 / 019 시작
    if len(digits) not in (10, 11) or not digits.startswith("01"):
        raise HTTPException(status_code=400, detail="올바른 휴대폰 번호 형식이 아닙니다.")
    return digits


@router.post("/send")
async def send_phone_otp(
    body: PhoneOtpSendRequest,
    req: Request,
    current_user: dict = Depends(get_current_user),
):
    """인증번호 발송. 인증된 사용자만 호출 가능 (자기 번호 전용)."""
    phone = _validate_phone(body.phone)
    ip = req.client.host if req.client else "unknown"

    limited = await check_send_rate_limits(phone, ip)
    if limited:
        remaining, msg = limited
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=msg)

    await send_otp(phone)
    logger.info(f"OTP sent to {phone[:3]}****{phone[-4:]} by user={current_user['user_id']}")
    return {"message": "인증번호를 발송했습니다.", "ttl_seconds": 300}


@router.post("/verify")
async def verify_phone_otp(
    body: PhoneOtpVerifyRequest,
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    인증번호 검증. 성공 시 User.phone + phone_verified_at 을 갱신해
    이후 10분 이내의 시설 연결 요청이 게이트를 통과할 수 있게 한다.
    """
    phone = _validate_phone(body.phone)

    try:
        await verify_otp(phone, body.code)
    except OtpVerifyError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # 사용자 전화번호 + 인증 시각 업데이트
    stmt = select(User).filter(User.id == current_user["user_id"])
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="사용자를 찾을 수 없습니다.")

    user.phone = phone
    user.phone_verified_at = datetime.utcnow()
    await db.commit()

    return {"message": "인증되었습니다.", "verified_at": user.phone_verified_at.isoformat()}


@router.get("/peek")
async def peek_phone_otp(phone: str, current_user: dict = Depends(get_current_user)):
    """
    [DEBUG 전용] 발송된 OTP 를 그대로 반환.
    DEBUG=True 이고 SMS_PROVIDER=log 일 때만 동작 — 운영 환경(DEBUG=False)에서는 404.

    개발 중 실제 SMS 없이 테스트하려고 둠. 로그에서 코드 찾는 것보다 편리.
    """
    settings = get_settings()
    if not settings.DEBUG or settings.SMS_PROVIDER != "log":
        raise HTTPException(status_code=404, detail="Not found")

    normalized = _validate_phone(phone)
    payload = await _load_code(normalized)
    if not payload:
        raise HTTPException(status_code=404, detail="저장된 OTP 가 없습니다. 먼저 /send 를 호출하세요.")

    logger.warning(f"[DEBUG] OTP peek by user={current_user['user_id']} phone={normalized[:3]}****{normalized[-4:]}")
    return {"phone": normalized, "code": payload["code"], "attempts": payload["attempts"]}
