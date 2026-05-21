"""
전화번호 OTP 엔드포인트 — 시설 연결 요청 등 "값비싼 액션" 앞에 붙는 game/gate.
"""

import logging
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.crypto import phone_blind_index
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

PHONE_DUP_DETAIL = "이미 다른 계정에 등록된 번호입니다."

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
    인증번호 검증. 성공 시 User.phone + phone_verified_at 을 갱신.
    이미 다른 계정에 등록된 번호면 409 — 프론트가 신고 (POST /support/phone-claim) 안내.
    """
    phone = _validate_phone(body.phone)

    try:
        await verify_otp(phone, body.code)
    except OtpVerifyError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # 다른 계정이 이미 그 phone 으로 등록돼있는지 사전 검사 (race 는 commit 의 IntegrityError 가 잡음).
    # T-320-3: blind-index 매칭으로 전환 — phone 은 위에서 _validate_phone 으로 이미 정규화.
    dup_stmt = select(User).filter(
        User.phone_bi == phone_blind_index(phone),
        User.id != current_user["user_id"],
    )
    if (await db.execute(dup_stmt)).scalar_one_or_none():
        raise HTTPException(status_code=409, detail=PHONE_DUP_DETAIL)

    stmt = select(User).filter(User.id == current_user["user_id"])
    user = (await db.execute(stmt)).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="사용자를 찾을 수 없습니다.")

    user.phone = phone
    user.phone_verified_at = datetime.utcnow()
    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=409, detail=PHONE_DUP_DETAIL)

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
