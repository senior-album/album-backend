"""
전화번호 OTP 저장·발송·검증.
- 코드는 Redis 에 저장 (key: otp:{phone}), TTL 5분
- 값: JSON {code, attempts}
- Redis 미가동 시 인메모리 fallback — 단일 프로세스 한정 (개발/테스트용)
"""

import json
import logging
import re
import secrets
import time
from typing import Optional

from app.core.config import get_settings
from app.core.redis import get_redis, check_rate_limit
from app.services.sms import get_sms_provider

logger = logging.getLogger(__name__)

# 인메모리 fallback: {phone: (expire_ts, {"code": str, "attempts": int})}
_inmemory_otp: dict[str, tuple[float, dict]] = {}


def normalize_phone(phone: str) -> str:
    """공백/하이픈/괄호 제거, 숫자만."""
    return re.sub(r"\D", "", phone or "")


def _generate_code() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


async def _store_code(phone: str, code: str, ttl: int) -> None:
    r = await get_redis()
    payload = {"code": code, "attempts": 0}
    if r is not None:
        try:
            await r.set(f"otp:{phone}", json.dumps(payload), ex=ttl)
            return
        except Exception as e:
            logger.warning(f"Redis set failed, falling back: {e}")
    _inmemory_otp[phone] = (time.time() + ttl, payload)


async def _load_code(phone: str) -> Optional[dict]:
    r = await get_redis()
    if r is not None:
        try:
            raw = await r.get(f"otp:{phone}")
            if raw is None:
                return None
            return json.loads(raw)
        except Exception as e:
            logger.warning(f"Redis get failed, falling back: {e}")
    entry = _inmemory_otp.get(phone)
    if not entry:
        return None
    expire_ts, payload = entry
    if time.time() > expire_ts:
        _inmemory_otp.pop(phone, None)
        return None
    return payload


async def _save_attempts(phone: str, payload: dict) -> None:
    r = await get_redis()
    if r is not None:
        try:
            ttl = await r.ttl(f"otp:{phone}")
            if ttl and ttl > 0:
                await r.set(f"otp:{phone}", json.dumps(payload), ex=ttl)
                return
        except Exception as e:
            logger.warning(f"Redis update attempts failed: {e}")
    entry = _inmemory_otp.get(phone)
    if entry:
        _inmemory_otp[phone] = (entry[0], payload)


async def _delete_code(phone: str) -> None:
    r = await get_redis()
    if r is not None:
        try:
            await r.delete(f"otp:{phone}")
        except Exception:
            pass
    _inmemory_otp.pop(phone, None)


async def check_send_rate_limits(phone: str, ip: str) -> Optional[tuple[int, str]]:
    """발송 요청 rate limit. (remaining_seconds, message) 반환 시 제한, None 이면 통과."""
    s = get_settings()

    blocked, remaining = await check_rate_limit(
        key=f"otp_send_minute:{phone}",
        max_attempts=s.OTP_SEND_RATE_PER_PHONE_PER_MINUTE,
        window_seconds=60,
    )
    if blocked:
        return remaining, "잠시 후 다시 시도해주세요."

    blocked, remaining = await check_rate_limit(
        key=f"otp_send_hour:{phone}",
        max_attempts=s.OTP_SEND_RATE_PER_PHONE_PER_HOUR,
        window_seconds=3600,
    )
    if blocked:
        return remaining, "해당 번호의 인증 발송 한도를 초과했습니다. 잠시 후 다시 시도해주세요."

    blocked, remaining = await check_rate_limit(
        key=f"otp_send_ip:{ip}",
        max_attempts=s.OTP_SEND_RATE_PER_IP_PER_HOUR,
        window_seconds=3600,
    )
    if blocked:
        return remaining, "요청이 너무 많습니다. 잠시 후 다시 시도해주세요."

    return None


async def send_otp(phone: str) -> None:
    """코드 생성 + 저장 + SMS 발송."""
    s = get_settings()
    code = _generate_code()
    await _store_code(phone, code, s.OTP_TTL_SECONDS)
    provider = get_sms_provider()
    await provider.send(phone, f"[Senior Album] 인증번호: {code} (5분 이내 입력)")


class OtpVerifyError(Exception):
    """code==None: 일치/불일치 에러 메시지를 위한 sentinel"""


async def verify_otp(phone: str, code: str) -> bool:
    """
    코드 검증. 성공 시 코드 삭제 후 True 반환.
    실패 시 attempts 증가, 초과되면 코드 폐기 + OtpVerifyError.
    """
    s = get_settings()
    payload = await _load_code(phone)
    if not payload:
        raise OtpVerifyError("인증번호가 만료되었거나 발급되지 않았습니다.")

    if payload["attempts"] >= s.OTP_MAX_VERIFY_ATTEMPTS:
        await _delete_code(phone)
        raise OtpVerifyError("시도 횟수를 초과했습니다. 인증번호를 다시 요청해주세요.")

    if code.strip() != payload["code"]:
        payload["attempts"] += 1
        await _save_attempts(phone, payload)
        remaining = s.OTP_MAX_VERIFY_ATTEMPTS - payload["attempts"]
        raise OtpVerifyError(f"인증번호가 일치하지 않습니다. (남은 시도 {remaining}회)")

    await _delete_code(phone)
    return True
