"""
SMS 발송 추상화. config_gated 로 프로바이더 선택.
- log: 로그에만 출력 (개발/테스트)
- coolsms: 프로덕션 — CoolSMS 4.x REST + HMAC-SHA256
"""

import hashlib
import hmac
import logging
import secrets
from abc import ABC, abstractmethod
from datetime import datetime, timezone

import httpx

from app.core.config import get_settings

logger = logging.getLogger(__name__)

COOLSMS_ENDPOINT = "https://api.coolsms.co.kr/messages/v4/send"
COOLSMS_TIMEOUT_SECONDS = 5.0


class SmsProvider(ABC):
    @abstractmethod
    async def send(self, phone: str, message: str) -> None:
        ...


class LogSmsProvider(SmsProvider):
    async def send(self, phone: str, message: str) -> None:
        logger.info(f"[SMS:log] to={phone} msg={message!r}")


class CoolSmsProvider(SmsProvider):
    """CoolSMS 4.x REST + HMAC-SHA256. docs/COOLSMS_SETUP.md 옵션 B."""

    async def send(self, phone: str, message: str) -> None:
        settings = get_settings()
        api_key = settings.COOLSMS_API_KEY
        api_secret = settings.COOLSMS_API_SECRET
        from_number = settings.COOLSMS_FROM_NUMBER
        if not (api_key and api_secret and from_number):
            raise RuntimeError(
                "CoolSMS 설정 누락: COOLSMS_API_KEY / COOLSMS_API_SECRET / COOLSMS_FROM_NUMBER 필요"
            )

        date = datetime.now(timezone.utc).isoformat()
        salt = secrets.token_hex(16)
        signature = hmac.new(
            api_secret.encode("utf-8"),
            (date + salt).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        authorization = (
            f"HMAC-SHA256 apiKey={api_key}, date={date}, "
            f"salt={salt}, signature={signature}"
        )
        body = {
            "message": {
                "to": phone,
                "from": from_number,
                "text": message,
            }
        }
        try:
            async with httpx.AsyncClient(timeout=COOLSMS_TIMEOUT_SECONDS) as client:
                resp = await client.post(
                    COOLSMS_ENDPOINT,
                    headers={
                        "Authorization": authorization,
                        "Content-Type": "application/json",
                    },
                    json=body,
                )
        except httpx.HTTPError as e:
            logger.error(f"[SMS:coolsms] HTTP error: {e}")
            raise

        if resp.status_code >= 400:
            # CoolSMS 는 에러 시 JSON 으로 errorCode/errorMessage 반환.
            # 본문에 OTP 가 들어있을 수 있으니 응답 body 만 로깅 (요청 body 는 X).
            logger.error(
                f"[SMS:coolsms] send failed: status={resp.status_code} body={resp.text!r}"
            )
            raise RuntimeError(f"CoolSMS 발송 실패 (status={resp.status_code})")

        logger.info(f"[SMS:coolsms] to={phone} ok")


def get_sms_provider() -> SmsProvider:
    settings = get_settings()
    if settings.SMS_PROVIDER == "coolsms":
        return CoolSmsProvider()
    return LogSmsProvider()
