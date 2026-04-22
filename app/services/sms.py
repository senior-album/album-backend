"""
SMS 발송 추상화. config_gated 로 프로바이더 선택.
- log: 로그에만 출력 (개발/테스트)
- coolsms: 프로덕션 (현 PR 에서는 stub — 후속 PR 에서 구현)
"""

import logging
from abc import ABC, abstractmethod

from app.core.config import get_settings

logger = logging.getLogger(__name__)


class SmsProvider(ABC):
    @abstractmethod
    async def send(self, phone: str, message: str) -> None:
        ...


class LogSmsProvider(SmsProvider):
    async def send(self, phone: str, message: str) -> None:
        logger.info(f"[SMS:log] to={phone} msg={message!r}")


class CoolSmsProvider(SmsProvider):
    """CoolSMS 어댑터 — 후속 PR 에서 실제 연동 (API 키, 발신번호 등록 필요)"""

    async def send(self, phone: str, message: str) -> None:
        settings = get_settings()
        if not settings.COOLSMS_API_KEY:
            raise RuntimeError("COOLSMS_API_KEY 가 설정되지 않았습니다.")
        # TODO: coolsms_python_sdk 또는 HTTP 호출 구현
        logger.warning(f"[SMS:coolsms:stub] to={phone} — 실제 발송 미구현")


def get_sms_provider() -> SmsProvider:
    settings = get_settings()
    if settings.SMS_PROVIDER == "coolsms":
        return CoolSmsProvider()
    return LogSmsProvider()
