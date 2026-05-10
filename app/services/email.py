"""
이메일 발송 추상화. config_gated 로 프로바이더 선택. sms.py 와 동일 패턴.
- log: 로그에만 출력 (개발/테스트, 기본값)
- brevo: 프로덕션 — Brevo Transactional Email API v3 (영구 무료 일 300통)

T-305 (roadmap#228). T-306 (비밀번호 재설정) 의 prerequisite.
"""

import logging
from abc import ABC, abstractmethod
from typing import Optional

import httpx

from app.core.config import get_settings

logger = logging.getLogger(__name__)

BREVO_ENDPOINT = "https://api.brevo.com/v3/smtp/email"
BREVO_TIMEOUT_SECONDS = 5.0


class EmailProvider(ABC):
    @abstractmethod
    async def send(
        self,
        to: str,
        subject: str,
        html: str,
        text: Optional[str] = None,
    ) -> None:
        ...


class LogEmailProvider(EmailProvider):
    async def send(
        self,
        to: str,
        subject: str,
        html: str,
        text: Optional[str] = None,
    ) -> None:
        # 본문은 길어질 수 있으니 길이만. subject 는 그대로 (PII 우려 낮음 — 본문은
        # 토큰/링크 포함 가능성 있어 마스킹).
        logger.info(
            f"[EMAIL:log] to={to} subject={subject!r} "
            f"html_len={len(html)} text_len={len(text) if text else 0}"
        )


class BrevoEmailProvider(EmailProvider):
    """Brevo (구 Sendinblue) Transactional Email API v3.

    docs/EMAIL_DNS.md 참조 — 발송 도메인의 SPF / DKIM / DMARC 레코드를 Cloudflare
    에 1회 셋업해야 deliverability 가 안정. 미설정 시 메일이 스팸함 직행.
    """

    async def send(
        self,
        to: str,
        subject: str,
        html: str,
        text: Optional[str] = None,
    ) -> None:
        settings = get_settings()
        api_key = settings.BREVO_API_KEY
        from_email = settings.BREVO_FROM_EMAIL
        from_name = settings.BREVO_FROM_NAME or "Senior Album"
        if not (api_key and from_email):
            raise RuntimeError(
                "Brevo 설정 누락: BREVO_API_KEY / BREVO_FROM_EMAIL 필요"
            )

        body: dict = {
            "sender": {"name": from_name, "email": from_email},
            "to": [{"email": to}],
            "subject": subject,
            "htmlContent": html,
        }
        if text:
            body["textContent"] = text

        try:
            async with httpx.AsyncClient(timeout=BREVO_TIMEOUT_SECONDS) as client:
                resp = await client.post(
                    BREVO_ENDPOINT,
                    headers={
                        "api-key": api_key,
                        "content-type": "application/json",
                        "accept": "application/json",
                    },
                    json=body,
                )
        except httpx.HTTPError as e:
            logger.error(f"[EMAIL:brevo] HTTP error: {e}")
            raise

        if resp.status_code >= 400:
            # Brevo 에러: { "code": "...", "message": "..." }. 본문에 토큰/링크가
            # 들어있을 수 있어 응답 body 만 로깅 (요청 body 는 X).
            logger.error(
                f"[EMAIL:brevo] send failed: status={resp.status_code} body={resp.text!r}"
            )
            raise RuntimeError(f"Brevo 발송 실패 (status={resp.status_code})")

        logger.info(f"[EMAIL:brevo] to={to} ok")


def get_email_provider() -> EmailProvider:
    settings = get_settings()
    if settings.EMAIL_PROVIDER == "brevo":
        return BrevoEmailProvider()
    return LogEmailProvider()
