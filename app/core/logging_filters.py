"""
T-103: 애플리케이션 로그에서 PII 마스킹.

이메일 / 한국 휴대폰 번호를 LogRecord 의 최종 메시지에서 redact 한다.
Filter 로 구현해서 root logger 에 한 번만 붙이면 모든 child logger 에 적용.

이름(한글) 마스킹은 일반 한글 토큰과 구분이 어려워 false positive 위험이
크므로 이 PR 에서는 제외 — PII 이름이 로그로 들어가는 경로는 auth/주소록 등
소수라 호출부에서 개별적으로 빼는 편이 안전.
"""

from __future__ import annotations

import logging
import re


_EMAIL_RE = re.compile(r"[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}")

# 한국 휴대폰(010/011/016/017/018/019) - 구분자 -, 공백, 없음 모두 허용.
# 앞뒤로 숫자가 붙어있으면 다른 숫자열(예: UUID 일부)일 가능성이 높아 제외.
_KR_PHONE_RE = re.compile(r"(?<!\d)(01[016789])[\s-]?(\d{3,4})[\s-]?(\d{4})(?!\d)")


def _mask_email(m: "re.Match[str]") -> str:
    local, _, rest = m.group(0).partition("@")
    if not local:
        return m.group(0)
    head = local[0]
    return f"{head}***@{rest}"


def _mask_phone(m: "re.Match[str]") -> str:
    return f"{m.group(1)}-****-{m.group(3)}"


def redact(message: str) -> str:
    """이메일 / 한국 휴대폰 번호를 마스킹한 문자열 반환."""
    message = _EMAIL_RE.sub(_mask_email, message)
    message = _KR_PHONE_RE.sub(_mask_phone, message)
    return message


class PIIRedactionFilter(logging.Filter):
    """
    LogRecord 의 최종 포맷 메시지에서 PII 를 마스킹.

    root logger 에 attach 하는 것을 전제 — 모든 child 가 propagate 로 root 에
    도달하므로 한 번만 붙이면 전체 로그에 적용된다. Handler 의 formatter 가
    record.msg 를 그대로 쓰도록 args 는 None 으로 치환.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:
            return True
        redacted = redact(message)
        if redacted != message:
            record.msg = redacted
            record.args = None
        return True
