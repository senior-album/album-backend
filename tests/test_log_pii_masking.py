"""
T-103: PII 로깅 마스킹 필터 단위 테스트.
"""

import logging
import pytest

from app.core.logging_filters import PIIRedactionFilter, redact


def test_email_masked():
    assert redact("user test@example.com logged in") == "user t***@example.com logged in"


def test_email_subdomain():
    assert redact("foo.bar+tag@sub.example.co.kr") == "f***@sub.example.co.kr"


def test_phone_with_dashes():
    assert redact("call 010-1234-5678 now") == "call 010-****-5678 now"


def test_phone_no_delimiter():
    assert redact("phone=01012345678 ok") == "phone=010-****-5678 ok"


def test_phone_with_spaces():
    assert redact("phone 010 1234 5678") == "phone 010-****-5678"


def test_non_mobile_not_masked():
    # 일반 전화(02, 031 등)는 패턴 외 — 그대로.
    assert redact("02-1234-5678") == "02-1234-5678"


def test_uuid_not_mistaken_for_phone():
    # UUID hex 조각이 01x 로 시작해도 앞뒤 숫자 컨텍스트로 제외되어야.
    s = "id=0123456789abcdef"
    assert redact(s) == s


def test_multiple_hits_in_one_line():
    out = redact("u a@b.io phone 010-1111-2222 and 010-3333-4444")
    assert "a***@b.io" in out
    assert "010-****-2222" in out
    assert "010-****-4444" in out


def test_filter_mutates_record_msg_fstring():
    flt = PIIRedactionFilter()
    rec = logging.LogRecord(
        name="x", level=logging.INFO, pathname=__file__, lineno=1,
        msg="Admin registered: test@example.com, 010-1234-5678",
        args=None, exc_info=None,
    )
    assert flt.filter(rec) is True
    assert rec.getMessage() == "Admin registered: t***@example.com, 010-****-5678"


def test_filter_handles_printf_style_args():
    flt = PIIRedactionFilter()
    rec = logging.LogRecord(
        name="x", level=logging.INFO, pathname=__file__, lineno=1,
        msg="user=%s phone=%s", args=("alice@mail.com", "01099998888"),
        exc_info=None,
    )
    assert flt.filter(rec) is True
    # args 로 들어온 PII 도 redact — 필터가 먼저 포맷한 뒤 치환하기 때문.
    assert rec.getMessage() == "user=a***@mail.com phone=010-****-8888"


def test_filter_non_pii_untouched():
    flt = PIIRedactionFilter()
    rec = logging.LogRecord(
        name="x", level=logging.INFO, pathname=__file__, lineno=1,
        msg="Database initialized successfully", args=None, exc_info=None,
    )
    assert flt.filter(rec) is True
    assert rec.getMessage() == "Database initialized successfully"


def test_filter_is_idempotent():
    flt = PIIRedactionFilter()
    rec = logging.LogRecord(
        name="x", level=logging.INFO, pathname=__file__, lineno=1,
        msg="send to a@b.io", args=None, exc_info=None,
    )
    assert flt.filter(rec) is True
    first = rec.getMessage()
    assert flt.filter(rec) is True
    assert rec.getMessage() == first
