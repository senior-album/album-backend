"""
phone OTP 서비스 유닛 테스트 (Redis 없이 인메모리 fallback 경로).
"""

import pytest

from app.services.phone_otp import (
    OtpVerifyError,
    _inmemory_otp,
    normalize_phone,
    send_otp,
    verify_otp,
)


def setup_function(_fn):
    _inmemory_otp.clear()


def test_normalize_phone_strips_non_digits():
    assert normalize_phone("010-1234-5678") == "01012345678"
    assert normalize_phone(" 010 1234 5678 ") == "01012345678"
    assert normalize_phone("") == ""


@pytest.mark.asyncio
async def test_send_then_verify_ok(monkeypatch):
    # SMS 발송은 로그 프로바이더라 실제 네트워크 호출 없음
    phone = "01012345678"
    await send_otp(phone)
    assert phone in _inmemory_otp
    _, payload = _inmemory_otp[phone]
    code = payload["code"]
    assert await verify_otp(phone, code) is True
    # 성공 시 삭제됨
    assert phone not in _inmemory_otp


@pytest.mark.asyncio
async def test_verify_wrong_code_increments_attempts():
    phone = "01099990000"
    await send_otp(phone)
    _, payload = _inmemory_otp[phone]
    wrong = "000000" if payload["code"] != "000000" else "111111"
    with pytest.raises(OtpVerifyError):
        await verify_otp(phone, wrong)
    _, after = _inmemory_otp[phone]
    assert after["attempts"] == 1


@pytest.mark.asyncio
async def test_verify_expired_code_raises():
    with pytest.raises(OtpVerifyError):
        await verify_otp("01000000000", "123456")
