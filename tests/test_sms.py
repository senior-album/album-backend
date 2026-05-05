"""
SMS 프로바이더 유닛 테스트.
- LogSmsProvider: 로그만 찍고 끝
- CoolSmsProvider: 4.x REST 호출 — httpx 모킹
"""

import pytest

from app.services.sms import (
    CoolSmsProvider,
    LogSmsProvider,
    get_sms_provider,
)


class _FakeResponse:
    def __init__(self, status_code: int, text: str = ""):
        self.status_code = status_code
        self.text = text


class _FakeAsyncClient:
    """httpx.AsyncClient stub. 마지막 요청을 기록하고 정해진 응답 반환."""

    last_call: dict | None = None

    def __init__(self, response: _FakeResponse, *, raise_exc: Exception | None = None):
        self._response = response
        self._raise_exc = raise_exc

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def post(self, url, *, headers, json):
        type(self).last_call = {"url": url, "headers": headers, "json": json}
        if self._raise_exc:
            raise self._raise_exc
        return self._response


@pytest.fixture(autouse=True)
def _reset_fake_client():
    _FakeAsyncClient.last_call = None
    yield


@pytest.fixture(autouse=True)
def _required_settings_env(monkeypatch):
    """settings 인스턴스화 필수 env (.env 누락 우회용 더미)."""
    from app.core import config as cfg

    monkeypatch.setenv("JWT_SECRET", "test-jwt-secret")
    monkeypatch.setenv("JWT_REFRESH_SECRET", "test-refresh-secret")
    monkeypatch.setenv("RESIDENT_PII_KEK", "0" * 64)
    monkeypatch.setenv("RESIDENT_NAME_HMAC_KEY", "0" * 64)
    cfg.get_settings.cache_clear()
    yield
    cfg.get_settings.cache_clear()


@pytest.mark.asyncio
async def test_log_provider_does_not_raise():
    p = LogSmsProvider()
    await p.send("01012345678", "hello")  # 그냥 안 터지면 OK


@pytest.mark.asyncio
async def test_get_provider_defaults_to_log(monkeypatch):
    from app.core import config as cfg

    cfg.get_settings.cache_clear()
    monkeypatch.delenv("SMS_PROVIDER", raising=False)
    try:
        assert isinstance(get_sms_provider(), LogSmsProvider)
    finally:
        cfg.get_settings.cache_clear()


@pytest.mark.asyncio
async def test_get_provider_returns_coolsms_when_configured(monkeypatch):
    from app.core import config as cfg

    cfg.get_settings.cache_clear()
    monkeypatch.setenv("SMS_PROVIDER", "coolsms")
    try:
        assert isinstance(get_sms_provider(), CoolSmsProvider)
    finally:
        cfg.get_settings.cache_clear()


@pytest.mark.asyncio
async def test_coolsms_raises_when_keys_missing(monkeypatch):
    from app.core import config as cfg

    cfg.get_settings.cache_clear()
    monkeypatch.setenv("COOLSMS_API_KEY", "")
    monkeypatch.setenv("COOLSMS_API_SECRET", "")
    monkeypatch.setenv("COOLSMS_FROM_NUMBER", "")
    try:
        p = CoolSmsProvider()
        with pytest.raises(RuntimeError, match="CoolSMS 설정 누락"):
            await p.send("01012345678", "hi")
    finally:
        cfg.get_settings.cache_clear()


@pytest.mark.asyncio
async def test_coolsms_signs_request_and_calls_endpoint(monkeypatch):
    from app.core import config as cfg
    from app.services import sms as sms_module

    cfg.get_settings.cache_clear()
    monkeypatch.setenv("COOLSMS_API_KEY", "K_TEST")
    monkeypatch.setenv("COOLSMS_API_SECRET", "S_TEST")
    monkeypatch.setenv("COOLSMS_FROM_NUMBER", "01099998888")

    fake = _FakeAsyncClient(_FakeResponse(200, '{"statusCode":"2000"}'))
    monkeypatch.setattr(sms_module.httpx, "AsyncClient", lambda *a, **kw: fake)

    try:
        await CoolSmsProvider().send("01012345678", "hello")
    finally:
        cfg.get_settings.cache_clear()

    call = _FakeAsyncClient.last_call
    assert call is not None
    assert call["url"] == sms_module.COOLSMS_ENDPOINT
    assert call["json"] == {
        "message": {"to": "01012345678", "from": "01099998888", "text": "hello"}
    }
    auth = call["headers"]["Authorization"]
    assert auth.startswith("HMAC-SHA256 apiKey=K_TEST,")
    assert "date=" in auth and "salt=" in auth and "signature=" in auth


@pytest.mark.asyncio
async def test_coolsms_raises_on_4xx(monkeypatch):
    from app.core import config as cfg
    from app.services import sms as sms_module

    cfg.get_settings.cache_clear()
    monkeypatch.setenv("COOLSMS_API_KEY", "K_TEST")
    monkeypatch.setenv("COOLSMS_API_SECRET", "S_TEST")
    monkeypatch.setenv("COOLSMS_FROM_NUMBER", "01099998888")

    fake = _FakeAsyncClient(_FakeResponse(403, '{"errorCode":"ValidationError"}'))
    monkeypatch.setattr(sms_module.httpx, "AsyncClient", lambda *a, **kw: fake)

    try:
        with pytest.raises(RuntimeError, match="CoolSMS 발송 실패"):
            await CoolSmsProvider().send("01012345678", "hi")
    finally:
        cfg.get_settings.cache_clear()


@pytest.mark.asyncio
async def test_coolsms_propagates_httpx_error(monkeypatch):
    import httpx as _httpx

    from app.core import config as cfg
    from app.services import sms as sms_module

    cfg.get_settings.cache_clear()
    monkeypatch.setenv("COOLSMS_API_KEY", "K_TEST")
    monkeypatch.setenv("COOLSMS_API_SECRET", "S_TEST")
    monkeypatch.setenv("COOLSMS_FROM_NUMBER", "01099998888")

    fake = _FakeAsyncClient(
        _FakeResponse(200), raise_exc=_httpx.ConnectTimeout("boom")
    )
    monkeypatch.setattr(sms_module.httpx, "AsyncClient", lambda *a, **kw: fake)

    try:
        with pytest.raises(_httpx.HTTPError):
            await CoolSmsProvider().send("01012345678", "hi")
    finally:
        cfg.get_settings.cache_clear()
