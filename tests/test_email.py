"""
이메일 프로바이더 유닛 테스트 (T-305).
- LogEmailProvider: 로그만 찍고 끝
- BrevoEmailProvider: Brevo Transactional Email v3 — httpx 모킹
"""

import pytest

from app.services.email import (
    BrevoEmailProvider,
    LogEmailProvider,
    get_email_provider,
)


class _FakeResponse:
    def __init__(self, status_code: int, text: str = ""):
        self.status_code = status_code
        self.text = text


class _FakeAsyncClient:
    """httpx.AsyncClient stub. 마지막 요청 기록 + 정해진 응답 반환."""

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
    p = LogEmailProvider()
    await p.send(to="x@example.com", subject="hi", html="<p>hi</p>", text="hi")


@pytest.mark.asyncio
async def test_get_provider_defaults_to_log(monkeypatch):
    from app.core import config as cfg

    cfg.get_settings.cache_clear()
    monkeypatch.delenv("EMAIL_PROVIDER", raising=False)
    try:
        assert isinstance(get_email_provider(), LogEmailProvider)
    finally:
        cfg.get_settings.cache_clear()


@pytest.mark.asyncio
async def test_get_provider_returns_brevo_when_configured(monkeypatch):
    from app.core import config as cfg

    cfg.get_settings.cache_clear()
    monkeypatch.setenv("EMAIL_PROVIDER", "brevo")
    try:
        assert isinstance(get_email_provider(), BrevoEmailProvider)
    finally:
        cfg.get_settings.cache_clear()


@pytest.mark.asyncio
async def test_brevo_raises_when_keys_missing(monkeypatch):
    from app.core import config as cfg

    cfg.get_settings.cache_clear()
    monkeypatch.setenv("BREVO_API_KEY", "")
    monkeypatch.setenv("BREVO_FROM_EMAIL", "")
    try:
        p = BrevoEmailProvider()
        with pytest.raises(RuntimeError, match="Brevo 설정 누락"):
            await p.send(to="x@example.com", subject="s", html="<p>h</p>")
    finally:
        cfg.get_settings.cache_clear()


@pytest.mark.asyncio
async def test_brevo_sends_with_correct_payload(monkeypatch):
    from app.core import config as cfg
    from app.services import email as email_module

    cfg.get_settings.cache_clear()
    monkeypatch.setenv("BREVO_API_KEY", "key-test")
    monkeypatch.setenv("BREVO_FROM_EMAIL", "noreply@senior-album.com")
    monkeypatch.setenv("BREVO_FROM_NAME", "Senior Album")

    fake = _FakeAsyncClient(_FakeResponse(201, '{"messageId":"<...>"}'))
    monkeypatch.setattr(email_module.httpx, "AsyncClient", lambda *a, **kw: fake)

    try:
        await BrevoEmailProvider().send(
            to="parent@example.com",
            subject="비밀번호 재설정",
            html="<p>링크</p>",
            text="링크",
        )
    finally:
        cfg.get_settings.cache_clear()

    call = _FakeAsyncClient.last_call
    assert call is not None
    assert call["url"] == email_module.BREVO_ENDPOINT
    assert call["headers"]["api-key"] == "key-test"
    assert call["headers"]["content-type"] == "application/json"
    assert call["json"] == {
        "sender": {"name": "Senior Album", "email": "noreply@senior-album.com"},
        "to": [{"email": "parent@example.com"}],
        "subject": "비밀번호 재설정",
        "htmlContent": "<p>링크</p>",
        "textContent": "링크",
    }


@pytest.mark.asyncio
async def test_brevo_omits_text_when_not_given(monkeypatch):
    from app.core import config as cfg
    from app.services import email as email_module

    cfg.get_settings.cache_clear()
    monkeypatch.setenv("BREVO_API_KEY", "key-test")
    monkeypatch.setenv("BREVO_FROM_EMAIL", "noreply@senior-album.com")

    fake = _FakeAsyncClient(_FakeResponse(201, ""))
    monkeypatch.setattr(email_module.httpx, "AsyncClient", lambda *a, **kw: fake)

    try:
        await BrevoEmailProvider().send(
            to="x@example.com",
            subject="s",
            html="<p>h</p>",
        )
    finally:
        cfg.get_settings.cache_clear()

    call = _FakeAsyncClient.last_call
    assert call is not None
    assert "textContent" not in call["json"]


@pytest.mark.asyncio
async def test_brevo_default_from_name_when_unset(monkeypatch):
    from app.core import config as cfg
    from app.services import email as email_module

    cfg.get_settings.cache_clear()
    monkeypatch.setenv("BREVO_API_KEY", "key-test")
    monkeypatch.setenv("BREVO_FROM_EMAIL", "noreply@senior-album.com")
    monkeypatch.setenv("BREVO_FROM_NAME", "")

    fake = _FakeAsyncClient(_FakeResponse(201, ""))
    monkeypatch.setattr(email_module.httpx, "AsyncClient", lambda *a, **kw: fake)

    try:
        await BrevoEmailProvider().send(to="x@example.com", subject="s", html="<p>h</p>")
    finally:
        cfg.get_settings.cache_clear()

    call = _FakeAsyncClient.last_call
    assert call is not None
    assert call["json"]["sender"]["name"] == "Senior Album"


@pytest.mark.asyncio
async def test_brevo_raises_on_4xx(monkeypatch):
    from app.core import config as cfg
    from app.services import email as email_module

    cfg.get_settings.cache_clear()
    monkeypatch.setenv("BREVO_API_KEY", "key-test")
    monkeypatch.setenv("BREVO_FROM_EMAIL", "noreply@senior-album.com")

    fake = _FakeAsyncClient(_FakeResponse(401, '{"code":"unauthorized"}'))
    monkeypatch.setattr(email_module.httpx, "AsyncClient", lambda *a, **kw: fake)

    try:
        with pytest.raises(RuntimeError, match="Brevo 발송 실패"):
            await BrevoEmailProvider().send(to="x@example.com", subject="s", html="<p>h</p>")
    finally:
        cfg.get_settings.cache_clear()


@pytest.mark.asyncio
async def test_brevo_propagates_httpx_error(monkeypatch):
    import httpx as _httpx

    from app.core import config as cfg
    from app.services import email as email_module

    cfg.get_settings.cache_clear()
    monkeypatch.setenv("BREVO_API_KEY", "key-test")
    monkeypatch.setenv("BREVO_FROM_EMAIL", "noreply@senior-album.com")

    fake = _FakeAsyncClient(
        _FakeResponse(0), raise_exc=_httpx.ConnectError("network down")
    )
    monkeypatch.setattr(email_module.httpx, "AsyncClient", lambda *a, **kw: fake)

    try:
        with pytest.raises(_httpx.HTTPError):
            await BrevoEmailProvider().send(to="x@example.com", subject="s", html="<p>h</p>")
    finally:
        cfg.get_settings.cache_clear()
