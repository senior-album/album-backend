"""
T-041: app.services.discord_notifier 단위 테스트.

httpx 를 mock 으로 떼고, 각 응답 코드별 정책 (성공/4xx 즉시 포기/5xx·429 재시도/
네트워크 에러 재시도) 과 실패가 절대 raise 되지 않는 것을 검증.
"""

from __future__ import annotations

from typing import Iterator

import httpx
import pytest

from app.core.config import get_settings
from app.services import discord_notifier as notifier_module
from app.services.discord_notifier import _build_payload, send_ops_alert


@pytest.fixture(autouse=True)
def _shrink_backoff(monkeypatch):
    """테스트가 실제로 0.5 → 1초 backoff 를 기다리지 않게 0 으로 압축."""
    monkeypatch.setattr(notifier_module, "_BACKOFF_BASE_SECONDS", 0)


@pytest.fixture
def webhook_set(monkeypatch):
    """settings.DISCORD_OPS_WEBHOOK_URL 을 강제 설정. lru_cache 비우고."""
    monkeypatch.setenv("DISCORD_OPS_WEBHOOK_URL", "https://discord.test/webhook/abc")
    monkeypatch.setenv("JWT_SECRET", "x" * 32)
    monkeypatch.setenv("JWT_REFRESH_SECRET", "x" * 32)
    monkeypatch.setenv("RESIDENT_PII_KEK", "A" * 44)
    monkeypatch.setenv("RESIDENT_NAME_HMAC_KEY", "B" * 44)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


class _FakeResponse:
    def __init__(self, status_code: int, headers: dict | None = None):
        self.status_code = status_code
        self.headers = headers or {}


class _FakeClient:
    """httpx.AsyncClient 를 흉내내는 컨텍스트 매니저. POST 시 미리 큐잉된 응답을
    순서대로 돌려준다 (또는 RequestError 를 raise)."""

    def __init__(self, outcomes: Iterator):
        self._outcomes = iter(outcomes)
        self.calls: list[tuple[str, dict]] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def post(self, url, json):
        self.calls.append((url, json))
        nxt = next(self._outcomes)
        if isinstance(nxt, Exception):
            raise nxt
        return nxt


def _patch_httpx_client(monkeypatch, outcomes):
    fake = _FakeClient(outcomes)

    def _factory(*_args, **_kwargs):
        return fake

    monkeypatch.setattr(notifier_module.httpx, "AsyncClient", _factory)
    return fake


# ---------------------------------------------------------------------------
# 미설정 — 알림 비활성
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_send_returns_false_when_url_unset(monkeypatch):
    """URL 비어있으면 즉시 False 반환 (아무 HTTP 호출도 안 일어남)."""
    monkeypatch.setenv("DISCORD_OPS_WEBHOOK_URL", "")
    monkeypatch.setenv("JWT_SECRET", "x" * 32)
    monkeypatch.setenv("JWT_REFRESH_SECRET", "x" * 32)
    monkeypatch.setenv("RESIDENT_PII_KEK", "A" * 44)
    monkeypatch.setenv("RESIDENT_NAME_HMAC_KEY", "B" * 44)
    get_settings.cache_clear()

    # 호출돼선 안 되는 fake client — 호출되면 StopIteration 으로 터진다.
    fake = _patch_httpx_client(monkeypatch, iter([]))

    assert await send_ops_alert("t", "m") is False
    assert fake.calls == []
    get_settings.cache_clear()


# ---------------------------------------------------------------------------
# 성공 / 4xx / 5xx / 429 / 네트워크
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_send_ok_on_204(webhook_set, monkeypatch):
    fake = _patch_httpx_client(monkeypatch, [_FakeResponse(204)])
    assert await send_ops_alert("t", "m") is True
    assert len(fake.calls) == 1


@pytest.mark.asyncio
async def test_send_gives_up_on_404_no_retry(webhook_set, monkeypatch):
    """4xx (non-429) 는 config 문제 — retry 안 함, False 반환."""
    fake = _patch_httpx_client(monkeypatch, [_FakeResponse(404)])
    assert await send_ops_alert("t", "m") is False
    assert len(fake.calls) == 1  # 한 번만 시도


@pytest.mark.asyncio
async def test_send_retries_on_5xx_then_succeeds(webhook_set, monkeypatch):
    fake = _patch_httpx_client(
        monkeypatch,
        [_FakeResponse(500), _FakeResponse(502), _FakeResponse(204)],
    )
    assert await send_ops_alert("t", "m") is True
    assert len(fake.calls) == 3


@pytest.mark.asyncio
async def test_send_returns_false_after_max_5xx(webhook_set, monkeypatch):
    """3 번 모두 5xx 면 False — raise 하지 않는다."""
    fake = _patch_httpx_client(
        monkeypatch,
        [_FakeResponse(503), _FakeResponse(503), _FakeResponse(503)],
    )
    assert await send_ops_alert("t", "m") is False
    assert len(fake.calls) == 3


@pytest.mark.asyncio
async def test_send_retries_on_429_with_retry_after(webhook_set, monkeypatch):
    """429 이면 Retry-After 헤더만큼 sleep 한 뒤 retry."""
    fake = _patch_httpx_client(
        monkeypatch,
        [_FakeResponse(429, headers={"Retry-After": "0"}), _FakeResponse(204)],
    )
    assert await send_ops_alert("t", "m") is True
    assert len(fake.calls) == 2


@pytest.mark.asyncio
async def test_send_retries_on_network_error_then_succeeds(webhook_set, monkeypatch):
    fake = _patch_httpx_client(
        monkeypatch,
        [httpx.ConnectError("dns nope"), _FakeResponse(204)],
    )
    assert await send_ops_alert("t", "m") is True
    assert len(fake.calls) == 2


@pytest.mark.asyncio
async def test_send_swallows_persistent_network_error(webhook_set, monkeypatch):
    fake = _patch_httpx_client(
        monkeypatch,
        [
            httpx.ConnectTimeout("t1"),
            httpx.ConnectTimeout("t2"),
            httpx.ConnectTimeout("t3"),
        ],
    )
    # 절대 raise 하지 않는다.
    assert await send_ops_alert("t", "m") is False
    assert len(fake.calls) == 3


# ---------------------------------------------------------------------------
# Payload 형태 / 길이 가드 / 색상
# ---------------------------------------------------------------------------


def test_build_payload_truncates_title_and_description():
    p = _build_payload(
        title="x" * 500,
        message="y" * 5000,
        level="error",
        fields=None,
    )
    embed = p["embeds"][0]
    assert len(embed["title"]) == 256
    assert len(embed["description"]) == 4096
    assert embed["color"] == 0xE74C3C


def test_build_payload_warning_color():
    p = _build_payload(title="t", message="m", level="warning", fields=None)
    assert p["embeds"][0]["color"] == 0xF1C40F


def test_build_payload_caps_fields_at_25_and_lengths():
    long_val = "z" * 2000
    fields = {f"k{i}": long_val for i in range(40)}
    p = _build_payload(title="t", message="m", level="info", fields=fields)
    embed_fields = p["embeds"][0]["fields"]
    assert len(embed_fields) == 25
    assert all(len(f["value"]) <= 1024 for f in embed_fields)


def test_build_payload_omits_fields_when_none():
    p = _build_payload(title="t", message="m", level="info", fields=None)
    assert "fields" not in p["embeds"][0]
