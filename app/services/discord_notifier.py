"""
T-041: 운영 장애 알림 — Discord 웹훅 송출.

Uptime Kuma 외형 모니터(T-040) 와 별도로 애플리케이션 내부 이벤트(예: 사진
처리 작업 retry 소진) 를 운영 채널로 푸시한다. 알림 실패는 절대 비즈니스
로직을 막지 않는다 — `send_ops_alert` 는 예외를 던지지 않고 성공 여부만 반환.

보안 주의:
- `DISCORD_OPS_WEBHOOK_URL` 자체가 시크릿(URL path 에 토큰 포함). 로그/에러
  메시지에 URL 이나 response body 를 남기지 말 것.
- payload 에 평문 PII 가 들어가지 않도록 호출자 측에서 식별자만 넘긴다.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

import httpx

from app.core.config import get_settings

logger = logging.getLogger(__name__)

_TIMEOUT_SECONDS = 5.0
_MAX_ATTEMPTS = 3
_BACKOFF_BASE_SECONDS = 0.5

_LEVEL_COLORS = {
    "error": 0xE74C3C,
    "warning": 0xF1C40F,
    "info": 0x3498DB,
}


async def send_ops_alert(
    title: str,
    message: str,
    *,
    level: str = "error",
    fields: Optional[dict] = None,
) -> bool:
    """
    Discord 운영 채널로 알림을 보낸다.

    Args:
        title: 알림 제목 (Discord embed title, ≤256자로 잘림)
        message: 본문 (description, ≤4096자로 잘림)
        level: error | warning | info — embed 색상 결정
        fields: 추가 키-값 쌍 (최대 25개). 각 key/value 는 str 변환 후 잘림.

    Returns:
        성공(204) 시 True, 미설정/실패 시 False. 절대 raise 하지 않는다.
    """
    settings = get_settings()
    url = settings.DISCORD_OPS_WEBHOOK_URL
    if not url:
        logger.debug("Discord webhook not configured, skipping alert: %s", title)
        return False

    payload = _build_payload(title=title, message=message, level=level, fields=fields)

    delay = _BACKOFF_BASE_SECONDS
    for attempt in range(1, _MAX_ATTEMPTS + 1):
        outcome = await _post_once(url, payload, attempt=attempt)
        if outcome is True:
            return True
        if outcome == "give_up":
            return False
        # outcome == "retry"
        if attempt < _MAX_ATTEMPTS:
            await asyncio.sleep(delay)
            delay *= 2

    logger.error(
        "Discord ops alert failed after %s attempts: %s",
        _MAX_ATTEMPTS,
        title,
    )
    return False


def _build_payload(
    *,
    title: str,
    message: str,
    level: str,
    fields: Optional[dict],
) -> dict:
    embed = {
        "title": title[:256],
        "description": message[:4096],
        "color": _LEVEL_COLORS.get(level, 0x95A5A6),
    }
    if fields:
        embed["fields"] = [
            {"name": str(k)[:256], "value": str(v)[:1024], "inline": True}
            for k, v in list(fields.items())[:25]
        ]
    return {
        "username": "Senior Album Ops",
        "embeds": [embed],
    }


async def _post_once(url: str, payload: dict, *, attempt: int):
    """
    한 번 POST 한다. 반환:
      - True       → 성공 (204)
      - "give_up"  → 4xx (URL/권한 문제, retry 무의미)
      - "retry"    → 네트워크/5xx/429, 재시도 가능
    """
    try:
        async with httpx.AsyncClient(timeout=_TIMEOUT_SECONDS) as client:
            resp = await client.post(url, json=payload)
    except httpx.RequestError as e:
        logger.warning(
            "Discord webhook attempt %s/%s network error: %s",
            attempt,
            _MAX_ATTEMPTS,
            type(e).__name__,
        )
        return "retry"

    status = resp.status_code

    if status == 204:
        return True

    if status == 429:
        retry_after = _parse_retry_after(resp.headers.get("Retry-After"))
        if retry_after is not None:
            await asyncio.sleep(min(retry_after, 5.0))
        return "retry"

    if 400 <= status < 500:
        # 401/403/404 — 웹훅 URL 죽었거나 권한 문제. response body 는 토큰 일부를
        # 포함할 수 있어 로그에 남기지 않는다.
        logger.error(
            "Discord webhook rejected payload (status=%s) — config issue, no retry",
            status,
        )
        return "give_up"

    # 5xx
    logger.warning(
        "Discord webhook %s on attempt %s/%s",
        status,
        attempt,
        _MAX_ATTEMPTS,
    )
    return "retry"


def _parse_retry_after(value: Optional[str]) -> Optional[float]:
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except (TypeError, ValueError):
        return None
