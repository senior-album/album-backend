"""
Redis 연결 관리
- 로그인 시도 제한 (Rate Limiting)
- 세션 캐시 (향후)
- 알림 큐 (향후)
"""

import logging
from typing import Optional

import redis.asyncio as aioredis

from app.core.config import get_settings

logger = logging.getLogger(__name__)

_redis: Optional[aioredis.Redis] = None


async def get_redis() -> Optional[aioredis.Redis]:
    """Redis 클라이언트 반환. 연결 실패 시 None."""
    global _redis
    if _redis is not None:
        try:
            await _redis.ping()
            return _redis
        except Exception:
            _redis = None

    settings = get_settings()
    try:
        _redis = aioredis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True,
            socket_connect_timeout=2,
        )
        await _redis.ping()
        logger.info(f"Redis connected: {settings.REDIS_URL}")
        return _redis
    except Exception as e:
        logger.warning(f"Redis connection failed: {e} — falling back to in-memory")
        _redis = None
        return None


async def close_redis():
    """Redis 연결 종료"""
    global _redis
    if _redis:
        await _redis.close()
        _redis = None
        logger.info("Redis connection closed")


# ==================== Rate Limiting ====================


async def check_rate_limit(key: str, max_attempts: int, window_seconds: int) -> tuple[bool, int]:
    """
    Redis 기반 Rate Limiting.
    Returns: (is_blocked, remaining_seconds)
    """
    r = await get_redis()
    if r is None:
        # Redis 없으면 통과 (인메모리 fallback은 auth.py에서)
        return False, 0

    try:
        current = await r.get(f"ratelimit:{key}")
        if current and int(current) >= max_attempts:
            ttl = await r.ttl(f"ratelimit:{key}")
            return True, max(ttl, 0)

        pipe = r.pipeline()
        pipe.incr(f"ratelimit:{key}")
        pipe.expire(f"ratelimit:{key}", window_seconds)
        await pipe.execute()
        return False, 0
    except Exception as e:
        logger.warning(f"Redis rate limit error: {e}")
        return False, 0


async def clear_rate_limit(key: str):
    """성공적인 로그인 후 제한 초기화"""
    r = await get_redis()
    if r:
        try:
            await r.delete(f"ratelimit:{key}")
        except Exception:
            pass
