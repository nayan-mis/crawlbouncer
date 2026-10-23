"""
CrawlBouncer — Rate Limiter
Sliding window rate limiting. Uses Redis when available, in-memory as fallback.
"""
from __future__ import annotations
import time
import threading
from collections import deque
from dataclasses import dataclass
from typing import Optional


# ─────────────────────────────────────────────────────────────────
# RESULT
# ─────────────────────────────────────────────────────────────────

@dataclass
class RateResult:
    allowed: bool
    count: int
    limit: int
    remaining: int
    reset_in: int          # seconds until window resets
    retry_after: Optional[int]


# ─────────────────────────────────────────────────────────────────
# IN-MEMORY SLIDING WINDOW (fallback when Redis is not available)
# ─────────────────────────────────────────────────────────────────

class InMemoryRateLimiter:
    """
    Thread-safe sliding window rate limiter.
    Stores timestamps of requests per key in a deque.
    Evicts timestamps older than the window on each check.
    """

    def __init__(self):
        self._store: dict[str, deque] = {}
        self._lock = threading.Lock()

    def check(self, key: str, limit: int = 120, window: int = 60) -> RateResult:
        now = time.time()
        cutoff = now - window

        with self._lock:
            if key not in self._store:
                self._store[key] = deque()

            bucket = self._store[key]

            # Remove timestamps outside window
            while bucket and bucket[0] < cutoff:
                bucket.popleft()

            count = len(bucket)
            allowed = count < limit

            if allowed:
                bucket.append(now)
                count += 1

        remaining = max(0, limit - count)
        reset_in = int(window - (now - bucket[0])) if bucket else window

        return RateResult(
            allowed=allowed,
            count=count,
            limit=limit,
            remaining=remaining,
            reset_in=reset_in,
            retry_after=reset_in if not allowed else None,
        )

    def reset(self, key: str):
        with self._lock:
            self._store.pop(key, None)

    def reset_all(self):
        """Clear all rate-limit state. Primarily for test isolation."""
        with self._lock:
            self._store.clear()

    def get_count(self, key: str, window: int = 60) -> int:
        now = time.time()
        cutoff = now - window
        with self._lock:
            if key not in self._store:
                return 0
            return sum(1 for t in self._store[key] if t >= cutoff)


# ─────────────────────────────────────────────────────────────────
# REDIS RATE LIMITER (production)
# ─────────────────────────────────────────────────────────────────

class RedisRateLimiter:
    """
    Redis-backed sliding window rate limiter.
    Uses sorted sets: member=timestamp, score=timestamp.
    Works correctly across multiple server processes.
    """

    def __init__(self, redis_client):
        self._redis = redis_client

    def check(self, key: str, limit: int = 120, window: int = 60) -> RateResult:
        now = time.time()
        cutoff = now - window
        rkey = f"rl:{key}"

        pipe = self._redis.pipeline()
        pipe.zremrangebyscore(rkey, 0, cutoff)
        pipe.zcard(rkey)
        pipe.zadd(rkey, {str(now): now})
        pipe.expire(rkey, window + 1)
        results = pipe.execute()

        count = results[1]
        allowed = count < limit

        if not allowed:
            # Undo the add
            self._redis.zrem(rkey, str(now))

        remaining = max(0, limit - count)
        oldest = self._redis.zrange(rkey, 0, 0, withscores=True)
        reset_in = int(window - (now - oldest[0][1])) if oldest else window

        return RateResult(
            allowed=allowed,
            count=count,
            limit=limit,
            remaining=remaining,
            reset_in=reset_in,
            retry_after=reset_in if not allowed else None,
        )


# ─────────────────────────────────────────────────────────────────
# FACTORY — returns the right limiter based on config
# ─────────────────────────────────────────────────────────────────

_limiter: Optional[InMemoryRateLimiter] = None


def get_limiter() -> InMemoryRateLimiter:
    global _limiter
    if _limiter is None:
        _limiter = InMemoryRateLimiter()
    return _limiter


def check_rate_limit(
    ip: str,
    is_bot: bool = False,
    limit: int = 120,
    bot_limit: int = 20,
    window: int = 60,
) -> RateResult:
    """
    Main entry point. Applies tighter limits to known bots.
    """
    effective_limit = bot_limit if is_bot else limit
    limiter = get_limiter()
    return limiter.check(key=ip, limit=effective_limit, window=window)
