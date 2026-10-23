"""
Tests for app/middleware/rate_limiter.py
Verifies sliding window logic, per-IP isolation,
and correct handling of bots vs humans.
"""
import time
import threading
import pytest
from app.middleware.rate_limiter import InMemoryRateLimiter, check_rate_limit, get_limiter


# ─────────────────────────────────────────────────────────────────
# BASIC ALLOW / BLOCK
# ─────────────────────────────────────────────────────────────────

class TestBasicRateLimiting:

    def setup_method(self):
        """Fresh limiter for each test."""
        self.limiter = InMemoryRateLimiter()

    def test_first_request_allowed(self):
        r = self.limiter.check("1.2.3.4", limit=10, window=60)
        assert r.allowed
        assert r.count == 1

    def test_requests_within_limit_allowed(self):
        for i in range(5):
            r = self.limiter.check("1.2.3.4", limit=10, window=60)
            assert r.allowed

    def test_request_at_limit_blocked(self):
        for _ in range(10):
            self.limiter.check("1.2.3.4", limit=10, window=60)
        r = self.limiter.check("1.2.3.4", limit=10, window=60)
        assert not r.allowed

    def test_blocked_request_returns_correct_count(self):
        for _ in range(5):
            self.limiter.check("1.2.3.4", limit=5, window=60)
        r = self.limiter.check("1.2.3.4", limit=5, window=60)
        assert not r.allowed
        assert r.count == 5
        assert r.remaining == 0

    def test_retry_after_set_when_blocked(self):
        for _ in range(5):
            self.limiter.check("1.2.3.4", limit=5, window=60)
        r = self.limiter.check("1.2.3.4", limit=5, window=60)
        assert r.retry_after is not None
        assert r.retry_after > 0

    def test_retry_after_none_when_allowed(self):
        r = self.limiter.check("1.2.3.4", limit=10, window=60)
        assert r.retry_after is None


# ─────────────────────────────────────────────────────────────────
# PER-IP ISOLATION
# ─────────────────────────────────────────────────────────────────

class TestIPIsolation:

    def setup_method(self):
        self.limiter = InMemoryRateLimiter()

    def test_different_ips_have_independent_limits(self):
        for _ in range(5):
            self.limiter.check("1.1.1.1", limit=5, window=60)

        # 1.1.1.1 is at limit — should be blocked
        r1 = self.limiter.check("1.1.1.1", limit=5, window=60)
        assert not r1.allowed

        # 2.2.2.2 has made no requests — should be allowed
        r2 = self.limiter.check("2.2.2.2", limit=5, window=60)
        assert r2.allowed

    def test_100_ips_all_independent(self):
        for i in range(100):
            ip = f"10.0.0.{i}"
            r  = self.limiter.check(ip, limit=3, window=60)
            assert r.allowed, f"First request from {ip} should be allowed"


# ─────────────────────────────────────────────────────────────────
# SLIDING WINDOW — EXPIRY
# ─────────────────────────────────────────────────────────────────

class TestSlidingWindow:

    def test_old_requests_expire(self):
        limiter = InMemoryRateLimiter()
        # Fill up the limit with a tiny 1-second window
        for _ in range(3):
            limiter.check("1.2.3.4", limit=3, window=1)

        # At limit — blocked
        r = limiter.check("1.2.3.4", limit=3, window=1)
        assert not r.allowed

        # Wait for window to expire
        time.sleep(1.1)

        # Should be allowed again
        r = limiter.check("1.2.3.4", limit=3, window=1)
        assert r.allowed

    def test_window_is_sliding_not_fixed(self):
        """
        In a sliding window, only requests within the last N seconds count.
        This verifies that old requests fall off rather than resetting the whole window.
        """
        limiter = InMemoryRateLimiter()
        # Make 2 requests, wait past the window, make 2 more — should not be blocked at limit=3
        limiter.check("1.2.3.4", limit=3, window=1)
        limiter.check("1.2.3.4", limit=3, window=1)
        time.sleep(1.2)
        # First 2 requests are now outside the 1s window and should have aged out
        r1 = limiter.check("1.2.3.4", limit=3, window=1)
        r2 = limiter.check("1.2.3.4", limit=3, window=1)
        assert r1.allowed
        assert r2.allowed


# ─────────────────────────────────────────────────────────────────
# RESET
# ─────────────────────────────────────────────────────────────────

def test_reset_clears_counter():
    limiter = InMemoryRateLimiter()
    for _ in range(5):
        limiter.check("1.2.3.4", limit=5, window=60)
    r = limiter.check("1.2.3.4", limit=5, window=60)
    assert not r.allowed

    limiter.reset("1.2.3.4")
    r = limiter.check("1.2.3.4", limit=5, window=60)
    assert r.allowed


# ─────────────────────────────────────────────────────────────────
# BOT VS HUMAN LIMITS
# ─────────────────────────────────────────────────────────────────

class TestBotVsHumanLimits:

    def setup_method(self):
        get_limiter().reset("10.0.0.1")

    def test_human_gets_higher_limit(self):
        r = check_rate_limit("10.0.0.1", is_bot=False, limit=120, bot_limit=20)
        assert r.limit == 120

    def test_bot_gets_lower_limit(self):
        r = check_rate_limit("10.0.0.1", is_bot=True, limit=120, bot_limit=20)
        assert r.limit == 20


# ─────────────────────────────────────────────────────────────────
# THREAD SAFETY
# ─────────────────────────────────────────────────────────────────

class TestThreadSafety:

    def test_concurrent_requests_do_not_exceed_limit(self):
        """
        100 threads all hammer the same IP simultaneously.
        Exactly `limit` should be allowed and the rest blocked.
        """
        LIMIT   = 10
        THREADS = 50
        limiter = InMemoryRateLimiter()
        results = []
        lock    = threading.Lock()

        def make_request():
            r = limiter.check("192.168.1.1", limit=LIMIT, window=60)
            with lock:
                results.append(r.allowed)

        threads = [threading.Thread(target=make_request) for _ in range(THREADS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        allowed_count = sum(1 for r in results if r)
        assert allowed_count == LIMIT, (
            f"Expected exactly {LIMIT} allowed requests, got {allowed_count}"
        )


# ─────────────────────────────────────────────────────────────────
# RESULT FIELDS
# ─────────────────────────────────────────────────────────────────

def test_result_remaining_decrements():
    limiter = InMemoryRateLimiter()
    for i in range(1, 6):
        r = limiter.check("9.9.9.9", limit=5, window=60)
        assert r.remaining == 5 - i

def test_result_limit_matches_requested():
    limiter = InMemoryRateLimiter()
    r = limiter.check("8.8.8.8", limit=42, window=60)
    assert r.limit == 42
