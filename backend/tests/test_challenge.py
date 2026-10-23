"""
CrawlBouncer — Challenge Middleware Tests
Covers signed challenge cookies, server-side proof-of-work verification,
hCaptcha verification, challenge page content, and the FastAPI routes.
"""
import hashlib
import time
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.middleware import challenge


# ─────────────────────────────────────────────────────────────────
# COOKIE — sign / verify
# ─────────────────────────────────────────────────────────────────

class TestChallengeCookie:

    def test_sign_and_verify_round_trip(self):
        cookie = challenge._sign_cookie("1.2.3.4")
        assert challenge.verify_cookie(cookie, "1.2.3.4") is True

    def test_rejects_empty_cookie(self):
        assert challenge.verify_cookie("", "1.2.3.4") is False

    def test_rejects_malformed_cookie(self):
        assert challenge.verify_cookie("not-a-valid-cookie", "1.2.3.4") is False

    def test_rejects_mismatched_ip(self):
        cookie = challenge._sign_cookie("1.2.3.4")
        assert challenge.verify_cookie(cookie, "9.9.9.9") is False

    def test_rejects_tampered_signature(self):
        cookie = challenge._sign_cookie("1.2.3.4")
        ip, issued_at, sig = cookie.split(":")
        tampered = f"{ip}:{issued_at}:{sig[::-1]}"
        assert challenge.verify_cookie(tampered, "1.2.3.4") is False

    def test_rejects_expired_cookie(self):
        old_issued = int(time.time()) - challenge.COOKIE_VALID_SECS - 60
        payload = f"1.2.3.4:{old_issued}"
        import hmac
        from app.config import cfg
        sig = hmac.new(cfg.JWT_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()[:16]
        expired_cookie = f"{payload}:{sig}"
        assert challenge.verify_cookie(expired_cookie, "1.2.3.4") is False


# ─────────────────────────────────────────────────────────────────
# PROOF-OF-WORK VERIFICATION
# ─────────────────────────────────────────────────────────────────

class TestProofOfWork:

    def _solve(self, nonce: str, difficulty: int) -> str:
        """Brute-force a valid PoW solution for test purposes."""
        candidate = 0
        prefix = "0" * difficulty
        while True:
            sol = str(candidate)
            if hashlib.sha256(f"{nonce}{sol}".encode()).hexdigest().startswith(prefix):
                return sol
            candidate += 1

    def test_valid_solution_passes(self):
        nonce = "test-nonce"
        solution = self._solve(nonce, difficulty=2)  # low difficulty — fast test
        assert challenge.verify_pow(nonce, solution, difficulty=2) is True

    def test_invalid_solution_fails(self):
        assert challenge.verify_pow("test-nonce", "not-a-real-solution", difficulty=4) is False

    def test_solution_for_different_nonce_fails(self):
        solution = self._solve("nonce-a", difficulty=2)
        assert challenge.verify_pow("nonce-b", solution, difficulty=2) is False


# ─────────────────────────────────────────────────────────────────
# HCAPTCHA VERIFICATION
# ─────────────────────────────────────────────────────────────────

class TestHcaptchaVerification:

    def test_always_passes_in_development(self, monkeypatch):
        from app.config import cfg
        monkeypatch.setattr(cfg, "ENV", "development")
        assert challenge.verify_hcaptcha("any-token") is True

    def test_rejects_empty_token_outside_development(self):
        assert challenge.verify_hcaptcha("") is False

    def test_rejects_when_secret_not_configured(self, monkeypatch):
        monkeypatch.setattr(challenge, "HCAPTCHA_SECRET", "")
        assert challenge.verify_hcaptcha("some-token") is False

    def test_calls_hcaptcha_api_when_configured(self, monkeypatch):
        monkeypatch.setattr(challenge, "HCAPTCHA_SECRET", "test-secret")

        class FakeResponse:
            def read(self):
                return b'{"success": true}'
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False

        with patch.object(challenge.urllib.request, "urlopen", return_value=FakeResponse()):
            assert challenge.verify_hcaptcha("real-token") is True

    def test_api_failure_returns_false(self, monkeypatch):
        monkeypatch.setattr(challenge, "HCAPTCHA_SECRET", "test-secret")
        with patch.object(challenge.urllib.request, "urlopen", side_effect=Exception("network error")):
            assert challenge.verify_hcaptcha("real-token") is False


# ─────────────────────────────────────────────────────────────────
# CHALLENGE PAGE CONTENT
# ─────────────────────────────────────────────────────────────────

class TestChallengePages:

    def test_pow_page_embeds_nonce_and_difficulty(self):
        page = challenge.pow_challenge_page("abc123", "/article/1")
        assert "abc123" in page
        assert str(challenge.POW_DIFFICULTY) in page
        assert "/article/1" in page

    def test_hcaptcha_page_embeds_sitekey(self):
        page = challenge.hcaptcha_challenge_page("/article/1")
        assert challenge.HCAPTCHA_SITEKEY in page
        assert "/article/1" in page

    def test_blocked_page_shows_access_denied(self):
        page = challenge.blocked_page()
        assert "Access denied" in page

    def test_blocked_page_never_reveals_which_rule_fired(self):
        page = challenge.blocked_page(reason="CMDi-001 matched")
        assert "CMDi-001" not in page


# ─────────────────────────────────────────────────────────────────
# FASTAPI ROUTES
# ─────────────────────────────────────────────────────────────────

@pytest.fixture
def challenge_client():
    app = FastAPI()
    challenge.register_challenge_routes(app)
    return TestClient(app)


class TestChallengeRoutes:

    def test_serve_pow_challenge_returns_html_with_nonce(self, challenge_client):
        resp = challenge_client.get("/challenge/pow?return=/home")
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]

    def test_verify_pow_with_correct_solution_sets_cookie(self, challenge_client):
        nonce = "route-test-nonce"
        candidate = 0
        prefix = "0" * challenge.POW_DIFFICULTY
        while not hashlib.sha256(f"{nonce}{candidate}".encode()).hexdigest().startswith(prefix):
            candidate += 1

        resp = challenge_client.post(
            "/challenge/verify",
            data={"nonce": nonce, "solution": str(candidate), "return": "/home"},
            follow_redirects=False,
        )
        assert resp.status_code == 302
        assert challenge.CHALLENGE_COOKIE in resp.cookies

    def test_verify_pow_with_wrong_solution_rejected(self, challenge_client):
        resp = challenge_client.post(
            "/challenge/verify",
            data={"nonce": "n", "solution": "wrong", "return": "/home"},
        )
        assert resp.status_code == 400

    def test_serve_captcha_returns_html(self, challenge_client):
        resp = challenge_client.get("/challenge/captcha?return=/home")
        assert resp.status_code == 200

    def test_verify_captcha_rejects_empty_token(self, challenge_client):
        resp = challenge_client.post("/challenge/captcha/verify", data={"return": "/home"})
        assert resp.status_code == 400


class TestChallengeOutcomeRecording:
    """Every solved/failed challenge should land in challenge_events —
    the anomaly detector's challenge_fail_rate feature depends on it."""

    def _count_events(self, ip: str, challenge_type: str, passed: bool) -> int:
        from app.database import get_db
        with get_db() as db:
            row = db.execute(
                "SELECT COUNT(*) FROM challenge_events WHERE ip=? AND challenge_type=? AND passed=?",
                (ip, challenge_type, int(passed))
            ).fetchone()
        return row[0]

    def test_pow_pass_is_recorded(self, challenge_client, monkeypatch):
        # get_client_ip only trusts X-Real-IP from a configured trusted
        # proxy (see client_ip.py / the SSRF-adjacent IP-spoofing fix
        # in challenge.py) — monkeypatching it here tests that a
        # correctly-resolved client IP gets recorded, without asserting
        # that an arbitrary caller-supplied header should be trusted,
        # which was the actual vulnerability this test used to encode.
        ip = "203.0.113.10"
        monkeypatch.setattr("app.middleware.challenge.get_client_ip", lambda request: ip)
        nonce = "record-pass-nonce"
        candidate = 0
        prefix = "0" * challenge.POW_DIFFICULTY
        while not hashlib.sha256(f"{nonce}{candidate}".encode()).hexdigest().startswith(prefix):
            candidate += 1

        before = self._count_events(ip, "pow", True)
        challenge_client.post("/challenge/verify",
            data={"nonce": nonce, "solution": str(candidate), "return": "/home"},
            follow_redirects=False)
        after = self._count_events(ip, "pow", True)
        assert after == before + 1

    def test_pow_failure_is_recorded(self, challenge_client, monkeypatch):
        ip = "203.0.113.11"
        monkeypatch.setattr("app.middleware.challenge.get_client_ip", lambda request: ip)
        before = self._count_events(ip, "pow", False)
        challenge_client.post("/challenge/verify",
            data={"nonce": "n", "solution": "wrong", "return": "/home"})
        after = self._count_events(ip, "pow", False)
        assert after == before + 1

    def test_captcha_failure_is_recorded(self, challenge_client, monkeypatch):
        ip = "203.0.113.12"
        monkeypatch.setattr("app.middleware.challenge.get_client_ip", lambda request: ip)
        before = self._count_events(ip, "captcha", False)
        challenge_client.post("/challenge/captcha/verify",
            data={"return": "/home"})
        after = self._count_events(ip, "captcha", False)
        assert after == before + 1

    def test_untrusted_caller_supplied_x_real_ip_is_ignored(self, challenge_client):
        """Regression test for the actual vulnerability: an untrusted
        direct caller sending X-Real-IP used to get that header taken
        at face value, letting anyone attribute a challenge outcome to
        an arbitrary IP of their choosing — poisoning challenge_events
        for a third party, or evading the anomaly detector's
        challenge_fail_rate feature entirely by spoofing a fresh IP on
        every failed attempt. get_client_ip only honors this header
        from a configured trusted proxy, which the test client isn't,
        so the header must now be silently ignored rather than trusted."""
        spoofed_victim_ip = "8.8.8.8"
        before = self._count_events(spoofed_victim_ip, "captcha", False)
        challenge_client.post("/challenge/captcha/verify",
            data={"return": "/home"}, headers={"X-Real-IP": spoofed_victim_ip})
        after = self._count_events(spoofed_victim_ip, "captcha", False)
        assert after == before, (
            "an untrusted caller's X-Real-IP header was trusted — "
            "challenge outcomes can be attributed to an arbitrary IP"
        )


class TestChallengeCookieSecureFlag:

    def test_pow_pass_sets_httponly_cookie(self, challenge_client):
        ip = "203.0.113.20"
        nonce = "secure-flag-nonce"
        candidate = 0
        prefix = "0" * challenge.POW_DIFFICULTY
        while not hashlib.sha256(f"{nonce}{candidate}".encode()).hexdigest().startswith(prefix):
            candidate += 1

        resp = challenge_client.post("/challenge/verify",
            data={"nonce": nonce, "solution": str(candidate), "return": "/home"},
            headers={"X-Real-IP": ip}, follow_redirects=False)
        set_cookie = resp.headers.get("set-cookie", "")
        assert "HttpOnly" in set_cookie
        # Secure is production-only — real HTTPS deployments need it, but
        # TestClient (and local http:// development) simulates plain
        # HTTP, where a Secure-flagged cookie would be silently dropped
        # by any spec-compliant client, breaking the exact flow this test
        # is checking. See docs/AUDIT.md 3.3 and the cfg.is_production
        # check in challenge.py / auth.py's set_session_cookies.
        assert "Secure" not in set_cookie

    def test_pow_pass_sets_secure_cookie_in_production(self, challenge_client, monkeypatch):
        import app.middleware.challenge as challenge_module
        monkeypatch.setattr(challenge_module.cfg, "ENV", "production")

        ip = "203.0.113.21"
        nonce = "secure-flag-nonce-prod"
        candidate = 0
        prefix = "0" * challenge.POW_DIFFICULTY
        while not hashlib.sha256(f"{nonce}{candidate}".encode()).hexdigest().startswith(prefix):
            candidate += 1

        resp = challenge_client.post("/challenge/verify",
            data={"nonce": nonce, "solution": str(candidate), "return": "/home"},
            headers={"X-Real-IP": ip}, follow_redirects=False)
        set_cookie = resp.headers.get("set-cookie", "")
        assert "Secure" in set_cookie
        assert "HttpOnly" in set_cookie
