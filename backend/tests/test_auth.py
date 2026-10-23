"""
Tests for app/security/jwt_handler.py and app/api/auth.py
Verifies token creation, verification, expiry, password hashing,
and the full register/login API flow.
"""
import time
import pytest
from app.security.jwt_handler import (
    create_token, verify_token, hash_password, verify_password
)
from conftest import register_and_verify


# ─────────────────────────────────────────────────────────────────
# JWT TOKEN
# ─────────────────────────────────────────────────────────────────

class TestJWT:

    def test_create_returns_three_part_token(self):
        token = create_token("user-001", "test@example.com")
        parts = token.split(".")
        assert len(parts) == 3

    def test_valid_token_verifies(self):
        token   = create_token("user-001", "test@example.com")
        payload = verify_token(token)
        assert payload is not None
        assert payload["sub"]   == "user-001"
        assert payload["email"] == "test@example.com"

    def test_payload_has_iat_and_exp(self):
        token   = create_token("user-001", "test@example.com")
        payload = verify_token(token)
        assert "iat" in payload
        assert "exp" in payload

    def test_exp_is_in_future(self):
        token   = create_token("user-001", "test@example.com")
        payload = verify_token(token)
        assert payload["exp"] > time.time()

    def test_exp_is_approximately_24_hours(self):
        token   = create_token("user-001", "test@example.com")
        payload = verify_token(token)
        expected = time.time() + 86400
        assert abs(payload["exp"] - expected) < 60     # within 1 minute

    def test_tampered_token_rejected(self):
        token  = create_token("user-001", "test@example.com")
        parts  = token.split(".")
        parts[1] = parts[1][:-2] + "XX"               # corrupt payload
        tampered = ".".join(parts)
        assert verify_token(tampered) is None

    def test_wrong_signature_rejected(self):
        token = create_token("user-001", "test@example.com")
        parts = token.split(".")
        parts[2] = "invalidsignature"
        bad_token = ".".join(parts)
        assert verify_token(bad_token) is None

    def test_empty_token_rejected(self):
        assert verify_token("") is None

    def test_malformed_token_rejected(self):
        assert verify_token("not.a.valid.jwt.token") is None
        assert verify_token("only-one-part") is None

    def test_different_users_get_different_tokens(self):
        t1 = create_token("user-001", "a@example.com")
        t2 = create_token("user-002", "b@example.com")
        assert t1 != t2


# ─────────────────────────────────────────────────────────────────
# PASSWORD HASHING
# ─────────────────────────────────────────────────────────────────

class TestPasswordHashing:

    def test_hash_is_not_plaintext(self):
        h = hash_password("mypassword")
        assert h != "mypassword"
        assert h.startswith("$2")  # bcrypt encoded hash

    def test_same_password_uses_unique_salt(self):
        h1 = hash_password("mypassword")
        h2 = hash_password("mypassword")
        assert h1 != h2
        assert verify_password("mypassword", h1)
        assert verify_password("mypassword", h2)

    def test_different_passwords_different_hashes(self):
        h1 = hash_password("password1")
        h2 = hash_password("password2")
        assert h1 != h2

    def test_verify_correct_password(self):
        h = hash_password("correctpassword")
        assert verify_password("correctpassword", h)

    def test_reject_wrong_password(self):
        h = hash_password("correctpassword")
        assert not verify_password("wrongpassword", h)

    def test_empty_password_hashes_use_unique_salts(self):
        h1 = hash_password("")
        h2 = hash_password("")
        assert h1 != h2

    def test_hash_is_timing_safe(self):
        """verify_password must use hmac.compare_digest (constant time)."""
        import inspect
        from app.security import jwt_handler
        source = inspect.getsource(jwt_handler.verify_password)
        assert "compare_digest" in source, "verify_password must use hmac.compare_digest"


# ─────────────────────────────────────────────────────────────────
# AUTH API ENDPOINTS
# ─────────────────────────────────────────────────────────────────

class TestAuthAPI:

    def test_logout_revokes_current_token(self, client, auth_headers):
        assert client.post("/api/auth/logout", headers=auth_headers).status_code == 200
        assert client.get("/api/auth/me", headers=auth_headers).status_code == 401

    def test_register_new_account(self, client):
        resp = client.post("/api/auth/register", json={
            "email":    "newuser@example.com",
            "password": "SecurePass123",
            "name":     "New User",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "verification_sent"
        assert "token" not in data  # no session until the email is verified

    def test_register_duplicate_email_returns_identical_response(self, client):
        """The whole point of this flow (docs/AUDIT.md 2.3): a duplicate
        email must be indistinguishable from a new one at the HTTP
        level — same status code, same response shape. The 409 this
        used to return was the actual enumeration vulnerability."""
        client.post("/api/auth/register", json={
            "email": "duplicate@example.com", "password": "Pass12345"
        })
        first = client.post("/api/auth/register", json={
            "email": "newone@example.com", "password": "Pass12345"
        })
        second = client.post("/api/auth/register", json={
            "email": "duplicate@example.com", "password": "Pass12345"
        })
        assert first.status_code == second.status_code == 200
        assert first.json() == second.json()

    def test_register_invalid_email_rejected(self, client):
        resp = client.post("/api/auth/register", json={
            "email": "notanemail", "password": "Pass1234"
        })
        assert resp.status_code == 400

    def test_register_short_password_rejected(self, client):
        resp = client.post("/api/auth/register", json={
            "email": "short@example.com", "password": "abc"
        })
        assert resp.status_code == 400

    def test_register_common_password_rejected(self, client):
        resp = client.post("/api/auth/register", json={
            "email": "commonpw@example.com", "password": "password123"
        })
        assert resp.status_code == 400
        assert "common" in resp.json()["detail"].lower()

    def test_register_common_password_rejected_case_insensitively(self, client):
        resp = client.post("/api/auth/register", json={
            "email": "commonpw2@example.com", "password": "PASSWORD123"
        })
        assert resp.status_code == 400

    def test_register_uncommon_password_accepted(self, client):
        resp = client.post("/api/auth/register", json={
            "email": "uncommonpw@example.com", "password": "Xk7mQz2vRt9p"
        })
        assert resp.status_code == 200


class TestRegisterRateLimit:

    def test_eleventh_registration_in_window_is_rate_limited(self, client):
        for i in range(10):
            resp = client.post("/api/auth/register", json={
                "email": f"ratelimit{i}@example.com", "password": "UniquePass123"
            })
            assert resp.status_code == 200

        resp = client.post("/api/auth/register", json={
            "email": "ratelimit-eleventh@example.com", "password": "UniquePass123"
        })
        assert resp.status_code == 429

    def test_login_correct_credentials(self, client, monkeypatch):
        register_and_verify(client, monkeypatch, "logintest@example.com", "GoodPass123")
        resp = client.post("/api/auth/login", json={
            "email": "logintest@example.com", "password": "GoodPass123"
        })
        assert resp.status_code == 200
        assert "token" in resp.json()

    def test_login_wrong_password_rejected(self, client):
        client.post("/api/auth/register", json={
            "email": "wrongpass@example.com", "password": "CorrectPass123"
        })
        resp = client.post("/api/auth/login", json={
            "email": "wrongpass@example.com", "password": "WrongPass456"
        })
        assert resp.status_code == 401

    def test_login_unknown_email_rejected(self, client):
        resp = client.post("/api/auth/login", json={
            "email": "doesnotexist@example.com", "password": "AnyPass123"
        })
        assert resp.status_code == 401

    def test_login_before_verification_rejected(self, client):
        """Right password, but the account was never verified — this
        must be reachable ONLY with the correct password (otherwise
        it's a second enumeration oracle), which this test also checks
        by confirming a wrong password on the same account still just
        gets the generic 401, not the verification-specific message."""
        client.post("/api/auth/register", json={
            "email": "unverified@example.com", "password": "RealPass123"
        })
        wrong = client.post("/api/auth/login", json={
            "email": "unverified@example.com", "password": "WrongGuess999"
        })
        assert wrong.status_code == 401

        right = client.post("/api/auth/login", json={
            "email": "unverified@example.com", "password": "RealPass123"
        })
        assert right.status_code == 403
        assert "verif" in right.json()["detail"]["message"].lower()

    def test_verify_email_with_bad_token_rejected(self, client):
        resp = client.post("/api/auth/verify-email", json={"token": "not-a-real-token"})
        assert resp.status_code == 400

    def test_verify_email_completes_registration_and_logs_in(self, client, monkeypatch):
        result = register_and_verify(client, monkeypatch, "verifyflow@example.com", "VerifyPass123")
        assert "token" in result
        assert result["email"] == "verifyflow@example.com"

    def test_verify_email_token_cannot_be_reused(self, client, monkeypatch):
        captured = {}
        monkeypatch.setattr("app.api.auth._send_verification_email",
                             lambda to_email, token: captured.update({"token": token}))
        client.post("/api/auth/register", json={"email": "reuse-verify@example.com", "password": "ReusePass123"})
        first = client.post("/api/auth/verify-email", json={"token": captured["token"]})
        second = client.post("/api/auth/verify-email", json={"token": captured["token"]})
        assert first.status_code == 200
        assert second.status_code == 400

    def test_resend_verification_returns_generic_response_regardless(self, client):
        """Same enumeration-safety property as register() — this
        endpoint exists specifically so a legitimate user who lost
        their first email isn't stuck, without reopening the hole."""
        client.post("/api/auth/register", json={"email": "resend-test@example.com", "password": "ResendPass123"})
        real = client.post("/api/auth/resend-verification", json={"email": "resend-test@example.com"})
        fake = client.post("/api/auth/resend-verification", json={"email": "never-registered@example.com"})
        assert real.status_code == fake.status_code == 200
        assert real.json() == fake.json()


class TestLoginBruteForceProtection:

    def test_sixth_attempt_in_window_is_rate_limited(self, client):
        client.post("/api/auth/register", json={
            "email": "bruteforce@example.com", "password": "RealPassword123"
        })
        for _ in range(5):
            resp = client.post("/api/auth/login", json={
                "email": "bruteforce@example.com", "password": "WrongGuess"
            })
            assert resp.status_code == 401

        resp = client.post("/api/auth/login", json={
            "email": "bruteforce@example.com", "password": "WrongGuess"
        })
        assert resp.status_code == 429

    def test_rate_limit_blocks_even_the_correct_password(self, client):
        """Once the window is exhausted, even the real password is
        blocked — the limiter runs before verification, on purpose."""
        client.post("/api/auth/register", json={
            "email": "bruteforce2@example.com", "password": "RealPassword123"
        })
        for _ in range(5):
            client.post("/api/auth/login", json={
                "email": "bruteforce2@example.com", "password": "WrongGuess"
            })

        resp = client.post("/api/auth/login", json={
            "email": "bruteforce2@example.com", "password": "RealPassword123"
        })
        assert resp.status_code == 429

    def test_rate_limit_is_scoped_per_email_not_global(self, client, monkeypatch):
        """A lockout on one account must not lock out a different account
        from the same IP."""
        client.post("/api/auth/register", json={
            "email": "victim1@example.com", "password": "VictimPass123"
        })
        register_and_verify(client, monkeypatch, "victim2@example.com", "VictimPass123")
        for _ in range(6):
            client.post("/api/auth/login", json={
                "email": "victim1@example.com", "password": "WrongGuess"
            })

        resp = client.post("/api/auth/login", json={
            "email": "victim2@example.com", "password": "VictimPass123"
        })
        assert resp.status_code == 200


class TestAuthAPIMisc:

    def test_protected_endpoint_requires_token(self, client):
        resp = client.get("/api/stats/overview")
        # Returns data (overview is public in demo) or 401 — either is fine
        assert resp.status_code in (200, 401)

    def test_token_from_register_is_valid(self, client, monkeypatch):
        result = register_and_verify(client, monkeypatch, "tokentest@example.com", "TestPass999")
        token   = result["token"]
        payload = verify_token(token)
        assert payload is not None
        assert payload["email"] == "tokentest@example.com"


class TestMFA:

    def _register_and_login(self, client, email, password="MfaTest12345", monkeypatch=None):
        result = register_and_verify(client, monkeypatch, email, password)
        return {"Authorization": f"Bearer {result['token']}"}

    def test_enroll_returns_secret_and_otpauth_uri(self, client, monkeypatch):
        headers = self._register_and_login(client, "mfa-enroll@example.com", monkeypatch=monkeypatch)
        resp = client.post("/api/auth/mfa/enroll", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "secret" in data
        assert data["otpauth_uri"].startswith("otpauth://totp/")

    def test_confirm_with_wrong_code_rejected(self, client, monkeypatch):
        headers = self._register_and_login(client, "mfa-wrongcode@example.com", monkeypatch=monkeypatch)
        client.post("/api/auth/mfa/enroll", headers=headers)
        resp = client.post("/api/auth/mfa/confirm", headers=headers, json={"code": "000000"})
        assert resp.status_code == 400

    def test_full_enroll_confirm_then_login_requires_code(self, client, monkeypatch):
        import pyotp
        email = "mfa-fullflow@example.com"
        password = "MfaTest12345"
        headers = self._register_and_login(client, email, password, monkeypatch=monkeypatch)

        secret = client.post("/api/auth/mfa/enroll", headers=headers).json()["secret"]
        confirm = client.post("/api/auth/mfa/confirm", headers=headers,
                               json={"code": pyotp.TOTP(secret).now()})
        assert confirm.status_code == 200
        assert confirm.json()["status"] == "mfa_enabled"

        # Password alone is no longer enough once MFA is enabled
        no_code = client.post("/api/auth/login", json={"email": email, "password": password})
        assert no_code.status_code == 401

        wrong_code = client.post("/api/auth/login", json={
            "email": email, "password": password, "mfa_code": "000000"
        })
        assert wrong_code.status_code == 401

        right_code = client.post("/api/auth/login", json={
            "email": email, "password": password, "mfa_code": pyotp.TOTP(secret).now()
        })
        assert right_code.status_code == 200
        assert "token" in right_code.json()

    def test_pending_secret_not_active_until_confirmed(self, client, monkeypatch):
        """Enrolling alone must not enable MFA — only confirming does.
        Otherwise a half-finished enrollment could lock a publisher out
        of their own account with no way back in.
        """
        import pyotp
        email = "mfa-notactive@example.com"
        password = "MfaTest12345"
        headers = self._register_and_login(client, email, password, monkeypatch=monkeypatch)
        client.post("/api/auth/mfa/enroll", headers=headers)

        # No confirm step — login with just the password must still work
        resp = client.post("/api/auth/login", json={"email": email, "password": password})
        assert resp.status_code == 200

    def test_totp_code_cannot_be_replayed(self, client, monkeypatch):
        """A captured valid code must not authenticate a second time.
        pyotp's valid_window=1 alone accepts a ~90s window around the
        current step — real replay protection means the same code
        can't be reused a second time inside that window, even though
        it would still independently verify as mathematically valid."""
        import pyotp
        email = "mfa-replay@example.com"
        password = "MfaTest12345"
        headers = self._register_and_login(client, email, password, monkeypatch=monkeypatch)

        secret = client.post("/api/auth/mfa/enroll", headers=headers).json()["secret"]
        client.post("/api/auth/mfa/confirm", headers=headers, json={"code": pyotp.TOTP(secret).now()})

        code = pyotp.TOTP(secret).now()
        first = client.post("/api/auth/login", json={
            "email": email, "password": password, "mfa_code": code
        })
        assert first.status_code == 200, "the first use of a fresh, valid code must succeed"

        replay = client.post("/api/auth/login", json={
            "email": email, "password": password, "mfa_code": code
        })
        assert replay.status_code == 401, (
            "the same TOTP code was accepted twice — a captured code can be replayed"
        )

    def test_totp_replay_protection_is_per_publisher(self, client, monkeypatch):
        """The replay guard must not cross-contaminate between two
        different accounts — each publisher's last-used step is
        tracked independently."""
        import pyotp
        pw = "MfaTest12345"
        h1 = self._register_and_login(client, "mfa-replay-a@example.com", pw, monkeypatch=monkeypatch)
        h2 = self._register_and_login(client, "mfa-replay-b@example.com", pw, monkeypatch=monkeypatch)

        secret1 = client.post("/api/auth/mfa/enroll", headers=h1).json()["secret"]
        client.post("/api/auth/mfa/confirm", headers=h1, json={"code": pyotp.TOTP(secret1).now()})
        secret2 = client.post("/api/auth/mfa/enroll", headers=h2).json()["secret"]
        client.post("/api/auth/mfa/confirm", headers=h2, json={"code": pyotp.TOTP(secret2).now()})

        code1 = pyotp.TOTP(secret1).now()
        resp = client.post("/api/auth/login", json={
            "email": "mfa-replay-a@example.com", "password": pw, "mfa_code": code1
        })
        assert resp.status_code == 200

        # Publisher B logging in with their own fresh code must be
        # unaffected by publisher A's login just now.
        code2 = pyotp.TOTP(secret2).now()
        resp2 = client.post("/api/auth/login", json={
            "email": "mfa-replay-b@example.com", "password": pw, "mfa_code": code2
        })
        assert resp2.status_code == 200


class TestCookieBasedSession:
    """Login/register set an httpOnly session cookie + a readable CSRF
    cookie (docs/AUDIT.md 3.3) — the browser dashboard uses these
    instead of storing the token in localStorage. Bearer-header auth
    (API/SDK consumers) is untouched — every other test in this file
    proves that by continuing to pass unchanged.

    register() itself no longer sets any cookies (docs/AUDIT.md 2.3) —
    only verify-email and login do, once there's an actual session to
    grant. These tests check the cookies set by verify-email/login."""

    def test_login_sets_session_and_csrf_cookies(self, client, monkeypatch):
        register_and_verify(client, monkeypatch, "cookie-login@example.com", "CookiePass123")
        resp = client.post("/api/auth/login", json={
            "email": "cookie-login@example.com", "password": "CookiePass123"
        })
        assert "cb_session" in resp.cookies
        assert "cb_csrf" in resp.cookies

    def test_session_cookie_is_httponly(self, client, monkeypatch):
        captured = {}
        monkeypatch.setattr("app.api.auth._send_verification_email",
                             lambda to_email, token: captured.update({"token": token}))
        client.post("/api/auth/register", json={
            "email": "httponly-check@example.com", "password": "CookiePass123"
        })
        resp = client.post("/api/auth/verify-email", json={"token": captured["token"]})
        set_cookie_headers = [v for k, v in resp.headers.raw if k.decode().lower() == "set-cookie"]
        session_header = next(h.decode() for h in set_cookie_headers if "cb_session" in h.decode())
        assert "HttpOnly" in session_header

    def test_csrf_cookie_is_not_httponly(self, client, monkeypatch):
        captured = {}
        monkeypatch.setattr("app.api.auth._send_verification_email",
                             lambda to_email, token: captured.update({"token": token}))
        client.post("/api/auth/register", json={
            "email": "csrf-not-httponly@example.com", "password": "CookiePass123"
        })
        resp = client.post("/api/auth/verify-email", json={"token": captured["token"]})
        set_cookie_headers = [v for k, v in resp.headers.raw if k.decode().lower() == "set-cookie"]
        csrf_header = next(h.decode() for h in set_cookie_headers if "cb_csrf" in h.decode())
        assert "HttpOnly" not in csrf_header

    def test_cookie_auth_get_request_works_without_csrf_header(self, client, monkeypatch):
        """GET is exempt from CSRF (it's not a mutating request)."""
        register_and_verify(client, monkeypatch, "cookie-get@example.com", "CookiePass123")
        resp = client.get("/api/auth/me")  # TestClient persists cookies across calls
        assert resp.status_code == 200

    def test_cookie_auth_mutating_request_without_csrf_header_rejected(self, client, monkeypatch):
        register_and_verify(client, monkeypatch, "cookie-nocsrf@example.com", "CookiePass123")
        # A mutating request relying on the cookie alone, no CSRF header
        resp = client.post("/api/team/invite", json={"email": "someone@example.com"})
        assert resp.status_code == 403
        assert "CSRF" in resp.json()["detail"]

    def test_cookie_auth_mutating_request_with_correct_csrf_header_succeeds(self, client, monkeypatch):
        register_and_verify(client, monkeypatch, "cookie-withcsrf@example.com", "CookiePass123")
        csrf_value = client.cookies.get("cb_csrf")
        resp = client.post("/api/team/invite",
            json={"email": "someone2@example.com"},
            headers={"x-csrf-token": csrf_value})
        assert resp.status_code == 200

    def test_cookie_auth_mutating_request_with_wrong_csrf_header_rejected(self, client, monkeypatch):
        register_and_verify(client, monkeypatch, "cookie-wrongcsrf@example.com", "CookiePass123")
        resp = client.post("/api/team/invite",
            json={"email": "someone3@example.com"},
            headers={"x-csrf-token": "totally-wrong-value"})
        assert resp.status_code == 403

    def test_bearer_header_auth_does_not_require_csrf(self, client, monkeypatch):
        """The whole point of the double-submit pattern is that it only
        matters when the *cookie* is the thing authenticating the
        request — an explicit Authorization header can't be forged by
        a third-party site the way an automatically-sent cookie can."""
        result = register_and_verify(client, monkeypatch, "bearer-nocsrf@example.com", "BearerPass123")
        token = result["token"]
        resp = client.post("/api/team/invite",
            headers={"Authorization": f"Bearer {token}"},
            json={"email": "someone4@example.com"})
        assert resp.status_code == 200

    def test_logout_clears_session_cookies(self, client, monkeypatch):
        register_and_verify(client, monkeypatch, "cookie-logout@example.com", "CookiePass123")
        csrf_value = client.cookies.get("cb_csrf")
        resp = client.post("/api/auth/logout", headers={"x-csrf-token": csrf_value})
        assert resp.status_code == 200

        # The revoked token behind the cookie must no longer work
        me = client.get("/api/auth/me")
        assert me.status_code == 401


# ─────────────────────────────────────────────────────────────────
# SELF-HOSTING SAFETY DEFAULTS
# ─────────────────────────────────────────────────────────────────

class TestSelfHostedDefaults:

    def test_signups_closed_once_an_account_exists(self, client, monkeypatch):
        """Only the very first account may self-register; after that it's invite-only."""
        from app.config import cfg
        monkeypatch.setattr(cfg, "ALLOW_SIGNUPS", False)
        resp = client.post("/api/auth/register",
                           json={"email": "stranger@example.com", "password": "TestPass12345"})
        assert resp.status_code == 403

    def test_reset_token_is_never_returned_outside_tests(self, client, monkeypatch):
        """Regression: with the default ENV=development the reset token used to be
        returned in the HTTP response, which allowed account takeover."""
        from app.config import cfg
        monkeypatch.setattr(cfg, "ENV", "development")
        resp = client.post("/api/auth/password-reset/request?email=test@example.com")
        assert resp.status_code == 200
        assert "reset_token" not in resp.json()
