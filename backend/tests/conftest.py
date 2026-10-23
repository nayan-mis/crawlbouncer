"""
CrawlBouncer — Test Configuration
Shared fixtures for all test files.
Uses an isolated in-memory test database so tests never touch real data.
"""
import os
import pytest
import sqlite3
from typing import Generator
from fastapi.testclient import TestClient

# ── Point to test database BEFORE importing app ───────────────────
os.environ["DATABASE_URL"] = ":memory:"
os.environ["JWT_SECRET"]   = "test-secret-key-not-for-production"
os.environ["ENV"]          = "test"
os.environ["ALLOW_SIGNUPS"] = "true"                  # tests register many accounts
os.environ["REQUIRE_EMAIL_VERIFICATION"] = "true"     # exercise the verification flow

from cryptography.fernet import Fernet
os.environ["MFA_ENCRYPTION_KEY"] = Fernet.generate_key().decode()


from app.main     import app
from app.database import get_db, SCHEMA


# ─────────────────────────────────────────────────────────────────
# TEST DATABASE
# ─────────────────────────────────────────────────────────────────

TEST_DB_PATH = "test_crawlbouncer.db"


def setup_test_db():
    """Create a fresh test database with the full schema."""
    if os.path.exists(TEST_DB_PATH):
        os.remove(TEST_DB_PATH)

    conn = sqlite3.connect(TEST_DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)

    # Seed test publisher
    conn.execute("""
        INSERT INTO publishers (id, email, password_hash, name, email_verified)
        VALUES ('pub-test-001', 'test@example.com', 'hashedpassword', 'Test Publisher', 1)
    """)

    # Seed test domain
    conn.execute("""
        INSERT INTO domains (id, publisher_id, domain, origin_url, cname_target, dns_verified, active)
        VALUES ('dom-test-001', 'pub-test-001', 'testblog.com', 'https://origin.testblog.com', 'abc123.proxy.example.com', 1, 1)
    """)

    # Seed a second, independent account (no domains yet), used for
    # tenant-isolation tests against the publisher above.
    conn.execute("""
        INSERT INTO publishers (id, email, password_hash, name, email_verified)
        VALUES ('pub-test-free', 'free@example.com', 'hashedpassword', 'Second Test Publisher', 1)
    """)

    # Seed a platform admin, used to test admin-only endpoints and
    # suspension flows independently of the two ordinary publishers above.
    conn.execute("""
        INSERT INTO publishers (id, email, password_hash, name, is_admin, email_verified)
        VALUES ('pub-test-admin', 'admin@example.com', 'hashedpassword', 'Admin Test User', 1, 1)
    """)

    conn.commit()
    conn.close()

    # Patch the DB path
    import app.database as db_module
    db_module.DB_PATH = TEST_DB_PATH


def teardown_test_db():
    if os.path.exists(TEST_DB_PATH):
        os.remove(TEST_DB_PATH)


# ─────────────────────────────────────────────────────────────────
# FIXTURES
# ─────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session", autouse=True)
def test_db():
    """Create test DB once for the whole test session."""
    setup_test_db()
    yield
    teardown_test_db()


@pytest.fixture(scope="session")
def client() -> Generator:
    """FastAPI test client — reused across all tests."""
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c


@pytest.fixture
def auth_headers(client) -> dict:
    """Return valid JWT auth headers for the test publisher."""
    from app.security.jwt_handler import create_token
    token = create_token("pub-test-001", "test@example.com")
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def free_auth_headers(client) -> dict:
    """Return valid JWT auth headers for the second test publisher."""
    from app.security.jwt_handler import create_token
    token = create_token("pub-test-free", "free@example.com")
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def admin_auth_headers(client) -> dict:
    """Return valid JWT auth headers for the platform admin test user."""
    from app.security.jwt_handler import create_token
    token = create_token("pub-test-admin", "admin@example.com")
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    """
    The rate limiter is a module-level in-memory singleton, shared across
    every test in the session. Without this, tests that repeatedly hit a
    rate-limited endpoint (e.g. login, brute-force protection) could start
    failing based on test execution order rather than their own logic.
    """
    from app.middleware.rate_limiter import get_limiter
    get_limiter().reset_all()
    yield
    get_limiter().reset_all()


@pytest.fixture(autouse=True)
def _reset_client_cookies(client):
    """
    The `client` fixture is session-scoped with a real, persistent
    cookie jar — since login/register now set session/CSRF cookies
    (cookie-based sessions), any test that authenticates via cookie
    would otherwise leak that cookie into every later test in the
    session, including ones in completely different files that assume
    an unauthenticated request. Clearing between every test makes that
    assumption safe again regardless of execution order.
    """
    client.cookies.clear()
    yield
    client.cookies.clear()


# ─────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────

def register_and_verify(client, monkeypatch, email: str, password: str = "TestPass12345", name: str | None = None) -> dict:
    """
    Registration is now a two-step, email-verified flow  — register() no longer returns a token or logs
    anyone in, only /api/auth/verify-email does, once a token proves
    the caller controls the email. There's no real inbox in tests, so
    this captures the token the same way the email would have
    delivered it (by monkeypatching the send function, the same
    pattern already used for team invites) and completes verification,
    returning the same shape client.post("/api/auth/login") would.
    Use this everywhere a test needs an immediately-usable account —
    calling /api/auth/register alone no longer provides one.
    """
    captured = {}
    monkeypatch.setattr(
        "app.api.auth._send_verification_email",
        lambda to_email, token: captured.update({"token": token})
    )
    body = {"email": email, "password": password}
    if name is not None:
        body["name"] = name
    reg = client.post("/api/auth/register", json=body)
    assert reg.status_code == 200, f"register() failed unexpectedly: {reg.text}"
    assert "token" in captured, "verification email was never sent — is this email already registered?"

    verify = client.post("/api/auth/verify-email", json={"token": captured["token"]})
    assert verify.status_code == 200, f"verify-email failed unexpectedly: {verify.text}"
    return verify.json()


def make_bot_request(ua: str) -> dict:
    """Helper: simulate an incoming request with a given user-agent."""
    return {"user_agent": ua, "ip": "10.0.0.1", "path": "/article/test"}
