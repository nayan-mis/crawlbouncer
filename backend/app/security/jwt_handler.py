"""
CrawlBouncer — JWT Handler
Signs and verifies JSON Web Tokens for publisher authentication.
"""
from __future__ import annotations
import hashlib
import hmac
import base64
import json
import time
import secrets
from typing import Optional
import bcrypt

from app.config import cfg


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _decode_b64(s: str) -> bytes:
    pad = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * pad)


def create_token(user_id: str, email: str, auth_version: int = 0,
                  role: str = "owner", actor_id: Optional[str] = None) -> str:
    """
    Create a signed JWT.
    `sub` is always the account (publisher_id) that owns domains — this is what every existing ownership check (`auth["sub"]`)
    keys off, whether the actual person logging in is the account owner
    or an invited team member. `actor_id`/`role` identify the real
    person for audit-log attribution and for gating owner-only actions
    (invites, account deletion). Defaults to role="owner" with
    actor_id=user_id, so every pre-existing call site that doesn't pass
    these keeps working exactly as before team seats existed.
    """
    header  = _b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64(json.dumps({
        "sub":      user_id,
        "email":    email,
        "role":     role,
        "actor_id": actor_id or user_id,
        "jti":      secrets.token_urlsafe(18),
        "ver":      auth_version,
        "iat":      int(time.time()),
        "exp":      int(time.time()) + cfg.JWT_EXPIRE_HOURS * 3600,
    }).encode())
    sig = _b64(hmac.new(
        cfg.JWT_SECRET.encode(),
        f"{header}.{payload}".encode(),
        hashlib.sha256,
    ).digest())
    return f"{header}.{payload}.{sig}"


def verify_token(token: str) -> Optional[dict]:
    """
    Verify a JWT and return its payload.
    Returns None if invalid or expired.
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None

        header, payload, provided_sig = parts

        # Verify signature
        expected_sig = _b64(hmac.new(
            cfg.JWT_SECRET.encode(),
            f"{header}.{payload}".encode(),
            hashlib.sha256,
        ).digest())

        if not hmac.compare_digest(provided_sig, expected_sig):
            return None

        # Decode payload
        data = json.loads(_decode_b64(payload))

        # Check expiry
        if data.get("exp", 0) < time.time():
            return None

        return data

    except Exception:
        return None


def hash_password(password: str) -> str:
    """Create an adaptive bcrypt password hash.

    Password hashes deliberately have an independent random salt; JWT secrets
    must never double as password peppers because rotating a JWT key would
    otherwise invalidate every login.
    """
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify bcrypt hashes and support one-time migration from legacy hashes."""
    if stored_hash.startswith("$2"):
        try:
            return bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8"))
        except ValueError:
            return False

    # Legacy SHA-256 hashes are accepted only at login so the caller can
    # immediately replace them with bcrypt. New registrations never create one.
    legacy = hashlib.sha256((password + cfg.JWT_SECRET[:16]).encode()).hexdigest()
    return hmac.compare_digest(legacy, stored_hash)


def needs_password_rehash(stored_hash: str) -> bool:
    return not stored_hash.startswith("$2")
