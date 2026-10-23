"""
CrawlBouncer — Auth API
Publisher signup, login, JWT token management.
"""
from __future__ import annotations
import re
import hashlib
import secrets
import time
from fastapi import APIRouter, HTTPException, Header, Depends, Request, Cookie, Response
from pydantic import BaseModel, EmailStr
from typing import Optional

from app.database import get_db
from app.config import cfg
from app.services.audit import record as audit
from app.services.mailer import send_email
from app.security.jwt_handler import (
    create_token, verify_token, hash_password, verify_password, needs_password_rehash,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
VERIFY_TOKEN_EXPIRE_HOURS = 24

# Not an exhaustive breach-list (that's a much larger dataset better
# handled by a dedicated service like HaveIBeenPwned's k-anonymity API)
# — this is a cheap, no-dependency floor that blocks the handful of
# passwords that show up at the top of literally every breach-corpus
# analysis. Length-only (the pre-existing check) lets all of these
# through otherwise.
COMMON_PASSWORDS = {
    "password", "password1", "password123", "12345678", "123456789",
    "1234567890", "qwerty123", "qwertyuiop", "letmein123", "welcome123",
    "admin1234", "iloveyou1", "sunshine1", "princess1", "football1",
    "baseball1", "dragon123", "monkey123", "trustno1", "abc123456",
    "changeme1", "passw0rd1", "p@ssw0rd1", "letmein12", "welcome12",
}


# ─────────────────────────────────────────────────────────────────
# SCHEMAS
# ─────────────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    email: str
    password: str
    name: Optional[str] = None


class RegisterResponse(BaseModel):
    status: str
    message: str


class VerifyEmailRequest(BaseModel):
    token: str


class ResendVerificationRequest(BaseModel):
    email: str


class LoginRequest(BaseModel):
    email: str
    password: str
    mfa_code: Optional[str] = None


class AuthResponse(BaseModel):
    token: str
    user_id: str
    email: str
    name: Optional[str]

class PasswordResetComplete(BaseModel):
    token: str
    password: str

class DeleteAccountRequest(BaseModel):
    password: str


class MFAConfirm(BaseModel):
    code: str

def _mfa_cipher():
    if not cfg.MFA_ENCRYPTION_KEY:
        raise HTTPException(503, "MFA is not configured on this server")
    from cryptography.fernet import Fernet
    try:
        return Fernet(cfg.MFA_ENCRYPTION_KEY.encode())
    except ValueError:
        raise HTTPException(503, "MFA encryption key is invalid")


def verify_totp_once(publisher_id: str, secret: str, code: str, valid_window: int = 1) -> bool:
    """Verify a TOTP code and reject replay of an already-used code.

    pyotp.TOTP.verify(valid_window=1) alone accepts the previous,
    current, and next 30s step — a ~90 second window in which the
    *same* code, if captured once (network interception, a compromised
    delivery channel, shoulder-surfing), can be replayed to authenticate
    a second time. RFC 6238 and common TOTP implementation guidance
    both call for rejecting a code from a step that's already been
    consumed. This checks each candidate step in the window directly
    (rather than trusting verify()'s boolean alone) so the exact
    matched step number is known, compares it against the last step
    this account successfully used, and only accepts strictly forward
    progress — then persists the new high-water mark so the same
    step can never be accepted twice.
    """
    import pyotp
    totp = pyotp.TOTP(secret)
    now_step = int(time.time()) // totp.interval

    with get_db() as db:
        row = db.execute("SELECT mfa_last_step FROM publishers WHERE id=?", (publisher_id,)).fetchone()
        last_step = row["mfa_last_step"] if row and row["mfa_last_step"] is not None else -1

        for offset in range(-valid_window, valid_window + 1):
            candidate_step = now_step + offset
            if candidate_step <= last_step:
                continue  # already used or older than the last accepted code
            if totp.at(candidate_step * totp.interval) == code:
                db.execute("UPDATE publishers SET mfa_last_step=? WHERE id=?", (candidate_step, publisher_id))
                return True
        return False


def _send_password_reset_email(email: str, token: str) -> None:
    """Send a reset link; callers never expose delivery errors."""
    link = f"{cfg.APP_BASE_URL.rstrip('/')}/reset-password.html?token={token}"
    send_email(email, "Reset your CrawlBouncer password",
               f"Reset your password within one hour: {link}")


def _send_verification_email(email: str, token: str) -> None:
    """Sent to a genuinely new registration. register() returns the same response
    whether this or _send_existing_account_notice_email fires, so the response
    never reveals whether an email was already registered."""
    link = f"{cfg.APP_BASE_URL.rstrip('/')}/verify-email.html?token={token}"
    send_email(email, "Verify your CrawlBouncer account",
               f"Confirm your email to finish setting up your account: {link}\n"
               f"This link expires in {VERIFY_TOKEN_EXPIRE_HOURS} hours.")


def _send_existing_account_notice_email(email: str) -> None:
    """Sent instead of a verification email when someone "registers" an email
    that already has an account. Never creates a second account and never
    reveals anything to the caller."""
    send_email(email, "Someone tried to register this email on CrawlBouncer",
               "You (or someone else) just tried to create a CrawlBouncer account with "
               "this email address, which already has one. If this was you, log in "
               "normally or use \"forgot password\". If it wasn't you, no action is "
               "needed. No new account was created.")


# ─────────────────────────────────────────────────────────────────
# COOKIE-BASED SESSION SUPPORT
#
# The JWT is returned in the JSON body of login and /verify-email (API
# consumers, the Python SDK's future auth needs, anything non-browser
# rely on that) — but the browser dashboard no longer has to store it
# in localStorage to use it. An httpOnly cookie carries the same token
# for browser requests, so JS on the page (and therefore any XSS, if
# one is ever introduced) cannot read it at all.
#
# httpOnly cookies are sent automatically by the browser on every
# request, including ones a malicious third-party site could trigger
# (CSRF) — a risk that plain Bearer-header auth doesn't have, since a
# page on another origin can't set a custom Authorization header on a
# request it forges. The double-submit cookie pattern closes that: a
# second, non-httpOnly cookie carries a random value the frontend JS
# reads and echoes back as a header on every mutating request. A CSRF
# attacker can forge the cookie-bearing request but can't read the
# CSRF cookie's value (cross-origin JS can't read another site's
# cookies) to also set the matching header.
# ─────────────────────────────────────────────────────────────────

SESSION_COOKIE = "cb_session"
CSRF_COOKIE = "cb_csrf"
CSRF_HEADER = "x-csrf-token"
CSRF_EXEMPT_METHODS = {"GET", "HEAD", "OPTIONS"}


def set_session_cookies(response: Response, token: str) -> str:
    """Set both the httpOnly session cookie and the readable CSRF
    cookie on a response. Returns the CSRF value in case a caller
    wants it (e.g. to hand to a non-browser client alongside the JSON
    body, though the JSON body's `token` field is the real mechanism
    for those)."""
    csrf_value = secrets.token_urlsafe(32)
    response.set_cookie(
        key=SESSION_COOKIE, value=token,
        max_age=cfg.JWT_EXPIRE_HOURS * 3600, httponly=True, samesite="lax",
        secure=cfg.is_production,
    )
    response.set_cookie(
        key=CSRF_COOKIE, value=csrf_value,
        max_age=cfg.JWT_EXPIRE_HOURS * 3600, httponly=False, samesite="lax",
        secure=cfg.is_production,
    )
    return csrf_value


def clear_session_cookies(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE)
    response.delete_cookie(CSRF_COOKIE)


# ─────────────────────────────────────────────────────────────────
# DEPENDENCY — require valid JWT on protected endpoints
# ─────────────────────────────────────────────────────────────────

def require_auth(
    request: Request,
    authorization: str = Header(default=""),
    cb_session: str = Cookie(default=""),
    cb_csrf: str = Cookie(default=""),
) -> dict:
    """
    FastAPI dependency that verifies a JWT from either the
    Authorization header (API/SDK consumers) or the httpOnly session
    cookie (the browser dashboard). Cookie-authenticated *mutating*
    requests additionally require a matching CSRF header — see the
    module-level comment above for why.
    """
    used_cookie = False
    if authorization.startswith("Bearer "):
        token = authorization.removeprefix("Bearer ").strip()
    elif cb_session:
        token = cb_session
        used_cookie = True
    else:
        raise HTTPException(401, "Missing or malformed Authorization header")

    if used_cookie and request.method not in CSRF_EXEMPT_METHODS:
        if not cb_csrf or not secrets.compare_digest(cb_csrf, request.headers.get(CSRF_HEADER, "")):
            raise HTTPException(403, "Missing or invalid CSRF token")

    payload = verify_token(token)

    if not payload:
        raise HTTPException(401, "Token invalid or expired")

    # Logout and incident-response revocation are enforced on every protected
    # route. Expired revocations are removed opportunistically.
    with get_db() as db:
        db.execute("DELETE FROM revoked_tokens WHERE expires_at < ?", (time.time(),))
        revoked = db.execute("SELECT 1 FROM revoked_tokens WHERE jti=?", (payload.get("jti", ""),)).fetchone()
        account = db.execute("SELECT auth_version, suspended FROM publishers WHERE id=?", (payload["sub"],)).fetchone()

        role = payload.get("role", "owner")
        if role == "member":
            # A member's session is invalidated independently of the
            # owner's — removing one member must not log everyone else
            # out, so their auth_version lives on their own row.
            member = db.execute(
                "SELECT auth_version, status FROM team_members WHERE id=?",
                (payload.get("actor_id", ""),)
            ).fetchone()
            if not member or member["status"] != "active" or payload.get("ver", 0) != member["auth_version"]:
                raise HTTPException(401, "Token session has been invalidated")
        else:
            if not account or payload.get("ver", 0) != account["auth_version"]:
                raise HTTPException(401, "Token session has been invalidated")

    if revoked:
        raise HTTPException(401, "Token has been revoked")
    if not account:
        raise HTTPException(401, "Account not found")
    if account["suspended"]:
        raise HTTPException(403, "This account has been suspended")

    return payload


def require_owner(auth: dict = Depends(require_auth)) -> dict:
    """
    Gate for actions team members must never do: inviting/removing members, deleting the account. Members get
    everything else the owner gets — this is the one restriction.
    """
    if auth.get("role", "owner") != "owner":
        raise HTTPException(403, "Only the account owner can do this")
    return auth


def require_admin(auth: dict = Depends(require_auth)) -> dict:
    """
    FastAPI dependency for platform-admin-only endpoints. Checked fresh
    against the DB on every call, never trusted from the JWT — a JWT
    claim would be stale from before an admin flag was granted or
    revoked.

    Team-member tokens are rejected outright, before the DB check even
    runs: a member's `sub` equals their team owner's publisher_id, so
    without this, being invited to an admin's account would silently
    inherit that admin's platform-wide access — is_admin is tied to a
    specific owner login, never to "shares an account with an admin."
    """
    if auth.get("role", "owner") != "owner":
        raise HTTPException(403, "Admin access required")
    with get_db() as db:
        row = db.execute("SELECT is_admin FROM publishers WHERE id=?", (auth["sub"],)).fetchone()
    if not row or not row["is_admin"]:
        raise HTTPException(403, "Admin access required")
    return auth


# ─────────────────────────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────────────────────────

@router.post("/register", response_model=RegisterResponse)
def register(body: RegisterRequest, request: Request):
    """
    Start account creation — does NOT log the caller in or return a
    token. Always returns the exact same response regardless of
    whether the email was new or already registered
    which emails have accounts (no 409 on duplicates). Now:
      - new email  -> account created, verification email sent (only if email
        verification is on; otherwise the account is active immediately)
      - known email -> nothing created, a notice email sent to that
        address instead — the caller gets an identical response either way
    Rate-limited per IP (10/hour) regardless of outcome.
    """
    from app.services.client_ip import get_client_ip
    from app.middleware.rate_limiter import get_limiter

    ip = get_client_ip(request)
    result = get_limiter().check(f"register:{ip}", limit=10, window=3600)
    if not result.allowed:
        raise HTTPException(429, {
            "error":       "Too many registration attempts",
            "message":     "Try again later.",
            "retry_after": result.retry_after,
        })

    # Validate email
    if not EMAIL_RE.match(body.email):
        raise HTTPException(400, "Invalid email address")

    # Validate password strength
    if len(body.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")
    if body.password.lower() in COMMON_PASSWORDS:
        raise HTTPException(400, "That password is too common. Please choose a less predictable one.")

    with get_db() as db:
        is_first = db.execute("SELECT COUNT(*) FROM publishers").fetchone()[0] == 0
    # The first account is always allowed (it becomes the admin).
    # After that, registration is closed unless ALLOW_SIGNUPS=true.
    if not is_first and not cfg.ALLOW_SIGNUPS:
        raise HTTPException(403, "Signups are closed on this instance. Ask the admin to invite you.")
    verify_required = cfg.require_email_verification and not is_first

    generic_response = RegisterResponse(
        status="verification_sent" if verify_required else "registered",
        message=("Check your email to verify your account and continue."
                 if verify_required else "Account created. You can log in now."),
    )

    with get_db() as db:
        existing_publisher = db.execute(
            "SELECT id FROM publishers WHERE email = ?", (body.email,)
        ).fetchone()
        existing_member = db.execute(
            "SELECT id FROM team_members WHERE email = ?", (body.email,)
        ).fetchone()

    if existing_publisher or existing_member:
        _send_existing_account_notice_email(body.email)
        return generic_response

    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    expires_at = time.strftime(
        "%Y-%m-%d %H:%M:%S", time.gmtime(time.time() + VERIFY_TOKEN_EXPIRE_HOURS * 3600)
    )

    with get_db() as db:
        pw_hash = hash_password(body.password)
        db.execute(
            "INSERT INTO publishers (email, password_hash, name, email_verified, is_admin, "
            "verify_token_hash, verify_token_expires_at) VALUES (?,?,?,?,?,?,?)",
            (body.email, pw_hash, body.name or body.email.split("@")[0],
             0 if verify_required else 1, 1 if is_first else 0,
             token_hash if verify_required else None, expires_at if verify_required else None)
        )
        new_id = db.execute("SELECT id FROM publishers WHERE email=?", (body.email,)).fetchone()["id"]

    if verify_required:
        _send_verification_email(body.email, raw_token)
    audit(new_id, new_id, "account.registered_pending_verification" if verify_required else "account.registered", "publisher", new_id)
    return generic_response


@router.post("/verify-email", response_model=AuthResponse)
def verify_email(body: VerifyEmailRequest, response: Response):
    """Completes registration — the token proves the caller controls
    the email address, so this is the point where a real session is
    finally issued (unlike register(), which never logs anyone in)."""
    token_hash = hashlib.sha256(body.token.encode()).hexdigest()
    now = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())

    with get_db() as db:
        user = db.execute(
            "SELECT id, email, name, auth_version, email_verified, verify_token_expires_at "
            "FROM publishers WHERE verify_token_hash = ?",
            (token_hash,)
        ).fetchone()

    if not user:
        raise HTTPException(400, "Invalid or already-used verification link")
    if user["email_verified"]:
        raise HTTPException(400, "This email is already verified. Try logging in.")
    if user["verify_token_expires_at"] and user["verify_token_expires_at"] < now:
        raise HTTPException(400, "This verification link has expired. Request a new one.")

    with get_db() as db:
        db.execute(
            "UPDATE publishers SET email_verified=1, verify_token_hash=NULL, "
            "verify_token_expires_at=NULL WHERE id=?",
            (user["id"],)
        )

    audit(user["id"], user["id"], "account.email_verified", "publisher", user["id"])
    token = create_token(user["id"], user["email"], user["auth_version"])
    set_session_cookies(response, token)
    return AuthResponse(
        token=token, user_id=user["id"], email=user["email"],
        name=user["name"],
    )


@router.post("/resend-verification", response_model=RegisterResponse)
def resend_verification(body: ResendVerificationRequest, request: Request):
    """Same generic-response-regardless-of-outcome shape as register()
    — otherwise this endpoint would reopen exactly the enumeration hole
    register() was just closed for."""
    from app.services.client_ip import get_client_ip
    from app.middleware.rate_limiter import get_limiter

    ip = get_client_ip(request)
    result = get_limiter().check(f"resend-verification:{ip}", limit=5, window=3600)
    if not result.allowed:
        raise HTTPException(429, {
            "error": "Too many requests", "message": "Try again later.",
            "retry_after": result.retry_after,
        })

    generic_response = RegisterResponse(
        status="verification_sent",
        message="If that email needs verifying, we've sent a new link.",
    )

    with get_db() as db:
        user = db.execute(
            "SELECT id, email_verified FROM publishers WHERE email = ?", (body.email,)
        ).fetchone()

    if not user or user["email_verified"]:
        return generic_response

    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    expires_at = time.strftime(
        "%Y-%m-%d %H:%M:%S", time.gmtime(time.time() + VERIFY_TOKEN_EXPIRE_HOURS * 3600)
    )
    with get_db() as db:
        db.execute(
            "UPDATE publishers SET verify_token_hash=?, verify_token_expires_at=? WHERE id=?",
            (token_hash, expires_at, user["id"])
        )
    _send_verification_email(body.email, raw_token)
    return generic_response


@router.post("/login", response_model=AuthResponse)
def login(body: LoginRequest, request: Request, response: Response):
    """Authenticate a publisher and return a JWT.

    Rate-limited per IP+email pair (5 attempts / 15 min) before password
    verification even runs. General API rate limiting is too loose for a
    credential-guessing attack."""
    from app.services.client_ip import get_client_ip
    from app.middleware.rate_limiter import get_limiter

    ip = get_client_ip(request)
    rl_key = f"login:{ip}:{body.email.strip().lower()}"
    result = get_limiter().check(rl_key, limit=5, window=900)
    if not result.allowed:
        raise HTTPException(429, {
            "error":       "Too many login attempts",
            "message":     "Try again later.",
            "retry_after": result.retry_after,
        })

    with get_db() as db:
        user = db.execute(
            "SELECT id, email, name, password_hash, auth_version, mfa_secret, mfa_enabled, "
            "suspended, email_verified "
            "FROM publishers WHERE email = ?",
            (body.email,)
        ).fetchone()

    if user:
        if not verify_password(body.password, user["password_hash"]):
            raise HTTPException(401, "Invalid email or password")
        if user["suspended"]:
            raise HTTPException(403, "This account has been suspended")
        if not user["email_verified"]:
            # Only reachable with the correct password, so this doesn't
            # reopen the enumeration hole register() closed — someone
            # probing for registered emails never gets this far without
            # already knowing the password.
            raise HTTPException(403, {
                "error": "Email not verified",
                "message": "Check your email for a verification link, or request a new one.",
            })
        if user["mfa_enabled"]:
            if not body.mfa_code:
                raise HTTPException(401, "MFA code required")
            secret = _mfa_cipher().decrypt(user["mfa_secret"].encode()).decode()
            if not verify_totp_once(user["id"], secret, body.mfa_code):
                raise HTTPException(401, "Invalid MFA code")

        # Safely migrate accounts created by the former SHA-256 implementation.
        if needs_password_rehash(user["password_hash"]):
            with get_db() as db:
                db.execute(
                    "UPDATE publishers SET password_hash=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                    (hash_password(body.password), user["id"]),
                )

        token = create_token(user["id"], user["email"], user["auth_version"], role="owner")
        set_session_cookies(response, token)
        return AuthResponse(
            token=token, user_id=user["id"], email=user["email"], name=user["name"],
        )

    # Not an owner account — check team members (invited seats).
    with get_db() as db:
        member = db.execute(
            "SELECT tm.id, tm.email, tm.password_hash, tm.auth_version, tm.status, "
            "       p.id AS owner_id, p.suspended, p.name AS account_name "
            "FROM team_members tm JOIN publishers p ON p.id = tm.publisher_id "
            "WHERE tm.email = ?",
            (body.email,)
        ).fetchone()

    if not member or member["status"] != "active" or not member["password_hash"] \
            or not verify_password(body.password, member["password_hash"]):
        raise HTTPException(401, "Invalid email or password")
    if member["suspended"]:
        raise HTTPException(403, "This account has been suspended")
    # Team member MFA isn't implemented yet — only the owner login can
    # require it. Noted as a known gap, not a silent omission.

    token = create_token(
        member["owner_id"], member["email"], member["auth_version"],
        role="member", actor_id=member["id"],
    )
    set_session_cookies(response, token)
    return AuthResponse(
        token=token, user_id=member["owner_id"], email=member["email"],
        name=member["account_name"],
    )


@router.get("/me")
def me(auth: dict = Depends(require_auth)):
    """
    Return the current session's profile. `email`/`name` reflect the
    actual logged-in person (owner or invited member) — `mfa_enabled`/`is_admin` reflect the account (auth["sub"]) they're
    acting on, which for a member is their team's owner account, not
    themselves. Conflating the two would misattribute an owner's email
    to a member viewing their own settings.
    """
    with get_db() as db:
        user = db.execute(
            "SELECT id, name, mfa_enabled, is_admin FROM publishers WHERE id = ?",
            (auth["sub"],)
        ).fetchone()

    if not user:
        raise HTTPException(404, "Publisher account not found")

    role = auth.get("role", "owner")
    return {
        "user_id": user["id"],
        "email": auth.get("email", ""),
        "name": user["name"] if role == "owner" else auth.get("email", ""),
        "mfa_enabled": bool(user["mfa_enabled"]),
        # is_admin is platform-staff status tied to the owner's own
        # login, never inherited by an invited team member just because
        # their token's `sub` happens to equal an admin's publisher_id.
        "is_admin": bool(user["is_admin"]) if role == "owner" else False,
        "role": role,
    }


@router.post("/logout")
def logout(response: Response, auth: dict = Depends(require_auth)):
    """Revoke the current JWT immediately rather than waiting for expiry."""
    clear_session_cookies(response)
    jti = auth.get("jti")
    exp = auth.get("exp")
    if not jti or not exp:
        raise HTTPException(401, "Token cannot be revoked")
    with get_db() as db:
        db.execute("INSERT OR IGNORE INTO revoked_tokens (jti, expires_at) VALUES (?,?)", (jti, exp))
    audit(auth["sub"], auth["sub"], "session.logged_out", "session", jti)
    return {"status": "logged_out"}

@router.post("/mfa/enroll")
def enroll_mfa(auth: dict = Depends(require_owner)):
    """Begin TOTP enrollment; confirm a code before MFA becomes active."""
    import pyotp
    secret = pyotp.random_base32()
    encrypted = _mfa_cipher().encrypt(secret.encode()).decode()
    with get_db() as db:
        db.execute("UPDATE publishers SET mfa_pending_secret=? WHERE id=?", (encrypted, auth["sub"]))
    return {"secret": secret, "otpauth_uri": pyotp.TOTP(secret).provisioning_uri(auth["email"], issuer_name="CrawlBouncer")}

@router.post("/mfa/confirm")
def confirm_mfa(body: MFAConfirm, auth: dict = Depends(require_owner)):
    import pyotp
    cipher = _mfa_cipher()
    with get_db() as db:
        row = db.execute("SELECT mfa_pending_secret FROM publishers WHERE id=?", (auth["sub"],)).fetchone()
        if not row or not row["mfa_pending_secret"]:
            raise HTTPException(400, "No MFA enrollment is pending")
        secret = cipher.decrypt(row["mfa_pending_secret"].encode()).decode()
        if not pyotp.TOTP(secret).verify(body.code, valid_window=1):
            raise HTTPException(400, "Invalid MFA code")
        db.execute("UPDATE publishers SET mfa_secret=mfa_pending_secret, mfa_pending_secret=NULL, mfa_enabled=1, auth_version=auth_version+1 WHERE id=?", (auth["sub"],))
    audit(auth["sub"], auth["sub"], "mfa.enabled", "publisher", auth["sub"])
    return {"status": "mfa_enabled"}


@router.post("/password-reset/request")
def request_password_reset(email: EmailStr):
    """Create a one-hour single-use reset token without disclosing account existence."""
    raw_token = secrets.token_urlsafe(32)
    with get_db() as db:
        user = db.execute("SELECT id FROM publishers WHERE email=?", (str(email).lower(),)).fetchone()
        if user:
            db.execute("DELETE FROM password_reset_tokens WHERE publisher_id=? OR expires_at < ?", (user["id"], int(time.time())))
            db.execute("INSERT INTO password_reset_tokens (token_hash, publisher_id, expires_at) VALUES (?,?,?)",
                       (hashlib.sha256(raw_token.encode()).hexdigest(), user["id"], int(time.time()) + 3600))
            _send_password_reset_email(str(email).lower(), raw_token)
    response = {"status": "accepted"}
    if cfg.is_test:   # only the test suite may see the token in the response
        response["reset_token"] = raw_token
    return response


@router.post("/password-reset/complete")
def complete_password_reset(body: PasswordResetComplete):
    if len(body.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")
    if body.password.lower() in COMMON_PASSWORDS:
        raise HTTPException(400, "That password is too common. Please choose a less predictable one.")
    token_hash = hashlib.sha256(body.token.encode()).hexdigest()
    with get_db() as db:
        reset = db.execute("SELECT * FROM password_reset_tokens WHERE token_hash=? AND used_at IS NULL", (token_hash,)).fetchone()
        if not reset or reset["expires_at"] < time.time():
            raise HTTPException(400, "Reset token is invalid or expired")
        db.execute("UPDATE password_reset_tokens SET used_at=CURRENT_TIMESTAMP WHERE token_hash=?", (token_hash,))
        db.execute("UPDATE publishers SET password_hash=?, auth_version=auth_version+1, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                   (hash_password(body.password), reset["publisher_id"]))
    audit(reset["publisher_id"], reset["publisher_id"], "password.reset", "publisher", reset["publisher_id"])
    return {"status": "password_reset"}


@router.delete("/account")
def delete_account(body: DeleteAccountRequest, auth: dict = Depends(require_owner)):
    """
    Permanently deactivate the account. Owner-only (require_owner) — the
    same restriction that already applies to team management.

    This is a soft delete, not a row deletion: the
    audit log references publisher_id and must survive. What actually happens:
      - password verified as confirmation for a destructive action
      - email/name anonymized, password made unusable, suspended=1 and
        auth_version bumped (kills all sessions immediately, same
        mechanism as admin suspension)
      - every domain set inactive — unlike a suspension, deletion is
        permanent and there's no one left to manage the domain, so
        protection actually stops (the pipeline 421s inactive domains).
        This is a deliberate difference from suspend's "sites stay up"
        behavior, not an oversight.
      - all team members removed (their sessions die immediately, same
        as an explicit removal)
    """
    with get_db() as db:
        user = db.execute(
            "SELECT id, password_hash FROM publishers WHERE id=?", (auth["sub"],)
        ).fetchone()
        if not user:
            raise HTTPException(404, "Account not found")
        if not verify_password(body.password, user["password_hash"]):
            raise HTTPException(401, "Incorrect password")

        anonymized_email = f"deleted-{auth['sub']}@deleted.invalid"
        db.execute(
            "UPDATE publishers SET email=?, name='Deleted account', password_hash=?, "
            "suspended=1, auth_version=auth_version+1, deleted_at=CURRENT_TIMESTAMP WHERE id=?",
            (anonymized_email, hash_password(secrets.token_urlsafe(32)), auth["sub"])
        )
        db.execute("UPDATE domains SET active=0 WHERE publisher_id=?", (auth["sub"],))
        db.execute("DELETE FROM team_members WHERE publisher_id=?", (auth["sub"],))

    audit(auth["sub"], auth["sub"], "account.deleted", "publisher", auth["sub"])
    return {"status": "deleted", "message": "Account deactivated. Your domains are no longer protected or served."}
