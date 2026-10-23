"""
CrawlBouncer — Team API
Owner-only invite/remove; members can list their own team. Invited
members get everything the owner gets except inviting others and removing/deleting the account — enforced via require_owner
on those actions.
"""
from __future__ import annotations
import hashlib
import secrets
import time
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, EmailStr, Field

from app.database import get_db
from app.api.auth import require_auth, require_owner
from app.security.jwt_handler import hash_password, create_token
from app.services.audit import record as audit
from app.config import cfg
from app.services.mailer import send_email

router = APIRouter(prefix="/api/team", tags=["team"])

INVITE_EXPIRE_SECONDS = 7 * 24 * 3600


class InviteRequest(BaseModel):
    email: EmailStr


class AcceptInviteRequest(BaseModel):
    token: str
    password: str = Field(..., min_length=8, max_length=200)


def _send_team_invite_email(email: str, token: str, account_name: str) -> None:
    """Best-effort invite email (printed to the log if SMTP isn't configured)."""
    link = f"{cfg.APP_BASE_URL.rstrip('/')}/team-accept.html?token={token}"
    send_email(email, f"You've been invited to {account_name}'s CrawlBouncer account",
               f"Set your password to join: {link}\nThis link expires in 7 days.")


@router.get("/")
def list_team(auth: dict = Depends(require_auth)):
    """Owner and members alike can see who's on the team."""
    with get_db() as db:
        owner = db.execute("SELECT email, name FROM publishers WHERE id=?", (auth["sub"],)).fetchone()
        members = db.execute(
            "SELECT id, email, status, invited_at, accepted_at FROM team_members "
            "WHERE publisher_id=? ORDER BY invited_at",
            (auth["sub"],)
        ).fetchall()
    return {
        "owner": {"email": owner["email"], "name": owner["name"]} if owner else None,
        "members": [dict(m) for m in members],
    }


@router.post("/invite")
def invite_member(body: InviteRequest, auth: dict = Depends(require_owner)):
    with get_db() as db:
        existing_publisher = db.execute("SELECT id FROM publishers WHERE email=?", (body.email,)).fetchone()
        existing_member = db.execute("SELECT id, status FROM team_members WHERE email=?", (body.email,)).fetchone()
        owner = db.execute("SELECT name FROM publishers WHERE id=?", (auth["sub"],)).fetchone()

    if existing_publisher:
        raise HTTPException(409, "This email already has its own CrawlBouncer account")
    if existing_member and existing_member["status"] == "active":
        raise HTTPException(409, "This email is already on a team")

    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    expires_at = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(time.time() + INVITE_EXPIRE_SECONDS))
    member_id = f"tm_{secrets.token_hex(12)}"

    with get_db() as db:
        if existing_member:
            # Re-invite: replace the old pending row's token rather than
            # erroring, so a lost invite email doesn't strand the owner.
            db.execute(
                "UPDATE team_members SET invite_token_hash=?, invite_expires_at=?, status='pending' "
                "WHERE email=?",
                (token_hash, expires_at, body.email)
            )
        else:
            db.execute(
                "INSERT INTO team_members (id, publisher_id, email, status, invite_token_hash, invite_expires_at) "
                "VALUES (?,?,?,'pending',?,?)",
                (member_id, auth["sub"], body.email, token_hash, expires_at)
            )

    _send_team_invite_email(body.email, raw_token, owner["name"] if owner else "your team")
    audit(auth["sub"], auth["sub"], "team.invited", "team_member", body.email)
    return {"email": body.email, "status": "pending", "message": "Invite sent."}


@router.post("/accept")
def accept_invite(body: AcceptInviteRequest):
    """Public — no auth. The invite token itself is the credential."""
    token_hash = hashlib.sha256(body.token.encode()).hexdigest()
    now = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())

    with get_db() as db:
        member = db.execute(
            "SELECT id, email, invite_expires_at, status FROM team_members WHERE invite_token_hash=?",
            (token_hash,)
        ).fetchone()

    if not member or member["status"] == "active":
        raise HTTPException(400, "Invalid or already-used invite link")
    if member["invite_expires_at"] and member["invite_expires_at"] < now:
        raise HTTPException(400, "This invite link has expired")

    with get_db() as db:
        db.execute(
            "UPDATE team_members SET password_hash=?, status='active', accepted_at=CURRENT_TIMESTAMP, "
            "invite_token_hash=NULL, invite_expires_at=NULL WHERE id=?",
            (hash_password(body.password), member["id"])
        )
    return {"email": member["email"], "status": "active", "message": "You can now log in."}


@router.delete("/{member_id}")
def remove_member(member_id: str, auth: dict = Depends(require_owner)):
    with get_db() as db:
        member = db.execute(
            "SELECT id FROM team_members WHERE id=? AND publisher_id=?",
            (member_id, auth["sub"])
        ).fetchone()
        if not member:
            raise HTTPException(404, "Team member not found")
        # Deleting the row makes any of their existing tokens fail the
        # require_auth member lookup immediately — no separate
        # invalidation step needed.
        db.execute("DELETE FROM team_members WHERE id=?", (member_id,))

    audit(auth["sub"], auth["sub"], "team.removed", "team_member", member_id)
    return {"id": member_id, "message": "Removed."}
