"""
CrawlBouncer — Admin API
Instance-wide visibility and controls, restricted to accounts with
is_admin=1. The first account registered on an instance is made admin
automatically; there is no other self-service way to become one.

Suspending a publisher blocks their dashboard/API access only (login is
rejected, all their existing sessions are invalidated via the same
auth_version-bump mechanism used for MFA/password changes). It does NOT
stop their domains from being proxied — a suspended account is an
account-level problem, not a reason to take a live site
offline for its own readers.
"""
from __future__ import annotations
import json
from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field

from app.database import get_db
from app.api.auth import require_admin
from app.services.audit import record as audit

router = APIRouter(prefix="/api/admin", tags=["admin"])


@router.get("/publishers")
def list_publishers(admin: dict = Depends(require_admin)):
    with get_db() as db:
        rows = db.execute("""
            SELECT p.id, p.email, p.name, p.suspended, p.is_admin, p.created_at,
                   COUNT(d.id) AS domain_count
            FROM publishers p
            LEFT JOIN domains d ON d.publisher_id = p.id
            GROUP BY p.id
            ORDER BY p.created_at DESC
        """).fetchall()
    return [{
        "id": r["id"], "email": r["email"], "name": r["name"],
        "suspended": bool(r["suspended"]), "is_admin": bool(r["is_admin"]),
        "domain_count": r["domain_count"], "created_at": r["created_at"],
    } for r in rows]


@router.post("/publishers/{publisher_id}/suspend")
def suspend_publisher(publisher_id: str, admin: dict = Depends(require_admin)):
    with get_db() as db:
        row = db.execute("SELECT id FROM publishers WHERE id=?", (publisher_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Publisher not found")
        db.execute(
            "UPDATE publishers SET suspended=1, auth_version=auth_version+1 WHERE id=?",
            (publisher_id,)
        )
    audit(publisher_id, admin["sub"], "publisher.suspended", "publisher", publisher_id)
    return {"id": publisher_id, "suspended": True}


@router.post("/publishers/{publisher_id}/unsuspend")
def unsuspend_publisher(publisher_id: str, admin: dict = Depends(require_admin)):
    with get_db() as db:
        row = db.execute("SELECT id FROM publishers WHERE id=?", (publisher_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Publisher not found")
        db.execute("UPDATE publishers SET suspended=0 WHERE id=?", (publisher_id,))
    audit(publisher_id, admin["sub"], "publisher.unsuspended", "publisher", publisher_id)
    return {"id": publisher_id, "suspended": False}


@router.get("/audit")
def platform_audit_log(
    limit: int = Query(100, ge=1, le=500),
    publisher_id: str | None = Query(None),
    admin: dict = Depends(require_admin),
):
    """Platform-wide audit trail — unlike /api/audit, not scoped to the
    calling account. Optionally filter to one publisher."""
    with get_db() as db:
        if publisher_id:
            rows = db.execute(
                "SELECT id, publisher_id, actor_id, action, resource_type, resource_id, details, created_at "
                "FROM audit_events WHERE publisher_id=? ORDER BY id DESC LIMIT ?",
                (publisher_id, limit)
            ).fetchall()
        else:
            rows = db.execute(
                "SELECT id, publisher_id, actor_id, action, resource_type, resource_id, details, created_at "
                "FROM audit_events ORDER BY id DESC LIMIT ?",
                (limit,)
            ).fetchall()
    return [{**dict(row), "details": json.loads(row["details"] or "{}")} for row in rows]


@router.get("/stats")
def platform_stats(admin: dict = Depends(require_admin)):
    with get_db() as db:
        publisher_count = db.execute("SELECT COUNT(*) FROM publishers").fetchone()[0]
        domain_count    = db.execute("SELECT COUNT(*) FROM domains").fetchone()[0]
        request_count   = db.execute("SELECT COUNT(*) FROM requests").fetchone()[0]

    return {
        "publishers": publisher_count,
        "domains":    domain_count,
        "requests":   request_count,
    }
