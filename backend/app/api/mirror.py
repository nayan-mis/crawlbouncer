"""
CrawlBouncer — Agent Mirror API
Owners set, per path/article, whether an allowed crawler receives the
CrawlBouncer-extracted "agent" rendition (default) or the real "html" origin page.
"""
from __future__ import annotations
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field

from app.database import get_db
from app.api.auth import require_auth
from app.services.audit import record as audit
from app.services.agent_mirror import (
    get_serve_mode, set_serve_mode, reset_serve_mode, list_overrides, VALID_MODES,
)

router = APIRouter(prefix="/api/mirror", tags=["agent-mirror"])


class MirrorSettingUpdate(BaseModel):
    path: str = Field(..., min_length=1, max_length=2048)
    serve_mode: str = Field(..., pattern="^(agent|html)$")


def _assert_owns_domain(domain_id: str, publisher_id: str):
    with get_db() as db:
        row = db.execute(
            "SELECT id FROM domains WHERE id=? AND publisher_id=?",
            (domain_id, publisher_id)
        ).fetchone()
    if not row:
        raise HTTPException(404, "Domain not found or access denied")


@router.get("/{domain_id}")
def list_mirror_settings(domain_id: str, auth: dict = Depends(require_auth)):
    """List every path with a non-default ('html') override for this domain."""
    _assert_owns_domain(domain_id, auth["sub"])
    return {
        "domain_id":     domain_id,
        "default_mode":  "agent",
        "overrides":     list_overrides(domain_id),
    }


@router.get("/{domain_id}/lookup")
def lookup_mirror_setting(domain_id: str, path: str, auth: dict = Depends(require_auth)):
    """Return the effective serve mode for one specific path."""
    _assert_owns_domain(domain_id, auth["sub"])
    return {"domain_id": domain_id, "path": path, "serve_mode": get_serve_mode(domain_id, path)}


@router.put("/{domain_id}")
def set_mirror_setting(domain_id: str, body: MirrorSettingUpdate, auth: dict = Depends(require_auth)):
    """
    Set the serve mode for a specific path. Setting it back to 'agent'
    (the default) removes the override row rather than storing a
    redundant explicit default.
    """
    _assert_owns_domain(domain_id, auth["sub"])

    if body.serve_mode == "agent":
        reset_serve_mode(domain_id, body.path)
    else:
        set_serve_mode(domain_id, body.path, body.serve_mode)

    audit(auth["sub"], auth["sub"], "mirror_setting.update", "domain", domain_id,
          {"path": body.path, "serve_mode": body.serve_mode})
    return {"domain_id": domain_id, "path": body.path, "serve_mode": body.serve_mode}


@router.delete("/{domain_id}")
def reset_mirror_setting(domain_id: str, path: str, auth: dict = Depends(require_auth)):
    """Reset a path to the 'agent' default."""
    _assert_owns_domain(domain_id, auth["sub"])
    reset_serve_mode(domain_id, path)
    audit(auth["sub"], auth["sub"], "mirror_setting.reset", "domain", domain_id, {"path": path})
    return {"domain_id": domain_id, "path": path, "serve_mode": "agent"}
