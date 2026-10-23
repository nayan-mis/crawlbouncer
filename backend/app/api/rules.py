"""
CrawlBouncer — Crawler Rules API
Owners set allow / block rules per AI crawler and per path.
Rules are cached and applied on every incoming request.
"""
from __future__ import annotations
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from typing import Optional

from app.database import get_db
from app.api.auth import require_auth
from app.services.audit import record as audit
from app.middleware.bot_detection import CRAWLERS

router = APIRouter(prefix="/api/rules", tags=["rules"])

# In-memory rule cache: {domain_id: {crawler_name: {action}}}
_rule_cache: dict[str, dict] = {}
# Separate cache for path rules: {domain_id: [(path_prefix, {action}), ...]}
# sorted longest-prefix-first so the first match found is the right one.
_path_rule_cache: dict[str, list] = {}


# ─────────────────────────────────────────────────────────────────
# SCHEMAS
# ─────────────────────────────────────────────────────────────────

class RuleUpdate(BaseModel):
    action: str = Field(..., pattern="^(allow|block)$")


class BulkRuleUpdate(BaseModel):
    rules: dict[str, RuleUpdate]   # {crawler_name: RuleUpdate}


class PathRuleUpdate(BaseModel):
    path_prefix: str = Field(..., min_length=1, max_length=2048)
    action: str = Field(..., pattern="^(allow|block)$")


# ─────────────────────────────────────────────────────────────────
# CACHE HELPERS
# ─────────────────────────────────────────────────────────────────

def _invalidate_cache(domain_id: str):
    _rule_cache.pop(domain_id, None)
    _path_rule_cache.pop(domain_id, None)


def _get_path_rule(domain_id: str, path: str) -> Optional[dict]:
    """Return the longest matching path_prefix rule for this path, or
    None if no path rule matches (caller falls back to crawler rules)."""
    if domain_id not in _path_rule_cache:
        with get_db() as db:
            rows = db.execute(
                "SELECT path_prefix, action FROM path_rules WHERE domain_id=?",
                (domain_id,)
            ).fetchall()
        # Longest prefix first, so the first match encountered is the
        # most specific one.
        _path_rule_cache[domain_id] = sorted(
            [dict(r) for r in rows], key=lambda r: -len(r["path_prefix"])
        )

    for rule in _path_rule_cache[domain_id]:
        if path.startswith(rule["path_prefix"]):
            return {"action": rule["action"]}
    return None


def get_rule(domain_id: str, crawler_name: str, path: str = "") -> dict:
    """
    Fast rule lookup for the proxy hot path.
    A matching path rule (longest-prefix) always wins over the
    crawler-based rule, regardless of which crawler is asking. If no
    path rule matches — including when path="" for callers that don't
    have path-level context — behavior is identical to before path
    rules existed.
    Returns {"action": str}.
    """
    if path:
        path_rule = _get_path_rule(domain_id, path)
        if path_rule is not None:
            return path_rule

    if domain_id in _rule_cache:
        cache = _rule_cache[domain_id]
        if crawler_name in cache:
            return cache[crawler_name]
        if "__default__" in cache:
            return cache["__default__"]

    # Load from database
    with get_db() as db:
        row = db.execute(
            "SELECT action FROM crawler_rules WHERE domain_id=? AND crawler_name=?",
            (domain_id, crawler_name)
        ).fetchone()
        default = db.execute(
            "SELECT action FROM crawler_rules WHERE domain_id=? AND crawler_name='__default__'",
            (domain_id,)
        ).fetchone()

    result = dict(row) if row else (
        dict(default) if default else
        {"action": CRAWLERS.get(crawler_name, {}).get("default_action", "allow")}
    )

    # Cache it
    if domain_id not in _rule_cache:
        _rule_cache[domain_id] = {}
    _rule_cache[domain_id][crawler_name] = result

    return result


# ─────────────────────────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────────────────────────

@router.get("/{domain_id}")
def list_rules(domain_id: str, auth: dict = Depends(require_auth)):
    """
    List all rules for a domain.
    Returns rules for all known crawlers, using defaults for any not configured.
    """
    _assert_owns_domain(domain_id, auth["sub"])

    with get_db() as db:
        saved = db.execute(
            "SELECT crawler_name, action FROM crawler_rules WHERE domain_id=?",
            (domain_id,)
        ).fetchall()

    saved_map = {r["crawler_name"]: dict(r) for r in saved}

    # Merge with known crawlers to show full list
    result = []
    for name, info in CRAWLERS.items():
        rule = saved_map.get(name, {
            "crawler_name": name,
            "action": info["default_action"],
        })
        result.append({
            "crawler_name": name,
            "company":      info["company"],
            "risk":         info["risk"],
            "robots_only":  bool(info.get("robots_only")),
            "action":       rule.get("action", info["default_action"]),
            "is_custom":    name in saved_map,
        })

    return result


@router.get("/{domain_id}/paths")
def list_path_rules(domain_id: str, auth: dict = Depends(require_auth)):
    """List all path-prefix rule overrides for a domain."""
    _assert_owns_domain(domain_id, auth["sub"])
    with get_db() as db:
        rows = db.execute(
            "SELECT path_prefix, action, updated_at FROM path_rules "
            "WHERE domain_id=? ORDER BY LENGTH(path_prefix) DESC",
            (domain_id,)
        ).fetchall()
    return [dict(r) for r in rows]


@router.put("/{domain_id}/paths")
def set_path_rule(domain_id: str, body: PathRuleUpdate, auth: dict = Depends(require_auth)):
    """
    Set a rule for a path prefix, overriding the crawler-based rule for
    any request under that prefix regardless of which crawler it is —
    e.g. always block /premium/, always allow /blog/.
    """
    _assert_owns_domain(domain_id, auth["sub"])

    if not body.path_prefix.startswith("/"):
        raise HTTPException(400, "path_prefix must start with /")

    with get_db() as db:
        existing = db.execute(
            "SELECT id FROM path_rules WHERE domain_id=? AND path_prefix=?",
            (domain_id, body.path_prefix)
        ).fetchone()
        if existing:
            db.execute(
                "UPDATE path_rules SET action=?, updated_at=CURRENT_TIMESTAMP "
                "WHERE domain_id=? AND path_prefix=?",
                (body.action, domain_id, body.path_prefix)
            )
        else:
            db.execute(
                "INSERT INTO path_rules (domain_id, path_prefix, action) VALUES (?,?,?)",
                (domain_id, body.path_prefix, body.action)
            )

    _invalidate_cache(domain_id)
    audit(auth["sub"], auth["sub"], "path_rule.updated", "domain", domain_id,
          {"path_prefix": body.path_prefix, "action": body.action})
    return {
        "path_prefix": body.path_prefix, "action": body.action,
        "message": "Path rule updated. Takes effect immediately.",
    }


@router.delete("/{domain_id}/paths")
def reset_path_rule(domain_id: str, path_prefix: str, auth: dict = Depends(require_auth)):
    """Remove a path-prefix rule; that prefix falls back to whatever the
    crawler-based rule says."""
    _assert_owns_domain(domain_id, auth["sub"])
    with get_db() as db:
        db.execute(
            "DELETE FROM path_rules WHERE domain_id=? AND path_prefix=?",
            (domain_id, path_prefix)
        )
    _invalidate_cache(domain_id)
    audit(auth["sub"], auth["sub"], "path_rule.reset", "domain", domain_id, {"path_prefix": path_prefix})
    return {"path_prefix": path_prefix, "message": "Path rule removed."}


# NOTE: the two routes above (GET/PUT/DELETE "/{domain_id}/paths") must
# stay registered before "/{domain_id}/{crawler_name}" below — FastAPI
# matches path routes in registration order, and the wildcard
# {crawler_name} segment would otherwise swallow literal "paths" as if
# it were a crawler name. Route order is a correctness requirement here,
# not just style.
@router.put("/{domain_id}/{crawler_name}")
def set_rule(
    domain_id: str,
    crawler_name: str,
    body: RuleUpdate,
    auth: dict = Depends(require_auth),
):
    """Set a rule for a specific crawler on a domain."""
    _assert_owns_domain(domain_id, auth["sub"])

    if crawler_name != "__default__" and crawler_name not in CRAWLERS:
        raise HTTPException(400, f"Unknown crawler: {crawler_name}")

    with get_db() as db:
        existing = db.execute(
            "SELECT id FROM crawler_rules WHERE domain_id=? AND crawler_name=?",
            (domain_id, crawler_name)
        ).fetchone()

        if existing:
            db.execute(
                "UPDATE crawler_rules SET action=?, updated_at=CURRENT_TIMESTAMP WHERE domain_id=? AND crawler_name=?",
                (body.action, domain_id, crawler_name)
            )
        else:
            db.execute(
                "INSERT INTO crawler_rules (domain_id, crawler_name, action) VALUES (?,?,?)",
                (domain_id, crawler_name, body.action)
            )

    _invalidate_cache(domain_id)
    audit(auth["sub"], auth["sub"], "crawler_rule.updated", "domain", domain_id,
          {"crawler": crawler_name, "action": body.action})

    return {
        "crawler_name":  crawler_name,
        "action":        body.action,
        "message":       f"Rule updated. Takes effect immediately.",
    }


@router.post("/{domain_id}/bulk")
def bulk_update(
    domain_id: str,
    body: BulkRuleUpdate,
    auth: dict = Depends(require_auth),
):
    """Update multiple crawler rules at once."""
    _assert_owns_domain(domain_id, auth["sub"])

    with get_db() as db:
        for crawler_name, rule in body.rules.items():
            if crawler_name not in CRAWLERS and crawler_name != "__default__":
                continue
            existing = db.execute(
                "SELECT id FROM crawler_rules WHERE domain_id=? AND crawler_name=?",
                (domain_id, crawler_name)
            ).fetchone()
            if existing:
                db.execute(
                    "UPDATE crawler_rules SET action=? WHERE domain_id=? AND crawler_name=?",
                    (rule.action, domain_id, crawler_name)
                )
            else:
                db.execute(
                    "INSERT INTO crawler_rules (domain_id, crawler_name, action) VALUES (?,?,?)",
                    (domain_id, crawler_name, rule.action)
                )

    _invalidate_cache(domain_id)
    audit(auth["sub"], auth["sub"], "crawler_rules.bulk_updated", "domain", domain_id,
          {"count": len(body.rules)})
    return {"message": f"Updated {len(body.rules)} rules"}


@router.delete("/{domain_id}/{crawler_name}")
def reset_rule(
    domain_id: str,
    crawler_name: str,
    auth: dict = Depends(require_auth),
):
    """Reset a crawler rule to the platform default."""
    _assert_owns_domain(domain_id, auth["sub"])

    with get_db() as db:
        db.execute(
            "DELETE FROM crawler_rules WHERE domain_id=? AND crawler_name=?",
            (domain_id, crawler_name)
        )

    _invalidate_cache(domain_id)
    audit(auth["sub"], auth["sub"], "crawler_rule.reset", "domain", domain_id,
          {"crawler": crawler_name})
    return {"message": f"Rule for {crawler_name} reset to default"}


# ─────────────────────────────────────────────────────────────────
# INTERNAL HELPER
# ─────────────────────────────────────────────────────────────────

def _assert_owns_domain(domain_id: str, publisher_id: str):
    with get_db() as db:
        row = db.execute(
            "SELECT id FROM domains WHERE id=? AND publisher_id=?",
            (domain_id, publisher_id)
        ).fetchone()
    if not row:
        raise HTTPException(404, "Domain not found or access denied")
