"""
CrawlBouncer — Analytics API
All data endpoints powering the dashboard.
"""
from __future__ import annotations
from fastapi import APIRouter, Query, Depends
from app.database import get_db
from app.api.auth import require_auth

router = APIRouter(prefix="/api/stats", tags=["analytics"])


def _owned_domain_filter(publisher_id: str) -> tuple[str, tuple[str]]:
    """Return a reusable SQL ownership predicate for request-backed analytics."""
    return "domain_id IN (SELECT id FROM domains WHERE publisher_id=?)", (publisher_id,)


@router.get("/overview")
def overview(auth: dict = Depends(require_auth)):
    """Monthly summary: requests, bots, blocked, allowed AI crawlers."""
    from datetime import datetime
    month = datetime.now().strftime("%Y-%m")

    predicate, owner = _owned_domain_filter(auth["sub"])
    with get_db() as db:
        total   = db.execute(f"SELECT COUNT(*) FROM requests WHERE {predicate} AND timestamp LIKE ?", owner + (f"{month}%",)).fetchone()[0]
        bots    = db.execute(f"SELECT COUNT(*) FROM requests WHERE {predicate} AND is_bot=1 AND timestamp LIKE ?", owner + (f"{month}%",)).fetchone()[0]
        blocked = db.execute(f"SELECT COUNT(*) FROM requests WHERE {predicate} AND action='block' AND timestamp LIKE ?", owner + (f"{month}%",)).fetchone()[0]
        crawlers_allowed = db.execute(f"SELECT COUNT(*) FROM requests WHERE {predicate} AND crawler_name IS NOT NULL AND action='allow' AND timestamp LIKE ?", owner + (f"{month}%",)).fetchone()[0]

    return {
        "total_requests":       total,
        "bot_requests":         bots,
        "human_requests":       total - bots,
        "bot_percentage":       round((bots / total * 100) if total else 0, 1),
        "blocked":              blocked,
        "crawlers_allowed":     crawlers_allowed,
        "period":               month,
    }


@router.get("/traffic")
def traffic(days: int = Query(30, ge=7, le=90), auth: dict = Depends(require_auth)):
    """Daily traffic breakdown for chart: humans, bots, blocked."""
    with get_db() as db:
        rows = db.execute("""
            SELECT
                DATE(timestamp)                                                   AS date,
                SUM(CASE WHEN is_bot=0              THEN 1 ELSE 0 END)            AS humans,
                SUM(CASE WHEN is_bot=1 AND action!='block' THEN 1 ELSE 0 END)    AS bots,
                SUM(CASE WHEN action='block'        THEN 1 ELSE 0 END)            AS blocked
            FROM requests
            WHERE domain_id IN (SELECT id FROM domains WHERE publisher_id=?)
              AND DATE(timestamp) >= DATE('now', ?)
            GROUP BY DATE(timestamp)
            ORDER BY date ASC
        """, (auth["sub"], f"-{days} days",)).fetchall()
    return [dict(r) for r in rows]


@router.get("/crawlers")
def crawlers(auth: dict = Depends(require_auth)):
    """Per-crawler breakdown: requests, action, risk, last seen."""
    with get_db() as db:
        rows = db.execute("""
            SELECT
                crawler_name                              AS name,
                company,
                risk,
                action,
                COUNT(*)                                  AS requests,
                MAX(timestamp)                            AS last_seen
            FROM requests
            WHERE domain_id IN (SELECT id FROM domains WHERE publisher_id=?)
              AND is_bot=1 AND crawler_name IS NOT NULL
            GROUP BY crawler_name
            ORDER BY requests DESC
        """, (auth["sub"],)).fetchall()
    return [dict(r) for r in rows]


@router.get("/top-pages")
def top_pages(limit: int = Query(10, le=50), auth: dict = Depends(require_auth)):
    """Most-scraped pages with visit counts."""
    with get_db() as db:
        rows = db.execute("""
            SELECT
                path,
                COUNT(*)                                  AS total_visits,
                SUM(CASE WHEN is_bot=1 THEN 1 ELSE 0 END) AS bot_visits
            FROM requests
            WHERE domain_id IN (SELECT id FROM domains WHERE publisher_id=?)
              AND path IS NOT NULL
            GROUP BY path
            ORDER BY bot_visits DESC
            LIMIT ?
        """, (auth["sub"], limit)).fetchall()
    return [dict(r) for r in rows]


@router.get("/waf")
def waf_stats(auth: dict = Depends(require_auth)):
    """WAF event summary for the publisher's domains only."""
    with get_db() as db:
        rows = db.execute("""
            SELECT rule_name, severity, COUNT(*) AS count, MAX(timestamp) AS last_seen
            FROM waf_events
            WHERE domain_id IN (SELECT id FROM domains WHERE publisher_id=?)
            GROUP BY rule_name
            ORDER BY count DESC
        """, (auth["sub"],)).fetchall()
        total = db.execute(
            "SELECT COUNT(*) FROM waf_events WHERE domain_id IN (SELECT id FROM domains WHERE publisher_id=?)",
            (auth["sub"],),
        ).fetchone()[0]
    return {"total_blocked": total, "by_rule": [dict(r) for r in rows]}


# ─────────────────────────────────────────────────────────────────
# RAW REQUEST LOG — separate prefix, mounted alongside stats router
# ─────────────────────────────────────────────────────────────────

log_router = APIRouter(prefix="/api/requests", tags=["analytics"])


@log_router.get("/log")
def request_log(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    auth: dict = Depends(require_auth),
):
    """Paginated raw request log powering the dashboard's live traffic view."""
    offset = (page - 1) * limit

    with get_db() as db:
        total = db.execute(
            "SELECT COUNT(*) FROM requests WHERE domain_id IN (SELECT id FROM domains WHERE publisher_id=?)",
            (auth["sub"],),
        ).fetchone()[0]
        rows = db.execute("""
            SELECT id, timestamp, domain_id, ip, path, method, user_agent,
                   is_bot, crawler_name, company, risk, action,
                   response_ms, status_code, country_code
            FROM requests
            WHERE domain_id IN (SELECT id FROM domains WHERE publisher_id=?)
            ORDER BY timestamp DESC
            LIMIT ? OFFSET ?
        """, (auth["sub"], limit, offset)).fetchall()

    return {
        "requests": [dict(r) for r in rows],
        "total":    total,
        "page":     page,
        "limit":    limit,
    }
