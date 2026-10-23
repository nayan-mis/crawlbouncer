"""
CrawlBouncer — Edge Decision API (bolt-on integration mode)

For people who keep their existing CDN/proxy/app server. Their own server
calls POST /v1/decide for each request and enforces the answer. It reuses the
same bot detection and rules the reverse-proxy mode uses — bolt-on only moves
*who enforces* the decision, not how it is made.

What this deliberately does NOT do: WAF, DDoS detection, IP reputation, rate
limiting. Those stay your CDN's job in this mode. Want them handled here?
Use reverse-proxy mode.
"""
from __future__ import annotations
import hashlib
import time
from fastapi import APIRouter, HTTPException, Header, Depends
from pydantic import BaseModel

from app.database import get_db
from app.middleware.bot_detection import detect
from app.api.rules import get_rule

router = APIRouter(prefix="/v1/decide", tags=["edge"])


class DecideRequest(BaseModel):
    path: str
    user_agent: str
    ip: str = ""


def require_edge_key(x_edge_key: str = Header(default="")) -> dict:
    """Resolve a bolt-on domain from its edge API key. This key identifies a
    specific *domain* and is meant to be used server-to-server only — never
    put it in a browser."""
    if not x_edge_key:
        raise HTTPException(401, "Missing X-Edge-Key header")

    key_hash = hashlib.sha256(x_edge_key.encode()).hexdigest()
    with get_db() as db:
        domain = db.execute(
            "SELECT id, publisher_id, domain, integration_mode, active "
            "FROM domains WHERE edge_api_key_hash = ?",
            (key_hash,)
        ).fetchone()

    if not domain or domain["integration_mode"] != "bolt_on":
        raise HTTPException(401, "Invalid edge key")
    if not domain["active"]:
        raise HTTPException(403, "This domain is not active")

    return dict(domain)


def _log_decision(domain_id: str, body: "DecideRequest", bot, action: str, started: float) -> None:
    """Record the decision so bolt-on domains show up in the dashboard too.
    Never allowed to break the decision itself."""
    try:
        with get_db() as db:
            db.execute(
                "INSERT INTO requests (ip, path, user_agent, is_bot, crawler_name, company, risk, "
                "action, status_code, response_ms, domain_id) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (body.ip or "", body.path, body.user_agent, int(bot.is_bot), bot.crawler_name,
                 bot.company, bot.risk, action, 403 if action == "block" else 200,
                 int((time.perf_counter() - started) * 1000), domain_id),
            )
    except Exception as exc:
        print(f"[WARN] Failed to log bolt-on decision: {exc}")


@router.post("")
def decide(body: DecideRequest, domain: dict = Depends(require_edge_key)):
    """
    Returns one of:
      {"action": "allow", ...}    serve the real content
      {"action": "block", ...}    refuse the request (403)
    """
    started = time.perf_counter()
    domain_id = domain["id"]
    bot = detect(body.user_agent, body.ip)

    if not bot.is_bot:
        _log_decision(domain_id, body, bot, "allow", started)
        return {"action": "allow", "is_bot": False}

    if not bot.crawler_name:
        # A bot we don't specifically recognise. Bolt-on mode isn't a general
        # bot-management layer, so it is left to your own CDN's judgment.
        _log_decision(domain_id, body, bot, "allow", started)
        return {"action": "allow", "is_bot": True, "crawler_name": None}

    action = get_rule(domain_id, bot.crawler_name, body.path)["action"]
    _log_decision(domain_id, body, bot, action, started)
    return {"action": action, "is_bot": True, "crawler_name": bot.crawler_name}
