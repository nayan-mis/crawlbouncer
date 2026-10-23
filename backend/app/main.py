"""
CrawlBouncer — Main Application
Wires every component into a single FastAPI app.
Request pipeline order (kept in sync with the numbered "── N. ──" comments
in the middleware function below):
  1. WAF (block attacks)
  2. Challenge cookie check
  3. IP reputation
  4. DDoS detection
  5. Bot detection (classify traffic)
  6. Unified risk ladder (non-crawler traffic only)
  7. Rate limiter (block floods)
  8. AI-crawler rules: allow / block
  9. Pass through to origin
  Logging happens throughout via _log_request.
"""
from __future__ import annotations
import time
import json
import os
import secrets
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from app.config import cfg
from app.database import init_db, get_db

# ── Middleware ────────────────────────────────────────────────────
from app.middleware.bot_detection  import detect, fingerprint
from app.middleware.rate_limiter   import check_rate_limit
from app.middleware.waf            import waf
from app.services.origin_proxy     import proxy_to_origin
from app.services.agent_mirror     import get_serve_mode, get_or_build_mirror, render_agent_page

# ── API Routers ───────────────────────────────────────────────────
from app.api.auth    import router as auth_router
from app.api.stats   import router as stats_router, log_router as requests_log_router
from app.api.domains import router as domains_router
from app.api.rules   import router as rules_router
from app.api.audit import router as audit_router
from app.api.mirror import router as mirror_router
from app.api.admin import router as admin_router
from app.api.team import router as team_router
from app.api.edge import router as edge_router

from app.middleware.challenge    import register_challenge_routes, verify_cookie, CHALLENGE_COOKIE
from app.middleware.challenge    import pow_challenge_page, hcaptcha_challenge_page, blocked_page

# ── Security workers ──────────────────────────────────────────────
from app.middleware.ip_reputation import check as check_ip_reputation
from app.middleware.risk_engine   import record_and_score
from app.workers.ddos_detector    import detector as ddos_detector


# ─────────────────────────────────────────────────────────────────
# STARTUP / SHUTDOWN
# ─────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Runs once on startup, once on shutdown."""
    print("━" * 50)
    print("  CrawlBouncer starting up")
    print(f"  ENV:  {cfg.ENV}")
    print(f"  PORT: {cfg.PORT}")
    print("━" * 50)

    # Refuse to boot in production with an insecure config — a weak or
    # default JWT_SECRET means anyone who reads this source file can
    # forge a valid token for any account. No-op outside production.
    problems = cfg.validate_production_config()
    if problems:
        print("  ✗ Refusing to start — insecure production config:")
        for p in problems:
            print(f"    - {p}")
        raise RuntimeError(
            "Insecure production configuration: " + "; ".join(problems)
        )

    init_db()
    print("  ✓ Database ready")

    # Start background scheduler (Tor list, anomaly check, retention)
    from app.workers.scheduler import start_scheduler
    from app.workers.tor_updater import start_tor_updater
    from app.workers.anomaly_detector import start_periodic_check as start_anomaly_check
    from app.workers.retention_job import start_retention_job
    scheduler = start_scheduler()
    if scheduler:
        start_tor_updater(scheduler)
        start_anomaly_check(scheduler)       # per-minute ML anomaly check
        start_retention_job(scheduler)       # daily requests/waf_events pruning

    print("  ✓ All routes registered")
    print("  ✓ Middleware pipeline active")
    print("  ✓ Background workers running")
    print("━" * 50)
    yield
    print("\n  CrawlBouncer shutting down")


# ─────────────────────────────────────────────────────────────────
# APP
# ─────────────────────────────────────────────────────────────────

app = FastAPI(
    title="CrawlBouncer",
    version="0.1.0",
    description="Self-hosted gatekeeper for AI crawlers: allow or block them, per site and per path.",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    lifespan=lifespan,
)

# CORS — allow the dashboard frontend to call the API.
# allow_credentials=True is required for the cookie-based session
# (docs/AUDIT.md 3.3) to work at all across a cross-origin request —
# and per the CORS spec, wildcard origins are incompatible with
# allow_credentials (browsers reject the combination outright), so dev
# needs an explicit origin list too, not "*".
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:8000"] if cfg.is_development
                  else [o.strip() for o in cfg.CORS_ORIGINS.split(",") if o.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    """
    Defense-in-depth: these headers already exist in the nginx config
    templates generated for customer domains (
    domains.py) — but that only protects requests that go through
    nginx correctly configured. This applies them to every response
    from the app itself (the API, the dashboard, the landing page),
    so a misconfigured or bypassed proxy in front of CrawlBouncer's own
    surfaces doesn't leave them with zero header protection.
    """
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    if cfg.is_production:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


# ─────────────────────────────────────────────────────────────────
# PATHS THAT BYPASS THE SECURITY PIPELINE
# ─────────────────────────────────────────────────────────────────

BYPASS_PATHS = {
    "/",
    "/health",
    "/api/docs",
    "/api/redoc",
    "/openapi.json",
}

def _is_internal(path: str, host: str) -> bool:
    platform_hosts = {item.strip().lower() for item in cfg.PLATFORM_HOSTS.split(",")}
    platform_request = host.split(":", 1)[0].lower() in platform_hosts
    return (
        path in BYPASS_PATHS - {"/"}
        or path.startswith("/api/")
        or path.startswith("/v1/")
        or path.startswith("/static/")
        or (platform_request and (
            path == "/" or path.endswith(".html") or path in {"/site.css"}
            or path == "/dashboard" or path.startswith("/dashboard/")
        ))
    )


# ─────────────────────────────────────────────────────────────────
# SECURITY PIPELINE MIDDLEWARE
# Runs on every request that is NOT an internal API call.
# ─────────────────────────────────────────────────────────────────

@app.middleware("http")
async def security_pipeline(request: Request, call_next):
    t0   = time.perf_counter()
    path = request.url.path
    host = request.headers.get("host", "")

    # ── Internal paths bypass the pipeline ───────────────────────
    if _is_internal(path, host):
        return await call_next(request)

    # Collect request context
    ip         = _get_ip(request)
    ua         = request.headers.get("User-Agent", "")
    qs         = str(request.url.query)
    fp         = fingerprint(ua, request.headers.get("Accept-Encoding", ""))

    # Domain identity resolved directly from Host against owned domains —
    # NOT from a client-supplied header. The previous version required
    # nginx to compute and inject X-Domain-ID after its own lookup, but
    # nginx has no practical way to do dynamic, per-request database
    # lookups against domains publishers add themselves (a static nginx
    # map would need a config regen + reload on every new domain, which
    # doesn't fit a self-service product). Host is already correctly
    # forwarded by nginx with no changes needed, and is what's actually
    # tied to how the request was routed in the first place.
    host = request.headers.get("host", "").split(":")[0].strip().lower()
    with get_db() as db:
        domain = db.execute(
            "SELECT id, origin_url, active FROM domains WHERE domain=?", (host,)
        ).fetchone() if host else None
    if not domain or not domain["active"]:
        return JSONResponse(status_code=421, content={"error": "Unknown or inactive protected domain"})
    domain_id = domain["id"]

    # ── 1. WAF ────────────────────────────────────────────────────
    waf_result = waf.check(path=path, query_string=qs)
    if waf_result.blocked:
        _log_waf_event(ip, path, waf_result, domain_id)
        return JSONResponse(
            status_code=403,
            content={
                "error":      "Request blocked",
                "request_id": fp,
                "message":    "Your request was identified as potentially malicious.",
            }
        )

    # ── 2. Challenge cookie check ──────────────────────────────
    challenge_cookie = request.cookies.get(CHALLENGE_COOKIE, "")
    has_pass = verify_cookie(challenge_cookie, ip)

    # ── 3. IP reputation ─────────────────────────────────────────
    ip_rep = check_ip_reputation(ip)

    # ── 4. DDoS detection ────────────────────────────────────────
    ddos_detector.record(ip, path)
    if ddos_detector.is_blocked(ip):
        return JSONResponse(status_code=429, content={"error": "Blocked — DDoS mitigation active"})

    # ── 5. Bot detection ──────────────────────────────────────────
    bot = detect(ua, ip)

    # ── 6. Unified risk ladder (non-crawler traffic only — named
    # crawlers are handled by step 8's allow/block rules) ──
    if not (bot.is_bot and bot.crawler_name):
        assessment = record_and_score(ip, bot.confidence, ip_rep.risk_score)

        if assessment.tier == "block" and not has_pass:
            _log_request(ip, path, ua, bot, "block", 403, fp, domain_id,
                         int((time.perf_counter() - t0) * 1000))
            return HTMLResponse(blocked_page("Access denied"), status_code=403)

        if assessment.tier == "hard_challenge" and not has_pass:
            _log_request(ip, path, ua, bot, "challenge", 403, fp, domain_id,
                         int((time.perf_counter() - t0) * 1000))
            return HTMLResponse(hcaptcha_challenge_page(path), status_code=403)

        if assessment.tier == "soft_challenge" and not has_pass:
            nonce = secrets.token_hex(16)
            _log_request(ip, path, ua, bot, "challenge", 403, fp, domain_id,
                         int((time.perf_counter() - t0) * 1000))
            return HTMLResponse(pow_challenge_page(nonce, path), status_code=403)

        # "monitor" and "allow" tiers, and anyone who already has_pass,
        # continue through the pipeline normally — the ladder's job is
        # to add friction proportional to risk, not to block by default.

    # ── 7. Rate limiting ──────────────────────────────────────────
    rate = check_rate_limit(ip, is_bot=bot.is_bot)
    if not rate.allowed:
        _log_request(ip, path, ua, bot, "block", 429, fp, domain_id,
                     int((time.perf_counter() - t0) * 1000))
        return JSONResponse(
            status_code=429,
            headers={"Retry-After": str(rate.retry_after or 60)},
            content={
                "error":       "Too Many Requests",
                "limit":       rate.limit,
                "retry_after": rate.retry_after,
            }
        )

    # ── 8. AI-crawler rules (named AI crawlers only) ─────────────
    action = "allow"
    if bot.is_bot and bot.crawler_name:
        from app.api.rules import get_rule
        action = get_rule(domain_id, bot.crawler_name, path)["action"]

        if action == "block":
            _log_request(ip, path, ua, bot, "block", 403, fp, domain_id,
                         int((time.perf_counter() - t0) * 1000))
            return JSONResponse(status_code=403, content={
                "error":   "Access denied",
                "message": "Your crawler does not have permission to access this content.",
            })

        # Optional Agent Mirror: serve a clean text rendition instead of the
        # full page. Off by default (MIRROR_ENABLED=true to turn on).
        if cfg.MIRROR_ENABLED and get_serve_mode(domain_id, path) == "agent":
            mirror = await get_or_build_mirror(
                domain_id, path, domain["origin_url"], request.url.query
            )
            page = render_agent_page(
                mirror["title"], mirror["content_html"],
                source_url=f"https://{host}{path}"
            )
            _log_request(ip, path, ua, bot, "allow", 200, fp, domain_id,
                         int((time.perf_counter() - t0) * 1000))
            return HTMLResponse(content=page, status_code=200)

    # ── 9. Pass through to origin ─────────────────────────────────
    response    = await proxy_to_origin(request, domain["origin_url"])
    duration_ms = int((time.perf_counter() - t0) * 1000)

    _log_request(ip, path, ua, bot, action, response.status_code, fp, domain_id, duration_ms)

    return response


# ─────────────────────────────────────────────────────────────────
# ROUTERS
# ─────────────────────────────────────────────────────────────────

app.include_router(auth_router)
app.include_router(stats_router)
app.include_router(requests_log_router)
app.include_router(domains_router)
app.include_router(rules_router)
app.include_router(audit_router)
app.include_router(mirror_router)
app.include_router(admin_router)
app.include_router(team_router)
app.include_router(edge_router)


# ─────────────────────────────────────────────────────────────────
# CORE ROUTES
# ─────────────────────────────────────────────────────────────────

# Static site files can live alongside run.py (the Docker layout — see
# Dockerfile's COPY steps) or one directory up (running `python run.py`
# straight from the backend/ source tree in local dev). Check both so
# neither path silently 404s depending on how the app was launched.
_HERE = os.path.dirname(os.path.abspath(__file__))          # .../backend/app
_BACKEND_DIR = os.path.dirname(_HERE)                        # .../backend  (Docker's /app layout)
_PROJECT_ROOT = os.path.dirname(_BACKEND_DIR)                 # .../crawlbouncer (local dev layout)
_STATIC_ROOTS = [_BACKEND_DIR, _PROJECT_ROOT]


def _find_static_file(relative_path: str):
    """Return the first existing full path for relative_path across known static roots, or None."""
    for root in _STATIC_ROOTS:
        candidate = os.path.join(root, relative_path)
        if os.path.exists(candidate):
            return candidate
    return None


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def landing_home():
    """Serve the landing page."""
    path = _find_static_file(os.path.join("web", "index.html"))
    if not path:
        return HTMLResponse("<h1>CrawlBouncer</h1><p>web/index.html not found</p>", status_code=500)
    with open(path, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


@app.get("/{page_name}.html", response_class=HTMLResponse, include_in_schema=False)
async def static_page(page_name: str):
    """Serve the small static pages (login, signup, ...) by name.
    dashboard.html is a legacy bookmark — the product now lives at
    /dashboard (the built React app), so redirect rather than serve
    a stale copy that would drift from the real thing."""
    if page_name == "dashboard":
        return RedirectResponse(url="/dashboard", status_code=301)
    for relative in [os.path.join("web", f"{page_name}.html")]:
        path = _find_static_file(relative)
        if path:
            with open(path, "r", encoding="utf-8") as f:
                return HTMLResponse(content=f.read())
    return HTMLResponse("<h1>404</h1><p>Page not found.</p>", status_code=404)


# ── Product (React dashboard) ──────────────────────────────────────
# Built by `cd frontend && npm run build`, output at frontend/dist/.
# Vite's base is set to /dashboard/ so the built asset paths match
# what's mounted below. React Router owns every path under /dashboard
# client-side (BrowserRouter basename="/dashboard"), so any deep link —
# /dashboard/settings, a page refresh, a bookmark — must still resolve
# to the same index.html and let the client-side router take it from
# there; only the catch-all route below makes that work.
_FRONTEND_DIST = _find_static_file(os.path.join("frontend", "dist"))
if _FRONTEND_DIST:
    app.mount("/dashboard/assets", StaticFiles(directory=os.path.join(_FRONTEND_DIST, "assets")), name="dashboard-assets")

    @app.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
    @app.get("/dashboard/{_rest:path}", response_class=HTMLResponse, include_in_schema=False)
    async def dashboard_app(_rest: str = ""):
        index_path = os.path.join(_FRONTEND_DIST, "index.html")
        with open(index_path, "r") as f:
            return HTMLResponse(content=f.read())
else:
    @app.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
    async def dashboard_not_built():
        return HTMLResponse(
            "<h1>Dashboard not built</h1><p>Run <code>cd frontend && npm install && npm run build</code>.</p>",
            status_code=500,
        )


@app.get("/site.css", include_in_schema=False)
async def site_css():
    """Serve the shared stylesheet."""
    path = _find_static_file(os.path.join("web", "site.css"))
    if not path:
        return Response(content="", media_type="text/css", status_code=404)
    with open(path, "r", encoding="utf-8") as f:
        return Response(content=f.read(), media_type="text/css")


@app.get("/health")
async def health():
    """Health check endpoint — used by load balancers and Docker."""
    try:
        with get_db() as db:
            db.execute("SELECT 1")
        db_ok = True
    except Exception:
        db_ok = False

    status = "ok" if db_ok else "degraded"
    return JSONResponse(
        status_code=200 if db_ok else 503,
        content={
            "status":   status,
            "version":  "0.1.0",
            "database": "ok" if db_ok else "error",
        }
    )


@app.get("/robots/{domain_id}", response_class=PlainTextResponse, include_in_schema=False)
async def robots_proxy(domain_id: str):
    """Internal: serve robots.txt for a domain (called by nginx)."""
    from app.api.domains import robots_txt
    return await robots_txt(domain_id)


# ─────────────────────────────────────────────────────────────────
# PRIVATE HELPERS
# ─────────────────────────────────────────────────────────────────

def _null_bot():
    """Return an empty DetectionResult for cases where bot detection did not run."""
    from app.middleware.bot_detection import DetectionResult
    return DetectionResult(is_bot=False, crawler_name=None, company=None,
                           risk=None, default_action="allow", confidence=0.0, signals=[])


def _get_ip(request: Request) -> str:
    from app.services.client_ip import get_client_ip
    return get_client_ip(request)


def _log_request(ip, path, ua, bot, action, status, fp, domain_id, duration_ms):
    """Write one request to the database (failures are logged, never raised)."""
    try:
        with get_db() as db:
            db.execute("""
                INSERT INTO requests
                  (ip, path, user_agent, is_bot, crawler_name, company, risk,
                   action, status_code, response_ms, fingerprint, domain_id)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                ip, path, ua,
                int(bot.is_bot),
                bot.crawler_name,
                bot.company,
                bot.risk,
                action, status, duration_ms, fp, domain_id,
            ))
    except Exception as e:
        print(f"[WARN] Failed to log request: {e}")


def _log_waf_event(ip, path, waf_result, domain_id):
    """Record a WAF block event."""
    try:
        with get_db() as db:
            db.execute("""
                INSERT INTO waf_events (domain_id, ip, path, rule_name, severity, payload)
                VALUES (?,?,?,?,?,?)
            """, (
                domain_id, ip, path,
                waf_result.rule.name if waf_result.rule else "unknown",
                waf_result.rule.severity if waf_result.rule else "unknown",
                waf_result.matched_value,
            ))
    except Exception as e:
        print(f"[WARN] Failed to log WAF event: {e}")


# ─────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=cfg.HOST,
        port=cfg.PORT,
        reload=cfg.is_development,
        log_level="info",
    )
