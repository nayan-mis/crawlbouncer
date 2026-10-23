# Architecture

One FastAPI process, one SQLite file, one React dashboard.

## Request pipeline (reverse-proxy mode)

Every request to a protected domain goes through `backend/app/main.py`:

1. **WAF**: block known attack patterns (`middleware/waf.py`)
2. **Challenge cookie**: let through visitors who already passed a challenge
3. **IP reputation** (`ip_reputation.py`): Tor list and optional AbuseIPDB
4. **Flood detection** (`workers/ddos_detector.py`)
5. **Bot detection** (`bot_detection.py`): human, generic bot, or a named AI crawler (User-Agent match)
6. **Risk ladder** (`risk_engine.py`) for non-crawler traffic: allow, challenge or block
7. **Rate limiter** (`rate_limiter.py`)
8. **Crawler rules** (`api/rules.py`): `allow` or `block`
9. **Pass through** to your origin (`origin_proxy.py`, SSRF-safe)

Each request is logged to the `requests` table for the dashboard.

## Bolt-on mode

`POST /v1/decide` (`api/edge.py`) runs only steps 5 and 8 and returns the decision as JSON so your own
server can enforce it.

## Folders

```
backend/app/
  main.py            pipeline + routes for the dashboard and static pages
  config.py          environment variables
  database.py        SQLite schema
  api/               HTTP API (auth, domains, rules, stats, team, admin, mirror, edge, WAF, requests)
  middleware/        WAF, bot detection, challenge, rate limiter, IP reputation, DDoS, risk
  services/          mailer (SMTP), origin proxy, SSRF-safe fetch, agent mirror, audit log
  security/          JWT sessions, MFA
  workers/           background jobs (scheduler, Tor list, anomaly check, retention, alerts)
frontend/            React dashboard (served at /dashboard)
web/                 landing page + login/signup/reset/verify/accept pages
```

## Adding a crawler

Add an entry to `CRAWLERS` in `backend/app/middleware/bot_detection.py` with a lowercase regex that matches its
User-Agent and a safe `default_action`. Add a test in `backend/tests/test_bot_detection.py`.
