# 🚪 CrawlBouncer

[![CI](https://github.com/nayan-mis/crawlbouncer/actions/workflows/ci.yml/badge.svg)](https://github.com/nayan-mis/crawlbouncer/actions/workflows/ci.yml)
![License: MIT](https://img.shields.io/badge/license-MIT-green)
![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)

**A bouncer for your website. The guests are robots.**

CrawlBouncer is a free, self-hosted gateway that sits in front of your site and decides, per AI crawler and per path, whether to **allow** it or **block** it. It comes with a dashboard, a web firewall, rate limiting and a `robots.txt` generator.

**Free and open source. No hosted service, no telemetry.** You run it, you own it.

> Status: early, honest software. It is a good bouncer, not a bank vault.
> Read [docs/KNOWN_LIMITATIONS.md](docs/KNOWN_LIMITATIONS.md) before you bet anything on it.

## Why this exists

AI companies crawl the web whether or not you agreed to it. Most tools that help are closed and run on someone else's servers. CrawlBouncer is the one you can read, change and run yourself.

## What you get

| Feature | In one line |
|---|---|
| **Per-crawler rules** | `allow` / `block` for GPTBot, ClaudeBot, PerplexityBot, Bytespider, CCBot and more |
| **Per-path rules** | `/blog/` open, `/premium/` closed, whatever you like |
| **Two ways to deploy** | *Reverse proxy* (point DNS at it) or *bolt-on* (your server asks `POST /v1/decide`) |
| **Web firewall (WAF)** | Blocks SQL injection, XSS, path traversal and similar classics |
| **Traffic defences** | Rate limiting, flood detection, IP reputation, Tor detection, optional ML anomaly check |
| **Dashboard** | Who visited, which bots, what the bouncer did |
| **robots.txt generator** | Always matches your rules |
| **Agent Mirror** *(optional)* | Serve allowed crawlers a clean text version of a page |
| **Accounts** | Two-factor login, team members, audit log |

## Quick start (Docker)

```bash
git clone https://github.com/nayan-mis/crawlbouncer.git
cd crawlbouncer
cp .env.example .env          # then edit it: set JWT_SECRET (openssl rand -hex 32)
docker compose up -d --build
```

Open <http://localhost:8000/signup.html> and create your account. **The first account becomes the admin**; after that signups are closed unless you set `ALLOW_SIGNUPS=true`.

Then in the dashboard: **Domains → Add domain**, choose *reverse proxy* or *bolt-on*, and set your crawler rules under **Crawlers**. The landing page at `/` walks through this in plain language.

### Try it in 2 minutes (no DNS needed)

1. In the dashboard add a domain, choose **Bolt-on**, and copy the edge key it shows (shown once).
2. Pretend to be GPTBot:

```bash
curl -s http://localhost:8000/v1/decide \
  -H "X-Edge-Key: PASTE_YOUR_KEY" -H "Content-Type: application/json" \
  -d '{"path": "/", "user_agent": "Mozilla/5.0 GPTBot/1.0", "ip": "203.0.113.7"}'
```

You get `{"action":"block", ...}` (GPTBot is blocked by default; ChatGPT-User is allowed). Change the rule on the **Crawlers** page and run it again. Every decision shows up on the dashboard.

### Without Docker

Needs Python 3.12 and Node 20.

```bash
cd frontend && npm ci && npm run build && cd ..
cd backend && pip install -r requirements.txt
cp ../.env.example ../.env     # edit it
python run.py
```

### HTTPS

CrawlBouncer does not manage certificates. Put [Caddy](https://caddyserver.com) (automatic HTTPS) or Cloudflare in front. See [`deploy/Caddyfile.example`](deploy/Caddyfile.example).

## Configuration

Everything is an environment variable (or a line in `.env`). The commented [`.env.example`](.env.example) lists them all. The important ones:

| Variable | Meaning |
|---|---|
| `JWT_SECRET` | Signs login sessions. Set it. Required when `ENV=production`. |
| `ENV` | `development` or `production` (production refuses to start with unsafe settings) |
| `ALLOW_SIGNUPS` | `false` by default. First account is always allowed. |
| `SMTP_*` | Optional. Without it, emails are printed to the log and accounts need no verification. |
| `MIRROR_ENABLED` | Turn on Agent Mirror |

## Project layout

```
backend/      FastAPI app (app/), tests (tests/)
frontend/     React dashboard (Vite)
web/          Landing page + login / signup / reset pages
integrations/ Bolt-on snippets for Node and nginx
deploy/       Caddy example
docs/         Architecture, known limitations, GitHub publishing guide
```

## Running the tests

```bash
cd backend  && pip install -r requirements-dev.txt && python -m pytest tests/
cd frontend && npm ci && npm test
node --test integrations/bolt-on/node/cbMiddleware.test.js
```

CI runs all three on every push.

## Contributing

Bug reports, fixes, docs and new crawler signatures are very welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md) and the issues labelled **good first issue**. Please follow the [Code of Conduct](CODE_OF_CONDUCT.md). Security problems: see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE).
