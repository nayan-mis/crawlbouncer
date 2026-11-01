# 🚪 CrawlBouncer

[![CI](https://github.com/nayan-mis/crawlbouncer/actions/workflows/ci.yml/badge.svg)](https://github.com/nayan-mis/crawlbouncer/actions/workflows/ci.yml)
![License: MIT](https://img.shields.io/badge/license-MIT-green)
![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)

**A bouncer for your website. The guests are robots.**

CrawlBouncer is a free, self-hosted gateway that sits in front of your site and decides, per AI crawler and per path, whether to **allow** it or **block** it. It comes with a dashboard, a web firewall, rate limiting and a `robots.txt` generator.

**Free and open source. No hosted service, no telemetry.** You run it, you own it.

> Status: early, honest software. It is a good bouncer, not a bank vault.
> Read [docs/KNOWN_LIMITATIONS.md](docs/KNOWN_LIMITATIONS.md) before you bet anything on it.

## The night shift

Most websites never had a doorman. Then AI companies started sending crawlers around the web — whether the owner asked them to or not.

If you write or publish anything online, you should get to choose who reads it.

Tools for this already exist, but most are closed and run on someone else's servers. CrawlBouncer is the one you can read, change and run yourself.

## Who gets in

The bouncer keeps a guest list, and it's really two lists in one.

- **Per crawler.** `allow` / `block` for GPTBot, ClaudeBot, PerplexityBot, Bytespider, CCBot and more — each crawler tagged with a risk rating.
- **Per path.** `/blog/` open, `/premium/` closed — whatever you like.

The defaults are opinionated but sane: bulk training scrapers get the door shut by default; bots that fetch a page because a human asked an assistant (and usually send the answer back to that human) get in.

## What the bouncer checks

| Check | What it does |
|---|---|
| **Web firewall** | Blocks SQL injection, XSS, path traversal and similar classics |
| **Challenge** | Lets through visitors who already passed a challenge |
| **IP reputation** | Tor list, plus optional AbuseIPDB |
| **Flood detection** | Slows down / stops traffic floods |
| **Bot detection** | Tells human, generic bot, or named AI crawler apart |
| **Risk ladder** | `allow` / `challenge` / `block` for non-crawler traffic |
| **Rate limiting** | Caps how fast a visitor (or IP) can hit you |
| **Crawler rules** | The final `allow` / `block`, per crawler and per path |
| **Pass through** | Forwards to your origin (SSRF-safe) |

## Two ways in

### Reverse proxy
You point your domain's DNS at CrawlBouncer and it stands at the door. Full pipeline, all checks.

### Bolt-on
You keep your own stack and just ask CrawlBouncer for a decision: `POST /v1/decide` runs the bot detection and crawler rules and returns the call.

## Back office

- **Dashboard** — who visited, which bots, what the bouncer did
- **robots.txt generator** — always matches your rules
- **Agent Mirror** *(optional)* — serve allowed crawlers a clean text version of a page
- **Accounts** — two-factor login, team members, audit log

## Honest limitations

- Crawlers are recognised by User-Agent only; a scraper can lie. Real verification (published IP ranges, reverse DNS, or the HTTP Message Signatures / "Web Bot Auth" standard) isn't implemented yet.
- `Google-Extended` and `Applebot-Extended` are robots.txt tokens, not User-Agents — they can only be controlled through the generated `robots.txt`.
- Unknown bots (curl, headless browsers, scripts) fall to the generic risk/rate-limit ladder, not per-crawler rules.
- Bolt-on mode only classifies named AI crawlers; WAF, rate limiting and flood protection aren't applied there by design (your CDN does that).
- SQLite, one process — fine for one server; run one worker.

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

Needs Python 3.12 and Node 22.

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
