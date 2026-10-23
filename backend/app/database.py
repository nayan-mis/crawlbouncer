"""
CrawlBouncer — Database
SQLite in WAL mode: plenty for a single-instance deployment. DATABASE_URL is
NOT read here; the file location comes from SQLITE_PATH. Moving to Postgres
would mean porting this file (see docs/KNOWN_LIMITATIONS.md).
"""
import os
import sqlite3
from contextlib import contextmanager
from typing import Generator

# Configurable so the file survives container restarts: point this at a
# mounted volume in production (the Docker setup sets it to /app/data/crawlbouncer.db).
DB_PATH = os.getenv("SQLITE_PATH", "crawlbouncer.db")
_db_dir = os.path.dirname(DB_PATH)
if _db_dir:
    os.makedirs(_db_dir, exist_ok=True)


# ─────────────────────────────────────────────────────────────────
# CONNECTION
# ─────────────────────────────────────────────────────────────────

@contextmanager
def get_db() -> Generator[sqlite3.Connection, None, None]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    # journal_mode=WAL is set once in init_db(), not here — it's a
    # database-level setting persisted in the file itself, not a
    # per-connection one. Re-querying it on every single request (as
    # this used to do) was a harmless no-op each time, but still a
    # wasted round-trip on every request. foreign_keys, unlike WAL, IS
    # a per-connection setting in SQLite and genuinely needs to be set
    # here every time.
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────────
# SCHEMA
# ─────────────────────────────────────────────────────────────────

SCHEMA = """
-- Accounts that can log in to the dashboard
CREATE TABLE IF NOT EXISTS publishers (
    id           TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
    email        TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    name         TEXT,
    auth_version INTEGER DEFAULT 0,
    is_admin     INTEGER DEFAULT 0,
    suspended    INTEGER DEFAULT 0,
    deleted_at   TEXT,
    email_verified          INTEGER DEFAULT 0,
    verify_token_hash       TEXT,
    verify_token_expires_at TEXT,
    mfa_secret TEXT,
    mfa_pending_secret TEXT,
    mfa_enabled INTEGER DEFAULT 0,
    mfa_last_step INTEGER,                -- last TOTP step used (replay protection)
    created_at   TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at   TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Domains protected by this gateway
CREATE TABLE IF NOT EXISTS domains (
    id           TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(8)))),
    publisher_id TEXT REFERENCES publishers(id),
    domain       TEXT UNIQUE NOT NULL,
    origin_url   TEXT,
    cname_target TEXT,
    dns_verified INTEGER DEFAULT 0,
    ssl_active   INTEGER DEFAULT 0,
    active       INTEGER DEFAULT 1,
    created_at   TEXT DEFAULT CURRENT_TIMESTAMP,
    -- 'reverse_proxy' (default, existing): CNAME points at CrawlBouncer, CrawlBouncer
    -- sees and gates every request itself — non-bypassable, but
    -- requires switching DNS away from whatever CDN the publisher
    -- already trusts (Cloudflare, etc.).
    -- 'bolt_on' (new): no DNS change. The publisher's own server/CDN
    -- calls POST /v1/decide per-request and enforces the decision
    -- itself. Easier to adopt, but enforcement depends on the
    -- publisher's own integration actually calling and honoring it —
    -- there's no structural guarantee the way reverse_proxy has one.
    -- Both modes reuse the same bot detection and rules;
    -- they only differ in who's actually gating the traffic.
    integration_mode  TEXT DEFAULT 'reverse_proxy',
    edge_api_key_hash TEXT
);

-- Per-crawler rules set by publishers
CREATE TABLE IF NOT EXISTS crawler_rules (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_id      TEXT REFERENCES domains(id),
    crawler_name   TEXT NOT NULL,
    action         TEXT NOT NULL DEFAULT 'allow',   -- allow | block
    updated_at     TEXT DEFAULT CURRENT_TIMESTAMP
);

-- Per-path rules: override the crawler-based rule above for requests
-- under a given path prefix, regardless of which crawler is asking —
-- e.g. always block /premium/, always allow /blog/.
-- Longest matching prefix wins. No matching row = crawler_rules applies
-- exactly as before this feature (fully backward compatible).
CREATE TABLE IF NOT EXISTS path_rules (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_id      TEXT REFERENCES domains(id),
    path_prefix    TEXT NOT NULL,
    action         TEXT NOT NULL DEFAULT 'allow',   -- allow | block
    updated_at     TEXT DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(domain_id, path_prefix)
);

-- Every solved/failed challenge (PoW or captcha) is a labeled bot/human
-- example. Recording it here lets the anomaly detector's feature set
-- include a real signal (challenge_fail_rate) instead of only inferring
-- "bot" from User-Agent pattern matching.
CREATE TABLE IF NOT EXISTS challenge_events (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp      TEXT DEFAULT CURRENT_TIMESTAMP,
    ip             TEXT NOT NULL,
    challenge_type TEXT NOT NULL,   -- 'pow' | 'captcha'
    passed         INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_challenge_events_timestamp ON challenge_events(timestamp);

-- Team seats: additional logins that can act on an owner's account.
-- The owner is always the publishers row itself — this table is only
-- for people the owner invites. A member's JWT still carries `sub` =
-- the owner's publisher_id (so every existing ownership check keeps
-- working unchanged), with `role`/`actor_id` in the token identifying
-- the actual person for audit attribution and for gating owner-only
-- actions (invites, account deletion).
CREATE TABLE IF NOT EXISTS team_members (
    id                TEXT PRIMARY KEY,
    publisher_id      TEXT REFERENCES publishers(id),   -- the account/owner they belong to
    email             TEXT NOT NULL UNIQUE,
    password_hash     TEXT,                              -- NULL until invite is accepted
    status            TEXT NOT NULL DEFAULT 'pending',    -- 'pending' | 'active'
    invite_token_hash TEXT,
    invite_expires_at TEXT,
    auth_version      INTEGER DEFAULT 0,
    invited_at        TEXT DEFAULT CURRENT_TIMESTAMP,
    accepted_at       TEXT
);

-- Agent Mirror: per-page/article override of what an allowed crawler
-- receives. No row = default ('agent' — CrawlBouncer's extracted rendition).
-- A row here only exists when a publisher has opted a specific path
-- into 'html' (proxied straight to the real origin page instead).
CREATE TABLE IF NOT EXISTS mirror_settings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_id   TEXT REFERENCES domains(id),
    path        TEXT NOT NULL,
    serve_mode  TEXT NOT NULL DEFAULT 'agent',
    updated_at  TEXT DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(domain_id, path)
);

-- Cached extracted "agent page" renditions, so every agent-mode
-- request doesn't re-fetch and re-extract the origin page.
CREATE TABLE IF NOT EXISTS mirror_cache (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_id     TEXT REFERENCES domains(id),
    path          TEXT NOT NULL,
    title         TEXT,
    content_html  TEXT,
    fetched_at    TEXT DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(domain_id, path)
);

-- Every request that passed through CrawlBouncer
CREATE TABLE IF NOT EXISTS requests (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    TEXT DEFAULT CURRENT_TIMESTAMP,
    domain_id    TEXT REFERENCES domains(id),
    ip           TEXT NOT NULL,
    path         TEXT,
    method       TEXT DEFAULT 'GET',
    user_agent   TEXT,
    is_bot       INTEGER DEFAULT 0,
    crawler_name TEXT,
    company      TEXT,
    risk         TEXT,
    action       TEXT DEFAULT 'allow',
    response_ms  INTEGER DEFAULT 0,
    status_code  INTEGER DEFAULT 200,
    fingerprint  TEXT,
    country_code TEXT
);

CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL,
    revoked_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    token_hash TEXT PRIMARY KEY,
    publisher_id TEXT NOT NULL REFERENCES publishers(id),
    expires_at INTEGER NOT NULL,
    used_at TEXT
);
CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    publisher_id TEXT NOT NULL REFERENCES publishers(id),
    actor_id TEXT REFERENCES publishers(id),
    action TEXT NOT NULL,
    resource_type TEXT,
    resource_id TEXT,
    details TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_audit_events_publisher ON audit_events(publisher_id, created_at);
CREATE INDEX IF NOT EXISTS idx_revoked_tokens_expiry ON revoked_tokens(expires_at);

-- WAF blocked requests
CREATE TABLE IF NOT EXISTS waf_events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    TEXT DEFAULT CURRENT_TIMESTAMP,
    domain_id    TEXT REFERENCES domains(id),
    ip           TEXT,
    path         TEXT,
    rule_name    TEXT,
    severity     TEXT,
    payload      TEXT
);

-- Security alerts
CREATE TABLE IF NOT EXISTS alerts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    TEXT DEFAULT CURRENT_TIMESTAMP,
    type         TEXT NOT NULL,
    severity     TEXT NOT NULL,
    message      TEXT NOT NULL,
    details      TEXT,
    resolved     INTEGER DEFAULT 0
);

-- IP reputation history — persisted (unlike the in-memory caches in
-- ip_reputation.py, this survives restarts) and inherently cross-tenant:
-- every domain/publisher served by this instance shares one table, so an
-- IP flagged as bad on one publisher's site is already known on every
-- other publisher's site the moment it's written. bad_hits decays over
-- time via last_seen rather than staying permanent — see risk_engine.py.
CREATE TABLE IF NOT EXISTS ip_reputation_history (
    ip           TEXT PRIMARY KEY,
    first_seen   TEXT DEFAULT CURRENT_TIMESTAMP,
    last_seen    TEXT DEFAULT CURRENT_TIMESTAMP,
    times_seen   INTEGER DEFAULT 0,
    bad_hits     INTEGER DEFAULT 0,
    last_score   INTEGER DEFAULT 0
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_requests_timestamp    ON requests(timestamp);
CREATE INDEX IF NOT EXISTS idx_requests_is_bot       ON requests(is_bot);
CREATE INDEX IF NOT EXISTS idx_requests_domain_id    ON requests(domain_id);
CREATE INDEX IF NOT EXISTS idx_requests_crawler_name ON requests(crawler_name);
CREATE INDEX IF NOT EXISTS idx_waf_events_timestamp  ON waf_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_waf_events_domain_id   ON waf_events(domain_id);
CREATE INDEX IF NOT EXISTS idx_iprep_last_seen        ON ip_reputation_history(last_seen);
"""


def init_db():
    """Create all tables ."""
    # Set WAL mode once, here, at startup — see get_db()'s comment for why.
    with sqlite3.connect(DB_PATH) as _conn:
        _conn.execute("PRAGMA journal_mode=WAL")
    with get_db() as db:
        db.executescript(SCHEMA)
        # Lightweight compatibility migration for databases created before WAF
        # events were tenant-scoped. New events must always carry domain_id.
        columns = {row["name"] for row in db.execute("PRAGMA table_info(waf_events)").fetchall()}
        if "domain_id" not in columns:
            db.execute("ALTER TABLE waf_events ADD COLUMN domain_id TEXT REFERENCES domains(id)")
        publisher_columns = {row["name"] for row in db.execute("PRAGMA table_info(publishers)").fetchall()}
        if "auth_version" not in publisher_columns:
            db.execute("ALTER TABLE publishers ADD COLUMN auth_version INTEGER DEFAULT 0")
        for name, definition in {
            "mfa_secret": "TEXT", "mfa_pending_secret": "TEXT", "mfa_enabled": "INTEGER DEFAULT 0",
            "is_admin": "INTEGER DEFAULT 0", "suspended": "INTEGER DEFAULT 0",
            "deleted_at": "TEXT",
            "email_verified": "INTEGER DEFAULT 0", "verify_token_hash": "TEXT",
            "verify_token_expires_at": "TEXT",
            # Tracks the TOTP counter (30s step) of the last code this
            # account successfully used, so the same valid code can't
            # be replayed again within its ~90s acceptance window
            # (valid_window=1) — see verify_totp_once() in auth.py.
            "mfa_last_step": "INTEGER",
        }.items():
            if name not in publisher_columns:
                db.execute(f"ALTER TABLE publishers ADD COLUMN {name} {definition}")

        domain_columns = {row["name"] for row in db.execute("PRAGMA table_info(domains)").fetchall()}
        for name, definition in {
            "integration_mode": "TEXT DEFAULT 'reverse_proxy'", "edge_api_key_hash": "TEXT",
        }.items():
            if name not in domain_columns:
                db.execute(f"ALTER TABLE domains ADD COLUMN {name} {definition}")
