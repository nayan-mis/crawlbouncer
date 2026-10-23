"""
CrawlBouncer — Configuration
All settings come from environment variables with safe defaults.
"""
import os
import secrets
from dataclasses import dataclass


def _load_dotenv() -> None:
    """Load KEY=value lines from a .env file (cwd, backend/, or repo root).
    Real environment variables always win. No extra dependency needed."""
    here = os.path.dirname(os.path.abspath(__file__))
    for folder in (os.getcwd(), os.path.dirname(here), os.path.dirname(os.path.dirname(here))):
        path = os.path.join(folder, ".env")
        if not os.path.isfile(path):
            continue
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                value = value.strip().strip('"').strip("'")
                if value:   # an empty value means "use the default"
                    os.environ.setdefault(key.strip(), value)
        return


_load_dotenv()


def _bool(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).strip().lower() in ("1", "true", "yes", "on")


@dataclass
class Config:
    # ── Server ─────────────────────────────────────────────────
    HOST: str = os.getenv("HOST", "0.0.0.0")
    PORT: int = int(os.getenv("PORT", 8000))
    DEBUG: bool = _bool("DEBUG")
    ENV: str = os.getenv("ENV", "development")

    # ── Database (SQLite file; see SQLITE_PATH in database.py) ──
    # Raw request logs and WAF events older than this are pruned daily.
    DATA_RETENTION_DAYS: int = int(os.getenv("DATA_RETENTION_DAYS", 90))

    # ── Security ────────────────────────────────────────────────
    # If JWT_SECRET is not set we generate a random one at startup: safe, but
    # everyone is logged out on each restart, so set it for real use.
    JWT_SECRET: str = os.getenv("JWT_SECRET") or secrets.token_urlsafe(48)
    JWT_EXPIRE_HOURS: int = int(os.getenv("JWT_EXPIRE_HOURS", 24))
    MFA_ENCRYPTION_KEY: str = os.getenv("MFA_ENCRYPTION_KEY", "")

    # ── Accounts ────────────────────────────────────────────────
    # The very first account is always allowed (and becomes admin).
    # After that, signups are closed unless you open them.
    ALLOW_SIGNUPS: bool = _bool("ALLOW_SIGNUPS", "false")  # read at import; tests set it before importing

    # ── Email (optional, plain SMTP — no third-party service) ───
    # If SMTP_HOST is empty, emails are printed to the server log instead
    # and new accounts are auto-verified (fine for a self-hosted box).
    SMTP_HOST: str = os.getenv("SMTP_HOST", "")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", 587))
    SMTP_USER: str = os.getenv("SMTP_USER", "")
    SMTP_PASSWORD: str = os.getenv("SMTP_PASSWORD", "")
    SMTP_STARTTLS: bool = _bool("SMTP_STARTTLS", "true")
    EMAIL_FROM: str = os.getenv("EMAIL_FROM", "crawlbouncer@localhost")
    APP_BASE_URL: str = os.getenv("APP_BASE_URL", "http://localhost:8000")

    # ── Alerts (both optional) ──────────────────────────────────
    ALERT_EMAIL: str = os.getenv("ALERT_EMAIL", "")            # needs SMTP_HOST
    SLACK_WEBHOOK_URL: str = os.getenv("SLACK_WEBHOOK_URL", "")

    # ── Optional external lookup: AbuseIPDB (free tier). Empty = skipped.
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")

    # ── Agent Mirror (off by default) ───────────────────────────
    MIRROR_ENABLED: bool = _bool("MIRROR_ENABLED")
    MIRROR_CACHE_TTL_SECONDS: int = int(os.getenv("MIRROR_CACHE_TTL_SECONDS", 86400))

    # ── Rate limiting ───────────────────────────────────────────
    RATE_LIMIT_REQUESTS: int = int(os.getenv("RATE_LIMIT_REQUESTS", 120))
    RATE_LIMIT_WINDOW: int = int(os.getenv("RATE_LIMIT_WINDOW", 60))
    BOT_RATE_LIMIT: int = int(os.getenv("BOT_RATE_LIMIT", 20))
    TRUSTED_PROXY_CIDRS: str = os.getenv("TRUSTED_PROXY_CIDRS", "")

    # Hostnames that serve CrawlBouncer's own dashboard/API (not proxied sites).
    PLATFORM_HOSTS: str = os.getenv("PLATFORM_HOSTS", "localhost,127.0.0.1,testserver")
    # Extra browser origins allowed to call the API in production (comma-separated).
    CORS_ORIGINS: str = os.getenv("CORS_ORIGINS", "")
    # Public hostname the CNAME records of protected sites should point to.
    PROXY_BASE: str = os.getenv("PROXY_BASE", "proxy.example.com")

    @property
    def is_production(self) -> bool:
        return self.ENV == "production"

    @property
    def is_development(self) -> bool:
        return self.ENV == "development"

    @property
    def is_test(self) -> bool:
        return self.ENV == "test"

    @property
    def require_email_verification(self) -> bool:
        """Verify email addresses only when we can actually send email
        (or when REQUIRE_EMAIL_VERIFICATION is set explicitly)."""
        raw = os.getenv("REQUIRE_EMAIL_VERIFICATION")
        return _bool("REQUIRE_EMAIL_VERIFICATION") if raw is not None else self.smtp_enabled

    @property
    def smtp_enabled(self) -> bool:
        return bool(self.SMTP_HOST)

    def validate_production_config(self) -> list[str]:
        """Problems that must be fixed before running in production.
        main.py refuses to boot if this is non-empty. Returns [] outside production."""
        if not self.is_production:
            return []
        problems = []
        if not os.getenv("JWT_SECRET"):
            problems.append("JWT_SECRET is not set. Generate one with `openssl rand -hex 32`.")
        if self.JWT_SECRET == "CHANGE_THIS_IN_PRODUCTION_USE_64_RANDOM_CHARS":
            problems.append(
                "JWT_SECRET is still the placeholder. Set a random value "
                "(e.g. `openssl rand -hex 32`)."
            )
        elif len(self.JWT_SECRET) < 32:
            problems.append(
                f"JWT_SECRET is only {len(self.JWT_SECRET)} characters. Use at least 32."
            )
        return problems


cfg = Config()
