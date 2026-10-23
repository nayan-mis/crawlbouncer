"""
CrawlBouncer — Data Retention Job

Prunes rows from the two tables that grow without bound on every
single piece of traffic this app ever proxies or blocks — `requests`
(one row per proxied request) and `waf_events` (one row per blocked
WAF match) — once they're older than DATA_RETENTION_DAYS
(config.py, default 90 days).

WHY THIS EXISTS: found during a security/reliability audit — no
retention or pruning of these tables existed anywhere in the
codebase, so both grow forever. At real traffic volume that's a
slow-motion, self-inflicted disk-exhaustion issue, not a one-time bug
to patch, which is why it needs an ongoing job rather than a single
cleanup script.

WHY A LONG DEFAULT: the dashboard's longest lookback is 90 days, so
DATA_RETENTION_DAYS must stay at or above that. If a lookback window ever grows,
this retention window needs to grow with it.
"""
from __future__ import annotations
from datetime import datetime, timedelta

from app.database import get_db
from app.config import cfg


def prune_old_data(retention_days: int | None = None) -> dict:
    """Delete requests/waf_events rows older than the retention
    window. Returns counts deleted, for logging/observability —
    callers should not need to guess whether this did anything."""
    days = retention_days if retention_days is not None else cfg.DATA_RETENTION_DAYS
    cutoff = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")

    with get_db() as db:
        requests_deleted = db.execute(
            "DELETE FROM requests WHERE timestamp < ?", (cutoff,)
        ).rowcount
        waf_events_deleted = db.execute(
            "DELETE FROM waf_events WHERE timestamp < ?", (cutoff,)
        ).rowcount

    return {"cutoff": cutoff, "requests_deleted": requests_deleted, "waf_events_deleted": waf_events_deleted}


def start_retention_job(scheduler):
    """
    Register the retention-pruning job with the existing APScheduler
    instance. Runs daily at 04:00 UTC (low-traffic time, same slot
    convention as tor_updater.py's daily refresh) — daily rather than
    monthly because a table growing forever is a continuous problem,
    not a monthly-batch one; running it often keeps each run cheap
    (few rows crossing the cutoff at a time) instead of one huge
    delete accumulating for weeks.
    """
    try:
        from apscheduler.triggers.cron import CronTrigger

        scheduler.add_job(
            prune_old_data,
            CronTrigger(hour=4, minute=0),
            id="data_retention_prune",
            replace_existing=True,
        )
        print(f"[Scheduler] Data retention job scheduled — daily at 04:00 UTC, {cfg.DATA_RETENTION_DAYS}-day window")
    except ImportError:
        print("[Scheduler] APScheduler not installed — data retention job disabled")
