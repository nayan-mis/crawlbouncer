"""
CrawlBouncer — Tor Exit Node Updater
Background worker that refreshes the Tor exit node list every 24 hours.
Runs as part of the shared APScheduler.
"""
from __future__ import annotations


def refresh_tor_list() -> int:
    """Download the latest Tor exit node list and return node count."""
    from app.middleware.ip_reputation import TorExitList
    count = TorExitList.refresh()
    return count


def start_tor_updater(scheduler):
    """
    Register the Tor update job with the existing APScheduler instance.
    Runs daily at 03:00 UTC (low-traffic time).
    """
    try:
        from apscheduler.triggers.cron import CronTrigger

        # Initial load in the background so a slow network never blocks startup
        scheduler.add_job(refresh_tor_list, id="tor_list_initial", replace_existing=True)

        scheduler.add_job(
            refresh_tor_list,
            CronTrigger(hour=3, minute=0),
            id="tor_list_refresh",
            replace_existing=True,
        )
        print("[TorUpdater] Scheduled — runs daily at 03:00 UTC")
    except ImportError:
        print("[TorUpdater] APScheduler not available — Tor list will only load once on startup")
    except Exception as e:
        print(f"[TorUpdater] Failed to schedule: {e}")
