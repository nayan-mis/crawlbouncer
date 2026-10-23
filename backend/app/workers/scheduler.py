"""CrawlBouncer — background scheduler (Tor list refresh, anomaly check, retention)."""
from __future__ import annotations


def start_scheduler():
    """Start APScheduler. Returns the scheduler, or None if APScheduler is missing."""
    try:
        from apscheduler.schedulers.background import BackgroundScheduler
        scheduler = BackgroundScheduler(timezone="UTC")
        scheduler.start()
        print("[Scheduler] started")
        return scheduler
    except ImportError:
        print("[Scheduler] APScheduler not installed — background jobs disabled")
        return None
