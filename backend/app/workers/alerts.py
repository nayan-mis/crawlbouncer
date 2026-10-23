"""
CrawlBouncer — Security Alerting
Sends notifications via optional email (SMTP) and an optional Slack webhook.
Deduplicates: same alert type fires at most once per 15 minutes.
All alerts are persisted to the database for the dashboard.
"""
from __future__ import annotations
import json
import time
import urllib.request
import urllib.error
from threading import Lock
from typing import Optional

from app.config import cfg


# ─────────────────────────────────────────────────────────────────
# SEVERITY LEVELS
# ─────────────────────────────────────────────────────────────────

SEVERITY_EMOJI = {
    "low":      "🔵",
    "medium":   "🟡",
    "high":     "🟠",
    "critical": "🔴",
}

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


# ─────────────────────────────────────────────────────────────────
# DEDUPLICATION
# ─────────────────────────────────────────────────────────────────

_last_sent: dict[str, float] = {}
_dedup_lock = Lock()
DEDUP_WINDOW = 900      # 15 minutes


def _should_send(alert_type: str) -> bool:
    now = time.time()
    with _dedup_lock:
        last = _last_sent.get(alert_type, 0)
        if now - last < DEDUP_WINDOW:
            return False
        _last_sent[alert_type] = now
        return True


# ─────────────────────────────────────────────────────────────────
# SLACK
# ─────────────────────────────────────────────────────────────────

def _send_slack(alert_type: str, severity: str, message: str, details: dict):
    if not cfg.SLACK_WEBHOOK_URL:
        return

    emoji = SEVERITY_EMOJI.get(severity, "⚪")
    text  = f"{emoji} *CrawlBouncer Alert — {severity.upper()}*\n{message}"

    if details:
        detail_lines = "\n".join(f"• {k}: {v}" for k, v in details.items())
        text += f"\n\n```\n{detail_lines}\n```"

    payload = json.dumps({
        "text":      text,
        "username":  "CrawlBouncer Security",
        "icon_emoji": ":shield:",
    }).encode()

    try:
        req = urllib.request.Request(
            cfg.SLACK_WEBHOOK_URL,
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        print(f"[Alerts] Slack delivery failed: {e}")


# ─────────────────────────────────────────────────────────────────
# EMAIL (plain SMTP, optional)
# ─────────────────────────────────────────────────────────────────

def _send_email(alert_type: str, severity: str, message: str, details: dict):
    if not cfg.ALERT_EMAIL:
        return
    from app.services.mailer import send_email
    subject = f"CrawlBouncer {severity.upper()} alert: {alert_type.replace('_', ' ')}"
    # Plain text on purpose: alert details can contain attacker-controlled
    # strings (paths, user agents), which must never be rendered as HTML.
    lines = [message, ""] + [f"{k}: {v}" for k, v in details.items()]
    send_email(cfg.ALERT_EMAIL, subject, "\n".join(lines))


def _severity_color(severity: str) -> str:
    return {"low": "#60A5FA", "medium": "#FBBF24", "high": "#FB923C", "critical": "#F43F5E"}.get(severity, "#94A3B8")


# ─────────────────────────────────────────────────────────────────
# DATABASE PERSISTENCE
# ─────────────────────────────────────────────────────────────────

def _persist(alert_type: str, severity: str, message: str, details: dict):
    try:
        from app.database import get_db
        with get_db() as db:
            db.execute(
                "INSERT INTO alerts (type, severity, message, details) VALUES (?,?,?,?)",
                (alert_type, severity, message, json.dumps(details))
            )
    except Exception as e:
        print(f"[Alerts] DB persist failed: {e}")


# ─────────────────────────────────────────────────────────────────
# MAIN ENTRY POINT
# ─────────────────────────────────────────────────────────────────

def send_alert(
    alert_type: str,
    severity: str,
    message: str,
    details: Optional[dict] = None,
    force: bool = False,
):
    """
    Send a security alert.
    Deduplicated by alert_type — same type fires at most once per 15 minutes.
    Set force=True to bypass deduplication (for testing).
    """
    if not force and not _should_send(alert_type):
        return

    details = details or {}
    details["timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S UTC")

    _persist(alert_type, severity, message, details)
    _send_slack(alert_type, severity, message, details)

    # Only email for high/critical to avoid inbox noise
    if SEVERITY_ORDER.get(severity, 0) >= SEVERITY_ORDER["high"]:
        _send_email(alert_type, severity, message, details)

    print(f"[Alerts] {SEVERITY_EMOJI.get(severity,'')} {severity.upper()} — {alert_type}: {message}")


# ─────────────────────────────────────────────────────────────────
# PREDEFINED ALERT SENDERS
# ─────────────────────────────────────────────────────────────────

def ddos_detected(rps: float, baseline: float, top_ips: list[str]):
    send_alert(
        "ddos_detected", "critical",
        f"DDoS attack detected — {rps:.1f} req/s ({rps/max(baseline,0.1):.1f}x above baseline)",
        {"current_rps": rps, "baseline_rps": baseline, "top_ips": ", ".join(top_ips[:3])},
    )


def waf_spike(rule_name: str, count: int, window_minutes: int = 5):
    send_alert(
        "waf_spike", "high",
        f"WAF rule '{rule_name}' fired {count} times in {window_minutes} minutes",
        {"rule": rule_name, "count": count},
    )


def high_error_rate(rate: float, total: int):
    send_alert(
        "high_error_rate", "medium",
        f"Error rate at {rate:.1%} ({int(rate*total)}/{total} requests returning 4xx/5xx)",
        {"error_rate": f"{rate:.1%}", "total_requests": total},
    )


def disk_high(percent: float):
    send_alert(
        "disk_high", "high" if percent > 90 else "medium",
        f"Disk usage at {percent:.1f}%",
        {"disk_used_percent": f"{percent:.1f}%"},
    )
