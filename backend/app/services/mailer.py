"""
CrawlBouncer — tiny SMTP mailer (standard library only).

Configure SMTP_HOST / SMTP_PORT / SMTP_USER / SMTP_PASSWORD in .env to send real
email. With no SMTP_HOST set, messages are printed to the server log instead, so a
self-hosted box works with zero email setup.
"""
from __future__ import annotations
import smtplib
import ssl
from email.message import EmailMessage

from app.config import cfg


def send_email(to: str, subject: str, body: str) -> bool:
    """Best-effort send. Returns True if handed to an SMTP server (or logged)."""
    if not cfg.smtp_enabled:
        print(f"[Mail] SMTP not configured. Would send to {to}: {subject}\n{body}\n")
        return True
    msg = EmailMessage()
    msg["From"] = cfg.EMAIL_FROM
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    try:
        if cfg.SMTP_PORT == 465:
            server = smtplib.SMTP_SSL(cfg.SMTP_HOST, cfg.SMTP_PORT, timeout=10,
                                      context=ssl.create_default_context())
        else:
            server = smtplib.SMTP(cfg.SMTP_HOST, cfg.SMTP_PORT, timeout=10)
            if cfg.SMTP_STARTTLS:
                server.starttls(context=ssl.create_default_context())
        with server:
            if cfg.SMTP_USER:
                server.login(cfg.SMTP_USER, cfg.SMTP_PASSWORD)
            server.send_message(msg)
        return True
    except Exception as exc:
        print(f"[Mail] delivery to {to} failed: {exc}")
        return False
