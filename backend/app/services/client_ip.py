"""
CrawlBouncer — Client IP resolution

Single source of truth for "what is the real client IP of this request."
Previously this logic lived only inside app/main.py's request pipeline;
anything else needing a trustworthy client IP (like login rate limiting)
would otherwise have had to duplicate the trusted-proxy check. Getting
this wrong is a real vulnerability (a spoofed X-Forwarded-For could let
an attacker bypass IP-based rate limiting), so it lives in exactly one
place.
"""
from __future__ import annotations
import ipaddress
from fastapi import Request

from app.config import cfg


def is_trusted_proxy(request: Request) -> bool:
    peer = request.client.host if request.client else ""
    try:
        peer_ip = ipaddress.ip_address(peer)
    except ValueError:
        return False
    for cidr in filter(None, (part.strip() for part in cfg.TRUSTED_PROXY_CIDRS.split(","))):
        try:
            if peer_ip in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            print(f"[WARN] Ignoring invalid TRUSTED_PROXY_CIDRS entry: {cidr}")
    return False


def get_client_ip(request: Request) -> str:
    """Extract client IP only from configured, trusted reverse proxies."""
    if is_trusted_proxy(request):
        return (
            request.headers.get("X-Real-IP")
            or request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            or (request.client.host if request.client else "0.0.0.0")
        )
    return request.client.host if request.client else "0.0.0.0"
