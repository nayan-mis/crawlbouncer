"""
CrawlBouncer — SSRF-safe outbound resolution

Single source of truth for "resolve this publisher-controlled
hostname, confirm it's public, and pin the actual connection to that
exact address" — used by every place this app makes an outbound HTTP
request to a URL a publisher configured (origin proxying, agent
mirror fetches).

WHY THIS EXISTS AS ITS OWN MODULE, NOT TWO COPIES:
Two call sites (origin_proxy.py, agent_mirror.py)
each independently implemented "resolve the hostname, reject it if
any answer is non-public" — and each then made the actual HTTP
request with a plain URL string, letting the HTTP client re-resolve
DNS on its own, completely independently of the check that just ran.
That gap is exploitable: an attacker who controls authoritative DNS
for their own origin/webhook hostname (zero or low TTL) can answer
the validation check with a public IP and the real connection,
microseconds to milliseconds later, with an internal one —
127.0.0.1, 169.254.169.254 (cloud metadata), or another internal
service. This is the standard DNS-rebinding SSRF pattern; "check,
then let something else resolve independently and connect" doesn't
close it, no matter how careful the check itself is.

The actual fix is pinning: resolve once, validate that one answer,
and make the real connection to that exact IP — never let the
HTTP client do its own, second, unpinned resolution. This module is
the one place that logic lives, so the call sites can't drift
out of sync with each other.
"""
from __future__ import annotations
import ipaddress
import socket
from urllib.parse import urlparse


class UnsafeURLError(ValueError):
    """Raised when a URL is malformed or resolves to a non-public address."""


def resolve_and_pin(url: str) -> tuple[str, dict]:
    """Validate a publisher-controlled URL and return (pinned_url, extensions).

    `pinned_url` has its hostname replaced with the one validated IP
    address this request should actually connect to. `extensions` is
    ready to pass as httpx's `extensions=` kwarg — for HTTPS it sets
    `sni_hostname` so TLS SNI and certificate validation still check
    against the real hostname even though the socket connects to the
    IP literal, exactly as if DNS had resolved normally.

    Raises UnsafeURLError with a caller-appropriate message on any
    invalid URL, unresolvable hostname, or non-public address.
    """
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise UnsafeURLError("URL must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password:
        raise UnsafeURLError("URL must not contain credentials")

    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(parsed.hostname, port)}
    except socket.gaierror:
        raise UnsafeURLError("hostname could not be resolved")
    for address in addresses:
        if not ipaddress.ip_address(address).is_global:
            raise UnsafeURLError("URL resolves to a non-public address")

    pinned_ip = next(iter(addresses))
    pinned_netloc = f"{pinned_ip}:{parsed.port}" if parsed.port else pinned_ip
    pinned_url = parsed._replace(netloc=pinned_netloc).geturl()
    extensions = {"sni_hostname": parsed.hostname} if parsed.scheme == "https" else {}
    return pinned_url, extensions
