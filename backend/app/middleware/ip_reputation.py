"""
CrawlBouncer — IP Reputation
Three-source IP classification:
  1. Tor exit node list    (updated daily)
  2. ASN lookup            (datacenter vs residential)
  3. AbuseIPDB             (community-reported bad IPs)
All results cached in memory to avoid repeated API calls.
"""
from __future__ import annotations
import time
import socket
import urllib.request
from dataclasses import dataclass, field
from threading import Lock
from typing import Optional

from app.config import cfg


# ─────────────────────────────────────────────────────────────────
# RESULT
# ─────────────────────────────────────────────────────────────────

@dataclass
class ReputationResult:
    ip:            str
    is_tor:        bool        = False
    is_datacenter: bool        = False
    is_residential:bool        = False
    abuse_score:   int         = 0        # 0-100 from AbuseIPDB
    asn:           str         = ""
    org:           str         = ""
    country:       str         = ""
    risk_score:    int         = 0        # composite 0-100
    signals:       list[str]   = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────
# KNOWN DATACENTER ASN PREFIXES
# ─────────────────────────────────────────────────────────────────

DATACENTER_ORGS = {
    "amazon", "aws", "google", "gcp", "microsoft", "azure",
    "digitalocean", "linode", "akamai", "cloudflare", "fastly",
    "vultr", "hetzner", "ovh", "leaseweb", "rackspace", "ibm",
    "oracle", "alibaba", "tencent", "huawei",
}


# ─────────────────────────────────────────────────────────────────
# TOR EXIT NODE LIST
# ─────────────────────────────────────────────────────────────────

class TorExitList:
    """
    Downloads and caches the official Tor exit node list.
    Refreshed daily in a background worker.
    """
    TOR_URL = "https://check.torproject.org/exit-addresses"
    _exits: set[str] = set()
    _loaded_at: float = 0.0
    _lock = Lock()

    @classmethod
    def is_exit(cls, ip: str) -> bool:
        return ip in cls._exits

    @classmethod
    def refresh(cls) -> int:
        """Download the latest Tor exit list. Returns node count."""
        try:
            with urllib.request.urlopen(cls.TOR_URL, timeout=15) as resp:
                text = resp.read().decode("utf-8")

            exits: set[str] = set()
            for line in text.splitlines():
                if line.startswith("ExitAddress"):
                    parts = line.split()
                    if len(parts) >= 2:
                        exits.add(parts[1])

            with cls._lock:
                cls._exits     = exits
                cls._loaded_at = time.time()

            print(f"[TorExitList] Refreshed — {len(exits)} exit nodes loaded")
            return len(exits)

        except Exception as e:
            print(f"[TorExitList] Refresh failed: {e}")
            return 0

    @classmethod
    def ensure_loaded(cls):
        """Load on first use if not already loaded."""
        if not cls._exits:
            cls.refresh()


_tor = TorExitList()


# ─────────────────────────────────────────────────────────────────
# ASN / ORG LOOKUP (using ipapi.co free tier)
# ─────────────────────────────────────────────────────────────────

_asn_cache: dict[str, dict] = {}
_asn_lock  = Lock()


def _lookup_asn(ip: str) -> dict:
    """
    Look up the ASN and organisation for an IP.
    Cached per IP for 24 hours. Uses ipapi.co free tier (1000 req/day).
    """
    with _asn_lock:
        cached = _asn_cache.get(ip)
        if cached and time.time() - cached["_ts"] < 86400:
            return cached

    try:
        import urllib.request, json
        url  = f"https://ipapi.co/{ip}/json/"
        req  = urllib.request.Request(url, headers={"User-Agent": "CrawlBouncer/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())

        result = {
            "asn":     data.get("asn", ""),
            "org":     data.get("org", ""),
            "country": data.get("country_code", ""),
            "_ts":     time.time(),
        }
    except Exception:
        result = {"asn": "", "org": "", "country": "", "_ts": time.time()}

    with _asn_lock:
        _asn_cache[ip] = result

    return result


def _is_datacenter(org: str) -> bool:
    org_lower = org.lower()
    return any(dc in org_lower for dc in DATACENTER_ORGS)


# ─────────────────────────────────────────────────────────────────
# ABUSEIPDB (community threat intelligence)
# ─────────────────────────────────────────────────────────────────

_abuse_cache: dict[str, dict] = {}
_abuse_lock  = Lock()


def _check_abuseipdb(ip: str) -> int:
    """
    Check AbuseIPDB for community-reported abuse score (0-100).
    Only called for IPs with anomaly score > 50 to stay within the free API quota.
    Returns 0 if API key not configured.
    """
    if not cfg.ABUSEIPDB_API_KEY:
        return 0

    with _abuse_lock:
        cached = _abuse_cache.get(ip)
        if cached and time.time() - cached["_ts"] < 3600:
            return cached["score"]

    try:
        import urllib.request, json
        url  = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=30"
        req  = urllib.request.Request(url, headers={
            "Key":    cfg.ABUSEIPDB_API_KEY,
            "Accept": "application/json",
        })
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
        score = data.get("data", {}).get("abuseConfidenceScore", 0)
    except Exception:
        score = 0

    with _abuse_lock:
        _abuse_cache[ip] = {"score": score, "_ts": time.time()}

    return score


# ─────────────────────────────────────────────────────────────────
# PRIVATE / LOOPBACK IP CHECK
# ─────────────────────────────────────────────────────────────────

def _is_private(ip: str) -> bool:
    """Return True for RFC1918, loopback, and link-local addresses."""
    try:
        import ipaddress
        addr = ipaddress.ip_address(ip)
        if addr.is_loopback or addr.is_link_local:
            return True
        rfc1918 = (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
        )
        return any(addr in net for net in rfc1918)
    except ValueError:
        return False


# ─────────────────────────────────────────────────────────────────
# MAIN CHECK
# ─────────────────────────────────────────────────────────────────

def check(ip: str, anomaly_score: int = 0) -> ReputationResult:
    """
    Full IP reputation check.
    anomaly_score: pass the ML anomaly score to decide whether to call AbuseIPDB.
    """
    result  = ReputationResult(ip=ip)
    signals = []

    # Skip private IPs (local dev / reverse proxy)
    if _is_private(ip):
        return result

    # 1. Tor check
    _tor.ensure_loaded()
    if _tor.is_exit(ip):
        result.is_tor = True
        result.risk_score += 40
        signals.append("tor_exit_node")

    # 2. ASN / org lookup
    asn_data       = _lookup_asn(ip)
    result.asn     = asn_data["asn"]
    result.org     = asn_data["org"]
    result.country = asn_data["country"]

    if _is_datacenter(result.org):
        result.is_datacenter = True
        result.risk_score   += 20
        signals.append(f"datacenter ({result.org})")
    elif result.org:
        result.is_residential = True

    # 3. AbuseIPDB (only for elevated-risk IPs to preserve free tier)
    if anomaly_score > 50 or result.is_tor:
        abuse = _check_abuseipdb(ip)
        result.abuse_score = abuse
        if abuse > 75:
            result.risk_score += 40
            signals.append(f"abuseipdb_score_{abuse}")
        elif abuse > 40:
            result.risk_score += 15
            signals.append(f"abuseipdb_score_{abuse}")

    result.risk_score = min(result.risk_score, 100)
    result.signals    = signals
    return result
