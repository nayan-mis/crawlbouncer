"""
CrawlBouncer — WAF Engine
Runs all 20 OWASP rules on every request.
Checks path, query string, and request body.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional
from urllib.parse import unquote
from app.security.waf_rules import RULES, WAFRule


@dataclass
class WAFResult:
    blocked: bool
    rule: Optional[WAFRule]
    matched_value: str
    location: str          # where the match was found: path | query | body | header


class WAFEngine:
    """
    Stateless WAF engine. Thread-safe by design (no shared mutable state).
    Call check() for every incoming request.
    """

    def check(
        self,
        path: str = "",
        query_string: str = "",
        body: str = "",
        headers: Optional[dict] = None,
    ) -> WAFResult:
        """
        Check a request against all WAF rules.
        Returns WAFResult — blocked=True if any critical/high rule matches.
        """
        # Normalize percent-encoding so encoded traversal/injection (e.g. ..%2F)
        # can't bypass patterns written against their decoded form.
        decoded_path = unquote(path or "")
        decoded_query = unquote(query_string or "")

        targets = {
            "path":         decoded_path,
            "query":        decoded_query,
            "body":         (body or "")[:4096],   # cap body check at 4KB
        }

        # Add header values (user-agent, referer are common injection vectors)
        if headers:
            for key in ("user-agent", "referer", "x-forwarded-for"):
                val = headers.get(key, "")
                if val:
                    targets[f"header:{key}"] = val

        for rule in RULES:
            for location, value in targets.items():
                if not value:
                    continue
                if rule.pattern.search(value):
                    return WAFResult(
                        blocked=(rule.action == "block"),
                        rule=rule,
                        matched_value=_safe_excerpt(value),
                        location=location,
                    )

        return WAFResult(blocked=False, rule=None, matched_value="", location="")

    def check_severity(
        self,
        path: str = "",
        query_string: str = "",
        min_severity: str = "high",
    ) -> WAFResult:
        """
        Quick check for only high/critical rules — faster for hot path.
        """
        cutoff = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        min_level = cutoff.get(min_severity, 1)

        for rule in RULES:
            if cutoff.get(rule.severity, 3) > min_level:
                continue
            for value in (path, query_string):
                if value and rule.pattern.search(value):
                    return WAFResult(
                        blocked=(rule.action == "block"),
                        rule=rule,
                        matched_value=_safe_excerpt(value),
                        location="path" if value == path else "query",
                    )

        return WAFResult(blocked=False, rule=None, matched_value="", location="")


def _safe_excerpt(value: str, max_len: int = 80) -> str:
    """Return a safe excerpt of a matched value for logging."""
    safe = value[:max_len].replace("\n", " ").replace("\r", "")
    return safe + "…" if len(value) > max_len else safe


# Singleton
waf = WAFEngine()
