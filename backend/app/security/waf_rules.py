"""
CrawlBouncer — WAF Rules
20 rules covering OWASP Top 10. Each rule has a name, regex pattern,
category, severity, and action (block or log).
"""
from __future__ import annotations
import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class WAFRule:
    id: str
    name: str
    pattern: re.Pattern
    category: str
    severity: str          # critical | high | medium | low
    action: str            # block | log
    description: str


def _r(pattern: str) -> re.Pattern:
    return re.compile(pattern, re.IGNORECASE | re.DOTALL)


RULES: list[WAFRule] = [

    # ── SQL Injection ─────────────────────────────────────────────
    WAFRule(
        id="SQLi-001",
        name="SQL Union Attack",
        pattern=_r(r"union\s+(?:all\s+)?select"),
        category="SQL Injection",
        severity="critical",
        action="block",
        description="Detects UNION SELECT statements used in SQL injection",
    ),
    WAFRule(
        id="SQLi-002",
        name="SQL Boolean Injection",
        pattern=_r(r"'\s*(?:or|and)\s+['\d]"),
        category="SQL Injection",
        severity="critical",
        action="block",
        description="Detects OR/AND-based boolean SQL injection",
    ),
    WAFRule(
        id="SQLi-003",
        name="SQL Drop Table",
        pattern=_r(r";\s*(?:drop|truncate|delete\s+from|update\s+\w+\s+set)\s+\w+"),
        category="SQL Injection",
        severity="critical",
        action="block",
        description="Detects destructive SQL statements",
    ),
    WAFRule(
        id="SQLi-004",
        name="SQL Time-Based Blind",
        pattern=_r(r"(?:sleep|benchmark|waitfor\s+delay|pg_sleep)\s*\("),
        category="SQL Injection",
        severity="high",
        action="block",
        description="Detects time-based blind SQL injection",
    ),
    WAFRule(
        id="SQLi-005",
        name="SQL Error-Based",
        pattern=_r(r"(?:extractvalue|updatexml|floor\(rand\()\s*\("),
        category="SQL Injection",
        severity="high",
        action="block",
        description="Detects error-based SQL injection functions",
    ),

    # ── Cross-Site Scripting ──────────────────────────────────────
    WAFRule(
        id="XSS-001",
        name="Script Tag Injection",
        pattern=_r(r"<script[\s>]"),
        category="XSS",
        severity="high",
        action="block",
        description="Detects script tag injection",
    ),
    WAFRule(
        id="XSS-002",
        name="JavaScript Protocol",
        pattern=_r(r"javascript\s*:"),
        category="XSS",
        severity="high",
        action="block",
        description="Detects javascript: URI schemes",
    ),
    WAFRule(
        id="XSS-003",
        name="Event Handler Injection",
        pattern=_r(r"on(?:load|error|click|mouseover|focus|blur|change|submit)\s*="),
        category="XSS",
        severity="high",
        action="block",
        description="Detects HTML event handler injection",
    ),
    WAFRule(
        id="XSS-004",
        name="HTML Entity Bypass",
        pattern=_r(r"(?:&#x?[0-9a-f]{1,6};?){3,}"),
        category="XSS",
        severity="medium",
        action="block",
        description="Detects HTML entity encoding used to bypass filters",
    ),

    # ── Path Traversal (literal ../ sequences — check early, specific) ─
    WAFRule(
        id="PT-001",
        name="Unix Path Traversal",
        pattern=_r(r"\.\./|\.\.\\"),
        category="Path Traversal",
        severity="high",
        action="block",
        description="Detects Unix directory traversal sequences",
    ),

    # ── Command Injection ─────────────────────────────────────────
    WAFRule(
        id="CMDi-001",
        name="Shell Metacharacters",
        pattern=_r(r"(?:;|\|{1,2}|&&)\s*(?:cat|ls|id|whoami|uname|wget|curl|bash|sh|python|perl|nc)\b"),
        category="Command Injection",
        severity="critical",
        action="block",
        description="Detects shell command injection via metacharacters",
    ),
    WAFRule(
        id="CMDi-002",
        name="Backtick Execution",
        pattern=_r(r"`[^`]*`|\$\([^)]*\)"),
        category="Command Injection",
        severity="high",
        action="block",
        description="Detects command substitution via backticks or $(...)",
    ),

    # ── SSRF ──────────────────────────────────────────────────────
    WAFRule(
        id="SSRF-001",
        name="Internal IP Access",
        pattern=_r(r"(?:http|https|ftp)://(?:127\.0\.0\.1|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|localhost)"),
        category="SSRF",
        severity="critical",
        action="block",
        description="Detects SSRF attempts targeting internal IP ranges",
    ),
    WAFRule(
        id="SSRF-002",
        name="AWS Metadata Endpoint",
        pattern=_r(r"169\.254\.169\.254"),
        category="SSRF",
        severity="critical",
        action="block",
        description="Detects attempts to access AWS instance metadata",
    ),

    # ── XXE ───────────────────────────────────────────────────────
    WAFRule(
        id="XXE-001",
        name="XML External Entity",
        pattern=_r(r"<!(?:ENTITY|DOCTYPE)[^>]*(?:SYSTEM|PUBLIC)\s+['\"]"),
        category="XXE",
        severity="high",
        action="block",
        description="Detects XML external entity injection",
    ),

    # ── Null Byte ─────────────────────────────────────────────────
    WAFRule(
        id="NULL-001",
        name="Null Byte Injection",
        pattern=_r(r"%00|\\x00|\0"),
        category="Injection",
        severity="medium",
        action="block",
        description="Detects null byte injection attempts",
    ),

    # ── Path Traversal — generic sensitive-file substring match.
    # Checked after the more specific attack categories above, since
    # exploit payloads for those categories often incidentally contain
    # "/etc/passwd" etc. (e.g. a command-injection or XXE payload used
    # to read that file) and should be classified by their real attack
    # type rather than shadowed by this broad check. ─────────────────
    WAFRule(
        id="PT-002",
        name="Sensitive File Access",
        pattern=_r(r"/etc/(?:passwd|shadow|hosts|crontab)|/proc/self"),
        category="Path Traversal",
        severity="critical",
        action="block",
        description="Detects attempts to access sensitive system files",
    ),

    # ── Broken Access Control (log-only — checked after block rules) ──
    WAFRule(
        id="BAC-001",
        name="Admin Path Access",
        pattern=_r(r"/(?:admin|administrator|wp-admin|phpmyadmin|cpanel|plesk)(?:/|$)"),
        category="Broken Access Control",
        severity="medium",
        action="log",
        description="Logs attempts to access common admin paths",
    ),
    WAFRule(
        id="BAC-002",
        name="IDOR Pattern",
        pattern=_r(r"\.\./(?:users?|accounts?|profiles?)/\d+"),
        category="Broken Access Control",
        severity="medium",
        action="log",
        description="Detects potential IDOR patterns in URL paths",
    ),

    # ── Security Misconfiguration ─────────────────────────────────
    WAFRule(
        id="SEC-001",
        name="Sensitive File Extension",
        pattern=_r(r"\.(?:env|htpasswd|htaccess|bak|sql|dump)(?:\?|$)|\.(?:git|svn)(?:/|\?|$)"),
        category="Security Misconfiguration",
        severity="high",
        action="block",
        description="Blocks requests for sensitive configuration files",
    ),
]

# Rule lookup by ID
RULE_MAP: dict[str, WAFRule] = {r.id: r for r in RULES}
