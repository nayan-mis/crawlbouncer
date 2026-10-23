"""
CrawlBouncer — Bot Detection Middleware
Identifies AI crawlers by user-agent, fingerprint, and behavioral signals.
"""
from __future__ import annotations
import re
import hashlib
from dataclasses import dataclass
from typing import Optional


# ─────────────────────────────────────────────────────────────────
# KNOWN AI CRAWLERS
# ─────────────────────────────────────────────────────────────────

CRAWLERS: dict[str, dict] = {
    # default_action: allow | block
    # Training / bulk scrapers default to "block"; bots that fetch a page because a
    # human asked an AI assistant (and usually send readers back) default to "allow".
    "GPTBot":            {"company": "OpenAI",      "risk": "high",   "default_action": "block", "pattern": r"gptbot"},
    "ChatGPT-User":      {"company": "OpenAI",      "risk": "medium", "default_action": "allow", "pattern": r"chatgpt-user"},
    "OAI-SearchBot":     {"company": "OpenAI",      "risk": "low",    "default_action": "allow", "pattern": r"oai-searchbot"},
    "ClaudeBot":         {"company": "Anthropic",   "risk": "high",   "default_action": "block", "pattern": r"claudebot"},
    "anthropic-ai":      {"company": "Anthropic",   "risk": "high",   "default_action": "block", "pattern": r"anthropic-ai"},
    "Claude-User":       {"company": "Anthropic",   "risk": "medium", "default_action": "allow", "pattern": r"claude-user"},
    "Claude-SearchBot":  {"company": "Anthropic",   "risk": "low",    "default_action": "allow", "pattern": r"claude-searchbot"},
    "Bytespider":        {"company": "ByteDance",   "risk": "high",   "default_action": "block", "pattern": r"bytespider"},
    "PerplexityBot":     {"company": "Perplexity",  "risk": "medium", "default_action": "allow", "pattern": r"perplexitybot"},
    "Perplexity-User":   {"company": "Perplexity",  "risk": "medium", "default_action": "allow", "pattern": r"perplexity-user"},
    "CCBot":             {"company": "Common Crawl","risk": "medium", "default_action": "block", "pattern": r"ccbot"},
    "Amazonbot":         {"company": "Amazon",      "risk": "medium", "default_action": "block", "pattern": r"amazonbot"},
    "FacebookBot":       {"company": "Meta",        "risk": "medium", "default_action": "block", "pattern": r"facebookbot"},
    "Meta-ExternalAgent":{"company": "Meta",        "risk": "high",   "default_action": "block", "pattern": r"meta-externalagent"},
    "cohere-ai":         {"company": "Cohere",      "risk": "medium", "default_action": "block", "pattern": r"cohere-ai"},
    "AI2Bot":            {"company": "Allen AI",    "risk": "low",    "default_action": "block", "pattern": r"ai2bot"},
    "Diffbot":           {"company": "Diffbot",     "risk": "medium", "default_action": "block", "pattern": r"diffbot"},
    "ImagesiftBot":      {"company": "Imagesift",   "risk": "medium", "default_action": "block", "pattern": r"imagesiftbot"},
    # robots.txt-only tokens: these NEVER appear in a User-Agent header (Google and Apple
    # fetch with their normal crawlers and merely *honour* the token). They can only be
    # controlled through the generated robots.txt, so they have no UA pattern.
    "Google-Extended":   {"company": "Google",      "risk": "low",    "default_action": "allow", "pattern": None, "robots_only": True},
    "Applebot-Extended": {"company": "Apple",       "risk": "low",    "default_action": "allow", "pattern": None, "robots_only": True},
}

# Pre-compile all patterns for performance
_COMPILED = {
    name: re.compile(info["pattern"], re.IGNORECASE)
    for name, info in CRAWLERS.items()
    if info.get("pattern")
}


# ─────────────────────────────────────────────────────────────────
# RESULT DATACLASS
# ─────────────────────────────────────────────────────────────────

@dataclass
class DetectionResult:
    is_bot: bool
    crawler_name: Optional[str]
    company: Optional[str]
    risk: Optional[str]
    default_action: str
    confidence: float          # 0.0 – 1.0
    signals: list[str]         # reasons for the decision


# ─────────────────────────────────────────────────────────────────
# DETECTOR
# ─────────────────────────────────────────────────────────────────

def detect(user_agent: str, ip: str = "") -> DetectionResult:
    """
    Classify an incoming request as bot or human.
    Returns a DetectionResult with full context.
    """
    ua = (user_agent or "").strip()
    signals: list[str] = []
    confidence = 0.0

    # 1. Check against known crawler user-agents
    for name, pattern in _COMPILED.items():
        if pattern.search(ua):
            info = CRAWLERS[name]
            return DetectionResult(
                is_bot=True,
                crawler_name=name,
                company=info["company"],
                risk=info["risk"],
                default_action=info["default_action"],
                confidence=0.98,
                signals=[f"user-agent matches {name}"],
            )

    # 2. Heuristic signals — suspicious but unconfirmed
    if not ua:
        signals.append("empty user-agent")
        confidence += 0.6

    if ua and "python" in ua.lower():
        signals.append("python http client")
        confidence += 0.5

    if ua and "curl" in ua.lower():
        signals.append("curl client")
        confidence += 0.4

    if ua and "java/" in ua.lower():
        signals.append("java http client")
        confidence += 0.35

    if ua and "go-http-client" in ua.lower():
        signals.append("go http client")
        confidence += 0.45

    # Confidence cap
    confidence = min(confidence, 0.85)

    is_suspicious_bot = confidence >= 0.4

    return DetectionResult(
        is_bot=is_suspicious_bot,
        crawler_name=None,
        company=None,
        risk="unknown" if is_suspicious_bot else None,
        default_action="challenge" if is_suspicious_bot else "allow",
        confidence=confidence,
        signals=signals,
    )


def fingerprint(user_agent: str, accept_encoding: str = "", accept_lang: str = "") -> str:
    """
    Generate a simple request fingerprint from headers.
    Identifies bots that rotate user-agents.
    """
    raw = f"{user_agent}|{sorted(accept_encoding.split(','))}|{accept_lang}"
    return hashlib.md5(raw.encode(), usedforsecurity=False).hexdigest()[:16]
