"""
Tests for app/middleware/bot_detection.py
Verifies that all known AI crawlers (that send a User-Agent) are correctly identified
and that human browsers are not falsely flagged.
"""
import pytest
from app.middleware.bot_detection import detect, fingerprint, CRAWLERS


# ─────────────────────────────────────────────────────────────────
# KNOWN AI CRAWLERS — must all be detected
# ─────────────────────────────────────────────────────────────────

KNOWN_BOT_AGENTS = [
    ("GPTBot/1.1",                                              "GPTBot",           "OpenAI"),
    ("Mozilla/5.0 AppleWebKit/537.36 ChatGPT-User/1.0",       "ChatGPT-User",     "OpenAI"),
    ("anthropic-ai/1.0",                                        "anthropic-ai",     "Anthropic"),
    ("ClaudeBot/1.0",                                           "ClaudeBot",        "Anthropic"),
    ("Bytespider;",                                             "Bytespider",       "ByteDance"),
    ("PerplexityBot/1.0",                                       "PerplexityBot",    "Perplexity"),
    ("CCBot/2.0",                                               "CCBot",            "Common Crawl"),
    ("Amazonbot/0.1",                                           "Amazonbot",        "Amazon"),
    ("facebookbot/1.0",                                         "FacebookBot",      "Meta"),
    ("cohere-ai/1.0",                                           "cohere-ai",        "Cohere"),
    ("AI2Bot/0.1",                                              "AI2Bot",           "Allen AI"),
    ("Diffbot/4.0",                                             "Diffbot",          "Diffbot"),
]

@pytest.mark.parametrize("ua,expected_name,expected_company", KNOWN_BOT_AGENTS)
def test_known_crawler_detected(ua, expected_name, expected_company):
    result = detect(ua)
    assert result.is_bot,                      f"Should detect '{ua}' as a bot"
    assert result.crawler_name == expected_name, f"Expected {expected_name}, got {result.crawler_name}"
    assert result.company == expected_company,   f"Expected company {expected_company}"
    assert result.confidence >= 0.95,            "Known crawlers should have high confidence"


# ─────────────────────────────────────────────────────────────────
# HUMAN BROWSERS — must NOT be flagged as bots
# ─────────────────────────────────────────────────────────────────

HUMAN_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15",
]

@pytest.mark.parametrize("ua", HUMAN_AGENTS)
def test_human_browsers_not_flagged(ua):
    result = detect(ua)
    assert not result.is_bot,          f"Should NOT flag human browser as bot: {ua[:50]}"
    assert result.crawler_name is None, "Human requests should have no crawler_name"


# ─────────────────────────────────────────────────────────────────
# SUSPICIOUS BUT UNCONFIRMED
# ─────────────────────────────────────────────────────────────────

def test_empty_user_agent_flagged():
    result = detect("")
    assert result.confidence >= 0.5, "Empty UA should have elevated confidence"
    assert "empty user-agent" in result.signals

def test_python_requests_flagged():
    result = detect("python-requests/2.31.0")
    assert result.confidence >= 0.4, "python-requests should be suspicious"
    assert "python http client" in result.signals

def test_curl_flagged():
    result = detect("curl/8.6.0")
    assert result.confidence >= 0.3, "curl should be suspicious"


# ─────────────────────────────────────────────────────────────────
# CASE INSENSITIVITY
# ─────────────────────────────────────────────────────────────────

def test_detection_is_case_insensitive():
    assert detect("GPTBOT/1.1").is_bot
    assert detect("gptbot/1.1").is_bot
    assert detect("GpTbOt/1.1").is_bot


# ─────────────────────────────────────────────────────────────────
# ACTIONS
# ─────────────────────────────────────────────────────────────────

def test_bytespider_default_action_is_block():
    result = detect("Bytespider/1.0")
    assert result.default_action == "block"

def test_gptbot_default_action_is_block():
    result = detect("GPTBot/1.0")
    assert result.default_action == "block"

def test_user_triggered_assistants_default_to_allow():
    for ua in ("ChatGPT-User/1.0", "Claude-User/1.0", "Perplexity-User/1.0"):
        assert detect(ua).default_action == "allow", ua

def test_robots_only_tokens_are_never_matched_by_user_agent():
    """Google-Extended / Applebot-Extended are robots.txt tokens, not User-Agents."""
    for name in ("Google-Extended", "Applebot-Extended"):
        assert CRAWLERS[name].get("robots_only") is True
        assert not detect(f"Mozilla/5.0 (compatible; {name})").crawler_name


# ─────────────────────────────────────────────────────────────────
# FINGERPRINTING
# ─────────────────────────────────────────────────────────────────

def test_fingerprint_is_deterministic():
    fp1 = fingerprint("GPTBot/1.1", "gzip, deflate")
    fp2 = fingerprint("GPTBot/1.1", "gzip, deflate")
    assert fp1 == fp2, "Same inputs must produce same fingerprint"

def test_fingerprint_differs_by_ua():
    fp1 = fingerprint("GPTBot/1.1")
    fp2 = fingerprint("Mozilla/5.0 Chrome")
    assert fp1 != fp2, "Different UAs must produce different fingerprints"

def test_fingerprint_is_16_chars():
    fp = fingerprint("any-user-agent")
    assert len(fp) == 16


# ─────────────────────────────────────────────────────────────────
# CRAWLER REGISTRY COMPLETENESS
# ─────────────────────────────────────────────────────────────────

def test_all_crawlers_have_required_fields():
    required = {"company", "risk", "default_action", "pattern"}  # pattern may be None (robots-only)
    for name, info in CRAWLERS.items():
        missing = required - set(info.keys())
        assert not missing, f"Crawler '{name}' missing fields: {missing}"

def test_all_crawlers_have_valid_risk_level():
    valid = {"low", "medium", "high"}
    for name, info in CRAWLERS.items():
        assert info["risk"] in valid, f"Crawler '{name}' has invalid risk: {info['risk']}"

def test_all_crawlers_have_valid_action():
    valid = {"allow", "block"}
    for name, info in CRAWLERS.items():
        assert info["default_action"] in valid, f"Crawler '{name}' has invalid action: {info['default_action']}"
