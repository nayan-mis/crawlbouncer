"""
CrawlBouncer — Risk Engine Tests
Proves the fused scoring, tier ladder, decay, and cross-tenant history
accumulation actually behave as designed — not just that nothing else broke.
"""
from datetime import datetime, timedelta, timezone

from app.database import get_db
from app.middleware.risk_engine import record_and_score, _tier_for, DECAY_DAYS


def _clear(ip: str):
    with get_db() as db:
        db.execute("DELETE FROM ip_reputation_history WHERE ip = ?", (ip,))
        db.commit()


# ─────────────────────────────────────────────────────────────────
# TIER MAPPING
# ─────────────────────────────────────────────────────────────────

def test_tier_for_boundaries():
    assert _tier_for(0)  == "allow"
    assert _tier_for(19) == "allow"
    assert _tier_for(20) == "monitor"
    assert _tier_for(39) == "monitor"
    assert _tier_for(40) == "soft_challenge"
    assert _tier_for(64) == "soft_challenge"
    assert _tier_for(65) == "hard_challenge"
    assert _tier_for(84) == "hard_challenge"
    assert _tier_for(85) == "block"
    assert _tier_for(100) == "block"


# ─────────────────────────────────────────────────────────────────
# FUSION
# ─────────────────────────────────────────────────────────────────

def test_clean_traffic_scores_low():
    _clear("203.0.113.10")
    result = record_and_score("203.0.113.10", bot_confidence=0.0, ip_risk_score=0)
    assert result.tier == "allow"
    assert result.score < 20


def test_high_signals_reach_block():
    _clear("203.0.113.11")
    result = record_and_score("203.0.113.11", bot_confidence=0.9, ip_risk_score=90, anomaly_flagged=True)
    assert result.tier == "block"
    assert result.score >= 85


def test_moderate_signals_land_in_challenge_range_not_allow_or_block():
    _clear("203.0.113.12")
    # 0.7*100*0.35 + 60*0.45 = 24.5 + 27 = 51.5 -> lands in soft_challenge (40-64)
    result = record_and_score("203.0.113.12", bot_confidence=0.7, ip_risk_score=60)
    assert result.tier in ("soft_challenge", "hard_challenge")


# ─────────────────────────────────────────────────────────────────
# REPEAT-OFFENDER ESCALATION (this IS the cross-tenant mechanism —
# there's no domain/publisher parameter at all, by design: the same IP's
# history applies no matter which of this instance's domains it hits)
# ─────────────────────────────────────────────────────────────────

def test_repeat_bad_hits_escalate_score_for_same_ip():
    ip = "203.0.113.13"
    _clear(ip)
    first  = record_and_score(ip, bot_confidence=0.6, ip_risk_score=50)
    second = record_and_score(ip, bot_confidence=0.6, ip_risk_score=50)
    third  = record_and_score(ip, bot_confidence=0.6, ip_risk_score=50)
    assert third.score > second.score >= first.score
    assert any("repeat bad activity" in r for r in third.reasons)


def test_history_persists_across_calls_regardless_of_which_domain_context():
    """
    record_and_score takes no domain/publisher argument — that's the point.
    A bad IP's record is the same record whether it hit publisher A's site
    or publisher B's site a minute later, because both share one database.
    """
    ip = "203.0.113.14"
    _clear(ip)
    record_and_score(ip, bot_confidence=0.7, ip_risk_score=60)  # "hits publisher A"
    result = record_and_score(ip, bot_confidence=0.0, ip_risk_score=0)  # "hits publisher B", clean signals this time
    # Even with clean signals on this specific request, the prior bad hit
    # still counts — that's the accumulated history working.
    assert result.score > 0
    assert any("repeat bad activity" in r for r in result.reasons)


# ─────────────────────────────────────────────────────────────────
# DECAY
# ─────────────────────────────────────────────────────────────────

def test_old_history_decays_after_decay_days():
    ip = "203.0.113.15"
    _clear(ip)
    with get_db() as db:
        old_date = (datetime.now(timezone.utc) - timedelta(days=DECAY_DAYS + 5)).isoformat()
        db.execute(
            "INSERT INTO ip_reputation_history (ip, first_seen, last_seen, times_seen, bad_hits, last_score) "
            "VALUES (?, ?, ?, 5, 5, 80)",
            (ip, old_date, old_date),
        )
        db.commit()

    result = record_and_score(ip, bot_confidence=0.0, ip_risk_score=0)
    assert any("decayed" in r for r in result.reasons)
    # Clean signals + decayed history should land back at allow, not still
    # be punished for behavior from weeks ago.
    assert result.tier == "allow"


def test_recent_history_does_not_decay():
    ip = "203.0.113.16"
    _clear(ip)
    with get_db() as db:
        recent_date = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
        db.execute(
            "INSERT INTO ip_reputation_history (ip, first_seen, last_seen, times_seen, bad_hits, last_score) "
            "VALUES (?, ?, ?, 5, 5, 80)",
            (ip, recent_date, recent_date),
        )
        db.commit()

    result = record_and_score(ip, bot_confidence=0.0, ip_risk_score=0)
    assert not any("decayed" in r for r in result.reasons)
    assert result.score > 0  # the 5 prior bad hits still count
