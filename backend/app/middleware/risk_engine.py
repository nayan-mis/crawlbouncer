"""
CrawlBouncer — Unified Risk Engine
Fuses bot detection, IP reputation, and anomaly signals into one score and
one graduated action, instead of three separate checks each applying their
own independent threshold. Also owns reputation decay: an IP's accumulated
bad history stops counting after DECAY_DAYS of clean behavior, rather than
staying flagged forever — the same "don't punish forever" principle behind
the rest of this platform's design.

Because every domain this instance serves shares one database, the history
this module builds is inherently cross-tenant: an IP flagged as bad on one
publisher's site is already known the moment it hits any other publisher's
site on the same deployment. No separate "shared cache" service needed —
it falls out of the existing single-database architecture for free.
"""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime, timezone

from app.database import get_db

DECAY_DAYS = 14

# (score_threshold, tier) — checked highest first, first match wins.
TIERS = [
    (85, "block"),
    (65, "hard_challenge"),
    (40, "soft_challenge"),
    (20, "monitor"),
    (0,  "allow"),
]


@dataclass
class RiskAssessment:
    score:   int         # 0-100 fused score
    tier:    str         # allow / monitor / soft_challenge / hard_challenge / block
    reasons: list[str]


def _tier_for(score: int) -> str:
    for threshold, tier in TIERS:
        if score >= threshold:
            return tier
    return "allow"


def record_and_score(ip: str, bot_confidence: float = 0.0, ip_risk_score: int = 0,
                      anomaly_flagged: bool = False) -> RiskAssessment:
    """
    Update this IP's persisted, cross-tenant history and return one fused
    risk assessment.

    bot_confidence:  0.0-1.0, from bot_detection's suspicious-pattern check
    ip_risk_score:   0-100, from ip_reputation.check()
    anomaly_flagged: from the ML anomaly detector
    """
    reasons: list[str] = []
    now = datetime.now(timezone.utc)

    raw_signal = int(bot_confidence * 100 * 0.35 + ip_risk_score * 0.45
                      + (20 if anomaly_flagged else 0))
    raw_signal = min(raw_signal, 100)

    with get_db() as db:
        row = db.execute(
            "SELECT * FROM ip_reputation_history WHERE ip = ?", (ip,)
        ).fetchone()

        if row:
            last_seen = datetime.fromisoformat(row["last_seen"])
            age_days = (now - last_seen).total_seconds() / 86400
            if age_days > DECAY_DAYS:
                decayed_bad_hits = 0
                reasons.append(f"history decayed (clean {int(age_days)}d)")
            else:
                decayed_bad_hits = row["bad_hits"]

            new_bad_hits = decayed_bad_hits + (1 if raw_signal >= 40 else 0)
            db.execute(
                "UPDATE ip_reputation_history SET last_seen=?, times_seen=times_seen+1, "
                "bad_hits=?, last_score=? WHERE ip=?",
                (now.isoformat(), new_bad_hits, raw_signal, ip),
            )
        else:
            new_bad_hits = 1 if raw_signal >= 40 else 0
            db.execute(
                "INSERT INTO ip_reputation_history "
                "(ip, first_seen, last_seen, times_seen, bad_hits, last_score) "
                "VALUES (?, ?, ?, 1, ?, ?)",
                (ip, now.isoformat(), now.isoformat(), new_bad_hits, raw_signal),
            )
        db.commit()

    # Repeat offenders escalate — capped so one old flag can't dominate forever.
    history_boost = min(new_bad_hits * 5, 25)
    if history_boost:
        reasons.append(f"repeat bad activity across {new_bad_hits} prior hit(s), this IP, any domain")

    if bot_confidence >= 0.4:
        reasons.append(f"bot signal {bot_confidence:.2f}")
    if ip_risk_score:
        reasons.append(f"ip reputation {ip_risk_score}")
    if anomaly_flagged:
        reasons.append("ml anomaly flagged")

    score = min(raw_signal + history_boost, 100)
    return RiskAssessment(score=score, tier=_tier_for(score), reasons=reasons)
