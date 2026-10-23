"""
CrawlBouncer — ML Anomaly Detector
Learns a baseline of "normal" traffic behavior across several dimensions
(volume, path diversity, error rate, bot ratio, response time, path
concentration) using scikit-learn's IsolationForest, and flags traffic
windows that deviate from that baseline in ways the DDoS detector's
single-threshold rules miss — e.g. normal request volume but a sudden
spike in errors and a collapse in path diversity, which often signals
scraping, credential stuffing, or a new attack pattern nobody wrote a
signature for yet.

Usage:
  - Call record_window(features) once per time bucket (the periodic
    worker below does this every minute using live request data).
  - Once enough history has accumulated, an IsolationForest is fit on
    it and every new window is scored against that baseline.
  - A statistically anomalous window fires an alert through the same
    alerts.send_alert() path the DDoS detector and WAF use.
"""
from __future__ import annotations
import time
import threading
from dataclasses import dataclass
from typing import Optional

import numpy as np
from sklearn.ensemble import IsolationForest


# ─────────────────────────────────────────────────────────────────
# FEATURES
# ─────────────────────────────────────────────────────────────────

FEATURE_NAMES = [
    "requests_per_min",
    "unique_ips",
    "unique_paths",
    "bot_ratio",
    "error_rate",
    "avg_response_ms",
    "path_concentration",   # share of traffic hitting the single busiest path
    "challenge_fail_rate",  # share of PoW/captcha challenges failed this window —
                             # a real labeled bot/human signal, not just UA pattern matching
]


def compute_window_features(
    requests: list[dict], window_seconds: float = 60.0, challenge_events: Optional[list[dict]] = None
) -> dict:
    """
    Build a feature vector from a batch of raw request records.
    Each record is expected to have: ip, path, is_bot, status_code, response_ms.
    Missing/None fields are treated as 0 / falsy so partial rows don't crash this.

    challenge_events (optional): records with a `passed` field (0/1) from
    challenge_events for the same window. No challenges in the window ->
    challenge_fail_rate defaults to 0.0 (treated as "nothing failed", the
    same convention already used for empty windows on every other feature
    here — not a claim that the traffic was verified human).
    """
    if not requests:
        return {name: 0.0 for name in FEATURE_NAMES}

    n = len(requests)
    unique_ips   = len({r.get("ip") for r in requests if r.get("ip")})
    unique_paths = len({r.get("path") for r in requests if r.get("path")})
    bot_count    = sum(1 for r in requests if r.get("is_bot"))
    error_count  = sum(1 for r in requests if (r.get("status_code") or 200) >= 400)
    avg_ms       = sum(r.get("response_ms") or 0 for r in requests) / n

    path_counts: dict[str, int] = {}
    for r in requests:
        p = r.get("path") or ""
        path_counts[p] = path_counts.get(p, 0) + 1
    path_concentration = (max(path_counts.values()) / n) if path_counts else 0.0

    challenge_events = challenge_events or []
    if challenge_events:
        failed = sum(1 for c in challenge_events if not c.get("passed"))
        challenge_fail_rate = failed / len(challenge_events)
    else:
        challenge_fail_rate = 0.0

    return {
        "requests_per_min":   n / (window_seconds / 60.0),
        "unique_ips":         float(unique_ips),
        "unique_paths":       float(unique_paths),
        "bot_ratio":          bot_count / n,
        "error_rate":         error_count / n,
        "avg_response_ms":    float(avg_ms),
        "path_concentration": path_concentration,
        "challenge_fail_rate": challenge_fail_rate,
    }


# ─────────────────────────────────────────────────────────────────
# ANOMALY EVENT
# ─────────────────────────────────────────────────────────────────

@dataclass
class AnomalyEvent:
    detected_at: float
    score:       float          # IsolationForest decision_function value; lower = more anomalous
    features:    dict
    message:     str


# ─────────────────────────────────────────────────────────────────
# DETECTOR
# ─────────────────────────────────────────────────────────────────

class AnomalyDetector:
    """
    Stateful ML anomaly detector. One instance per process (see the
    `detector` singleton below, mirroring ddos_detector.py's convention).
    """

    MIN_SAMPLES_TO_FIT = 30       # need this much history before the model means anything
    REFIT_EVERY         = 20      # re-fit on a fresh slice of history every N windows
    CONTAMINATION        = 0.05   # assume ~5% of historical windows were themselves anomalous
    ALERT_COOLDOWN_SECS  = 300    # same 5-minute cooldown convention as the DDoS detector

    def __init__(self, max_history: int = 10_080):  # ~7 days of 1-minute windows
        self._history: list[list[float]] = []
        self._max_history = max_history
        self._model: Optional[IsolationForest] = None
        self._lock = threading.Lock()
        self._windows_since_fit = 0
        self._last_alert = 0.0

    def record_window(self, features: dict) -> Optional[AnomalyEvent]:
        """Record one time-bucket's feature vector and check it for anomaly."""
        vector = [float(features.get(name, 0.0)) for name in FEATURE_NAMES]

        with self._lock:
            self._history.append(vector)
            if len(self._history) > self._max_history:
                self._history.pop(0)
            self._windows_since_fit += 1

            needs_first_fit = self._model is None and len(self._history) >= self.MIN_SAMPLES_TO_FIT
            needs_refit      = self._windows_since_fit >= self.REFIT_EVERY and len(self._history) >= self.MIN_SAMPLES_TO_FIT

            if needs_first_fit or needs_refit:
                self._fit()
                self._windows_since_fit = 0

        return self._check(vector, features)

    def _fit(self):
        """Fit IsolationForest on all accumulated history."""
        X = np.array(self._history)
        model = IsolationForest(
            n_estimators=100,
            contamination=self.CONTAMINATION,
            random_state=42,
        )
        model.fit(X)
        self._model = model

    def _check(self, vector: list[float], features: dict) -> Optional[AnomalyEvent]:
        if self._model is None:
            return None  # not enough history yet to judge anything

        is_outlier = self._model.predict([vector])[0] == -1
        if not is_outlier:
            return None
        score = float(self._model.decision_function([vector])[0])

        now = time.time()
        if now - self._last_alert < self.ALERT_COOLDOWN_SECS:
            return None
        self._last_alert = now

        event = AnomalyEvent(
            detected_at=now,
            score=round(score, 4),
            features=features,
            message=self._describe(features, score),
        )
        self._persist(event)
        self._trigger_alerts(event)
        return event

    def _describe(self, features: dict, score: float) -> str:
        return (
            f"Traffic pattern anomaly detected (score {score:.3f}): "
            f"{features.get('requests_per_min', 0):.0f} req/min, "
            f"error rate {features.get('error_rate', 0) * 100:.0f}%, "
            f"{features.get('unique_paths', 0):.0f} unique paths, "
            f"{features.get('bot_ratio', 0) * 100:.0f}% bot traffic."
        )

    def snapshot(self) -> dict:
        return {
            "history_size":       len(self._history),
            "model_fitted":       self._model is not None,
            "windows_since_fit":  self._windows_since_fit,
        }

    # ── Persistence / alerting (same pattern as ddos_detector.py) ────

    def _persist(self, event: AnomalyEvent):
        try:
            import json
            from app.database import get_db
            with get_db() as db:
                db.execute("""
                    INSERT INTO alerts (type, severity, message, details)
                    VALUES (?,?,?,?)
                """, (
                    "ml_anomaly",
                    "medium",
                    event.message,
                    json.dumps({"score": event.score, "features": event.features}),
                ))
        except Exception as e:
            print(f"[AnomalyDetector] Failed to persist alert: {e}")

    def _trigger_alerts(self, event: AnomalyEvent):
        try:
            from app.workers.alerts import send_alert
            send_alert(
                alert_type="ml_anomaly",
                severity="medium",
                message=event.message,
                details={"score": event.score, **event.features},
            )
        except Exception as e:
            print(f"[AnomalyDetector] Alert delivery failed: {e}")


# Singleton — mirrors ddos_detector.py's `detector` convention
detector = AnomalyDetector()


# ─────────────────────────────────────────────────────────────────
# PERIODIC WORKER
# ─────────────────────────────────────────────────────────────────

def _run_periodic_check():
    """Pull the last minute of requests and challenge outcomes from the
    DB, compute features, feed the detector."""
    try:
        from app.database import get_db
        cutoff = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(time.time() - 60))
        with get_db() as db:
            rows = db.execute(
                "SELECT ip, path, is_bot, status_code, response_ms FROM requests WHERE timestamp >= ?",
                (cutoff,),
            ).fetchall()
            challenge_rows = db.execute(
                "SELECT ip, challenge_type, passed FROM challenge_events WHERE timestamp >= ?",
                (cutoff,),
            ).fetchall()
        requests = [dict(r) for r in rows]
        challenge_events = [dict(r) for r in challenge_rows]
        features = compute_window_features(requests, challenge_events=challenge_events)
        detector.record_window(features)
    except Exception as e:
        print(f"[AnomalyDetector] Periodic check failed: {e}")


def start_periodic_check(scheduler):
    """Register a job that runs every minute — call from main.py's startup, alongside the other workers."""
    try:
        from apscheduler.triggers.interval import IntervalTrigger
        scheduler.add_job(
            _run_periodic_check,
            IntervalTrigger(minutes=1),
            id="ml_anomaly_check",
            replace_existing=True,
        )
        print("[AnomalyDetector] Periodic anomaly check scheduled every 1 minute")
    except ImportError:
        print("[AnomalyDetector] APScheduler not available")
