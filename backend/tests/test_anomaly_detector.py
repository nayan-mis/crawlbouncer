"""
CrawlBouncer — ML Anomaly Detector Tests
Covers feature extraction from raw request batches, cold-start behavior
(no alerts before enough history exists), model fitting, anomaly scoring
against a learned baseline, alert cooldown, and periodic worker scheduling.
"""
import random
from unittest.mock import patch, MagicMock

from app.workers.anomaly_detector import (
    AnomalyDetector,
    FEATURE_NAMES,
    compute_window_features,
    start_periodic_check,
)


def _seed_baseline(det: AnomalyDetector, n: int = 60):
    """Feed realistic-variance 'normal' windows so IsolationForest has something to calibrate against."""
    rng = random.Random(42)
    for _ in range(n):
        normal = {
            "requests_per_min":   100 + rng.uniform(-10, 10),
            "unique_ips":         20 + rng.uniform(-3, 3),
            "unique_paths":       15 + rng.uniform(-2, 2),
            "bot_ratio":          0.3 + rng.uniform(-0.05, 0.05),
            "error_rate":         0.01 + rng.uniform(-0.005, 0.005),
            "avg_response_ms":    80 + rng.uniform(-10, 10),
            "path_concentration": 0.2 + rng.uniform(-0.03, 0.03),
        }
        det.record_window(normal)
    det._last_alert = 0.0  # baseline seeding may have tripped a spurious cooldown; clear it before the real assertion


# ─────────────────────────────────────────────────────────────────
# FEATURE EXTRACTION
# ─────────────────────────────────────────────────────────────────

class TestComputeWindowFeatures:

    def test_empty_batch_returns_zeroed_features(self):
        features = compute_window_features([])
        assert set(features.keys()) == set(FEATURE_NAMES)
        assert all(v == 0.0 for v in features.values())

    def test_counts_unique_ips_and_paths(self):
        requests = [
            {"ip": "1.1.1.1", "path": "/a", "is_bot": False, "status_code": 200, "response_ms": 50},
            {"ip": "1.1.1.1", "path": "/b", "is_bot": False, "status_code": 200, "response_ms": 60},
            {"ip": "2.2.2.2", "path": "/a", "is_bot": True,  "status_code": 200, "response_ms": 40},
        ]
        features = compute_window_features(requests)
        assert features["unique_ips"] == 2
        assert features["unique_paths"] == 2
        assert round(features["bot_ratio"], 3) == round(1 / 3, 3)

    def test_error_rate_reflects_4xx_5xx_responses(self):
        requests = [
            {"ip": "1.1.1.1", "path": "/a", "is_bot": False, "status_code": 200, "response_ms": 10},
            {"ip": "1.1.1.1", "path": "/a", "is_bot": False, "status_code": 500, "response_ms": 10},
            {"ip": "1.1.1.1", "path": "/a", "is_bot": False, "status_code": 404, "response_ms": 10},
            {"ip": "1.1.1.1", "path": "/a", "is_bot": False, "status_code": 200, "response_ms": 10},
        ]
        features = compute_window_features(requests)
        assert features["error_rate"] == 0.5

    def test_path_concentration_high_when_single_path_dominates(self):
        requests = [{"ip": f"{i}.0.0.0", "path": "/hot", "is_bot": False, "status_code": 200, "response_ms": 10} for i in range(9)]
        requests.append({"ip": "9.0.0.0", "path": "/other", "is_bot": False, "status_code": 200, "response_ms": 10})
        features = compute_window_features(requests)
        assert features["path_concentration"] == 0.9

    def test_handles_missing_fields_gracefully(self):
        requests = [{"ip": "1.1.1.1"}, {"path": "/x"}]
        features = compute_window_features(requests)
        assert features["error_rate"] == 0.0  # missing status_code defaults to 200 (not an error)
        assert features["avg_response_ms"] == 0.0

    def test_requests_per_min_scales_with_window_size(self):
        requests = [{"ip": "1.1.1.1", "path": "/a", "is_bot": False, "status_code": 200, "response_ms": 10}] * 30
        features = compute_window_features(requests, window_seconds=30.0)
        assert features["requests_per_min"] == 60.0  # 30 reqs in 30s == 60/min

    def test_challenge_fail_rate_defaults_to_zero_when_no_challenges(self):
        requests = [{"ip": "1.1.1.1", "path": "/a", "is_bot": True, "status_code": 200, "response_ms": 10}]
        features = compute_window_features(requests, challenge_events=[])
        assert features["challenge_fail_rate"] == 0.0

    def test_challenge_fail_rate_computed_correctly(self):
        requests = [{"ip": "1.1.1.1", "path": "/a", "is_bot": True, "status_code": 200, "response_ms": 10}]
        challenge_events = [
            {"passed": 1}, {"passed": 1}, {"passed": 0}, {"passed": 0},
        ]
        features = compute_window_features(requests, challenge_events=challenge_events)
        assert features["challenge_fail_rate"] == 0.5

    def test_challenge_fail_rate_all_passed(self):
        requests = [{"ip": "1.1.1.1", "path": "/a", "is_bot": False, "status_code": 200, "response_ms": 10}]
        challenge_events = [{"passed": 1}, {"passed": 1}]
        features = compute_window_features(requests, challenge_events=challenge_events)
        assert features["challenge_fail_rate"] == 0.0


class TestPeriodicWorkerIncludesChallengeEvents:

    def test_run_periodic_check_feeds_challenge_events_to_detector(self, monkeypatch):
        """Regression guard for the periodic worker itself, not just
        compute_window_features in isolation — confirms the DB query for
        challenge_events was actually wired in, not just the function
        signature that accepts it."""
        from app.database import get_db
        from app.workers import anomaly_detector as mod

        with get_db() as db:
            db.execute(
                "INSERT INTO requests (ip, path, is_bot, status_code, response_ms) VALUES (?,?,?,?,?)",
                ("198.51.100.5", "/periodic-test", 1, 200, 20)
            )
            db.execute(
                "INSERT INTO challenge_events (ip, challenge_type, passed) VALUES (?,?,?)",
                ("198.51.100.5", "pow", 0)
            )

        captured = {}
        def fake_record_window(features):
            captured.update(features)
            return None
        monkeypatch.setattr(mod.detector, "record_window", fake_record_window)

        mod._run_periodic_check()

        assert captured.get("challenge_fail_rate") == 1.0


# ─────────────────────────────────────────────────────────────────
# COLD START — no model yet
# ─────────────────────────────────────────────────────────────────

class TestColdStart:

    def test_no_alert_before_minimum_history(self):
        det = AnomalyDetector()
        normal = {"requests_per_min": 100, "unique_ips": 20, "unique_paths": 15,
                  "bot_ratio": 0.3, "error_rate": 0.01, "avg_response_ms": 80, "path_concentration": 0.2}
        for _ in range(det.MIN_SAMPLES_TO_FIT - 1):
            event = det.record_window(normal)
            assert event is None
        snap = det.snapshot()
        assert snap["model_fitted"] is False

    def test_model_fits_once_minimum_history_reached(self):
        det = AnomalyDetector()
        normal = {"requests_per_min": 100, "unique_ips": 20, "unique_paths": 15,
                  "bot_ratio": 0.3, "error_rate": 0.01, "avg_response_ms": 80, "path_concentration": 0.2}
        for _ in range(det.MIN_SAMPLES_TO_FIT):
            det.record_window(normal)
        assert det.snapshot()["model_fitted"] is True


# ─────────────────────────────────────────────────────────────────
# ANOMALY DETECTION AGAINST A LEARNED BASELINE
# ─────────────────────────────────────────────────────────────────

class TestAnomalyDetection:

    def test_flags_clearly_anomalous_window(self):
        det = AnomalyDetector()
        _seed_baseline(det)

        anomalous = {
            "requests_per_min":   100,     # volume looks normal...
            "unique_ips":         2,       # ...but almost no ip diversity
            "unique_paths":       1,       # ...and everything hits one path
            "bot_ratio":          0.99,
            "error_rate":         0.85,    # ...with a huge error spike
            "avg_response_ms":    2500,
            "path_concentration": 0.99,
        }
        event = det.record_window(anomalous)
        assert event is not None
        assert event.score < 0
        assert "anomaly" in event.message.lower()

    def test_normal_window_after_baseline_not_flagged(self):
        det = AnomalyDetector()
        _seed_baseline(det)
        normal = {
            "requests_per_min": 102, "unique_ips": 19, "unique_paths": 16,
            "bot_ratio": 0.31, "error_rate": 0.012, "avg_response_ms": 82,
            "path_concentration": 0.21,
        }
        event = det.record_window(normal)
        assert event is None

    def test_alert_cooldown_suppresses_rapid_repeat_alerts(self):
        det = AnomalyDetector()
        _seed_baseline(det)
        anomalous = {
            "requests_per_min": 100, "unique_ips": 2, "unique_paths": 1,
            "bot_ratio": 0.99, "error_rate": 0.85, "avg_response_ms": 2500,
            "path_concentration": 0.99,
        }
        first  = det.record_window(anomalous)
        second = det.record_window(anomalous)
        assert first is not None
        assert second is None  # cooldown active


# ─────────────────────────────────────────────────────────────────
# ALERT DELIVERY
# ─────────────────────────────────────────────────────────────────

class TestAlertDelivery:

    def test_fires_alert_through_shared_alerts_module(self):
        det = AnomalyDetector()
        _seed_baseline(det)

        with patch("app.workers.alerts.send_alert") as mock_send:
            det.record_window({
                "requests_per_min": 100, "unique_ips": 1, "unique_paths": 1,
                "bot_ratio": 1.0, "error_rate": 0.99, "avg_response_ms": 5000,
                "path_concentration": 1.0,
            })
        mock_send.assert_called_once()
        assert mock_send.call_args.kwargs["alert_type"] == "ml_anomaly"

    def test_alert_delivery_failure_does_not_raise(self):
        det = AnomalyDetector()
        _seed_baseline(det)

        with patch("app.workers.alerts.send_alert", side_effect=Exception("smtp down")):
            event = det.record_window({
                "requests_per_min": 100, "unique_ips": 1, "unique_paths": 1,
                "bot_ratio": 1.0, "error_rate": 0.99, "avg_response_ms": 5000,
                "path_concentration": 1.0,
            })
        assert event is not None  # detection itself still succeeds even if delivery fails


# ─────────────────────────────────────────────────────────────────
# PERIODIC WORKER SCHEDULING
# ─────────────────────────────────────────────────────────────────

class TestPeriodicScheduling:

    def test_registers_per_minute_job(self):
        fake_scheduler = MagicMock()
        start_periodic_check(fake_scheduler)
        fake_scheduler.add_job.assert_called_once()
        _, kwargs = fake_scheduler.add_job.call_args
        assert kwargs["id"] == "ml_anomaly_check"
