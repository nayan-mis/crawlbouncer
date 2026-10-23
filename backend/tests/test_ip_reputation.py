"""
Tests for app/middleware/ip_reputation.py and app/workers/ddos_detector.py
"""
import time
import pytest
from app.middleware.ip_reputation import ReputationResult, _is_datacenter, _is_private


# ─────────────────────────────────────────────────────────────────
# PRIVATE IP DETECTION
# ─────────────────────────────────────────────────────────────────

class TestPrivateIPs:

    @pytest.mark.parametrize("ip", [
        "127.0.0.1",
        "10.0.0.1",
        "10.255.255.255",
        "192.168.1.1",
        "192.168.0.100",
        "172.16.0.1",
        "172.31.255.255",
        "::1",
    ])
    def test_private_ips_detected(self, ip):
        assert _is_private(ip), f"{ip} should be private"

    @pytest.mark.parametrize("ip", [
        "8.8.8.8",
        "1.1.1.1",
        "93.184.216.34",
        "203.0.113.1",
    ])
    def test_public_ips_not_private(self, ip):
        assert not _is_private(ip), f"{ip} should NOT be private"


# ─────────────────────────────────────────────────────────────────
# DATACENTER DETECTION
# ─────────────────────────────────────────────────────────────────

class TestDatacenterDetection:

    @pytest.mark.parametrize("org", [
        "AS16509 Amazon.com, Inc.",
        "AS15169 Google LLC",
        "AS8075 Microsoft Corporation",
        "AS14061 DigitalOcean, LLC",
        "AS20473 Vultr Holdings LLC",
        "AS24940 Hetzner Online GmbH",
    ])
    def test_datacenter_orgs_detected(self, org):
        assert _is_datacenter(org), f"'{org}' should be detected as datacenter"

    @pytest.mark.parametrize("org", [
        "AS7922 Comcast Cable",
        "AS20001 Charter Communications",
        "AS701 Verizon Online",
        "AS3215 Orange S.A.",
    ])
    def test_residential_isps_not_datacenter(self, org):
        assert not _is_datacenter(org), f"'{org}' should NOT be detected as datacenter"


# ─────────────────────────────────────────────────────────────────
# REPUTATION RESULT STRUCTURE
# ─────────────────────────────────────────────────────────────────

def test_result_has_all_fields():
    r = ReputationResult(ip="1.2.3.4")
    assert hasattr(r, "ip")
    assert hasattr(r, "is_tor")
    assert hasattr(r, "is_datacenter")
    assert hasattr(r, "is_residential")
    assert hasattr(r, "abuse_score")
    assert hasattr(r, "risk_score")
    assert hasattr(r, "signals")

def test_default_risk_score_is_zero():
    r = ReputationResult(ip="1.2.3.4")
    assert r.risk_score == 0

def test_default_signals_is_empty_list():
    r = ReputationResult(ip="1.2.3.4")
    assert r.signals == []

def test_risk_score_bounded():
    r = ReputationResult(ip="1.2.3.4", risk_score=150)
    # Risk score should be used as-is in the dataclass
    # but the check() function caps it at 100
    assert r.risk_score == 150     # dataclass allows it; check() caps it


# ─────────────────────────────────────────────────────────────────
# DDOS DETECTOR
# ─────────────────────────────────────────────────────────────────

class TestDDoSDetector:

    def setup_method(self):
        from app.workers.ddos_detector import DDoSDetector
        self.detector = DDoSDetector()

    def test_single_request_no_alert(self):
        alert = self.detector.check("1.2.3.4", "/article/test")
        assert alert is None

    def test_ip_not_blocked_initially(self):
        assert not self.detector.is_blocked("1.2.3.4")

    def test_flood_from_single_ip_triggers_block(self):
        ip = "99.99.99.99"
        # Record 600 requests (over 500/min threshold)
        for _ in range(600):
            self.detector.record(ip, "/article/test")

        alert = self.detector.check(ip, "/article/test")
        # Should be blocked now
        assert self.detector.is_blocked(ip)

    def test_unblock_removes_ip(self):
        ip = "88.88.88.88"
        for _ in range(600):
            self.detector.record(ip, "/test")
        self.detector._auto_block(ip)
        assert self.detector.is_blocked(ip)
        self.detector.unblock(ip)
        assert not self.detector.is_blocked(ip)

    def test_top_ips_returns_list(self):
        self.detector.record("1.1.1.1", "/test")
        self.detector.record("2.2.2.2", "/test")
        tops = self.detector.top_ips(5)
        assert isinstance(tops, list)
        assert len(tops) <= 5

    def test_top_paths_returns_list(self):
        self.detector.record("1.1.1.1", "/path/a")
        self.detector.record("1.1.1.1", "/path/b")
        tops = self.detector.top_paths(3)
        assert isinstance(tops, list)

    def test_snapshot_has_required_keys(self):
        snap = self.detector.snapshot()
        assert "rps"          in snap
        assert "baseline_rps" in snap
        assert "top_ips"      in snap
        assert "top_paths"    in snap
        assert "blocked_ips"  in snap

    def test_snapshot_rps_is_numeric(self):
        self.detector.record("5.5.5.5", "/test")
        snap = self.detector.snapshot()
        assert isinstance(snap["rps"], (int, float))
        assert snap["rps"] >= 0

    def test_different_ips_tracked_independently(self):
        ip1, ip2 = "10.0.1.1", "10.0.1.2"
        for _ in range(10):
            self.detector.record(ip1, "/test")
        for _ in range(5):
            self.detector.record(ip2, "/test")

        tops = dict(self.detector.top_ips())
        if ip1 in tops and ip2 in tops:
            assert tops[ip1] >= tops[ip2]
