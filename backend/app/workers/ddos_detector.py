"""
CrawlBouncer — DDoS Detector
Monitors traffic patterns in real time.
Learns a 7-day baseline. Alerts when current traffic deviates significantly.
Auto-blocks attacking IPs by adding them to the rate limiter blocklist.
"""
from __future__ import annotations
import time
import threading
from collections import deque, defaultdict
from dataclasses import dataclass, field
from typing import Optional


# ─────────────────────────────────────────────────────────────────
# ATTACK EVENT
# ─────────────────────────────────────────────────────────────────

@dataclass
class AttackEvent:
    detected_at:   float
    attack_type:   str
    severity:      str              # low | medium | high | critical
    rps:           float            # requests per second at detection
    baseline_rps:  float
    top_ips:       list[str]
    top_path:      Optional[str]
    message:       str


# ─────────────────────────────────────────────────────────────────
# SLIDING COUNTERS
# ─────────────────────────────────────────────────────────────────

class _Counter:
    """Thread-safe sliding window counter."""

    def __init__(self, window: int = 60):
        self._window  = window
        self._events: deque[float] = deque()
        self._lock    = threading.Lock()

    def record(self):
        now = time.time()
        with self._lock:
            self._events.append(now)
            self._purge(now)

    def count(self) -> int:
        now = time.time()
        with self._lock:
            self._purge(now)
            return len(self._events)

    def rate_per_second(self) -> float:
        return self.count() / self._window

    def _purge(self, now: float):
        cutoff = now - self._window
        while self._events and self._events[0] < cutoff:
            self._events.popleft()


# ─────────────────────────────────────────────────────────────────
# DDOS DETECTOR
# ─────────────────────────────────────────────────────────────────

class DDoSDetector:
    """
    Stateful DDoS detector.
    - Records every request with IP and path
    - Computes rolling RPS over 60s window
    - Maintains a 7-day baseline (simple exponential moving average)
    - Fires alert when traffic exceeds threshold × baseline
    - Auto-blocks top attacking IPs
    """

    # Alert thresholds
    GLOBAL_SPIKE_FACTOR   = 5.0       # alert if rps > baseline × 5
    SINGLE_IP_LIMIT       = 500       # alert if one IP > 500 req/min
    PATH_CONCENTRATION    = 0.80      # alert if one path > 80% of traffic
    ERROR_RATE_THRESHOLD  = 0.50      # alert if error rate > 50%

    def __init__(self):
        self._global   = _Counter(window=60)
        self._ip_counts: defaultdict[str, _Counter]   = defaultdict(lambda: _Counter(window=60))
        self._path_counts: defaultdict[str, _Counter] = defaultdict(lambda: _Counter(window=60))

        # Exponential moving average baseline (7-day)
        self._baseline_rps = 0.0
        self._baseline_lock = threading.Lock()

        # Alert cooldown — same alert fires at most once per 5 minutes
        self._last_alert: dict[str, float] = {}
        self._alert_lock  = threading.Lock()

        # Auto-blocked IPs (shared with rate limiter)
        self._blocked_ips: set[str] = set()

        # Start baseline updater
        self._start_baseline_thread()

    # ── Record request ─────────────────────────────────────────────

    def record(self, ip: str, path: str, status_code: int = 200):
        """Call this for every request that passes through the proxy."""
        self._global.record()
        self._ip_counts[ip].record()
        self._path_counts[path].record()

    # ── Check for attack ───────────────────────────────────────────

    def check(self, ip: str, path: str) -> Optional[AttackEvent]:
        """
        Check current traffic patterns for attack signatures.
        Returns an AttackEvent if an attack is detected, None otherwise.
        """
        current_rps  = self._global.rate_per_second()
        baseline_rps = self._baseline_rps or max(current_rps, 0.1)

        # 1. Global spike
        if current_rps > baseline_rps * self.GLOBAL_SPIKE_FACTOR and current_rps > 5:
            return self._fire_alert("volume_spike", "high", current_rps, baseline_rps,
                                    f"Global RPS {current_rps:.1f} is {current_rps/baseline_rps:.1f}x above baseline ({baseline_rps:.1f})")

        # 2. Single IP flooding
        ip_rps = self._ip_counts[ip].count()
        if ip_rps > self.SINGLE_IP_LIMIT:
            self._auto_block(ip)
            return self._fire_alert("single_ip_flood", "critical", current_rps, baseline_rps,
                                    f"IP {ip} made {ip_rps} requests/min — auto-blocked")

        # 3. Path concentration (many IPs hitting same endpoint)
        total = self._global.count()
        if total > 50:
            path_count = self._path_counts[path].count()
            if path_count / total > self.PATH_CONCENTRATION:
                return self._fire_alert("path_concentration", "medium", current_rps, baseline_rps,
                                        f"{path_count/total*100:.0f}% of traffic targeting {path}")

        return None

    def is_blocked(self, ip: str) -> bool:
        return ip in self._blocked_ips

    def unblock(self, ip: str):
        self._blocked_ips.discard(ip)

    # ── Top offenders ──────────────────────────────────────────────

    def top_ips(self, n: int = 5) -> list[tuple[str, int]]:
        return sorted(
            [(ip, c.count()) for ip, c in self._ip_counts.items()],
            key=lambda x: x[1], reverse=True
        )[:n]

    def top_paths(self, n: int = 5) -> list[tuple[str, int]]:
        return sorted(
            [(p, c.count()) for p, c in self._path_counts.items()],
            key=lambda x: x[1], reverse=True
        )[:n]

    def snapshot(self) -> dict:
        """Current traffic snapshot for the alerting system."""
        return {
            "rps":          round(self._global.rate_per_second(), 2),
            "baseline_rps": round(self._baseline_rps, 2),
            "top_ips":      self.top_ips(),
            "top_paths":    self.top_paths(),
            "blocked_ips":  list(self._blocked_ips),
        }

    # ── Private helpers ────────────────────────────────────────────

    def _fire_alert(
        self,
        alert_type: str,
        severity: str,
        rps: float,
        baseline: float,
        message: str,
    ) -> Optional[AttackEvent]:
        """Fire an alert if cooldown has expired."""
        now = time.time()
        with self._alert_lock:
            last = self._last_alert.get(alert_type, 0)
            if now - last < 300:         # 5-minute cooldown
                return None
            self._last_alert[alert_type] = now

        tops = [ip for ip, _ in self.top_ips(3)]
        top_path = self.top_paths(1)[0][0] if self.top_paths(1) else None

        event = AttackEvent(
            detected_at=now,
            attack_type=alert_type,
            severity=severity,
            rps=round(rps, 2),
            baseline_rps=round(baseline, 2),
            top_ips=tops,
            top_path=top_path,
            message=message,
        )

        # Persist to DB and trigger alerts
        self._persist(event)
        self._trigger_alerts(event)

        return event

    def _auto_block(self, ip: str):
        """Add IP to the auto-block set and the rate limiter."""
        self._blocked_ips.add(ip)
        try:
            from app.middleware.rate_limiter import get_limiter
            get_limiter().reset(ip)
        except Exception:
            pass

    def _persist(self, event: AttackEvent):
        try:
            from app.database import get_db
            with get_db() as db:
                import json
                db.execute("""
                    INSERT INTO alerts (type, severity, message, details)
                    VALUES (?,?,?,?)
                """, (
                    event.attack_type,
                    event.severity,
                    event.message,
                    json.dumps({
                        "rps": event.rps,
                        "baseline_rps": event.baseline_rps,
                        "top_ips": event.top_ips,
                        "top_path": event.top_path,
                    }),
                ))
        except Exception as e:
            print(f"[DDoS] Failed to persist alert: {e}")

    def _trigger_alerts(self, event: AttackEvent):
        """Send email and Slack notifications for the attack event."""
        try:
            from app.workers.alerts import send_alert
            send_alert(
                alert_type=event.attack_type,
                severity=event.severity,
                message=event.message,
                details={
                    "rps":          event.rps,
                    "baseline_rps": event.baseline_rps,
                    "top_ips":      event.top_ips,
                },
            )
        except Exception as e:
            print(f"[DDoS] Alert delivery failed: {e}")

    def _start_baseline_thread(self):
        """Update baseline RPS every 60 seconds using exponential moving average."""
        def _update():
            while True:
                time.sleep(60)
                current = self._global.rate_per_second()
                with self._baseline_lock:
                    if self._baseline_rps == 0:
                        self._baseline_rps = current
                    else:
                        # EMA with α=0.1 (slow-moving baseline)
                        self._baseline_rps = 0.1 * current + 0.9 * self._baseline_rps

        t = threading.Thread(target=_update, daemon=True)
        t.start()


# Singleton used by main.py middleware
detector = DDoSDetector()
