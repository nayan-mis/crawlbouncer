"""
Tests for app.workers.retention_job.prune_old_data — the fix for the
"requests/waf_events grow forever" finding from the security audit
(docs/AUDIT.md section 8.4).
"""
import uuid
from datetime import datetime, timedelta
from app.database import get_db
from app.workers.retention_job import prune_old_data


def _insert_domain(db, domain_id, publisher_id="pub-retention-test"):
    db.execute(
        "INSERT OR IGNORE INTO publishers (id, email, password_hash) VALUES (?,?,'x')",
        (publisher_id, f"{publisher_id}@test.com"),
    )
    db.execute(
        "INSERT INTO domains (id, publisher_id, domain, active) VALUES (?,?,?,1)",
        (domain_id, publisher_id, f"{domain_id}.example.com"),
    )


def _iso(days_ago):
    return (datetime.utcnow() - timedelta(days=days_ago)).strftime("%Y-%m-%d %H:%M:%S")


class TestPruneOldData:

    def test_deletes_requests_older_than_the_window_keeps_newer_ones(self):
        domain_id = "dom-retention-" + uuid.uuid4().hex[:8]
        with get_db() as db:
            _insert_domain(db, domain_id)
            db.execute("INSERT INTO requests (domain_id, ip, timestamp) VALUES (?,?,?)",
                       (domain_id, "1.1.1.1", _iso(500)))  # old — should be pruned
            db.execute("INSERT INTO requests (domain_id, ip, timestamp) VALUES (?,?,?)",
                       (domain_id, "2.2.2.2", _iso(10)))   # recent — must survive

        result = prune_old_data(retention_days=400)
        assert result["requests_deleted"] >= 1

        with get_db() as db:
            remaining = db.execute(
                "SELECT ip FROM requests WHERE domain_id=?", (domain_id,)
            ).fetchall()
        remaining_ips = {r["ip"] for r in remaining}
        assert "1.1.1.1" not in remaining_ips, "old request row survived pruning"
        assert "2.2.2.2" in remaining_ips, "recent request row was incorrectly pruned"

    def test_deletes_waf_events_older_than_the_window_keeps_newer_ones(self):
        domain_id = "dom-retentionwaf-" + uuid.uuid4().hex[:8]
        with get_db() as db:
            _insert_domain(db, domain_id)
            db.execute("INSERT INTO waf_events (domain_id, ip, rule_name, timestamp) VALUES (?,?,?,?)",
                       (domain_id, "3.3.3.3", "sql_injection", _iso(500)))
            db.execute("INSERT INTO waf_events (domain_id, ip, rule_name, timestamp) VALUES (?,?,?,?)",
                       (domain_id, "4.4.4.4", "sql_injection", _iso(10)))

        result = prune_old_data(retention_days=400)
        assert result["waf_events_deleted"] >= 1

        with get_db() as db:
            remaining = db.execute(
                "SELECT ip FROM waf_events WHERE domain_id=?", (domain_id,)
            ).fetchall()
        remaining_ips = {r["ip"] for r in remaining}
        assert "3.3.3.3" not in remaining_ips
        assert "4.4.4.4" in remaining_ips

    def test_default_window_does_not_touch_recent_data(self):
        """The default window must comfortably exceed the dashboard's
        longest lookback (90 days): a 60-day-old row must survive."""
        domain_id = "dom-retentionyear-" + uuid.uuid4().hex[:8]
        with get_db() as db:
            _insert_domain(db, domain_id)
            db.execute("INSERT INTO requests (domain_id, ip, timestamp) VALUES (?,?,?)",
                       (domain_id, "5.5.5.5", _iso(60)))  # ~2 months old

        prune_old_data()  # uses the real configured default, not an override

        with get_db() as db:
            row = db.execute(
                "SELECT ip FROM requests WHERE domain_id=? AND ip='5.5.5.5'", (domain_id,)
            ).fetchone()
        assert row is not None, "a 60-day-old request was pruned by the default retention window"

    def test_does_not_touch_unrelated_tables(self):
        """Pruning must be scoped to requests/waf_events only —
        domains and everything else this
        session's earlier cascade-delete fix touches must be
        completely unaffected by a retention sweep."""
        domain_id = "dom-retentionscope-" + uuid.uuid4().hex[:8]
        with get_db() as db:
            _insert_domain(db, domain_id)
            db.execute("INSERT INTO requests (domain_id, ip, timestamp) VALUES (?,?,?)",
                       (domain_id, "6.6.6.6", _iso(500)))

        before = None
        with get_db() as db:
            before = db.execute("SELECT COUNT(*) FROM domains WHERE id=?", (domain_id,)).fetchone()[0]
        assert before == 1

        prune_old_data(retention_days=400)

        with get_db() as db:
            after = db.execute("SELECT COUNT(*) FROM domains WHERE id=?", (domain_id,)).fetchone()[0]
        assert after == 1, "pruning requests incorrectly deleted the domain row too"

    def test_returns_a_summary_dict_for_observability(self):
        result = prune_old_data(retention_days=400)
        assert set(result.keys()) == {"cutoff", "requests_deleted", "waf_events_deleted"}
        assert isinstance(result["requests_deleted"], int)
        assert isinstance(result["waf_events_deleted"], int)
