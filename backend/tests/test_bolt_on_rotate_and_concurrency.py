"""
Tests for POST /api/domains/{id}/rotate-key (bolt-on edge key rotation),
plus concurrency/race tests around bolt-on domain deletion and key
rotation — the two operations most likely to interact badly under
concurrent access, since both mutate the same row that /v1/decide
reads on every request.
"""
import threading
import pytest


def _create_bolt_on_domain(client, auth_headers, domain="rotatetest.com"):
    resp = client.post("/api/domains/", headers=auth_headers, json={
        "domain": domain, "integration_mode": "bolt_on",
    })
    assert resp.status_code == 200, resp.text
    return resp.json()


class TestRotateEdgeKey:

    def test_rotate_returns_a_new_key(self, client, auth_headers):
        data = _create_bolt_on_domain(client, auth_headers, "rotatebasic.com")
        old_key = data["edge_api_key"]
        resp = client.post(f"/api/domains/{data['id']}/rotate-key", headers=auth_headers)
        assert resp.status_code == 200, resp.text
        new_key = resp.json()["edge_api_key"]
        assert new_key != old_key
        assert new_key.startswith("cb_edge_")

    def test_old_key_stops_working_after_rotation(self, client, auth_headers):
        """The whole point of rotation — verify it behaviorally, not
        just that a new key string came back."""
        data = _create_bolt_on_domain(client, auth_headers, "rotateinvalidatesold.com")
        old_key = data["edge_api_key"]
        client.post(f"/api/domains/{data['id']}/rotate-key", headers=auth_headers)

        resp = client.post("/v1/decide",
            headers={"X-Edge-Key": old_key},
            json={"path": "/article", "user_agent": "GPTBot/1.0"})
        assert resp.status_code == 401

    def test_new_key_works_immediately(self, client, auth_headers):
        data = _create_bolt_on_domain(client, auth_headers, "rotatenewworks.com")
        new_key = client.post(f"/api/domains/{data['id']}/rotate-key", headers=auth_headers).json()["edge_api_key"]

        resp = client.post("/v1/decide",
            headers={"X-Edge-Key": new_key},
            json={"path": "/article", "user_agent": "Mozilla/5.0 (real browser)"})
        assert resp.status_code == 200
        assert resp.json()["action"] == "allow"

    def test_reverse_proxy_domain_has_no_key_to_rotate(self, client, auth_headers):
        resp = client.post("/api/domains/", headers=auth_headers, json={
            "domain": "notbolton.com", "origin_url": "https://93.184.216.34",
        })
        domain_id = resp.json()["id"]
        rotate = client.post(f"/api/domains/{domain_id}/rotate-key", headers=auth_headers)
        assert rotate.status_code == 400

    def test_cannot_rotate_another_publishers_domain(self, client, auth_headers, free_auth_headers):
        """IDOR check: publisher B must not be able to rotate (and
        thereby invalidate, denial-of-service style) publisher A's
        edge key just by guessing/enumerating the domain id."""
        data = _create_bolt_on_domain(client, auth_headers, "rotatecrosstenant.com")
        old_key = data["edge_api_key"]

        resp = client.post(f"/api/domains/{data['id']}/rotate-key", headers=free_auth_headers)
        assert resp.status_code == 404

        # And the real owner's key must still work — the rejected
        # cross-tenant attempt must not have mutated anything.
        check = client.post("/v1/decide",
            headers={"X-Edge-Key": old_key},
            json={"path": "/article", "user_agent": "Mozilla/5.0 (real browser)"})
        assert check.status_code == 200

    def test_rotate_nonexistent_domain_404s(self, client, auth_headers):
        resp = client.post("/api/domains/doesnotexist/rotate-key", headers=auth_headers)
        assert resp.status_code == 404


class TestDomainDeletionCascade:
    """Real bug found during this session's review, not something
    introduced by it: foreign_keys=ON is enforced (database.py), and
    8 tables reference domains.id, but remove_domain only ever cleaned
    up crawler_rules. Deleting a domain that had a path rule, logged
    traffic, a WAF event, or a mirror override raised sqlite3.IntegrityError and 500'd the
    whole request — i.e. any domain that had ever served real traffic
    could not be removed at all."""

    def test_delete_with_path_rule_does_not_500(self, client, auth_headers):
        data = client.post("/api/domains/", headers=auth_headers, json={
            "domain": "cascadepathrule.com", "integration_mode": "bolt_on",
        }).json()
        client.put(f"/api/rules/{data['id']}/paths", headers=auth_headers,
                   json={"path_prefix": "/private/", "action": "block"})
        resp = client.delete(f"/api/domains/{data['id']}", headers=auth_headers)
        assert resp.status_code == 200, resp.text

    def test_delete_with_logged_requests_does_not_500(self, client, auth_headers):
        """The most realistic trigger: a domain that has ever served
        traffic has rows in `requests`. This is the case most likely
        to actually happen to a real publisher, not an edge case."""
        data = client.post("/api/domains/", headers=auth_headers, json={
            "domain": "cascaderequests.com", "integration_mode": "bolt_on",
        }).json()
        from app.database import get_db
        with get_db() as db:
            db.execute(
                "INSERT INTO requests (domain_id, ip, path, is_bot) VALUES (?,?,?,?)",
                (data["id"], "1.2.3.4", "/article", 1)
            )
        resp = client.delete(f"/api/domains/{data['id']}", headers=auth_headers)
        assert resp.status_code == 200, resp.text

    def test_delete_with_waf_event_does_not_500(self, client, auth_headers):
        data = client.post("/api/domains/", headers=auth_headers, json={
            "domain": "cascadewaf.com", "integration_mode": "bolt_on",
        }).json()
        from app.database import get_db
        with get_db() as db:
            db.execute(
                "INSERT INTO waf_events (domain_id, ip, path, rule_name, severity) VALUES (?,?,?,?,?)",
                (data["id"], "1.2.3.4", "/../etc/passwd", "path_traversal", "high")
            )
        resp = client.delete(f"/api/domains/{data['id']}", headers=auth_headers)
        assert resp.status_code == 200, resp.text

    def test_delete_with_mirror_setting_does_not_500(self, client, auth_headers):
        data = client.post("/api/domains/", headers=auth_headers, json={
            "domain": "cascademirror.com", "integration_mode": "bolt_on",
        }).json()
        from app.database import get_db
        with get_db() as db:
            db.execute(
                "INSERT INTO mirror_settings (domain_id, path, serve_mode) VALUES (?,?,?)",
                (data["id"], "/article/*", "agent")
            )
        resp = client.delete(f"/api/domains/{data['id']}", headers=auth_headers)
        assert resp.status_code == 200, resp.text

    def test_delete_actually_removes_dependent_rows_not_just_avoids_500(self, client, auth_headers):
        """Confirm this is a real fix and not e.g. a silently-swallowed
        exception — the dependent rows must actually be gone, not just
        no-longer-blocking the delete."""
        data = client.post("/api/domains/", headers=auth_headers, json={
            "domain": "cascadeverify.com", "integration_mode": "bolt_on",
        }).json()
        domain_id = data["id"]
        client.put(f"/api/rules/{domain_id}/paths", headers=auth_headers,
                   json={"path_prefix": "/x/", "action": "block"})

        from app.database import get_db
        with get_db() as db:
            db.execute("INSERT INTO requests (domain_id, ip, path) VALUES (?,?,?)", (domain_id, "9.9.9.9", "/x"))

        resp = client.delete(f"/api/domains/{domain_id}", headers=auth_headers)
        assert resp.status_code == 200

        with get_db() as db:
            for table in ("path_rules", "requests", "domains"):
                count = db.execute(f"SELECT COUNT(*) FROM {table} WHERE {'id' if table == 'domains' else 'domain_id'}=?", (domain_id,)).fetchone()[0]
                assert count == 0, f"{table} still has rows for deleted domain {domain_id}"

    def test_reverse_proxy_domain_also_affected(self, client, auth_headers):
        """This bug is not bolt-on specific — path_rules/requests/etc.
        are shared by both integration modes."""
        resp = client.post("/api/domains/", headers=auth_headers, json={
            "domain": "cascadereverseproxy.com", "origin_url": "https://93.184.216.34",
        })
        domain_id = resp.json()["id"]
        client.put(f"/api/rules/{domain_id}/paths", headers=auth_headers,
                   json={"path_prefix": "/y/", "action": "block"})
        delete_resp = client.delete(f"/api/domains/{domain_id}", headers=auth_headers)
        assert delete_resp.status_code == 200, delete_resp.text

    def test_concurrent_rotations_leave_exactly_one_valid_key(self, client, auth_headers):
        """Fire N rotate-key calls at the same domain simultaneously.
        Whichever write lands last in SQLite's serialized-commit order
        should be the only key that authenticates afterward — no
        crashes, no two-keys-both-valid state, no domain left with an
        unusable/corrupted hash."""
        data = _create_bolt_on_domain(client, auth_headers, "rotateconcurrent.com")
        domain_id = data["id"]
        n = 12
        results = [None] * n
        errors = []

        def rotate(i):
            try:
                r = client.post(f"/api/domains/{domain_id}/rotate-key", headers=auth_headers)
                results[i] = r.json().get("edge_api_key") if r.status_code == 200 else None
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=rotate, args=(i,)) for i in range(n)]
        for t in threads: t.start()
        for t in threads: t.join()

        assert not errors, f"concurrent rotation raised: {errors}"
        keys_returned = [k for k in results if k]
        assert len(keys_returned) == n, "every concurrent rotation should still succeed with 200"

        # Exactly one of the n returned keys should now actually work —
        # whichever DB write committed last.
        working = []
        for key in set(keys_returned):
            r = client.post("/v1/decide",
                headers={"X-Edge-Key": key},
                json={"path": "/x", "user_agent": "Mozilla/5.0 (real browser)"})
            if r.status_code == 200:
                working.append(key)
        assert len(working) == 1, f"expected exactly one live key after concurrent rotation, got {len(working)}"

    def test_delete_during_concurrent_decide_calls_never_500s(self, client, auth_headers):
        """Spam /v1/decide with a valid key on one thread while another
        thread deletes the domain mid-flight. Every response — before,
        during, and after the delete — must be a clean 200 or 401,
        never a 500 (e.g. from a row disappearing between the
        require_edge_key lookup and a later read in the same request)."""
        data = _create_bolt_on_domain(client, auth_headers, "rotatedeleteduring.com")
        domain_id, edge_key = data["id"], data["edge_api_key"]

        stop = threading.Event()
        statuses = []
        lock = threading.Lock()

        def hammer_decide():
            while not stop.is_set():
                r = client.post("/v1/decide",
                    headers={"X-Edge-Key": edge_key},
                    json={"path": "/x", "user_agent": "GPTBot/1.0"})
                with lock:
                    statuses.append(r.status_code)

        workers = [threading.Thread(target=hammer_decide) for _ in range(4)]
        for w in workers: w.start()

        # Let a few requests land first, then delete mid-stream.
        import time; time.sleep(0.05)
        delete_resp = client.delete(f"/api/domains/{domain_id}", headers=auth_headers)
        assert delete_resp.status_code == 200

        time.sleep(0.1)
        stop.set()
        for w in workers: w.join()

        assert statuses, "no requests were recorded — test didn't exercise anything"
        bad = [s for s in statuses if s not in (200, 401, 403)]
        assert not bad, f"got unexpected status codes during concurrent delete: {bad}"

        # And it must have actually converged: the tail end of the
        # requests, after the delete committed, should be consistently
        # rejected, not still occasionally succeeding.
        tail = statuses[-5:] if len(statuses) >= 5 else statuses
        assert all(s in (401, 403) for s in tail), f"key still worked after domain deletion: {tail}"

