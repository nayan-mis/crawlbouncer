"""
Tests for per-path rules (app/api/rules.py path_prefix overrides) —
both the settings API and that get_rule() actually applies them with
correct longest-prefix-match precedence over crawler-based rules.
"""
import pytest
from app.api.rules import get_rule, _invalidate_cache


class TestPathRuleLookup:

    def setup_method(self):
        from app.database import get_db
        with get_db() as db:
            # Establish a known baseline: no explicit crawler_rules row
            # for GPTBot (falls back to its registry default, "block"),
            # and no path rules. Other test files in this session-scoped
            # DB set and don't always clean up the GPTBot rule on this
            # same seeded domain, so relying on "nothing else touched
            # it" is not safe.
            db.execute("DELETE FROM crawler_rules WHERE domain_id='dom-test-001' AND crawler_name='GPTBot'")
            db.execute("DELETE FROM path_rules WHERE domain_id='dom-test-001'")
        _invalidate_cache("dom-test-001")

    def teardown_method(self):
        from app.database import get_db
        with get_db() as db:
            db.execute("DELETE FROM crawler_rules WHERE domain_id='dom-test-001' AND crawler_name='GPTBot'")
            db.execute("DELETE FROM path_rules WHERE domain_id='dom-test-001'")
        _invalidate_cache("dom-test-001")

    def test_no_path_rule_falls_back_to_crawler_rule(self, client, auth_headers):
        client.put("/api/rules/dom-test-001/GPTBot", headers=auth_headers,
                   json={"action": "block"})
        rule = get_rule("dom-test-001", "GPTBot", "/some/random/page")
        assert rule["action"] == "block"
        client.delete("/api/rules/dom-test-001/GPTBot", headers=auth_headers)

    def test_path_rule_overrides_crawler_rule(self, client, auth_headers):
        """A path rule must win even when the crawler rule says something
        completely different — this is the whole point of the feature."""
        client.put("/api/rules/dom-test-001/GPTBot", headers=auth_headers,
                   json={"action": "block"})
        client.put("/api/rules/dom-test-001/paths", headers=auth_headers,
                   json={"path_prefix": "/blog/", "action": "allow"})

        rule = get_rule("dom-test-001", "GPTBot", "/blog/my-post")
        assert rule["action"] == "allow"

        # Outside the path prefix, the crawler rule still applies
        other = get_rule("dom-test-001", "GPTBot", "/premium/report")
        assert other["action"] == "block"

        client.delete("/api/rules/dom-test-001/GPTBot", headers=auth_headers)

    def test_longest_prefix_wins(self, client, auth_headers):
        client.put("/api/rules/dom-test-001/paths", headers=auth_headers,
                   json={"path_prefix": "/blog/", "action": "allow"})
        client.put("/api/rules/dom-test-001/paths", headers=auth_headers,
                   json={"path_prefix": "/blog/premium/", "action": "block"})

        general = get_rule("dom-test-001", "GPTBot", "/blog/a-normal-post")
        assert general["action"] == "allow"

        specific = get_rule("dom-test-001", "GPTBot", "/blog/premium/deep-dive")
        assert specific["action"] == "block"

    def test_empty_path_never_matches_path_rules(self, client, auth_headers):
        """Callers that don't have path context (path='') must be
        unaffected by path rules entirely — this is the backward-
        compatibility guarantee for any future caller of get_rule."""
        client.put("/api/rules/dom-test-001/paths", headers=auth_headers,
                   json={"path_prefix": "/blog/", "action": "block"})
        rule = get_rule("dom-test-001", "GPTBot")
        assert rule["action"] != "block"


class TestPathRuleAPI:

    def test_list_requires_auth(self, client):
        resp = client.get("/api/rules/dom-test-001/paths")
        assert resp.status_code == 401

    def test_cannot_set_path_rule_on_domain_you_dont_own(self, client, free_auth_headers):
        resp = client.put("/api/rules/dom-test-001/paths", headers=free_auth_headers,
                           json={"path_prefix": "/x/", "action": "block"})
        assert resp.status_code == 404

    def test_path_prefix_must_start_with_slash(self, client, auth_headers):
        resp = client.put("/api/rules/dom-test-001/paths", headers=auth_headers,
                           json={"path_prefix": "no-slash", "action": "block"})
        assert resp.status_code == 400

    def test_set_list_and_delete_round_trip(self, client, auth_headers):
        client.put("/api/rules/dom-test-001/paths", headers=auth_headers,
                   json={"path_prefix": "/archive/", "action": "block"})

        listed = client.get("/api/rules/dom-test-001/paths", headers=auth_headers).json()
        assert any(r["path_prefix"] == "/archive/" for r in listed)

        resp = client.delete("/api/rules/dom-test-001/paths?path_prefix=/archive/", headers=auth_headers)
        assert resp.status_code == 200

        listed_after = client.get("/api/rules/dom-test-001/paths", headers=auth_headers).json()
        assert not any(r["path_prefix"] == "/archive/" for r in listed_after)
