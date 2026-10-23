"""
Tests for bolt-on integration mode: domain creation with
integration_mode="bolt_on" and the POST /v1/decide edge decision API.
"""
import pytest


def _create_bolt_on_domain(client, auth_headers, domain="boltontest.com"):
    resp = client.post("/api/domains/", headers=auth_headers, json={
        "domain": domain, "integration_mode": "bolt_on",
    })
    assert resp.status_code == 200, resp.text
    return resp.json()


class TestBoltOnDomainCreation:

    def test_bolt_on_domain_gets_edge_key_not_cname(self, client, auth_headers):
        data = _create_bolt_on_domain(client, auth_headers, "boltoncreate1.com")
        assert data["integration_mode"] == "bolt_on"
        assert data["edge_api_key"] is not None
        assert data["cname_target"] is None
        assert data["dns_verified"] is True   # nothing to verify — no DNS change

    def test_bolt_on_domain_does_not_require_origin_url(self, client, auth_headers):
        resp = client.post("/api/domains/", headers=auth_headers, json={
            "domain": "boltonnoorigin.com", "integration_mode": "bolt_on",
        })
        assert resp.status_code == 200

    def test_bolt_on_dns_verified_persists_after_refresh(self, client, auth_headers):
        """The creation response hardcodes dns_verified/ssl_active=True
        (nothing to verify in bolt-on mode) — that must actually be what's
        stored, not just what's returned once. A dashboard reload
        (GET /api/domains/) must see the same thing the creation response
        promised, or the UI shows 'Pending' on a domain with no DNS step."""
        _create_bolt_on_domain(client, auth_headers, "boltonpersist.com")
        listed = client.get("/api/domains/", headers=auth_headers).json()
        row = next(d for d in listed if d["domain"] == "boltonpersist.com")
        assert row["dns_verified"] == 1
        assert row["ssl_active"] == 1
        assert row["active"] == 1

    def test_reverse_proxy_domain_unaffected_by_new_field(self, client, auth_headers):
        """Default mode, and existing behavior — must be completely
        unchanged by adding bolt-on as an option."""
        resp = client.post("/api/domains/", headers=auth_headers, json={
            "domain": "stillreverseproxy.com", "origin_url": "https://o.stillreverseproxy.com",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["integration_mode"] == "reverse_proxy"
        assert data["cname_target"] is not None
        assert data["edge_api_key"] is None

    def test_reverse_proxy_domain_still_requires_origin_url(self, client, auth_headers):
        resp = client.post("/api/domains/", headers=auth_headers, json={
            "domain": "noorigingiven.com",
        })
        assert resp.status_code == 400


class TestEdgeDecideAuth:

    def test_missing_edge_key_rejected(self, client):
        resp = client.post("/v1/decide", json={"path": "/x", "user_agent": "GPTBot/1.0"})
        assert resp.status_code == 401

    def test_invalid_edge_key_rejected(self, client):
        resp = client.post("/v1/decide",
            headers={"X-Edge-Key": "not-a-real-key"},
            json={"path": "/x", "user_agent": "GPTBot/1.0"})
        assert resp.status_code == 401

    def test_reverse_proxy_domains_key_material_cannot_be_used(self, client, auth_headers):
        """A reverse-proxy domain has no edge key at all — confirms
        there's no way to accidentally authenticate against /v1/decide
        using anything tied to a non-bolt-on domain."""
        resp = client.post("/v1/decide",
            headers={"X-Edge-Key": "dom-test-001"},  # not a real key, just not-a-bolt-on-domain-either
            json={"path": "/x", "user_agent": "GPTBot/1.0"})
        assert resp.status_code == 401


class TestEdgeDecideLogic:

    def test_non_bot_traffic_always_allowed(self, client, auth_headers):
        data = _create_bolt_on_domain(client, auth_headers, "decidenonbot.com")
        resp = client.post("/v1/decide",
            headers={"X-Edge-Key": data["edge_api_key"]},
            json={"path": "/article", "user_agent": "Mozilla/5.0 (real browser)"})
        assert resp.status_code == 200
        assert resp.json() == {"action": "allow", "is_bot": False}

    def test_unrecognized_bot_allowed_not_managed(self, client, auth_headers):
        """Bolt-on mode isn't a general bot-management layer — that
        stays the publisher's own CDN's job."""
        data = _create_bolt_on_domain(client, auth_headers, "decideunknownbot.com")
        resp = client.post("/v1/decide",
            headers={"X-Edge-Key": data["edge_api_key"]},
            json={"path": "/article", "user_agent": "python-requests/2.31"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["action"] == "allow"
        assert body["is_bot"] is True
        assert body["crawler_name"] is None

    def test_known_training_crawler_default_is_block(self, client, auth_headers):
        data = _create_bolt_on_domain(client, auth_headers, "decidedefault.com")
        resp = client.post("/v1/decide",
            headers={"X-Edge-Key": data["edge_api_key"]},
            json={"path": "/article", "user_agent": "Mozilla/5.0 GPTBot/1.0"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["action"] == "block"
        assert body["crawler_name"] == "GPTBot"

    def test_path_rule_block_overrides_crawler_rule(self, client, auth_headers):
        data = _create_bolt_on_domain(client, auth_headers, "decideblockpath.com")
        client.put(f"/api/rules/{data['id']}/paths", headers=auth_headers,
                   json={"path_prefix": "/private/", "action": "block"})
        resp = client.post("/v1/decide",
            headers={"X-Edge-Key": data["edge_api_key"]},
            json={"path": "/private/secret", "user_agent": "Mozilla/5.0 GPTBot/1.0"})
        assert resp.status_code == 200
        assert resp.json()["action"] == "block"

    def test_crawler_rule_allow_lets_it_through(self, client, auth_headers):
        data = _create_bolt_on_domain(client, auth_headers, "decideallow.com")
        client.put(f"/api/rules/{data['id']}/GPTBot", headers=auth_headers,
                   json={"action": "allow"})
        resp = client.post("/v1/decide",
            headers={"X-Edge-Key": data["edge_api_key"]},
            json={"path": "/article", "user_agent": "Mozilla/5.0 GPTBot/1.0"})
        assert resp.status_code == 200
        assert resp.json()["action"] == "allow"

    def test_inactive_domain_rejected(self, client, auth_headers):
        data = _create_bolt_on_domain(client, auth_headers, "decideinactive.com")
        client.delete(f"/api/domains/{data['id']}", headers=auth_headers)
        resp = client.post("/v1/decide",
            headers={"X-Edge-Key": data["edge_api_key"]},
            json={"path": "/article", "user_agent": "GPTBot/1.0"})
        assert resp.status_code in (401, 403)


class TestDecisionsAreLogged:

    def test_bolt_on_decision_appears_in_request_log(self, client, auth_headers):
        from app.database import get_db
        data = _create_bolt_on_domain(client, auth_headers, "decidelogged.com")
        resp = client.post("/v1/decide",
            headers={"X-Edge-Key": data["edge_api_key"]},
            json={"path": "/logged-path", "user_agent": "Mozilla/5.0 GPTBot/1.0", "ip": "9.9.9.9"})
        assert resp.status_code == 200
        with get_db() as db:
            row = db.execute(
                "SELECT crawler_name, action, status_code FROM requests WHERE domain_id=? AND path=?",
                (data["id"], "/logged-path")).fetchone()
        assert row is not None
        assert row["crawler_name"] == "GPTBot"
        assert row["action"] == resp.json()["action"]
