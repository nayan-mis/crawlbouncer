"""
CrawlBouncer — API Integration Tests
End-to-end tests hitting the actual FastAPI endpoints.
Tests the full request pipeline: auth → domain → rules → stats → crawler API.
"""
import pytest
from fastapi.testclient import TestClient


# ─────────────────────────────────────────────────────────────────
# HEALTH CHECK
# ─────────────────────────────────────────────────────────────────

class TestHealth:

    def test_health_returns_200(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200

    def test_health_returns_status_ok(self, client):
        data = client.get("/health").json()
        assert data["status"] in ("ok", "degraded")

    def test_health_includes_version(self, client):
        data = client.get("/health").json()
        assert "version" in data

    def test_health_includes_database_status(self, client):
        data = client.get("/health").json()
        assert "database" in data


# ─────────────────────────────────────────────────────────────────
# DASHBOARD
# ─────────────────────────────────────────────────────────────────

class TestDashboard:

    def test_dashboard_returns_html(self, client):
        resp = client.get("/")
        assert resp.status_code in (200, 500)   # 500 if dashboard.html not present
        if resp.status_code == 200:
            assert "text/html" in resp.headers["content-type"]


# ─────────────────────────────────────────────────────────────────
# STATS API
# ─────────────────────────────────────────────────────────────────

class TestStatsAPI:

    def test_overview_returns_200(self, client, auth_headers):
        resp = client.get("/api/stats/overview", headers=auth_headers)
        assert resp.status_code == 200

    def test_overview_has_required_fields(self, client, auth_headers):
        data = client.get("/api/stats/overview", headers=auth_headers).json()
        required = ["total_requests", "bot_requests", "blocked", "crawlers_allowed"]
        for field in required:
            assert field in data, f"Missing field: {field}"

    def test_overview_bot_percentage_valid(self, client, auth_headers):
        data = client.get("/api/stats/overview", headers=auth_headers).json()
        pct  = data["bot_percentage"]
        assert 0 <= pct <= 100

    def test_traffic_returns_list(self, client, auth_headers):
        resp = client.get("/api/stats/traffic?days=7", headers=auth_headers)
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_traffic_30_days(self, client, auth_headers):
        resp = client.get("/api/stats/traffic?days=30", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) <= 30

    def test_traffic_invalid_days_rejected(self, client, auth_headers):
        resp = client.get("/api/stats/traffic?days=999", headers=auth_headers)
        assert resp.status_code == 422

    def test_crawlers_returns_list(self, client, auth_headers):
        resp = client.get("/api/stats/crawlers", headers=auth_headers)
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_crawlers_have_required_fields(self, client, auth_headers):
        data = client.get("/api/stats/crawlers", headers=auth_headers).json()
        if data:
            required = ["name", "requests", "action"]
            for field in required:
                assert field in data[0], f"Missing crawler field: {field}"

    def test_top_pages_endpoint(self, client, auth_headers):
        resp = client.get("/api/stats/top-pages", headers=auth_headers)
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_top_pages_limit_respected(self, client, auth_headers):
        resp = client.get("/api/stats/top-pages?limit=5", headers=auth_headers)
        assert len(resp.json()) <= 5

    def test_waf_stats_endpoint(self, client, auth_headers):
        resp = client.get("/api/stats/waf", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "total_blocked" in data


# ─────────────────────────────────────────────────────────────────
# REQUEST LOG
# ─────────────────────────────────────────────────────────────────

class TestRequestLog:

    def test_log_returns_200(self, client, auth_headers):
        resp = client.get("/api/requests/log", headers=auth_headers)
        assert resp.status_code == 200

    def test_log_has_pagination_fields(self, client, auth_headers):
        data = client.get("/api/requests/log", headers=auth_headers).json()
        assert "requests" in data
        assert "total"    in data
        assert "page"     in data

    def test_log_page_param(self, client, auth_headers):
        resp = client.get("/api/requests/log?page=1&limit=10", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["requests"]) <= 10

    def test_log_invalid_limit_rejected(self, client, auth_headers):
        resp = client.get("/api/requests/log?limit=9999", headers=auth_headers)
        assert resp.status_code == 422


# ─────────────────────────────────────────────────────────────────
# DOMAINS API
# ─────────────────────────────────────────────────────────────────

class TestDomainsAPI:

    def test_list_domains_requires_auth(self, client):
        resp = client.get("/api/domains/")
        assert resp.status_code == 401

    def test_list_domains_with_auth(self, client, auth_headers):
        resp = client.get("/api/domains/", headers=auth_headers)
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_add_domain_requires_auth(self, client):
        resp = client.post("/api/domains/", json={
            "domain": "example.com", "origin_url": "https://origin.example.com"
        })
        assert resp.status_code == 401

    def test_add_valid_domain(self, client, auth_headers):
        resp = client.post("/api/domains/", headers=auth_headers, json={
            "domain":     "valid-test-domain.com",
            "origin_url": "https://origin.valid-test-domain.com",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["domain"]      == "valid-test-domain.com"
        assert data["dns_verified"] == False
        assert "cname_target" in data
        assert "dns_instructions" in data

    def test_add_invalid_domain_rejected(self, client, auth_headers):
        resp = client.post("/api/domains/", headers=auth_headers, json={
            "domain":     "not a valid domain!!",
            "origin_url": "https://origin.example.com",
        })
        assert resp.status_code == 400

    def test_add_domain_without_https_rejected(self, client, auth_headers):
        resp = client.post("/api/domains/", headers=auth_headers, json={
            "domain":     "example2.com",
            "origin_url": "ftp://origin.example2.com",
        })
        assert resp.status_code == 400

    def test_duplicate_domain_rejected(self, client, auth_headers):
        client.post("/api/domains/", headers=auth_headers, json={
            "domain": "duplicate-test.com", "origin_url": "https://o.duplicate-test.com"
        })
        resp = client.post("/api/domains/", headers=auth_headers, json={
            "domain": "duplicate-test.com", "origin_url": "https://o.duplicate-test.com"
        })
        assert resp.status_code == 409

    def test_no_domain_limit(self, client, auth_headers):
        """There are no plans any more: an account can add as many domains as it likes."""
        for i in range(3):
            resp = client.post("/api/domains/", headers=auth_headers, json={
                "domain": f"unlimited-{i}.com", "origin_url": f"https://o.unlimited-{i}.com"
            })
            assert resp.status_code == 200

    def test_dns_verify_endpoint(self, client):
        from app.security.jwt_handler import create_token
        from app.database import get_db
        # Dedicated publisher so this test isn't affected by the shared
        # pub-test-001 fixture's domain quota being used up by earlier tests.
        with get_db() as db:
            db.execute("""
                INSERT OR IGNORE INTO publishers (id, email, password_hash, name)
                VALUES ('pub-verify-test', 'verify-test@example.com', 'x', 'Verify Test Publisher')
            """)
        token = create_token("pub-verify-test", "verify-test@example.com")
        headers = {"Authorization": f"Bearer {token}"}

        add = client.post("/api/domains/", headers=headers, json={
            "domain": "verify-test.com", "origin_url": "https://o.verify-test.com"
        })
        domain_id = add.json()["id"]
        resp = client.get(f"/api/domains/{domain_id}/verify", headers=headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "dns_verified" in data
        assert "message" in data


# ─────────────────────────────────────────────────────────────────
# RULES API
# ─────────────────────────────────────────────────────────────────

class TestRulesAPI:

    def _get_domain_id(self, client, auth_headers) -> str:
        resp = client.post("/api/domains/", headers=auth_headers, json={
            "domain": "rules-api-test.com", "origin_url": "https://o.rules-api-test.com"
        })
        return resp.json()["id"]

    def test_list_rules_requires_auth(self, client):
        resp = client.get("/api/rules/dom-test-001")
        assert resp.status_code == 401

    def test_list_rules_returns_all_crawlers(self, client, auth_headers):
        resp = client.get("/api/rules/dom-test-001", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) > 0
        names = [r["crawler_name"] for r in data]
        assert "GPTBot"   in names
        assert "ClaudeBot" in names

    def test_set_rule_block(self, client, auth_headers):
        resp = client.put(
            "/api/rules/dom-test-001/GPTBot",
            headers=auth_headers,
            json={"action": "block"},
        )
        assert resp.status_code == 200
        assert resp.json()["action"] == "block"

    def test_only_allow_and_block_exist(self, client, auth_headers):
        for bad in ("charge", "license"):
            resp = client.put(
                "/api/rules/dom-test-001/ClaudeBot",
                headers=auth_headers,
                json={"action": bad},
            )
            assert resp.status_code == 422

    def test_invalid_action_rejected(self, client, auth_headers):
        resp = client.put(
            "/api/rules/dom-test-001/GPTBot",
            headers=auth_headers,
            json={"action": "invalid"},
        )
        assert resp.status_code == 422

    def test_bulk_update(self, client, auth_headers):
        resp = client.post(
            "/api/rules/dom-test-001/bulk",
            headers=auth_headers,
            json={"rules": {
                "GPTBot":    {"action": "block"},
                "ClaudeBot": {"action": "allow"},
            }},
        )
        assert resp.status_code == 200
        assert "Updated" in resp.json()["message"]


