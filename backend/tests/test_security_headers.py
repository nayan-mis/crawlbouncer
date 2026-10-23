"""
Tests for the security_headers middleware in main.py — applies
X-Frame-Options/X-Content-Type-Options/Referrer-Policy to every
response from the app itself, plus HSTS in production only.
"""


class TestSecurityHeaders:

    def test_headers_present_on_a_normal_response(self, client):
        resp = client.get("/health")
        assert resp.headers.get("x-frame-options") == "DENY"
        assert resp.headers.get("x-content-type-options") == "nosniff"
        assert resp.headers.get("referrer-policy") == "strict-origin-when-cross-origin"

    def test_headers_present_even_on_error_responses(self, client):
        """A misconfigured request (401, 404, etc.) must still get the
        same protection — these headers guard against things like
        clickjacking regardless of whether the request succeeded."""
        resp = client.get("/api/domains/")  # no auth -> 401
        assert resp.status_code == 401
        assert resp.headers.get("x-frame-options") == "DENY"

    def test_hsts_absent_outside_production(self, client):
        """HSTS in local/dev would make browsers force HTTPS on
        localhost and break local development — must only apply in
        production. Test env's cfg.ENV is 'test', not 'production'."""
        resp = client.get("/health")
        assert "strict-transport-security" not in {k.lower() for k in resp.headers.keys()}

    def test_hsts_present_in_production(self, client, monkeypatch):
        import app.main as main_module
        monkeypatch.setattr(main_module.cfg, "ENV", "production")
        resp = client.get("/health")
        assert resp.headers.get("strict-transport-security") == "max-age=31536000; includeSubDomains"
