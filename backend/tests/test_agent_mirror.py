"""
End-to-end tests for Agent Mirror (app/services/agent_mirror.py, wired
into the request pipeline in app/main.py).

These exercise the full pipeline via TestClient with a real Host header
and an allowed AI crawler (ChatGPT-User), rather than testing extraction in
isolation — the bug this is guarding against (main.py referencing
domain['domain'], a column never selected by that query) only shows up
when the whole path actually runs end to end.
"""
import pytest
from app.main import app
from app.database import get_db

CANNED_ORIGIN_HTML = """
<html><head><title>The Real Article Title</title></head>
<body>
<nav><a href="/">Home</a><a href="/about">About</a></nav>
<script>trackVisitor();</script>
<article>
<h1>The Real Article Title</h1>
<p>This is the first real paragraph of the article, with actual content a reader wants.</p>
<p>This is the second paragraph, continuing the story.</p>
</article>
<footer>Copyright 2026</footer>
</body></html>
"""


BOT_UA = "Mozilla/5.0 ChatGPT-User/1.0"   # default action: allow


@pytest.fixture(autouse=True)
def _mirror_on(monkeypatch):
    """Agent Mirror is off by default; these tests exercise it switched on."""
    from app.config import cfg
    monkeypatch.setattr(cfg, "MIRROR_ENABLED", True)


class TestAgentMirrorDefault:

    def test_default_mode_serves_extracted_agent_page(self, client, monkeypatch):
        async def fake_fetch(origin_url, path, query=""):
            return CANNED_ORIGIN_HTML
        monkeypatch.setattr("app.services.agent_mirror._fetch_origin_html", fake_fetch)

        resp = client.get(
            "/article/mirror-default-test",
            headers={
                "Host": "testblog.com",
                "User-Agent": BOT_UA,
            },
        )
        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        assert "The Real Article Title" in resp.text
        assert "first real paragraph" in resp.text
        # Nav/script/footer chrome must be stripped out of the agent page
        assert "trackVisitor" not in resp.text
        assert "Copyright 2026" not in resp.text
        assert resp.headers.get("content-type", "").startswith("text/html")

    def test_default_mode_does_not_call_origin_proxy(self, client, monkeypatch):
        """Regression guard: agent mode must never fall through to
        proxy_to_origin — if it did, this test's origin fetch would hit a
        real (nonexistent) network host and fail/hang instead of using
        the canned fixture."""
        called = {"proxy": False}

        async def fake_fetch(origin_url, path, query=""):
            return CANNED_ORIGIN_HTML

        async def fail_if_called(*args, **kwargs):
            called["proxy"] = True
            raise AssertionError("proxy_to_origin should not be called in agent mode")

        monkeypatch.setattr("app.services.agent_mirror._fetch_origin_html", fake_fetch)
        monkeypatch.setattr("app.main.proxy_to_origin", fail_if_called)

        resp = client.get(
            "/article/mirror-no-proxy-test",
            headers={
                "Host": "testblog.com",
                "User-Agent": BOT_UA,
            },
        )
        assert resp.status_code == 200
        assert called["proxy"] is False

    def test_repeat_requests_use_cache_not_refetch(self, client, monkeypatch):
        """A second request for the same path within the cache TTL
        must be served from mirror_cache, not re-fetched from origin."""
        fetch_count = {"n": 0}

        async def counting_fetch(origin_url, path, query=""):
            fetch_count["n"] += 1
            return CANNED_ORIGIN_HTML
        monkeypatch.setattr("app.services.agent_mirror._fetch_origin_html", counting_fetch)

        path = "/article/mirror-cache-test"
        for _ in range(2):
            resp = client.get(path, headers={
                "Host": "testblog.com",
                "User-Agent": BOT_UA,
            })
            assert resp.status_code == 200

        assert fetch_count["n"] == 1


class TestAgentMirrorOffByDefault:

    def test_mirror_is_not_used_when_disabled(self, client, monkeypatch):
        from app.config import cfg
        monkeypatch.setattr(cfg, "MIRROR_ENABLED", False)
        from fastapi.responses import Response

        async def fake_proxy(request, origin_url):
            return Response(content=b"PLAIN ORIGIN", status_code=200, headers={"content-type": "text/html"})
        monkeypatch.setattr("app.main.proxy_to_origin", fake_proxy)

        resp = client.get("/article/mirror-off", headers={"Host": "testblog.com", "User-Agent": BOT_UA})
        assert resp.status_code == 200
        assert resp.text == "PLAIN ORIGIN"


class TestAgentMirrorHtmlOverride:

    def test_html_override_proxies_straight_to_origin(self, client, auth_headers, monkeypatch):
        path = "/article/mirror-html-override-test"

        # Owner opts this specific path into 'html'
        set_resp = client.put(
            "/api/mirror/dom-test-001",
            headers=auth_headers,
            json={"path": path, "serve_mode": "html"},
        )
        assert set_resp.status_code == 200
        assert set_resp.json()["serve_mode"] == "html"

        from fastapi.responses import Response

        async def fake_proxy(request, origin_url):
            return Response(content=b"REAL ORIGIN HTML, UNMODIFIED", status_code=200,
                             headers={"content-type": "text/html"})

        async def fail_if_extraction_called(*args, **kwargs):
            raise AssertionError("agent extraction should not run when serve_mode='html'")

        monkeypatch.setattr("app.main.proxy_to_origin", fake_proxy)
        monkeypatch.setattr("app.services.agent_mirror._fetch_origin_html", fail_if_extraction_called)

        resp = client.get(path, headers={
            "Host": "testblog.com",
            "User-Agent": BOT_UA,
        })
        assert resp.status_code == 200
        assert resp.text == "REAL ORIGIN HTML, UNMODIFIED"

    def test_reset_to_agent_removes_override(self, client, auth_headers):
        path = "/article/mirror-reset-test"
        client.put("/api/mirror/dom-test-001", headers=auth_headers,
                    json={"path": path, "serve_mode": "html"})

        resp = client.delete(f"/api/mirror/dom-test-001?path={path}", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["serve_mode"] == "agent"

        lookup = client.get(f"/api/mirror/dom-test-001/lookup?path={path}", headers=auth_headers)
        assert lookup.json()["serve_mode"] == "agent"


class TestAgentMirrorSettingsAPI:

    def test_list_requires_auth(self, client):
        resp = client.get("/api/mirror/dom-test-001")
        assert resp.status_code == 401

    def test_cannot_set_mirror_on_domain_you_dont_own(self, client, free_auth_headers):
        resp = client.put(
            "/api/mirror/dom-test-001",
            headers=free_auth_headers,
            json={"path": "/article/x", "serve_mode": "html"},
        )
        assert resp.status_code == 404

    def test_setting_agent_explicitly_does_not_create_a_row(self, client, auth_headers):
        path = "/article/mirror-noop-test"
        resp = client.put("/api/mirror/dom-test-001", headers=auth_headers,
                           json={"path": path, "serve_mode": "agent"})
        assert resp.status_code == 200

        listing = client.get("/api/mirror/dom-test-001", headers=auth_headers).json()
        assert all(o["path"] != path for o in listing["overrides"])
