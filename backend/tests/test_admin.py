"""
Tests for app/api/admin.py — platform admin API, account suspension,
and the require_admin gate.
"""
import pytest
from conftest import register_and_verify


class TestRequireAdminGate:

    def test_non_admin_cannot_list_publishers(self, client, auth_headers):
        resp = client.get("/api/admin/publishers", headers=auth_headers)
        assert resp.status_code == 403

    def test_admin_can_list_publishers(self, client, admin_auth_headers):
        resp = client.get("/api/admin/publishers", headers=admin_auth_headers)
        assert resp.status_code == 200
        emails = [p["email"] for p in resp.json()]
        assert "test@example.com" in emails

    def test_unauthenticated_request_rejected(self, client):
        resp = client.get("/api/admin/publishers")
        assert resp.status_code == 401

    def test_non_admin_cannot_suspend(self, client, auth_headers):
        resp = client.post("/api/admin/publishers/pub-test-free/suspend", headers=auth_headers)
        assert resp.status_code == 403


class TestSuspension:

    def _register_and_login(self, client, monkeypatch, email, password="SuspendMe12345"):
        result = register_and_verify(client, monkeypatch, email, password)
        return result["user_id"], password

    def test_suspend_blocks_login(self, client, admin_auth_headers, monkeypatch):
        pub_id, password = self._register_and_login(client, monkeypatch, "suspend-login@example.com")
        resp = client.post(f"/api/admin/publishers/{pub_id}/suspend", headers=admin_auth_headers)
        assert resp.status_code == 200
        assert resp.json()["suspended"] is True

        login = client.post("/api/auth/login", json={
            "email": "suspend-login@example.com", "password": password
        })
        assert login.status_code == 403

    def test_suspend_invalidates_existing_session_immediately(self, client, admin_auth_headers, monkeypatch):
        """A suspension must kill sessions that were already issued before
        the suspension happened, not just block future logins."""
        pub_id, password = self._register_and_login(client, monkeypatch, "suspend-session@example.com")
        login = client.post("/api/auth/login", json={
            "email": "suspend-session@example.com", "password": password
        })
        old_headers = {"Authorization": f"Bearer {login.json()['token']}"}

        # Token works before suspension
        assert client.get("/api/auth/me", headers=old_headers).status_code == 200

        client.post(f"/api/admin/publishers/{pub_id}/suspend", headers=admin_auth_headers)

        resp = client.get("/api/auth/me", headers=old_headers)
        # Suspension bumps auth_version, so the pre-existing token is
        # caught by the session-invalidation check (401) before it would
        # ever reach the suspended check (403) — either way, access must
        # be denied immediately, not just for future logins.
        assert resp.status_code in (401, 403)

    def test_suspension_does_not_block_domain_traffic(self, client, admin_auth_headers):
        """Suspension is account-level only — per the product decision,
        a suspended publisher's protected domains must keep being served,
        not go dark for their own readers. This test locks in that
        boundary: main.py's request pipeline never checks `suspended` at
        all, only require_auth (dashboard/API) does."""
        import app.main as main_module
        import inspect
        source = inspect.getsource(main_module)
        pipeline_source = source[source.index("SECURITY PIPELINE MIDDLEWARE"):source.index("def _get_ip")]
        assert "suspended" not in pipeline_source

    def test_unsuspend_restores_login(self, client, admin_auth_headers, monkeypatch):
        pub_id, password = self._register_and_login(client, monkeypatch, "unsuspend-me@example.com")
        client.post(f"/api/admin/publishers/{pub_id}/suspend", headers=admin_auth_headers)
        resp = client.post(f"/api/admin/publishers/{pub_id}/unsuspend", headers=admin_auth_headers)
        assert resp.status_code == 200
        assert resp.json()["suspended"] is False

        login = client.post("/api/auth/login", json={
            "email": "unsuspend-me@example.com", "password": password
        })
        assert login.status_code == 200

    def test_suspend_nonexistent_publisher_404s(self, client, admin_auth_headers):
        resp = client.post("/api/admin/publishers/does-not-exist/suspend", headers=admin_auth_headers)
        assert resp.status_code == 404


class TestPlatformAuditAndStats:

    def test_platform_audit_sees_events_across_publishers(self, client, admin_auth_headers, auth_headers):
        client.put("/api/mirror/dom-test-001", headers=auth_headers,
                   json={"path": "/article/admin-audit-test", "serve_mode": "html"})
        resp = client.get("/api/admin/audit", headers=admin_auth_headers)
        assert resp.status_code == 200
        actions = [e["action"] for e in resp.json()]
        assert "mirror_setting.update" in actions

    def test_platform_stats_returns_totals(self, client, admin_auth_headers):
        resp = client.get("/api/admin/stats", headers=admin_auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert data["publishers"] >= 3
        assert "requests" in data

    def test_non_admin_cannot_see_platform_audit(self, client, auth_headers):
        resp = client.get("/api/admin/audit", headers=auth_headers)
        assert resp.status_code == 403


class TestTeamMemberCannotInheritAdminAccess:
    """A team member invited to an admin's account must never gain
    platform-admin API access just because their token's `sub` equals
    that admin's publisher_id — is_admin is tied to a specific owner
    login, not "shares an account with an admin." """

    def test_member_of_admin_account_cannot_access_admin_endpoints(self, client, admin_auth_headers, monkeypatch):
        captured = {}
        monkeypatch.setattr("app.api.team._send_team_invite_email",
                             lambda to_email, token, account_name: captured.update({"token": token}))
        client.post("/api/team/invite", headers=admin_auth_headers, json={"email": "admin-team-member@example.com"})
        client.post("/api/team/accept", json={"token": captured["token"], "password": "MemberPass123"})
        login = client.post("/api/auth/login", json={
            "email": "admin-team-member@example.com", "password": "MemberPass123"
        })
        member_headers = {"Authorization": f"Bearer {login.json()['token']}"}

        resp = client.get("/api/admin/publishers", headers=member_headers)
        assert resp.status_code == 403

    def test_me_reports_is_admin_false_for_member_of_admin_account(self, client, admin_auth_headers, monkeypatch):
        captured = {}
        monkeypatch.setattr("app.api.team._send_team_invite_email",
                             lambda to_email, token, account_name: captured.update({"token": token}))
        client.post("/api/team/invite", headers=admin_auth_headers, json={"email": "admin-team-member2@example.com"})
        client.post("/api/team/accept", json={"token": captured["token"], "password": "MemberPass123"})
        login = client.post("/api/auth/login", json={
            "email": "admin-team-member2@example.com", "password": "MemberPass123"
        })
        member_headers = {"Authorization": f"Bearer {login.json()['token']}"}

        me = client.get("/api/auth/me", headers=member_headers)
        assert me.json()["is_admin"] is False
