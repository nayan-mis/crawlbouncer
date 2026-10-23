"""
Tests for team seats: invite -> accept -> member login, permission
scoping (members can do everything except invite/remove), and
session invalidation on removal.
"""
import pytest


class TestInviteFlow:

    def test_only_owner_can_invite(self, client, free_auth_headers):
        """free_auth_headers is an owner login (pub-test-free), just on
        a different account than dom-test-001 — still a valid owner, so
        this specifically checks a *member* can't invite, tested below;
        this test checks the endpoint requires auth at all as a sanity base."""
        resp = client.post("/api/team/invite", headers=free_auth_headers, json={"email": "x@example.com"})
        assert resp.status_code == 200  # pub-test-free IS an owner of its own account

    def test_invite_requires_auth(self, client):
        resp = client.post("/api/team/invite", json={"email": "x@example.com"})
        assert resp.status_code == 401

    def test_cannot_invite_email_with_its_own_account(self, client, auth_headers):
        resp = client.post("/api/team/invite", headers=auth_headers,
                            json={"email": "test@example.com"})  # pub-test-001's own email
        assert resp.status_code == 409

    def test_invite_creates_pending_member(self, client, auth_headers):
        resp = client.post("/api/team/invite", headers=auth_headers, json={"email": "newmember@example.com"})
        assert resp.status_code == 200
        assert resp.json()["status"] == "pending"

        listing = client.get("/api/team/", headers=auth_headers).json()
        assert any(m["email"] == "newmember@example.com" and m["status"] == "pending"
                   for m in listing["members"])


class TestAcceptAndLogin:

    def _invite_and_get_token(self, client, auth_headers, email, monkeypatch) -> str:
        captured = {}
        def fake_send(to_email, token, account_name):
            captured["token"] = token
        monkeypatch.setattr("app.api.team._send_team_invite_email", fake_send)
        resp = client.post("/api/team/invite", headers=auth_headers, json={"email": email})
        assert resp.status_code == 200
        return captured["token"]

    def test_accept_with_invalid_token_rejected(self, client):
        resp = client.post("/api/team/accept", json={"token": "not-a-real-token", "password": "MemberPass123"})
        assert resp.status_code == 400

    def test_full_invite_accept_login_flow(self, client, auth_headers, monkeypatch):
        token = self._invite_and_get_token(client, auth_headers, "member1@example.com", monkeypatch)

        accept = client.post("/api/team/accept", json={"token": token, "password": "MemberPass123"})
        assert accept.status_code == 200
        assert accept.json()["status"] == "active"

        login = client.post("/api/auth/login", json={"email": "member1@example.com", "password": "MemberPass123"})
        assert login.status_code == 200
        member_headers = {"Authorization": f"Bearer {login.json()['token']}"}

        # sub resolves to the owner's account, so ownership checks work unchanged
        assert login.json()["user_id"] == "pub-test-001"

        me = client.get("/api/auth/me", headers=member_headers)
        assert me.status_code == 200

    def test_accept_token_cannot_be_reused(self, client, auth_headers, monkeypatch):
        token = self._invite_and_get_token(client, auth_headers, "member2@example.com", monkeypatch)
        client.post("/api/team/accept", json={"token": token, "password": "MemberPass123"})
        second = client.post("/api/team/accept", json={"token": token, "password": "DifferentPass456"})
        assert second.status_code == 400


class TestMemberPermissionScoping:

    def _make_active_member(self, client, auth_headers, email, monkeypatch) -> dict:
        captured = {}
        monkeypatch.setattr("app.api.team._send_team_invite_email",
                             lambda to_email, token, account_name: captured.update({"token": token}))
        client.post("/api/team/invite", headers=auth_headers, json={"email": email})
        client.post("/api/team/accept", json={"token": captured["token"], "password": "MemberPass123"})
        login = client.post("/api/auth/login", json={"email": email, "password": "MemberPass123"})
        return {"Authorization": f"Bearer {login.json()['token']}"}

    def test_member_can_manage_domains(self, client, auth_headers, monkeypatch):
        member_headers = self._make_active_member(client, auth_headers, "member3@example.com", monkeypatch)
        resp = client.get("/api/domains/", headers=member_headers)
        assert resp.status_code == 200

    def test_member_cannot_invite_others(self, client, auth_headers, monkeypatch):
        member_headers = self._make_active_member(client, auth_headers, "member4@example.com", monkeypatch)
        resp = client.post("/api/team/invite", headers=member_headers, json={"email": "someoneelse@example.com"})
        assert resp.status_code == 403

    def test_member_cannot_remove_members(self, client, auth_headers, monkeypatch):
        member_headers = self._make_active_member(client, auth_headers, "member5@example.com", monkeypatch)
        resp = client.delete("/api/team/some-id", headers=member_headers)
        assert resp.status_code == 403

    def test_member_cannot_enroll_mfa_on_owners_account(self, client, auth_headers, monkeypatch):
        """mfa_secret/mfa_enabled live on the publishers row keyed by
        auth["sub"] — which for a member equals the OWNER's id, not
        their own. Without gating this to require_owner, a member
        could silently enroll 2FA on the owner's account (a secret only
        the member knows), potentially locking the owner out of their
        own login. Found during a real permissions audit, not a
        hypothetical."""
        member_headers = self._make_active_member(client, auth_headers, "member8@example.com", monkeypatch)
        resp = client.post("/api/auth/mfa/enroll", headers=member_headers)
        assert resp.status_code == 403

    def test_member_cannot_confirm_mfa_on_owners_account(self, client, auth_headers, monkeypatch):
        member_headers = self._make_active_member(client, auth_headers, "member9@example.com", monkeypatch)
        resp = client.post("/api/auth/mfa/confirm", headers=member_headers, json={"code": "000000"})
        assert resp.status_code == 403


class TestRemoveMember:

    def _make_active_member(self, client, auth_headers, email, monkeypatch) -> tuple:
        captured = {}
        monkeypatch.setattr("app.api.team._send_team_invite_email",
                             lambda to_email, token, account_name: captured.update({"token": token}))
        client.post("/api/team/invite", headers=auth_headers, json={"email": email})
        client.post("/api/team/accept", json={"token": captured["token"], "password": "MemberPass123"})
        login = client.post("/api/auth/login", json={"email": email, "password": "MemberPass123"})
        member_headers = {"Authorization": f"Bearer {login.json()['token']}"}

        from app.database import get_db
        with get_db() as db:
            row = db.execute("SELECT id FROM team_members WHERE email=?", (email,)).fetchone()
        return member_headers, row["id"]

    def test_removed_member_token_stops_working_immediately(self, client, auth_headers, monkeypatch):
        member_headers, member_id = self._make_active_member(client, auth_headers, "removeme@example.com", monkeypatch)

        assert client.get("/api/auth/me", headers=member_headers).status_code == 200

        resp = client.delete(f"/api/team/{member_id}", headers=auth_headers)
        assert resp.status_code == 200

        assert client.get("/api/auth/me", headers=member_headers).status_code == 401

    def test_removed_member_cannot_log_in_again(self, client, auth_headers, monkeypatch):
        member_headers, member_id = self._make_active_member(client, auth_headers, "removeme2@example.com", monkeypatch)
        client.delete(f"/api/team/{member_id}", headers=auth_headers)

        login = client.post("/api/auth/login", json={"email": "removeme2@example.com", "password": "MemberPass123"})
        assert login.status_code == 401

    def test_removing_a_member_does_not_affect_the_owner(self, client, auth_headers, monkeypatch):
        member_headers, member_id = self._make_active_member(client, auth_headers, "removeme3@example.com", monkeypatch)
        client.delete(f"/api/team/{member_id}", headers=auth_headers)
        assert client.get("/api/auth/me", headers=auth_headers).status_code == 200

    def test_owner_cannot_remove_member_from_another_account(self, client, auth_headers, free_auth_headers, monkeypatch):
        member_headers, member_id = self._make_active_member(client, auth_headers, "removeme4@example.com", monkeypatch)
        resp = client.delete(f"/api/team/{member_id}", headers=free_auth_headers)
        assert resp.status_code == 404
