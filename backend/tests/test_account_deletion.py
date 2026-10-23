"""
Tests for DELETE /api/auth/account — owner-only soft delete: anonymize,
suspend, deactivate domains, remove team members, 
still pending.
"""
import pytest
from conftest import register_and_verify


def _register_owner(client, monkeypatch, email, password="DeleteMe12345"):
    result = register_and_verify(client, monkeypatch, email, password)
    headers = {"Authorization": f"Bearer {result['token']}"}
    return result["user_id"], headers, password


class TestAccountDeletionAuth:

    def test_requires_auth(self, client, monkeypatch):
        resp = client.request("DELETE", "/api/auth/account", json={"password": "x"})
        assert resp.status_code == 401

    def test_member_cannot_delete_account(self, client, auth_headers, monkeypatch):
        captured = {}
        monkeypatch.setattr("app.api.team._send_team_invite_email",
                             lambda to_email, token, account_name: captured.update({"token": token}))
        client.post("/api/team/invite", headers=auth_headers, json={"email": "del-member@example.com"})
        client.post("/api/team/accept", json={"token": captured["token"], "password": "MemberPass123"})
        login = client.post("/api/auth/login", json={"email": "del-member@example.com", "password": "MemberPass123"})
        member_headers = {"Authorization": f"Bearer {login.json()['token']}"}

        resp = client.request("DELETE", "/api/auth/account", headers=member_headers, json={"password": "MemberPass123"})
        assert resp.status_code == 403

    def test_wrong_password_rejected(self, client, monkeypatch):
        pub_id, headers, password = _register_owner(client, monkeypatch, "delwrongpass@example.com")
        resp = client.request("DELETE", "/api/auth/account", headers=headers, json={"password": "TotallyWrongPassword"})
        assert resp.status_code == 401


class TestAccountDeletionEffects:

    def test_deletion_blocks_future_login(self, client, monkeypatch):
        pub_id, headers, password = _register_owner(client, monkeypatch, "delfuture@example.com")
        resp = client.request("DELETE", "/api/auth/account", headers=headers, json={"password": password})
        assert resp.status_code == 200

        login = client.post("/api/auth/login", json={"email": "delfuture@example.com", "password": password})
        assert login.status_code == 401  # old email no longer resolves to any account

    def test_deletion_kills_the_deleting_owners_own_session(self, client, monkeypatch):
        pub_id, headers, password = _register_owner(client, monkeypatch, "delownsession@example.com")
        client.request("DELETE", "/api/auth/account", headers=headers, json={"password": password})

        resp = client.get("/api/auth/me", headers=headers)
        assert resp.status_code in (401, 403)

    def test_deletion_deactivates_domains(self, client, monkeypatch):
        pub_id, headers, password = _register_owner(client, monkeypatch, "deldomains@example.com")
        add = client.post("/api/domains/", headers=headers, json={
            "domain": "delete-test-domain.com", "origin_url": "https://o.delete-test-domain.com"
        })
        assert add.status_code == 200

        client.request("DELETE", "/api/auth/account", headers=headers, json={"password": password})

        from app.database import get_db
        with get_db() as db:
            row = db.execute(
                "SELECT active FROM domains WHERE domain='delete-test-domain.com'"
            ).fetchone()
        assert row["active"] == 0

    def test_deletion_removes_team_members(self, client, monkeypatch):
        pub_id, headers, password = _register_owner(client, monkeypatch, "delteam@example.com")
        captured = {}
        monkeypatch.setattr("app.api.team._send_team_invite_email",
                             lambda to_email, token, account_name: captured.update({"token": token}))
        client.post("/api/team/invite", headers=headers, json={"email": "orphaned-member@example.com"})
        client.post("/api/team/accept", json={"token": captured["token"], "password": "MemberPass123"})
        login = client.post("/api/auth/login", json={"email": "orphaned-member@example.com", "password": "MemberPass123"})
        member_headers = {"Authorization": f"Bearer {login.json()['token']}"}
        assert client.get("/api/auth/me", headers=member_headers).status_code == 200

        client.request("DELETE", "/api/auth/account", headers=headers, json={"password": password})

        resp = client.get("/api/auth/me", headers=member_headers)
        assert resp.status_code == 401

    def test_email_is_freed_up_after_deletion(self, client, monkeypatch):
        """A deleted account's email must not permanently squat the
        address — someone should be able to register it again."""
        pub_id, headers, password = _register_owner(client, monkeypatch, "delreuse@example.com")
        client.request("DELETE", "/api/auth/account", headers=headers, json={"password": password})

        reg = client.post("/api/auth/register", json={"email": "delreuse@example.com", "password": "NewPassword123"})
        assert reg.status_code == 200
