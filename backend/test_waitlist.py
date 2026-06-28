from fastapi.testclient import TestClient

import main as app_main
from services import supabase_store


def _client() -> TestClient:
    return TestClient(app_main.app)


def test_waitlist_rejects_invalid_email():
    response = _client().post("/v1/waitlist", json={"email": "not-an-email"})
    assert response.status_code == 400


def test_waitlist_accepts_without_supabase(monkeypatch):
    monkeypatch.setattr(supabase_store, "SUPABASE_URL", "")
    monkeypatch.setattr(supabase_store, "SUPABASE_SERVICE_ROLE_KEY", "")

    response = _client().post("/v1/waitlist", json={"email": "Test.User@Example.COM"})

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "accepted"
    assert body["stored"] is False


def test_waitlist_upserts_email_with_unique_conflict(monkeypatch):
    calls = []

    def fake_post_json(table, payload, prefer="return=minimal", params=None):
        calls.append({"table": table, "payload": payload, "prefer": prefer, "params": params})
        return {}

    monkeypatch.setattr(supabase_store, "SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setattr(supabase_store, "SUPABASE_SERVICE_ROLE_KEY", "server-only-key")
    monkeypatch.setattr(supabase_store, "_post_json", fake_post_json)

    response = _client().post(
        "/v1/waitlist",
        json={"email": "Test.User@Example.COM", "source": "landing"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["stored"] is True

    assert len(calls) == 1
    assert calls[0]["table"] == "waitlist_signups"
    assert calls[0]["payload"]["email"] == "test.user@example.com"
    assert calls[0]["payload"]["source"] == "landing"
    assert calls[0]["prefer"] == "resolution=merge-duplicates,return=minimal"
    assert calls[0]["params"] == {"on_conflict": "email"}
