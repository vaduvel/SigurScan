"""P-RULES Felia 2 — /v1/rules/sync serves the rules manifest, version-gated."""

from services.rules_manifest import manifest_version, rules_sync_payload


def test_full_payload_when_no_client_version():
    payload = rules_sync_payload(None)
    assert payload["changed"] is True
    assert payload["version"] == manifest_version()
    assert payload["count"] > 0
    assert isinstance(payload["manifest"], dict)
    assert "groups" in payload["manifest"]


def test_no_op_when_client_version_matches():
    payload = rules_sync_payload(manifest_version())
    assert payload == {
        "changed": False,
        "version": manifest_version(),
        "manifest": None,
        "count": 0,
    }


def test_full_payload_when_client_version_stale():
    payload = rules_sync_payload("some-old-version")
    assert payload["changed"] is True
    assert payload["manifest"] is not None


def test_endpoint_serves_and_is_version_gated():
    from fastapi.testclient import TestClient
    import main as app_main

    client = TestClient(app_main.app)

    full = client.get("/v1/rules/sync")
    assert full.status_code == 200
    body = full.json()
    assert body["changed"] is True and body["count"] > 0

    gated = client.get("/v1/rules/sync", params={"client_version": body["version"]})
    assert gated.status_code == 200
    assert gated.json()["changed"] is False
