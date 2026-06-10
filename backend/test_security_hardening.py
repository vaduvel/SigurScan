import os
import sys
import time

import pytest
from fastapi.testclient import TestClient

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import main as app_main
from services import play_integrity, rate_limiter


CLIENT_KEY = "client-key-test-1"
CLIENT_KEY_SECOND = "client-key-test-2"
ADMIN_KEY = "admin-key-test-1"

ADMIN_ENDPOINTS = (
    "/v1/orchestration/dashboard",
    "/v1/orchestration/telemetry",
    "/v1/feedback/summary",
    "/v1/adjudication/shadow",
    "/v1/adjudication/dashboard",
)

CHEAP_CLIENT_ENDPOINT = "/v1/reputation/cache/stats"


@pytest.fixture(autouse=True)
def reset_rate_limiter_memory():
    rate_limiter.reset_memory_buckets()
    yield
    rate_limiter.reset_memory_buckets()


def _enable_client_auth(monkeypatch):
    monkeypatch.setattr(app_main, "REQUIRE_API_KEY", True)
    monkeypatch.setattr(app_main, "ALLOWED_API_KEYS", {CLIENT_KEY, CLIENT_KEY_SECOND})


def _enable_admin_auth(monkeypatch):
    monkeypatch.setattr(app_main, "ADMIN_API_KEYS", {ADMIN_KEY})


def test_health_stays_public_and_reports_security_posture(monkeypatch):
    _enable_client_auth(monkeypatch)
    client = TestClient(app_main.app)
    response = client.get("/health")
    assert response.status_code == 200
    config = response.json()["config"]
    assert config["api_key_required"] is True
    assert config["rate_limit_backend"] in {"upstash", "memory_best_effort"}
    assert config["play_integrity_mode"] in {"off", "monitor", "enforce"}
    assert config["admin_api_configured"] in {True, False}


def test_scan_routes_reject_missing_or_invalid_client_key(monkeypatch):
    _enable_client_auth(monkeypatch)
    client = TestClient(app_main.app)

    assert client.get(CHEAP_CLIENT_ENDPOINT).status_code == 401
    assert client.get(CHEAP_CLIENT_ENDPOINT, headers={"X-API-KEY": "wrong"}).status_code == 401
    assert client.post("/v1/scan/text", json={"text": "salut"}).status_code == 401


def test_scan_routes_accept_any_configured_client_key_for_rotation(monkeypatch):
    _enable_client_auth(monkeypatch)
    client = TestClient(app_main.app)

    assert client.get(CHEAP_CLIENT_ENDPOINT, headers={"X-API-KEY": CLIENT_KEY}).status_code == 200
    assert client.get(CHEAP_CLIENT_ENDPOINT, headers={"X-API-KEY": CLIENT_KEY_SECOND}).status_code == 200
    bearer = {"Authorization": f"Bearer {CLIENT_KEY}"}
    assert client.get(CHEAP_CLIENT_ENDPOINT, headers=bearer).status_code == 200


def test_auth_fails_closed_when_no_client_keys_configured(monkeypatch):
    monkeypatch.setattr(app_main, "REQUIRE_API_KEY", True)
    monkeypatch.setattr(app_main, "ALLOWED_API_KEYS", set())
    client = TestClient(app_main.app)

    assert client.get(CHEAP_CLIENT_ENDPOINT).status_code == 401
    assert client.get(CHEAP_CLIENT_ENDPOINT, headers={"X-API-KEY": "anything"}).status_code == 401


def test_admin_endpoints_fail_closed_when_admin_keys_missing(monkeypatch):
    monkeypatch.setattr(app_main, "ADMIN_API_KEYS", set())
    _enable_client_auth(monkeypatch)
    client = TestClient(app_main.app)

    for path in ADMIN_ENDPOINTS:
        response = client.get(path, headers={"X-API-KEY": CLIENT_KEY})
        assert response.status_code == 403, path


def test_admin_endpoints_reject_client_key_and_accept_admin_key(monkeypatch):
    _enable_client_auth(monkeypatch)
    _enable_admin_auth(monkeypatch)
    client = TestClient(app_main.app)

    for path in ADMIN_ENDPOINTS:
        assert client.get(path).status_code == 401, path
        assert client.get(path, headers={"X-API-KEY": CLIENT_KEY}).status_code == 401, path

    assert client.get("/v1/orchestration/telemetry", headers={"X-API-KEY": ADMIN_KEY}).status_code == 200
    assert client.get("/v1/feedback/summary", headers={"X-API-KEY": ADMIN_KEY}).status_code == 200
    assert client.get("/v1/orchestration/dashboard", headers={"X-API-KEY": ADMIN_KEY}).status_code == 200


def test_admin_key_also_works_on_client_routes(monkeypatch):
    _enable_client_auth(monkeypatch)
    _enable_admin_auth(monkeypatch)
    client = TestClient(app_main.app)

    assert client.get(CHEAP_CLIENT_ENDPOINT, headers={"X-API-KEY": ADMIN_KEY}).status_code == 200


def test_screenshot_proxy_stays_loadable_without_headers(monkeypatch):
    """Coil/image loaders cannot attach headers; the GET screenshot proxy must not 401."""
    _enable_client_auth(monkeypatch)
    client = TestClient(app_main.app)

    response = client.get("/v1/sandbox/urlscan/00000000-0000-0000-0000-000000000000/screenshot")
    assert response.status_code != 401


def test_rate_limit_returns_429_after_burst(monkeypatch):
    monkeypatch.setattr(app_main, "ENABLE_RATE_LIMIT", True)
    monkeypatch.setattr(app_main, "RATE_LIMIT_PER_MINUTE", 3)
    client = TestClient(app_main.app)

    statuses = [client.get(CHEAP_CLIENT_ENDPOINT).status_code for _ in range(5)]
    assert statuses[:3] == [200, 200, 200]
    assert 429 in statuses[3:]

    blocked = client.get(CHEAP_CLIENT_ENDPOINT)
    assert blocked.status_code == 429
    assert blocked.headers.get("Retry-After")


def test_rate_limiter_memory_fallback_when_upstash_unconfigured(monkeypatch):
    monkeypatch.setattr(rate_limiter, "UPSTASH_REDIS_REST_URL", "")
    monkeypatch.setattr(rate_limiter, "UPSTASH_REDIS_REST_TOKEN", "")
    assert rate_limiter.backend_mode() == "memory_best_effort"

    decision = None
    for _ in range(4):
        decision = rate_limiter.check_sync(
            api_key=None, client_ip="10.0.0.9", path="/test/fallback", limit_per_minute=3
        )
    assert decision is not None
    assert decision.allowed is False
    assert decision.backend == "memory_best_effort"


def test_rate_limiter_uses_upstash_pipeline_when_configured(monkeypatch):
    monkeypatch.setattr(rate_limiter, "UPSTASH_REDIS_REST_URL", "https://fake-upstash.example")
    monkeypatch.setattr(rate_limiter, "UPSTASH_REDIS_REST_TOKEN", "fake-token")
    assert rate_limiter.backend_mode() == "upstash"

    captured = {}

    def fake_pipeline(commands):
        captured["commands"] = commands
        return [{"result": 0}, {"result": 1}, {"result": 5}, {"result": 1}]

    monkeypatch.setattr(rate_limiter, "_run_upstash_pipeline", fake_pipeline)
    decision = rate_limiter.check_sync(
        api_key="secret-raw-key", client_ip="10.0.0.1", path="/v1/scan/url", limit_per_minute=3
    )
    assert decision.allowed is False
    assert decision.backend == "upstash"
    flattened = " ".join(str(part) for cmd in captured["commands"] for part in cmd)
    assert "secret-raw-key" not in flattened, "raw API key must never reach Redis"


def test_rate_limiter_fails_open_to_memory_on_upstash_error(monkeypatch):
    monkeypatch.setattr(rate_limiter, "UPSTASH_REDIS_REST_URL", "https://fake-upstash.example")
    monkeypatch.setattr(rate_limiter, "UPSTASH_REDIS_REST_TOKEN", "fake-token")

    def broken_pipeline(commands):
        raise RuntimeError("upstash unreachable")

    monkeypatch.setattr(rate_limiter, "_run_upstash_pipeline", broken_pipeline)
    decision = rate_limiter.check_sync(
        api_key=None, client_ip="10.0.0.2", path="/v1/scan/url", limit_per_minute=3
    )
    assert decision.allowed is True
    assert decision.backend == "memory_best_effort"


def test_play_integrity_default_mode_off_does_not_block(monkeypatch):
    assert play_integrity.mode() == "off"
    _enable_client_auth(monkeypatch)
    client = TestClient(app_main.app)
    response = client.get(CHEAP_CLIENT_ENDPOINT, headers={"X-API-KEY": CLIENT_KEY})
    assert response.status_code == 200


def test_play_integrity_enforce_blocks_scan_without_token(monkeypatch):
    _enable_client_auth(monkeypatch)
    monkeypatch.setattr(play_integrity, "PLAY_INTEGRITY_MODE", "enforce")
    client = TestClient(app_main.app)

    response = client.post(
        "/v1/scan/text", json={"text": "salut"}, headers={"X-API-KEY": CLIENT_KEY}
    )
    assert response.status_code == 401
    assert "integrity" in response.json()["detail"].lower()


def test_play_integrity_enforce_allows_valid_token(monkeypatch):
    _enable_client_auth(monkeypatch)
    monkeypatch.setattr(play_integrity, "PLAY_INTEGRITY_MODE", "enforce")
    monkeypatch.setattr(
        play_integrity, "verify_token", lambda token: {"status": "valid", "verdict": "MEETS_DEVICE_INTEGRITY"}
    )
    client = TestClient(app_main.app)

    response = client.post(
        "/v1/scan/text",
        json={"text": "salut"},
        headers={"X-API-KEY": CLIENT_KEY, "X-Play-Integrity-Token": "fake-token"},
    )
    assert response.status_code != 401


def test_play_integrity_monitor_mode_never_blocks(monkeypatch):
    _enable_client_auth(monkeypatch)
    monkeypatch.setattr(play_integrity, "PLAY_INTEGRITY_MODE", "monitor")
    client = TestClient(app_main.app)

    response = client.post(
        "/v1/scan/text", json={"text": "salut"}, headers={"X-API-KEY": CLIENT_KEY}
    )
    assert response.status_code != 401


def test_play_integrity_verify_token_unconfigured_status():
    result = play_integrity.verify_token("some-token")
    assert result["status"] == "unconfigured"


def test_play_integrity_verify_token_missing():
    result = play_integrity.verify_token("")
    assert result["status"] == "missing"
