import os
import re
import time

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

import config
from app import app
from core.identity import _new_scan_id
from core.scan_context import _resolve_eval_dataset_path
from services import play_integrity, play_integrity_nonce, rate_limiter
from services.scan_helpers import _is_allowed_image_bytes, _validate_file_upload


CLIENT_KEY = "client-key-test-1"
CLIENT_KEY_SECOND = "client-key-test-2"
ADMIN_KEY = "admin-key-test-1"

ADMIN_ENDPOINTS = (
    "/v1/orchestration/dashboard",
    "/v1/orchestration/telemetry",
    "/v1/feedback/summary",
    "/v1/adjudication/shadow",
    "/v1/adjudication/dashboard",
    "/v1/intel/ingest",
    "/v1/intel/moderate",
    "/v1/intel/moderation-queue",
    "/v1/intel/sources",
    "/v1/campaign/active",
    "/v1/campaign/families",
    "/v1/campaign/match",
    "/v1/evaluation/feedback",
    "/v1/evaluation/run",
    "/v1/feedback/samples",
    "/v1/feedback/quality",
    "/v1/evaluation/feedback/trend",
    "/v1/evaluation/readiness",
)

CHEAP_CLIENT_ENDPOINT = "/v1/reputation/cache/stats"


@pytest.fixture(autouse=True)
def reset_rate_limiter_memory():
    rate_limiter.reset_memory_buckets()
    yield
    rate_limiter.reset_memory_buckets()


def _enable_client_auth(monkeypatch):
    monkeypatch.setattr(config, "REQUIRE_API_KEY", True)
    monkeypatch.setattr(config, "ALLOWED_API_KEYS", {CLIENT_KEY, CLIENT_KEY_SECOND})


def _enable_admin_auth(monkeypatch):
    monkeypatch.setattr(config, "ADMIN_API_KEYS", {ADMIN_KEY})


def test_health_stays_public_and_reports_security_posture(monkeypatch):
    _enable_client_auth(monkeypatch)
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    config = response.json()["config"]
    assert config["api_key_required"] is True
    assert config["rate_limit_backend"] in {"upstash", "memory_best_effort"}
    assert config["play_integrity_mode"] in {"off", "monitor", "enforce"}
    assert config["admin_api_configured"] in {True, False}
    assert config["mock_ocr_allowed"] in {True, False}


def test_security_health_exposes_non_secret_prod_posture(monkeypatch):
    _enable_client_auth(monkeypatch)
    monkeypatch.setattr(config, "ALLOWED_MOCK_OCR", False)
    client = TestClient(app)

    response = client.get("/health/security")

    assert response.status_code == 200
    body = response.json()
    assert body["api_key_required"] is True
    assert body["mock_ocr_allowed"] is False
    assert "providers" in body


def test_api_docs_are_not_public_by_default():
    client = TestClient(app)

    assert client.get("/docs").status_code != 200
    assert client.get("/openapi.json").status_code != 200
    assert client.get("/redoc").status_code != 200
    assert client.get("/").json()["api_docs"] is None


def test_cors_policy_uses_explicit_methods_and_headers():
    assert "*" not in config.ALLOWED_CORS_METHODS
    assert "*" not in config.ALLOWED_CORS_HEADERS
    assert {"GET", "POST", "OPTIONS"}.issubset(set(config.ALLOWED_CORS_METHODS))
    assert {
        "Authorization",
        "Content-Type",
        "X-API-KEY",
        "X-Play-Integrity-Token",
        "X-SigurScan-Client-Instance",
    }.issubset(set(config.ALLOWED_CORS_HEADERS))


def test_image_upload_validation_checks_magic_bytes():
    with pytest.raises(HTTPException) as exc:
        _validate_file_upload(
            filename="invoice.jpg",
            content_type="image/jpeg",
            file_bytes=b"not really an image",
            max_bytes=config.MAX_IMAGE_BYTES,
            allowed_exts=config.ALLOWED_IMAGE_EXTS,
            allowed_mime_types=config.ALLOWED_IMAGE_MIME_TYPES,
            magic_validator=_is_allowed_image_bytes,
        )

    assert exc.value.status_code == 400
    assert "valid" in str(exc.value.detail).lower()


def test_scan_routes_reject_missing_or_invalid_client_key(monkeypatch):
    _enable_client_auth(monkeypatch)
    client = TestClient(app)

    assert client.get(CHEAP_CLIENT_ENDPOINT).status_code == 401
    assert client.get(CHEAP_CLIENT_ENDPOINT, headers={"X-API-KEY": "wrong"}).status_code == 401
    assert client.post("/v1/scan/text", json={"text": "salut"}).status_code == 401


def test_scan_routes_accept_any_configured_client_key_for_rotation(monkeypatch):
    _enable_client_auth(monkeypatch)
    client = TestClient(app)

    assert client.get(CHEAP_CLIENT_ENDPOINT, headers={"X-API-KEY": CLIENT_KEY}).status_code == 200
    assert client.get(CHEAP_CLIENT_ENDPOINT, headers={"X-API-KEY": CLIENT_KEY_SECOND}).status_code == 200
    bearer = {"Authorization": f"Bearer {CLIENT_KEY}"}
    assert client.get(CHEAP_CLIENT_ENDPOINT, headers=bearer).status_code == 200


def test_auth_fails_closed_when_no_client_keys_configured(monkeypatch):
    monkeypatch.setattr(config, "REQUIRE_API_KEY", True)
    monkeypatch.setattr(config, "ALLOWED_API_KEYS", set())
    client = TestClient(app)

    assert client.get(CHEAP_CLIENT_ENDPOINT).status_code == 401
    assert client.get(CHEAP_CLIENT_ENDPOINT, headers={"X-API-KEY": "anything"}).status_code == 401


def test_admin_endpoints_fail_closed_when_admin_keys_missing(monkeypatch):
    monkeypatch.setattr(config, "ADMIN_API_KEYS", set())
    _enable_client_auth(monkeypatch)
    client = TestClient(app)

    for path in ADMIN_ENDPOINTS:
        response = client.get(path, headers={"X-API-KEY": CLIENT_KEY})
        assert response.status_code == 403, path


def test_admin_endpoints_reject_client_key_and_accept_admin_key(monkeypatch):
    _enable_client_auth(monkeypatch)
    _enable_admin_auth(monkeypatch)
    client = TestClient(app)

    for path in ADMIN_ENDPOINTS:
        assert client.get(path).status_code == 401, path
        assert client.get(path, headers={"X-API-KEY": CLIENT_KEY}).status_code == 401, path

    assert client.get("/v1/orchestration/telemetry", headers={"X-API-KEY": ADMIN_KEY}).status_code == 200
    assert client.get("/v1/feedback/summary", headers={"X-API-KEY": ADMIN_KEY}).status_code == 200
    assert client.get("/v1/orchestration/dashboard", headers={"X-API-KEY": ADMIN_KEY}).status_code == 200


def test_admin_key_does_not_work_on_client_routes(monkeypatch):
    _enable_client_auth(monkeypatch)
    _enable_admin_auth(monkeypatch)
    client = TestClient(app)

    assert client.get(CHEAP_CLIENT_ENDPOINT, headers={"X-API-KEY": ADMIN_KEY}).status_code == 401


def test_internal_worker_routes_reject_client_and_admin_api_keys(monkeypatch):
    _enable_client_auth(monkeypatch)
    _enable_admin_auth(monkeypatch)
    monkeypatch.setattr(config, "INTERNAL_WORKER_TOKEN", "unit-worker-token")
    client = TestClient(app)

    path = "/internal/orchestrated/orch_missing/advance"

    assert client.post(path, headers={"X-API-KEY": CLIENT_KEY}).status_code == 401
    assert client.post(path, headers={"X-API-KEY": ADMIN_KEY}).status_code == 401
    assert client.post(path, headers={"X-Internal-Worker-Token": "unit-worker-token"}).status_code == 404


def test_scan_ids_do_not_expose_timestamp_or_low_entropy_suffix():
    generated = {_new_scan_id("orch") for _ in range(20)}

    assert len(generated) == 20
    for scan_id in generated:
        assert scan_id.startswith("orch_")
        assert not re.match(r"^orch_\d{9,12}_[0-9a-f]{8}$", scan_id)
        assert len(scan_id.removeprefix("orch_")) >= 24


def test_evaluation_dataset_path_is_limited_to_backend_data(tmp_path):
    outside_dataset = tmp_path / "external_eval.jsonl"
    outside_dataset.write_text("{}\n", encoding="utf-8")

    with pytest.raises(HTTPException) as exc:
        _resolve_eval_dataset_path(str(outside_dataset))

    assert getattr(exc.value, "status_code", None) == 400


def test_screenshot_proxy_stays_loadable_without_headers(monkeypatch):
    """Coil/image loaders cannot attach headers; the GET screenshot proxy must not 401."""
    _enable_client_auth(monkeypatch)
    client = TestClient(app)

    response = client.get("/v1/sandbox/urlscan/00000000-0000-0000-0000-000000000000/screenshot")
    assert response.status_code != 401


def test_rate_limit_returns_429_after_burst(monkeypatch):
    monkeypatch.setattr(config, "ENABLE_RATE_LIMIT", True)
    monkeypatch.setattr(config, "RATE_LIMIT_PER_MINUTE", 3)
    client = TestClient(app)

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


def test_shared_client_api_key_does_not_create_global_rate_limit_bucket(monkeypatch):
    monkeypatch.setattr(rate_limiter, "UPSTASH_REDIS_REST_URL", "")
    monkeypatch.setattr(rate_limiter, "UPSTASH_REDIS_REST_TOKEN", "")

    first = rate_limiter.check_sync(
        api_key=CLIENT_KEY,
        client_ip="10.0.0.10",
        path="/v1/scan/orchestrated",
        limit_per_minute=1,
        include_api_key_identity=False,
    )
    second_ip_same_key = rate_limiter.check_sync(
        api_key=CLIENT_KEY,
        client_ip="10.0.0.11",
        path="/v1/scan/orchestrated",
        limit_per_minute=1,
        include_api_key_identity=False,
    )
    same_ip_again = rate_limiter.check_sync(
        api_key=CLIENT_KEY,
        client_ip="10.0.0.10",
        path="/v1/scan/orchestrated",
        limit_per_minute=1,
        include_api_key_identity=False,
    )

    assert first.allowed is True
    assert second_ip_same_key.allowed is True
    assert same_ip_again.allowed is False
    assert same_ip_again.identity == "ip:10.0.0.10"


def test_operator_api_key_can_still_be_rate_limited_across_ips(monkeypatch):
    monkeypatch.setattr(rate_limiter, "UPSTASH_REDIS_REST_URL", "")
    monkeypatch.setattr(rate_limiter, "UPSTASH_REDIS_REST_TOKEN", "")

    first = rate_limiter.check_sync(
        api_key=ADMIN_KEY,
        client_ip="10.0.0.20",
        path="/v1/orchestration/dashboard",
        limit_per_minute=1,
        include_api_key_identity=True,
    )
    second_ip_same_key = rate_limiter.check_sync(
        api_key=ADMIN_KEY,
        client_ip="10.0.0.21",
        path="/v1/orchestration/dashboard",
        limit_per_minute=1,
        include_api_key_identity=True,
    )

    assert first.allowed is True
    assert second_ip_same_key.allowed is False
    assert second_ip_same_key.identity.startswith("key:")


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
    monkeypatch.setattr(rate_limiter, "RATE_LIMIT_FAIL_CLOSED", False)

    def broken_pipeline(commands):
        raise RuntimeError("upstash unreachable")

    monkeypatch.setattr(rate_limiter, "_run_upstash_pipeline", broken_pipeline)
    decision = rate_limiter.check_sync(
        api_key=None, client_ip="10.0.0.2", path="/v1/scan/url", limit_per_minute=3
    )
    assert decision.allowed is True
    assert decision.backend == "memory_best_effort"


def test_rate_limiter_can_fail_closed_on_upstash_error(monkeypatch):
    monkeypatch.setattr(rate_limiter, "UPSTASH_REDIS_REST_URL", "https://fake-upstash.example")
    monkeypatch.setattr(rate_limiter, "UPSTASH_REDIS_REST_TOKEN", "fake-token")
    monkeypatch.setattr(rate_limiter, "RATE_LIMIT_FAIL_CLOSED", True)

    def broken_pipeline(commands):
        raise RuntimeError("upstash unreachable")

    monkeypatch.setattr(rate_limiter, "_run_upstash_pipeline", broken_pipeline)
    decision = rate_limiter.check_sync(
        api_key=None, client_ip="10.0.0.10", path="/v1/scan/text", limit_per_minute=60
    )

    assert decision.allowed is False
    assert decision.backend == "upstash_unavailable"


def test_play_integrity_default_mode_off_does_not_block(monkeypatch):
    assert play_integrity.mode() == "off"
    _enable_client_auth(monkeypatch)
    client = TestClient(app)
    response = client.get(CHEAP_CLIENT_ENDPOINT, headers={"X-API-KEY": CLIENT_KEY})
    assert response.status_code == 200


def test_play_integrity_enforce_blocks_scan_without_token(monkeypatch):
    _enable_client_auth(monkeypatch)
    monkeypatch.setattr(play_integrity, "PLAY_INTEGRITY_MODE", "enforce")
    client = TestClient(app)

    response = client.post(
        "/v1/scan/text", json={"text": "salut"}, headers={"X-API-KEY": CLIENT_KEY}
    )
    assert response.status_code == 401
    assert "integrity" in response.json()["detail"].lower()


def test_play_integrity_enforce_blocks_audio_semantic_review_without_token(monkeypatch):
    _enable_client_auth(monkeypatch)
    monkeypatch.setattr(play_integrity, "PLAY_INTEGRITY_MODE", "enforce")
    client = TestClient(app)

    response = client.post(
        "/v1/audio/semantic-review",
        json={"transcript_redacted": "[redactat]"},
        headers={"X-API-KEY": CLIENT_KEY},
    )

    assert response.status_code == 401
    assert "integrity" in response.json()["detail"].lower()


def test_play_integrity_enforce_allows_valid_token(monkeypatch):
    _enable_client_auth(monkeypatch)
    monkeypatch.setattr(play_integrity, "PLAY_INTEGRITY_MODE", "enforce")
    monkeypatch.setattr(
        play_integrity,
        "verify_token",
        lambda token, api_key="": {"status": "valid", "verdict": "MEETS_DEVICE_INTEGRITY"},
    )
    client = TestClient(app)

    response = client.post(
        "/v1/scan/text",
        json={"text": "salut"},
        headers={"X-API-KEY": CLIENT_KEY, "X-Play-Integrity-Token": "fake-token"},
    )
    assert response.status_code != 401


def test_play_integrity_enforce_blocks_unconfigured_or_transient_error(monkeypatch):
    monkeypatch.setattr(play_integrity, "PLAY_INTEGRITY_MODE", "enforce")
    monkeypatch.setattr(
        play_integrity,
        "verify_token",
        lambda token, api_key="": {"status": "unconfigured"},
    )
    assert play_integrity.evaluate_request_token("fake-token", CLIENT_KEY)["block"] is True

    monkeypatch.setattr(
        play_integrity,
        "verify_token",
        lambda token, api_key="": {"status": "error", "detail": "google timeout"},
    )
    assert play_integrity.evaluate_request_token("fake-token", CLIENT_KEY)["block"] is True

    monkeypatch.setattr(
        play_integrity,
        "verify_token",
        lambda token, api_key="": {"status": "invalid"},
    )
    assert play_integrity.evaluate_request_token("fake-token", CLIENT_KEY)["block"] is True


def test_play_integrity_monitor_mode_never_blocks(monkeypatch):
    _enable_client_auth(monkeypatch)
    monkeypatch.setattr(play_integrity, "PLAY_INTEGRITY_MODE", "monitor")
    client = TestClient(app)

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


def test_play_integrity_mints_access_token_from_service_account_json(monkeypatch):
    captured = {}

    class FakeCredentials:
        token = None

        def with_scopes(self, scopes):
            captured["scopes"] = scopes
            return self

        def refresh(self, request):
            captured["request"] = request
            self.token = "ya29.fake-access-token"

    class FakeCredentialsFactory:
        @staticmethod
        def from_service_account_info(info):
            captured["service_account_info"] = info
            return FakeCredentials()

    class FakeServiceAccountModule:
        Credentials = FakeCredentialsFactory

    monkeypatch.setattr(
        play_integrity,
        "PLAY_INTEGRITY_CREDENTIALS_JSON",
        '{"client_email":"sigurscan@example.iam.gserviceaccount.com","private_key":"fake"}',
    )
    monkeypatch.setattr(play_integrity, "service_account", FakeServiceAccountModule, raising=False)
    monkeypatch.setattr(play_integrity, "GoogleAuthRequest", lambda: "google-auth-request", raising=False)

    assert play_integrity._mint_access_token() == "ya29.fake-access-token"
    assert captured["service_account_info"]["client_email"] == "sigurscan@example.iam.gserviceaccount.com"
    assert "https://www.googleapis.com/auth/playintegrity" in captured["scopes"]
    assert captured["request"] == "google-auth-request"


def test_play_integrity_nonce_issue_stores_only_hash_and_client_binding(monkeypatch):
    monkeypatch.setattr(play_integrity_nonce, "UPSTASH_REDIS_REST_URL", "https://fake-upstash.example")
    monkeypatch.setattr(play_integrity_nonce, "UPSTASH_REDIS_REST_TOKEN", "fake-token")
    monkeypatch.setattr(play_integrity_nonce.secrets, "token_urlsafe", lambda _: "issued-nonce-value")
    captured = {}

    def fake_command(command):
        captured["command"] = command
        return {"result": "OK"}

    monkeypatch.setattr(play_integrity_nonce, "_run_upstash_command", fake_command)
    issued = play_integrity_nonce.issue_nonce(CLIENT_KEY)

    assert issued["status"] == "issued"
    assert issued["nonce"] == "issued-nonce-value"
    command_text = " ".join(captured["command"])
    assert "issued-nonce-value" not in command_text
    assert CLIENT_KEY not in command_text
    assert captured["command"][0] == "SET"
    assert captured["command"][-1] == "NX"


def test_play_integrity_nonce_consume_is_atomic_and_single_use(monkeypatch):
    monkeypatch.setattr(play_integrity_nonce, "UPSTASH_REDIS_REST_URL", "https://fake-upstash.example")
    monkeypatch.setattr(play_integrity_nonce, "UPSTASH_REDIS_REST_TOKEN", "fake-token")
    stored_binding = play_integrity_nonce._client_binding(CLIENT_KEY)
    replies = iter(({"result": stored_binding}, {"result": None}))
    commands = []

    def fake_command(command):
        commands.append(command)
        return next(replies)

    monkeypatch.setattr(play_integrity_nonce, "_run_upstash_command", fake_command)

    assert play_integrity_nonce.consume_nonce("nonce-1", CLIENT_KEY)["status"] == "consumed"
    assert play_integrity_nonce.consume_nonce("nonce-1", CLIENT_KEY)["status"] == "missing_or_replayed"
    assert all(command[0] == "GETDEL" for command in commands)


def test_play_integrity_nonce_store_errors_fail_closed_without_crashing(monkeypatch):
    monkeypatch.setattr(play_integrity_nonce, "UPSTASH_REDIS_REST_URL", "https://fake-upstash.example")
    monkeypatch.setattr(play_integrity_nonce, "UPSTASH_REDIS_REST_TOKEN", "fake-token")
    monkeypatch.setattr(
        play_integrity_nonce,
        "_run_upstash_command",
        lambda command: (_ for _ in ()).throw(ValueError("invalid redis response")),
    )

    assert play_integrity_nonce.issue_nonce(CLIENT_KEY)["status"] == "store_unavailable"
    assert play_integrity_nonce.consume_nonce("nonce-1", CLIENT_KEY)["status"] == "store_unavailable"


def test_play_integrity_nonce_client_mismatch_is_rejected(monkeypatch):
    monkeypatch.setattr(play_integrity_nonce, "UPSTASH_REDIS_REST_URL", "https://fake-upstash.example")
    monkeypatch.setattr(play_integrity_nonce, "UPSTASH_REDIS_REST_TOKEN", "fake-token")
    monkeypatch.setattr(
        play_integrity_nonce,
        "_run_upstash_command",
        lambda command: {"result": play_integrity_nonce._client_binding(CLIENT_KEY_SECOND)},
    )

    assert play_integrity_nonce.consume_nonce("nonce-1", CLIENT_KEY)["status"] == "client_mismatch"


def test_play_integrity_valid_verdict_requires_fresh_consumed_nonce(monkeypatch):
    now_ms = int(time.time() * 1000)
    monkeypatch.setattr(
        play_integrity_nonce,
        "consume_nonce",
        lambda nonce, api_key: {"status": "consumed"},
    )
    decoded = {
        "tokenPayloadExternal": {
            "requestDetails": {"nonce": "nonce-1", "timestampMillis": str(now_ms)},
            "appIntegrity": {
                "appRecognitionVerdict": "PLAY_RECOGNIZED",
                "packageName": "ro.sigurscan.app",
            },
            "deviceIntegrity": {"deviceRecognitionVerdict": ["MEETS_DEVICE_INTEGRITY"]},
        }
    }

    result = play_integrity._evaluate_verdict(decoded, CLIENT_KEY)

    assert result["status"] == "valid"
    assert result["nonce_status"] == "consumed"
    assert result["timestamp_fresh"] is True


def test_play_integrity_rejects_stale_or_replayed_nonce(monkeypatch):
    old_ms = int((time.time() - play_integrity.PLAY_INTEGRITY_MAX_TOKEN_AGE_SECONDS - 5) * 1000)
    monkeypatch.setattr(
        play_integrity_nonce,
        "consume_nonce",
        lambda nonce, api_key: {"status": "missing_or_replayed"},
    )
    decoded = {
        "tokenPayloadExternal": {
            "requestDetails": {"nonce": "nonce-1", "timestampMillis": str(old_ms)},
            "appIntegrity": {
                "appRecognitionVerdict": "PLAY_RECOGNIZED",
                "packageName": "ro.sigurscan.app",
            },
            "deviceIntegrity": {"deviceRecognitionVerdict": ["MEETS_DEVICE_INTEGRITY"]},
        }
    }

    result = play_integrity._evaluate_verdict(decoded, CLIENT_KEY)

    assert result["status"] == "invalid"
    assert result["nonce_status"] == "missing_or_replayed"
    assert result["timestamp_fresh"] is False


def test_play_integrity_enforce_can_authorize_scan_without_static_client_key(monkeypatch):
    _enable_client_auth(monkeypatch)
    monkeypatch.setattr(play_integrity, "PLAY_INTEGRITY_MODE", "enforce")
    captured = {}

    def fake_evaluate(token, client_binding=""):
        captured["token"] = token
        captured["client_binding"] = client_binding
        return {"block": False, "result": {"status": "valid"}}

    monkeypatch.setattr(play_integrity, "evaluate_request_token", fake_evaluate)
    client = TestClient(app)

    response = client.post(
        "/v1/scan/text",
        json={"text": "salut"},
        headers={
            "X-Play-Integrity-Token": "valid-integrity-token",
            "X-SigurScan-Client-Instance": "android-install-1",
        },
    )

    assert response.status_code != 401
    assert captured == {
        "token": "valid-integrity-token",
        "client_binding": "android-install-1",
    }


def test_play_integrity_nonce_endpoint_uses_client_instance_without_static_key(monkeypatch):
    _enable_client_auth(monkeypatch)
    monkeypatch.setattr(play_integrity, "PLAY_INTEGRITY_MODE", "enforce")
    captured = {}

    def fake_issue_nonce(client_binding):
        captured["client_binding"] = client_binding
        return {"status": "issued", "nonce": "nonce-1", "expires_in_seconds": 120}

    monkeypatch.setattr(
        play_integrity_nonce,
        "issue_nonce",
        fake_issue_nonce,
    )
    client = TestClient(app)

    response = client.post(
        "/v1/security/play-integrity/nonce",
        headers={"X-SigurScan-Client-Instance": " android-install-1 "},
    )

    assert response.status_code == 200
    assert response.json() == {"nonce": "nonce-1", "expires_in_seconds": 120}
    assert captured == {"client_binding": "android-install-1"}
