import time
from datetime import datetime, timezone

from fastapi.testclient import TestClient

import main as app_main
from services import supabase_store
from services.orchestrated_scan import OrchestratedScanEngine


class _FakeResponse:
    def __init__(self, data=None):
        self._data = [] if data is None else data
        self.content = b"" if data is None else b"json"

    def raise_for_status(self):
        return None

    def json(self):
        return self._data


def _iso(ts: int) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def test_supabase_expired_scan_job_is_not_loaded_or_retried_through_legacy_query(monkeypatch):
    now = int(time.time())
    calls = []

    def fake_get(*args, **kwargs):
        calls.append(kwargs)
        return _FakeResponse(
            [
                {
                    "payload": {
                        "scan_id": "orch_expired",
                        "created_at": now - 120,
                        "expires_at": now - 1,
                    },
                    "expires_at": _iso(now - 1),
                    "revision": 4,
                }
            ]
        )

    with monkeypatch.context() as patched:
        patched.setattr(supabase_store, "SUPABASE_URL", "https://example.supabase.co")
        patched.setattr(supabase_store, "SUPABASE_SERVICE_ROLE_KEY", "server-only-key")
        patched.setattr(supabase_store.requests, "get", fake_get)

        job = supabase_store.load_scan_job("orch_expired")

    assert job is None
    assert len(calls) == 1
    assert "expires_at" in calls[0]["params"]["select"]


def test_supabase_unexpired_scan_job_keeps_expiry_and_storage_metadata(monkeypatch):
    now = int(time.time())

    with monkeypatch.context() as patched:
        patched.setattr(supabase_store, "SUPABASE_URL", "https://example.supabase.co")
        patched.setattr(supabase_store, "SUPABASE_SERVICE_ROLE_KEY", "server-only-key")
        patched.setattr(
            supabase_store.requests,
            "get",
            lambda *args, **kwargs: _FakeResponse(
                [
                    {
                        "payload": {
                            "scan_id": "orch_live",
                            "created_at": now,
                            "expires_at": now + 300,
                        },
                        "expires_at": _iso(now + 300),
                        "updated_at": _iso(now),
                        "revision": 8,
                    }
                ]
            ),
        )

        job = supabase_store.load_scan_job("orch_live")

    assert job is not None
    assert job["scan_id"] == "orch_live"
    assert job["expires_at"] == now + 300
    assert job["_storage_revision"] == 8


def test_supabase_claim_requires_unexpired_job(monkeypatch):
    calls = []

    def fake_patch(*args, **kwargs):
        calls.append(kwargs)
        return _FakeResponse([])

    with monkeypatch.context() as patched:
        patched.setattr(supabase_store, "SUPABASE_URL", "https://example.supabase.co")
        patched.setattr(supabase_store, "SUPABASE_SERVICE_ROLE_KEY", "server-only-key")
        patched.setattr(supabase_store.requests, "patch", fake_patch)

        claimed = supabase_store.claim_scan_job(
            "orch_expired",
            expected_revision=3,
            owner="worker-a",
            active_step="resolved",
        )

    assert claimed is None
    assert calls[0]["params"]["expires_at"].startswith("gt.")


def test_supabase_cleanup_deletes_only_expired_rows_without_returning_payload(monkeypatch):
    calls = []

    def fake_delete(*args, **kwargs):
        calls.append(kwargs)
        return _FakeResponse()

    with monkeypatch.context() as patched:
        patched.setattr(supabase_store, "SUPABASE_URL", "https://example.supabase.co")
        patched.setattr(supabase_store, "SUPABASE_SERVICE_ROLE_KEY", "server-only-key")
        patched.setattr(supabase_store.requests, "delete", fake_delete)

        cleaned = supabase_store.cleanup_expired_scan_jobs(before_ts=1_800_000_000)

    assert cleaned is True
    assert calls[0]["params"] == {"expires_at": "lte.2027-01-15T08:00:00+00:00"}
    assert calls[0]["headers"]["Prefer"] == "return=minimal"


def test_orchestrated_memory_fallback_cannot_resurrect_expired_job(monkeypatch):
    now = int(time.time())
    engine = OrchestratedScanEngine()
    engine._ORCHESTRATED_SCAN_JOBS["orch_expired"] = {
        "scan_id": "orch_expired",
        "created_at": now - 120,
        "expires_at": now - 1,
    }

    monkeypatch.setattr(supabase_store, "load_scan_job", lambda scan_id: None)

    assert engine._load_orchestrated_job("orch_expired") is None
    assert "orch_expired" not in engine._ORCHESTRATED_SCAN_JOBS


def test_orchestrated_status_endpoint_returns_404_after_job_ttl(monkeypatch):
    now = int(time.time())
    expired_jobs = {
        "orch_http_expired": {
            "scan_id": "orch_http_expired",
            "created_at": now - 120,
            "expires_at": now - 1,
            "status": "complete",
            "pipeline_stage": "done",
        }
    }
    monkeypatch.setattr(app_main.supabase_store, "load_scan_job", lambda scan_id: None)
    monkeypatch.setattr(app_main.orchestrated_engine, "_ORCHESTRATED_SCAN_JOBS", expired_jobs)
    monkeypatch.setattr(app_main.orchestrated_engine, "_ORCHESTRATED_SCAN_LOCKS", {})

    response = TestClient(app_main.app).get(
        "/v1/scan/orchestrated/orch_http_expired/status"
    )

    assert response.status_code == 404
    assert "expirat" in response.json()["detail"]


def test_fresh_orchestrated_engine_resumes_unexpired_job_from_supabase(monkeypatch):
    now = int(time.time())
    stored_job = {
        "scan_id": "orch_after_restart",
        "created_at": now - 10,
        "expires_at": now + 300,
        "status": "scanning",
        "pipeline_stage": "analysis_ready",
        "_storage_revision": 5,
    }
    engine = OrchestratedScanEngine()
    monkeypatch.setattr(supabase_store, "load_scan_job", lambda scan_id: dict(stored_job))

    resumed = engine._load_orchestrated_job("orch_after_restart")

    assert resumed == stored_job
    assert engine._ORCHESTRATED_SCAN_JOBS["orch_after_restart"] == stored_job


def test_orchestrated_claim_does_not_fall_back_to_stale_job_when_claimed_row_expired(monkeypatch):
    now = int(time.time())
    engine = OrchestratedScanEngine()
    stale_job = {
        "scan_id": "orch_claim_race",
        "created_at": now - 120,
        "expires_at": now + 10,
        "_storage_revision": 2,
    }
    expired_claim = {
        "payload": {**stale_job, "expires_at": now - 1},
        "expires_at": _iso(now - 1),
        "revision": 3,
    }
    monkeypatch.setattr(supabase_store, "claim_scan_job", lambda *args, **kwargs: expired_claim)

    assert engine._claim_distributed_orchestrated_refresh(stale_job) is None


def test_orchestrated_supabase_cleanup_is_throttled_and_failure_is_non_blocking(monkeypatch):
    engine = OrchestratedScanEngine()
    calls = []

    def fake_cleanup(*, before_ts):
        calls.append(before_ts)
        return False

    monkeypatch.setattr(supabase_store, "cleanup_expired_scan_jobs", fake_cleanup)
    monkeypatch.setattr("services.orchestrated_scan.ORCHESTRATED_SUPABASE_CLEANUP_INTERVAL_SECONDS", 300)
    monkeypatch.setattr("services.orchestrated_scan.time.time", lambda: 1_800_000_000.0)

    assert engine._cleanup_expired_orchestrated_jobs() is False
    assert engine._cleanup_expired_orchestrated_jobs() is False
    assert calls == [1_800_000_000]
