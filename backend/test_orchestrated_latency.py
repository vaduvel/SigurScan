"""Fast-path behavior of the orchestrated pipeline: stage collapsing within a
poll time budget, early provisional verdicts before the urlscan report, and
deferred AI explanations. The legacy stage-per-poll semantics stay covered in
test_backend.py with these features pinned off."""

import os
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import main as app_main
from test_backend import (
    _clean_external_intel_for_resolved_urls,
    _fake_confirmed_offer_claim,
    _fake_urlscan_get_clean,
    _fake_urlscan_get_malicious,
    _fake_urlscan_post,
    _fake_yoxo_safe_scan,
    _poll_orchestrated,
)

YOXO_MESSAGE = (
    "Ai un telefon sau o tableta pe care nu le mai folosesti? "
    "Acum le poti transforma rapid in bani cu serviciul de buy-back YOXO. "
    "Afla cat valoreaza dispozitivul tau si incepe procesul chiar acum: buyback.yoxo.ro"
)


@pytest.fixture(autouse=True)
def _disable_live_mistral(monkeypatch):
    monkeypatch.setattr(app_main, "MISTRAL_SEMANTIC_API_KEY", "")


@pytest.fixture(autouse=True)
def _isolate_preview_caches(monkeypatch):
    app_main._URLSCAN_PREVIEW_CACHE.clear()
    app_main._FAST_PREVIEW_CACHE.clear()
    monkeypatch.setattr(app_main.supabase_store, "load_urlscan_preview_cache", lambda url_hash: None)
    monkeypatch.setattr(app_main.supabase_store, "save_urlscan_preview_cache", lambda entry: None)
    monkeypatch.setattr(app_main.supabase_store, "load_fast_preview_cache", lambda url_hash: None)
    monkeypatch.setattr(app_main.supabase_store, "load_fast_preview_alias_cache", lambda alias_hash: None)
    monkeypatch.setattr(app_main.supabase_store, "create_preview_signed_url", lambda *args, **kwargs: None)
    yield
    app_main._URLSCAN_PREVIEW_CACHE.clear()
    app_main._FAST_PREVIEW_CACHE.clear()


@pytest.fixture(autouse=True)
def _fast_path_enabled(monkeypatch):
    monkeypatch.setattr(app_main, "ORCHESTRATED_EARLY_VERDICT", True)
    monkeypatch.setattr(app_main, "ORCHESTRATED_DEFER_AI_EXPLANATION", True)
    monkeypatch.setattr(app_main, "MAX_SINGLE_POLL_SERVER_WORK_MS", 7500)


def _patch_clean_scan(patched, urlscan_get=_fake_urlscan_get_clean):
    patched.setattr(app_main, "PRIVACY_SAFE_MODE", False)
    patched.setattr(app_main, "URLSCAN_API_KEY", "server-only-key")
    patched.setattr(app_main, "_safe_scan_url_list", _fake_yoxo_safe_scan)
    patched.setattr(app_main, "_gather_external_intel_safe", _clean_external_intel_for_resolved_urls)
    patched.setattr(app_main, "_enrich_offer_claim_verification_async", _fake_confirmed_offer_claim)
    patched.setattr(app_main.requests, "post", _fake_urlscan_post)
    if urlscan_get is not None:
        patched.setattr(app_main.requests, "get", urlscan_get)


def _start_scan(client):
    return client.post(
        "/v1/scan/orchestrated",
        json={"input_type": "text", "text": YOXO_MESSAGE, "source_channel": "android_native"},
    ).json()


def test_first_poll_publishes_provisional_verdict_before_urlscan(monkeypatch):
    client = TestClient(app_main.app)
    with monkeypatch.context() as patched:
        _patch_clean_scan(patched, urlscan_get=None)

        start = _start_scan(client)
        _, payload = _poll_orchestrated(client, start["scan_id"], count=1)

    assert payload["status"] == "scanning"
    assert payload["result"] is not None
    assert payload["result"]["user_risk_label"] == "SIGUR"
    assert payload["result"]["is_final"] is False
    assert payload["pillars"]["urlscan"]["status"] == "pending"
    assert "preliminar" in payload["status_message"].lower()


def test_first_poll_returns_provisional_without_entering_llm_stage(monkeypatch):
    """BLOCKER 6: the provisional verdict ships from fast-lane evidence; the
    cloud-LLM semantic/claim stage must never run synchronously inside the
    first poll (a slow LLM would otherwise push the poll toward maxDuration)."""
    client = TestClient(app_main.app)
    semantic_calls = []

    async def recording_semantic(text, analysis, resolved_urls):
        semantic_calls.append(True)
        app_main._enrich_local_semantic_review(text, analysis)

    with monkeypatch.context() as patched:
        _patch_clean_scan(patched, urlscan_get=None)
        patched.setattr(app_main, "_enrich_semantic_review_async", recording_semantic)

        start = _start_scan(client)
        _, first = _poll_orchestrated(client, start["scan_id"], count=1)
        first_poll_semantic_calls = list(semantic_calls)
        _, second = _poll_orchestrated(client, start["scan_id"], count=1)

    assert first["result"] is not None
    assert first["result"]["is_final"] is False
    assert not first_poll_semantic_calls, "LLM semantic stage must not run in the first poll"
    assert semantic_calls, "semantic enrichment must run on a later poll"
    assert second["result"] is not None


def test_deferred_explanation_upgrades_on_next_poll_without_blocking_first(monkeypatch):
    client = TestClient(app_main.app)
    explainer_calls = []

    async def fake_explainer(text, analysis, resolved_urls):
        explainer_calls.append(True)
        return {"summary": "explicatie cloud", "source": "fake-llm"}

    with monkeypatch.context() as patched:
        _patch_clean_scan(patched, urlscan_get=None)
        patched.setattr(app_main, "_build_ai_explanation_async", fake_explainer)

        start = _start_scan(client)
        _, first = _poll_orchestrated(client, start["scan_id"], count=1)
        _, second = _poll_orchestrated(client, start["scan_id"], count=1)

    assert first["result"] is not None
    assert not explainer_calls or first["result"]["is_final"] is False
    assert explainer_calls, "cloud explanation must be computed by the follow-up poll"
    assert second["result"] is not None


def test_provisional_verdict_finalizes_after_clean_urlscan(monkeypatch):
    client = TestClient(app_main.app)
    with monkeypatch.context() as patched:
        _patch_clean_scan(patched, urlscan_get=_fake_urlscan_get_clean)

        start = _start_scan(client)
        _, provisional = _poll_orchestrated(client, start["scan_id"], count=1)
        _, final = _poll_orchestrated(client, start["scan_id"], count=4)

    assert provisional["result"]["is_final"] is False
    assert final["status"] == "complete"
    assert final["result"]["user_risk_label"] == "SIGUR"
    assert final["result"]["is_final"] is True
    assert final["result"]["evidence"]["provider_gate"]["urlscan_consulted"] is True


def test_late_malicious_urlscan_raises_provisional_safe_verdict(monkeypatch):
    client = TestClient(app_main.app)
    with monkeypatch.context() as patched:
        _patch_clean_scan(patched, urlscan_get=_fake_urlscan_get_malicious)

        start = _start_scan(client)
        _, provisional = _poll_orchestrated(client, start["scan_id"], count=1)
        _, upgraded = _poll_orchestrated(client, start["scan_id"], count=4)

    assert provisional["result"]["user_risk_label"] == "SIGUR"
    assert provisional["result"]["is_final"] is False
    assert upgraded["status"] == "complete"
    assert upgraded["result"]["user_risk_label"] == "PERICULOS"
    assert upgraded["result"]["risk_level"] == "high"
    assert upgraded["result"]["is_final"] is True


def test_scan_events_logged_only_for_final_verdicts(monkeypatch):
    client = TestClient(app_main.app)
    emitted = []

    with monkeypatch.context() as patched:
        _patch_clean_scan(patched, urlscan_get=_fake_urlscan_get_clean)
        patched.setattr(
            app_main,
            "_emit_scan_event",
            lambda **kwargs: emitted.append(kwargs["scan_payload"]["is_final"]),
        )

        start = _start_scan(client)
        _poll_orchestrated(client, start["scan_id"], count=5)

    assert emitted, "the final verdict must be logged"
    assert all(emitted), "provisional verdicts must not pollute scan_events telemetry"


def test_collapse_respects_disabled_budget(monkeypatch):
    monkeypatch.setattr(app_main, "MAX_SINGLE_POLL_SERVER_WORK_MS", 0)
    monkeypatch.setattr(app_main, "ORCHESTRATED_EARLY_VERDICT", False)
    monkeypatch.setattr(app_main, "ORCHESTRATED_DEFER_AI_EXPLANATION", False)
    client = TestClient(app_main.app)
    with monkeypatch.context() as patched:
        _patch_clean_scan(patched, urlscan_get=None)

        start = _start_scan(client)
        _, payload = _poll_orchestrated(client, start["scan_id"], count=1)

    assert payload["status"] == "scanning"
    assert payload["result"] is None
    assert payload["diagnostics"]["pipeline_stage"] in {"semantic_ready", "analysis_ready"}
