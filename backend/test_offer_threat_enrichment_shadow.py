import asyncio
import copy
import json

from api_models import OrchestratedScanRequest
from services import orchestrated_scan as orchestrated_module
from services.orchestrated_scan import orchestrated_engine


SENSITIVE_OFFER_URL = "https://anaf-spv.info/plata?otp=123456&campaign=summer"
SAFE_OFFER_URL = "https://anaf-spv.info/plata?campaign=summer"


def _make_offer_job(monkeypatch):
    monkeypatch.setattr(orchestrated_engine, "_persist_orchestrated_job", lambda candidate: candidate)
    monkeypatch.setattr(orchestrated_engine, "_emit_orchestrated_telemetry", lambda *args, **kwargs: None)
    return asyncio.run(
        orchestrated_engine._create_orchestrated_job(
            OrchestratedScanRequest(
                input_type="offer",
                text=f"Oferta este disponibilă la {SENSITIVE_OFFER_URL}",
                source_channel="share_text",
            )
        )
    )


def _run_offer_lane(job):
    return asyncio.run(orchestrated_engine._run_orchestrated_offer_fast_lane(job, None))


def _fake_malicious_intel(resolved_urls, **kwargs):
    url = resolved_urls[0]["final_url"]
    return {
        url: {
            "url": url,
            "sources": {
                "google_web_risk": {
                    "status": "malicious",
                    "verdict": "phishing",
                    "consulted": True,
                }
            },
        }
    }


def test_offer_threat_enrichment_shadow_flag_defaults_off():
    assert orchestrated_module.OFFER_THREAT_ENRICHMENT_SHADOW is False


def test_offer_shadow_off_makes_no_provider_calls(monkeypatch):
    job = _make_offer_job(monkeypatch)
    initial_enrichment = copy.deepcopy(job["threat_enrichment"])

    monkeypatch.setattr(orchestrated_module, "OFFER_THREAT_ENRICHMENT_SHADOW", False)
    monkeypatch.setattr(
        orchestrated_module,
        "_safe_scan_url_list",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("resolver must stay off")),
    )
    monkeypatch.setattr(
        orchestrated_module,
        "_gather_external_intel_safe",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("providers must stay off")),
    )

    result = _run_offer_lane(job)

    assert result["analysis"]["evidence"]["verdict_gate"]["label"]
    assert result["threat_enrichment"] == initial_enrichment
    assert "offer_threat_enrichment_shadow" not in result


def test_offer_shadow_records_malicious_provider_without_changing_verdict(monkeypatch):
    base_job = _make_offer_job(monkeypatch)
    off_job = copy.deepcopy(base_job)
    on_job = copy.deepcopy(base_job)
    resolver_inputs = []
    provider_inputs = []

    monkeypatch.setattr(orchestrated_module, "OFFER_THREAT_ENRICHMENT_SHADOW", False)
    off_result = _run_offer_lane(off_job)
    off_label = off_result["analysis"]["evidence"]["verdict_gate"]["label"]

    def fake_resolver(urls):
        resolver_inputs.extend(urls)
        return [{"url": urls[0], "final_url": urls[0], "success": True}]

    def fake_gather(resolved_urls, **kwargs):
        provider_inputs.extend(copy.deepcopy(resolved_urls))
        return _fake_malicious_intel(resolved_urls, **kwargs)

    monkeypatch.setattr(orchestrated_module, "OFFER_THREAT_ENRICHMENT_SHADOW", True)
    monkeypatch.setattr(orchestrated_module, "_safe_scan_url_list", fake_resolver)
    monkeypatch.setattr(orchestrated_module, "_gather_external_intel_safe", fake_gather)
    on_result = _run_offer_lane(on_job)

    on_label = on_result["analysis"]["evidence"]["verdict_gate"]["label"]
    enrichment = on_result["threat_enrichment"]
    measurement = on_result["offer_threat_enrichment_shadow"]
    persisted_shadow = json.dumps(
        {
            "threat_enrichment": enrichment,
            "measurement": measurement,
            "resolver_inputs": resolver_inputs,
            "provider_inputs": provider_inputs,
        },
        ensure_ascii=False,
    )

    assert on_label == off_label
    assert resolver_inputs == [SAFE_OFFER_URL]
    assert provider_inputs[0]["final_url"] == SAFE_OFFER_URL
    assert enrichment["shadow_only"] is True
    assert enrichment["provider_verdict"] == "malicious"
    assert enrichment["has_positive_threat_evidence"] is True
    assert measurement == {
        "schema": "sigurscan_offer_threat_shadow_v1",
        "status": "complete",
        "bundle_provider_verdict": "clean",
        "bundle_provider_completeness": True,
        "threat_provider_verdict": "malicious",
        "threat_enrichment_status": "complete",
        "provider_verdict_mismatch": True,
        "provider_completeness_mismatch": False,
    }
    assert "123456" not in persisted_shadow
    assert SENSITIVE_OFFER_URL not in persisted_shadow
    assert "threat_enrichment" not in orchestrated_engine._orchestrated_status_payload(on_result)
    assert "offer_threat_enrichment_shadow" not in orchestrated_engine._orchestrated_status_payload(on_result)


def test_offer_shadow_failure_cannot_break_primary_offer_scan(monkeypatch):
    job = _make_offer_job(monkeypatch)
    monkeypatch.setattr(orchestrated_module, "OFFER_THREAT_ENRICHMENT_SHADOW", True)
    monkeypatch.setattr(
        orchestrated_module,
        "_safe_scan_url_list",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("resolver failure with otp=123456")),
    )

    result = _run_offer_lane(job)

    assert result["analysis"]["evidence"]["verdict_gate"]["label"]
    assert result["offer_threat_enrichment_shadow"] == {
        "schema": "sigurscan_offer_threat_shadow_v1",
        "status": "error",
        "error_type": "RuntimeError",
    }
    assert "123456" not in json.dumps(result["offer_threat_enrichment_shadow"])
