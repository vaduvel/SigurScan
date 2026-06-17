import json
import re
import urllib.parse
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import main as app_main
from test_backend import (
    _clean_external_intel_for_resolved_urls,
    _fake_inconclusive_offer_claim,
    _fake_urlscan_post_rejects_domain,
    _poll_orchestrated,
)


FIXTURE_PATH = Path(__file__).resolve().parent / "testdata" / "web_redteam_scam_fixtures_2026_06_16.json"
SEVERITY_RANK = {"SAFE": 0, "UNVERIFIED": 1, "SUSPECT": 2, "DANGEROUS": 3}


def _load_fixture_pack():
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def _safe_test_resolver(urls):
    resolved = []
    for raw_url in urls:
        parsed = urllib.parse.urlparse(raw_url)
        host = (parsed.hostname or "").lower()
        registered_domain = ".".join(host.split(".")[-2:]) if host.count(".") else host
        resolved.append(
            {
                "url": raw_url,
                "original_url": raw_url,
                "final_url": raw_url,
                "hostname": host,
                "final_hostname": host,
                "registered_domain": registered_domain,
                "final_registered_domain": registered_domain,
                "redirect_chain": [{"url": raw_url}],
                "redirect_count": 0,
                "shortener_count": 0,
                "uses_shortener": False,
                "detected_soft_redirects": [],
                "domain_age_days": 3,
                "domain_created_date": "2026-06-13",
                "has_mx_records": False,
                "success": True,
            }
        )
    return resolved


async def _fresh_test_domain_signals(domain: str) -> dict:
    return {
        "ssl": {"valid": True, "cert_age_days": 2, "issuer_org": "Test CA"},
        "rdap": {"age_days": 3, "registered": True},
    }


@pytest.mark.parametrize("case", _load_fixture_pack()["fixtures"], ids=lambda case: case["id"])
def test_web_redteam_replicas_are_detected_by_orchestrated_pipeline(monkeypatch, case):
    app_main._ORCHESTRATED_SCAN_JOBS.clear()
    client = TestClient(app_main.app)

    with monkeypatch.context() as patched:
        patched.setattr(app_main, "PRIVACY_SAFE_MODE", False)
        patched.setattr(app_main, "ENABLE_CLOUD_AI_EXPLANATION", False)
        patched.setattr(app_main, "ORCHESTRATED_DEFER_AI_EXPLANATION", False)
        patched.setattr(app_main, "URLSCAN_API_KEY", "server-only-key")
        patched.setattr(app_main, "MISTRAL_SEMANTIC_API_KEY", "")
        patched.setattr(app_main, "_safe_scan_url_list", _safe_test_resolver)
        patched.setattr(app_main, "_gather_external_intel_safe", _clean_external_intel_for_resolved_urls)
        patched.setattr(app_main, "_enrich_offer_claim_verification_async", _fake_inconclusive_offer_claim)
        patched.setattr(app_main, "check_domain_ssl_parallel", _fresh_test_domain_signals)
        patched.setattr(app_main.requests, "post", _fake_urlscan_post_rejects_domain)
        patched.setattr(app_main, "_emit_scan_event", lambda *args, **kwargs: None)
        patched.setattr(app_main, "_emit_orchestrated_telemetry", lambda *args, **kwargs: None)

        start = client.post(
            "/v1/scan/orchestrated",
            json={
                "input_type": case["input_type"],
                "text": case["text"],
                "source_channel": case["source_channel"],
            },
        ).json()
        _, payload = _poll_orchestrated(client, start["scan_id"], count=8)

    result = payload.get("result") or {}
    actual = str(result.get("user_risk_label") or "UNVERIFIED").upper()
    expected = str(case["expected_label"]).upper()

    assert payload["status"] == "complete"
    assert result.get("is_final") is True
    assert SEVERITY_RANK[actual] >= SEVERITY_RANK[expected], (
        f"{case['id']} expected at least {expected}, got {actual}; "
        f"family={result.get('detected_family_id')} reasons={result.get('reasons')}"
    )


def test_web_redteam_fixture_pack_is_source_backed_and_non_live():
    pack = _load_fixture_pack()
    assert pack["fixtures"]
    for case in pack["fixtures"]:
        assert case["source_refs"], case["id"]
        assert case["text"].strip(), case["id"]
        for url in case.get("urls", []):
            host = urllib.parse.urlparse(url).hostname or ""
            assert host.endswith(".test"), f"{case['id']} uses a non-reserved host: {host}"
            assert not re.search(r"(?:\\.ro|\\.com|\\.net|\\.org)$", host), case["id"]
