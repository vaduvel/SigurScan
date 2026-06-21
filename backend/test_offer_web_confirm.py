"""PR6 — web confirm / reverse image ASYNC pe ruta ofertă.

Reguli pinuite:
- EXTINDE offer_claim_verifier (fără web_confirm.py nou).
- NU blochează primul verdict (enrichment rulează doar după ce result există).
- not_found/inconclusive = context, max SUSPECT solo — nu schimbă verdictul.
- DOAR severity=high poate escalada, exclusiv prin reduce_verdict; severitatea
  poate doar să crească, niciodată să scadă.
- reverse image fără provider conform → NOT_CONFIGURED onest.
"""
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

import main as app_main
from services.anaf_cui import CuiResult
from services import offer_claim_verifier as ocv
from test_backend import _poll_orchestrated


def _cui_down():
    return CuiResult(exists=False, checked=False, denumire=None, activ=False,
                     data_inactivare=None, platitor_tva=False, enrolled_efactura=False, raw=None)


def _claim(status="not_found", severity="unknown"):
    return {
        "provider": "ai_offer_web_check", "status": status, "verdict": status,
        "severity": severity, "summary": "stub", "details": "stub", "confidence": 50,
        "claimed_brand": "Nespecificat", "official_domains": [], "query": "q",
        "evidence_urls": [], "method": "test", "official_source_found": False,
        "knowledge_target": None,
    }


SUSPECT_TEXT = "SC Real SRL\nCUI: 24387371\nPlateste in cont IBAN RO33RNCB1234567890123456\nTotal: 100 lei"


def _run_offer(monkeypatch, *, gemini=True, claim_payload=None, polls_after_result=2):
    client = TestClient(app_main.app)

    async def _fake_explain(*args, **kwargs):
        return {"summary": "stub"}

    with monkeypatch.context() as p:
        p.setattr(app_main, "_build_ai_explanation_async", _fake_explain)
        p.setattr(app_main, "ORCHESTRATED_DEFER_AI_EXPLANATION", False)
        if gemini:
            p.setenv("GEMINI_API_KEY", "test-key")
        else:
            p.delenv("GEMINI_API_KEY", raising=False)
        with patch("services.offer_entity_verifier.check_cui", new_callable=AsyncMock) as mock:
            mock.return_value = _cui_down()
            with patch("services.offer_claim_verifier.verify_offer_claim") as claim_mock:
                claim_mock.return_value = claim_payload or _claim()
                post = client.post(
                    "/v1/scan/orchestrated",
                    json={"input_type": "offer", "text": SUSPECT_TEXT},
                )
                scan_id = post.json()["scan_id"]
                # Captăm PRIMUL rezultat publicat (poll cu poll): enrichment-ul web
                # rulează abia la poll-ul DUPĂ publicare, deci primul verdict e curat.
                first_risk = None
                for _ in range(4):
                    _, payload = _poll_orchestrated(client, scan_id, count=1)
                    if payload["result"] is not None:
                        first_risk = payload["result"]["risk_level"]
                        break
                assert first_risk is not None, "primul verdict trebuie publicat fără web check"
                _, payload = _poll_orchestrated(client, scan_id, count=polls_after_result)
    job = app_main.orchestrated_engine._load_orchestrated_job(scan_id)
    return first_risk, payload, job


class TestExtendNotRecreate:
    def test_no_web_confirm_module(self):
        import importlib.util
        assert importlib.util.find_spec("services.web_confirm") is None

    def test_wrapper_enriches_query_with_offer_context(self):
        captured = {}

        def fake_verify(text, analysis, urls, *, brand_registry):
            captured["text"] = text
            return _claim()

        with patch.object(ocv, "verify_offer_claim", side_effect=fake_verify):
            ocv.verify_offer_web_claim(
                "Oferta speciala", {}, [], brand_registry={},
                family_code="OP-04", issuer_name="EuroTransport SRL", platform_name="Autovit",
            )
        assert "vanzare auto" in captured["text"]
        assert "EuroTransport SRL" in captured["text"]
        assert "Autovit" in captured["text"]
        assert "Oferta speciala" in captured["text"]

    def test_reverse_image_not_configured(self):
        result = ocv.verify_reverse_image()
        assert result["status"] == "not_configured"
        assert result["confidence"] == 0


class TestAsyncNonBlocking:
    def test_first_verdict_published_before_web_check(self, monkeypatch):
        first_risk, _, job = _run_offer(monkeypatch, claim_payload=_claim("not_found"))
        assert first_risk == "medium"  # SUSPECT publicat fără să aștepte web check
        assert job["offer_web_claim"]["status"] == "done"

    def test_not_found_does_not_change_verdict(self, monkeypatch):
        first_risk, payload, job = _run_offer(monkeypatch, claim_payload=_claim("not_found"))
        assert payload["result"]["risk_level"] == first_risk == "medium"
        evidence = job["analysis"]["evidence"]
        assert evidence["offer_claim_verification"]["status"] == "not_found"

    def test_inconclusive_does_not_change_verdict(self, monkeypatch):
        first_risk, payload, _ = _run_offer(monkeypatch, claim_payload=_claim("inconclusive"))
        assert payload["result"]["risk_level"] == first_risk == "medium"

    def test_high_severity_escalates_via_gate_only_up(self, monkeypatch):
        first_risk, payload, job = _run_offer(
            monkeypatch, claim_payload=_claim("inconclusive", severity="high"), polls_after_result=3
        )
        assert first_risk == "medium"
        assert payload["result"]["risk_level"] == "high"  # SUSPECT -> DANGEROUS (doar în sus)
        gate = job["analysis"]["evidence"]["verdict_gate"]
        assert gate["label"] == "DANGEROUS"
        assert gate["reason_codes"] == ["provider_malicious"]  # prin reduce_verdict, nu alt motor

    def test_without_gemini_key_skipped_no_enrichment(self, monkeypatch):
        first_risk, payload, job = _run_offer(monkeypatch, gemini=False)
        assert job["offer_web_claim"]["status"] == "skipped"
        assert payload["result"]["risk_level"] == first_risk
        assert "offer_claim_verification" not in job["analysis"].get("evidence", {})
