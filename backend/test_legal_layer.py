"""PR5 — stratul „Ce spune legea" (educativ, determinist).

Reguli pinuite:
- NU schimbă verdictul (verdict_gate rămâne singurul judecător).
- NU inventează articole: cardurile vin DOAR din data/legal_kb.json, verbatim.
- Fără mapping → listă goală. Disclaimerul e mereu prezent.
- Label UI = „Ce spune legea" (nu „Jurist"/„Avocat").
"""
import json
import os
from unittest.mock import AsyncMock, patch

import pytest

from services import offer_signals as S
from services.legal_layer import (
    UI_LABEL,
    legal_cards_for,
    load_legal_kb,
)


KB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "legal_kb.json")


class TestKbDeterminist:
    def test_kb_file_exists_and_loads(self):
        kb = load_legal_kb()
        assert kb["disclaimer"]
        assert len(kb["cards"]) >= 8

    def test_ui_label_is_not_jurist(self):
        assert UI_LABEL == "Ce spune legea"

    def test_cards_have_required_fields(self):
        for card in load_legal_kb()["cards"]:
            assert card["id"] and card["title"] and card["summary"]
            assert card["actions"] and card["source_refs"]


class TestSignalMapping:
    def test_id_document_maps_to_furt_identitate(self):
        out = legal_cards_for(signals=[S.OFFER_ID_DOCUMENT_REQUEST])
        ids = [c["id"] for c in out["cards"]]
        assert "law-furt-identitate-327" in ids

    def test_card_cvv_maps_to_instrumente_plata(self):
        out = legal_cards_for(signals=[S.OFFER_CARD_CVV_OTP_REQUEST])
        assert "law-instrumente-plata-311" in [c["id"] for c in out["cards"]]

    def test_off_platform_maps(self):
        out = legal_cards_for(signals=[S.OFFER_OFF_PLATFORM_PAYMENT])
        assert "law-off-platform" in [c["id"] for c in out["cards"]]

    def test_urgency_maps_to_scadenta(self):
        out = legal_cards_for(signals=[S.OFFER_PRICE_URGENCY])
        assert "law-scadenta-urgenta" in [c["id"] for c in out["cards"]]

    def test_incoherent_document_maps_to_fals(self):
        out = legal_cards_for(signals=[S.OFFER_TOTALS_INCOHERENT])
        assert "law-fals-inscrisuri-320-323" in [c["id"] for c in out["cards"]]

    def test_high_risk_payment_maps_to_inselaciune(self):
        out = legal_cards_for(signals=[S.OFFER_PAYMENT_METHOD_HIGH_RISK])
        assert "law-inselaciune-244" in [c["id"] for c in out["cards"]]

    def test_invoice_document_gets_factura_card(self):
        out = legal_cards_for(signals=[], document_type="invoice")
        assert "law-factura-319-efactura" in [c["id"] for c in out["cards"]]

    def test_op07_family_gets_identity_card(self):
        out = legal_cards_for(signals=[], family_code="OP-07")
        assert "law-furt-identitate-327" in [c["id"] for c in out["cards"]]

    def test_no_mapping_empty_cards_with_disclaimer(self):
        out = legal_cards_for(signals=[])
        assert out["cards"] == []
        assert out["disclaimer"]
        assert out["label"] == "Ce spune legea"

    def test_cards_are_deduplicated(self):
        out = legal_cards_for(
            signals=[S.OFFER_ID_DOCUMENT_REQUEST], family_code="OP-07"
        )
        ids = [c["id"] for c in out["cards"]]
        assert len(ids) == len(set(ids))

    def test_content_is_verbatim_from_kb(self):
        # Fără invenții: summary/actions identice cu KB-ul.
        kb_card = next(c for c in load_legal_kb()["cards"] if c["id"] == "law-off-platform")
        out = legal_cards_for(signals=[S.OFFER_OFF_PLATFORM_PAYMENT])
        produced = next(c for c in out["cards"] if c["id"] == "law-off-platform")
        assert produced["summary"] == kb_card["summary"]
        assert produced["actions"] == kb_card["actions"]


class TestMissingKb:
    def test_missing_kb_returns_empty_no_crash(self, monkeypatch):
        monkeypatch.setenv("LEGAL_KB_PATH", "/nonexistent/legal_kb.json")
        load_legal_kb.cache_clear()
        try:
            out = legal_cards_for(signals=[S.OFFER_ID_DOCUMENT_REQUEST])
            assert out["cards"] == []
            assert out["disclaimer"]
        finally:
            monkeypatch.delenv("LEGAL_KB_PATH", raising=False)
            load_legal_kb.cache_clear()


class TestVerdictNeverChanges:
    @pytest.mark.asyncio
    async def test_gate_label_identical_with_and_without_legal_layer(self):
        from services.anaf_cui import CuiResult
        from services.invoice_orchestrator import scan_offer

        text = "Trimite poza buletinului si plata avans in IBAN RO33RNCB1234567890123456"
        cui = CuiResult(exists=False, checked=False, denumire=None, activ=False,
                        data_inactivare=None, platitor_tva=False, enrolled_efactura=False, raw=None)
        with patch("services.offer_entity_verifier.check_cui", new_callable=AsyncMock) as mock:
            mock.return_value = cui
            result = await scan_offer(text)
            label_before = result.gate["label"]
            hash_before = result.bundle["evidence_hash"]
            # Stratul legal rulează DUPĂ gate și nu atinge bundle-ul/gate-ul.
            legal_cards_for(signals=result.signals, family_code=result.family_code,
                            document_type=result.fields.document_type)
            result2 = await scan_offer(text)
        assert result2.gate["label"] == label_before
        assert result2.bundle["evidence_hash"] == hash_before
        assert "legal" not in result.bundle.get("context", {})

    def test_offer_fast_lane_attaches_legal_without_touching_verdict(self):
        from fastapi.testclient import TestClient
        from unittest.mock import AsyncMock, patch
        import main as app_main
        from services.anaf_cui import CuiResult
        from test_backend import _poll_orchestrated

        client = TestClient(app_main.app)
        cui = CuiResult(exists=False, checked=False, denumire=None, activ=False,
                        data_inactivare=None, platitor_tva=False, enrolled_efactura=False, raw=None)
        with patch("services.offer_entity_verifier.check_cui", new_callable=AsyncMock) as mock:
            mock.return_value = cui
            post = client.post(
                "/v1/scan/orchestrated",
                json={"input_type": "offer", "text": "Hai pe WhatsApp, plata direct, trimite CVV ca sa primesti banii"},
            )
            scan_id = post.json()["scan_id"]
            _, payload = _poll_orchestrated(client, scan_id, count=1)
        # Stage-ul a rulat fast-lane-ul; analysis are secțiunea legal.
        job = app_main._load_orchestrated_job(scan_id)
        analysis = job["analysis"]
        assert analysis["legal"]["label"] == "Ce spune legea"
        assert analysis["legal"]["disclaimer"]
        ids = [c["id"] for c in analysis["legal"]["cards"]]
        assert "law-instrumente-plata-311" in ids
        # Verdictul vine tot din verdict_gate (neatins de stratul legal).
        assert analysis["evidence"]["verdict_gate"]["label"] in {"SIGUR", "SUSPECT", "PERICULOS"}
        assert analysis["risk_level"] == analysis["evidence"]["verdict_gate"]["risk_level"]

    def test_result_legal_is_the_client_contract_key(self):
        # Cheia consumată de Android: result.legal = {label, cards[], disclaimer}.
        from fastapi.testclient import TestClient
        from unittest.mock import AsyncMock, patch
        import main as app_main
        from services.anaf_cui import CuiResult

        async def _fake_explain(*args, **kwargs):
            return {"summary": "stub"}

        client = TestClient(app_main.app)
        cui = CuiResult(exists=False, checked=False, denumire=None, activ=False,
                        data_inactivare=None, platitor_tva=False, enrolled_efactura=False, raw=None)
        old_explain = app_main._build_ai_explanation_async
        old_defer = app_main.ORCHESTRATED_DEFER_AI_EXPLANATION
        app_main._build_ai_explanation_async = _fake_explain
        app_main.ORCHESTRATED_DEFER_AI_EXPLANATION = False
        try:
            with patch("services.offer_entity_verifier.check_cui", new_callable=AsyncMock) as mock:
                mock.return_value = cui
                post = client.post(
                    "/v1/scan/orchestrated",
                    json={"input_type": "offer", "text": "Hai pe WhatsApp, plata direct, trimite CVV ca sa primesti banii"},
                )
                scan_id = post.json()["scan_id"]
                payload = None
                for _ in range(4):
                    payload = client.get(f"/v1/scan/orchestrated/{scan_id}").json()
                    if payload.get("result"):
                        break
        finally:
            app_main._build_ai_explanation_async = old_explain
            app_main.ORCHESTRATED_DEFER_AI_EXPLANATION = old_defer
        legal = payload["result"]["legal"]
        assert legal["label"] == "Ce spune legea"
        assert legal["cards"] and legal["disclaimer"]
