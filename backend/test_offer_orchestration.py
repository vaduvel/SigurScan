"""Cablarea rutei offer în orchestrator + endpoint.

scan_offer = parse_offer → entity → mapper → reduce_verdict (gate unic), determinist,
fără cache PII, fără calls noi de rețea (check_cui e mock-uit în teste).
"""
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

import main as app_main
from services.anaf_cui import CuiResult
from services.invoice_orchestrator import scan_offer, scan_invoice
from test_backend import _poll_orchestrated


def _cui(checked=True, exists=True, activ=True, denumire="SC TEST SRL"):
    return CuiResult(
        exists=exists, checked=checked, denumire=denumire, activ=activ,
        data_inactivare=None, platitor_tva=True, enrolled_efactura=False, raw=None,
    )


async def _scan(text, *, cui_result=None, links=None, qr=None):
    with patch("services.offer_entity_verifier.check_cui", new_callable=AsyncMock) as mock:
        mock.return_value = cui_result or _cui(checked=False, exists=False, denumire=None)
        return await scan_offer(text, links=links, qr_payloads=qr)


class TestScanOfferChain:
    @pytest.mark.asyncio
    async def test_deterministic_label_and_hash(self):
        text = "Plateste avansul in crypto wallet pentru rezervare"
        r1 = await _scan(text)
        r2 = await _scan(text)
        assert r1.gate["label"] == r2.gate["label"]
        assert r1.bundle["evidence_hash"] == r2.bundle["evidence_hash"]
        assert r1.gate["is_final"] is True

    @pytest.mark.asyncio
    async def test_crypto_payment_periculos(self):
        r = await _scan("Plateste avansul in crypto wallet pentru rezervare")
        assert r.gate["label"] == "DANGEROUS"

    @pytest.mark.asyncio
    async def test_id_document_alone_is_not_periculos(self):
        # CI/CNP singur, fără context de plată/contract → SUSPECT, NU PERICULOS.
        r = await _scan("Trimite o poza cu buletinul tau")
        assert r.gate["label"] != "DANGEROUS"

    @pytest.mark.asyncio
    async def test_id_document_with_payment_context_periculos(self):
        # CI/CNP + context (contract + avans/plată) → PERICULOS (combinație).
        r = await _scan("Trimite poza cu buletinul si CNP ca sa pregatesc contractul, plata avans")
        assert r.gate["label"] == "DANGEROUS"

    @pytest.mark.asyncio
    async def test_verified_active_company_is_safe(self):
        text = (
            "Furnizor: ENEL ENERGIE SA\nCUI: 24387371\nTotal: 245,00 RON\n"
            "IBAN: RO33RNCB1234567890123456\nData: 01.06.2026\nScadenta: 15.06.2026"
        )
        r = await _scan(text, cui_result=_cui(exists=True, activ=True, denumire="ENEL ENERGIE SA"))
        assert r.gate["label"] == "SAFE"

    @pytest.mark.asyncio
    async def test_qr_payloads_threaded(self):
        r = await _scan("scaneaza codul", qr=["RO49AAAA1B31007593840000"])
        assert r.fields.qr_payloads == ["RO49AAAA1B31007593840000"]


class TestInvoiceRouteUntouched:
    @pytest.mark.asyncio
    async def test_scan_invoice_still_works(self):
        text = "Furnizor: ENEL ENERGIE SA\nCUI: RO24387371\nIBAN: RO33RNCB1234567890123456\nTotal: 100 RON"
        with patch("services.invoice_orchestrator.check_cui", new_callable=AsyncMock) as mock:
            mock.return_value = _cui(denumire="ENEL ENERGIE SA")
            result = await scan_invoice(text)
        assert result.fields.cui == "24387371"
        assert result.error is None


class TestOfferEndpoint:
    def test_offer_routes_to_offer_fast_lane(self, monkeypatch):
        client = TestClient(app_main.app)
        with patch("services.offer_entity_verifier.check_cui", new_callable=AsyncMock) as mock:
            mock.return_value = _cui(checked=False, exists=False, denumire=None)
            post = client.post(
                "/v1/scan/orchestrated",
                json={"input_type": "offer", "text": "Trimite o poza cu buletinul tau"},
            )
            assert post.status_code == 200
            assert post.json()["status"] == "scanning"
            scan_id = post.json()["scan_id"]
            # primul poll rulează offer fast-lane (ruta URL ar fi „resolved")
            _, payload = _poll_orchestrated(client, scan_id, count=1)
        assert payload["diagnostics"]["pipeline_stage"] == "analysis_ready"

    def test_offer_endpoint_crypto_periculos(self, monkeypatch):
        client = TestClient(app_main.app)

        async def _fake_explain(*args, **kwargs):
            return {"summary": "stub"}

        with monkeypatch.context() as p:
            p.setattr(app_main, "_build_ai_explanation_async", _fake_explain)
            p.setattr(app_main, "ORCHESTRATED_DEFER_AI_EXPLANATION", False)
            with patch("services.offer_entity_verifier.check_cui", new_callable=AsyncMock) as mock:
                mock.return_value = _cui(checked=False, exists=False, denumire=None)
                post = client.post(
                    "/v1/scan/orchestrated",
                    json={"input_type": "offer", "text": "Plateste avansul in crypto wallet pentru rezervare"},
                )
                assert post.status_code == 200
                scan_id = post.json()["scan_id"]
                _, payload = _poll_orchestrated(client, scan_id, count=3)
        assert payload["status"] == "complete"
        assert payload["result"] is not None
        assert payload["result"]["risk_level"] == "high"
