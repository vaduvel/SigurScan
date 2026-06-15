import os
import sys

from fastapi.testclient import TestClient

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import main as app_main


ANTHROPIC_INVOICE_TEXT = """
Invoice
Invoice number Q4HWLGHJ-0001
Date of issue
March 1, 2026
Date due
March 1, 2026
Anthropic, PBC
548 Market Street
support@anthropic.com
Description
Claude Pro
Subtotal
Total excluding tax
Tax (21% on €18.00)
Total
Amount due
€18.00
€18.00
€3.78
€21.78
€21.78
"""

MGH_PDF_TEXT = """
Factura MGH 0013
Data emiterii: 06.04.2022
Termen plata: 07.04.2022
Furnizor:
MARKETING GROWTH HUB S.R.L.
CIF:
45758405
IBAN (RON):
RO42INGB0000999912242622
Total plata 200.00 RON
"""


def test_scan_invoice_accepts_pdf_upload(monkeypatch):
    async def fake_extract_text_for_scan(filename, file_bytes, extract_fn):
        assert filename == "anthropic-invoice.pdf"
        assert file_bytes.startswith(b"%PDF-")
        return ANTHROPIC_INVOICE_TEXT, None

    monkeypatch.setattr(app_main, "extract_text_for_scan", fake_extract_text_for_scan)
    client = TestClient(app_main.app)

    response = client.post(
        "/v1/scan/invoice",
        files={
            "pdf_file": (
                "anthropic-invoice.pdf",
                b"%PDF-1.4\n/URI (https://pay.anthropic.com/invoice/Q4HWLGHJ-0001)\n%%EOF",
                "application/pdf",
            )
        },
        data={"source_channel": "test"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["source_type"] == "pdf"
    assert payload["fields"]["emitent"] == "Anthropic, PBC"
    assert payload["fields"]["nr_factura"] == "Q4HWLGHJ-0001"
    assert payload["fields"]["currency"] == "EUR"
    assert payload["fields"]["invoice_profile"] == "international"
    assert payload["fields"]["subtotal"] == 18.0
    assert payload["fields"]["tva"] == 3.78
    assert payload["fields"]["total"] == 21.78
    assert payload["readiness"]["state"] == "ready_for_analysis"
    assert payload["readiness"]["blocks_safe_verdict"] is False


def test_scan_invoice_pdf_merges_embedded_text_when_ocr_misses_cui(monkeypatch):
    from services.anaf_cui import CuiResult

    async def fake_extract_text_for_scan(filename, file_bytes, extract_fn):
        return (
            "Factura MGH 0013\n"
            "Furnizor: MARKETING GROWTH HUB S.R.L.\n"
            "IBAN RO42INGB0000999912242622\n"
            "Total plata 200.00 RON",
            None,
        )

    async def fake_check_cui(cui: str):
        assert cui == "45758405"
        return CuiResult(
            exists=True,
            checked=True,
            denumire="MARKETING GROWTH HUB S.R.L.",
            activ=True,
            data_inactivare=None,
            platitor_tva=False,
            enrolled_efactura=False,
            raw=None,
        )

    monkeypatch.setattr(app_main, "extract_text_for_scan", fake_extract_text_for_scan)
    monkeypatch.setattr(app_main, "_extract_pdf_embedded_text", lambda _: MGH_PDF_TEXT)
    monkeypatch.setattr("services.invoice_orchestrator.check_cui", fake_check_cui)
    client = TestClient(app_main.app)

    response = client.post(
        "/v1/scan/invoice",
        files={"pdf_file": ("mgh.pdf", b"%PDF-1.4\n%%EOF", "application/pdf")},
        data={"source_channel": "android_native"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["fields"]["cui"] == "45758405"
    assert payload["fields"]["iban"] == "RO42INGB0000999912242622"
    assert payload["anaf"]["checked"] is True
    assert payload["evidence_bundle"]["identity"]["status"] == "coherent"
    assert payload["payment_destination"]["matched"] is False
    assert payload["beneficiary_name_check"]["recommended"] is True
    assert payload["verdict_gate"]["label"] == "SAFE"
    assert payload["verdict_gate"]["reason_codes"] == ["positive_provenance_clean"]


def test_scan_invoice_endpoint_returns_gate_for_brand_never_asks(monkeypatch):
    async def fake_extract_text_for_scan(filename, file_bytes, extract_fn):
        return (
            "SAMEDAY CUI RO21303530: taxa livrare neachitata 9.99 RON. "
            "Plateste prin IBAN RO49AAAA1B31007593840000.",
            None,
        )

    monkeypatch.setattr(app_main, "extract_text_for_scan", fake_extract_text_for_scan)
    client = TestClient(app_main.app)

    response = client.post(
        "/v1/scan/invoice",
        files={"image_file": ("invoice.jpg", b"\xff\xd8\xff\xe0fakejpeg", "image/jpeg")},
        data={"source_channel": "sms"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["verdict_gate"]["label"] == "DANGEROUS"
    assert "payment_request_sms" in payload["evidence_bundle"]["identity"]["violated_never_asks"]


def test_scan_invoice_rejects_missing_file():
    client = TestClient(app_main.app)

    response = client.post("/v1/scan/invoice", data={"source_channel": "test"})

    assert response.status_code == 400
    assert "exact o factură" in response.json()["detail"]
