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
