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

MGH_OFFICIAL_XML_DIFFERENT_IBAN = b"""<?xml version="1.0" encoding="UTF-8"?>
<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2"
         xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2"
         xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2">
  <cbc:ID>MGH 0013</cbc:ID>
  <cbc:IssueDate>2022-04-06</cbc:IssueDate>
  <cbc:DueDate>2022-04-07</cbc:DueDate>
  <cac:AccountingSupplierParty>
    <cac:Party>
      <cac:PartyName><cbc:Name>MARKETING GROWTH HUB S.R.L.</cbc:Name></cac:PartyName>
      <cac:PartyTaxScheme><cbc:CompanyID>RO45758405</cbc:CompanyID></cac:PartyTaxScheme>
    </cac:Party>
  </cac:AccountingSupplierParty>
  <cac:PaymentMeans>
    <cac:PayeeFinancialAccount><cbc:ID>RO49AAAA1B31007593840000</cbc:ID></cac:PayeeFinancialAccount>
  </cac:PaymentMeans>
  <cac:LegalMonetaryTotal>
    <cbc:PayableAmount currencyID="RON">200.00</cbc:PayableAmount>
  </cac:LegalMonetaryTotal>
</Invoice>
"""

MGH_OFFICIAL_XML_MATCHING_IBAN = MGH_OFFICIAL_XML_DIFFERENT_IBAN.replace(
    b"RO49AAAA1B31007593840000",
    b"RO42INGB0000999912242622",
)


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


def test_scan_invoice_official_xml_match_confirms_payment_destination_t2(monkeypatch):
    from services.anaf_cui import CuiResult

    async def fake_extract_text_for_scan(filename, file_bytes, extract_fn):
        return MGH_PDF_TEXT, None

    async def fake_check_cui(cui: str):
        return CuiResult(
            exists=True,
            checked=True,
            denumire="MARKETING GROWTH HUB S.R.L.",
            activ=True,
            data_inactivare=None,
            platitor_tva=False,
            enrolled_efactura=True,
            raw=None,
        )

    monkeypatch.setattr(app_main, "extract_text_for_scan", fake_extract_text_for_scan)
    monkeypatch.setattr("services.invoice_orchestrator.check_cui", fake_check_cui)
    client = TestClient(app_main.app)

    response = client.post(
        "/v1/scan/invoice",
        files={
            "pdf_file": ("mgh.pdf", b"%PDF-1.4\n%%EOF", "application/pdf"),
            "official_xml_file": ("efactura.xml", MGH_OFFICIAL_XML_MATCHING_IBAN, "application/xml"),
        },
        data={"source_channel": "android_native"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["official_document_check"]["status"] == "match"
    assert payload["payment_destination"]["matched"] is True
    assert payload["payment_destination"]["can_contribute_to_safe"] is True
    assert payload["payment_destination"]["trust_tier"] == "T2_OFFICIAL_DOCUMENT_CHAIN"
    assert payload["payment_destination"]["source_kind"] == "official_efactura_xml"
    assert payload["payment_destination"]["display"] == "IBAN confirmat prin document oficial"
    evidence_payment = payload["evidence_bundle"]["providers"]["payment_destination"]
    assert evidence_payment["status"] == "clean"
    assert evidence_payment["trust_tier"] == "T2_OFFICIAL_DOCUMENT_CHAIN"
    assert evidence_payment["source_kind"] == "official_efactura_xml"
    assert payload["verdict_gate"]["label"] == "SAFE"


def test_scan_invoice_flags_official_xml_mismatch(monkeypatch):
    from services.anaf_cui import CuiResult

    async def fake_extract_text_for_scan(filename, file_bytes, extract_fn):
        return MGH_PDF_TEXT, None

    async def fake_check_cui(cui: str):
        return CuiResult(
            exists=True,
            checked=True,
            denumire="MARKETING GROWTH HUB S.R.L.",
            activ=True,
            data_inactivare=None,
            platitor_tva=False,
            enrolled_efactura=True,
            raw=None,
        )

    monkeypatch.setattr(app_main, "extract_text_for_scan", fake_extract_text_for_scan)
    monkeypatch.setattr("services.invoice_orchestrator.check_cui", fake_check_cui)
    client = TestClient(app_main.app)

    response = client.post(
        "/v1/scan/invoice",
        files={
            "pdf_file": ("mgh.pdf", b"%PDF-1.4\n%%EOF", "application/pdf"),
            "official_xml_file": ("efactura.xml", MGH_OFFICIAL_XML_DIFFERENT_IBAN, "application/xml"),
        },
        data={"source_channel": "android_native"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["official_document_check"]["status"] == "mismatch"
    assert payload["official_document_check"]["risk_flag"] == "EFACTURA_OFFICIAL_DOCUMENT_MISMATCH"
    assert "EFACTURA_OFFICIAL_DOCUMENT_MISMATCH" in payload["fraud_flags"]
    assert payload["verdict_gate"]["label"] == "DANGEROUS"


def test_scan_invoice_invalid_official_xml_blocks_safe(monkeypatch):
    from services.anaf_cui import CuiResult

    async def fake_extract_text_for_scan(filename, file_bytes, extract_fn):
        return MGH_PDF_TEXT, None

    async def fake_check_cui(cui: str):
        return CuiResult(
            exists=True,
            checked=True,
            denumire="MARKETING GROWTH HUB S.R.L.",
            activ=True,
            data_inactivare=None,
            platitor_tva=False,
            enrolled_efactura=True,
            raw=None,
        )

    monkeypatch.setattr(app_main, "extract_text_for_scan", fake_extract_text_for_scan)
    monkeypatch.setattr("services.invoice_orchestrator.check_cui", fake_check_cui)
    client = TestClient(app_main.app)

    response = client.post(
        "/v1/scan/invoice",
        files={
            "pdf_file": ("mgh.pdf", b"%PDF-1.4\n%%EOF", "application/pdf"),
            "official_xml_file": ("efactura.xml", b"<Invoice>", "application/xml"),
        },
        data={"source_channel": "android_native"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["official_document_check"]["status"] == "parse_error"
    assert payload["official_document_check"]["risk_flag"] == "EFACTURA_OFFICIAL_DOCUMENT_UNREADABLE"
    assert "EFACTURA_OFFICIAL_DOCUMENT_UNREADABLE" in payload["fraud_flags"]
    assert payload["verdict_gate"]["label"] != "SAFE"


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
