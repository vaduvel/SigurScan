from fastapi.testclient import TestClient

import main as app_main


PNG_BYTES = b"\x89PNG\r\n\x1a\nrelease-contract"


def test_image_extractor_returns_evidence_without_final_verdict(monkeypatch):
    client = TestClient(app_main.app)

    async def fake_extract_text_for_scan(filename, file_bytes, extract_fn):
        return "Verifica https://www.yoxo.ro/", None

    monkeypatch.setattr(app_main, "extract_text_for_scan", fake_extract_text_for_scan)

    response = client.post(
        "/v1/extract/image",
        files={"image_file": ("scan.png", PNG_BYTES, "image/png")},
        data={"source_channel": "release_contract_image"},
    )

    body = response.json()
    assert response.status_code == 200
    assert body["input_type"] == "image_ocr"
    assert body["source_channel"] == "release_contract_image"
    assert "https://www.yoxo.ro/" in body["extracted_urls"]
    assert "user_risk_label" not in body


def test_pdf_and_email_extractors_return_intake_evidence_without_final_verdict(monkeypatch):
    client = TestClient(app_main.app)
    pdf = (
        b"%PDF-1.7\n"
        b"1 0 obj << /A << /S /URI /URI (https://www.yoxo.ro/) >> >> endobj\n%%EOF"
    )

    async def fake_extract_text_for_scan(filename, file_bytes, extract_fn):
        return "Oferta oficiala https://www.yoxo.ro/", None

    monkeypatch.setattr(app_main, "extract_text_for_scan", fake_extract_text_for_scan)

    pdf_response = client.post(
        "/v1/extract/pdf",
        files={"pdf_file": ("offer.pdf", pdf, "application/pdf")},
        data={"source_channel": "release_contract_pdf"},
    )
    pdf_body = pdf_response.json()
    assert pdf_response.status_code == 200
    assert pdf_body["input_type"] == "pdf_ocr"
    assert pdf_body["source_channel"] == "release_contract_pdf"
    assert "https://www.yoxo.ro/" in pdf_body["extracted_urls"]
    assert "user_risk_label" not in pdf_body

    email_response = client.post(
        "/v1/extract/email",
        data={
            "html_content": "<a href='https://www.yoxo.ro/'>Vezi oferta</a>",
            "source_channel": "release_contract_email",
        },
    )
    email_body = email_response.json()
    assert email_response.status_code == 200
    assert email_body["input_type"] == "email"
    assert email_body["source_channel"] == "release_contract_email"
    assert "https://www.yoxo.ro/" in email_body["extracted_urls"]
    assert "user_risk_label" not in email_body
