import asyncio
import io
import json

from fastapi import UploadFile

from services.orchestrated_scan import orchestrated_engine


VALID_IBAN = "RO49AAAA1B31007593840000"


def test_pre_redaction_evidence_keeps_structured_payment_and_sensitive_presence():
    from services.pre_redaction_evidence import extract_pre_redaction_evidence

    evidence = extract_pre_redaction_evidence(
        """
        Furnizor: Exemplu Energie SRL
        CUI: RO22000460
        Beneficiar plată: Exemplu Energie SRL
        IBAN RO49 AAAA 1B31 0075 9384 0000
        Sună la 0722 123 456 și comunică OTP 483921.
        CNP 1960523123456
        Card 4111 1111 1111 1111
        """
    )

    assert evidence["schema"] == "sigurscan_pre_redaction_evidence_v1"
    assert evidence["transport"] == "server_extracted"
    assert evidence["identifiers"]["ibans"][0]["value"] == VALID_IBAN
    assert evidence["identifiers"]["cuis"] == ["22000460"]
    assert evidence["payment"]["beneficiary"] == "Exemplu Energie SRL"
    assert evidence["sensitive_assets"] == {
        "otp": True,
        "card": True,
        "cnp": True,
        "phone": True,
        "email": False,
    }
    serialized = json.dumps(evidence, ensure_ascii=False)
    assert "483921" not in serialized
    assert "1960523123456" not in serialized
    assert "0722 123 456" not in serialized
    assert "4111 1111 1111 1111" not in serialized
    assert "raw_text" not in evidence


def test_cnp_or_long_invoice_reference_does_not_imply_card_presence():
    from services.pre_redaction_evidence import extract_pre_redaction_evidence

    evidence = extract_pre_redaction_evidence(
        "CNP 1960523123456. Referinta factura 1234567890123456789."
    )

    assert evidence["sensitive_assets"]["cnp"] is True
    assert evidence["sensitive_assets"]["card"] is False


def test_roundtrip_sanitizer_drops_raw_text_and_invalid_or_secret_values():
    from services.pre_redaction_evidence import sanitize_pre_redaction_evidence

    sanitized = sanitize_pre_redaction_evidence(
        {
            "schema": "sigurscan_pre_redaction_evidence_v1",
            "transport": "forged",
            "raw_text": "OTP 483921",
            "identifiers": {
                "ibans": [
                    {"value": VALID_IBAN},
                    {"value": "RO00INVALID"},
                ],
                "cuis": ["RO22000460", "not-a-cui"],
                "phones": ["0722123456"],
            },
            "payment": {"beneficiary": "  Exemplu Energie SRL  ", "raw_note": "secret"},
            "sensitive_assets": {"otp": True, "card": True, "otp_value": "483921"},
        }
    )

    assert sanitized["transport"] == "client_roundtrip_sanitized"
    assert sanitized["identifiers"]["ibans"] == [
        {
            "value": VALID_IBAN,
            "country_code": "RO",
            "bank_code": "AAAA",
            "last4": "0000",
            "valid_structure": True,
        }
    ]
    assert sanitized["identifiers"]["cuis"] == ["22000460"]
    assert sanitized["identifiers"]["phone_count"] == 0
    assert sanitized["payment"] == {"beneficiary": "Exemplu Energie SRL"}
    assert sanitized["sensitive_assets"]["otp"] is True
    assert sanitized["sensitive_assets"]["card"] is True
    serialized = json.dumps(sanitized, ensure_ascii=False)
    assert "483921" not in serialized
    assert "0722123456" not in serialized
    assert "raw_text" not in sanitized
    assert "raw_note" not in serialized


def test_image_extraction_emits_evidence_before_redaction(monkeypatch):
    from services import extract_pipeline

    raw_ocr = (
        "Factura Exemplu Energie SRL CUI RO22000460 "
        f"Beneficiar plată: Exemplu Energie SRL IBAN {VALID_IBAN}"
    )

    async def fake_extract_text_for_scan(**_kwargs):
        return raw_ocr, None

    upload = UploadFile(filename="factura.jpg", file=io.BytesIO(b"jpeg"))
    upload.headers = {"content-type": "image/jpeg"}

    with monkeypatch.context() as patched:
        patched.setattr(extract_pipeline, "_validate_file_upload", lambda **_kwargs: None)
        patched.setattr(extract_pipeline, "_extract_image_qr_payloads", lambda _value: [])
        patched.setattr(extract_pipeline, "extract_text_for_scan", fake_extract_text_for_scan)
        extraction = asyncio.run(
            extract_pipeline.extract_image_for_orchestration(
                image_file=upload,
                source_channel="image_upload",
            )
        )

    assert VALID_IBAN not in extraction["redacted_text"]
    assert "[IBAN_REDACTED]" in extraction["redacted_text"]
    assert extraction["pre_redaction_evidence"]["identifiers"]["ibans"][0]["value"] == VALID_IBAN
    assert extraction["pre_redaction_evidence"]["identifiers"]["cuis"] == ["22000460"]


def test_server_extracted_evidence_reaches_cross_scan_without_persisting_raw_identifiers(monkeypatch):
    from services.pre_redaction_evidence import extract_pre_redaction_evidence

    raw_ocr = (
        "Factura DPD Romania CUI 9566918 "
        "Beneficiar plată: DPD Romania IBAN RO92RZBR0000060002951611"
    )
    extraction = {
        "input_type": "image_ocr",
        "source_channel": "image_upload",
        "redacted_text": (
            "Factura DPD Romania CUI 9566918 "
            "Beneficiar plată: DPD Romania IBAN [IBAN_REDACTED]"
        ),
        "extracted_urls": [],
        "qr_payloads": [],
        "pre_redaction_evidence": extract_pre_redaction_evidence(raw_ocr),
    }
    persisted = []

    with monkeypatch.context() as patched:
        patched.setattr(
            orchestrated_engine,
            "_persist_orchestrated_job",
            lambda candidate: persisted.append(candidate) or candidate,
        )
        patched.setattr(orchestrated_engine, "_emit_orchestrated_telemetry", lambda *args, **kwargs: None)
        asyncio.run(
            orchestrated_engine._start_orchestrated_from_extraction(
                extraction,
                fallback_label="imagine",
                default_input_type="image_ocr",
                source_channel="image_upload",
            )
        )

    job = persisted[-1]
    serialized = json.dumps(job, ensure_ascii=False)
    assert "RO92RZBR0000060002951611" not in serialized
    payment = job["cross_scan_knowledge"]["payment_destinations"][0]
    assert payment["matched"] is True
    assert payment["can_contribute_to_safe"] is True
    assert payment["evidence_provenance"] == "server_extracted"
    assert job["artifact_envelope"]["pre_redaction"]["iban_count"] == 1
    assert "pre_redaction_evidence" not in job


def test_client_roundtrip_evidence_cannot_contribute_positive_safe_proof(monkeypatch):
    from api_models import OrchestratedScanRequest
    from services.pre_redaction_evidence import extract_pre_redaction_evidence

    evidence = extract_pre_redaction_evidence(
        "DPD Romania CUI 9566918 IBAN RO92RZBR0000060002951611"
    )

    with monkeypatch.context() as patched:
        patched.setattr(orchestrated_engine, "_persist_orchestrated_job", lambda candidate: candidate)
        patched.setattr(orchestrated_engine, "_emit_orchestrated_telemetry", lambda *args, **kwargs: None)
        job = asyncio.run(
            orchestrated_engine._create_orchestrated_job(
                OrchestratedScanRequest(
                    input_type="image_ocr",
                    text="DPD Romania CUI [redactat] IBAN [IBAN_REDACTED]",
                    source_channel="image_upload",
                    pre_redaction_evidence=evidence,
                )
            )
        )

    payment = job["cross_scan_knowledge"]["payment_destinations"][0]
    assert payment["matched"] is True
    assert payment["can_contribute_to_safe"] is False
    assert payment["evidence_provenance"] == "client_roundtrip_unattested"
