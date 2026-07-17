import asyncio
import io
import json
from email.message import EmailMessage

from fastapi import UploadFile
from fastapi.testclient import TestClient

import main as app_main
from config import EMAIL_COMPOUND_EVIDENCE_ACTIVE_DEFAULT
from services import extract_pipeline
from services.email_evidence_ledger import (
    extract_email_compound_evidence,
    sanitize_email_evidence_ledger,
)
from services.orchestrated_scan import orchestrated_engine


def test_email_compound_evidence_activation_defaults_off():
    assert EMAIL_COMPOUND_EVIDENCE_ACTIVE_DEFAULT is False


def _compound_message() -> EmailMessage:
    message = EmailMessage()
    message["From"] = "Contabilitate <billing@vendor.example>"
    message["To"] = "George Client <george@example.test>"
    message["Reply-To"] = "plati@vendor-payments.example"
    message["Subject"] = "Factura lunara"
    message["Authentication-Results"] = "mx.example; spf=pass dkim=pass dmarc=pass"
    message.set_content("Factura poate fi consultata in portalul oficial.")
    message.add_attachment(
        "<html><body><a href='https://payment.example/verify?token=attachment-secret'>"
        "Deschide factura pentru George Ionescu</a></body></html>",
        subtype="html",
        filename="George-invoice.html",
    )
    return message


def test_compound_email_ledger_preserves_body_headers_and_attachment_without_raw_identity():
    message = _compound_message()

    compound = extract_email_compound_evidence(
        message,
        body_text="Factura poate fi consultata in portalul oficial.",
        body_html=None,
        body_urls=[],
        email_auth={"auth_strength": "pass"},
    )

    ledger = compound["ledger"]
    serialized = json.dumps(ledger, ensure_ascii=False)
    assert ledger["schema"] == "sigurscan_email_evidence_ledger_v1"
    assert ledger["summary"] == {
        "header_part_count": 1,
        "body_part_count": 1,
        "attachment_count": 1,
        "extracted_attachment_count": 1,
        "unsupported_attachment_count": 0,
        "failed_attachment_count": 0,
        "candidate_url_count": 1,
        "candidate_qr_count": 0,
    }
    assert compound["attachment_urls"] == [
        "https://payment.example/verify?token=attachment-secret"
    ]
    assert ledger["coverage"]["status"] == "complete"
    assert "George-invoice.html" not in serialized
    assert "George Client" not in serialized
    assert "George Ionescu" not in serialized
    assert "george@example.test" not in serialized
    assert "attachment-secret" not in serialized
    assert all("redacted_text" not in part for part in ledger["parts"])
    assert ledger["parts"][0]["independence_group"] == "email_message"
    assert all(part["independence_group"] == "email_message" for part in ledger["parts"])


def test_compound_email_pdf_attachment_reuses_local_text_link_and_qr_extractors(monkeypatch):
    message = EmailMessage()
    message.set_content("Vezi documentul atasat.")
    message.add_attachment(
        b"%PDF-1.4 deterministic-test-payload",
        maintype="application",
        subtype="pdf",
        filename="statement.pdf",
    )
    monkeypatch.setattr(
        "services.email_evidence_ledger._extract_pdf_embedded_text",
        lambda _payload: "Plateste factura din document.",
    )
    monkeypatch.setattr(
        "services.email_evidence_ledger._extract_pdf_annotation_links",
        lambda _payload: ["https://invoice.example/pay?session=private-token"],
    )
    monkeypatch.setattr(
        "services.email_evidence_ledger._extract_pdf_qr_payloads",
        lambda _payload: ["https://invoice.example/qr?otp=123456"],
    )

    compound = extract_email_compound_evidence(
        message,
        body_text="Vezi documentul atasat.",
        body_html=None,
        body_urls=[],
        email_auth=None,
    )

    assert compound["attachment_text"] == "Plateste factura din document."
    assert compound["attachment_urls"] == [
        "https://invoice.example/pay?session=private-token",
        "https://invoice.example/qr?otp=123456",
    ]
    assert compound["attachment_qr_payloads"] == [
        "https://invoice.example/qr?otp=123456"
    ]
    attachment = compound["ledger"]["parts"][-1]
    assert attachment["mime_family"] == "pdf"
    assert attachment["extraction_status"] == "partial"
    assert attachment["qr"]["count"] == 1


def test_email_compound_shadow_does_not_activate_attachment_urls(monkeypatch):
    message = _compound_message()
    upload = UploadFile(filename="message.eml", file=io.BytesIO(message.as_bytes()))
    monkeypatch.setattr(extract_pipeline, "EMAIL_COMPOUND_EVIDENCE_ACTIVE", False)

    extraction = asyncio.run(
        extract_pipeline.extract_email_for_orchestration(
            email_file=upload,
            source_channel="android_share",
        )
    )

    assert extraction["extracted_urls"] == []
    assert extraction["email_compound_active"] is False
    assert extraction["email_compound_candidate_urls"] == [
        "https://payment.example/verify?token=attachment-secret"
    ]
    assert extraction["hidden_url_visibility"] is False
    assert extraction["email_evidence_ledger"]["summary"]["attachment_count"] == 1
    public_payload = extract_pipeline.public_email_extraction_payload(extraction)
    assert public_payload["email_evidence_ledger"]["schema"] == "sigurscan_email_evidence_ledger_v1"
    assert "email_compound_candidate_text" not in public_payload
    assert "email_compound_candidate_urls" not in public_payload
    assert "email_compound_candidate_qr_payloads" not in public_payload


def test_public_email_extract_route_does_not_expose_shadow_attachment_evidence(monkeypatch):
    message = _compound_message()
    monkeypatch.setattr(extract_pipeline, "EMAIL_COMPOUND_EVIDENCE_ACTIVE", False)

    response = TestClient(app_main.app).post(
        "/v1/extract/email",
        files={"email_file": ("message.eml", message.as_bytes(), "message/rfc822")},
        data={"source_channel": "android_share"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["extracted_urls"] == []
    assert payload["email_evidence_ledger"]["schema"] == "sigurscan_email_evidence_ledger_v1"
    assert "email_compound_candidate_text" not in payload
    assert "email_compound_candidate_urls" not in payload
    assert "email_compound_candidate_qr_payloads" not in payload


def test_attached_email_is_measured_without_treating_it_as_independent_provenance():
    nested = EmailMessage()
    nested["From"] = "Pretins furnizor <billing@other.example>"
    nested.set_content("Plateste aici https://nested.example/pay?token=secret")
    outer = EmailMessage()
    outer.set_content("Mesaj redirectionat in atasament.")
    outer.add_attachment(nested, filename="forwarded.eml")

    compound = extract_email_compound_evidence(
        outer,
        body_text="Mesaj redirectionat in atasament.",
        body_html=None,
        body_urls=[],
        email_auth=None,
    )

    attachment = compound["ledger"]["parts"][-1]
    assert attachment["mime_family"] == "email"
    assert attachment["extraction_status"] == "partial"
    assert attachment["independence_group"] == "email_message"
    assert compound["attachment_urls"] == [
        "https://nested.example/pay?token=secret"
    ]


def test_binary_attachment_budget_reports_skipped_parts_without_processing_them(monkeypatch):
    message = EmailMessage()
    message.set_content("Documente atasate.")
    for index in range(6):
        message.add_attachment(
            b"%PDF-1.4 payload",
            maintype="application",
            subtype="pdf",
            filename=f"document-{index}.pdf",
        )
    calls = {"count": 0}

    def count_pdf_text(_payload):
        calls["count"] += 1
        return "Text PDF"

    monkeypatch.setattr(
        "services.email_evidence_ledger._extract_pdf_embedded_text",
        count_pdf_text,
    )
    monkeypatch.setattr(
        "services.email_evidence_ledger._extract_pdf_annotation_links",
        lambda _payload: [],
    )
    monkeypatch.setattr(
        "services.email_evidence_ledger._extract_pdf_qr_payloads",
        lambda _payload: [],
    )

    compound = extract_email_compound_evidence(
        message,
        body_text="Documente atasate.",
        body_html=None,
        body_urls=[],
        email_auth=None,
    )

    statuses = [
        part["extraction_status"]
        for part in compound["ledger"]["parts"]
        if part["role"] == "attachment"
    ]
    assert calls["count"] == 4
    assert statuses.count("budget_skipped") == 2
    assert compound["ledger"]["coverage"]["status"] == "partial"


def test_email_compound_active_adds_attachment_urls_and_threads_header_auth(monkeypatch):
    message = _compound_message()
    upload = UploadFile(filename="message.eml", file=io.BytesIO(message.as_bytes()))
    monkeypatch.setattr(extract_pipeline, "EMAIL_COMPOUND_EVIDENCE_ACTIVE", True)
    extraction = asyncio.run(
        extract_pipeline.extract_email_for_orchestration(
            email_file=upload,
            source_channel="android_share",
        )
    )

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
                fallback_label="email",
                default_input_type="email",
                source_channel="android_share",
            )
        )

    job = persisted[-1]
    assert extraction["email_compound_active"] is True
    assert extraction["extracted_urls"] == [
        "https://payment.example/verify?token=attachment-secret"
    ]
    assert extraction["hidden_url_visibility"] is True
    assert job["email_auth"] == extraction["email_auth"]
    assert job["email_evidence_ledger"]["summary"]["attachment_count"] == 1
    assert job["email_compound_shadow"]["active"] is True
    assert "email_evidence_ledger" not in orchestrated_engine._orchestrated_status_payload(job)


def test_email_compound_shadow_preserves_existing_header_auth_fast_lane(monkeypatch):
    extraction = {
        "input_type": "email",
        "source_channel": "android_share",
        "redacted_text": "Mesaj informativ.",
        "extracted_urls": [],
        "email_auth": {"auth_strength": "fail"},
        "email_compound_active": False,
        "email_evidence_ledger": {
            "schema": "sigurscan_email_evidence_ledger_v1",
            "summary": {"attachment_count": 0, "candidate_url_count": 0},
            "coverage": {"status": "complete"},
            "parts": [],
        },
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
                fallback_label="email",
                default_input_type="email",
                source_channel="android_share",
            )
        )

    job = persisted[-1]
    assert job["email_auth"] == extraction["email_auth"]
    assert job["artifact_envelope"]["email_auth"]["present"] is True
    assert job["email_compound_shadow"]["candidate_email_auth_present"] is True


def test_client_roundtrip_ledger_is_resanitized_before_job_persistence(monkeypatch):
    forged_ledger = {
        "schema": "sigurscan_email_evidence_ledger_v1",
        "parts": [
            {
                "part_id": "attachment:1",
                "role": "attachment",
                "source_type": "George-private-source",
                "extraction_status": "complete",
                "redacted_text": "George https://evil.example/pay?otp=123456",
                "urls": {"items": ["https://evil.example/pay?otp=123456"], "count": 99},
                "qr": {"count": "not-an-int", "url_count": 0},
                "unknown_raw_field": "must-not-persist",
            }
        ],
    }
    with monkeypatch.context() as patched:
        patched.setattr(
            "services.orchestrated_scan.EMAIL_COMPOUND_EVIDENCE_ACTIVE",
            False,
        )
        patched.setattr(orchestrated_engine, "_persist_orchestrated_job", lambda candidate: candidate)
        patched.setattr(orchestrated_engine, "_emit_orchestrated_telemetry", lambda *args, **kwargs: None)
        job = asyncio.run(
            orchestrated_engine._create_orchestrated_job(
                app_main.OrchestratedScanRequest(
                    input_type="email",
                    text="Mesaj",
                    email_evidence_ledger=forged_ledger,
                    email_compound_active=True,
                )
            )
        )

    serialized = json.dumps(job["email_evidence_ledger"], ensure_ascii=False)
    assert job["email_evidence_ledger"]["transport"] == "client_roundtrip_sanitized"
    assert job["email_compound_shadow"]["active"] is False
    assert "unknown_raw_field" not in serialized
    assert "George-private-source" not in serialized
    assert "George" not in serialized
    assert "123456" not in serialized
    assert "otp=" not in serialized


def test_client_roundtrip_ledger_enforces_canonical_part_cardinality():
    repeated_parts = [
        {"role": "headers", "extraction_status": "complete"},
        {"role": "headers", "extraction_status": "complete"},
        {"role": "body", "extraction_status": "complete"},
        {"role": "body", "extraction_status": "complete"},
    ] + [
        {
            "role": "attachment",
            "extraction_status": "complete",
            "content_type": "text/plain",
        }
        for _index in range(40)
    ]

    sanitized = sanitize_email_evidence_ledger(
        {
            "schema": "sigurscan_email_evidence_ledger_v1",
            "parts": repeated_parts,
        }
    )

    assert sanitized is not None
    assert sanitized["summary"]["header_part_count"] == 1
    assert sanitized["summary"]["body_part_count"] == 1
    assert sanitized["summary"]["attachment_count"] == 32
    assert [part["part_id"] for part in sanitized["parts"][:2]] == ["headers", "body"]
    assert len({part["part_id"] for part in sanitized["parts"]}) == 34


def test_server_flag_can_activate_sanitized_client_roundtrip(monkeypatch):
    persisted = []
    with monkeypatch.context() as patched:
        patched.setattr(
            "services.orchestrated_scan.EMAIL_COMPOUND_EVIDENCE_ACTIVE",
            True,
        )
        patched.setattr(
            orchestrated_engine,
            "_persist_orchestrated_job",
            lambda candidate: persisted.append(candidate) or candidate,
        )
        patched.setattr(orchestrated_engine, "_emit_orchestrated_telemetry", lambda *args, **kwargs: None)
        asyncio.run(
            orchestrated_engine._create_orchestrated_job(
                app_main.OrchestratedScanRequest(
                    input_type="email",
                    text="Mesaj",
                    email_evidence_ledger={
                        "schema": "sigurscan_email_evidence_ledger_v1",
                        "parts": [
                            {"role": "headers", "extraction_status": "complete"},
                            {"role": "body", "extraction_status": "complete"},
                        ],
                    },
                    email_compound_active=True,
                )
            )
        )

    assert persisted[-1]["email_compound_shadow"]["active"] is True
