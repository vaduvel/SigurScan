"""Scan compatibility wrappers extracted from runtime.py."""

from __future__ import annotations

from typing import List, Optional
import urllib.parse

from fastapi import File, Form, HTTPException, UploadFile
import importlib

from api_models import OrchestratedScanRequest, TextScanRequest, URLScanRequest
from config import (
    ALLOWED_IMAGE_EXTS,
    ALLOWED_IMAGE_MIME_TYPES,
    ALLOWED_PDF_EXTS,
    ALLOWED_PDF_MIME_TYPES,
    ALLOWED_XML_EXTS,
    ALLOWED_XML_MIME_TYPES,
    MAX_IMAGE_BYTES,
    MAX_PDF_BYTES,
    MAX_TEXT_CHARS,
    MAX_XML_BYTES,
)
from core.text_utils import _normalise_obfuscated_text
from core.url_intelligence import (
    _canonicalize_url,
    _dedupe_preserve_order,
    _extract_image_qr_payloads,
    _extract_pdf_annotation_links,
    _extract_pdf_embedded_text,
    _extract_pdf_qr_payloads,
    _merge_ocr_and_embedded_text,
    _normalize_sanb_attestation,
    extract_urls,
)
from services.google_vision_ocr import extract_text_from_pdf_with_vision, extract_text_with_vision
from services import extract_pipeline
from services.scan_helpers import (
    _invoice_payment_destination_for_client,
    _is_allowed_image_bytes,
    _validate_text_input,
    _validate_file_upload,
    extract_text_for_scan,
)
from services.orchestrated_scan import orchestrated_engine
from services.payment_case import build_payment_case_facts
from services.pre_redaction_evidence import extract_pre_redaction_evidence
from services import payment_case_store


def _extract_compat_fn(name: str, fallback):
    try:
        app_main = importlib.import_module("main")
        candidate = getattr(app_main, name)
        if callable(candidate):
            return candidate
    except Exception:
        pass
    return fallback


def _invoice_decision_scope(invoice_truth: dict | None) -> dict[str, str]:
    """Describe what the invoice verdict does and does not establish."""
    truth = invoice_truth if isinstance(invoice_truth, dict) else {}
    if str(truth.get("verdict") or "") == "NU_PLATI":
        payment_assurance = "DO_NOT_AUTHORIZE"
    elif truth.get("safe_to_pay") is True:
        payment_assurance = "CONFIRMED"
    elif truth:
        payment_assurance = "USER_VERIFICATION_REQUIRED"
    else:
        payment_assurance = "UNKNOWN"
    return {
        "primary_verdict_scope": "DOCUMENT_AUTHENTICITY_AND_FRAUD_RISK",
        # SigurScan has no bank account or SPV access and never claims to know
        # whether the invoice has already been paid.
        "payment_status": "NOT_ASSESSED",
        "payment_assurance": payment_assurance,
    }


async def scan_text(request: TextScanRequest):
    """
    Compatibility wrapper. Starts the product-grade orchestrated scan and returns scan_id/status.
    """
    raw_text = _normalise_obfuscated_text((request.text or "").strip())
    _validate_text_input("Textul trimis", raw_text, MAX_TEXT_CHARS)
    return await orchestrated_engine._start_orchestrated_compat(
        OrchestratedScanRequest(
            input_type="text",
            text=raw_text,
            source_channel=request.source_channel or "manual",
        )
    )


async def scan_url(request: URLScanRequest):
    """
    Compatibility wrapper. Starts the product-grade orchestrated URL scan and returns scan_id/status.
    """
    url = _canonicalize_url(_normalise_obfuscated_text(request.url or ""))
    if not url:
        raise HTTPException(status_code=400, detail="URL invalid sau format neacceptat.")
    return await orchestrated_engine._start_orchestrated_compat(
        OrchestratedScanRequest(
            input_type="url",
            url=url,
            source_channel=request.source_channel or "url_scan",
        )
    )


async def scan_email(
    email_file: Optional[UploadFile] = File(None),
    html_content: Optional[str] = Form(None),
    source_channel: Optional[str] = Form("email"),
):
    """
    Compatibility wrapper. Extracts email evidence, then starts orchestrated scan.
    """
    extract_email_for_orchestration = _extract_compat_fn(
        "extract_email_for_orchestration",
        extract_pipeline.extract_email_for_orchestration,
    )
    extraction = await extract_email_for_orchestration(
        email_file=email_file,
        html_content=html_content,
        source_channel=source_channel,
    )
    return await orchestrated_engine._start_orchestrated_from_extraction(
        extraction,
        fallback_label="email",
        default_input_type="email",
        source_channel=source_channel,
    )


async def scan_image(
    image_file: UploadFile = File(...),
    source_channel: Optional[str] = Form("image_upload"),
):
    """
    Compatibility wrapper. Extracts OCR evidence, then starts orchestrated scan.
    """
    extract_image_for_orchestration = _extract_compat_fn(
        "extract_image_for_orchestration",
        extract_pipeline.extract_image_for_orchestration,
    )
    extraction = await extract_image_for_orchestration(
        image_file=image_file,
        source_channel=source_channel,
    )
    return await orchestrated_engine._start_orchestrated_from_extraction(
        extraction,
        fallback_label="imagine",
        default_input_type="image_ocr",
        source_channel=source_channel,
    )


async def scan_pdf(
    pdf_file: UploadFile = File(...),
    source_channel: Optional[str] = Form("pdf_upload"),
):
    """
    Compatibility wrapper. Extracts PDF OCR evidence, then starts orchestrated scan.
    """
    extract_pdf_for_orchestration = _extract_compat_fn(
        "extract_pdf_for_orchestration",
        extract_pipeline.extract_pdf_for_orchestration,
    )
    extraction = await extract_pdf_for_orchestration(
        pdf_file=pdf_file,
        source_channel=source_channel,
    )
    return await orchestrated_engine._start_orchestrated_from_extraction(
        extraction,
        fallback_label="PDF",
        default_input_type="pdf_ocr",
        source_channel=source_channel,
    )


async def scan_invoice_endpoint(
    image_file: Optional[UploadFile] = File(None),
    pdf_file: Optional[UploadFile] = File(None),
    official_xml_file: Optional[UploadFile] = File(None),
    source_channel: Optional[str] = Form("android_native"),
    sanb_attestation: Optional[str] = Form(None),
    client_instance_id: str | None = None,
    payment_case_active: bool = Form(False),
):
    """
    Invoice-specific scan endpoint.
    Accepts an image or PDF, runs OCR, extracts invoice fields, validates
    IBAN/CUI/brand, checks ANAF registry, and returns structured warnings.
    """
    from services.efactura_xml import EFacturaXmlError, compare_invoice_to_official_xml, parse_efactura_xml
    from services.invoice_orchestrator import evaluate_invoice_verdict, scan_invoice, with_official_document_check

    if bool(image_file) == bool(pdf_file):
        raise HTTPException(
            status_code=400,
            detail="Trimite exact o factură: imagine sau PDF.",
        )

    pdf_annotation_urls: List[str] = []
    qr_payloads: List[str] = []
    ocr_warning = None
    ocr_text = ""

    if pdf_file is not None:
        filename = pdf_file.filename or "invoice.pdf"
        file_bytes = await pdf_file.read()
        if not file_bytes:
            raise HTTPException(status_code=400, detail="PDF-ul încărcat este gol.")
        _validate_file_upload(
            filename=filename,
            content_type=pdf_file.content_type,
            file_bytes=file_bytes,
            max_bytes=MAX_PDF_BYTES,
            allowed_exts=ALLOWED_PDF_EXTS,
            allowed_mime_types=ALLOWED_PDF_MIME_TYPES,
        )
        if not file_bytes.startswith(b"%PDF-"):
            raise HTTPException(status_code=400, detail="Fișierul nu pare să fie un PDF valid.")
        pdf_annotation_urls = _extract_pdf_annotation_links(file_bytes)
        qr_payloads = _extract_pdf_qr_payloads(file_bytes)
        embedded_text = _extract_pdf_embedded_text(file_bytes)
        try:
            ocr_text, ocr_warning = await extract_text_for_scan(
                filename=filename,
                file_bytes=file_bytes,
                extract_fn=extract_text_from_pdf_with_vision,
            )
        except HTTPException as exc:
            if exc.status_code != 503 or (not pdf_annotation_urls and not embedded_text):
                raise
            ocr_text = ""
            ocr_warning = str(exc.detail)
        ocr_text = _merge_ocr_and_embedded_text(ocr_text, embedded_text)
        source_type = "pdf"
    else:
        assert image_file is not None
        filename = image_file.filename or "invoice.jpg"
        file_bytes = await image_file.read()
        if not file_bytes:
            raise HTTPException(status_code=400, detail="Imaginea încărcată este goală.")
        _validate_file_upload(
            filename=filename,
            content_type=image_file.content_type,
            file_bytes=file_bytes,
            max_bytes=MAX_IMAGE_BYTES,
            allowed_exts=ALLOWED_IMAGE_EXTS,
            allowed_mime_types=ALLOWED_IMAGE_MIME_TYPES,
            magic_validator=_is_allowed_image_bytes,
        )
        ocr_text, ocr_warning = await extract_text_for_scan(
            filename=filename,
            file_bytes=file_bytes,
            extract_fn=extract_text_with_vision,
        )
        qr_payloads = _extract_image_qr_payloads(file_bytes)
        source_type = "image"

    extracted_urls = _dedupe_preserve_order(
        pdf_annotation_urls
        + extract_urls(ocr_text)
        + qr_payloads
        + [url for payload in qr_payloads for url in extract_urls(payload)]
    )
    result = await scan_invoice(ocr_text, links=extracted_urls)
    official_document_check = {"provided": False, "status": "not_provided"}
    if official_xml_file is not None:
        xml_filename = official_xml_file.filename or "efactura.xml"
        xml_bytes = await official_xml_file.read()
        if not xml_bytes:
            raise HTTPException(status_code=400, detail="XML-ul oficial încărcat este gol.")
        _validate_file_upload(
            filename=xml_filename,
            content_type=official_xml_file.content_type,
            file_bytes=xml_bytes,
            max_bytes=MAX_XML_BYTES,
            allowed_exts=ALLOWED_XML_EXTS,
            allowed_mime_types=ALLOWED_XML_MIME_TYPES,
        )
        try:
            official_fields = parse_efactura_xml(xml_bytes)
            official_document_check = compare_invoice_to_official_xml(result.fields, official_fields)
        except EFacturaXmlError as exc:
            official_document_check = {
                "provided": True,
                "status": "parse_error",
                "risk_flag": "EFACTURA_OFFICIAL_DOCUMENT_UNREADABLE",
                "mismatches": [],
                "matched_fields": [],
                "missing_official_fields": [],
                "error": str(exc),
            }
        result = with_official_document_check(result, official_document_check)

    normalized_sanb_attestation = _normalize_sanb_attestation(sanb_attestation)
    invoice_gate = evaluate_invoice_verdict(
        result,
        result.raw_text,
        source_channel=source_channel,
        sanb_attestation=normalized_sanb_attestation,
    )
    client_payment_destination = _invoice_payment_destination_for_client(result, invoice_gate)
    invoice_truth = invoice_gate.get("invoice_truth")

    response = {
        "source_type": source_type,
        "fields": {
            "emitent": result.fields.emitent,
            "cui": result.fields.cui,
            "iban": result.fields.iban,
            "nr_factura": result.fields.nr_factura,
            "data_emitere": result.fields.data_emitere,
            "scadenta": result.fields.scadenta,
            "subtotal": result.fields.subtotal,
            "tva": result.fields.tva,
            "total": result.fields.total,
            "currency": result.fields.currency,
            "invoice_profile": result.fields.invoice_profile,
            "all_ibans": result.fields.all_ibans,
            "payment_beneficiary": result.fields.payment_beneficiary,
        },
        "readiness": {
            "state": result.readiness.state.value,
            "blocks_safe_verdict": result.readiness.blocks_safe_verdict,
            "items": [
                {"id": item.id, "label": item.label, "detail": item.detail, "next_action": item.next_action}
                for item in result.readiness.items
            ],
        },
        "coherence": {
            "totals_match": result.coherence.totals_match,
            "tva_rate_plausible": result.coherence.tva_rate_plausible,
            "dates_plausible": result.coherence.dates_plausible,
            "all_ok": result.coherence.all_ok,
        },
        "iban": {
            "valid": result.iban_valid.valid_structure if result.iban_valid else None,
            "bank": result.iban_valid.bank_name if result.iban_valid else None,
            "is_trezorerie": result.iban_valid.is_trezorerie if result.iban_valid else None,
        } if result.iban_valid else None,
        "brand": result.brand,
        "brand_match": {
            "domain_matches": result.brand_match.domain_matches,
            "cui_matches": result.brand_match.cui_matches,
            "iban_matches": result.brand_match.iban_matches,
            "impersonation_risk": result.brand_match.impersonation_risk,
        } if result.brand_match else None,
        "payment_destination": client_payment_destination,
        "beneficiary_name_check": result.beneficiary_name_check,
        "official_document_check": official_document_check,
        "anaf": result.anaf_cui_check,
        "fraud_flags": result.fraud_flags,
        "evidence_bundle": invoice_gate["bundle"],
        "verdict_gate": invoice_gate["gate"],
        "decision_scope": _invoice_decision_scope(invoice_truth),
        "invoice_truth": invoice_truth,
        "sanb_attestation": normalized_sanb_attestation,
        "warnings": result.warnings,
        "error": result.error,
        "ocr_warning": ocr_warning,
        "qr_payloads": qr_payloads,
    }
    if payment_case_active is True and str(client_instance_id or "").strip():
        gate = invoice_gate.get("gate") if isinstance(invoice_gate.get("gate"), dict) else {}
        primary_reason = str((invoice_truth or {}).get("primary_reason_code") or "")
        signals = list(result.fraud_flags or [])
        if primary_reason:
            signals.append(primary_reason)
        facts = build_payment_case_facts(
            artifact_type="invoice",
            pre_redaction_evidence=extract_pre_redaction_evidence(result.raw_text),
            entity_name=result.fields.emitent or result.fields.payment_beneficiary,
            cui=result.fields.cui,
            amount=result.fields.total,
            currency=result.fields.currency,
            requested_actions=["pay_invoice"] if result.fields.iban or result.fields.total is not None else [],
            signals=signals,
            domains=[
                host
                for url in extracted_urls
                if (host := (urllib.parse.urlparse(url).hostname or "").lower())
            ],
            evidence_provenance="server_extracted",
        )
        try:
            artifact = payment_case_store.register_server_artifact(
                client_instance_id=client_instance_id,
                artifact_type="invoice",
                verdict=str(gate.get("label") or "UNVERIFIED"),
                is_final=True,
                reason_codes=gate.get("reason_codes") if isinstance(gate.get("reason_codes"), list) else [],
                facts=facts,
            )
            response["payment_case_artifact_ref"] = artifact["artifact_ref"]
        except Exception:
            # The invoice verdict remains usable if the optional case store is
            # temporarily unavailable; the UI simply cannot combine it yet.
            pass
    return response
