"""Extraction endpoint handlers extracted from runtime.py."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import importlib
import sys


from bs4 import BeautifulSoup
from fastapi import File, Form, HTTPException, UploadFile


class _RuntimeProxy:
    def __getattr__(self, name: str):
        runtime = sys.modules.get("main")
        if runtime is None:
            runtime = importlib.import_module("app")
        return getattr(runtime, name)


runtime = _RuntimeProxy()


async def extract_image_for_orchestration(
    image_file: UploadFile = File(...),
    source_channel: Optional[str] = Form("image_upload"),
):
    """Extract OCR text/URLs from an image. Final verdict is handled by /v1/scan/orchestrated."""
    filename = image_file.filename or "screenshot.jpg"
    image_bytes = await image_file.read()
    if not image_bytes:
        raise HTTPException(status_code=400, detail="Imaginea încărcată este goală.")

    runtime._validate_file_upload(
        filename=filename,
        content_type=image_file.content_type,
        file_bytes=image_bytes,
        max_bytes=runtime.MAX_IMAGE_BYTES,
        allowed_exts=runtime.ALLOWED_IMAGE_EXTS,
        allowed_mime_types=runtime.ALLOWED_IMAGE_MIME_TYPES,
        magic_validator=runtime._is_allowed_image_bytes,
    )

    qr_payloads = runtime._extract_image_qr_payloads(image_bytes)
    try:
        ocr_text, ocr_warning = await runtime.extract_text_for_scan(
            filename=filename,
            file_bytes=image_bytes,
            extract_fn=runtime.extract_text_with_vision,
        )
    except HTTPException as exc:
        if exc.status_code != 503 or not qr_payloads:
            raise
        ocr_text = ""
        ocr_warning = str(exc.detail)
    redacted_text = runtime.redact_pii(ocr_text)
    extracted_urls = runtime._dedupe_preserve_order(
        runtime.extract_urls(ocr_text)
        + runtime.extract_urls(redacted_text)
        + [url for payload in qr_payloads for url in runtime.extract_urls(payload)]
    )
    return {
        "input_type": "image_ocr",
        "source_channel": source_channel,
        "redacted_text": redacted_text,
        "extracted_urls": extracted_urls,
        "qr_payloads": qr_payloads,
        "html_content": None,
        "warning": ocr_warning,
        "hidden_url_visibility": bool(qr_payloads),
    }


async def extract_pdf_for_orchestration(
    pdf_file: UploadFile = File(...),
    source_channel: Optional[str] = Form("pdf_upload"),
):
    """Extract OCR text/URLs from a PDF. Final verdict is handled by /v1/scan/orchestrated."""
    filename = pdf_file.filename or "document.pdf"
    pdf_bytes = await pdf_file.read()
    if not pdf_bytes:
        raise HTTPException(status_code=400, detail="PDF-ul încărcat este gol.")

    runtime._validate_file_upload(
        filename=filename,
        content_type=pdf_file.content_type,
        file_bytes=pdf_bytes,
        max_bytes=runtime.MAX_PDF_BYTES,
        allowed_exts=runtime.ALLOWED_PDF_EXTS,
        allowed_mime_types={"application/pdf"},
    )

    if not pdf_bytes.startswith(b"%PDF-"):
        raise HTTPException(status_code=400, detail="Format PDF invalid.")

    annotation_urls = runtime._extract_pdf_annotation_links(pdf_bytes)
    qr_payloads = runtime._extract_pdf_qr_payloads(pdf_bytes)
    embedded_text = runtime._extract_pdf_embedded_text(pdf_bytes)
    try:
        ocr_text, ocr_warning = await runtime.extract_text_for_scan(
            filename=filename,
            file_bytes=pdf_bytes,
            extract_fn=runtime.extract_text_from_pdf_with_vision,
        )
    except HTTPException as exc:
        if exc.status_code != 503 or (not annotation_urls and not embedded_text):
            raise
        # PDF annotations/embedded text are real scan evidence even when OCR cannot read text.
        ocr_text = ""
        ocr_warning = str(exc.detail)
    ocr_text = runtime._merge_ocr_and_embedded_text(ocr_text, embedded_text)

    redacted_text = runtime.redact_pii(ocr_text)
    extracted_urls = runtime._dedupe_preserve_order(
        annotation_urls
        + runtime.extract_urls(ocr_text)
        + runtime.extract_urls(redacted_text)
        + [url for payload in qr_payloads for url in runtime.extract_urls(payload)]
    )
    return {
        "input_type": "pdf_ocr",
        "source_channel": source_channel,
        "redacted_text": redacted_text,
        "extracted_urls": extracted_urls,
        "qr_payloads": qr_payloads,
        "html_content": None,
        "warning": ocr_warning,
        "hidden_url_visibility": bool(annotation_urls or qr_payloads),
    }


async def extract_email_for_orchestration(
    email_file: Optional[UploadFile] = File(None),
    html_content: Optional[str] = Form(None),
    source_channel: Optional[str] = Form("email"),
):
    """Extract visible text, HTML, and clickable targets from email/HTML without producing a verdict."""
    from email import message_from_bytes, policy
    from email.message import Message

    html_to_parse = ""
    is_forwarded = True
    parsed_message: Optional[Message] = None

    if email_file is None and not html_content:
        raise HTTPException(status_code=400, detail="Trebuie trimis email_file sau html_content.")

    if email_file:
        content = await email_file.read()
        if len(content) > runtime.MAX_TEXT_CHARS * 4:
            raise HTTPException(status_code=413, detail="Fișierul este prea mare.")
        try:
            parsed_message = message_from_bytes(content, policy=policy.default)
            is_forwarded = False
            html_part = parsed_message.get_body(preferencelist=("html",))
            if html_part:
                html_to_parse = html_part.get_content()
            else:
                text_part = parsed_message.get_body(preferencelist=("plain",))
                if text_part:
                    html_to_parse = text_part.get_content()
        except Exception as exc:
            runtime.logger.error(f"Error parsing .eml for extraction: {exc}")
            raise HTTPException(status_code=400, detail=f"Invalid .eml file format: {exc}")
    elif html_content:
        if len(html_content) > runtime.MAX_TEXT_CHARS * 8:
            raise HTTPException(status_code=413, detail="Conținutul HTML este prea mare.")
        html_to_parse = html_content

    html_to_parse = runtime._normalise_obfuscated_text(html_to_parse)
    email_context = runtime._extract_email_auth_context(parsed_message, is_forwarded_guess=is_forwarded)
    if not html_to_parse.strip():
        return {
            "input_type": "email",
            "source_channel": source_channel,
            "redacted_text": "",
            "html_content": None,
            "extracted_urls": [],
            "buttons": [],
            "email_auth": email_context,
            "warning": "Corpul e-mailului este gol sau nu a putut fi citit.",
        }

    soup = BeautifulSoup(html_to_parse, "html.parser")
    click_targets = runtime._collect_click_targets_from_html(soup)
    discovered_urls: List[str] = []
    buttons: List[Dict[str, Any]] = []
    cta_words = [
        "verific",
        "confirm",
        "plăte",
        "plate",
        "cont",
        "login",
        "conect",
        "intrare",
        "detalii",
        "colet",
        "awb",
        "reactivare",
        "urgent",
    ]

    for target in click_targets:
        raw_url = target.get("original_url")
        if not raw_url or raw_url in discovered_urls:
            continue
        discovered_urls.append(raw_url)
        button_text = str(target.get("button_text") or "")
        buttons.append(
            {
                "button_text": button_text,
                "original_url": raw_url,
                "is_sensitive_cta": any(word in button_text.lower() for word in cta_words),
                "source_tag": target.get("source_tag"),
                "source_attr": target.get("source_attr"),
            }
        )

    visible_text = soup.get_text(separator=" ", strip=True)
    for url in runtime.extract_urls(visible_text):
        if url not in discovered_urls:
            discovered_urls.append(url)

    email_subject = parsed_message.get("Subject", "") if parsed_message else ""
    inferred_brand_hints = runtime._infer_brand_hints_from_click_targets(
        click_targets,
        runtime.BRAND_REGISTRY,
    )
    content_for_analysis = "\n".join(
        part
        for part in [
            email_subject,
            visible_text,
            " ".join(inferred_brand_hints),
        ]
        if part.strip()
    )
    return {
        "input_type": "email",
        "source_channel": source_channel,
        "redacted_text": runtime.redact_pii(content_for_analysis),
        "html_content": html_to_parse,
        "extracted_urls": discovered_urls,
        "buttons": buttons,
        "email_auth": email_context,
        "subject": email_subject,
        "from": parsed_message.get("From") if parsed_message else None,
        "reply_to": parsed_message.get("Reply-To") if parsed_message else None,
        "message_id": parsed_message.get("Message-ID") if parsed_message else None,
        "inferred_brand_hints": inferred_brand_hints,
        "warning": None,
    }


def _assemble_extracted_text_for_orchestration(extraction: Dict[str, Any], fallback_label: str) -> str:
    text = str(extraction.get("redacted_text") or "").strip()
    urls = [
        str(url).strip()
        for url in extraction.get("extracted_urls") or []
        if str(url).strip()
    ]
    qr_payloads = [
        str(payload).strip()
        for payload in extraction.get("qr_payloads") or []
        if str(payload).strip()
    ]
    parts = [text or f"Conținut extras din {fallback_label}."]
    if urls:
        parts.append("Linkuri extrase:")
        parts.extend(urls)
    if qr_payloads:
        parts.append("Coduri QR extrase:")
        parts.extend(qr_payloads)
    return "\n".join(parts).strip()
