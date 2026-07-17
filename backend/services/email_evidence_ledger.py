"""Privacy-safe evidence ledger for compound RFC822 messages.

The ledger is verdict-neutral. It records which MIME parts were inspected and
returns transient attachment candidates to the caller. Raw attachment bytes,
file names, identities, and QR payloads must never be persisted in the ledger.
"""

from __future__ import annotations

import hashlib
import json
import re
from email.message import Message
from pathlib import PurePath
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from bs4 import BeautifulSoup

from core.click_intelligence import _collect_click_targets_from_html
from core.url_intelligence import (
    _dedupe_preserve_order,
    _extract_image_qr_payloads,
    _extract_pdf_annotation_links,
    _extract_pdf_embedded_text,
    _extract_pdf_qr_payloads,
    extract_urls,
)
from services.external_url_privacy import prepare_external_urls


EMAIL_EVIDENCE_LEDGER_SCHEMA = "sigurscan_email_evidence_ledger_v1"
MAX_EMAIL_MIME_PARTS = 32
MAX_EMAIL_BINARY_ATTACHMENT_SCANS = 4
MAX_EMAIL_PART_BYTES = 12 * 1024 * 1024
MAX_TRANSIENT_ATTACHMENT_TEXT_CHARS = 24000

_TEXT_ATTACHMENT_TYPES = {
    "text/plain",
    "text/csv",
    "text/markdown",
    "application/json",
    "application/xml",
    "text/xml",
}
_IMAGE_ATTACHMENT_TYPES = {"image/jpeg", "image/png", "image/webp"}
_SAFE_CONTENT_TYPE_RE = re.compile(r"^[a-z0-9.+_-]+/[a-z0-9.+_-]+$")


def _stable_hash(payload: Mapping[str, Any]) -> str:
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _safe_content_type(value: Any) -> str:
    normalized = str(value or "application/octet-stream").strip().lower()
    if not _SAFE_CONTENT_TYPE_RE.fullmatch(normalized):
        return "application/octet-stream"
    return normalized[:96]


def _safe_extension(filename: Any) -> Optional[str]:
    if not filename:
        return None
    suffix = PurePath(str(filename)).suffix.lower()
    if re.fullmatch(r"\.[a-z0-9]{1,10}", suffix):
        return suffix
    return None


def _part_bytes(part: Message) -> bytes:
    payload = part.get_payload(decode=True)
    if isinstance(payload, bytes):
        return payload
    try:
        content = part.get_content()
    except Exception:
        return b""
    if isinstance(content, bytes):
        return content
    if isinstance(content, str):
        charset = part.get_content_charset() or "utf-8"
        return content.encode(charset, errors="replace")
    return b""


def _decode_text_part(part: Message, payload: bytes) -> str:
    try:
        content = part.get_content()
    except Exception:
        content = None
    if isinstance(content, str):
        return content
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except (LookupError, UnicodeError):
        return payload.decode("utf-8", errors="replace")


def _html_evidence(html: str) -> Tuple[str, List[str]]:
    soup = BeautifulSoup(str(html or ""), "html.parser")
    urls: List[str] = []
    for target in _collect_click_targets_from_html(soup):
        url = str(target.get("original_url") or "").strip()
        if url and url not in urls:
            urls.append(url)
    visible_text = soup.get_text(separator=" ", strip=True)
    return visible_text, _dedupe_preserve_order(urls + extract_urls(visible_text))


def _safe_urls(urls: Iterable[str]) -> List[str]:
    safe_urls, _privacy = prepare_external_urls(str(url or "") for url in urls or [])
    return safe_urls


def _text_size_bucket(value: Any) -> str:
    length = len(str(value or "").strip())
    if length == 0:
        return "empty"
    if length <= 512:
        return "short"
    if length <= 4096:
        return "medium"
    return "long"


def _bounded_int(value: Any, *, maximum: int = 64) -> int:
    try:
        return max(0, min(int(value or 0), maximum))
    except (TypeError, ValueError):
        return 0


def _base_part(part_id: str, role: str, source_type: str) -> Dict[str, Any]:
    return {
        "part_id": part_id,
        "role": role,
        "source_type": source_type,
        "source_group": "email_message",
        "independence_group": "email_message",
        "authority": "user_supplied",
    }


def _body_part(body_text: str, body_html: Optional[str], body_urls: Sequence[str]) -> Dict[str, Any]:
    part = _base_part("body", "body", "mime_body")
    part.update(
        {
            "content_type": "text/html" if body_html else "text/plain",
            "has_html": bool(body_html),
            "extraction_status": "complete" if (body_text or body_html) else "empty",
            "text_present": bool(str(body_text or "").strip()),
            "text_size_bucket": _text_size_bucket(body_text),
            "urls": {"items": _safe_urls(body_urls), "count": len(_dedupe_preserve_order(body_urls))},
            "qr": {"count": 0, "url_count": 0},
        }
    )
    return part


def _nested_email_evidence(part: Message) -> Tuple[str, List[str]]:
    nested_payload = part.get_payload()
    if not isinstance(nested_payload, list) or not nested_payload:
        return "", []
    nested = nested_payload[0]
    if not isinstance(nested, Message):
        return "", []
    body = nested.get_body(preferencelist=("html", "plain"))
    if body is None:
        return "", []
    payload = _part_bytes(body)
    content = _decode_text_part(body, payload)
    if str(body.get_content_type() or "").lower() == "text/html":
        return _html_evidence(content)
    return content, extract_urls(content)


def _attachment_evidence(
    part: Message,
    index: int,
    *,
    allow_binary_scan: bool = True,
) -> Tuple[Dict[str, Any], str, List[str], List[str]]:
    content_type = _safe_content_type(part.get_content_type())
    filename = part.get_filename()
    payload = _part_bytes(part)
    evidence = _base_part(f"attachment:{index}", "attachment", "mime_attachment")
    evidence.update(
        {
            "content_type": content_type,
            "content_disposition": str(part.get_content_disposition() or "inline").lower(),
            "filename_present": bool(filename),
            "extension": _safe_extension(filename),
            "size_bucket": (
                "empty"
                if not payload
                else "small"
                if len(payload) <= 256 * 1024
                else "medium"
                if len(payload) <= 2 * 1024 * 1024
                else "large"
            ),
        }
    )

    text = ""
    urls: List[str] = []
    qr_payloads: List[str] = []
    mime_family = "other"
    extraction_status = "unsupported"

    if content_type in {"application/pdf", *_IMAGE_ATTACHMENT_TYPES} and not allow_binary_scan:
        mime_family = "pdf" if content_type == "application/pdf" else "image"
        extraction_status = "budget_skipped"
    elif len(payload) > MAX_EMAIL_PART_BYTES:
        extraction_status = "too_large"
    elif content_type == "text/html":
        mime_family = "text"
        text, urls = _html_evidence(_decode_text_part(part, payload))
        extraction_status = "complete"
    elif content_type in _TEXT_ATTACHMENT_TYPES:
        mime_family = "text"
        text = _decode_text_part(part, payload).strip()
        urls = extract_urls(text)
        extraction_status = "complete"
    elif content_type == "application/pdf" and payload.startswith(b"%PDF-"):
        mime_family = "pdf"
        text = _extract_pdf_embedded_text(payload)
        qr_payloads = _extract_pdf_qr_payloads(payload)
        urls = _dedupe_preserve_order(
            _extract_pdf_annotation_links(payload)
            + extract_urls(text)
            + [url for qr in qr_payloads for url in extract_urls(qr)]
        )
        # No cloud OCR is invoked inside e-mail parsing. Scanned-only PDF text
        # may therefore remain unseen and the coverage must stay explicit.
        extraction_status = "partial"
    elif content_type in _IMAGE_ATTACHMENT_TYPES:
        mime_family = "image"
        qr_payloads = _extract_image_qr_payloads(payload)
        urls = _dedupe_preserve_order(
            [url for qr in qr_payloads for url in extract_urls(qr)]
        )
        extraction_status = "partial"
    elif content_type == "message/rfc822":
        mime_family = "email"
        text, urls = _nested_email_evidence(part)
        extraction_status = "partial"

    safe_urls = _safe_urls(urls)
    qr_url_count = len(
        _dedupe_preserve_order([url for qr in qr_payloads for url in extract_urls(qr)])
    )
    evidence.update(
        {
            "mime_family": mime_family,
            "extraction_status": extraction_status,
            "text_present": bool(text.strip()),
            "text_size_bucket": _text_size_bucket(text),
            "urls": {"items": safe_urls, "count": len(_dedupe_preserve_order(urls))},
            "qr": {"count": len(qr_payloads), "url_count": qr_url_count},
        }
    )
    return evidence, text, _dedupe_preserve_order(urls), _dedupe_preserve_order(qr_payloads)


def extract_email_compound_evidence(
    parsed_message: Optional[Message],
    *,
    body_text: str,
    body_html: Optional[str],
    body_urls: Sequence[str],
    email_auth: Optional[Mapping[str, Any]],
) -> Dict[str, Any]:
    """Inspect compound MIME parts without changing the active scan decision."""

    parts: List[Dict[str, Any]] = []
    header = _base_part("headers", "headers", "rfc822_headers")
    header.update(
        {
            "extraction_status": "complete" if parsed_message is not None else "unavailable",
            "email_auth_present": bool(email_auth),
            "reply_to_present": bool(parsed_message and parsed_message.get("Reply-To")),
        }
    )
    parts.append(header)
    parts.append(_body_part(body_text, body_html, body_urls))

    attachment_texts: List[str] = []
    attachment_urls: List[str] = []
    attachment_qr_payloads: List[str] = []
    attachment_count = 0
    extracted_attachment_count = 0
    unsupported_attachment_count = 0
    failed_attachment_count = 0

    if parsed_message is not None:
        leaf_parts = [
            part
            for part in parsed_message.walk()
            if not part.is_multipart() or part.get_content_type() == "message/rfc822"
        ]
        binary_scans = 0
        for part in leaf_parts:
            filename = part.get_filename()
            disposition = str(part.get_content_disposition() or "").lower()
            content_type = _safe_content_type(part.get_content_type())
            is_attachment = (
                bool(filename)
                or disposition == "attachment"
                or content_type not in {"text/plain", "text/html"}
            )
            if not is_attachment:
                continue
            attachment_count += 1
            if attachment_count > MAX_EMAIL_MIME_PARTS:
                failed_attachment_count += 1
                continue
            try:
                is_binary = content_type == "application/pdf" or content_type in _IMAGE_ATTACHMENT_TYPES
                allow_binary_scan = not is_binary or binary_scans < MAX_EMAIL_BINARY_ATTACHMENT_SCANS
                evidence, text, urls, qr_payloads = _attachment_evidence(
                    part,
                    attachment_count,
                    allow_binary_scan=allow_binary_scan,
                )
                if is_binary and allow_binary_scan:
                    binary_scans += 1
            except Exception:
                evidence = _base_part(
                    f"attachment:{attachment_count}",
                    "attachment",
                    "mime_attachment",
                )
                evidence.update(
                    {
                        "content_type": _safe_content_type(part.get_content_type()),
                        "content_disposition": disposition or "inline",
                        "filename_present": bool(filename),
                        "extension": _safe_extension(filename),
                        "mime_family": "other",
                        "extraction_status": "failed",
                        "text_present": False,
                        "text_size_bucket": "empty",
                        "urls": {"items": [], "count": 0},
                        "qr": {"count": 0, "url_count": 0},
                    }
                )
                text, urls, qr_payloads = "", [], []
            parts.append(evidence)
            status = str(evidence.get("extraction_status") or "failed")
            if status in {"complete", "partial"}:
                extracted_attachment_count += 1
            elif status == "unsupported":
                unsupported_attachment_count += 1
            else:
                failed_attachment_count += 1
            if text.strip() and text not in attachment_texts:
                attachment_texts.append(text.strip())
            attachment_urls.extend(urls)
            attachment_qr_payloads.extend(qr_payloads)

    attachment_urls = _dedupe_preserve_order(attachment_urls)
    attachment_qr_payloads = _dedupe_preserve_order(attachment_qr_payloads)
    has_partial = any(
        part.get("extraction_status") == "partial"
        for part in parts
        if part.get("role") == "attachment"
    )
    coverage_status = (
        "partial"
        if has_partial or unsupported_attachment_count or failed_attachment_count
        else "complete"
    )
    ledger: Dict[str, Any] = {
        "schema": EMAIL_EVIDENCE_LEDGER_SCHEMA,
        "source_type": "email",
        "source_group": "email_message",
        "parts": parts,
        "summary": {
            "header_part_count": 1,
            "body_part_count": 1,
            "attachment_count": attachment_count,
            "extracted_attachment_count": extracted_attachment_count,
            "unsupported_attachment_count": unsupported_attachment_count,
            "failed_attachment_count": failed_attachment_count,
            "candidate_url_count": len(attachment_urls),
            "candidate_qr_count": len(attachment_qr_payloads),
        },
        "coverage": {
            "status": coverage_status,
            "cloud_ocr_used": False,
            "attachment_limit": MAX_EMAIL_MIME_PARTS,
            "binary_scan_limit": MAX_EMAIL_BINARY_ATTACHMENT_SCANS,
        },
    }
    ledger["ledger_hash"] = _stable_hash(ledger)
    return {
        "ledger": ledger,
        "attachment_text": "\n".join(attachment_texts)[:MAX_TRANSIENT_ATTACHMENT_TEXT_CHARS],
        "attachment_urls": attachment_urls,
        "attachment_qr_payloads": attachment_qr_payloads,
    }


def sanitize_email_evidence_ledger(candidate: Any) -> Optional[Dict[str, Any]]:
    """Whitelist and re-sanitize a ledger returned through a client round-trip."""

    if not isinstance(candidate, Mapping) or candidate.get("schema") != EMAIL_EVIDENCE_LEDGER_SCHEMA:
        return None
    raw_parts = candidate.get("parts")
    if not isinstance(raw_parts, list):
        return None

    header_part: Optional[Dict[str, Any]] = None
    body_part: Optional[Dict[str, Any]] = None
    attachment_parts: List[Dict[str, Any]] = []
    allowed_statuses = {
        "complete",
        "partial",
        "empty",
        "unavailable",
        "unsupported",
        "failed",
        "too_large",
        "budget_skipped",
    }
    # Inspect a bounded superset because a forged payload may repeat singleton
    # roles before valid attachments. The canonical output still permits only
    # one headers part, one body part, and MAX_EMAIL_MIME_PARTS attachments.
    for raw_part in raw_parts[: MAX_EMAIL_MIME_PARTS * 4 + 2]:
        if not isinstance(raw_part, Mapping):
            continue
        role = str(raw_part.get("role") or "unknown").strip().lower()
        if role not in {"headers", "body", "attachment"}:
            continue
        if role == "headers" and header_part is not None:
            continue
        if role == "body" and body_part is not None:
            continue
        if role == "attachment" and len(attachment_parts) >= MAX_EMAIL_MIME_PARTS:
            continue
        status = str(raw_part.get("extraction_status") or "failed").strip().lower()
        if status not in allowed_statuses:
            status = "failed"
        raw_urls = raw_part.get("urls") if isinstance(raw_part.get("urls"), Mapping) else {}
        safe_urls = _safe_urls(raw_urls.get("items") if isinstance(raw_urls.get("items"), list) else [])
        raw_qr = raw_part.get("qr") if isinstance(raw_part.get("qr"), Mapping) else {}
        part = _base_part(
            role if role in {"headers", "body"} else f"attachment:{len(attachment_parts) + 1}",
            role,
            {
                "headers": "rfc822_headers",
                "body": "mime_body",
                "attachment": "mime_attachment",
            }[role],
        )
        part.update(
            {
                "extraction_status": status,
                "urls": {"items": safe_urls, "count": len(safe_urls)},
                "qr": {
                    "count": _bounded_int(raw_qr.get("count")),
                    "url_count": _bounded_int(raw_qr.get("url_count")),
                },
            }
        )
        if raw_part.get("content_type") is not None:
            part["content_type"] = _safe_content_type(raw_part.get("content_type"))
        if str(raw_part.get("content_disposition") or "").lower() in {"inline", "attachment"}:
            part["content_disposition"] = str(raw_part.get("content_disposition")).lower()
        extension = _safe_extension("file" + str(raw_part.get("extension") or ""))
        if extension:
            part["extension"] = extension
        if str(raw_part.get("mime_family") or "").lower() in {"text", "pdf", "image", "email", "other"}:
            part["mime_family"] = str(raw_part.get("mime_family")).lower()
        if str(raw_part.get("size_bucket") or "").lower() in {"empty", "small", "medium", "large"}:
            part["size_bucket"] = str(raw_part.get("size_bucket")).lower()
        if str(raw_part.get("text_size_bucket") or "").lower() in {"empty", "short", "medium", "long"}:
            part["text_size_bucket"] = str(raw_part.get("text_size_bucket")).lower()
        for key in (
            "has_html",
            "filename_present",
            "text_present",
            "email_auth_present",
            "reply_to_present",
        ):
            if key in raw_part:
                part[key] = bool(raw_part.get(key))
        if role == "headers":
            header_part = part
        elif role == "body":
            body_part = part
        else:
            attachment_parts.append(part)

    parts = [part for part in (header_part, body_part) if part is not None] + attachment_parts
    unsupported = sum(part.get("extraction_status") == "unsupported" for part in attachment_parts)
    failed = sum(
        part.get("extraction_status") in {"failed", "too_large", "budget_skipped"}
        for part in attachment_parts
    )
    extracted = sum(
        part.get("extraction_status") in {"complete", "partial"}
        for part in attachment_parts
    )
    coverage_status = "partial" if unsupported or failed or any(
        part.get("extraction_status") == "partial" for part in attachment_parts
    ) else "complete"
    ledger: Dict[str, Any] = {
        "schema": EMAIL_EVIDENCE_LEDGER_SCHEMA,
        "source_type": "email",
        "source_group": "email_message",
        "transport": "client_roundtrip_sanitized",
        "parts": parts,
        "summary": {
            "header_part_count": sum(part.get("role") == "headers" for part in parts),
            "body_part_count": sum(part.get("role") == "body" for part in parts),
            "attachment_count": len(attachment_parts),
            "extracted_attachment_count": extracted,
            "unsupported_attachment_count": unsupported,
            "failed_attachment_count": failed,
            "candidate_url_count": sum(
                int((part.get("urls") or {}).get("count") or 0) for part in attachment_parts
            ),
            "candidate_qr_count": sum(
                int((part.get("qr") or {}).get("count") or 0) for part in attachment_parts
            ),
        },
        "coverage": {
            "status": coverage_status,
            "cloud_ocr_used": False,
            "attachment_limit": MAX_EMAIL_MIME_PARTS,
            "binary_scan_limit": MAX_EMAIL_BINARY_ATTACHMENT_SCANS,
        },
    }
    ledger["ledger_hash"] = _stable_hash(ledger)
    return ledger
