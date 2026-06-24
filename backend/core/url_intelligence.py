from __future__ import annotations

import base64
import html
import ipaddress
import logging
import os
import re
import urllib.parse
import tldextract
from typing import Any, Dict, List, Optional

from core.text_utils import _normalise_obfuscated_text

logger = logging.getLogger("main")

PLAIN_URL_NOISE_LABELS = {
    "dvs",
    "eu",
    "rog",
}

TRACKING_QUERY_PARAMS = {
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "utm_id",
    "utm_referrer",
    "gclid",
    "fbclid",
    "mc_eid",
}

MAX_TEXT_CHARS = int(os.getenv("MAX_TEXT_CHARS", "12000"))
MAX_URLS_PER_SCAN = int(os.getenv("MAX_URLS_PER_SCAN", "15"))

URL_REGEX = re.compile(
    r"(?:(?:https?://)|www\.|(?:[a-zA-Z0-9][a-zA-Z0-9+.-]*\.[a-zA-Z]{2,}))"
    r"[a-zA-Z0-9-._~:/?#\[\]@!$&'()*+,;=%]*",
    re.IGNORECASE,
)
NON_HTTP_DEEPLINK_REGEX = re.compile(
    r"\b([a-zA-Z][a-zA-Z0-9+.-]{1,31})://[^\s<>()\"']+",
    re.IGNORECASE,
)
DATA_URL_REGEX = re.compile(
    r"\bdata:(?P<mime>text/html|text/plain|application/xhtml\+xml)[^,\s<>()\"']*,(?P<body>[^\s<>()\"']{8,8192})",
    re.IGNORECASE,
)
_PDF_URI_LITERAL_RE = re.compile(rb"/URI\s*\(((?:\\.|[^\\)]){0,8192})\)", re.IGNORECASE | re.DOTALL)
_PDF_URI_HEX_RE = re.compile(rb"/URI\s*<([0-9A-Fa-f\s]{6,16384})>", re.IGNORECASE)


def _is_allowed_origin(url: str) -> bool:
    try:
        parsed = urllib.parse.urlparse(url)
    except ValueError:
        return False
    scheme = (parsed.scheme or "").lower()
    if scheme not in {"http", "https"}:
        return False
    if not parsed.hostname:
        return False
    return True


def _dedupe_preserve_order(values: List[str]) -> List[str]:
    seen = set()
    output: List[str] = []
    for value in values:
        if not value:
            continue
        if value in seen:
            continue
        seen.add(value)
        output.append(value)
    return output


def _is_noise_plain_url(raw_url: str, host: str) -> bool:
    normalized_raw = (raw_url or "").strip().lower()
    normalized_host = (host or "").lower()

    if not normalized_raw:
        return True

    if normalized_raw.startswith(("http://", "https://", "www.")):
        return False

    first_label = normalized_host.split(".")[0]
    if first_label in PLAIN_URL_NOISE_LABELS:
        return True

    return False


def _canonicalize_url(raw_url: str) -> Optional[str]:
    if not raw_url:
        return None

    cleaned = raw_url.strip().strip(") ]}>;,:.!?")
    if cleaned.startswith("//"):
        cleaned = f"https:{cleaned}"
    if not cleaned:
        return None

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", cleaned):
        cleaned = f"https://{cleaned}"

    try:
        parsed = urllib.parse.urlparse(cleaned)
    except ValueError:
        return None
    if not _is_allowed_origin(cleaned):
        return None

    query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    filtered_query = [
        (key, value)
        for key, value in query_pairs
        if (key or "").lower() not in TRACKING_QUERY_PARAMS
    ]

    normalized_path = parsed.path or ""
    if not normalized_path:
        normalized_path = "/"
    normalized = parsed._replace(
        query=urllib.parse.urlencode(filtered_query, doseq=True),
        fragment="",
        path=normalized_path.rstrip("/") or "/",
    )
    return urllib.parse.urlunparse(normalized)


def extract_urls(text: str) -> List[str]:
    normalized_text = _normalise_obfuscated_text(text or "")
    normalized_text = re.sub(r"(?<!\s)(https?://|www\.)", r" \1", normalized_text, flags=re.IGNORECASE)
    raw_urls = URL_REGEX.findall(normalized_text)
    urls: List[str] = []
    seen = set()

    def append_url(raw_url: str) -> None:
        if len(urls) >= MAX_URLS_PER_SCAN:
            return
        url = _canonicalize_url(raw_url)
        if not url or not _is_allowed_origin(url):
            return
        parsed = urllib.parse.urlparse(url)
        host = (parsed.hostname or "").lower()
        if not host or _is_noise_plain_url(raw_url, host):
            return
        try:
            ipaddress.ip_address(host)
        except Exception:
            tld_suffix = tldextract.extract(host).suffix
            has_explicit_scheme = bool(re.match(r"^https?://", str(raw_url).strip(), re.IGNORECASE))
            if not tld_suffix and not has_explicit_scheme:
                logger.debug("Skipping extracted token without valid public suffix: %s", host)
                return
        if url not in seen:
            seen.add(url)
            urls.append(url)

    def decoded_variants(value: str) -> List[str]:
        variants: List[str] = []
        current = html.unescape(str(value or ""))
        for _ in range(3):
            decoded = urllib.parse.unquote(current)
            if decoded == current:
                break
            current = decoded
            if current not in variants:
                variants.append(current)
        return variants

    for raw_url in raw_urls:
        append_url(raw_url)
        if len(urls) >= MAX_URLS_PER_SCAN:
            break
        canonical = _canonicalize_url(raw_url)
        if not canonical:
            continue
        parsed = urllib.parse.urlparse(canonical)
        query_values = [value for _, value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)]
        fragment_values = [parsed.fragment] if parsed.fragment else []
        for value in query_values + fragment_values:
            for decoded in decoded_variants(value):
                for embedded in URL_REGEX.findall(decoded):
                    append_url(embedded)
                    if len(urls) >= MAX_URLS_PER_SCAN:
                        break
                if len(urls) >= MAX_URLS_PER_SCAN:
                    break
            if len(urls) >= MAX_URLS_PER_SCAN:
                break
    return _dedupe_preserve_order(urls)


def _non_http_deeplink_context(text: str) -> Dict[str, Any]:
    normalized_text = text or ""
    schemes: List[str] = []
    seen = set()
    for match in NON_HTTP_DEEPLINK_REGEX.finditer(normalized_text):
        scheme = str(match.group(1) or "").strip().lower()
        if scheme in {"http", "https"} or not scheme:
            continue
        if scheme not in seen:
            seen.add(scheme)
            schemes.append(scheme)
        if len(schemes) >= MAX_URLS_PER_SCAN:
            break
    if DATA_URL_REGEX.search(normalized_text) and "data" not in seen:
        seen.add("data")
        schemes.append("data")
    return {
        "present": bool(schemes),
        "count": len(schemes),
        "schemes": schemes,
        "preview_supported": False,
    }


def _decoded_data_url_text(raw_text: str) -> str:
    decoded_parts: List[str] = []
    for match in DATA_URL_REGEX.finditer(raw_text or ""):
        whole = match.group(0) or ""
        body = match.group("body") or ""
        try:
            if ";base64" in whole[:80].lower():
                padded = body + ("=" * (-len(body) % 4))
                raw = base64.b64decode(padded, validate=False)
            else:
                raw = urllib.parse.unquote_to_bytes(body)
            decoded = raw[:8192].decode("utf-8", errors="replace")
        except Exception:
            continue
        if decoded:
            decoded_parts.append(decoded)
    return "\n".join(decoded_parts)


def _data_url_contains_sensitive_form(raw_text: str) -> bool:
    decoded = _decoded_data_url_text(raw_text)
    if not decoded:
        return False
    normalized = decoded.lower()
    return bool(
        re.search(r"<\s*form\b|<\s*input\b|action\s*=", normalized, re.IGNORECASE)
        and re.search(r"\b(login|auth|password|parol[ăa]|otp|cod|card|cvv|cvc|user|utilizator)\b", normalized, re.IGNORECASE)
    )


def _decode_pdf_string_bytes(value: bytes) -> str:
    if not value:
        return ""

    if value.startswith(b"\xfe\xff"):
        return value[2:].decode("utf-16-be", errors="replace")
    if value.startswith(b"\xff\xfe"):
        return value[2:].decode("utf-16-le", errors="replace")
    return value.decode("utf-8", errors="replace")


def _decode_pdf_literal_string(value: bytes) -> str:
    output = bytearray()
    index = 0
    while index < len(value):
        current = value[index]
        if current != 0x5C:
            output.append(current)
            index += 1
            continue

        index += 1
        if index >= len(value):
            break
        escaped = value[index]
        index += 1

        if escaped in b"nrtbf":
            output.append({ord("n"): 10, ord("r"): 13, ord("t"): 9, ord("b"): 8, ord("f"): 12}[escaped])
            continue
        if escaped in b"\\()":
            output.append(escaped)
            continue
        if escaped in b"\r\n":
            if escaped == 13 and index < len(value) and value[index] == 10:
                index += 1
            continue
        if 48 <= escaped <= 55:
            octal = bytes([escaped])
            for _ in range(2):
                if index < len(value) and 48 <= value[index] <= 55:
                    octal += bytes([value[index]])
                    index += 1
                else:
                    break
            output.append(int(octal, 8) & 0xFF)
            continue
        output.append(escaped)

    return _decode_pdf_string_bytes(bytes(output))


def _urls_from_pdf_uri_text(value: str) -> List[str]:
    decoded = html.unescape(urllib.parse.unquote((value or "").strip()))
    variants = [decoded]
    collapsed = re.sub(r"\s+", "", decoded)
    if collapsed and collapsed != decoded:
        variants.append(collapsed)

    urls: List[str] = []
    for variant in variants:
        canonical = _canonicalize_url(variant)
        if canonical:
            urls.append(canonical)
            continue
        urls.extend(extract_urls(variant))
    return _dedupe_preserve_order(urls)


def _extract_pdf_annotation_links(pdf_bytes: bytes) -> List[str]:
    if not pdf_bytes:
        return []

    urls: List[str] = []
    for match in _PDF_URI_LITERAL_RE.finditer(pdf_bytes):
        urls.extend(_urls_from_pdf_uri_text(_decode_pdf_literal_string(match.group(1))))
        if len(urls) >= MAX_URLS_PER_SCAN:
            break

    if len(urls) < MAX_URLS_PER_SCAN:
        for match in _PDF_URI_HEX_RE.finditer(pdf_bytes):
            try:
                hex_value = re.sub(rb"\s+", b"", match.group(1))
                if len(hex_value) % 2:
                    hex_value += b"0"
                decoded_hex = _decode_pdf_string_bytes(bytes.fromhex(hex_value.decode("ascii")))
                urls.extend(_urls_from_pdf_uri_text(decoded_hex))
            except Exception:
                continue
            if len(urls) >= MAX_URLS_PER_SCAN:
                break

    return _dedupe_preserve_order(urls)[:MAX_URLS_PER_SCAN]


def _extract_pdf_embedded_text(pdf_bytes: bytes, *, max_chars: int = MAX_TEXT_CHARS) -> str:
    if not pdf_bytes:
        return ""
    try:
        from io import BytesIO

        from pypdf import PdfReader

        reader = PdfReader(BytesIO(pdf_bytes))
        parts: list[str] = []
        for page in reader.pages[:10]:
            text = page.extract_text() or ""
            if text.strip():
                parts.append(text.strip())
            if sum(len(part) for part in parts) >= max_chars:
                break
        return "\n".join(parts)[:max_chars].strip()
    except Exception as exc:
        logger.info("PDF embedded text extraction failed: %s", exc)
        return ""


def _decode_qr_payloads_from_pil_images(images: List[Any], *, max_payloads: int = MAX_URLS_PER_SCAN) -> List[str]:
    if not images:
        return []
    try:
        import zxingcpp  # type: ignore
    except Exception:
        return []

    payloads: List[str] = []
    for image in images:
        try:
            decoded = zxingcpp.read_barcodes(image)
        except Exception as exc:
            logger.info("QR/barcode decode failed: %s", exc)
            continue
        for item in decoded or []:
            text = str(getattr(item, "text", "") or "").strip()
            if text and text not in payloads:
                payloads.append(text)
            if len(payloads) >= max_payloads:
                return payloads
    return payloads


def _extract_image_qr_payloads(image_bytes: bytes, *, max_payloads: int = MAX_URLS_PER_SCAN) -> List[str]:
    if not image_bytes:
        return []
    try:
        from io import BytesIO

        from PIL import Image

        with Image.open(BytesIO(image_bytes)) as image:
            image.load()
            return _decode_qr_payloads_from_pil_images([image], max_payloads=max_payloads)
    except Exception as exc:
        logger.info("Image QR extraction failed: %s", exc)
        return []


def _extract_pdf_qr_payloads(pdf_bytes: bytes, *, max_payloads: int = MAX_URLS_PER_SCAN) -> List[str]:
    if not pdf_bytes:
        return []
    try:
        from io import BytesIO

        from pypdf import PdfReader

        reader = PdfReader(BytesIO(pdf_bytes))
        images: List[Any] = []
        for page in reader.pages[:5]:
            for image_file in list(page.images)[:20]:
                image = getattr(image_file, "image", None)
                if image is not None:
                    images.append(image)
                    continue
                data = getattr(image_file, "data", None)
                if data:
                    try:
                        from PIL import Image

                        images.append(Image.open(BytesIO(data)))
                    except Exception:
                        continue
                if len(images) >= 20:
                    break
            if len(images) >= 20:
                break
        return _decode_qr_payloads_from_pil_images(images, max_payloads=max_payloads)
    except Exception as exc:
        logger.info("PDF QR extraction failed: %s", exc)
        return []


def _merge_ocr_and_embedded_text(ocr_text: str, embedded_text: str) -> str:
    ocr = (ocr_text or "").strip()
    embedded = (embedded_text or "").strip()
    if not embedded:
        return ocr
    if not ocr:
        return embedded
    if embedded in ocr:
        return ocr
    if ocr in embedded:
        return embedded
    return f"{ocr}\n\n--- PDF embedded text ---\n{embedded}"


def _normalize_sanb_attestation(value: Optional[str]) -> Optional[str]:
    normalized = str(value or "").strip().lower()
    if not normalized:
        return None
    aliases = {
        "matches": "match",
        "matched": "match",
        "same": "match",
        "close": "close_match",
        "close-match": "close_match",
        "close match": "close_match",
        "similar": "close_match",
        "mismatch": "no_match",
        "no-match": "no_match",
        "no match": "no_match",
        "different": "no_match",
        "not-shown": "not_shown",
        "not shown": "not_shown",
        "not_displayed": "not_shown",
        "unavailable": "not_shown",
    }
    normalized = aliases.get(normalized, normalized)
    if normalized not in {"match", "close_match", "no_match", "not_shown"}:
        from fastapi import HTTPException

        raise HTTPException(status_code=400, detail="Răspuns SANB invalid.")
    return normalized
