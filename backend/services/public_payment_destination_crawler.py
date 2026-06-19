from __future__ import annotations

import hashlib
import io
import json
import re
import zipfile
from datetime import date, datetime, timezone
from xml.etree import ElementTree
from typing import Any, Callable, Iterable

import requests
from bs4 import BeautifulSoup
from pypdf import PdfReader

from services.iban_validator import normalize_iban, validate_iban
from services.invoice_parser import parse_invoice


ACTIVE_SAFE_TIERS = {"T0_PARTNER_SIGNED", "T1_PUBLIC_OFFICIAL", "T2_OFFICIAL_DOCUMENT_CHAIN"}
DEFAULT_TIMEOUT_SECONDS = 12
MAX_RESPONSE_BYTES = 4_000_000


def _norm_cui(value: Any) -> str | None:
    digits = "".join(ch for ch in str(value or "") if ch.isdigit())
    return digits or None


def _slug(value: Any) -> str:
    raw = str(value or "").strip().lower()
    raw = (
        raw.replace("ă", "a")
        .replace("â", "a")
        .replace("î", "i")
        .replace("ș", "s")
        .replace("ş", "s")
        .replace("ț", "t")
        .replace("ţ", "t")
    )
    raw = re.sub(r"[^a-z0-9]+", "_", raw).strip("_")
    return raw[:80] or "unknown_source"


def mask_iban_for_client(iban: str) -> str:
    normalized = normalize_iban(iban or "") or ""
    if len(normalized) < 12:
        return normalized
    return f"{normalized[:4]} {normalized[4:8]} **** **** **** {normalized[-4:]}"


def _source_ref(source: dict[str, Any]) -> dict[str, Any]:
    return {
        "url": str(source.get("url") or ""),
        "publisher": str(source.get("publisher") or source.get("display_name") or source.get("legal_name") or ""),
        "accessed_at": str(source.get("accessed_at") or date.today().isoformat()),
        "confidence": str(source.get("source_confidence") or source.get("confidence") or "medium"),
        "source_lines": str(source.get("source_lines") or "Crawler extracted IBAN/CUI from public source."),
    }


def _candidate_key(candidate: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(candidate.get("iban_normalized") or ""),
        str(candidate.get("brand_id") or ""),
        str((candidate.get("source_refs") or [{}])[0].get("url") or ""),
    )


def _is_masked_iban(raw: str) -> bool:
    normalized = str(raw or "").upper().replace(" ", "").replace("-", "")
    return "XX" in normalized or "*" in normalized or "…" in normalized


def _source_identity(source: dict[str, Any], parsed_emitent: str | None) -> dict[str, Any]:
    display_name = (
        source.get("display_name")
        or source.get("legal_name")
        or parsed_emitent
        or source.get("publisher")
        or source.get("url")
    )
    legal_name = source.get("legal_name") or display_name or parsed_emitent
    brand_id = source.get("brand_id") or _slug(display_name)
    return {
        "brand_id": str(brand_id),
        "display_name": str(display_name or brand_id),
        "legal_name": str(legal_name or display_name or brand_id),
    }


def extract_candidates_from_text(text: str, source: dict[str, Any]) -> list[dict[str, Any]]:
    parsed = parse_invoice(text or "")
    source_cui = _norm_cui(source.get("cui"))
    parsed_cui = _norm_cui(parsed.cui)
    cui = source_cui or parsed_cui
    cui_conflict = bool(source_cui and parsed_cui and source_cui != parsed_cui)
    identity = _source_identity(source, parsed.emitent)
    source_kind = str(source.get("source_kind") or "public_webpage")
    trust_tier = str(source.get("trust_tier") or "T4_STRUCTURALLY_VALID_UNKNOWN")
    source_confidence = str(source.get("confidence") or ("high" if source_kind == "official_webpage" else "medium"))
    allow_safe = bool(source.get("allow_safe_contribution"))

    candidates: list[dict[str, Any]] = []
    seen_ibans: set[str] = set()
    for raw_iban in parsed.all_ibans:
        if _is_masked_iban(raw_iban):
            continue
        normalized = normalize_iban(raw_iban or "")
        if not normalized or normalized in seen_ibans:
            continue
        iban_result = validate_iban(normalized)
        if not iban_result.valid_structure:
            continue
        seen_ibans.add(normalized)

        high_confidence = source_confidence == "high" and not cui_conflict
        can_contribute = bool(
            allow_safe
            and high_confidence
            and trust_tier in ACTIVE_SAFE_TIERS
            and source_kind in {"official_webpage", "official_pdf", "partner_signed_feed"}
            and cui
        )
        candidates.append(
            {
                **identity,
                "cui": cui,
                "issuer_name_extracted": parsed.emitent,
                "payment_beneficiary_extracted": parsed.payment_beneficiary,
                "iban_normalized": normalized,
                "iban_display_official": " ".join(normalized[i : i + 4] for i in range(0, len(normalized), 4)),
                "iban_masked_for_client": mask_iban_for_client(normalized),
                "bank_code": iban_result.bank_code,
                "bank_name": iban_result.bank_name,
                "is_trezorerie": iban_result.is_trezorerie,
                "source_kind": source_kind,
                "scope": str(source.get("scope") or "payment_destination_public_source"),
                "trust_tier": trust_tier,
                "confidence": source_confidence if not cui_conflict else "low",
                "review_status": "active" if can_contribute else "needs_review",
                "can_contribute_to_safe": can_contribute,
                "client_distribution_allowed": False,
                "match_policy": "exact_hmac_match_required",
                "hashing_required": True,
                "cui_conflict": cui_conflict,
                "source_refs": [_source_ref(source)],
            }
        )
    return candidates


def _json_text(payload: Any) -> str:
    if isinstance(payload, dict):
        parts: list[str] = []
        for value in payload.values():
            text = _json_text(value)
            if text:
                parts.append(text)
        return "\n".join(parts)
    if isinstance(payload, list):
        return "\n".join(_json_text(item) for item in payload)
    if isinstance(payload, (str, int, float)):
        return str(payload)
    return ""


def _xlsx_text(content: bytes) -> str:
    # Minimal XLSX reader for public-data spreadsheets. It is intentionally
    # dependency-light and extracts cell text only, enough for CUI/IBAN discovery.
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            shared_strings: list[str] = []
            if "xl/sharedStrings.xml" in archive.namelist():
                root = ElementTree.fromstring(archive.read("xl/sharedStrings.xml"))
                for item in root.iter():
                    if item.tag.endswith("}t") or item.tag == "t":
                        if item.text:
                            shared_strings.append(item.text)
            parts: list[str] = []
            for name in sorted(archive.namelist()):
                if not name.startswith("xl/worksheets/") or not name.endswith(".xml"):
                    continue
                root = ElementTree.fromstring(archive.read(name))
                for cell in root.iter():
                    if not (cell.tag.endswith("}c") or cell.tag == "c"):
                        continue
                    cell_type = cell.attrib.get("t")
                    value = None
                    for child in cell:
                        if child.tag.endswith("}v") or child.tag == "v":
                            value = child.text
                            break
                    if value is None:
                        continue
                    if cell_type == "s":
                        try:
                            value = shared_strings[int(value)]
                        except (ValueError, IndexError):
                            pass
                    parts.append(str(value))
            return "\n".join(parts)
    except Exception:
        return ""


def extract_text_from_response(content: bytes, *, content_type: str = "", url: str = "") -> str:
    content_type = (content_type or "").lower()
    if len(content or b"") > MAX_RESPONSE_BYTES:
        content = content[:MAX_RESPONSE_BYTES]
    if "pdf" in content_type or str(url).lower().endswith(".pdf"):
        reader = PdfReader(io.BytesIO(content))
        return "\n".join(page.extract_text() or "" for page in reader.pages)
    if (
        "spreadsheetml" in content_type
        or str(url).lower().endswith(".xlsx")
        or str(url).lower().endswith(".xlsm")
    ):
        return _xlsx_text(content)
    raw = content.decode("utf-8", errors="replace")
    if "json" in content_type or str(url).lower().endswith(".json"):
        try:
            return _json_text(json.loads(raw))
        except json.JSONDecodeError:
            return raw
    if "html" in content_type or "<html" in raw[:500].lower():
        soup = BeautifulSoup(raw, "html.parser")
        for node in soup(["script", "style", "noscript"]):
            node.decompose()
        title = soup.title.get_text(" ", strip=True) if soup.title else ""
        return "\n".join(part for part in (title, soup.get_text("\n", strip=True)) if part)
    return raw


def _discover_resource_sources(content: bytes, source: dict[str, Any], *, content_type: str = "") -> list[dict[str, Any]]:
    if not source.get("discover_resources"):
        return []
    raw = content.decode("utf-8", errors="replace")
    if "json" not in (content_type or "").lower() and not raw.lstrip().startswith("{"):
        return []
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return []
    resources = (((payload.get("result") or {}) if isinstance(payload, dict) else {}).get("resources") or [])
    if not isinstance(resources, list):
        return []
    max_resources = int(source.get("max_resource_urls") or 10)
    children: list[dict[str, Any]] = []
    for resource in resources[:max_resources]:
        if not isinstance(resource, dict):
            continue
        url = str(resource.get("url") or "").strip()
        if not url.startswith(("http://", "https://")):
            continue
        child = dict(source)
        child["url"] = url
        child["publisher"] = str(resource.get("name") or resource.get("description") or source.get("publisher") or "")
        child["source_kind"] = source.get("resource_source_kind") or "public_dataset_resource"
        child["discover_resources"] = False
        child["source_lines"] = f"Discovered from dataset catalog {source.get('url')}"
        children.append(child)
    return children


def _request_headers(source: dict[str, Any]) -> dict[str, str]:
    url = str(source.get("url") or "")
    wants_json = source.get("source_kind") == "public_dataset_catalog" or "/api/3/action/" in url
    accept = (
        "application/json,text/plain;q=0.9,*/*;q=0.2"
        if wants_json
        else "text/html,application/pdf,application/json,text/plain;q=0.9,*/*;q=0.2"
    )
    return {
        "User-Agent": str(source.get("user_agent") or "Mozilla/5.0"),
        "Accept": accept,
    }


def crawl_public_payment_sources(
    sources: Iterable[dict[str, Any]],
    *,
    fetcher: Callable[..., Any] | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    fetch = fetcher or requests.get
    candidates: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    sources_read = 0

    queue = list(sources)
    while queue:
        if limit is not None and sources_read >= limit:
            break
        source = queue.pop(0)
        url = str(source.get("url") or "").strip()
        if not url:
            continue
        sources_read += 1
        try:
            response = fetch(
                url,
                timeout=float(source.get("timeout_seconds") or DEFAULT_TIMEOUT_SECONDS),
                headers=_request_headers(source),
            )
            status_code = int(getattr(response, "status_code", 0) or 0)
            if status_code >= 400:
                errors.append({"url": url, "error": f"http_{status_code}"})
                continue
            headers = getattr(response, "headers", {}) or {}
            content_type = headers.get("content-type") or headers.get("Content-Type") or ""
            content = getattr(response, "content", b"")
            if not content and getattr(response, "text", ""):
                content = str(response.text).encode("utf-8")
            queue.extend(_discover_resource_sources(content, source, content_type=content_type))
            text = extract_text_from_response(content, content_type=content_type, url=url)
            candidates.extend(extract_candidates_from_text(text, source))
        except Exception as exc:  # pragma: no cover - defensive for live crawls
            errors.append({"url": url, "error": type(exc).__name__, "message": str(exc)[:300]})

    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for candidate in candidates:
        key = _candidate_key(candidate)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(candidate)

    return {
        "summary": {
            "sources_read": sources_read,
            "candidates": len(deduped),
            "errors": len(errors),
        },
        "candidates": deduped,
        "errors": errors,
    }


def build_payment_destination_registry_delta(
    candidates: list[dict[str, Any]],
    *,
    version: str | None = None,
) -> dict[str, Any]:
    generated_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    grouped: dict[str, dict[str, Any]] = {}
    for candidate in candidates:
        brand_id = str(candidate.get("brand_id") or _slug(candidate.get("display_name")))
        entry = grouped.setdefault(
            brand_id,
            {
                "brand_id": brand_id,
                "display_name": candidate.get("display_name"),
                "legal_name": candidate.get("legal_name"),
                "cui": candidate.get("cui"),
                "category": "public_payment_destination_corpus",
                "payment_destinations": [],
            },
        )
        destination = {
            "kind": "iban",
            "trust_tier": candidate.get("trust_tier"),
            "source_kind": candidate.get("source_kind"),
            "scope": candidate.get("scope"),
            "confidence": candidate.get("confidence"),
            "review_status": candidate.get("review_status"),
            "client_distribution_allowed": False,
            "hashing_required": True,
            "match_policy": "exact_hmac_match_required",
            "can_contribute_to_safe": bool(candidate.get("can_contribute_to_safe")),
            "bank_name": candidate.get("bank_name"),
            "source_refs": candidate.get("source_refs") or [],
            "iban_normalized_backend_seed_only": candidate.get("iban_normalized"),
            "iban_display_official": candidate.get("iban_display_official"),
            "iban_masked_for_client": candidate.get("iban_masked_for_client"),
            "crawler_candidate_id": hashlib.sha256(
                f"{candidate.get('iban_normalized')}|{brand_id}|{(candidate.get('source_refs') or [{}])[0].get('url')}".encode("utf-8")
            ).hexdigest()[:16],
        }
        entry["payment_destinations"].append(destination)

    return {
        "version": version or f"pdr-public-crawl-{date.today().isoformat()}",
        "generated_at": generated_at,
        "purpose": (
            "Crawler-generated public payment destination candidates. Backend-only; "
            "review_status=needs_review cannot contribute to SAFE."
        ),
        "rules": {
            "no_public_iban_owner_lookup": True,
            "default_review_status": "needs_review",
            "safe_requires_explicit_allow_safe_contribution": True,
        },
        "entries": list(grouped.values()),
    }
