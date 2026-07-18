"""Privacy-safe evidence extracted before OCR text redaction.

The structured contract preserves payment and sensitive-asset presence for
downstream analysis without persisting the raw OCR transcript or secret values.
Client round-trips are treated as untrusted input and rebuilt field by field.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Mapping, Optional

from services.external_url_privacy import sanitize_external_text
from services.iban_validator import normalize_iban, validate_iban
from services.invoice_parser import CUI_PATTERN, parse_invoice
from services.pii_redactor import CARD_REGEX, CNP_REGEX, EMAIL_REGEX, OTP_REGEX, PHONE_REGEX


PRE_REDACTION_EVIDENCE_SCHEMA = "sigurscan_pre_redaction_evidence_v1"
MAX_IDENTIFIER_ITEMS = 12
MAX_BENEFICIARY_CHARS = 160


def _dedupe(values: list[str]) -> list[str]:
    output: list[str] = []
    for value in values:
        if value and value not in output:
            output.append(value)
    return output[:MAX_IDENTIFIER_ITEMS]


def _iban_entry(raw: Any) -> Optional[Dict[str, Any]]:
    normalized = normalize_iban(str(raw or ""))
    if not normalized:
        return None
    result = validate_iban(normalized)
    if not result.valid_structure:
        return None
    return {
        "value": normalized,
        "country_code": normalized[:2],
        "bank_code": result.bank_code,
        "last4": normalized[-4:],
        "valid_structure": True,
    }


def _clean_cui(raw: Any) -> Optional[str]:
    digits = "".join(ch for ch in str(raw or "") if ch.isdigit())
    if 2 <= len(digits) <= 10:
        return digits
    return None


def _clean_beneficiary(raw: Any) -> Optional[str]:
    value = re.sub(r"\s+", " ", sanitize_external_text(raw)).strip(" .,:;-\t\r\n")
    if len(value) < 3:
        return None
    return value[:MAX_BENEFICIARY_CHARS]


def _passes_luhn(value: str) -> bool:
    digits = [int(ch) for ch in value if ch.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def _has_valid_card_number(text: str) -> bool:
    # A labelled CNP is also a 13-digit sequence and must not become card
    # evidence. Card presence is intentionally checksum-backed so invoice IDs
    # and other long numeric references do not create a sensitive-asset claim.
    without_cnp = CNP_REGEX.sub("", text)
    return any(_passes_luhn(match.group(0)) for match in CARD_REGEX.finditer(without_cnp))


def extract_pre_redaction_evidence(raw_text: str) -> Dict[str, Any]:
    """Extract canonical evidence while the raw OCR text exists in memory."""

    text = str(raw_text or "")
    fields = parse_invoice(text)
    iban_values = _dedupe(list(fields.all_ibans or []) + ([fields.iban] if fields.iban else []))
    ibans = [entry for value in iban_values if (entry := _iban_entry(value)) is not None]

    cui_values: list[str] = []
    if fields.cui:
        cui_values.append(fields.cui)
    for match in CUI_PATTERN.finditer(text):
        candidate = _clean_cui(match.group("label") or match.group("bare"))
        if candidate:
            cui_values.append(candidate)

    return {
        "schema": PRE_REDACTION_EVIDENCE_SCHEMA,
        "transport": "server_extracted",
        "identifiers": {
            "ibans": ibans[:MAX_IDENTIFIER_ITEMS],
            "cuis": _dedupe([value for value in (_clean_cui(item) for item in cui_values) if value]),
            "phone_count": min(sum(1 for _ in PHONE_REGEX.finditer(text)), MAX_IDENTIFIER_ITEMS),
            "email_count": min(sum(1 for _ in EMAIL_REGEX.finditer(text)), MAX_IDENTIFIER_ITEMS),
        },
        "payment": {
            "beneficiary": _clean_beneficiary(fields.payment_beneficiary),
        },
        "sensitive_assets": {
            "otp": bool(OTP_REGEX.search(text)),
            "card": _has_valid_card_number(text),
            "cnp": bool(CNP_REGEX.search(text)),
            "phone": bool(PHONE_REGEX.search(text)),
            "email": bool(EMAIL_REGEX.search(text)),
        },
        "raw_text_persisted": False,
    }


def sanitize_pre_redaction_evidence(
    candidate: Any,
    *,
    transport: str = "client_roundtrip_sanitized",
) -> Optional[Dict[str, Any]]:
    """Rebuild the contract without accepting arbitrary client-provided keys."""

    if not isinstance(candidate, Mapping):
        return None
    identifiers = candidate.get("identifiers")
    identifiers = identifiers if isinstance(identifiers, Mapping) else {}

    raw_ibans = identifiers.get("ibans")
    raw_ibans = raw_ibans if isinstance(raw_ibans, list) else []
    ibans: list[Dict[str, Any]] = []
    seen_ibans: set[str] = set()
    for raw in raw_ibans[:MAX_IDENTIFIER_ITEMS]:
        value = raw.get("value") if isinstance(raw, Mapping) else raw
        entry = _iban_entry(value)
        if entry and entry["value"] not in seen_ibans:
            seen_ibans.add(entry["value"])
            ibans.append(entry)

    raw_cuis = identifiers.get("cuis")
    raw_cuis = raw_cuis if isinstance(raw_cuis, list) else []
    cuis = _dedupe([value for raw in raw_cuis if (value := _clean_cui(raw))])

    def bounded_count(key: str) -> int:
        value = identifiers.get(key)
        if isinstance(value, bool):
            return 0
        if isinstance(value, (int, float)):
            return max(0, min(int(value), MAX_IDENTIFIER_ITEMS))
        return 0

    payment = candidate.get("payment")
    payment = payment if isinstance(payment, Mapping) else {}
    beneficiary = _clean_beneficiary(payment.get("beneficiary"))
    assets = candidate.get("sensitive_assets")
    assets = assets if isinstance(assets, Mapping) else {}

    return {
        "schema": PRE_REDACTION_EVIDENCE_SCHEMA,
        "transport": "server_extracted" if transport == "server_extracted" else "client_roundtrip_sanitized",
        "identifiers": {
            "ibans": ibans,
            "cuis": cuis,
            "phone_count": bounded_count("phone_count"),
            "email_count": bounded_count("email_count"),
        },
        "payment": {"beneficiary": beneficiary} if beneficiary else {},
        "sensitive_assets": {
            key: assets.get(key) is True
            for key in ("otp", "card", "cnp", "phone", "email")
        },
        "raw_text_persisted": False,
    }


def pre_redaction_context_text(evidence: Any) -> str:
    """Build an ephemeral parser input from structured values, never raw OCR."""

    sanitized = sanitize_pre_redaction_evidence(evidence)
    if not sanitized:
        return ""
    identifiers = sanitized["identifiers"]
    payment = sanitized.get("payment") or {}
    parts = [f"IBAN {item['value']}" for item in identifiers.get("ibans", [])]
    parts.extend(f"CUI {value}" for value in identifiers.get("cuis", []))
    if payment.get("beneficiary"):
        parts.append(f"Beneficiar plata: {payment['beneficiary']}")
    return "\n".join(parts)


def pre_redaction_primary_cui(evidence: Any) -> Optional[str]:
    sanitized = sanitize_pre_redaction_evidence(evidence)
    if not sanitized:
        return None
    cuis = sanitized["identifiers"].get("cuis") or []
    return str(cuis[0]) if cuis else None


def pre_redaction_summary(evidence: Any) -> Dict[str, Any]:
    """Return the non-identifying summary safe for ArtifactEnvelope."""

    sanitized = sanitize_pre_redaction_evidence(evidence)
    if not sanitized:
        return {"present": False}
    identifiers = sanitized["identifiers"]
    assets = sanitized["sensitive_assets"]
    return {
        "present": True,
        "schema": PRE_REDACTION_EVIDENCE_SCHEMA,
        "iban_count": len(identifiers.get("ibans") or []),
        "cui_count": len(identifiers.get("cuis") or []),
        "phone_count": int(identifiers.get("phone_count") or 0),
        "email_count": int(identifiers.get("email_count") or 0),
        "beneficiary_present": bool((sanitized.get("payment") or {}).get("beneficiary")),
        "sensitive_asset_types": sorted(key for key, present in assets.items() if present),
        "raw_text_persisted": False,
    }
