from __future__ import annotations

from typing import Any, Optional

from services.brand_never_asks import evaluate_brand_never_asks
from services.iban_validator import IBAN_LENGTH_BY_COUNTRY, normalize_iban, validate_iban
from services.invoice_parser import ANY_IBAN_PATTERN
from services.payment_destination_registry import match_payment_destination


def _extract_ibans(text: str) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for match in ANY_IBAN_PATTERN.finditer(text or ""):
        normalized = normalize_iban(match.group(0))
        if not normalized:
            continue
        candidates = [normalized]
        expected_len = IBAN_LENGTH_BY_COUNTRY.get(normalized[:2])
        if expected_len and len(normalized) > expected_len:
            candidates.append(normalized[:expected_len])
        for candidate in candidates:
            if candidate in seen:
                continue
            if validate_iban(candidate).valid_structure:
                seen.add(candidate)
                output.append(candidate)
                break
    return output


def evaluate_cross_scan_knowledge(
    *,
    text: str,
    claimed_brand: Optional[str] = None,
    cui: Optional[str] = None,
    source_channel: Optional[str] = None,
    fraud_flags: Optional[list[str]] = None,
    evidence_provenance: str = "direct_input",
) -> dict[str, Any]:
    flags = list(fraud_flags or [])
    b2b_signals: dict[str, Any] = {"flags": [], "warnings": [], "metadata": {}}
    try:
        from services.b2b_invoice_signals import evaluate_b2b_invoice_signals

        b2b = evaluate_b2b_invoice_signals(text or "", claimed_vendor=claimed_brand)
        b2b_signals = {"flags": b2b.flags, "warnings": b2b.warnings, "metadata": b2b.metadata}
        for flag in b2b.flags:
            if flag not in flags:
                flags.append(flag)
    except Exception:
        pass
    payment_destinations: list[dict[str, Any]] = []
    for iban in _extract_ibans(text):
        payment = match_payment_destination(iban, claimed_brand=claimed_brand, cui=cui)
        payment["evidence_provenance"] = evidence_provenance
        if evidence_provenance == "client_roundtrip_unattested":
            # Client-returned structured values may still expose mismatches, but
            # cannot provide the positive proof required by a SAFE verdict.
            payment["can_contribute_to_safe"] = False
        payment_destinations.append(payment)
        if (
            payment.get("matched")
            and payment.get("brand_matches") is False
            and payment.get("cui_matches") is not True
        ):
            # cui_matches=True => same legal entity (CUI confirmed); not a mismatch.
            if "PAYMENT_DESTINATION_BRAND_MISMATCH" not in flags:
                flags.append("PAYMENT_DESTINATION_BRAND_MISMATCH")
        elif (
            not payment.get("matched")
            and payment.get("registry_has_brand_destinations")
            and claimed_brand
        ):
            if "UNKNOWN_PAYMENT_DESTINATION" not in flags:
                flags.append("UNKNOWN_PAYMENT_DESTINATION")

    primary_payment = next(
        (item for item in payment_destinations if item.get("matched")),
        payment_destinations[0] if payment_destinations else None,
    )
    never_asks = evaluate_brand_never_asks(
        claimed_brand=claimed_brand,
        text=text,
        source_channel=source_channel,
        fraud_flags=flags,
        payment_destination=primary_payment,
    )
    return {
        "payment_destinations": payment_destinations,
        "brand_never_asks": never_asks,
        "b2b_invoice_signals": b2b_signals,
        "fraud_flags": flags,
    }
