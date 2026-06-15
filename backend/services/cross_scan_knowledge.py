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
) -> dict[str, Any]:
    flags = list(fraud_flags or [])
    payment_destinations: list[dict[str, Any]] = []
    for iban in _extract_ibans(text):
        payment = match_payment_destination(iban, claimed_brand=claimed_brand, cui=cui)
        payment_destinations.append(payment)
        if payment.get("matched") and payment.get("brand_matches") is False:
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
        "fraud_flags": flags,
    }
