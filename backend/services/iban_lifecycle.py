from __future__ import annotations

from dataclasses import dataclass

from services.iban_validator import IBAN_LENGTH_BY_COUNTRY, normalize_iban, validate_iban


@dataclass(frozen=True)
class IbanCandidate:
    """A single normalized IBAN token discovered in scanned text, with its
    structural (mod-97 + length + RO bank-code) validity resolved once.

    Replaces the historical `require_valid` boolean threaded through the invoice
    orchestrator: the two distinct uses -- fragmentation *detection* (all tokens)
    vs real *payment targets* (structurally valid only) -- are now explicit,
    typed selectors over the same candidate list instead of a flag.
    """

    normalized: str
    valid_structure: bool

    @property
    def is_payment_target(self) -> bool:
        return self.valid_structure


def normalize_iban_candidates(values: list[str]) -> list[IbanCandidate]:
    """Normalize + dedup raw IBAN-ish tokens (first-seen order) and resolve each
    one's structural validity exactly once.

    Applies the same normalization, over-length truncation, and RO bank-code
    guards previously inlined in the orchestrator's _unique_ibans, so downstream
    selectors are guaranteed consistent.
    """
    seen: set[str] = set()
    out: list[IbanCandidate] = []
    for raw in values or []:
        normalized = normalize_iban(str(raw or ""))
        if not normalized or normalized in seen:
            continue
        expected_len = IBAN_LENGTH_BY_COUNTRY.get(normalized[:2])
        if expected_len and len(normalized) > expected_len:
            normalized = normalized[:expected_len]
            if normalized in seen:
                continue
        if normalized.startswith("RO") and len(normalized) >= 8 and not normalized[4:8].isalpha():
            continue
        seen.add(normalized)
        out.append(
            IbanCandidate(normalized=normalized, valid_structure=validate_iban(normalized).valid_structure)
        )
    return out


def payment_target_ibans(values: list[str]) -> list[str]:
    """Structurally valid IBANs only -- safe to treat as real payment targets
    (feeds fields.all_ibans, MULTIPLE_IBANS, payment-destination matching).
    Equivalent to the old _unique_ibans(..., require_valid=True)."""
    return [c.normalized for c in normalize_iban_candidates(values) if c.valid_structure]


def detection_candidate_ibans(values: list[str]) -> list[str]:
    """All normalized IBAN-ish tokens (valid or not) -- for fragmentation
    *detection* only, never for payment targeting. An OCR artifact such as a
    client code must never reach payment_target_ibans. Equivalent to the old
    _unique_ibans(..., require_valid=False)."""
    return [c.normalized for c in normalize_iban_candidates(values)]
