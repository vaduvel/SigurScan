"""Cross-check the bank name printed on an invoice against the bank implied by
the payment IBAN (F2).

Rationale: on a genuine invoice the printed bank ("Banca Transilvania", "BRD",
...) matches the bank that owns the IBAN's 4-character bank identifier. When a
fraudster swaps only the IBAN (payment hijack) but leaves the printed bank name
(or vice-versa), the two disagree. This module turns that disagreement into an
explicit, conservative signal.

It is deliberately conservative: it reports MISMATCH only when BOTH the printed
name and the IBAN's bank resolve to a *known, different* Romanian bank. Anything
ambiguous returns UNKNOWN, so on its own it can never produce a false
"do not pay".

Pure and dependency-light: relies only on iban_validator, sanb_registry and the
ro_morphology text helpers.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from services.iban_validator import RO_BANK_CODES, validate_iban
from services.ro_morphology import contains_all, strip_diacritics
from services.sanb_registry import lookup_sanb_participant

# Canonical bank key -> alias phrases (lowercase, diacritic-free). Short/ambiguous
# aliases (brd, bcr, cec, ing) are matched on word boundaries only; longer
# phrases may match as substrings.
BANK_ALIASES: Dict[str, List[str]] = {
    "BANCA_TRANSILVANIA": ["banca transilvania", "transilvania"],
    "BRD": ["brd", "groupe societe generale", "societe generale"],
    "BCR": ["bcr", "banca comerciala romana"],
    "ING": ["ing bank", "ing"],
    "RAIFFEISEN": ["raiffeisen"],
    "UNICREDIT": ["unicredit"],
    "CEC": ["cec bank", "cec"],
    "ALPHA": ["alpha bank"],
    "LIBRA": ["libra internet bank", "libra"],
    "FIRST_BANK": ["first bank"],
    "SALT": ["salt bank"],
    "REVOLUT": ["revolut"],
    "TREZORERIE": ["trezoreria statului", "trezoreria", "trezorerie", "trezorer"],
    "INTESA": ["intesa sanpaolo", "intesa", "sanpaolo"],
    "GARANTI": ["garanti bbva", "garanti"],
    "EXIM": ["exim banca romaneasca", "exim"],
    "PATRIA": ["patria bank", "patria", "carpatica"],
    "PROCREDIT": ["procredit"],
    "VISTA": ["vista bank"],
    "CREDITCOOP": ["creditcoop"],
    "NEXENT": ["nexent"],
    "BRCI": ["banca romana de credite si investitii"],
    "TECHVENTURES": ["techventures"],
    "BANORIENT": ["banorient"],
}

# Aliases too short to match safely as substrings; matched on a word boundary.
_WORD_BOUNDARY_ALIASES = {"brd", "bcr", "cec", "ing"}

STATUS_MATCH = "MATCH"
STATUS_MISMATCH = "MISMATCH"
STATUS_UNKNOWN = "UNKNOWN"
STATUS_NO_DATA = "NO_DATA"

# Fraud-flag token emitted for a confirmed mismatch (soft; caller sets severity).
IBAN_BANK_NAME_MISMATCH_FLAG = "IBAN_BANK_NAME_MISMATCH"


@dataclass(frozen=True)
class BankNameCrosscheck:
    status: str
    iban_bank_code: Optional[str] = None
    iban_bank_key: Optional[str] = None
    iban_bank_name: Optional[str] = None
    printed_bank_key: Optional[str] = None
    printed_bank_name: Optional[str] = None
    reason: Optional[str] = None

    @property
    def is_mismatch(self) -> bool:
        return self.status == STATUS_MISMATCH


def _prep(text: str) -> str:
    folded = strip_diacritics(text or "").lower()
    return re.sub(r"[^0-9a-z]+", " ", folded).strip()


def detect_bank_key(text: Optional[str]) -> Optional[str]:
    """Resolve free text to a canonical bank key, or None if not identifiable."""
    prepared = _prep(text or "")
    if not prepared:
        return None
    padded = f" {prepared} "
    for key, aliases in BANK_ALIASES.items():
        for alias in aliases:
            if alias in _WORD_BOUNDARY_ALIASES:
                if re.search(rf"\b{re.escape(alias)}\b", prepared):
                    return key
            elif alias in prepared or f" {alias} " in padded:
                return key
            # P-MORPH: token-based fallback for multi-word aliases, robust to word
            # order / spacing / light inflection via ro_morphology. Restricted to
            # multi-word aliases so the short word-boundary aliases (brd/bcr/cec/
            # ing) keep their stricter rule and matching is never loosened for them.
            elif " " in alias and contains_all(prepared, alias, stem=True):
                return key
    return None


def crosscheck(printed_bank_name: Optional[str], iban: Optional[str]) -> BankNameCrosscheck:
    printed_key = detect_bank_key(printed_bank_name)
    if not iban:
        return BankNameCrosscheck(
            status=STATUS_NO_DATA,
            printed_bank_key=printed_key,
            printed_bank_name=printed_bank_name,
            reason="no_iban",
        )
    result = validate_iban(iban)
    if not result.valid_structure or result.bank_code is None:
        return BankNameCrosscheck(
            status=STATUS_NO_DATA,
            iban_bank_code=result.bank_code,
            printed_bank_key=printed_key,
            printed_bank_name=printed_bank_name,
            reason="iban_not_ro_or_invalid",
        )
    iban_name = result.bank_name or RO_BANK_CODES.get(result.bank_code)
    iban_key = detect_bank_key(iban_name)
    if iban_key is None:
        participant = lookup_sanb_participant(result.bank_code)
        if participant is not None:
            iban_key = detect_bank_key(participant.institution)
            iban_name = iban_name or participant.institution
    base = dict(
        iban_bank_code=result.bank_code,
        iban_bank_key=iban_key,
        iban_bank_name=iban_name,
        printed_bank_key=printed_key,
        printed_bank_name=printed_bank_name,
    )
    if printed_key is None:
        return BankNameCrosscheck(status=STATUS_UNKNOWN, reason="printed_bank_unrecognized", **base)
    if iban_key is None:
        return BankNameCrosscheck(status=STATUS_UNKNOWN, reason="iban_bank_unrecognized", **base)
    if printed_key == iban_key:
        return BankNameCrosscheck(status=STATUS_MATCH, reason="bank_matches_iban", **base)
    return BankNameCrosscheck(
        status=STATUS_MISMATCH,
        reason=f"printed_{printed_key}_vs_iban_{iban_key}",
        **base,
    )


def crosscheck_invoice_fields(fields: Any) -> BankNameCrosscheck:
    """Convenience wrapper for a parsed InvoiceFields-like object."""
    return crosscheck(
        getattr(fields, "printed_bank_name", None),
        getattr(fields, "iban", None),
    )


def crosscheck_fraud_flags(fields: Any) -> List[str]:
    """Return fraud-flag tokens for the invoice pipeline. Conservative: only a
    confirmed MISMATCH yields a (soft) flag; callers decide severity."""
    if crosscheck_invoice_fields(fields).is_mismatch:
        return [IBAN_BANK_NAME_MISMATCH_FLAG]
    return []
