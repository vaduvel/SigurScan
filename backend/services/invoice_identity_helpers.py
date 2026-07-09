"""R6 — invoice name/beneficiary/identity predicates.

Pure helpers extracted verbatim from invoice_orchestrator to shrink that module.
Behavior-preserving: invoice_orchestrator re-imports every name below, so both its
own call sites and external `from services.invoice_orchestrator import <name>`
imports keep working unchanged. Depends only on the shared constants module (no
import of invoice_orchestrator -> no cycle).
"""
from __future__ import annotations

import re
from typing import Optional

from services.invoice_orchestrator_constants import (
    _DIACRITICS,
    _COMPANY_MARKERS,
    _NAME_STOPWORDS,
    _GENERIC_BENEFICIARY_TERMS,
)


def _txt_norm(text: str) -> str:
    return (text or "").lower().translate(_DIACRITICS)


def _name_tokens(name: str) -> set[str]:
    cleaned = _COMPANY_MARKERS.sub(" ", _txt_norm(name))
    return {token for token in re.findall(r"[a-z]{2,}", cleaned) if token not in _NAME_STOPWORDS}


def _beneficiary_is_person(name: Optional[str]) -> bool:
    if not name or _COMPANY_MARKERS.search(name):
        return False
    tokens = re.findall(r"[A-Za-zĂÂÎȘŞȚŢăâîșşțţ]{2,}", name.strip())
    normalized_tokens = {token.lower().translate(_DIACRITICS) for token in tokens}
    if normalized_tokens & _GENERIC_BENEFICIARY_TERMS:
        return False
    return 2 <= len(tokens) <= 4


def _beneficiary_is_company(name: Optional[str]) -> bool:
    return bool(name and _COMPANY_MARKERS.search(name))


def _beneficiary_mismatch(beneficiary: Optional[str], issuer: Optional[str]) -> bool:
    if not _beneficiary_is_person(beneficiary):
        return False
    beneficiary_tokens = _name_tokens(beneficiary or "")
    issuer_tokens = _name_tokens(issuer or "")
    if beneficiary_tokens and issuer_tokens and len(beneficiary_tokens & issuer_tokens) >= min(
        2, len(beneficiary_tokens), len(issuer_tokens)
    ):
        return False
    return True


def _beneficiary_company_mismatch(beneficiary: Optional[str], issuer: Optional[str]) -> bool:
    if not _beneficiary_is_company(beneficiary):
        return False
    beneficiary_tokens = _name_tokens(beneficiary or "")
    issuer_tokens = _name_tokens(issuer or "")
    if not beneficiary_tokens or not issuer_tokens:
        return False
    return beneficiary_tokens != issuer_tokens


def _payment_destination_confirms_current_invoice(payment_destination: Optional[dict]) -> bool:
    if not payment_destination:
        return False
    return bool(
        payment_destination.get("matched")
        and payment_destination.get("can_contribute_to_safe") is True
        and (
            payment_destination.get("brand_matches") is True
            or payment_destination.get("cui_matches") is True
        )
    )


def _anaf_identity_matches_invoice(anaf: Optional[dict], issuer: Optional[str]) -> bool:
    if not anaf or anaf.get("checked") is False or not anaf.get("exists") or not anaf.get("activ"):
        return False
    anaf_tokens = _name_tokens(str(anaf.get("denumire") or ""))
    issuer_tokens = _name_tokens(issuer or "")
    if not anaf_tokens or not issuer_tokens:
        return False
    return bool(anaf_tokens & issuer_tokens)
