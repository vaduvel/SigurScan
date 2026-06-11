"""Offer entity verifier — produce FAPTE despre emitentul ofertei.

REUSE: anaf_cui.check_cui (CUI emitent), iban_validator.validate_iban (IBAN plată),
brand_registry.detect_claimed_brand/match_brand (brand pretins). NU produce verdict
și NU adaugă calls noi de rețea (doar refolosește serviciile existente; păstrează
timeout-urile ANAF din anaf_cui).

Reguli respectate:
- ANAF date_generale:null → checked=True, exists=False (UNKNOWN, NU eșec). check_cui
  tratează deja asta; aici doar consumăm corect (checked=False = ANAF indisponibil).
- CUI valid ≠ ofertă reală: returnăm fapte, gate-ul decide.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import List, Optional

from services.anaf_cui import check_cui
from services.brand_registry import detect_claimed_brand, match_brand
from services.iban_validator import validate_iban

if False:  # typing only, evită import circular la runtime
    from services.offer_parser import OfferFields

_LEGAL_FORMS = re.compile(
    r"\b(s\.?c\.?|s\.?r\.?l\.?|s\.?a\.?|p\.?f\.?a\.?|i\.?i\.?|s\.?n\.?c\.?|srl|sa|pfa)\b",
    re.IGNORECASE,
)
_COMPANY_HINT = re.compile(r"\b(srl|s\.?r\.?l\.?|sa|s\.?a\.?|s\.?c\.?|pfa|ii|snc|gmbh|ltd|llc)\b", re.IGNORECASE)
NAME_MATCH_THRESHOLD = 0.82


@dataclass
class OfferEntityResult:
    has_cui: bool = False
    cui_checked: bool = False        # ANAF a răspuns (False = indisponibil, NU eșec de fraudă)
    cui_exists: bool = False
    cui_active: bool = False
    denumire: Optional[str] = None
    name_matches: Optional[bool] = None   # issuer_name vs denumire (None dacă nu putem compara)
    iban_present: bool = False
    iban_valid: Optional[bool] = None     # None dacă nu există IBAN
    iban_is_trezorerie: bool = False
    claimed_brand: Optional[str] = None
    brand_impersonation: bool = False
    brand_cui_matches: bool = True
    brand_iban_matches: bool = True
    claims_company: bool = False
    warnings: List[str] = field(default_factory=list)


def _normalize_company_name(name: str) -> str:
    n = name.lower()
    n = _LEGAL_FORMS.sub(" ", n)
    n = re.sub(r"[^a-z0-9ăâîșţț ]", " ", n)
    n = re.sub(r"\s+", " ", n).strip()
    return n


def _names_align(issuer_name: Optional[str], denumire: Optional[str]) -> Optional[bool]:
    if not issuer_name or not denumire:
        return None
    a = _normalize_company_name(issuer_name)
    b = _normalize_company_name(denumire)
    if not a or not b:
        return None
    if a in b or b in a:
        return True
    ratio = SequenceMatcher(None, a, b).ratio()
    if ratio >= NAME_MATCH_THRESHOLD:
        return True
    # token-subset: toate tokenele lungi din numele scurt apar în celălalt
    ta = {t for t in a.split() if len(t) >= 4}
    tb = {t for t in b.split() if len(t) >= 4}
    if ta and tb and (ta <= tb or tb <= ta):
        return True
    return False


async def verify_offer_entity(
    fields: "OfferFields", *, links: Optional[List[str]] = None
) -> OfferEntityResult:
    text = fields.raw_text or ""
    issuer = fields.issuer_name or fields.emitent
    all_links = list(links or fields.urls or [])
    result = OfferEntityResult()

    # IBAN
    if fields.iban:
        result.iban_present = True
        iban_res = validate_iban(fields.iban)
        result.iban_valid = iban_res.valid_structure
        result.iban_is_trezorerie = iban_res.is_trezorerie
        if not iban_res.valid_structure:
            result.warnings.append("IBAN invalid (MOD-97)")
    else:
        iban_res = None

    # Brand pretins (doar brand_registry pe ruta ofertă, conform regulii #5)
    claimed_brand = detect_claimed_brand(issuer, text, all_links)
    result.claimed_brand = claimed_brand
    if claimed_brand:
        bm = match_brand(
            emitent=issuer,
            text=text,
            links=all_links,
            cui=fields.cui,
            validated_iban=iban_res,
            iban_raw=fields.iban,
        )
        result.brand_impersonation = bm.impersonation_risk
        result.brand_cui_matches = bm.cui_matches
        result.brand_iban_matches = bm.iban_matches
        if bm.impersonation_risk:
            result.warnings.append(f"Posibilă impersonare a brandului {claimed_brand}")

    # „Pretinde firmă?" — pentru combo-ul CUI inexistent + pretinde firmă + plată
    result.claims_company = bool(
        claimed_brand
        or fields.cui
        or (issuer and _COMPANY_HINT.search(issuer))
    )

    # ANAF CUI (emitent)
    if fields.cui:
        result.has_cui = True
        cui_res = await check_cui(fields.cui)
        result.cui_checked = cui_res.checked
        result.cui_exists = cui_res.exists
        result.cui_active = cui_res.activ
        result.denumire = cui_res.denumire
        result.name_matches = _names_align(issuer, cui_res.denumire)
        if not cui_res.checked:
            result.warnings.append("ANAF temporar indisponibil (verificare neconcludentă)")
        elif not cui_res.exists:
            result.warnings.append(f"CUI {fields.cui} negăsit în registrul ANAF")
        elif not cui_res.activ:
            result.warnings.append(f"Firmă inactivă: {cui_res.denumire or fields.cui}")
        elif result.name_matches is False:
            result.warnings.append("Numele emitentului nu corespunde cu denumirea ANAF")

    return result
