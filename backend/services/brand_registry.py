from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from services.iban_validator import IbanResult
from services.ro_morphology import contains_all, strip_diacritics

# SOURCE OF TRUTH for invoice route brand matching.
# This registry feeds invoice_orchestrator.match_brand() and is the only
# brand registry used on the inputType=invoice path. The separate registry
# in scam_atlas.py serves the message/link/email flow and is NOT consulted
# during invoice scans. Both registries may overlap in content but are
# maintained independently to match their respective detection contexts.


@dataclass
class BrandEntry:
    aliases: List[str]
    domains: List[str]
    cuis: List[str]
    trezorerie_only: bool
    official_ibans: List[str]


BRAND_REGISTRY: Dict[str, BrandEntry] = {
    "enel": BrandEntry(
        aliases=["enel", "e-distributie", "enel energie"],
        domains=["enel.ro", "e-distributie.com"],
        cuis=["24387371"],
        trezorerie_only=False,
        official_ibans=[],
    ),
    "ppc": BrandEntry(
        aliases=["ppc", "ppc energie"],
        domains=["ppcenergy.ro", "digital.ppcenergy.ro"],
        cuis=["22000460", "24387371"],
        trezorerie_only=False,
        official_ibans=[],
    ),
    "electrica": BrandEntry(
        aliases=["electrica", "electrica furnizare", "electrica distributie"],
        domains=["electrica.ro", "electrica-furnizare.ro"],
        cuis=["28909028"],
        trezorerie_only=False,
        official_ibans=[],
    ),
    "eon": BrandEntry(
        aliases=["e.on", "eon", "eon energie"],
        domains=["eon.ro"],
        cuis=["22043010"],
        trezorerie_only=False,
        official_ibans=[],
    ),
    "engie": BrandEntry(
        aliases=["engie", "gdf suez"],
        domains=["engie.ro"],
        cuis=["13093222"],
        trezorerie_only=False,
        official_ibans=[],
    ),
    "hidroelectrica": BrandEntry(
        aliases=["hidroelectrica"],
        domains=["hidroelectrica.ro"],
        cuis=["13267213"],
        trezorerie_only=False,
        official_ibans=[],
    ),
    "digi": BrandEntry(
        aliases=["digi", "digi.telekom", "rcs rds"],
        domains=["digi.ro", "rcs-rds.ro"],
        cuis=["5888716"],
        trezorerie_only=False,
        official_ibans=[],
    ),
    "orange": BrandEntry(
        aliases=["orange"],
        domains=["orange.ro"],
        cuis=["9010105"],
        trezorerie_only=False,
        official_ibans=[],
    ),
    "vodafone": BrandEntry(
        aliases=["vodafone"],
        domains=["vodafone.ro"],
        cuis=["8971726"],
        trezorerie_only=False,
        official_ibans=[],
    ),
    "telekom": BrandEntry(
        aliases=["telekom"],
        domains=["telekom.ro"],
        cuis=["11952970"],
        trezorerie_only=False,
        official_ibans=[],
    ),
    "anaf": BrandEntry(
        aliases=["anaf", "agentia nationala de administrare fiscala", "fisc", "finante"],
        domains=["anaf.ro", "ghiseul.ro", "static.anaf.ro"],
        cuis=[],
        trezorerie_only=True,
        official_ibans=[],
    ),
    "premier_energy": BrandEntry(
        aliases=["premier energy"],
        domains=["premierenergy.ro", "premierenergy.info"],
        cuis=["21349608"],
        trezorerie_only=False,
        official_ibans=[],
    ),
    "energy_gas": BrandEntry(
        aliases=["energy gas provider", "energy gas"],
        domains=["energy-gas.ro"],
        cuis=["26741040"],
        trezorerie_only=False,
        official_ibans=["RO25RNCB0300134768150001", "RO83BTRLRONCRT0299335701", "RO08RZBR0000060012601131"],
    ),
    "apa_nova": BrandEntry(
        aliases=["apa nova"],
        domains=["apanovabucuresti.ro"],
        cuis=["12276949"],
        trezorerie_only=False,
        official_ibans=[],
    ),
    "cnadnr": BrandEntry(
        aliases=["cnadnr", "compania nationala de drumuri", "rovignieta"],
        domains=["cnadnr.ro"],
        cuis=["16054316"],
        trezorerie_only=False,
        official_ibans=[],
    ),
    "impozite": BrandEntry(
        aliases=["impozite", "taxe locale", "directia de venituri", "direcția de venituri"],
        domains=[],
        cuis=[],
        trezorerie_only=True,
        official_ibans=[],
    ),
    # ===== COURIER =====
    "fan_courier": BrandEntry(
        aliases=["fan courier", "fancourier"],
        domains=["fancourier.ro", "fan.ro", "selfawb.ro"],
        cuis=["13838336"],
        trezorerie_only=False,
        official_ibans=[],
    ),
    "posta_romana": BrandEntry(
        aliases=["posta romana", "poșta română", "posta", "postaromana"],
        domains=["posta-romana.ro", "ropost.ro"],
        cuis=["427130"],
        trezorerie_only=False,
        official_ibans=[],
    ),
    "sameday": BrandEntry(
        aliases=["sameday", "sdy", "easybox"],
        domains=["sameday.ro", "sdy.ro"],
        cuis=["21303530"],
        trezorerie_only=False,
        official_ibans=[],
    ),
    "cargus": BrandEntry(
        aliases=["cargus", "urgent cargus"],
        domains=["cargus.ro"],
        cuis=["14533640", "3541906"],
        trezorerie_only=False,
        official_ibans=[],
    ),
    "dpd_romania": BrandEntry(
        aliases=["dpd", "dpd romania", "dynamic parcel distribution"],
        domains=["dpd.com"],
        cuis=["9566918"],
        trezorerie_only=False,
        official_ibans=[],
    ),
    "dhl": BrandEntry(
        aliases=["dhl"],
        domains=["dhl.ro", "dhl.com"],
        cuis=["11351979"],
        trezorerie_only=False,
        official_ibans=[],
    ),
    # ===== E-COMMERCE =====
    "emag": BrandEntry(
        aliases=["emag", "emag marketplace", "dante international"],
        domains=["emag.ro", "marketplace.emag.ro"],
        cuis=["14399840"],
        trezorerie_only=False,
        official_ibans=[],
    ),
    "altex": BrandEntry(
        aliases=["altex", "media galaxy", "mediagalaxy"],
        domains=["altex.ro", "mediagalaxy.ro"],
        cuis=["2864518"],
        trezorerie_only=False,
        official_ibans=[],
    ),
    "flanco": BrandEntry(
        aliases=["flanco"],
        domains=["flanco.ro"],
        cuis=[],
        trezorerie_only=False,
        official_ibans=[],
    ),
    "pcgarage": BrandEntry(
        aliases=["pc garage", "pcgarage"],
        domains=["pcgarage.ro"],
        cuis=["17612390"],
        trezorerie_only=False,
        official_ibans=[],
    ),
    # ===== RETAIL / SUPERMARKET =====
    "dedeman": BrandEntry(
        aliases=["dedeman"],
        domains=["dedeman.ro"],
        cuis=["2816464"],
        trezorerie_only=False,
        official_ibans=[],
    ),
    "raja": BrandEntry(
        aliases=["raja", "raja sa", "rajac"],
        domains=["rajac.ro"],
        cuis=["1890420"],
        trezorerie_only=False,
        official_ibans=[],
    ),
    "kaufland": BrandEntry(
        aliases=["kaufland"],
        domains=["kaufland.ro"],
        cuis=["15991149"],
        trezorerie_only=False,
        official_ibans=[],
    ),
    "lidl": BrandEntry(
        aliases=["lidl"],
        domains=["lidl.ro"],
        cuis=[],
        trezorerie_only=False,
        official_ibans=[],
    ),
    "carrefour": BrandEntry(
        aliases=["carrefour"],
        domains=["carrefour.ro"],
        cuis=["11588780"],
        trezorerie_only=False,
        official_ibans=[],
    ),
    "mega_image": BrandEntry(
        aliases=["mega image", "mega-image"],
        domains=["mega-image.ro"],
        cuis=[],
        trezorerie_only=False,
        official_ibans=[],
    ),
    "profi": BrandEntry(
        aliases=["profi"],
        domains=["profi.ro"],
        cuis=[],
        trezorerie_only=False,
        official_ibans=[],
    ),
    "auchan": BrandEntry(
        aliases=["auchan"],
        domains=["auchan.ro"],
        cuis=[],
        trezorerie_only=False,
        official_ibans=[],
    ),
    "ikea": BrandEntry(
        aliases=["ikea"],
        domains=["ikea.com", "ikea.ro"],
        cuis=[],
        trezorerie_only=False,
        official_ibans=[],
    ),
    "decathlon": BrandEntry(
        aliases=["decathlon"],
        domains=["decathlon.ro"],
        cuis=[],
        trezorerie_only=False,
        official_ibans=[],
    ),
    # ===== DIY / HOME IMPROVEMENT =====
    "hornbach": BrandEntry(
        aliases=["hornbach"],
        domains=["hornbach.ro"],
        cuis=["17777320"],
        trezorerie_only=False,
        official_ibans=[],
    ),
    "leroy_merlin": BrandEntry(
        aliases=["leroy merlin", "leroymerlin"],
        domains=["leroymerlin.ro"],
        cuis=["16702141"],
        trezorerie_only=False,
        official_ibans=[],
    ),
    "brico_depot": BrandEntry(
        aliases=["brico depot", "bricodepot"],
        domains=["bricodepot.ro"],
        cuis=[],
        trezorerie_only=False,
        official_ibans=[],
    ),
    "mobexpert": BrandEntry(
        aliases=["mobexpert"],
        domains=["mobexpert.ro"],
        cuis=[],
        trezorerie_only=False,
        official_ibans=[],
    ),
    # ===== FUEL / PETROL =====
    "petrom": BrandEntry(
        aliases=["petrom", "omv petrom"],
        domains=["petrom.ro", "omvpetrom.com"],
        cuis=["1590082"],
        trezorerie_only=False,
        official_ibans=[],
    ),
    "mol": BrandEntry(
        aliases=["mol romania", "mol group"],
        domains=["mol.ro", "molromania.ro"],
        cuis=[],
        trezorerie_only=False,
        official_ibans=[],
    ),
    "rompetrol": BrandEntry(
        aliases=["rompetrol"],
        domains=["rompetrol.ro"],
        cuis=[],
        trezorerie_only=False,
        official_ibans=[],
    ),
    # ===== INSURANCE =====
    "groupama": BrandEntry(
        aliases=["groupama"],
        domains=["groupama.ro"],
        cuis=["6291812"],
        trezorerie_only=False,
        official_ibans=[],
    ),
    "allianz_tiriac": BrandEntry(
        aliases=["allianz", "allianz tiriac", "allianz-țiriac"],
        domains=["allianztiriac.ro"],
        cuis=["6120740"],
        trezorerie_only=False,
        official_ibans=[],
    ),
    "asirom": BrandEntry(
        aliases=["asirom"],
        domains=["asirom.ro"],
        cuis=["26371010"],
        trezorerie_only=False,
        official_ibans=[],
    ),
    "omniasig": BrandEntry(
        aliases=["omniasig"],
        domains=["omniasig.ro"],
        cuis=["14360018"],
        trezorerie_only=False,
        official_ibans=[],
    ),
    # ===== HEALTHCARE =====
    "regina_maria": BrandEntry(
        aliases=["regina maria"],
        domains=["reginamaria.ro"],
        cuis=[],
        trezorerie_only=False,
        official_ibans=[],
    ),
    "medlife": BrandEntry(
        aliases=["medlife"],
        domains=["medlife.ro"],
        cuis=[],
        trezorerie_only=False,
        official_ibans=[],
    ),
    # ===== TRANSPORT =====
    "cfr_calatori": BrandEntry(
        aliases=["cfr calatori", "cfr călători", "cfr"],
        domains=["cfrcalatori.ro"],
        cuis=[],
        trezorerie_only=False,
        official_ibans=[],
    ),
    "metrorex": BrandEntry(
        aliases=["metrorex", "metrou"],
        domains=["metrorex.ro"],
        cuis=[],
        trezorerie_only=False,
        official_ibans=[],
    ),
    "stb": BrandEntry(
        aliases=["stb", "societatea de transport bucuresti"],
        domains=["stb.ro"],
        cuis=[],
        trezorerie_only=False,
        official_ibans=[],
    ),
    # ===== OTHER UTILITIES =====
    "romgaz": BrandEntry(
        aliases=["romgaz"],
        domains=["romgaz.ro"],
        cuis=[],
        trezorerie_only=False,
        official_ibans=[],
    ),
    "termoenergetica": BrandEntry(
        aliases=["termoenergetica"],
        domains=["termoenergetica.ro"],
        cuis=[],
        trezorerie_only=False,
        official_ibans=[],
    ),
}


@dataclass
class BrandMatchResult:
    claimed_brand: str | None
    domain_matches: bool | None
    iban_matches: bool | None
    cui_matches: bool | None
    impersonation_risk: bool
    # True when the brand was matched strictly (word boundary / exact domain);
    # False when it was matched only via the fuzzy P-MORPH token fallback. A
    # fuzzy match adds recall but must never drive a hard PERICOL verdict.
    claimed_brand_match_strict: bool = True


def _norm_text(text: str) -> str:
    # P-MORPH: folding complet de diacritice (majuscule/minuscule, â→a,
    # î→i, ș/ş, ț/ţ) prin ro_morphology, in loc de translate partial.
    return strip_diacritics(text or "").lower()


def _looks_like_anaf_reference_not_issuer(text: str) -> bool:
    normalized = _norm_text(" ".join((text or "").split("\n")[:4]))
    if re.match(r"\s*(anaf|agentia\s+nationala|ministerul\s+finantelor|fisc)\b", normalized):
        return False
    return bool(
        re.search(
            r"\b(e-?factura|roefactura|spv|acceptat[aa]\s+de\s+anaf|inregistrare\s+anaf|"
            r"sistemul\s+e-?factura)\b",
            normalized,
        )
    )


def _strict_alias_brand(hay: str, *, anaf_ref_text: str | None = None) -> str | None:
    # Word-boundary alias match: reproduce exact comportamentul pre-P-MORPH.
    for brand_key, entry in BRAND_REGISTRY.items():
        if brand_key == "anaf" and anaf_ref_text is not None and _looks_like_anaf_reference_not_issuer(anaf_ref_text):
            continue
        for alias in entry.aliases:
            if re.search(rf"\b{re.escape(alias)}\b", hay, re.IGNORECASE):
                return brand_key
    return None


def _fuzzy_alias_brand(hay: str, *, anaf_ref_text: str | None = None) -> str | None:
    # P-MORPH: potrivire pe token-uri (robusta la diacritice/inflexiune/ordine).
    # stem=False intentionat: numele de brand nu se stemeaza. Adauga recall, dar
    # apelantul o marcheaza ca ne-stricta -> nu poate escalada la PERICOL.
    for brand_key, entry in BRAND_REGISTRY.items():
        if brand_key == "anaf" and anaf_ref_text is not None and _looks_like_anaf_reference_not_issuer(anaf_ref_text):
            continue
        for alias in entry.aliases:
            if contains_all(hay, alias, stem=False):
                return brand_key
    return None


def _detect_claimed_brand_detailed(
    emitent: str | None, text: str, links: List[str]
) -> tuple[str | None, bool]:
    """Return ``(brand_key, matched_strictly)``.

    Strict matches (word boundary on emitent/header, or an exact payment-link
    domain) take priority over the fuzzy P-MORPH token fallback, so a fuzzy match
    can never shadow a strict brand attribution. The strict pass reproduces the
    pre-P-MORPH detection order exactly; the fuzzy pass is a last resort that only
    adds recall and is flagged non-strict for the caller.
    """
    header = " ".join(text.split("\n")[:3])

    # Pass 1 — strict, in the original source priority (emitent, link, header).
    if emitent:
        brand = _strict_alias_brand(emitent)
        if brand:
            return brand, True
    if links:
        link_lower = " ".join(link.lower() for link in links)
        for brand_key, entry in BRAND_REGISTRY.items():
            for domain in entry.domains:
                if domain in link_lower:
                    return brand_key, True
    brand = _strict_alias_brand(header, anaf_ref_text=text)
    if brand:
        return brand, True

    # Pass 2 — fuzzy fallback (recall only; flagged non-strict, never PERICOL).
    if emitent:
        brand = _fuzzy_alias_brand(emitent)
        if brand:
            return brand, False
    brand = _fuzzy_alias_brand(header, anaf_ref_text=text)
    if brand:
        return brand, False

    return None, False


def detect_claimed_brand(emitent: str | None, text: str, links: List[str]) -> str | None:
    return _detect_claimed_brand_detailed(emitent, text, links)[0]


def _domain_belongs_to_brand(link: str, domains: List[str]) -> bool:
    from urllib.parse import urlparse
    link_lower = link.lower()
    try:
        parsed = urlparse(link_lower)
        hostname = parsed.hostname or link_lower
    except Exception:
        hostname = link_lower
    for domain in domains:
        if hostname == domain or hostname.endswith("." + domain):
            return True
    return False


def _any_link_matches(links: List[str], domains: List[str]) -> bool | None:
    if not links:
        return None
    if not domains:
        return None
    matched = any(_domain_belongs_to_brand(link, domains) for link in links)
    return matched


def match_brand(
    emitent: str | None,
    text: str,
    links: List[str],
    cui: str | None,
    validated_iban: IbanResult | None,
    iban_raw: str | None,
) -> BrandMatchResult:
    claimed_brand, claimed_brand_match_strict = _detect_claimed_brand_detailed(emitent, text, links)
    if not claimed_brand:
        return BrandMatchResult(
            claimed_brand=None, domain_matches=None, iban_matches=None,
            cui_matches=None, impersonation_risk=False,
        )
    entry = BRAND_REGISTRY.get(claimed_brand)
    if not entry:
        return BrandMatchResult(
            claimed_brand=claimed_brand, domain_matches=None, iban_matches=None,
            cui_matches=None, impersonation_risk=False,
            claimed_brand_match_strict=claimed_brand_match_strict,
        )
    domain_matches = _any_link_matches(links, entry.domains)
    cui_matches: bool | None = None
    if entry.cuis:
        cui_normalized = _normalize_cui(cui) if cui else ""
        normalized_entry_cuis = [_normalize_cui(c) for c in entry.cuis]
        cui_matches = (cui_normalized in normalized_entry_cuis) if cui_normalized else None
    iban_matches: bool | None = None
    if entry.trezorerie_only:
        if validated_iban and validated_iban.valid_structure:
            iban_matches = validated_iban.is_trezorerie
    elif entry.official_ibans and iban_raw:
        iban_normalized = iban_raw.strip().upper().replace(" ", "")
        iban_matches = iban_normalized in [i.strip().upper().replace(" ", "") for i in entry.official_ibans]
    impersonation_risk = (domain_matches is False) or (iban_matches is False) or (cui_matches is False)
    return BrandMatchResult(
        claimed_brand=claimed_brand,
        domain_matches=domain_matches,
        iban_matches=iban_matches,
        cui_matches=cui_matches,
        impersonation_risk=impersonation_risk,
        claimed_brand_match_strict=claimed_brand_match_strict,
    )


def _normalize_cui(raw: str | None) -> str:
    if not raw:
        return ""
    return "".join(ch for ch in raw if ch.isdigit())
