from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from services.iban_validator import IbanResult


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
        cuis=["14345906"],
        trezorerie_only=False,
        official_ibans=[],
    ),
    "ppc": BrandEntry(
        aliases=["ppc", "ppc energie"],
        domains=["ppc.ro"],
        cuis=[],
        trezorerie_only=False,
        official_ibans=[],
    ),
    "electrica": BrandEntry(
        aliases=["electrica", "electrica furnizare", "electrica distributie"],
        domains=["electrica.ro", "electrica-furnizare.ro"],
        cuis=["13267293"],
        trezorerie_only=False,
        official_ibans=[],
    ),
    "eon": BrandEntry(
        aliases=["e.on", "eon", "eon energie"],
        domains=["eon.ro"],
        cuis=["15877338"],
        trezorerie_only=False,
        official_ibans=[],
    ),
    "engie": BrandEntry(
        aliases=["engie", "gdf suez"],
        domains=["engie.ro"],
        cuis=["35194668"],
        trezorerie_only=False,
        official_ibans=[],
    ),
    "hidroelectrica": BrandEntry(
        aliases=["hidroelectrica"],
        domains=["hidroelectrica.ro"],
        cuis=["13267259"],
        trezorerie_only=False,
        official_ibans=[],
    ),
    "digi": BrandEntry(
        aliases=["digi", "digi.telekom", "rcs rds"],
        domains=["digi.ro", "rcs-rds.ro"],
        cuis=["33141033", "5888716"],
        trezorerie_only=False,
        official_ibans=[],
    ),
    "orange": BrandEntry(
        aliases=["orange"],
        domains=["orange.ro"],
        cuis=["16339980"],
        trezorerie_only=False,
        official_ibans=[],
    ),
    "vodafone": BrandEntry(
        aliases=["vodafone"],
        domains=["vodafone.ro"],
        cuis=["15049623"],
        trezorerie_only=False,
        official_ibans=[],
    ),
    "telekom": BrandEntry(
        aliases=["telekom"],
        domains=["telekom.ro"],
        cuis=["16339980"],
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
    "energy_gas": BrandEntry(
        aliases=["energy gas provider", "energy gas"],
        domains=["energy-gas.ro"],
        cuis=["26741040"],
        trezorerie_only=False,
        official_ibans=["RO25RNCB0300134768150001", "RO83BTRLRONCRT0299335701", "RO08RZBR0000060012601131"],
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
}


@dataclass
class BrandMatchResult:
    claimed_brand: str | None
    domain_matches: bool
    iban_matches: bool
    cui_matches: bool
    impersonation_risk: bool


def detect_claimed_brand(emitent: str | None, text: str, links: List[str]) -> str | None:
    if emitent:
        for brand_key, entry in BRAND_REGISTRY.items():
            for alias in entry.aliases:
                if re.search(rf"\b{re.escape(alias)}\b", emitent, re.IGNORECASE):
                    return brand_key
    if links:
        for brand_key, entry in BRAND_REGISTRY.items():
            link_lower = " ".join(link.lower() for link in links)
            for domain in entry.domains:
                if domain in link_lower:
                    return brand_key
    header_lines = text.split("\n")[:3]
    header = " ".join(header_lines)
    for brand_key, entry in BRAND_REGISTRY.items():
        for alias in entry.aliases:
            if re.search(rf"\b{re.escape(alias)}\b", header, re.IGNORECASE):
                return brand_key
    return None


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
    claimed_brand = detect_claimed_brand(emitent, text, links)
    if not claimed_brand:
        return BrandMatchResult(
            claimed_brand=None, domain_matches=True, iban_matches=True,
            cui_matches=True, impersonation_risk=False,
        )
    entry = BRAND_REGISTRY.get(claimed_brand)
    if not entry:
        return BrandMatchResult(
            claimed_brand=claimed_brand, domain_matches=True, iban_matches=True,
            cui_matches=True, impersonation_risk=False,
        )
    domain_matches_raw = _any_link_matches(links, entry.domains)
    domain_matches = domain_matches_raw if domain_matches_raw is not None else True
    cui_matches: bool | None = True
    if entry.cuis:
        cui_normalized = _normalize_cui(cui) if cui else ""
        normalized_entry_cuis = [_normalize_cui(c) for c in entry.cuis]
        cui_matches = bool(cui_normalized) and cui_normalized in normalized_entry_cuis
    iban_matches: bool | None = True
    if entry.trezorerie_only:
        iban_matches = validated_iban.is_trezorerie if validated_iban else False
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
    )


def _normalize_cui(raw: str | None) -> str:
    if not raw:
        return ""
    return "".join(ch for ch in raw if ch.isdigit())
