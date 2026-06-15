from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from services.iban_validator import IbanResult

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
    # IBAN-mismatch = impersonare DOAR dacă lista de conturi oficiale e COMPLETĂ.
    # Implicit False: un brand poate avea mai multe conturi → un IBAN neprezent în
    # listă NU înseamnă fraudă (doar „neconfirmat"). Match pozitiv rămâne boost.
    iban_list_complete: bool = False


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
        official_ibans=[
            "RO53BRDE270SV23904012700", "RO27INGB0015000028188911",
            "RO58BACX0000003701625003", "RO88CRCOX130013000088260",
            "RO14TREZ4765069XXX007593",
        ],  # eon.ro/info-utile (2026-06-14); listă incompletă → doar boost pozitiv
    ),
    "engie": BrandEntry(
        aliases=["engie", "gdf suez"],
        domains=["engie.ro"],
        cuis=["13093222"],
        trezorerie_only=False,
        official_ibans=[
            "RO26BRDE450SV11436814500", "RO40RZBR0000060010660361",
            "RO16RNCB007400184206G242", "RO18CITI0000000824902224",
            "RO70CRCOX410041000021931", "RO54BACX0000000124823310",
            "RO83INGB0001000000000888", "RO80CECEB315N5RON2189733",
            "RO44BTRL0430160100713643", "RO41TREZ7005069XXX000397",
        ],  # engie.ro modalitati-de-plata (2026-06-14); listă incompletă → boost
    ),
    "hidroelectrica": BrandEntry(
        aliases=["hidroelectrica"],
        domains=["hidroelectrica.ro"],
        cuis=["13267213"],
        trezorerie_only=False,
        official_ibans=["RO63RNCB0072018331870495"],  # hidroelectrica.ro (2026-06-14); incompletă → boost
    ),
    "digi": BrandEntry(
        aliases=["digi", "digi.telekom", "rcs rds"],
        domains=["digi.ro", "rcs-rds.ro"],
        cuis=["5888716"],
        trezorerie_only=False,
        official_ibans=[
            "RO51INGB0001000000018827", "RO64BRDE450SV72419954500",
            "RO94BACX0000000189518001", "RO16RZBR0000060018483261",
        ],  # digi.ro/asistenta/modalitati-de-plata (2026-06-14); incompletă → boost
    ),
    "orange": BrandEntry(
        aliases=["orange"],
        domains=["orange.ro"],
        cuis=["9010105"],
        trezorerie_only=False,
        official_ibans=[
            "RO91INGB0001000000011511", "RO33BRDE450SV01035364500",
            "RO91BTRL0000160106816100", "RO20RZBR0000060003074933",
            "RO02TREZ7005069XXX000711", "RO45CECEB10046RON0403003",
            "RO08BACX0000000030877310",
        ],  # orange.ro/help conturi virament (2026-06-14); incompletă → boost
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
        official_ibans=[
            "RO53RNCB0072049690440015", "RO27BRDE450SV23764524500",
            "RO34BTRL0000160100719900", "RO55CECEB31544RON4213814",
            "RO72CRCOX410041000022089", "RO98PIRB4228705728002000",
            "RO15UGBI0000512001205RON", "RO30INGB0001000000017362",
            "RO47RZBR0000060012892302",
        ],  # mobile.telekom.ro modalitati-plata (2026-06-14); incompletă → boost
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
        iban_list_complete=True,  # listă autoritară → mismatch = impersonare (decizie existentă)
    ),
    "apa_nova": BrandEntry(
        aliases=["apa nova"],
        domains=["apanovabucuresti.ro"],
        cuis=["12276949"],
        trezorerie_only=False,
        official_ibans=["RO33BRDE450SV01059614500"],  # apanovabucuresti.ro contract (2026-06-15); incompletă → boost
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
        official_ibans=["RO23BPOS85002717790ROL02"],  # posta-romana.ro (2026-06-15); incompletă → boost
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
        cuis=["14533640"],
        trezorerie_only=False,
        official_ibans=["RO75RNCB0081104613950180"],  # cargus.ro taxa logistica (2026-06-15); incompletă → boost
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
        official_ibans=["RO76RNCB0279014382090139", "RO75TREZ0615069XXX001476"],  # dedeman.ro plata online (2026-06-15)
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
        official_ibans=[
            "RO53BTRL0130160100656313", "RO78BRDE450SV88175384500",
            "RO54RNCB0082000537541809", "RO02BACX0000000030262147",
            "RO36BTRL0130460100656313", "RO66BRDE450SV88175624500",
            "RO27RNCB0082000537541810", "RO15BTRL0130260100656313",
            "RO40BRDE450SV31665884500",
        ],  # groupama.ro modalitati-de-plata (2026-06-15); incompletă → boost
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
        official_ibans=[
            "RO92BTRLEURCRT0331106601", "RO96BTRLUSDCRT0331106601",
            "RO98RNCB0082044182221925", "RO71RNCB0082044182221926",
            "RO97RNCB0082044182220003", "RO50RZBR0000060002802114",
            "RO98RZBR0000060002802123",
        ],  # asirom.ro modalitati-de-plata (2026-06-15); incompletă → boost
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
    # IBAN-mismatch contribuie la impersonare DOAR dacă lista e autoritară/completă
    # (trezorerie = regulă completă prin natură; altfel doar dacă iban_list_complete).
    # Pentru liste incomplete: un IBAN neprezent ≠ impersonare (evită fals-pozitiv pe
    # facturi legitime cu alt cont oficial al aceluiași brand). Match rămâne boost.
    iban_mismatch_authoritative = (iban_matches is False) and (
        entry.trezorerie_only or entry.iban_list_complete
    )
    impersonation_risk = (domain_matches is False) or iban_mismatch_authoritative or (cui_matches is False)
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
