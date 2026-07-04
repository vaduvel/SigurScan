from __future__ import annotations

import json
import os
import re
from functools import lru_cache
from typing import Any, Dict, Optional

from services.iban_validator import normalize_iban, validate_iban

_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DEFAULT_PATH = os.path.join(
    _BACKEND_DIR,
    "data",
    "payment_destination_registry",
    "payment_destination_registry_ro_seed_2026_06_15.json",
)
_DEFAULT_DIR = os.path.dirname(_DEFAULT_PATH)

_ACTIVE_TIERS = {"T0_PARTNER_SIGNED", "T1_PUBLIC_OFFICIAL", "T2_OFFICIAL_DOCUMENT_CHAIN"}
_DIACRITICS = str.maketrans("ăâîșşțţĂÂÎȘŞȚŢ", "aaissttAAISSTT")
_ENTITY_SUFFIX_RE = re.compile(
    r"\b(s\.?\s?c\.?|s\.?\s?r\.?\s?l\.?|s\.?\s?a\.?|p\.?\s?f\.?\s?a\.?|i\.?\s?i\.?|"
    r"s\.?\s?n\.?\s?c\.?|societatea|societate|compania|company|co|ltd|llc|inc)\b",
    re.IGNORECASE,
)
_BRAND_ALIASES = {
    "ppc": "ppc_energy",
    "ppc_energy": "ppc_energy",
    "eon": "eon_energie_romania",
    "eon_energie_romania": "eon_energie_romania",
    "apavital": "apavital_iasi",
    "apavital_iasi": "apavital_iasi",
    "apa_canal_galati": "apa_canal_galati",
    "apa canal galati": "apa_canal_galati",
    "apa canal galați": "apa_canal_galati",
    "salubris": "salubris_iasi",
    "salubris_iasi": "salubris_iasi",
    "salubris iasi": "salubris_iasi",
    "salubris iași": "salubris_iasi",
    "compania_apa_olt": "compania_apa_olt",
    "compania apa olt": "compania_apa_olt",
    "apa olt": "compania_apa_olt",
    "retim": "retim_ecologic_service",
    "retim_ecologic_service": "retim_ecologic_service",
    "retim ecologic service": "retim_ecologic_service",
    "apa_brasov": "compania_apa_brasov",
    "compania_apa_brasov": "compania_apa_brasov",
    "hidroelectrica": "hidroelectrica",
    "engie": "engie_romania",
    "engie_romania": "engie_romania",
    "electrica": "electrica_furnizare",
    "electrica_furnizare": "electrica_furnizare",
    "digi": "digi_romania",
    "digi_romania": "digi_romania",
    "rcs_rds": "digi_romania",
    "rcs-rds": "digi_romania",
    "rcs rds": "digi_romania",
    "rcs & rds": "digi_romania",
    "orange": "orange_romania",
    "orange_romania": "orange_romania",
    "orange_communications": "orange_romania_communications",
    "orange_romania_communications": "orange_romania_communications",
    "orange romania communications": "orange_romania_communications",
    "vodafone": "vodafone_romania",
    "vodafone_romania": "vodafone_romania",
    "vodafone romania": "vodafone_romania",
    "nextgen": "nextgen_communications",
    "nextgen_communications": "nextgen_communications",
    "nextgen communications": "nextgen_communications",
    "next-gen": "nextgen_communications",
    "apa_nova": "apa_nova_bucuresti",
    "apa_nova_bucuresti": "apa_nova_bucuresti",
    "apa nova": "apa_nova_bucuresti",
    "apa nova bucuresti": "apa_nova_bucuresti",
    "aquatim": "aquatim",
    "asirom": "asirom",
    "groupama": "groupama",
    "groupama asigurari": "groupama",
    "groupama asigurări": "groupama",
    "uniqa": "uniqa_asigurari",
    "uniqa asigurari": "uniqa_asigurari",
    "uniqa asigurări": "uniqa_asigurari",
    "uniqa asigurari de viata": "uniqa_asigurari_de_viata",
    "uniqa asigurări de viață": "uniqa_asigurari_de_viata",
    "uniqa viata": "uniqa_asigurari_de_viata",
    "uniqa life": "uniqa_asigurari_de_viata",
    "unita asigurari": "uniqa_asigurari",
    "unita": "uniqa_asigurari",
    "mega_image": "mega_image",
    "mega image": "mega_image",
    "mega-image": "mega_image",
    "mega image srl": "mega_image",
    "omniasig": "omniasig",
    "allianz": "allianz_tiriac",
    "allianz tiriac": "allianz_tiriac",
    "allianz-tiriac": "allianz_tiriac",
    "allianz_tiriac": "allianz_tiriac",
    "emag_ads": "emag_ads_dante",
    "emag ads": "emag_ads_dante",
    "emag_ads_dante": "emag_ads_dante",
    "telekom": "telekom_romania_mobile",
    "telekom_romania": "telekom_romania_mobile",
    "telekom romania": "telekom_romania_mobile",
    "telekom_romania_mobile": "telekom_romania_mobile",
    "cargus": "cargus",
    "urgent cargus": "cargus",
    "dpd": "dpd_romania",
    "dpd_romania": "dpd_romania",
    "dynamic parcel distribution": "dpd_romania",
    "dedeman": "dedeman",
    "raja": "raja",
    "rajac": "raja",
    "nn": "nn_romania",
    "nn_romania": "nn_romania",
    "nn romania": "nn_romania",
    "nn asigurari": "nn_romania",
    "nn asigurări": "nn_romania",
    "altex": "altex_romania",
    "altex_romania": "altex_romania",
    "altex romania": "altex_romania",
    "compania_apa_somes": "compania_apa_somes",
    "compania apa somes": "compania_apa_somes",
    "compania de apa somes": "compania_apa_somes",
    "ca somes": "compania_apa_somes",
    "casomes": "compania_apa_somes",
    "hydrokov": "hydrokov_covasna",
    "hydrokov_covasna": "hydrokov_covasna",
    "aquacovas": "hydrokov_covasna",
    "aqua covas": "hydrokov_covasna",
    "compania_apa_arad": "compania_apa_arad",
    "compania apa arad": "compania_apa_arad",
    "ca arad": "compania_apa_arad",
    "caarad": "compania_apa_arad",
    "apa_canal_2000": "apa_canal_2000_pitesti",
    "apa_canal_2000_pitesti": "apa_canal_2000_pitesti",
    "apa canal 2000": "apa_canal_2000_pitesti",
    "apa canal 2000 pitesti": "apa_canal_2000_pitesti",
    "distrigaz_vest": "distrigaz_vest",
    "distrigaz vest": "distrigaz_vest",
    "carrefour": "carrefour_romania",
    "carrefour_romania": "carrefour_romania",
    "carrefour romania": "carrefour_romania",
    "hornbach": "hornbach_romania",
    "hornbach_romania": "hornbach_romania",
    "hornbach centrala": "hornbach_romania",
    "regina_maria": "regina_maria",
    "regina maria": "regina_maria",
    "sanador": "sanador",
    "synevo": "synevo_romania",
    "synevo_romania": "synevo_romania",
    "rompetrol": "rompetrol_downstream",
    "rompetrol_downstream": "rompetrol_downstream",
    "rompetrol rafinare": "rompetrol_rafinare",
    "rompetrol_rafinare": "rompetrol_rafinare",
    "banca_transilvania": "banca_transilvania",
    "banca transilvania": "banca_transilvania",
    "bt": "banca_transilvania",
    "anaf": "anaf",
    "osim": "osim",
    "oficiul de stat pentru inventii si marci": "osim",
    "oficiul de stat pentru invenții și mărci": "osim",
    "politia": "politia_romana",
    "politia_romana": "politia_romana",
    "politia romana": "politia_romana",
    "primaria_sector_1": "primaria_sector_1",
    "primaria sector 1": "primaria_sector_1",
    "primaria_sector_2": "primaria_sector_2",
    "primaria sector 2": "primaria_sector_2",
    "primaria_sector_3": "primaria_sector_3",
    "primaria sector 3": "primaria_sector_3",
    "primaria_sector_4": "primaria_sector_4",
    "primaria sector 4": "primaria_sector_4",
    "primaria_sector_5": "primaria_sector_5",
    "primaria sector 5": "primaria_sector_5",
    "primaria_sector_6": "primaria_sector_6",
    "primaria sector 6": "primaria_sector_6",
    "primaria_bucuresti": "primaria_bucuresti",
    "primaria bucuresti": "primaria_bucuresti",
    "primaria_cluj": "primaria_cluj_napoca",
    "primaria_cluj_napoca": "primaria_cluj_napoca",
    "primaria cluj": "primaria_cluj_napoca",
    "primaria_timisoara": "primaria_timisoara",
    "primaria timisoara": "primaria_timisoara",
    "primaria_iasi": "primaria_iasi",
    "primaria iasi": "primaria_iasi",
}

_BRAND_ALIASES.update({
    "rcs_rds": "digi_romania",
    "rcs-rds": "digi_romania",
    "rcs rds": "digi_romania",
    "rcs & rds": "digi_romania",
    "groupama asigurari": "groupama",
    "groupama asigurări": "groupama",
    "uniqa": "uniqa_asigurari",
    "uniqa asigurari": "uniqa_asigurari",
    "uniqa asigurări": "uniqa_asigurari",
    "uniqa asigurari de viata": "uniqa_asigurari_de_viata",
    "uniqa asigurări de viață": "uniqa_asigurari_de_viata",
    "uniqa viata": "uniqa_asigurari_de_viata",
    "uniqa life": "uniqa_asigurari_de_viata",
    "unita": "uniqa_asigurari",
    "unita asigurari": "uniqa_asigurari",
    "mega_image": "mega_image",
    "mega image": "mega_image",
    "mega-image": "mega_image",
    "mega image srl": "mega_image",
    "telekom_romania": "telekom_romania_mobile",
    "telekom romania": "telekom_romania_mobile",
    "nn": "nn_romania",
    "nn_romania": "nn_romania",
    "nn romania": "nn_romania",
    "nn asigurari": "nn_romania",
    "nn asigurări": "nn_romania",
    "altex": "altex_romania",
    "altex_romania": "altex_romania",
    "altex romania": "altex_romania",
    "compania_apa_somes": "compania_apa_somes",
    "compania apa somes": "compania_apa_somes",
    "compania de apa somes": "compania_apa_somes",
    "ca somes": "compania_apa_somes",
    "casomes": "compania_apa_somes",
    "hydrokov": "hydrokov_covasna",
    "hydrokov_covasna": "hydrokov_covasna",
    "aquacovas": "hydrokov_covasna",
    "aqua covas": "hydrokov_covasna",
    "compania_apa_arad": "compania_apa_arad",
    "compania apa arad": "compania_apa_arad",
    "ca arad": "compania_apa_arad",
    "caarad": "compania_apa_arad",
    "apa_canal_2000": "apa_canal_2000_pitesti",
    "apa_canal_2000_pitesti": "apa_canal_2000_pitesti",
    "apa canal 2000": "apa_canal_2000_pitesti",
    "apa canal 2000 pitesti": "apa_canal_2000_pitesti",
    "distrigaz_vest": "distrigaz_vest",
    "distrigaz vest": "distrigaz_vest",
    "carrefour": "carrefour_romania",
    "carrefour_romania": "carrefour_romania",
    "carrefour romania": "carrefour_romania",
    "hornbach": "hornbach_romania",
    "hornbach_romania": "hornbach_romania",
    "hornbach centrala": "hornbach_romania",
    "regina_maria": "regina_maria",
    "regina maria": "regina_maria",
    "sanador": "sanador",
    "synevo": "synevo_romania",
    "synevo_romania": "synevo_romania",
    "rompetrol": "rompetrol_downstream",
    "rompetrol_downstream": "rompetrol_downstream",
    "rompetrol rafinare": "rompetrol_rafinare",
    "rompetrol_rafinare": "rompetrol_rafinare",
    "banca_transilvania": "banca_transilvania",
    "banca transilvania": "banca_transilvania",
    "bt": "banca_transilvania",
    "anaf": "anaf",
    "osim": "osim",
    "oficiul de stat pentru inventii si marci": "osim",
    "oficiul de stat pentru invenții și mărci": "osim",
    "politia": "politia_romana",
    "politia_romana": "politia_romana",
    "politia romana": "politia_romana",
    "primaria_sector_1": "primaria_sector_1",
    "primaria sector 1": "primaria_sector_1",
    "primaria_sector_2": "primaria_sector_2",
    "primaria sector 2": "primaria_sector_2",
    "primaria_sector_3": "primaria_sector_3",
    "primaria sector 3": "primaria_sector_3",
    "primaria_sector_4": "primaria_sector_4",
    "primaria sector 4": "primaria_sector_4",
    "primaria_sector_5": "primaria_sector_5",
    "primaria sector 5": "primaria_sector_5",
    "primaria_sector_6": "primaria_sector_6",
    "primaria sector 6": "primaria_sector_6",
    "primaria_bucuresti": "primaria_bucuresti",
    "primaria bucuresti": "primaria_bucuresti",
    "primaria_cluj": "primaria_cluj_napoca",
    "primaria_cluj_napoca": "primaria_cluj_napoca",
    "primaria cluj": "primaria_cluj_napoca",
    "primaria_timisoara": "primaria_timisoara",
    "primaria timisoara": "primaria_timisoara",
    "primaria_iasi": "primaria_iasi",
    "primaria iasi": "primaria_iasi",
    "compania_apa_oltenia": "compania_apa_oltenia",
    "compania apa oltenia": "compania_apa_oltenia",
    "compania de apa oltenia": "compania_apa_oltenia",
    "apa oltenia": "compania_apa_oltenia",
    "vital": "vital_baia_mare",
    "vital baia mare": "vital_baia_mare",
    "arabesque": "arabesque",
    "mathaus": "arabesque",
    "forit": "forit",
    "clinica sante": "clinica_sante",
    "sante": "clinica_sante",
    "bootcamp": "bootcamp_as_training",
    "bootcamp as": "bootcamp_as_training",
    "bootcamp education": "bootcamp_education",
    "apsap": "apsap",
    "grawe": "grawe_romania",
    "grawe romania": "grawe_romania",
    "metlife": "metlife_romania",
    "metlife romania": "metlife_romania",
    "metropolitan life": "metlife_romania",
    "credius": "credius_ifn",
    "credius ifn": "credius_ifn",
    "tbi": "tbi_bank",
    "tbi bank": "tbi_bank",
    "hzone": "hzone",
    "h-zone": "hzone",
    "it genetics": "it_genetics",
    "itgstore": "it_genetics",
    "rsd": "rsd_grup",
    "rsd grup": "rsd_grup",
    "aer conzal": "aer_conzal",
    "kival": "kival_blue",
    "kival blue": "kival_blue",
    "toolsbox": "toolsbox_services",
    "toolsbox services": "toolsbox_services",
    "epiesa": "euro_parts_distribution",
    "autohut": "euro_parts_distribution",
    "piese-auto.ro": "euro_parts_distribution",
    "piese auto": "euro_parts_distribution",
    "euro parts distribution": "euro_parts_distribution",
    "autosoft": "autosoft_tires_parts",
    "auto soft": "autosoft_tires_parts",
    "anvelope.ro": "webtrade_marketing_anvelope",
    "anvelope": "webtrade_marketing_anvelope",
    "webtrade marketing": "webtrade_marketing_anvelope",
    "primaria_constanta": "primaria_constanta",
    "primaria constanta": "primaria_constanta",
    "spit constanta": "primaria_constanta",
    "primaria_baia_mare": "primaria_baia_mare",
    "primaria baia mare": "primaria_baia_mare",
    "primaria_piatra_neamt": "primaria_piatra_neamt",
    "primaria piatra neamt": "primaria_piatra_neamt",
    "primaria piatra neamț": "primaria_piatra_neamt",
    "primaria_sibiu": "primaria_sibiu",
    "primaria sibiu": "primaria_sibiu",
    "primaria_ploiesti": "primaria_ploiesti",
    "primaria ploiesti": "primaria_ploiesti",
    "primaria ploiești": "primaria_ploiesti",
})


def _path() -> str:
    return os.getenv("PAYMENT_DESTINATION_REGISTRY_PATH") or _DEFAULT_PATH


def _paths() -> list[str]:
    configured = os.getenv("PAYMENT_DESTINATION_REGISTRY_PATHS")
    if configured:
        return [p.strip() for p in configured.split(os.pathsep) if p.strip()]
    if not os.path.isdir(_DEFAULT_DIR):
        return [_DEFAULT_PATH]
    return [
        os.path.join(_DEFAULT_DIR, name)
        for name in sorted(os.listdir(_DEFAULT_DIR))
        if name.endswith(".json") and name.startswith("payment_destination_registry_ro_")
    ]


def _empty_result(iban: str | None, claimed_brand: str | None, *, registry_has_brand_destinations: bool = False) -> Dict[str, Any]:
    return {
        "matched": False,
        "brand_matches": None,
        "cui_matches": None,
        "brand_id": None,
        "claimed_brand": claimed_brand,
        "registry_has_brand_destinations": registry_has_brand_destinations,
        "trust_tier": "T4_STRUCTURALLY_VALID_UNKNOWN" if iban else "missing",
        "confidence": "unknown",
        "can_contribute_to_safe": False,
        "client_distribution_allowed": False,
        "iban_masked_for_client": None,
        "source_kind": None,
        "source_refs": [],
    }


def _canonical_brand(brand: str | None) -> str | None:
    key = str(brand or "").strip().lower()
    return _BRAND_ALIASES.get(key) or key or None


def _norm_cui(cui: Any) -> str:
    if isinstance(cui, dict):
        cui = cui.get("value")
    return "".join(ch for ch in str(cui or "") if ch.isdigit())


def _name_key(value: Any) -> str:
    raw = str(value or "").translate(_DIACRITICS).lower()
    raw = _ENTITY_SUFFIX_RE.sub(" ", raw)
    raw = re.sub(r"[^a-z0-9]+", " ", raw)
    return " ".join(raw.split())


def _entry_name_keys(entry: Dict[str, Any], brand_id: str) -> set[str]:
    keys: set[str] = set()
    for value in (
        brand_id,
        str(brand_id or "").replace("_", " "),
        entry.get("display_name"),
        entry.get("legal_name"),
    ):
        key = _name_key(value)
        if key:
            keys.add(key)
    for alias in entry.get("aliases") or []:
        key = _name_key(alias)
        if key:
            keys.add(key)
    return keys


def _entry_brand_match_keys(entry: Dict[str, Any], brand_id: str) -> set[str]:
    keys: set[str] = set()
    for value in (
        brand_id,
        str(brand_id or "").replace("_", " "),
        entry.get("display_name"),
    ):
        key = _name_key(value)
        if key:
            keys.add(key)
    for alias in entry.get("aliases") or []:
        key = _name_key(alias)
        if key:
            keys.add(key)
    return keys


def _identity_key(candidate: Dict[str, Any]) -> tuple[str, str]:
    return (str(candidate.get("brand_id") or ""), str(candidate.get("cui") or ""))


def _looks_masked_iban_seed(raw: Any, *, literal_x_iban: bool = False) -> bool:
    normalized = str(raw or "").strip().upper().replace(" ", "")
    if literal_x_iban:
        return False
    return "XX" in normalized


@lru_cache(maxsize=1)
def _registry() -> Dict[str, Any]:
    entries: list[dict] = []
    for path in _paths():
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError):
            continue
        entries.extend(data.get("entries") or [])
        entries.extend(data.get("brands") or [])
    by_iban: Dict[str, list[Dict[str, Any]]] = {}
    brands_with_destinations: set[str] = set()
    brands_by_cui: Dict[str, set[str]] = {}
    brands_by_name: Dict[str, set[str]] = {}
    for entry in entries:
        brand_id = _canonical_brand(entry.get("brand_id"))
        if not brand_id:
            continue
        destinations = entry.get("payment_destinations") or []
        if destinations:
            brands_with_destinations.add(brand_id)
            cui_key = _norm_cui(entry.get("cui"))
            if cui_key:
                brands_by_cui.setdefault(cui_key, set()).add(brand_id)
            for name_key in _entry_name_keys(entry, brand_id):
                brands_by_name.setdefault(name_key, set()).add(brand_id)
        for destination in destinations:
            raw = destination.get("iban_normalized_backend_seed_only")
            if (
                _looks_masked_iban_seed(raw, literal_x_iban=bool(destination.get("literal_x_iban")))
                or destination.get("match_policy") == "reference_only_not_exact_match"
            ):
                continue
            normalized = normalize_iban(str(raw or ""))
            if not normalized or not validate_iban(normalized).valid_structure:
                continue
            can_safe = (
                destination.get("can_contribute_to_safe") is True
                and destination.get("review_status") == "active"
                and destination.get("match_policy") == "exact_hmac_match_required"
                and destination.get("trust_tier") in _ACTIVE_TIERS
                and destination.get("confidence") == "high"
            )
            by_iban.setdefault(normalized, []).append({
                "brand_id": brand_id,
                "display_name": entry.get("display_name"),
                "legal_name": entry.get("legal_name"),
                "cui": _norm_cui(entry.get("cui")),
                "name_keys": _entry_name_keys(entry, brand_id),
                "brand_match_keys": _entry_brand_match_keys(entry, brand_id),
                "trust_tier": destination.get("trust_tier"),
                "confidence": destination.get("confidence") or "unknown",
                "can_contribute_to_safe": bool(can_safe),
                "client_distribution_allowed": bool(destination.get("client_distribution_allowed")),
                "iban_masked_for_client": destination.get("iban_masked_for_client"),
                "source_kind": destination.get("source_kind"),
                "source_refs": destination.get("source_refs") or [],
                "scope": destination.get("scope"),
                "bank_name": destination.get("bank_name"),
            })
    return {
        "entries": entries,
        "by_iban": by_iban,
        "brands_with_destinations": brands_with_destinations,
        "brands_by_cui": brands_by_cui,
        "brands_by_name": brands_by_name,
    }


def reload_registry() -> None:
    _registry.cache_clear()


def brand_has_destinations(
    claimed_brand: str | None,
    *,
    cui: str | None = None,
    issuer_name: str | None = None,
) -> bool:
    canonical = _canonical_brand(claimed_brand)
    registry = _registry()
    if canonical and canonical in registry["brands_with_destinations"]:
        return True
    claimed_name_key = _name_key(claimed_brand)
    if claimed_name_key and claimed_name_key in registry["brands_by_name"]:
        return True
    cui_key = _norm_cui(cui)
    if cui_key and cui_key in registry["brands_by_cui"]:
        return True
    name_key = _name_key(issuer_name)
    return bool(name_key and name_key in registry["brands_by_name"])


def match_payment_destination(
    iban: str | None,
    *,
    claimed_brand: str | None = None,
    cui: str | None = None,
    issuer_name: str | None = None,
) -> Dict[str, Any]:
    normalized = normalize_iban(iban or "")
    canonical_claim = _canonical_brand(claimed_brand)
    has_brand_destinations = brand_has_destinations(
        canonical_claim,
        cui=cui,
        issuer_name=issuer_name,
    )
    if not normalized or not validate_iban(normalized).valid_structure:
        return _empty_result(iban, claimed_brand, registry_has_brand_destinations=has_brand_destinations)

    entries = _registry()["by_iban"].get(normalized) or []
    if not entries:
        return _empty_result(iban, claimed_brand, registry_has_brand_destinations=has_brand_destinations)

    cui_key = _norm_cui(cui)

    def score_entry(candidate: Dict[str, Any]) -> tuple[int, int, int]:
        cui_score = 1 if cui_key and candidate.get("cui") == cui_key else 0
        brand_score = 1 if canonical_claim and candidate["brand_id"] == canonical_claim else 0
        safe_score = 1 if candidate.get("can_contribute_to_safe") else 0
        return (cui_score, brand_score, safe_score)

    ranked = sorted(entries, key=score_entry, reverse=True)
    best_score = score_entry(ranked[0])
    best_entries = [candidate for candidate in ranked if score_entry(candidate) == best_score]
    if len(best_entries) > 1 and best_score[0] == 0 and best_score[1] == 0:
        best_identities = {_identity_key(candidate) for candidate in best_entries}
        if len(best_identities) == 1:
            best_entries = [best_entries[0]]
        else:
            return {
                **_empty_result(iban, claimed_brand, registry_has_brand_destinations=has_brand_destinations),
                "matched": True,
                "brand_matches": None,
                "cui_matches": None,
                "trust_tier": "ambiguous_shared_destination",
                "confidence": "ambiguous",
                "match_count": len(best_entries),
                "ambiguous": True,
            }
    entry = ranked[0]

    brand_matches = True
    if canonical_claim:
        claimed_name_key = _name_key(claimed_brand)
        brand_matches = entry["brand_id"] == canonical_claim or (
            bool(claimed_name_key) and claimed_name_key in (entry.get("brand_match_keys") or set())
        )
    entry_cui = entry.get("cui") or ""
    cui_matches = None
    if entry_cui and _norm_cui(cui):
        cui_matches = entry_cui == _norm_cui(cui)
    # A CUI mismatch normally means the IBAN belongs to a different entity than the
    # one claimed. But when this destination's own brand_id already matches the
    # claimed brand AND it is a curated official destination (can_contribute_to_safe),
    # the CUI divergence is a data gap — a stale/wrong seed CUI, a subsidiary, or an
    # updated registration — not a "belongs elsewhere" fraud. Paying a curated-official
    # IBAN sends money to the real brand regardless of the printed CUI, so keep the
    # genuine brand match; the CUI gap still blocks auto-safe below (verify, not safe).
    destination_is_official = bool(entry.get("can_contribute_to_safe"))
    if cui_matches is False and not (brand_matches and destination_is_official):
        brand_matches = False
    same_identity_entries = [
        candidate
        for candidate in entries
        if candidate.get("brand_id") == entry.get("brand_id")
        and (not entry_cui or candidate.get("cui") == entry_cui)
    ]
    has_conflicting_non_safe_context = any(
        not candidate.get("can_contribute_to_safe")
        for candidate in same_identity_entries
    )
    distinct_identities = {_identity_key(candidate) for candidate in entries}

    return {
        "matched": True,
        "brand_matches": bool(brand_matches),
        "cui_matches": cui_matches,
        "brand_id": entry["brand_id"],
        "claimed_brand": claimed_brand,
        "registry_has_brand_destinations": has_brand_destinations,
        "trust_tier": entry["trust_tier"],
        "confidence": entry["confidence"],
        "can_contribute_to_safe": bool(
            entry["can_contribute_to_safe"]
            # Exact registry CUI match proves the SAME legal entity, so it stands
            # in for a textual brand match (e.g. "Dante International SA" vs eMAG).
            and (brand_matches or cui_matches is True)
            # A divergent printed CUI keeps a brand-matched official destination out
            # of auto-safe: the payer verifies (SANB) instead of being told it is
            # confirmed. No longer a hard conflict, just unconfirmed.
            and cui_matches is not False
            and not has_conflicting_non_safe_context
        ),
        "client_distribution_allowed": entry["client_distribution_allowed"],
        "iban_masked_for_client": entry["iban_masked_for_client"],
        "source_kind": entry["source_kind"],
        "source_refs": entry["source_refs"],
        "scope": entry.get("scope"),
        "bank_name": entry.get("bank_name"),
        "match_count": len(entries),
        "ambiguous": len(distinct_identities) > 1 and best_score[0] == 0 and best_score[1] == 0,
        "conflicting_non_safe_context": has_conflicting_non_safe_context,
    }
