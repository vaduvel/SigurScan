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
    "omniasig": "omniasig",
    "allianz": "allianz_tiriac",
    "allianz tiriac": "allianz_tiriac",
    "allianz-tiriac": "allianz_tiriac",
    "allianz_tiriac": "allianz_tiriac",
    "emag_ads": "emag_ads_dante",
    "emag ads": "emag_ads_dante",
    "emag_ads_dante": "emag_ads_dante",
    "telekom": "telekom_romania_mobile",
    "telekom_romania_mobile": "telekom_romania_mobile",
    "cargus": "cargus",
    "urgent cargus": "cargus",
    "dpd": "dpd_romania",
    "dpd_romania": "dpd_romania",
    "dynamic parcel distribution": "dpd_romania",
    "dedeman": "dedeman",
    "raja": "raja",
    "rajac": "raja",
}


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


def _looks_masked_iban_seed(raw: Any) -> bool:
    normalized = str(raw or "").strip().upper().replace(" ", "")
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
    by_iban: Dict[str, Dict[str, Any]] = {}
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
            if _looks_masked_iban_seed(raw) or destination.get("match_policy") == "reference_only_not_exact_match":
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
            by_iban[normalized] = {
                "brand_id": brand_id,
                "display_name": entry.get("display_name"),
                "legal_name": entry.get("legal_name"),
                "cui": _norm_cui(entry.get("cui")),
                "trust_tier": destination.get("trust_tier"),
                "confidence": destination.get("confidence") or "unknown",
                "can_contribute_to_safe": bool(can_safe),
                "client_distribution_allowed": bool(destination.get("client_distribution_allowed")),
                "iban_masked_for_client": destination.get("iban_masked_for_client"),
                "source_kind": destination.get("source_kind"),
                "source_refs": destination.get("source_refs") or [],
                "scope": destination.get("scope"),
                "bank_name": destination.get("bank_name"),
            }
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

    entry = _registry()["by_iban"].get(normalized)
    if not entry:
        return _empty_result(iban, claimed_brand, registry_has_brand_destinations=has_brand_destinations)

    brand_matches = True
    if canonical_claim:
        brand_matches = entry["brand_id"] == canonical_claim
    entry_cui = entry.get("cui") or ""
    cui_matches = None
    if entry_cui and _norm_cui(cui):
        cui_matches = entry_cui == _norm_cui(cui)
    if cui_matches is False:
        brand_matches = False

    return {
        "matched": True,
        "brand_matches": bool(brand_matches),
        "cui_matches": cui_matches,
        "brand_id": entry["brand_id"],
        "claimed_brand": claimed_brand,
        "registry_has_brand_destinations": has_brand_destinations,
        "trust_tier": entry["trust_tier"],
        "confidence": entry["confidence"],
        "can_contribute_to_safe": bool(entry["can_contribute_to_safe"] and brand_matches),
        "client_distribution_allowed": entry["client_distribution_allowed"],
        "iban_masked_for_client": entry["iban_masked_for_client"],
        "source_kind": entry["source_kind"],
        "source_refs": entry["source_refs"],
        "scope": entry.get("scope"),
        "bank_name": entry.get("bank_name"),
    }
