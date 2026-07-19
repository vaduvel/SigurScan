import json
import os
import re
import unicodedata
import urllib.parse
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import tldextract
import hashlib


REPUTATION_STATUS_PRIORITY = {
    "error": 0,
    "unknown": 1,
    "clean": 2,
    "suspicious": 3,
    "malicious": 4,
}


def _coerce_reputation_status(value: Any) -> str:
    status = (str(value).strip().lower() if value is not None else "")
    if status in REPUTATION_STATUS_PRIORITY:
        return status
    return "unknown"


def _coerce_reputation_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _merge_reputation_status(existing: str, candidate: str) -> str:
    existing_status = _coerce_reputation_status(existing)
    candidate_status = _coerce_reputation_status(candidate)
    if existing_status == candidate_status:
        return existing_status
    existing_rank = REPUTATION_STATUS_PRIORITY.get(existing_status, 1)
    candidate_rank = REPUTATION_STATUS_PRIORITY.get(candidate_status, 1)
    return candidate_status if candidate_rank > existing_rank else existing_status


def _resolve_path(raw_path: Optional[str], fallback: str) -> str:
    if raw_path:
        candidate = Path(raw_path).expanduser()
        if not candidate.is_absolute():
            candidate = (Path(__file__).resolve().parent.parent / candidate).resolve()
    else:
        candidate = Path(fallback)
        if not candidate.is_absolute():
            candidate = (Path(__file__).resolve().parent.parent / candidate).resolve()
    return str(candidate)


def _load_json_map(raw_path: Optional[str], fallback: Dict[str, Any]) -> Dict[str, Any]:
    path = _resolve_path(raw_path, str((Path(__file__).resolve().parent / "brand_knowledge_pack.json")))
    try:
        if not os.path.exists(path):
            return dict(fallback)
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                return data
    except Exception as exc:
        print(f"Failed to load brand knowledge from {path}: {exc}")
    return dict(fallback)


def _coerce_str_list(values: Any) -> List[str]:
    if not values:
        return []
    if isinstance(values, (str, int, float)):
        values = [values]
    out: List[str] = []
    for item in values:
        if not item:
            continue
        if isinstance(item, dict):
            item = (
                item.get("text")
                or item.get("sample_text")
                or item.get("example")
                or item.get("value")
                or ""
            )
        text = str(item).strip()
        if text:
            out.append(text)
    return out


def _dedupe_preserve_order(values: List[str]) -> List[str]:
    seen = set()
    deduped: List[str] = []
    for value in values:
        if not value:
            continue
        if value in seen:
            continue
        seen.add(value)
        deduped.append(value)
    return deduped


def _normalize_atlas_family(raw: Any) -> Optional[Dict[str, Any]]:
    """Normalize mixed research schemas into the runtime semantic contract.

    Runtime knowledge deliberately excludes verdict-like oracle fields. Atlas
    families may enrich semantic_review, but only verdict_gate emits a label.
    """

    if not isinstance(raw, dict):
        return None

    family_id = str(raw.get("id") or raw.get("family_id") or raw.get("scenario_id") or "").strip()
    family_name = str(raw.get("family") or raw.get("title") or raw.get("name") or "").strip()
    if not family_id or not family_name:
        return None

    signals = _coerce_str_list(raw.get("signals"))
    examples = _coerce_str_list(raw.get("examples"))
    hook_parts = _coerce_str_list(
        [
            raw.get("hook"),
            raw.get("claimed_brand_or_role"),
            *signals,
            *examples,
        ]
    )
    match_parts = _coerce_str_list(
        [
            raw.get("hook"),
            raw.get("claimed_brand_or_role"),
            family_name,
            *signals,
        ]
    )
    asks_for = _coerce_str_list(raw.get("asks_for") or raw.get("requested_asset"))

    normalized = {
        "id": family_id,
        "title": str(raw.get("title") or family_name).strip(),
        "family": family_name,
        "hook": " | ".join(_dedupe_preserve_order(hook_parts)),
        "match_text": " | ".join(_dedupe_preserve_order(match_parts)),
        "asks_for": _dedupe_preserve_order(asks_for),
        "safe_actions": _dedupe_preserve_order(_coerce_str_list(raw.get("safe_actions"))),
        "channels": _dedupe_preserve_order(_coerce_str_list(raw.get("channels"))),
        "claimed_brand_or_role": str(raw.get("claimed_brand_or_role") or "").strip() or None,
        "requested_asset": _dedupe_preserve_order(_coerce_str_list(raw.get("requested_asset"))),
        "signals": _dedupe_preserve_order(signals),
        "sources": _dedupe_preserve_order(_coerce_str_list(raw.get("sources") or raw.get("source_ids"))),
        "examples": _dedupe_preserve_order(examples),
    }

    required_token_groups = raw.get("required_token_groups")
    if isinstance(required_token_groups, list):
        normalized_groups = [
            _dedupe_preserve_order(_coerce_str_list(group))
            for group in required_token_groups
            if isinstance(group, list)
        ]
        normalized_groups = [group for group in normalized_groups if group]
        if normalized_groups:
            normalized["required_token_groups"] = normalized_groups

    # Preserve auditable knowledge metadata in evidence without turning the
    # atlas into a second verdict engine. verdict_gate does not consume these
    # fields unless they are explicitly mapped through the evidence contract.
    for field in ("structured_signals", "verification_sources", "source_refs"):
        value = raw.get(field)
        if isinstance(value, list):
            normalized[field] = [item for item in value if isinstance(item, dict)]

    payment_risk = raw.get("payment_risk")
    if isinstance(payment_risk, dict):
        normalized["payment_risk"] = dict(payment_risk)

    scan_rule_ids = raw.get("scan_rule_ids")
    if isinstance(scan_rule_ids, list):
        normalized["scan_rule_ids"] = _dedupe_preserve_order(_coerce_str_list(scan_rule_ids))

    return normalized


def _merge_map_of_lists(*items: Dict[str, List[str]]) -> Dict[str, List[str]]:
    merged: Dict[str, List[str]] = {}
    for source in items:
        for key, values in source.items():
            current = merged.setdefault(key, [])
            for value in _coerce_str_list(values):
                normalized = value.strip().lower()
                if normalized and normalized not in current:
                    current.append(normalized)
    return merged


def _merge_map_of_strings(*items: Dict[str, str]) -> Dict[str, str]:
    merged: Dict[str, str] = {}
    for source in items:
        for key, value in source.items():
            if isinstance(value, str) and value.strip():
                merged[key] = value.strip()
    return merged


def _merge_aliases(*items: Dict[str, List[str]]) -> Dict[str, List[str]]:
    merged: Dict[str, List[str]] = {}
    for source in items:
        for key, values in source.items():
            bucket = merged.setdefault(key, [])
            for value in _coerce_str_list(values):
                normalized = value.strip().lower()
                if normalized and normalized not in bucket:
                    bucket.append(normalized)
    return merged


def _pattern_from_aliases(aliases: List[str]) -> str:
    patterns: List[str] = []
    for alias in aliases:
        cleaned = re.sub(r"\s+", " ", str(alias).strip().lower())
        if not cleaned:
            continue
        tokenized = [re.escape(part) for part in cleaned.split()]
        if not tokenized:
            continue
        tokenized = [part for part in tokenized if part]
        if not tokenized:
            continue
        patterns.append(r"\b" + r"\s*".join(tokenized) + r"\b")
    return "|".join(patterns)


DEFAULT_BRAND_KNOWLEDGE = {
    "brand_registry": {
        "ANAF": ["anaf.ro", "mfinante.gov.ro", "mfinante.ro"],
        "Revolut": ["revolut.com", "revolut.me", "revolut.space"],
        "ING": ["ing.ro", "ing.com", "ingbusiness.ro"],
        "Banca Transilvania": [
            "bancatransilvania.ro",
            "btpay.ro",
            "neo-bt.ro",
            "neo.bancatransilvania.ro",
            "bt.ro",
        ],
        "BCR": ["bcr.ro", "george.bcr.ro"],
        "FAN Courier": ["fancourier.ro", "fan.ro", "fanbox.ro", "fan-courier.ro"],
        "Posta Romana": ["posta-romana.ro"],
        "Sameday": ["sameday.ro", "sameday.delivery", "easybox.ro"],
        "DHL": ["dhl.ro", "dhl.com", "dhl-express.ro"],
        "eMAG": ["emag.ro", "emag.delivery"],
        "Uber": ["uber.com", "ubereats.com"],
        "Bolt": ["bolt.eu"],
        "Fashion Days": ["fashiondays.ro"],
        "Mega Image": ["mega-image.ro"],
        "DPD": ["dpd.com"],
        "Netflix": ["netflix.com"],
        "Spotify": ["spotify.com"],
        "Electrica": ["electricafurnizare.ro"],
        "YOXO": ["yoxo.ro", "buyback.yoxo.ro", "orange.ro"],
        "OLX": ["olx.ro"],
        "Google": ["google.com", "google.ro", "gmail.com"],
        "Microsoft": ["microsoft.com", "outlook.com", "office.com", "live.com"],
        "Meta": ["meta.com", "facebook.com", "instagram.com", "whatsapp.com"],
    },
    "brand_domain_exceptions": {
        "Uber": ["sng.link", "uber.link", "app.link", "branch.link", "bnc.lt"],
        "eMAG": ["sng.link", "app.link", "branch.link", "bnc.lt"],
    },
    "trusted_base_names": {
        "anaf": "ANAF",
        "mfinante": "ANAF",
        "revolut": "Revolut",
        "ing": "ING",
        "ingbusiness": "ING",
        "bancatransilvania": "Banca Transilvania",
        "btpay": "Banca Transilvania",
        "neo-bt": "Banca Transilvania",
        "bcr": "BCR",
        "george": "BCR",
        "fancourier": "FAN Courier",
        "fanbox": "FAN Courier",
        "fan-courier": "FAN Courier",
        "fan": "FAN Courier",
        "posta-romana": "Posta Romana",
        "sameday": "Sameday",
        "dhl": "DHL",
        "dhl-express": "DHL",
        "emag": "eMAG",
        "uber": "Uber",
        "ubereats": "Uber",
        "bolt": "Bolt",
        "fashiondays": "Fashion Days",
        "mega-image": "Mega Image",
        "megaimage": "Mega Image",
        "dpd": "DPD",
        "netflix": "Netflix",
        "spotify": "Spotify",
        "electrica": "Electrica",
        "electricafurnizare": "Electrica",
        "yoxo": "YOXO",
        "orange": "YOXO",
        "olx": "OLX",
        "google": "Google",
        "gmail": "Google",
        "microsoft": "Microsoft",
        "outlook": "Microsoft",
        "office": "Microsoft",
        "live": "Microsoft",
        "facebook": "Meta",
        "instagram": "Meta",
        "whatsapp": "Meta",
        "meta": "Meta",
    },
    "brand_aliases": {
        "ANAF": ["anaf", "spv", "spatiul privat"],
        "Posta Romana": ["posta romana", "posta"],
        "Banca Transilvania": ["banca transilvania", "bt pay", "bt"],
        "FAN Courier": ["fan courier", "fan"],
        "Sameday": ["sameday", "easybox"],
        "Uber": ["uber", "uber eats"],
        "Bolt": ["bolt"],
        "Fashion Days": ["fashion days", "fashiondays"],
        "Mega Image": ["mega image", "mega-image"],
        "DPD": ["dpd"],
        "Netflix": ["netflix"],
        "Spotify": ["spotify"],
        "Electrica": ["electrica", "electrica furnizare"],
        "YOXO": ["yoxo", "buy back yoxo"],
        "Revolut": ["revolut"],
        "BCR": ["bcr"],
        "Banca Transilvania": ["bt"],
        "Google": ["google"],
        "Microsoft": ["microsoft", "outlook", "office"],
        "Meta": ["meta", "facebook", "instagram", "whatsapp"],
    },
}

_brand_knowledge_path = _resolve_path(os.getenv("SCAM_ATLAS_BRAND_KNOWLEDGE_PATH"), "data/brand_knowledge_pack.json")
_loaded_brand_knowledge = _load_json_map(_brand_knowledge_path, DEFAULT_BRAND_KNOWLEDGE)

_official_registry_updates = [
    entry
    for entry in _loaded_brand_knowledge.get("official_registry_updates", [])
    if isinstance(entry, dict)
]


def _normalise_host(value: Any) -> str:
    return str(value or "").strip().lower().strip(".")


def _normalise_path(value: Any) -> str:
    path = str(value or "").strip()
    if not path:
        return ""
    if not path.startswith("/"):
        path = f"/{path}"
    return path


def _url_path_from_parts(url: Optional[str] = None, path: Optional[str] = None) -> str:
    if path:
        return _normalise_path(path)
    if not url:
        return ""
    try:
        return _normalise_path(urllib.parse.urlparse(url).path)
    except Exception:
        return ""


def _official_entry_display_name(entry: Dict[str, Any]) -> str:
    return str(entry.get("display_name") or entry.get("brand") or entry.get("brand_id") or "").strip()


def _official_entry_tokens(entry: Dict[str, Any]) -> List[str]:
    tokens = [
        _official_entry_display_name(entry),
        str(entry.get("legal_entity") or "").strip(),
    ]
    tokens.extend(_coerce_str_list(entry.get("entity_context_tokens")))
    tokens.extend(_coerce_str_list(entry.get("aliases")))
    return _dedupe_preserve_order([token for token in tokens if token])


def _ascii_fold(value: str) -> str:
    folded = unicodedata.normalize("NFKD", value or "")
    return "".join(char for char in folded if not unicodedata.combining(char))


def _compact_token(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", _ascii_fold(str(value or "")).lower())


def _lookalike_tokens_for_official_entry(entry: Dict[str, Any]) -> List[str]:
    tokens: List[str] = []
    generic_public_labels = {
        "directia",
        "institutia",
        "inspectoratul",
        "judetul",
        "prefectului",
        "prefectura",
        "publica",
        "romania",
        "sanatate",
    }
    for domain in (
        _coerce_str_list(entry.get("official_domains"))
        + _coerce_str_list(entry.get("subdomains"))
        + _coerce_str_list(entry.get("delegated_domains"))
        + _coerce_str_list(entry.get("exact_hosts"))
    ):
        labels = [
            label
            for label in _normalise_host(domain).split(".")
            if len(label) >= 4
            and label not in {"www", "gov", "edu", "com", "net", "org"}
            and label not in generic_public_labels
        ]
        tokens.extend(labels)
    for alias in _official_entry_tokens(entry):
        compact = _compact_token(alias)
        if len(compact) >= 5:
            tokens.append(compact)
        words = [
            _compact_token(word)
            for word in re.split(r"[^0-9A-Za-zĂÂÎȘȚăâîșț]+", alias)
            if len(_compact_token(word)) >= 4
        ]
        tokens.extend(word for word in words if word not in generic_public_labels)
        if 1 < len(words) <= 3:
            tokens.append("".join(words))
    if entry.get("category") == "prefecture":
        display = _official_entry_display_name(entry)
        county_match = re.search(r"jude[țt]ul\s+(.+)$", display, flags=re.IGNORECASE)
        if county_match:
            county = _compact_token(county_match.group(1))
            if len(county) >= 4:
                tokens.append(f"prefectura{county}")
    return _dedupe_preserve_order([token for token in tokens if token])


def _display_name_preference_score(display_name: str) -> tuple[int, int]:
    text = str(display_name or "").strip()
    lower = _ascii_fold(text).lower()
    official_words = sum(
        1
        for word in (
            "directia",
            "institutia",
            "inspectoratul",
            "consiliul",
            "autoritatea",
        )
        if word in lower
    )
    return (official_words, len(text))


OFFICIAL_REGISTRY_POLICIES_BY_BRAND: Dict[str, List[Dict[str, Any]]] = {}
OFFICIAL_REGISTRY_ALIASES_BY_BRAND: Dict[str, List[str]] = {}
for entry in _official_registry_updates:
    display_name = _official_entry_display_name(entry)
    if not display_name:
        continue
    OFFICIAL_REGISTRY_POLICIES_BY_BRAND.setdefault(display_name, []).append(entry)
    OFFICIAL_REGISTRY_ALIASES_BY_BRAND.setdefault(display_name, [])
    OFFICIAL_REGISTRY_ALIASES_BY_BRAND[display_name].extend(_official_entry_tokens(entry))

OFFICIAL_REGISTRY_ALIASES_BY_BRAND = {
    brand: _dedupe_preserve_order(tokens)
    for brand, tokens in OFFICIAL_REGISTRY_ALIASES_BY_BRAND.items()
}

OFFICIAL_REGISTRY_LOOKALIKE_TOKENS: Dict[str, str] = {}
for entry in _official_registry_updates:
    display_name = _official_entry_display_name(entry)
    if not display_name:
        continue
    for token in _lookalike_tokens_for_official_entry(entry):
        current = OFFICIAL_REGISTRY_LOOKALIKE_TOKENS.get(token)
        if current is None or _display_name_preference_score(display_name) > _display_name_preference_score(current):
            OFFICIAL_REGISTRY_LOOKALIKE_TOKENS[token] = display_name

BRAND_ID_TO_DISPLAY_NAME: Dict[str, str] = {
    str(entry.get("brand_id") or "").strip(): str(entry.get("display_name") or "").strip()
    for entry in _official_registry_updates
    if str(entry.get("brand_id") or "").strip() and str(entry.get("display_name") or "").strip()
}
BRAND_WARNING_RULES: Dict[str, Dict[str, Any]] = {}
for entry in _loaded_brand_knowledge.get("brand_warnings", []):
    if not isinstance(entry, dict):
        continue
    brand_id = str(entry.get("brand_id") or "").strip()
    if not brand_id:
        continue
    BRAND_WARNING_RULES[brand_id] = entry

BRAND_REGISTRY: Dict[str, List[str]] = _merge_map_of_lists(
    DEFAULT_BRAND_KNOWLEDGE["brand_registry"],
    {
        k: _coerce_str_list(v)
        for k, v in _loaded_brand_knowledge.get("brand_registry", {}).items()
        if isinstance(k, str)
    },
)

BRAND_DOMAIN_EXCEPTIONS: Dict[str, List[str]] = _merge_map_of_lists(
    DEFAULT_BRAND_KNOWLEDGE["brand_domain_exceptions"],
    {
        k: _coerce_str_list(v)
        for k, v in _loaded_brand_knowledge.get("brand_domain_exceptions", {}).items()
        if isinstance(k, str)
    },
)

TRUSTED_BASE_NAMES: Dict[str, str] = _merge_map_of_strings(
    DEFAULT_BRAND_KNOWLEDGE["trusted_base_names"],
    {
        k: str(v)
        for k, v in _loaded_brand_knowledge.get("trusted_base_names", {}).items()
        if isinstance(k, str) and isinstance(v, str)
    },
)

_loaded_aliases = _merge_aliases(
    DEFAULT_BRAND_KNOWLEDGE["brand_aliases"],
    {
        k: _coerce_str_list(v)
        for k, v in _loaded_brand_knowledge.get("brand_aliases", {}).items()
        if isinstance(k, str)
    },
)

if not _brand_knowledge_path or not os.path.exists(_brand_knowledge_path):
    print(
        "Brand knowledge pack not found; fallback to embedded defaults from backend/services/scam_atlas.py"
    )

from services.scam_atlas_patterns import (
    SUSPICIOUS_PATH_SEGMENTS,
    SUSPICIOUS_QUERY_KEYS,
    TRACKING_QUERY_KEYS,
    SUSPICIOUS_TOP_LEVEL_DOMAINS,
    HIGH_RISK_PORTS,
    SENSITIVE_CREDENTIAL_PATTERNS,
    SENSITIVE_WHATSAPP_PATTERNS,
    SENSITIVE_PAYMENT_PATTERNS,
    MALWARE_APK_PATTERNS,
    SENSITIVE_QR_PATTERNS,
    SENSITIVE_SEXTORTION_PATTERNS,
    SENSITIVE_SIM_SWAP_PATTERNS,
    OLX_CARD_PATTERNS,
    REMOTE_ACCESS_PATTERNS,
    URGENCY_MANIPULATION_PATTERNS,
    MANIPULATION_REWARD_PATTERNS,
    DELIVERY_MANIPULATION_PATTERNS,
    HIGH_RISK_TEXT_ONLY_SIGNAL_MARKERS,
    HIGH_RISK_TEXT_ONLY_ASK_MARKERS,
    KNOWN_DEEPLINK_PROVIDERS,
)
from services.ro_morphology import strip_diacritics as _strip_diacritics


def _morph_fold(text: str) -> str:
    # P-MORPH-WIRE: fold Romanian diacritics before the semantic keyword regexes
    # so scam phrasings written with diacritics (e.g. "transferă", "plătește")
    # match the same patterns as their ASCII forms. Diacritic folding only maps
    # ă→a / ș→s / ț→t etc.; it never invents words, and the patterns already carry
    # ASCII alternatives, so it can only add recall, not change which words exist.
    # Escape hatch (default ON) for instant rollback without a revert.
    if os.getenv("SCAM_ATLAS_MORPH_FOLD", "1").strip().lower() in {"0", "false", "no", "off"}:
        return text or ""
    return _strip_diacritics(text or "")


# Local repo seed path for the Romania corpus. This replaces the old absolute path from the
# legacy workspace and keeps ScamAtlas reproducible across machines and deployments.
SEED_PATH = _resolve_path(
    os.getenv("SCAM_ATLAS_SEED_PATH"),
    "data/scam_atlas_ro_2025_2026_seed.json",
)
DEFAULT_EXTRA_SEED_PATHS = ("data/scam_atlas_impersonation_seed.json",)

# Offer-advance subfamilies (romance/stranded advance-fee + marketplace seller
# advance). They correct broad family labels on cleanly-written money requests.
# Classification changes can alter user-facing explanations, so the seed loads
# only behind this default-OFF flag until the shared offer ThreatEnrichment path
# and rollout measurement are both accepted.
OFFER_ADVANCE_SEED_PATH = "data/scam_atlas_offer_advance_seed.json"


def _offer_advance_families_enabled() -> bool:
    value = str(os.getenv("SCAM_ATLAS_OFFER_ADVANCE_FAMILIES", "0")).strip().lower()
    return value in {"1", "true", "yes", "on"}


def _extra_seed_paths() -> List[str]:
    raw_paths = list(DEFAULT_EXTRA_SEED_PATHS)
    if _offer_advance_families_enabled():
        raw_paths.append(OFFER_ADVANCE_SEED_PATH)
    env_value = os.getenv("SCAM_ATLAS_EXTRA_SEED_PATHS")
    if env_value:
        raw_paths.extend(item.strip() for item in env_value.split(os.pathsep) if item.strip())

    resolved: List[str] = []
    seen = set()
    for raw_path in raw_paths:
        path = _resolve_path(raw_path, raw_path)
        if path not in seen:
            seen.add(path)
            resolved.append(path)
    return resolved


def _build_brand_mention_patterns(
    brand_registry: Dict[str, List[str]],
    aliases: Dict[str, List[str]],
) -> Dict[str, re.Pattern]:
    patterns: Dict[str, re.Pattern] = {}
    brand_names = _dedupe_preserve_order(
        list(brand_registry.keys()) + list(OFFICIAL_REGISTRY_ALIASES_BY_BRAND.keys())
    )
    for brand_name in brand_names:
        candidates = aliases.get(brand_name, [])
        candidates = candidates + OFFICIAL_REGISTRY_ALIASES_BY_BRAND.get(brand_name, [])
        candidates = _dedupe_preserve_order(candidates + [brand_name])
        pattern = _pattern_from_aliases(candidates)
        if pattern:
            patterns[brand_name] = re.compile(pattern, re.IGNORECASE)
    return patterns


BRAND_REGISTRY = _merge_map_of_lists(BRAND_REGISTRY)
BRAND_DOMAIN_EXCEPTIONS = _merge_map_of_lists(BRAND_DOMAIN_EXCEPTIONS)
TRUSTED_BASE_NAMES = dict(TRUSTED_BASE_NAMES)
_loaded_aliases = _merge_aliases(_loaded_aliases)
BRAND_MENTION_PATTERNS = _build_brand_mention_patterns(BRAND_REGISTRY, _loaded_aliases)


def _known_brand_names() -> List[str]:
    return _dedupe_preserve_order(
        list(BRAND_REGISTRY.keys())
        + list(BRAND_DOMAIN_EXCEPTIONS.keys())
        + list(OFFICIAL_REGISTRY_POLICIES_BY_BRAND.keys())
        + list(OFFICIAL_REGISTRY_ALIASES_BY_BRAND.keys())
    )


def _canonical_brand_candidates(claimed_brand: Optional[str]) -> List[str]:
    raw = str(claimed_brand or "").strip()
    if not raw:
        return []

    raw_lower = raw.lower()
    compact = _compact_token(raw)
    candidates: List[str] = []

    def add(brand_name: Optional[str]) -> None:
        if brand_name and brand_name not in candidates:
            candidates.append(brand_name)

    for brand_name in _known_brand_names():
        if brand_name == raw or brand_name.lower() == raw_lower:
            add(brand_name)

    for base_name, brand_name in TRUSTED_BASE_NAMES.items():
        if compact and compact == _compact_token(base_name):
            add(brand_name)

    for brand_id, display_name in BRAND_ID_TO_DISPLAY_NAME.items():
        if compact and compact == _compact_token(brand_id):
            add(display_name)

    for brand_name in _known_brand_names():
        aliases = _dedupe_preserve_order(
            _loaded_aliases.get(brand_name, [])
            + OFFICIAL_REGISTRY_ALIASES_BY_BRAND.get(brand_name, [])
            + [brand_name]
        )
        for alias in aliases:
            if compact and compact == _compact_token(alias):
                add(brand_name)
                break

    return candidates


def _get_registrable_domain(extracted: "tldextract.ExtractResult") -> str:
    domain = getattr(extracted, "top_domain_under_public_suffix", "")
    if isinstance(domain, str) and domain.strip():
        return domain.strip().lower()
    return ""


def _candidate_domain_values(reg_domain: str, hostname: Optional[str] = None) -> List[str]:
    candidates: List[str] = []
    for candidate in (reg_domain, hostname):
        normalized = _normalise_host(candidate)
        if not normalized:
            continue
        candidates.append(normalized)
        extracted = tldextract.extract(normalized)
        extracted_domain = _get_registrable_domain(extracted)
        if extracted_domain and extracted_domain != normalized:
            candidates.append(extracted_domain)
    return _dedupe_preserve_order(candidates)


def _host_matches_domain(candidate: str, allowed: str) -> bool:
    candidate = _normalise_host(candidate)
    allowed = _normalise_host(allowed)
    return bool(candidate and allowed and (candidate == allowed or candidate.endswith(f".{allowed}")))


def _official_policy_allows_url(
    entry: Dict[str, Any],
    reg_domain: str,
    hostname: Optional[str] = None,
    url: Optional[str] = None,
    path: Optional[str] = None,
) -> bool:
    if not bool(entry.get("can_contribute_to_safe", True)):
        return False

    normalized_host = _normalise_host(hostname)
    normalized_path = _url_path_from_parts(url=url, path=path)
    match_policy = str(entry.get("match_policy") or "").strip().lower()
    shared_host = bool(entry.get("shared_host"))
    exact_hosts = [_normalise_host(item) for item in _coerce_str_list(entry.get("exact_hosts"))]
    exact_hosts = [item for item in exact_hosts if item]
    official_domains = [_normalise_host(item) for item in _coerce_str_list(entry.get("official_domains"))]
    delegated_domains = [_normalise_host(item) for item in _coerce_str_list(entry.get("delegated_domains"))]
    path_prefixes = [_normalise_path(item).lower() for item in _coerce_str_list(entry.get("path_prefixes"))]
    path_prefixes = [item for item in path_prefixes if item]

    if match_policy == "exact_host":
        return bool(normalized_host and normalized_host in exact_hosts)

    if shared_host or match_policy in {"shared_host_plus_path_prefix", "path_scoped"}:
        if not normalized_host or not path_prefixes:
            return False
        host_allowed = (
            normalized_host in exact_hosts
            or any(_host_matches_domain(normalized_host, domain) for domain in official_domains)
        )
        if not host_allowed:
            return False
        lowered_path = normalized_path.lower()
        return any(lowered_path == prefix.rstrip("/") or lowered_path.startswith(prefix) for prefix in path_prefixes)

    candidates = _candidate_domain_values(reg_domain, hostname)
    for allowed in [*official_domains, *delegated_domains]:
        if any(_host_matches_domain(candidate, allowed) for candidate in candidates):
            return True
    if exact_hosts:
        return bool(normalized_host and normalized_host in exact_hosts)
    return False

class ScamAtlasEngine:
    def __init__(self):
        self.families = []
        self.load_seed_data()

    def load_seed_data(self):
        self.families = []
        for path in [SEED_PATH, *_extra_seed_paths()]:
            if not os.path.exists(path):
                print(f"Scam Atlas seed not found at {path}")
                continue
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    raw_families = data.get("scam_families", []) if isinstance(data, dict) else data
                    self.families.extend(
                        normalized
                        for raw in (raw_families if isinstance(raw_families, list) else [])
                        if (normalized := _normalize_atlas_family(raw)) is not None
                    )
            except Exception as e:
                print(f"Error loading Scam Atlas seed from {path}: {e}")

    def _is_whitelisted_domain(self, reg_domain: str, hostname: str | None = None) -> bool:
        if not reg_domain and not hostname:
            return False

        candidates: List[str] = []
        for candidate in (reg_domain, hostname):
            if not candidate:
                continue
            normalized = str(candidate).strip().lower().strip(".")
            if not normalized:
                continue
            candidates.append(normalized)
            extracted = tldextract.extract(normalized)
            extracted_domain = _get_registrable_domain(extracted)
            if extracted_domain and extracted_domain != normalized:
                candidates.append(extracted_domain)

        for allowed_domains in BRAND_REGISTRY.values():
            for allowed in allowed_domains:
                allowed_domain = allowed.lower()
                for candidate in candidates:
                    if candidate == allowed_domain or candidate.endswith(f".{allowed_domain}"):
                        return True
        return False

    def _is_brand_allowed_domain(
        self,
        claimed_brand: str,
        reg_domain: str,
        hostname: str | None = None,
        url: str | None = None,
        path: str | None = None,
    ) -> bool:
        if not claimed_brand:
            return False

        candidates = _candidate_domain_values(reg_domain, hostname)
        for canonical_brand in _canonical_brand_candidates(claimed_brand):
            allowed_domains = set(BRAND_REGISTRY.get(canonical_brand, []))
            allowed_domains.update(BRAND_DOMAIN_EXCEPTIONS.get(canonical_brand, []))
            for allowed_domain in allowed_domains:
                allowed = _normalise_host(allowed_domain)
                if not allowed:
                    continue
                for candidate in candidates:
                    if _host_matches_domain(candidate, allowed):
                        return True

            for entry in OFFICIAL_REGISTRY_POLICIES_BY_BRAND.get(canonical_brand, []):
                if _official_policy_allows_url(entry, reg_domain, hostname=hostname, url=url, path=path):
                    return True
        return False

    def _is_brand_delegated_deeplink(
        self,
        claimed_brand: str,
        reg_domain: str,
        hostname: str | None = None,
    ) -> bool:
        if not claimed_brand or not reg_domain or reg_domain not in KNOWN_DEEPLINK_PROVIDERS:
            return False
        normalized_host = (hostname or "").strip().lower().strip(".")
        if not normalized_host.endswith(f".{reg_domain}"):
            return False
        subdomain = normalized_host[: -(len(reg_domain) + 1)].split(".")[-1]
        if not subdomain:
            return False
        brand_tokens = {str(claimed_brand).strip().lower().replace(" ", ""), str(claimed_brand).strip().lower()}
        for canonical_brand in _canonical_brand_candidates(claimed_brand):
            brand_tokens.add(canonical_brand.strip().lower().replace(" ", ""))
            brand_tokens.add(canonical_brand.strip().lower())
            brand_tokens.update(self._claimed_brand_base_candidates(canonical_brand))
            brand_tokens.update(alias.replace(" ", "") for alias in _loaded_aliases.get(canonical_brand, []))
        return subdomain.replace("-", "").replace("_", "") in {
            token.replace("-", "").replace("_", "")
            for token in brand_tokens
            if token
        }

    def _is_context_allowed_domain(
        self,
        reg_domain: str,
        hostname: str | None = None,
        claimed_brand: Optional[str] = None,
        url: Optional[str] = None,
        path: Optional[str] = None,
    ) -> bool:
        if self._is_whitelisted_domain(reg_domain, hostname=hostname):
            return True
        if claimed_brand and self._is_brand_allowed_domain(
            claimed_brand,
            reg_domain,
            hostname,
            url=url,
            path=path,
        ):
            return True
        if claimed_brand and self._is_brand_delegated_deeplink(claimed_brand, reg_domain, hostname):
            return True
        return False

    def _is_ip_address(self, hostname: str) -> bool:
        if not hostname:
            return False
        return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", hostname))

    def _claimed_brand_base_candidates(self, claimed_brand: Optional[str]) -> List[str]:
        if not claimed_brand:
            return []
        canonical_brands = set(_canonical_brand_candidates(claimed_brand))
        return [base for base, brand in TRUSTED_BASE_NAMES.items() if brand in canonical_brands]

    def detect_claimed_brand(self, text: str) -> Optional[str]:
        """
        Detects if a trusted brand name is mentioned in the text.
        """
        best_brand: Optional[str] = None
        best_specificity = -1
        for brand_name, pattern in BRAND_MENTION_PATTERNS.items():
            if pattern.search(text):
                aliases = _dedupe_preserve_order(
                    _loaded_aliases.get(brand_name, [])
                    + OFFICIAL_REGISTRY_ALIASES_BY_BRAND.get(brand_name, [])
                    + [brand_name]
                )
                matched_lengths = [
                    len(alias)
                    for alias in aliases
                    if alias and (alias_pattern := _pattern_from_aliases([alias]))
                    and re.search(alias_pattern, text, re.IGNORECASE)
                ]
                specificity = max(matched_lengths) if matched_lengths else len(brand_name)
                canonical_pattern = _pattern_from_aliases([brand_name])
                if canonical_pattern and re.search(canonical_pattern, text, re.IGNORECASE):
                    specificity += 1000
                if specificity > best_specificity:
                    best_brand = brand_name
                    best_specificity = specificity
        return best_brand

    def check_brand_mismatch(self, claimed_brand: str, urls: List[Dict[str, Any]]) -> Tuple[bool, Optional[str]]:
        """
        Verifies if there is a mismatch: a trusted brand is claimed, but the links do not resolve
        to its official domain(s).
        Returns (has_mismatch, offending_registered_domain)
        """
        if not claimed_brand or not _canonical_brand_candidates(claimed_brand):
            return False, None

        for url_info in urls:
            reg_domain = (url_info.get("final_registered_domain") or url_info.get("registered_domain") or "").lower()
            hostname = (url_info.get("final_hostname") or url_info.get("hostname") or "").lower()
            final_url = url_info.get("final_url") or url_info.get("url") or ""
            if not hostname and final_url:
                parsed = urllib.parse.urlparse(final_url)
                hostname = (parsed.hostname or "").lower()
            if self._is_brand_allowed_domain(claimed_brand, reg_domain, hostname, url=final_url):
                continue
            if reg_domain or hostname:
                return True, reg_domain or hostname
        return False, None

    def check_transport_and_dns_risk(
        self,
        urls: List[Dict[str, Any]],
        claimed_brand: Optional[str] = None,
    ) -> Tuple[int, List[str], Dict[str, Dict[str, str]]]:
        score_penalty = 0
        reasons: List[str] = []
        evidence: Dict[str, Dict[str, str]] = {}

        for url_info in urls:
            final_url = url_info.get("final_url") or url_info.get("url") or ""
            if not final_url:
                continue

            parsed = urllib.parse.urlparse(final_url)
            hostname = (parsed.hostname or "").lower()
            reg_domain = (url_info.get("final_registered_domain") or "").lower()
            is_allowed_url = self._is_context_allowed_domain(
                reg_domain,
                hostname=hostname,
                claimed_brand=claimed_brand,
                url=final_url,
            )
            scheme = (parsed.scheme or "").lower()
            try:
                port = parsed.port
            except ValueError:
                port = None
            final_scheme = "http" if scheme == "http" else scheme

            if not hostname:
                continue

            if self._is_ip_address(hostname):
                score_penalty += 30
                reason = f"Utilizare IP direct în link: {final_url} — indicator clasic de linkuri de phishing"
                reasons.append(reason)
                evidence[final_url] = {"type": "ip_hostname"}

            if final_scheme == "http" and not is_allowed_url:
                score_penalty += 12
                reasons.append(
                    f"Trimitere prin HTTP necriptat ({final_url}) — poate permite intercepție întreagă"
                )

            if port and port in HIGH_RISK_PORTS and not is_allowed_url:
                score_penalty += 10
                reasons.append(f"Port neobișnuit folosit în URL ({port}) pentru {final_url}, risc de infrastructură improvizată")

            if hostname.count(".") >= 6:
                score_penalty += 8
                reasons.append(f"Hostname cu structură excesivă ({hostname}) — posibil serviciu de ofuscare / redirect")

            if any(hostname.endswith(tld) for tld in SUSPICIOUS_TOP_LEVEL_DOMAINS):
                if not is_allowed_url:
                    score_penalty += 12
                    reasons.append(f"Extensie de domeniu neobișnuită pentru risc online: {hostname}")

        return score_penalty, reasons, evidence

    def levenshtein_distance(self, s1: str, s2: str) -> int:
        if len(s1) < len(s2):
            return self.levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
            
        return previous_row[-1]

    def calculate_entropy(self, s: str) -> float:
        import math
        from collections import Counter
        if not s:
            return 0.0
        entropy = 0.0
        cnt = Counter(s)
        len_s = len(s)
        for count in cnt.values():
            p = count / len_s
            entropy -= p * math.log2(p)
        return entropy

    def check_typosquatting_and_lexical(
        self,
        urls: List[Dict[str, Any]],
        claimed_brand: Optional[str] = None,
    ) -> Tuple[int, List[str]]:
        score_penalty = 0
        reasons = []
        claimed_brand_normalized = str(claimed_brand or "").strip().lower()
        claimed_brand_bases = self._claimed_brand_base_candidates(claimed_brand)
        
        for url_info in urls:
            domains_to_check = set()
            hostnames_to_check = set()
            context_allowed_domains = set()
            
            # Extract from final destination
            final_url = url_info.get("final_url") or url_info.get("url") or ""
            if final_url:
                ext = tldextract.extract(final_url)
                registrable_domain = _get_registrable_domain(ext)
                parsed = urllib.parse.urlparse(final_url)
                hname = url_info.get("final_hostname") or parsed.hostname
                if hname:
                    hostnames_to_check.add(hname.lower())
                if registrable_domain:
                    domains_to_check.add(registrable_domain)
                    if claimed_brand and self._is_brand_allowed_domain(
                        claimed_brand,
                        registrable_domain,
                        hostname=(str(hname).lower() if hname else None),
                        url=final_url,
                    ):
                        context_allowed_domains.add(registrable_domain)
                    
            # Extract from redirect chain hops
            for hop in url_info.get("redirect_chain", []):
                h = hop.get("hostname")
                reg = hop.get("registered_domain")
                if h:
                    hostnames_to_check.add(h.lower())
                if reg:
                    normalized_reg = reg.lower()
                    domains_to_check.add(normalized_reg)
                    if claimed_brand and self._is_brand_allowed_domain(
                        claimed_brand,
                        normalized_reg,
                        hostname=(str(h).lower() if h else None),
                    ):
                        context_allowed_domains.add(normalized_reg)

            # 1. IDN / Punycode Check
            has_punycode = False
            for hostname in hostnames_to_check:
                if "xn--" in hostname:
                    has_punycode = True
                    reasons.append(f"Detecție IDN/Punycode: Domeniul '{hostname}' folosește caractere speciale homoglife pentru a imita un brand oficial (tactică extrem de periculoasă)")
                    break
            if has_punycode:
                score_penalty += 25

            # 2. Typosquatting / Lookalike Check
            for reg_domain in domains_to_check:
                if reg_domain in context_allowed_domains:
                    continue
                if claimed_brand_normalized and self._is_brand_allowed_domain(
                    claimed_brand,
                    reg_domain,
                ):
                    continue
                ext = tldextract.extract(reg_domain)
                base = ext.domain.lower()
                if not base:
                    continue

                claim_typo_detected = False
                if claimed_brand_bases and not self._is_brand_allowed_domain(claimed_brand, reg_domain):
                    for t_base in claimed_brand_bases:
                        dist = self.levenshtein_distance(base, t_base)
                        is_typo = False
                        if dist > 0:
                            if len(t_base) > 4 and dist <= 2:
                                is_typo = True
                            elif len(t_base) <= 4 and dist <= 1:
                                is_typo = True
                        if is_typo:
                            reasons.append(
                                f"Detecție Typosquatting: Domeniul '{reg_domain}' este extrem de similar cu brandul oficial "
                                f"'{claimed_brand}' (distanță Levenshtein {dist}) — posibilă deturnare către alt brand sau infrastructură de phishing"
                            )
                            score_penalty += 40
                            claim_typo_detected = True
                            break
                if claim_typo_detected:
                    continue
                
                is_official = False
                matched_brand = None
                
                # Check if exact base match but on a spoofed domain
                if base in TRUSTED_BASE_NAMES:
                    matched_brand = TRUSTED_BASE_NAMES[base]
                    allowed_domains = BRAND_REGISTRY.get(matched_brand, [])
                    if any(reg_domain == allowed.lower() or reg_domain.endswith("." + allowed.lower()) for allowed in allowed_domains):
                        is_official = True
                    
                    if not is_official:
                        reasons.append(
                            f"Mismatch critic: Domeniul '{reg_domain}' pretinde direct a fi brandul oficial '{matched_brand}', "
                            f"dar este înregistrat sub o extensie sau o structură neoficială"
                        )
                        score_penalty += 35

                if is_official:
                    continue

                # Check Levenshtein distance
                for t_base, brand in TRUSTED_BASE_NAMES.items():
                    if brand == matched_brand:
                        continue
                        
                    dist = self.levenshtein_distance(base, t_base)
                    is_typo = False
                    if dist > 0:
                        if len(t_base) > 4 and dist <= 2:
                            is_typo = True
                        elif (
                            len(t_base) <= 4
                            and dist <= 1
                            and claimed_brand_normalized
                            and claimed_brand_normalized in brand.lower()
                        ):
                            is_typo = True

                    if is_typo:
                        reasons.append(
                            f"Detecție Typosquatting: Domeniul '{reg_domain}' este extrem de similar cu brandul oficial "
                            f"'{brand}' (distanță Levenshtein {dist}) — metodă de inducere în eroare a utilizatorilor"
                        )
                        score_penalty += 40
                        break

                # Check if trusted base is a substring of the base name (lookalike check, e.g. revolut-romania)
                # But don't double count if we already matched exact/typosquatting
                if not is_official and not any("Typosquatting" in r and reg_domain in r for r in reasons):
                    for t_base, brand in TRUSTED_BASE_NAMES.items():
                        if len(t_base) >= 4 and t_base in base and base != t_base:
                            reasons.append(
                                f"Domeniu Lookalike: Domeniul '{reg_domain}' conține numele brandului protejat "
                                f"'{brand}' în denumire, dar folosește un link neoficial — indică tentativă de phishing"
                            )
                            score_penalty += 35
                            break

                # 3. Shannon Entropy Check
                entropy = self.calculate_entropy(base)
                if len(base) >= 10 and entropy > 3.8:
                    reasons.append(
                        f"Entropie ridicată: Domeniul '{reg_domain}' are o entropie mare ({entropy:.2f}), "
                        f"ceea ce sugerează un domeniu generat automat (DGA) sau un șir aleatoriu de caractere"
                    )
                    score_penalty += 15

        return score_penalty, reasons

    def check_url_behaviour(
        self,
        urls: List[Dict[str, Any]],
        claimed_brand: Optional[str] = None,
    ) -> Tuple[int, List[str], Dict[str, List[str]]]:
        """
        Checks URL-level behavior signals:
        - suspicious path segments
        - opaque/encoded redirects in query
        - excessive subdomain depth
        """
        score_penalty = 0
        reasons: List[str] = []
        evidence: Dict[str, List[str]] = {}

        for url_info in urls:
            final_url = url_info.get("final_url") or url_info.get("url")
            if not final_url:
                continue

            parsed = urllib.parse.urlparse(final_url)
            path = (parsed.path or "").lower()
            query = parsed.query.lower()
            hostname = (parsed.hostname or "").lower()
            reg_domain = (url_info.get("final_registered_domain") or "").lower()
            is_official_url = self._is_context_allowed_domain(
                reg_domain,
                hostname=hostname,
                claimed_brand=claimed_brand,
                url=final_url,
                path=path,
            )

            url_signals = []
            if path and not is_official_url:
                path_parts = [part for part in path.split("/") if part]
                for part in path_parts:
                    if part in SUSPICIOUS_PATH_SEGMENTS:
                        score_penalty += 12
                        msg = f"Pattern de risc pe cale URL: segment '{part}' la {final_url}"
                        if msg not in reasons:
                            reasons.append(msg)
                        url_signals.append(part)

            if query and not is_official_url:
                query_pairs = urllib.parse.parse_qs(query, keep_blank_values=True)
                query_keys = {key.lower() for key in query_pairs.keys()}

                if any(key in SUSPICIOUS_QUERY_KEYS for key in query_keys):
                    score_penalty += 10
                    msg = f"URL-ul conține parametri de redirecționare/sesiune în query: {', '.join(sorted(query_keys.intersection(SUSPICIOUS_QUERY_KEYS)))}"
                    if msg not in reasons:
                        reasons.append(msg)
                    url_signals.extend(sorted(query_keys.intersection(SUSPICIOUS_QUERY_KEYS)))

                if any(key in TRACKING_QUERY_KEYS for key in query_keys):
                    score_penalty += 2
                    reasons.append(
                        f"URL-ul ascunde parametri de tracking (probabil campanii de marketing, nu o semnal clar de scam) la {final_url}"
                    )
                    url_signals.extend(
                        sorted(query_keys.intersection(TRACKING_QUERY_KEYS))
                    )

                for value in query_pairs.values():
                    for item in value:
                        lowered = item.lower()
                        if len(lowered) > 200:
                            score_penalty += 8
                            reasons.append(
                                f"Parametru URL cu valoare foarte lungă suspectă (posibil codificat): '{item[:20]}...'"
                            )
                            url_signals.append("obfuscare_query")
                            break

            if hostname and not is_official_url:
                dot_count = hostname.count(".")
                if dot_count > 3:
                    score_penalty += 8
                    msg = f"Hostname cu structură complexă (posibil tehnică de impersonare): {hostname}"
                    if msg not in reasons:
                        reasons.append(msg)
                    url_signals.append("hostname_complex")

            if url_signals:
                evidence[url_info.get("final_url", final_url)] = sorted(set(url_signals))

        return score_penalty, reasons, evidence

    def check_sensitive_requests(self, text: str) -> List[str]:
        """
        Detects requests for sensitive credentials/data in the text.
        Handles Romanian inflections (e.g., card/cardul/cardurile, cod/codul/codurile)
        and diacritics via P-MORPH folding (transferă -> transfera).
        """
        signals = []
        text = _morph_fold(text)
        lower_text = text.lower()
        
        # Credit Card CVC/OTP/PIN/Password (articulated or inflected)
        card_request = re.search(
            r"\b(?:introdu\w*|completeaz\w*|trimite\w*|spune\w*|comunic\w*|confirm\w*|verific\w*|valideaz\w*)\b"
            r"(?:\W+\w+){0,10}\W+"
            r"(?:date(?:le)?\s+(?:de\s+)?card(?:ului)?|num[aă]r(?:ul)?\s+(?:de\s+)?card(?:ului)?|card(?:ul|ului)?|cvv|cvc)",
            text,
            re.IGNORECASE,
        ) or re.search(
            r"(?:date(?:le)?\s+(?:de\s+)?card(?:ului)?|num[aă]r(?:ul)?\s+(?:de\s+)?card(?:ului)?|card(?:ul|ului)?|cvv|cvc)"
            r"(?:\W+\w+){0,10}\W+"
            r"\b(?:introdu\w*|completeaz\w*|trimite\w*|spune\w*|comunic\w*|confirm\w*|verific\w*|valideaz\w*)\b",
            text,
            re.IGNORECASE,
        )
        if card_request:
            signals.append("Solicitare date sensibile (card, CVC, PIN, cod de securitate)")
        elif any(pattern.search(text) for pattern in SENSITIVE_CREDENTIAL_PATTERNS):
            signals.append("Solicitare date sensibile (card, CVC, PIN, cod de securitate)")

        if re.search(
            r"\b(?:introdu\w*|completeaz\w*|trimite\w*|spune\w*|comunic\w*|confirm\w*|verific\w*|valideaz\w*)\b"
            r"(?:\W+\w+){0,10}\W+"
            r"(?:cnp|iban|date\s+personale|num[aă]r(?:ul)?\s+(?:de\s+)?(?:buletin|card|telefon)|copie\s+act|act(?:ul)?\s+(?:de\s+)?identitate)",
            text,
            re.IGNORECASE,
        ):
            signals.append("Solicitare date personale sensibile (CNP, IBAN sau identificare)")

        if re.search(r"\b(?:verificare|confirmare|validare)\s+(?:identitate|date|cont|client)\b", text, re.IGNORECASE):
            signals.append("Solicitare verificare identitate/date de cont")

        if re.search(r"\b(?:completeaz[aă]|completeaza|introdu|trimite)\b.*\b(?:nume|adres[aă]|telefon|cnp|iban|date\w*)\b", text, re.IGNORECASE):
            signals.append("Solicitare completare date personale")

        if re.search(r"\b(?:cod(?:ul)?\s+sms|cod\s+otp|otp|cod(?:ul)?\s+de\s+confirmare)\b", text, re.IGNORECASE):
            signals.append("Solicitare cod SMS/OTP")

        if re.search(r"\b(?:pl[aă]te[sș]te|plateste|plati[țt]i|achit[aă]|tax[aă])\b", text, re.IGNORECASE):
            signals.append("Solicitare de plată/taxă")
        
        # WhatsApp verification codes
        if any(pattern.search(text) for pattern in SENSITIVE_WHATSAPP_PATTERNS):
            signals.append("Solicitare cod de confirmare WhatsApp (takeover cont)")
            
        # Remote access apps
        if REMOTE_ACCESS_PATTERNS[0].search(text) and (
            REMOTE_ACCESS_PATTERNS[1].search(text)
            or re.search(r"\b(?:broker[a-z]*|consultant[a-z]*|investi[a-z]*|profit|banc[aă]|suport[a-z]*)\b", text, re.IGNORECASE)
        ):
            signals.append("Instrucțiuni de instalare a unei aplicații de acces la distanță (e.g., AnyDesk)")
            
        # Money transfers and payments (e.g., plata, plateste, platesc, platit, transfera)
        if any(pattern.search(text) for pattern in SENSITIVE_PAYMENT_PATTERNS):
            signals.append("Solicitare de transfer de bani sau plată online rapidă")

        # OLX payment scams (receive money on card: primesti bani, incaseaza, primire)
        if any(pattern.search(text) for pattern in OLX_CARD_PATTERNS):
            signals.append("Pretext de primire a banilor direct pe card (specific tentativelor OLX/Marketplace)")

        # Malware APK lure
        if any(pattern.search(text) for pattern in MALWARE_APK_PATTERNS):
            signals.append("Solicitare de instalare aplicație APK din sursă externă (posibil malware)")

        # QR phishing / quishing
        if (
            any(pattern.search(text) for pattern in SENSITIVE_QR_PATTERNS)
            and re.search(r"\b(?:qr|q\s*r|cod\s+qr)\b", text, re.IGNORECASE)
        ):
            signals.append("Solicitare de scanare/plată prin QR într-un context de risc")

        # Sextortion (digital blackmail)
        sextortion_context = re.search(r"\b(?:ameninț|amenint|șantaj|santaj|compromis|poze|video|camera|parole)\b", lower_text, re.IGNORECASE)
        sextortion_payment = re.search(r"\b(?:plat[aă]|bani|sum[aă]|ron|eur|crypto)\b", lower_text, re.IGNORECASE)
        if sextortion_context and sextortion_payment and any(pattern.search(text) for pattern in SENSITIVE_SEXTORTION_PATTERNS):
            signals.append("Semnal de șantaj digital: amenințare + cerere de plată")

        # SIM swap / telecom impersonation
        if any(pattern.search(text) for pattern in SENSITIVE_SIM_SWAP_PATTERNS):
            signals.append("Indicator de impostură pe SIM/abonament cu solicitare de acces sau date")

        return signals

    def check_language_manipulation(self, text: str) -> List[str]:
        """
        Detects urgency, fear, greed, authority-abuse signals with Romanian
        inflections and diacritics via P-MORPH folding.
        """
        signals = []
        text = _morph_fold(text)
        # Urgency (e.g., urgent, urgență, imediat, acum, bloca/blocat/blocare, suspendat, expira)
        if any(pattern.search(text) for pattern in URGENCY_MANIPULATION_PATTERNS):
            signals.append("Crearea unui sentiment artificial de urgență sau presiune psihologică")
            
        # Fake rewards / refunds (e.g., castig/castiga/castiguri, premiu/premiul, rambursare, investitii, profit)
        if any(pattern.search(text) for pattern in MANIPULATION_REWARD_PATTERNS):
            signals.append("Promisiune de câștiguri rapide, profit garantat sau returnare de taxe/rambursare")
            
        # Fake warnings / parcel delivery (e.g., colet/coletul/coletele, customs, vama, taxa/taxe/taxele, locker/lockerul, adresa)
        if any(pattern.search(text) for pattern in DELIVERY_MANIPULATION_PATTERNS):
            signals.append("Pretext de livrare a unui colet sau taxe vamale neachitate")
            
        return signals

    def classify_scam_family(self, text: str, claimed_brand: Optional[str]) -> Tuple[Dict[str, Any], float]:
        """
        Finds the matching scam family from the atlas seed using keyword matching.
        Returns (family_dict, confidence_score)
        """
        best_match = None
        highest_score = 0.0
        highest_quality = -1

        generic_tokens = {
            "acest", "aceasta", "aici", "către", "catre", "com", "confirmare",
            "detalii", "http", "https", "link", "mesaj", "online", "pentru",
            "prin", "romania", "românia", "servicii", "test", "verifica", "verifică",
            "www",
        }

        def semantic_tokens(value: str) -> set[str]:
            return {
                token
                for token in re.findall(r"\b[\wșțîâă]+\b", (value or "").lower())
                if len(token) >= 4 and token not in generic_tokens
            }

        def contains_phrase(value: str, phrase: str) -> bool:
            normalized_phrase = str(phrase or "").strip().lower()
            if not normalized_phrase:
                return False
            return bool(re.search(rf"(?<!\w){re.escape(normalized_phrase)}(?!\w)", value.lower()))

        text_words = semantic_tokens(text)
        for family in self.families:
            required_token_groups = family.get("required_token_groups") or []
            if required_token_groups:
                folded_text_words = semantic_tokens(_morph_fold(text))
                required_groups_match = all(
                    bool(
                        folded_text_words.intersection(
                            {
                                token
                                for value in group
                                for token in semantic_tokens(_morph_fold(str(value)))
                            }
                        )
                    )
                    for group in required_token_groups
                )
                if not required_groups_match:
                    continue

            score = 0.0
            family_name = family.get("family", "").lower()
            hook = family.get("match_text", family.get("hook", "")).lower()
            asks_for = family.get("asks_for") or []
            
            # Match by claimed brand
            if claimed_brand:
                claimed_role = str(family.get("claimed_brand_or_role") or "").lower()
                if claimed_brand.lower() in family_name or claimed_brand.lower() in claimed_role:
                    score += 0.25

            # Match only meaningful runtime family tokens. Examples and URL boilerplate
            # are intentionally excluded from match_text during normalization.
            hook_words = semantic_tokens(hook)
            overlap = hook_words.intersection(text_words)
            if overlap:
                score += min(0.48, len(overlap) * 0.12)

            asks_overlap = 0
            for ask in asks_for:
                if not ask:
                    continue
                if contains_phrase(text, ask):
                    asks_overlap += 1
            if asks_overlap:
                score += min(0.5, asks_overlap * 0.2)

            # Check if any red flags or channel matches
            family_quality = (
                len(family.get("signals") or []) * 2
                + len(family.get("asks_for") or [])
                + len(family.get("examples") or [])
            )
            if score > highest_score or (
                score == highest_score and score > 0 and family_quality > highest_quality
            ):
                highest_score = score
                highest_quality = family_quality
                best_match = family

        # Default fallback family if score is low
        if not best_match or highest_score < 0.2:
            best_match = {
                "id": "unknown-scam",
                "family": "Suspect / Necunoscut",
                "safe_actions": [
                    "Nu accesați linkuri și nu răspundeți la mesaj.",
                    "Nu introduceți datele cardului, coduri primite prin SMS/WhatsApp sau parole.",
                    "Dacă mesajul pretinde că e de la o bancă sau curier, contactați instituția pe canalul oficial."
                ]
            }
            highest_score = 0.0

        confidence = min(highest_score, 1.0)
        return best_match, confidence

    @staticmethod
    def _family_supports_high_risk_text_only(family: Dict[str, Any]) -> bool:
        signals = {str(value).strip().upper() for value in family.get("signals") or [] if str(value).strip()}
        asks_for = {str(value).strip().lower() for value in family.get("asks_for") or [] if str(value).strip()}
        requested_assets = {
            str(value).strip().lower().replace("_", " ")
            for value in family.get("requested_asset") or []
            if str(value).strip()
        }
        return bool(
            signals.intersection(HIGH_RISK_TEXT_ONLY_SIGNAL_MARKERS)
            or (asks_for | requested_assets).intersection(HIGH_RISK_TEXT_ONLY_ASK_MARKERS)
        )

    @classmethod
    def _semantic_review_from_family(
        cls,
        family: Dict[str, Any],
        confidence: float,
        *,
        supports_high_text_only: Optional[bool] = None,
    ) -> Dict[str, Any]:
        family_id = str(family.get("id") or "").strip()
        family_name = str(family.get("family") or "").strip()
        family_key = f"{family_id} {family_name}".lower()
        known = bool(family_id) and family_id != "unknown-scam"
        if supports_high_text_only is None:
            supports_high_text_only = cls._family_supports_high_risk_text_only(family)

        risk_class = "unknown"
        if confidence < 0.2 or not known:
            risk_class = "unknown"
        elif family_key.startswith("guard/") or "guard/" in family_key or "legitim" in family_key:
            risk_class = "benign"
        elif supports_high_text_only and confidence >= 0.35:
            risk_class = "high"
        elif confidence >= 0.25:
            risk_class = "medium"

        confidence_class = "high" if confidence >= 0.5 else "medium" if confidence >= 0.25 else "low"
        return {
            "status": "done",
            "claim_matches_known_scam_family": risk_class in {"high", "medium"},
            "matched_family": (family_id or family_name or None) if risk_class in {"high", "medium"} else None,
            "claim_matches_legit_template": risk_class == "benign",
            "matched_template": (family_id or family_name or None) if risk_class == "benign" else None,
            "reason_codes": [f"semantic:{risk_class}", f"family:{(family_id or family_name or 'unknown').lower()}"],
            "risk_class": risk_class,
            "confidence_class": confidence_class,
            "family_confidence": round(float(confidence or 0.0), 3),
            "confidence": round(float(confidence or 0.0), 3),
            "completeness": True,
            "source": "scam_atlas_structured",
        }

    def analyze(
        self,
        text: str,
        urls: List[Dict[str, Any]] = None,
        external_threat_intel: Optional[Dict[str, Dict[str, str]]] = None,
        email_context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Main analysis pipeline:
        - Detect brand name
        - Check domain mismatches
        - Check sensitive requests
        - Check language manipulation
        - Classify family
        - Compute risk score 0-100
        """
        if urls is None:
            urls = []
        email_context = email_context or {}

        reasons = []
        score = 0
        external_intel_hits = 0
        external_intel_sources: Dict[str, int] = {}
        external_intel_source_status: Dict[str, Dict[str, Any]] = {}
        external_intel_summaries: Dict[str, Dict[str, Any]] = {}

        has_suspicious_tld = False
        lexical_evidence: Dict[str, Any] = {}
        behaviour_evidence: Dict[str, List[str]] = {}
        dns_risk_evidence: Dict[str, Dict[str, str]] = {}
        
        # 1. Brand Detection
        claimed_brand = self.detect_claimed_brand(text)
        
        # 2. Check Domain Whitelist Mismatch (Weight: 35)
        has_mismatch = False
        mismatched_domain = None
        if claimed_brand:
            has_mismatch, mismatched_domain = self.check_brand_mismatch(claimed_brand, urls)
        if has_mismatch:
                score += 50
                reasons.append(
                    f"Mismatch de Domeniu: Pretinde a fi de la '{claimed_brand}', dar link-ul duce către un domeniu neoficial ({mismatched_domain})"
                )

        # 3. Check Sensitive Requests (Weight: 25)
        sensitive_signals = self.check_sensitive_requests(text)
        if sensitive_signals:
            score += 25
            reasons.extend(sensitive_signals)

        # 4. Check Language Manipulation (Weight: 15)
        language_signals = self.check_language_manipulation(text)
        if language_signals:
            score += 15
            reasons.extend(language_signals)

        # 5. URL analysis signals (Weight: up to 30)
        if urls:
            total_shortener_count = 0
            total_soft_redirects = 0
            max_redirect_depth = 0
            unresolved_count = 0
            has_url_risk_signal = False

            # 5a. Run advanced lookalike and lexical checks
            lexical_penalty, lexical_reasons = self.check_typosquatting_and_lexical(
                urls,
                claimed_brand=claimed_brand,
            )
            lexical_evidence = {
                "penalty": lexical_penalty,
                "reasons": list(lexical_reasons),
                "has_signal": lexical_penalty > 0,
            }
            score += lexical_penalty
            reasons.extend(lexical_reasons)
            if lexical_penalty > 0:
                has_url_risk_signal = True

            behaviour_penalty, behaviour_reasons, behaviour_evidence = self.check_url_behaviour(
                urls,
                claimed_brand=claimed_brand,
            )
            score += behaviour_penalty
            reasons.extend(behaviour_reasons)
            if behaviour_penalty > 0:
                has_url_risk_signal = True

            dns_penalty, dns_reasons, dns_risk_evidence = self.check_transport_and_dns_risk(
                urls,
                claimed_brand=claimed_brand,
            )
            score += dns_penalty
            reasons.extend(dns_reasons)
            if dns_penalty > 0:
                has_url_risk_signal = True

            for url_info in urls:
                url_unresolved = not url_info.get("success", True)

                # ── Shortener detection (uses new resolver field) ──
                url_shortener_count = url_info.get("shortener_count", 0)
                if not url_shortener_count:
                    # Fallback: check uses_shortener flag or chain hops
                    if url_info.get("uses_shortener"):
                        url_shortener_count = 1
                    else:
                        chain = url_info.get("redirect_chain", [])
                        url_shortener_count = sum(1 for hop in chain if hop.get("is_shortener"))
                total_shortener_count += url_shortener_count

                # ── Soft redirect detection (meta-refresh / JS redirect) ──
                soft_redirects = url_info.get("detected_soft_redirects", [])
                total_soft_redirects += len(soft_redirects)

                # ── Redirect chain depth ──
                redirect_count = url_info.get("redirect_count", 0)
                max_redirect_depth = max(max_redirect_depth, redirect_count)

                # ── Suspicious TLD on FINAL destination ──
                reg_domain = (url_info.get("final_registered_domain") or url_info.get("registered_domain") or "").lower()
                hostname = (url_info.get("final_hostname") or url_info.get("hostname") or "").lower()
                if not hostname and (url_info.get("final_url") or url_info.get("url")):
                    parsed_for_host = urllib.parse.urlparse(url_info.get("final_url") or url_info.get("url") or "")
                    hostname = (parsed_for_host.hostname or "").lower()
                is_whitelisted_url = self._is_context_allowed_domain(
                    reg_domain,
                    hostname=hostname,
                    claimed_brand=claimed_brand,
                    url=url_info.get("final_url") or url_info.get("url") or "",
                )
                if url_unresolved and not is_whitelisted_url:
                    unresolved_count += 1
                if (
                    reg_domain.endswith((".ru", ".top", ".xyz", ".club", ".info", ".online", ".site", ".cc", ".link", ".live", ".space"))
                    and not is_whitelisted_url
                ):
                    has_suspicious_tld = True
                    has_url_risk_signal = True

                # ── Domain age check (populated by redirect resolver) ──
                age_days = url_info.get("domain_age_days")
                if age_days is not None:
                    # Skip check for whitelisted domains
                    is_whitelisted = is_whitelisted_url
                    if not is_whitelisted:
                        if age_days < 30:
                            has_url_risk_signal = True
                            score += 35
                            reasons.append(
                                f"Domeniu recent înregistrat: Domeniul final '{reg_domain}' are o vechime de doar {age_days} zile "
                                f"— comportament tipic pentru campaniile active de phishing"
                            )
                        elif age_days < 90:
                            has_url_risk_signal = True
                            score += 15
                            reasons.append(
                                f"Domeniu relativ nou: Domeniul final '{reg_domain}' are o vechime de {age_days} zile "
                                f"— necesită atenție sporită"
                            )

                # ── Mail server verification (MX records) ──
                has_mx = url_info.get("has_mx_records")
                if has_mx is False: # Explicitly False (unchecked/error will be None)
                    is_whitelisted = is_whitelisted_url
                    if not is_whitelisted:
                        has_url_risk_signal = True
                        score += 10
                        reasons.append(
                            f"Lipsă server e-mail (MX): Domeniul final '{reg_domain}' nu are configurat "
                            f"un server de e-mail — specific paginilor create doar pentru scam/phishing"
                        )

                # ── Third-party threat intel (Safe Browsing)
                final_url = url_info.get("final_url") or ""
                if final_url and external_threat_intel:
                    threat_key = hashlib.sha256(final_url.encode("utf-8")).hexdigest()
                    threat = external_threat_intel.get(final_url) or external_threat_intel.get(threat_key, {})
                    if threat:
                        verdict = (threat.get("verdict") or "").lower()
                        threat_score = _coerce_reputation_int(threat.get("risk_score", 0), 0)
                        sources = threat.get("sources", {})
                        if isinstance(sources, dict):
                            for source_name, source_data in sources.items():
                                if not isinstance(source_data, dict):
                                    continue

                                source_status = _coerce_reputation_status(source_data.get("status", "unknown"))
                                consulted = bool(source_data.get("consulted", False))
                                source_weight = _coerce_reputation_int(source_data.get("weight", 0), 0)
                                source_risk_score = _coerce_reputation_int(source_data.get("score", 0), 0)
                                source_risk_contribution = source_data.get("risk_contribution")
                                source_threat_type = str(source_data.get("threat_type", "unknown")).lower()

                                if consulted and source_status in {"malicious", "suspicious"}:
                                    external_intel_sources[source_name] = external_intel_sources.get(source_name, 0) + 1

                                source_entry = external_intel_source_status.setdefault(
                                    source_name,
                                    {
                                        "source": source_name,
                                        "status": source_status,
                                        "consulted": consulted,
                                        "weight": source_weight,
                                        "risk_score": source_risk_score,
                                        "threat_type": source_threat_type,
                                        "risk_contribution": source_risk_contribution,
                                        "url_count": 0,
                                        "malicious_hit_count": 0,
                                    },
                                )
                                source_entry["status"] = _merge_reputation_status(source_entry["status"], source_status)
                                if consulted:
                                    source_entry["consulted"] = True
                                    source_entry["url_count"] = int(source_entry.get("url_count", 0)) + 1
                                    source_entry["risk_score"] = max(
                                        int(source_entry.get("risk_score", 0) or 0),
                                        source_risk_score,
                                    )
                                    if source_entry.get("risk_contribution") is None:
                                        source_entry["risk_contribution"] = source_risk_contribution
                                    if source_status in {"malicious", "suspicious"}:
                                        source_entry["malicious_hit_count"] = int(source_entry.get("malicious_hit_count", 0)) + 1

                                summary_entry = external_intel_summaries.setdefault(
                                    source_name,
                                    {
                                        "status": source_status,
                                        "consulted": consulted,
                                        "url_count": 0,
                                        "url_example": final_url,
                                        "risk_score": source_risk_score,
                                        "weight": source_weight,
                                        "threat_type": source_threat_type,
                                    },
                                )
                                summary_entry["status"] = _merge_reputation_status(summary_entry["status"], source_status)
                                summary_entry["consulted"] = bool(summary_entry.get("consulted", False)) or consulted
                                summary_entry["url_count"] = int(summary_entry.get("url_count", 0)) + 1
                                summary_entry["risk_score"] = max(
                                    int(summary_entry.get("risk_score", 0) or 0),
                                    source_risk_score,
                                )
                                summary_entry["url_example"] = final_url
                        
                        if verdict == "malicious":
                            external_intel_hits += 1
                            score += min(max(threat_score, 60), 100)
                            reasons.append(
                                f"Reputație URL critică pentru '{final_url}' "
                                f"(surse: {', '.join(sorted(external_intel_sources.keys()) or ['reputație'])})."
                            )
                        elif verdict == "suspicious":
                            external_intel_hits += 1
                            score += max(25, min(threat_score, 55))
                            reasons.append(
                                f"Semnale de risc moderate pentru URL-ul '{final_url}' (surse: {', '.join(sorted(external_intel_sources.keys()) or ['reputație'])})."
                            )
                        elif threat.get("cached"):
                            reasons.append(f"URL reputat ca sigur prin surse externe: '{final_url}'")

            # Score: shorteners
            if total_shortener_count == 1:
                score += 10
                reasons.append("Mesajul folosește un link scurtat pentru a ascunde destinația reală")
                has_url_risk_signal = True
            elif total_shortener_count >= 2:
                score += 25
                reasons.append(
                    f"Lanț de {total_shortener_count} scurtătoare de link-uri detectat "
                    f"(bit.ly → tinyurl → ... → destinația reală) — tactică frecventă de phishing"
                )
                has_url_risk_signal = True

            # Score: soft redirects (meta-refresh or JS)
            if total_soft_redirects > 0:
                score += 10
                has_url_risk_signal = True
                reasons.append(
                    f"Detectat{'e' if total_soft_redirects > 1 else 'ă'} {total_soft_redirects} "
                    f"redirecționăr{'i' if total_soft_redirects > 1 else 'e'} ascuns{'e' if total_soft_redirects > 1 else 'ă'} "
                    f"în pagina HTML (meta-refresh sau JavaScript) — nu este un comportament normal"
                )

            # Score: excessive redirect depth
            if max_redirect_depth > 4:
                score += 5
                reasons.append(
                    f"Lanț de redirecționare neobișnuit de lung ({max_redirect_depth} hop-uri) — "
                    f"link-urile legitime redirecționează de obicei maxim 1-2 ori"
                )
                has_url_risk_signal = True

            # Score: suspicious TLD
            if has_suspicious_tld:
                score += 15
                has_url_risk_signal = True
                reasons.append("Linkul duce către un domeniu cu extensie neobișnuită (e.g. .ru, .xyz, .top)")

            if unresolved_count > 0:
                score += 6
                has_url_risk_signal = True
                reasons.append(
                    f"Nu au putut fi verificate complet {unresolved_count}/{len(urls)} link(uri)."
                )

            if external_intel_hits > 0:
                has_url_risk_signal = True
                score += 0  # already weighted above, keep for explainability only

        # Cap score at 100
        score = min(score, 100)

        # Email-specific trust signals (if available)
        auth_strength = email_context.get("auth_strength", "missing")
        auth_fail_reasons = email_context.get("auth_fail_reasons", [])
        if email_context:
            action_plan = email_context.get("auth_action_plan", {}) or {}
            if isinstance(action_plan, dict):
                action = str(action_plan.get("action", "monitor")).lower()
                score += int(action_plan.get("risk_score_delta", 0) or 0)
                action_reasons = action_plan.get("reasons", [])
                if not isinstance(action_reasons, list):
                    action_reasons = []
                for reason in action_reasons:
                    reasons.append(f"Email policy: {reason}")
            else:
                action = "monitor"

            if auth_fail_reasons:
                if action != "reject":
                    score += 20
                reasons.extend([f"Email suspicious: {reason}" for reason in auth_fail_reasons])
            elif auth_strength == "pass":
                reasons.append("Email autentificat prin SPF/DKIM/DMARC.")
            elif auth_strength == "partial":
                score += 8
                reasons.append("Email autentificat parțial; confirmările SPF/DKIM/DMARC sunt incomplete.")
            elif auth_strength == "missing":
                score += 12
                reasons.append("Emailul nu include dovezi complete de autentificare SPF/DKIM/DMARC.")

        # Classify scam family
        family, confidence = self.classify_scam_family(text, claimed_brand)
        family_id = str(family.get("id") or "")

        legacy_high_risk_text_only_families = {
            "RO_SCN_004_BNR_POLICE_SAFE_ACCOUNT",
            "RO_SCN_005_CREDIT_FRAUDULOS",
            "RO_SCN_006_VOTEAZA_ADELINE",
            "RO_SCN_007_PETITIE_WHATSAPP",
            "RO_SCN_008_TELEFON_STRICAT",
            "RO_SCN_009_ACCIDENT_NEPOT",
            "RO_SCN_011_HIDRO_INVESTMENT",
            "RO_SCN_012_CRYPTO_BROKER_REMOTE",
            "RO_SCN_013_FAKE_BANK_APK",
            "RO_SCN_018_REVOLUT_CALL_OTP",
            "RO_SCN_024_SEXTORTION_SMS_NO_URL",
            "RO_SCN_025_PIG_BUTCHERING",
        }
        high_risk_text_only_family = (
            family_id in legacy_high_risk_text_only_families
            or self._family_supports_high_risk_text_only(family)
        )
        semantic_review = self._semantic_review_from_family(
            family,
            confidence,
            supports_high_text_only=high_risk_text_only_family,
        )
        if not urls and confidence >= 0.2 and high_risk_text_only_family:
            score += 75
            reasons.append(
                "Scenariu de fraudă socială confirmat în corpusul România: fără link de scanat, "
                "dar mesajul cere bani, acces, control la distanță sau date sensibile."
            )
        elif not urls:
            normalized_for_text_only = text.lower()
            if (
                re.search(r"\b(?:cod|otp)\b.*\b(?:sms|whatsapp|revolut)\b|\b(?:sms|whatsapp|revolut)\b.*\b(?:cod|otp)\b", normalized_for_text_only)
                or re.search(r"\b(?:bnr|poli[țt]ie|banc[aă])\b.*\b(?:proteja[țt]i|cont\s+sigur|banii|transfer)\b", normalized_for_text_only)
                or re.search(r"\b(?:urgent|acum)\b.*\b(?:bani|lei|împrumut|imprumut)\b|\b(?:bani|lei|împrumut|imprumut)\b.*\b(?:urgent|acum)\b", normalized_for_text_only)
            ):
                score += 75
                reasons.append(
                    "Semnal text-only puternic: mesajul cere coduri, bani sau acțiune financiară urgentă fără canal verificabil."
                )

        if confidence >= 0.2 and family.get("id") == "ro-2025-qr-quishing":
            if any(pattern.search(text) for pattern in SENSITIVE_QR_PATTERNS):
                score += 20
                reasons.append("Indicator specific quishing: context QR + semnale de plată/scanare")

        if confidence >= 0.2 and family.get("id") in ("MINOR_017_ADULT_SHAME_SEXTORTION_EMAIL", "RO_SCN_024_SEXTORTION_SMS_NO_URL"):
            if any(pattern.search(text) for pattern in SENSITIVE_SEXTORTION_PATTERNS):
                score += 20
                reasons.append("Indicator specific sextortion: șantaj digital + cerere financiară")

        if confidence >= 0.2 and family.get("id") == "RO_SCN_025_PIG_BUTCHERING":
            score += 30
            reasons.append("Indicator specific pig-butchering: construire încredere + cerere investiție/platformă falsă")

        if confidence >= 0.2 and family.get("id") == "ro-2025-telecom-sim-swap":
            if any(pattern.search(text) for pattern in SENSITIVE_SIM_SWAP_PATTERNS):
                score += 20
                reasons.append("Indicator specific SIM swap: solicitare de date/acces pe cont și abonament")
            elif any(token in text.lower() for token in ("schimbare sim", "date personale", "acces cont", "abonament")):
                score += 15
                reasons.append("Indicator specific SIM swap: termeni de schimbare SIM/abonament + acces")

        # Determine risk level
        if score >= 75:
            risk_level = "critical"
        elif score >= 50:
            risk_level = "high"
        elif score >= 25:
            risk_level = "medium"
        else:
            # If there's a link but no strong risk match, only mark medium when domain/path is non-trusted.
            if urls:
                has_non_whitelisted_url = any(
                    not self._is_context_allowed_domain(
                        (url_info.get("final_registered_domain") or url_info.get("registered_domain") or "").lower(),
                        hostname=(url_info.get("final_hostname") or url_info.get("hostname") or "").lower()
                        or (
                            urllib.parse.urlparse(url_info.get("final_url") or url_info.get("url") or "").hostname or ""
                        ),
                        claimed_brand=claimed_brand,
                        url=url_info.get("final_url") or url_info.get("url") or "",
                    )
                    for url_info in urls
                )
                if has_url_risk_signal:
                    risk_level = "medium"
                    score = max(score, 25)
                    if not any("linkuri externe" in r for r in reasons):
                        reasons.append("Mesajul conține linkuri externe care ar trebui tratate cu atenție")
                elif claimed_brand and has_url_risk_signal:
                    risk_level = "medium"
                    score = max(score, 25)
                    if not any("brand cunoscut" in r for r in reasons):
                        reasons.append(
                            "Mesajul conține un brand cunoscut cu un link inclus; verifică sursa oficială înainte de acțiune."
                        )
                else:
                    risk_level = "low"

            else:
                risk_level = "low"

        # Combine safe actions from Scam Atlas
        safe_actions = family.get("safe_actions", [
            "Nu accesați linkuri din mesaje nesolicitate.",
            "Nu comunicați parole, coduri OTP sau date de card.",
            "Sunați la numărul oficial al brandului dacă aveți îndoieli."
        ])

        deduped_reasons = _dedupe_preserve_order(reasons)

        external_intel_summary: Dict[str, Dict[str, Any]] = {}
        for source_name in sorted(external_intel_summaries.keys()):
            summary_entry = external_intel_summaries[source_name]
            external_intel_summary[source_name] = {
                "source": summary_entry.get("source", source_name),
                "status": summary_entry.get("status", "unknown"),
                "consulted": bool(summary_entry.get("consulted", False)),
                "weight": _coerce_reputation_int(summary_entry.get("weight", 0), 0),
                "risk_score": _coerce_reputation_int(summary_entry.get("risk_score", 0), 0),
                "threat_type": str(summary_entry.get("threat_type", "unknown")),
                "risk_contribution": summary_entry.get("risk_contribution"),
                "url_count": _coerce_reputation_int(summary_entry.get("url_count", 0), 0),
                "malicious_hit_count": _coerce_reputation_int(summary_entry.get("malicious_hit_count", 0), 0),
                "url_example": summary_entry.get("url_example"),
            }

        external_intel_source_status_payload: Dict[str, Dict[str, Any]] = {}
        for source_name in sorted(external_intel_source_status.keys()):
            source_entry = external_intel_source_status[source_name]
            external_intel_source_status_payload[source_name] = {
                "source": source_entry.get("source", source_name),
                "status": source_entry.get("status", "unknown"),
                "consulted": bool(source_entry.get("consulted", False)),
                "weight": _coerce_reputation_int(source_entry.get("weight", 0), 0),
                "risk_score": _coerce_reputation_int(source_entry.get("risk_score", 0), 0),
                "threat_type": str(source_entry.get("threat_type", "unknown")),
                "risk_contribution": source_entry.get("risk_contribution"),
                "url_count": _coerce_reputation_int(source_entry.get("url_count", 0), 0),
                "malicious_hit_count": _coerce_reputation_int(source_entry.get("malicious_hit_count", 0), 0),
            }

        return {
            "risk_score": score,
            "risk_level": risk_level,
            "detected_family": family.get("family", "Unknown"),
            "detected_family_id": family.get("id", "unknown"),
            "claimed_brand": claimed_brand or "Nespecificat",
            "reasons": deduped_reasons if deduped_reasons else ["Nu au fost detectate semnale evidente de risc."],
            "safe_actions": safe_actions,
            "confidence": confidence,
            "evidence": {
                "has_domain_mismatch": has_mismatch,
                "mismatched_domain": mismatched_domain,
                "url_lexical": lexical_evidence if urls else {},
                "url_behaviour": behaviour_evidence if urls else {},
                "url_transport": dns_risk_evidence if urls else {},
                "extracted_urls": urls,
                "external_intel": bool(external_threat_intel),
                "external_intel_hits": external_intel_hits,
                "external_intel_sources": sorted(external_intel_sources.keys()),
                "email_auth": email_context,
                "external_intel_summary": external_intel_summary,
                "external_intel_source_status": external_intel_source_status_payload,
                "email_auth_action": email_context.get("auth_action_plan") if email_context else None,
                "scam_family": dict(family),
                "family_confidence": confidence,
                "family_high_risk_text_only": high_risk_text_only_family,
                "semantic_review": semantic_review,
            }
        }
