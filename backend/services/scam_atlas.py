import json
import os
import re
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
    out: List[str] = []
    for item in values:
        if not item:
            continue
        text = str(item).strip()
        if text:
            out.append(text)
    return out


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
        "FAN Courier": ["fancourier.ro", "fanbox.ro", "fan-courier.ro"],
        "Posta Romana": ["posta-romana.ro"],
        "Sameday": ["sameday.ro", "sameday.delivery", "easybox.ro"],
        "DHL": ["dhl.ro", "dhl.com", "dhl-express.ro"],
        "eMAG": ["emag.ro", "emag.delivery"],
        "Uber": ["uber.com", "ubereats.com"],
        "YOXO": ["yoxo.ro", "buyback.yoxo.ro", "orange.ro"],
        "OLX": ["olx.ro"],
        "Google": ["google.com", "google.ro", "gmail.com"],
        "Microsoft": ["microsoft.com", "outlook.com", "office.com", "live.com"],
        "Meta": ["meta.com", "facebook.com", "instagram.com", "whatsapp.com"],
    },
    "brand_domain_exceptions": {
        "ANAF": ["anaf-spv.info", "anaf-spv.ro", "anaf-spv.gov.ro"],
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
        "posta-romana": "Posta Romana",
        "sameday": "Sameday",
        "dhl": "DHL",
        "dhl-express": "DHL",
        "emag": "eMAG",
        "uber": "Uber",
        "ubereats": "Uber",
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

SUSPICIOUS_PATH_SEGMENTS = {
    "login",
    "signin",
    "verify",
    "verifica",
    "recover",
    "unlock",
    "otp",
    "security",
    "reactiveaza",
    "reactiveare",
    "reactivare",
    "cont",
    "update",
    "suspendat",
    "suspendare",
    "bloqueaza",
    "auth",
    "authorization",
    "authorize",
}

SUSPICIOUS_QUERY_KEYS = {
    "redirect",
    "next",
    "return",
    "continue",
    "url",
    "target",
    "dest",
    "u",
    "r",
}

TRACKING_QUERY_KEYS = {
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "utm_id",
    "utm_referrer",
    "gclid",
    "fbclid",
}

SUSPICIOUS_TOP_LEVEL_DOMAINS = {
    ".ru",
    ".top",
    ".xyz",
    ".club",
    ".info",
    ".online",
    ".site",
    ".cc",
    ".link",
    ".live",
    ".space",
    ".click",
    ".store",
    ".win",
    ".top",
    ".download",
}

HIGH_RISK_PORTS = {
    8080,
    8081,
    8888,
    10000,
    1337,
    4444,
    5555,
    8088,
}

SENSITIVE_CREDENTIAL_PATTERNS = (
    re.compile(r"\b(?:cvc|cvv|otp|pin)\b", re.IGNORECASE),
    re.compile(
        r"\b(?:cod(?:ul)?\s+(?:de|al)?\s*(?:verificare|confirmare|activare|acces))\b",
        re.IGNORECASE,
    ),
    re.compile(r"\b(?:parol(?:a|ele|ile)|parola ta|parolele)\b", re.IGNORECASE),
)

SENSITIVE_WHATSAPP_PATTERNS = (
    re.compile(r"\bwhatsapp\b.*\b(?:cod|otp)\b|\b(?:cod|otp)\b.*\bwhatsapp\b", re.IGNORECASE),
)

SENSITIVE_PAYMENT_PATTERNS = (
    re.compile(
        r"\btransfer[a-z]*\b.*\b(?:bani|sum[aă]|ron|eur|usd)\b|\btrimite[a-z]*\s+bani\b|\bpl[aă]te[a-z]*\s+(?:taxa|comisionul|livrare|factur|abonament|restanta)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\bcont\s+sigur\b|\btrimite(?:ti|ti)?\s+bani\b|\bpl[aă]t[a-z]*\s+(?:sum[aă]|taxa)\b", re.IGNORECASE),
    re.compile(r"\btrimite\s+transfer\s+bancar\b", re.IGNORECASE),
    re.compile(r"\btrimite\s+depunere\s+(?:initiala|inițial[ăa]?|bani|initial|sum[aă])\b|\bdepunere\s+(?:bani|initiala|inițial[ăa]?|sum[aă])\b", re.IGNORECASE),
    re.compile(r"\btrimite\s+confirmare\b|\btrimite\s+.+\s+confirmare\b", re.IGNORECASE),
)

MALWARE_APK_PATTERNS = (
    re.compile(r"\binstal\w*\s+.*\sapk\b", re.IGNORECASE),
    re.compile(r"\b(?:instaleaz[aăa]|instala\-?zi|instalare)\b\s+(?:app|aplicat\w+|aplicație|aplicatia|apk)\b", re.IGNORECASE),
    re.compile(r"\b(?:apk|app)\s+.*\b(?:fals|neoficial|suspect|scam)\b", re.IGNORECASE),
)

SENSITIVE_QR_PATTERNS = (
    re.compile(r"\b(?:qr|q\\s*r|cod\\s+qr)\b", re.IGNORECASE),
    re.compile(r"\b(?:scan\\w*|scanare|scan\\-at|scanat)\b", re.IGNORECASE),
    re.compile(r"\b(?:pl[aă]t[aă]|factur|abonament|parcare|reducer|taxa)\b", re.IGNORECASE),
)

SENSITIVE_SEXTORTION_PATTERNS = (
    re.compile(r"\b(?:camera|poze|video|imagini|fișiere|documente)\b", re.IGNORECASE),
    re.compile(r"\bplat[aă]\b.*\b(?:crypto|bani|suma|ron|eur)\b", re.IGNORECASE),
    re.compile(
        r"\b(?:ameninț|compromis|parole|acces)\b(?:\s+\w+){0,8}\b(?:plat[aă]|bani|taxa|sum[aă]|ron|eur)\b",
        re.IGNORECASE,
    ),
)

SENSITIVE_SIM_SWAP_PATTERNS = (
    re.compile(r"\bsim\b.*\b(?:swap|schimb|înlocui|actualizare)\b", re.IGNORECASE),
    re.compile(r"\b(?:date\s+personale|coduri?|codurile?)\b.*\b(?:acces|cont|operator|telefon)\b", re.IGNORECASE),
    re.compile(r"\b(?:abonament|linie)\b.*\b(?:nu\s+merge|nu\s+funcționează|schimbat|probleme)\b", re.IGNORECASE),
    re.compile(r"\bschimb\w*\b.*\bsim\b", re.IGNORECASE),
)

OLX_CARD_PATTERNS = (
    re.compile(r"\bprim\w*\s+bani\w*\s+direct\s+pe\s+card\b", re.IGNORECASE),
    re.compile(r"\bincaseaz[a-z]*\b|\bîncas[a-z]*\b|\bintroduce[a-z]*\s+card[a-z]*\s+pentru\s+a\s+primi\b", re.IGNORECASE),
)

REMOTE_ACCESS_PATTERNS = (
    re.compile(r"\b(anydesk|teamviewer|rustdesk)\b", re.IGNORECASE),
    re.compile(r"\b(?:instal|instale[az]i|instalare|instala|instalez|instalați)\b.*\b(?:aplica(?:ție|t?ie)|app|software|program)\b", re.IGNORECASE),
)

URGENCY_MANIPULATION_PATTERNS = (
    re.compile(r"\burgent[a-z]*\b|\burgenta\b|\bimediat\b|\b24\s*ore\b", re.IGNORECASE),
    re.compile(r"\bbloc[aă]t\b|\bsuspendat\b|\bexpir[aă]\b", re.IGNORECASE),
)

MANIPULATION_REWARD_PATTERNS = (
    re.compile(r"\bcâ[sș]tig[a-z]*\b|\bcastig[a-z]*\b|\bpremi[a-z]*\b", re.IGNORECASE),
    re.compile(r"\binvesti[a-z]*\b|\bprofit[a-z]*\b|\bgarantat[a-z]*\b|\bramburs[a-z]*\b", re.IGNORECASE),
)

DELIVERY_MANIPULATION_PATTERNS = (
    re.compile(r"\bcolet[a-z]*\b.*\b(?:taxa|vama|locker|awb|livr|ridic|adresa|expedi)\b", re.IGNORECASE),
    re.compile(r"\b(?:taxe|taxa|vam[a-z]*|locker)\b.*\b(?:colet|livrare|parcel|pachet)\b", re.IGNORECASE),
)


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

# Path to the seed JSON
SEED_PATH = "/Users/vaduvageorge/Desktop/NuDaClick/ScamShield_RO_NuDaClick_Implementation_Pack/scam_atlas_ro_2025_2026_seed.json"

# Brand Registry: whitelist of official domains for trusted brands in Romania
BRAND_REGISTRY: Dict[str, List[str]] = {
    "ANAF": ["anaf.ro", "mfinante.gov.ro", "mfinante.ro"],
    "Revolut": ["revolut.com", "revolut.me", "revolut.space"], # Revolut Space is a known official subdomain page sometimes, but let's stick to core
    "ING": ["ing.ro", "ing.com", "ingbusiness.ro"],
    "Banca Transilvania": [
        "bancatransilvania.ro",
        "btpay.ro",
        "neo-bt.ro",
        "neo.bancatransilvania.ro",
        "bt.ro",
    ],
    "BCR": ["bcr.ro", "george.bcr.ro"],
    "FAN Courier": ["fancourier.ro", "fanbox.ro", "fan-courier.ro"],
    "Posta Romana": ["posta-romana.ro"],
    "Sameday": ["sameday.ro", "sameday.delivery", "easybox.ro"],
    "DHL": ["dhl.ro", "dhl.com", "dhl-express.ro"],
    "eMAG": ["emag.ro", "emag.delivery"],
    "Uber": ["uber.com", "ubereats.com"],
    "YOXO": ["yoxo.ro", "buyback.yoxo.ro", "orange.ro"],
    "OLX": ["olx.ro"],
    "Google": ["google.com", "google.ro", "gmail.com"],
    "Microsoft": ["microsoft.com", "outlook.com", "office.com", "live.com"],
    "Meta": ["meta.com", "facebook.com", "instagram.com", "whatsapp.com"],
}

# Brand-specific exceptions for official/partner domains that should not trigger a hard mismatch.
# Keep this list tight; these are based on observed real-world official patterns.
BRAND_DOMAIN_EXCEPTIONS: Dict[str, List[str]] = {
    "ANAF": ["anaf-spv.info", "anaf-spv.ro", "anaf-spv.gov.ro"],
    "Uber": ["sng.link", "uber.link", "app.link", "branch.link", "bnc.lt"],
    "eMAG": ["sng.link", "app.link", "branch.link", "bnc.lt"],
}

# Trusted base names for typosquatting / lookalike detection
TRUSTED_BASE_NAMES: Dict[str, str] = {
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
    "posta-romana": "Posta Romana",
    "sameday": "Sameday",
    "dhl": "DHL",
    "dhl-express": "DHL",
    "emag": "eMAG",
    "uber": "Uber",
    "ubereats": "Uber",
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
    "meta": "Meta"
}

# Regex to detect brand name mentions in text
BRAND_MENTION_PATTERNS = {
    brand_name: re.compile(rf'\b{re.escape(brand_name)}\b', re.IGNORECASE)
    for brand_name in BRAND_REGISTRY.keys()
}

# Let's map specific common alternate spellings or sub-brands
BRAND_MENTION_PATTERNS["ANAF"] = re.compile(r'\banaf\b|\bspv\b|\bspatiul privat\b', re.IGNORECASE)
BRAND_MENTION_PATTERNS["Posta Romana"] = re.compile(r'\bposta\s*romana\b|\bposta\b', re.IGNORECASE)
BRAND_MENTION_PATTERNS["Banca Transilvania"] = re.compile(r'\bbanca\s*transilvania\b|\bbt\s*pay\b|\bbt\b', re.IGNORECASE)
BRAND_MENTION_PATTERNS["FAN Courier"] = re.compile(r'\bfan\s*courier\b|\bfan\b', re.IGNORECASE)
BRAND_MENTION_PATTERNS["Sameday"] = re.compile(r'\bsameday\b|\beasybox\b', re.IGNORECASE)
BRAND_MENTION_PATTERNS["Uber"] = re.compile(r'\buber\b|\buber\s*eats\b', re.IGNORECASE)
BRAND_MENTION_PATTERNS["YOXO"] = re.compile(r'\byoxo\b|\bbuy[\s-]?back\s+yoxo\b', re.IGNORECASE)


def _build_brand_mention_patterns(
    brand_registry: Dict[str, List[str]],
    aliases: Dict[str, List[str]],
) -> Dict[str, re.Pattern]:
    patterns: Dict[str, re.Pattern] = {}
    for brand_name in brand_registry.keys():
        candidates = aliases.get(brand_name, [])
        candidates = _dedupe_preserve_order(candidates + [brand_name])
        pattern = _pattern_from_aliases(candidates)
        if pattern:
            patterns[brand_name] = re.compile(pattern, re.IGNORECASE)
    return patterns


def _apply_loaded_brand_knowledge() -> None:
    global BRAND_REGISTRY, BRAND_DOMAIN_EXCEPTIONS, TRUSTED_BASE_NAMES, BRAND_MENTION_PATTERNS, _loaded_aliases

    loaded_registry = {
        k: _coerce_str_list(v)
        for k, v in _loaded_brand_knowledge.get("brand_registry", {}).items()
        if isinstance(k, str)
    }
    loaded_exceptions = {
        k: _coerce_str_list(v)
        for k, v in _loaded_brand_knowledge.get("brand_domain_exceptions", {}).items()
        if isinstance(k, str)
    }
    loaded_trusted_base_names = {
        k: str(v)
        for k, v in _loaded_brand_knowledge.get("trusted_base_names", {}).items()
        if isinstance(k, str) and isinstance(v, str)
    }
    loaded_aliases = {
        k: _coerce_str_list(v)
        for k, v in _loaded_brand_knowledge.get("brand_aliases", {}).items()
        if isinstance(k, str)
    }

    BRAND_REGISTRY = _merge_map_of_lists(BRAND_REGISTRY, loaded_registry)
    BRAND_DOMAIN_EXCEPTIONS = _merge_map_of_lists(BRAND_DOMAIN_EXCEPTIONS, loaded_exceptions)
    TRUSTED_BASE_NAMES = _merge_map_of_strings(TRUSTED_BASE_NAMES, loaded_trusted_base_names)
    _loaded_aliases = _merge_aliases(_loaded_aliases, loaded_aliases)
    BRAND_MENTION_PATTERNS = _build_brand_mention_patterns(BRAND_REGISTRY, _loaded_aliases)


_apply_loaded_brand_knowledge()


def _get_registrable_domain(extracted: "tldextract.ExtractResult") -> str:
    domain = getattr(extracted, "top_domain_under_public_suffix", "")
    if isinstance(domain, str) and domain.strip():
        return domain.strip().lower()
    return ""

class ScamAtlasEngine:
    def __init__(self):
        self.families = []
        self.load_seed_data()

    def load_seed_data(self):
        if os.path.exists(SEED_PATH):
            try:
                with open(SEED_PATH, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.families = data.get("scam_families", [])
            except Exception as e:
                print(f"Error loading Scam Atlas seed: {e}")
                self.families = []
        else:
            print(f"Scam Atlas seed not found at {SEED_PATH}")
            self.families = []

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
    ) -> bool:
        if not claimed_brand or claimed_brand not in BRAND_REGISTRY:
            return False

        allowed_domains = set(BRAND_REGISTRY[claimed_brand])
        allowed_domains.update(BRAND_DOMAIN_EXCEPTIONS.get(claimed_brand, []))
        if not allowed_domains:
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

        for allowed_domain in allowed_domains:
            allowed = str(allowed_domain).strip().lower()
            if not allowed:
                continue
            for candidate in candidates:
                if candidate == allowed or candidate.endswith(f".{allowed}"):
                    return True
        return False

    def _is_context_allowed_domain(
        self,
        reg_domain: str,
        hostname: str | None = None,
        claimed_brand: Optional[str] = None,
    ) -> bool:
        if self._is_whitelisted_domain(reg_domain, hostname=hostname):
            return True
        if claimed_brand and self._is_brand_allowed_domain(claimed_brand, reg_domain, hostname):
            return True
        return False

    def _is_ip_address(self, hostname: str) -> bool:
        if not hostname:
            return False
        return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", hostname))

    def _claimed_brand_base_candidates(self, claimed_brand: Optional[str]) -> List[str]:
        if not claimed_brand:
            return []
        return [base for base, brand in TRUSTED_BASE_NAMES.items() if brand == claimed_brand]

    def detect_claimed_brand(self, text: str) -> Optional[str]:
        """
        Detects if a trusted brand name is mentioned in the text.
        """
        for brand_name, pattern in BRAND_MENTION_PATTERNS.items():
            if pattern.search(text):
                return brand_name
        return None

    def check_brand_mismatch(self, claimed_brand: str, urls: List[Dict[str, Any]]) -> Tuple[bool, Optional[str]]:
        """
        Verifies if there is a mismatch: a trusted brand is claimed, but the links do not resolve
        to its official domain(s).
        Returns (has_mismatch, offending_registered_domain)
        """
        if not claimed_brand or claimed_brand not in BRAND_REGISTRY:
            return False, None

        for url_info in urls:
            reg_domain = (url_info.get("final_registered_domain") or url_info.get("registered_domain") or "").lower()
            hostname = (url_info.get("final_hostname") or url_info.get("hostname") or "").lower()
            if not hostname and (url_info.get("final_url") or url_info.get("url")):
                parsed = urllib.parse.urlparse(url_info.get("final_url") or url_info.get("url") or "")
                hostname = (parsed.hostname or "").lower()
            if self._is_brand_allowed_domain(claimed_brand, reg_domain, hostname):
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
            is_allowed_url = self._is_context_allowed_domain(reg_domain, hostname=hostname, claimed_brand=claimed_brand)
            scheme = (parsed.scheme or "").lower()
            port = parsed.port
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
            
            # Extract from final destination
            final_url = url_info.get("final_url") or url_info.get("url") or ""
            if final_url:
                ext = tldextract.extract(final_url)
                registrable_domain = _get_registrable_domain(ext)
                if registrable_domain:
                    domains_to_check.add(registrable_domain)
                parsed = urllib.parse.urlparse(final_url)
                hname = url_info.get("final_hostname") or parsed.hostname
                if hname:
                    hostnames_to_check.add(hname.lower())
                    
            # Extract from redirect chain hops
            for hop in url_info.get("redirect_chain", []):
                h = hop.get("hostname")
                reg = hop.get("registered_domain")
                if h:
                    hostnames_to_check.add(h.lower())
                if reg:
                    domains_to_check.add(reg.lower())

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
            is_official_url = self._is_context_allowed_domain(reg_domain, hostname=hostname, claimed_brand=claimed_brand)

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
        Handles Romanian inflections (e.g., card/cardul/cardurile, cod/codul/codurile).
        """
        signals = []
        
        # Credit Card CVC/OTP/PIN/Password (articulated or inflected)
        if (
            re.search(r"\bcard\b", text, re.IGNORECASE)
            and re.search(r"\b(?:numar|numărul|datele|detaliile|cvv|cvc|plat[aă]|trimite|transfer|scaneaz)\b", text, re.IGNORECASE)
        ):
            signals.append("Solicitare date sensibile (card, CVC, PIN, cod de securitate)")
        elif any(pattern.search(text) for pattern in SENSITIVE_CREDENTIAL_PATTERNS):
            signals.append("Solicitare date sensibile (card, CVC, PIN, cod de securitate)")
        
        # WhatsApp verification codes
        if any(pattern.search(text) for pattern in SENSITIVE_WHATSAPP_PATTERNS):
            signals.append("Solicitare cod de confirmare WhatsApp (takeover cont)")
            
        # Remote access apps
        if REMOTE_ACCESS_PATTERNS[0].search(text) and REMOTE_ACCESS_PATTERNS[1].search(text):
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
            and re.search(r"\b(?:qr|q\\s*r|cod\\s+qr)\b", text, re.IGNORECASE)
        ):
            signals.append("Solicitare de scanare/plată prin QR într-un context de risc")

        # Sextortion (digital blackmail)
        if any(pattern.search(text) for pattern in SENSITIVE_SEXTORTION_PATTERNS):
            signals.append("Semnal de șantaj digital: amenințare + cerere de plată")

        # SIM swap / telecom impersonation
        if any(pattern.search(text) for pattern in SENSITIVE_SIM_SWAP_PATTERNS):
            signals.append("Indicator de impostură pe SIM/abonament cu solicitare de acces sau date")

        return signals

    def check_language_manipulation(self, text: str) -> List[str]:
        """
        Detects urgency, fear, greed, authority-abuse signals with Romanian inflections.
        """
        signals = []
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

        for family in self.families:
            score = 0.0
            family_name = family.get("family", "").lower()
            hook = family.get("hook", "").lower()
            asks_for = family.get("asks_for") or []
            
            # Match by claimed brand
            if claimed_brand:
                # E.g. "FAN Courier" matches family "Curier fals / FAN Courier"
                if claimed_brand.lower() in family_name or claimed_brand.lower() in hook:
                    score += 0.5

            # Match keywords from hook
            hook_words = set(re.findall(r'\b\w+\b', hook))
            text_words = set(re.findall(r'\b\w+\b', text.lower()))
            overlap = hook_words.intersection(text_words)
            if overlap:
                score += len(overlap) * 0.1

            asks_overlap = 0
            for ask in asks_for:
                if not ask:
                    continue
                if ask.lower() in text.lower():
                    asks_overlap += 1
            if asks_overlap:
                score += min(0.5, asks_overlap * 0.15)

            # Check if any red flags or channel matches
            if score > highest_score:
                highest_score = score
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

        if confidence >= 0.2 and family.get("id") == "ro-2025-qr-quishing":
            if any(pattern.search(text) for pattern in SENSITIVE_QR_PATTERNS):
                score += 20
                reasons.append("Indicator specific quishing: context QR + semnale de plată/scanare")

        if confidence >= 0.2 and family.get("id") == "ro-2025-sextortion":
            if any(pattern.search(text) for pattern in SENSITIVE_SEXTORTION_PATTERNS):
                score += 20
                reasons.append("Indicator specific sextortion: șantaj digital + cerere financiară")

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
            }
        }
