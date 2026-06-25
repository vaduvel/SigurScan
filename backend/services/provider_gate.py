"""Provider-gate helpers extracted from ``runtime.py``."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import tldextract
import urllib.parse
from typing import Any, Callable, Dict, List, Optional, Tuple

from core.serialization import _deep_copy_jsonable
from core.text_utils import _normalise_obfuscated_text
from core.url_intelligence import _data_url_contains_sensitive_form
from runtime_state import engine
from services import dns_reputation
from services.scam_atlas import BRAND_ID_TO_DISPLAY_NAME, BRAND_WARNING_RULES
from services.verdict_gate import verdict as reduce_verdict
from app_stores import brand_truth_registry
from config import DOMAIN_ESTABLISHED_AGE_DAYS, DOMAIN_SUSPICIOUS_AGE_DAYS, ENABLE_DNS_REPUTATION
MAX_URLS_PER_SCAN = int(os.getenv("MAX_URLS_PER_SCAN", "15"))
# Regular expression to extract URLs from text
URL_REGEX = re.compile(
    r'(?:(?:https?://)|www\.|(?:[a-zA-Z0-9][a-zA-Z0-9+.-]*\.[a-zA-Z]{2,}))'
    r'[a-zA-Z0-9-._~:/?#\[\]@!$&\'()*+,;=%]*',
    re.IGNORECASE
)
NON_HTTP_DEEPLINK_REGEX = re.compile(
    r"\b([a-zA-Z][a-zA-Z0-9+.-]{1,31})://[^\s<>()\"']+",
    re.IGNORECASE,
)
DATA_URL_REGEX = re.compile(
    r"\bdata:(?P<mime>text/html|text/plain|application/xhtml\+xml)[^,\s<>()\"']*,(?P<body>[^\s<>()\"']{8,8192})",
    re.IGNORECASE,
)

GENERIC_LOOKALIKE_TOKENS = {
    "account",
    "accounts",
    "app",
    "client",
    "cont",
    "eportal",
    "login",
    "online",
    "pay",
    "payment",
    "plata",
    "plati",
    "portal",
    "secure",
    "service",
    "servicii",
    "verify",
}


_SOCIAL_ENGINEERING_PRESSURE_PATTERNS = (
    # authority / law-enforcement impersonation
    r"\b(parchet|procuror|comisar|poli[țt]i[ae]|politi[ae]|dosar\s+penal|mandat\s+de\s+aducere|"
    r"anchet[ăa]|ancheta|diicot|dna)\b",
    # secrecy / isolation
    r"\bnu\s+spune(?:ti|ți)?\s+nim[ăa]nui\b",
    r"\bnu\s+(?:discuta(?:ti|ți)?|spune(?:ti|ți)?)\b.{0,40}\b(nim[ăa]nui|familie|colegi|superiori)\b",
    r"\b(confiden[țt]ial|clasificat[ăa]?|[îi]ntre\s+noi)\b",
    # out-of-band callback / stay on the line
    r"\b(suna(?:ti|ți)?[-\s]?ne|suna(?:ti|ți)?\s+(?:urgent|acum|la)|reveni(?:ti|ți)\s+telefonic)\b",
    r"\br[ăa]m(?:a|â)ne(?:ti|ți)?\s+pe\s+(?:linie|fir)\b",
    # safe-account / move funds to a "protective" account
    r"\bcont(?:ul)?\s+(?:de\s+)?(?:siguran[țt][ăa]|protec[țt]ie|seif|temporar)\b",
    r"\b(transfera(?:ti|ți)?|muta(?:ti|ți)?|mut[ăa])\b.{0,60}\bcont(?:ul)?\s+(?:nou|sigur)\b",
    r"\bbeneficiar(?:ul)?\s+(?:de\s+)?(?:siguran[țt][ăa]|temporar)\b",
    r"\b(?:cod(?:ul)?\s+unic|cod(?:ul)?.{0,50}aplica[țt]ia\s+bancar[ăa]|cod(?:ul)?\s+qr.{0,40}esim)\b",
    # threat + coercion
    r"\b(arest|aresta(?:t|re)|re[țt]inere|re[țt]inut|dezactivat|clon[ăa])\b",
)


SOCIAL_ENGINEERING_INTENTS = {
    "credential_theft",
    "payment_redirection",
    "remote_access",
    "investment_fraud",
    "impersonation",
    "recovery_scam",
    "benign",
    "unknown",
}
SOCIAL_ENGINEERING_ASK_TYPES = {
    "transfer",
    "otp",
    "card",
    "remote_install",
    "gift_card",
    "seed_phrase",
    "callback",
    "none",
}
SOCIAL_ENGINEERING_LEVERS = {
    "authority",
    "fear",
    "urgency",
    "scarcity",
    "liking",
    "reciprocity",
    "social_proof",
    "loss_aversion",
    "sunk_cost",
    "compassion",
    "greed",
    "secrecy",
}


def _has_social_engineering_pressure(text: str) -> bool:
    """Heuristic: does the text apply social-engineering pressure (authority,
    secrecy, out-of-band callback, safe-account, threat) even without an explicit
    hard-sensitive keyword?

    Conservative for recall, but intentionally excludes ordinary marketing and
    legitimate transactional wording, so the tier1 benign override is blocked only
    on genuine manipulation — never on a real BT/Sameday/marketing message.
    """
    normalized = _normalise_obfuscated_text(text or "").lower()
    if not normalized:
        return False
    return any(re.search(pattern, normalized) for pattern in _SOCIAL_ENGINEERING_PRESSURE_PATTERNS)
def _source_status_impl(summary: Dict[str, Any], source_name: str) -> str:
    raw = summary.get(source_name)
    if not isinstance(raw, dict):
        return "missing"
    return str(raw.get("verdict") or raw.get("status") or "unknown").strip().lower()


def _source_consulted_impl(summary: Dict[str, Any], source_name: str) -> bool:
    raw = summary.get(source_name)
    return bool(isinstance(raw, dict) and raw.get("consulted", False))


def _source_ready(summary: Dict[str, Any], source_name: str) -> bool:
    return _source_ready_impl(summary, source_name)


def _source_ready_impl(summary: Dict[str, Any], source_name: str) -> bool:
    status = _source_status(summary, source_name)
    return _source_consulted(summary, source_name) and status not in {"missing", "unknown", "error"}


def _normalize_claimed_brand(raw_brand: str) -> str:
    normalized = str(raw_brand or "").strip().lower()
    if not normalized or normalized in {"nespecificat", "unknown", "none"}:
        return ""
    return normalized


def _compact_brand_match_token(raw: str) -> str:
    text = _normalise_obfuscated_text(str(raw or "")).lower()
    return re.sub(r"[^a-z0-9]+", "", text)


def _first_final_url(resolved_urls: List[Dict[str, Any]]) -> Optional[str]:
    for entry in resolved_urls:
        final_url = entry.get("final_url") or entry.get("url") or entry.get("original_url")
        if isinstance(final_url, str) and final_url.strip():
            return final_url.strip()
    return None


def _first_domain_age_days(resolved_urls: List[Dict[str, Any]]) -> Optional[int]:
    for entry in resolved_urls or []:
        if not isinstance(entry, dict):
            continue
        try:
            value = entry.get("domain_age_days")
            if value is not None:
                return int(value)
        except (TypeError, ValueError):
            continue
    return None


def _domain_reputation_from_age(age_days: Optional[int]) -> str:
    if age_days is None:
        return "unknown"
    if age_days >= DOMAIN_ESTABLISHED_AGE_DAYS:
        return "established"
    if age_days < DOMAIN_SUSPICIOUS_AGE_DAYS:
        return "new"
    return "young"


def _official_destination_confirmed_impl(resolved_urls: List[Dict[str, Any]], claimed_brand: str) -> bool:
    saw_allowed_destination = False
    for entry in resolved_urls:
        reg_domain = str(entry.get("final_registered_domain") or entry.get("registered_domain") or "").lower()
        hostname = str(entry.get("final_hostname") or entry.get("hostname") or "").lower()
        final_url = str(entry.get("final_url") or entry.get("url") or "")
        if not hostname and final_url:
            hostname = urllib.parse.urlparse(final_url).hostname or ""
        normalized_claim_for_destination = _normalize_claimed_brand(claimed_brand)
        if normalized_claim_for_destination:
            destination_allowed = engine._is_brand_allowed_domain(
                claimed_brand,
                reg_domain,
                hostname=hostname,
                url=final_url,
            )
        else:
            destination_allowed = engine._is_context_allowed_domain(
                reg_domain,
                hostname=hostname,
                claimed_brand=None,
                url=final_url,
            )
        if destination_allowed:
            saw_allowed_destination = True
            continue
        original_hostname = str(entry.get("hostname") or "").lower()
        original_reg_domain = str(entry.get("registered_domain") or "").lower()
        original_url = str(entry.get("url") or "")
        if not original_hostname and original_url:
            original_hostname = urllib.parse.urlparse(original_url).hostname or ""
        original_is_brand_delegated = engine._is_context_allowed_domain(
            original_reg_domain,
            hostname=original_hostname,
            claimed_brand=claimed_brand,
            url=original_url,
        )
        final_hostname = str(entry.get("final_hostname") or hostname or "").lower()
        normalized_brand = _normalize_claimed_brand(claimed_brand)
        if (
            original_is_brand_delegated
            and "yoxo" in normalized_brand
            and final_hostname in {"apps.apple.com", "play.google.com"}
            and "yoxo" in urllib.parse.unquote(final_url).lower()
        ):
            saw_allowed_destination = True
            continue

        final_url = str(entry.get("final_url") or entry.get("url") or "")
        normalized_brand = _normalize_claimed_brand(claimed_brand)
        compact_brand = _compact_brand_match_token(normalized_brand)
        compact_domain = _compact_brand_match_token(reg_domain or hostname)
        try:
            age_days = int(entry.get("domain_age_days")) if entry.get("domain_age_days") is not None else None
        except (TypeError, ValueError):
            age_days = None
        suspicious_unofficial = bool(
            entry.get("uses_shortener")
            or (age_days is not None and age_days < DOMAIN_SUSPICIOUS_AGE_DAYS)
            or reg_domain.endswith((".top", ".xyz", ".click", ".work", ".quest", ".icu", ".shop"))
            or (compact_brand and compact_brand in compact_domain)
            or any(token in final_url.lower() for token in ("login", "auth", "card", "pay", "plata", "anulare", "confirm"))
        )
        if suspicious_unofficial:
            return False
    return saw_allowed_destination


def _official_destination_confirmed(
    resolved_urls: List[Dict[str, Any]],
    claimed_brand: str,
) -> bool:
    return _official_destination_confirmed_impl(
resolved_urls,
        claimed_brand,

    )


def _collect_infrastructure_flags_impl(
    analysis: Dict[str, Any],
    resolved_urls: List[Dict[str, Any]],
    *,
    official_destination: bool = False,
) -> Dict[str, Any]:
    evidence = analysis.get("evidence", {}) if isinstance(analysis.get("evidence"), dict) else {}
    lexical_evidence = evidence.get("url_lexical") if isinstance(evidence.get("url_lexical"), dict) else {}
    lexical_text = " ".join(str(item) for item in lexical_evidence.get("reasons", []) if item).lower()
    extracted_urls = evidence.get("extracted_urls") if isinstance(evidence.get("extracted_urls"), list) else resolved_urls
    url_behaviour = evidence.get("url_behaviour") if isinstance(evidence.get("url_behaviour"), dict) else {}
    url_transport = evidence.get("url_transport") if isinstance(evidence.get("url_transport"), dict) else {}

    age_days = []
    for item in extracted_urls or []:
        if not isinstance(item, dict):
            continue
        value = item.get("domain_age_days")
        try:
            if value is not None:
                age_days.append(int(value))
        except (TypeError, ValueError):
            continue

    youngest_domain_age_days = min(age_days) if age_days else None
    domain_signals = evidence.get("domain_signals") if isinstance(evidence.get("domain_signals"), dict) else {}
    rdap_age = domain_signals.get("domain_age_days")
    if rdap_age is not None and youngest_domain_age_days is None:
        youngest_domain_age_days = rdap_age

    terminal_host_unreachable = bool(
        domain_signals.get("unreachable")
        and (
            not official_destination
            or domain_signals.get("dns_nxdomain")
            or domain_signals.get("rdap_404")
        )
    )
    lexical_typosquat = (
        "typosquatting" in lexical_text
        or "lookalike" in lexical_text
        or "mismatch critic" in lexical_text
    )

    return {
        "typosquat": bool(lexical_typosquat and not official_destination),
        "homoglyph": "homoglif" in lexical_text or "homoglyph" in lexical_text,
        "punycode": "punycode" in lexical_text or "idn/punycode" in lexical_text,
        "dga_entropy": "entropie ridicat" in lexical_text or "entropie mare" in lexical_text or "entropy" in lexical_text or "dga" in lexical_text,
        "very_new_domain": youngest_domain_age_days is not None and youngest_domain_age_days < 7,
        "suspicious_domain_age": youngest_domain_age_days is not None and youngest_domain_age_days < DOMAIN_SUSPICIOUS_AGE_DAYS,
        "established_domain": youngest_domain_age_days is not None and youngest_domain_age_days >= DOMAIN_ESTABLISHED_AGE_DAYS,
        "url_behaviour": bool(url_behaviour),
        "url_transport": bool(url_transport),
        "youngest_domain_age_days": youngest_domain_age_days,
        "rdap_inexistent": bool(domain_signals.get("rdap_404")),
        "domain_young": bool(domain_signals.get("domain_young")),
        "ssl_invalid": bool(domain_signals.get("ssl_valid") is False),
        "cert_very_young": bool(domain_signals.get("cert_young")),
        "host_unreachable": terminal_host_unreachable,
    }


def _collect_infrastructure_flags(
    analysis: Dict[str, Any],
    resolved_urls: List[Dict[str, Any]],
    *,
    official_destination: bool = False,
) -> Dict[str, Any]:
    return _collect_infrastructure_flags_impl(
analysis,
        resolved_urls,
        official_destination=official_destination,

    )


def _augment_summary_with_infra_flags_impl(summary: Dict[str, Any], infra_flags: Dict[str, Any]) -> None:
    lexical_labels: List[str] = []
    if infra_flags.get("homoglyph"):
        lexical_labels.append("homoglyph")
    if infra_flags.get("punycode"):
        lexical_labels.append("punycode")
    if infra_flags.get("typosquat"):
        lexical_labels.append("typosquatting")
    if infra_flags.get("dga_entropy"):
        lexical_labels.append("entropy")
    if lexical_labels:
        summary["sigurscan_lexical"] = {
            "status": "suspicious",
            "verdict": ",".join(lexical_labels),
            "severity": "high" if any(label in {"homoglyph", "punycode", "typosquatting"} for label in lexical_labels) else "medium",
            "consulted": True,
            "details": "signals=" + ",".join(lexical_labels),
        }

    youngest_domain_age_days = infra_flags.get("youngest_domain_age_days")
    if youngest_domain_age_days is not None and infra_flags.get("suspicious_domain_age"):
        summary["infra_domain_age"] = {
            "status": "suspicious",
            "verdict": "very_new_domain" if infra_flags.get("very_new_domain") else "new_domain",
            "severity": "high" if infra_flags.get("very_new_domain") else "medium",
            "consulted": True,
            "details": f"domain_age_days={youngest_domain_age_days}",
        }
    elif youngest_domain_age_days is not None and infra_flags.get("established_domain"):
        summary["infra_domain_age"] = {
            "status": "clean",
            "verdict": "established_domain",
            "severity": "low",
            "consulted": True,
            "details": f"domain_age_days={youngest_domain_age_days}",
        }

    if infra_flags.get("url_behaviour"):
        summary["infra_url_behaviour"] = {
            "status": "suspicious",
            "verdict": "url_behaviour",
            "severity": "medium",
            "consulted": True,
            "details": "backend url_behaviour flags present",
        }

    if infra_flags.get("url_transport"):
        summary["infra_url_transport"] = {
            "status": "suspicious",
            "verdict": "url_transport",
            "severity": "medium",
            "consulted": True,
            "details": "backend url_transport flags present",
        }

    if infra_flags.get("rdap_inexistent"):
        # Weighted signal only, never terminal: severity stays below "high" so
        # _providers_verdict cannot turn an RDAP 404 into a standalone
        # PERICULOS (rdap.org 404s also happen for TLDs it cannot route).
        summary["infra_rdap"] = {
            "status": "suspicious",
            "verdict": "inexistent_domain",
            "severity": "medium",
            "consulted": True,
            "details": "Domeniul nu apare în registrul RDAP (404); semnal ponderat, nu verdict.",
        }

    if infra_flags.get("ssl_invalid"):
        # severity stays below "high": standalone invalid SSL is a weighted
        # signal; the terminal path for SSL is the deterministic combo rule
        # (young domain + invalid SSL + impersonated brand) in verdict_gate.
        summary["infra_ssl"] = {
            "status": "suspicious",
            "verdict": "invalid_certificate",
            "severity": "medium",
            "consulted": True,
            "details": "Certificatul SSL este invalid sau auto-semnat",
        }


def _augment_summary_with_infra_flags(summary: Dict[str, Any], infra_flags: Dict[str, Any]) -> None:
    return _augment_summary_with_infra_flags_impl(
summary,
        infra_flags,

    )


def _dedupe_preserve_order(values: List[str]) -> List[str]:
    seen = set()
    output: List[str] = []
    for value in values:
        if not value:
            continue
        if value in seen:
            continue
        seen.add(value)
        output.append(value)
    return output
def _non_http_deeplink_context(text: str) -> Dict[str, Any]:
    normalized_text = _normalise_obfuscated_text(text or "")
    schemes: List[str] = []
    seen = set()
    for match in NON_HTTP_DEEPLINK_REGEX.finditer(normalized_text):
        scheme = str(match.group(1) or "").strip().lower()
        if scheme in {"http", "https"} or not scheme:
            continue
        if scheme not in seen:
            seen.add(scheme)
            schemes.append(scheme)
        if len(schemes) >= MAX_URLS_PER_SCAN:
            break
    if DATA_URL_REGEX.search(normalized_text) and "data" not in seen:
        seen.add("data")
        schemes.append("data")
    return {
        "present": bool(schemes),
        "count": len(schemes),
        "schemes": schemes,
        "preview_supported": False,
    }
def _decoded_data_url_text(raw_text: str) -> str:
    normalized = _normalise_obfuscated_text(raw_text or "")
    decoded_parts: List[str] = []
    for match in DATA_URL_REGEX.finditer(normalized):
        whole = match.group(0) or ""
        body = match.group("body") or ""
        try:
            if ";base64" in whole[:80].lower():
                padded = body + ("=" * (-len(body) % 4))
                raw = base64.b64decode(padded, validate=False)
            else:
                raw = urllib.parse.unquote_to_bytes(body)
            decoded = raw[:8192].decode("utf-8", errors="replace")
        except Exception:
            continue
        if decoded:
            decoded_parts.append(_normalise_obfuscated_text(decoded))
    return "\n".join(decoded_parts)
def _provider_payload_is_hard_bad(raw: Dict[str, Any], *, include_suspicious: bool = False) -> bool:
    bad_tokens = ("malicious", "phishing", "phish", "malware", "dangerous", "blacklisted")
    if include_suspicious:
        bad_tokens = bad_tokens + ("suspicious",)
    benign_phrases = ("no malicious", "not malicious", "no classification", "no malicious classification")
    status = str(raw.get("status") or "").strip().lower()
    if status in {"clean", "no_match", "no-match", "safe", "unknown", "missing", "error"}:
        return False
    if any(token in status for token in bad_tokens):
        return True
    verdict = str(raw.get("verdict") or raw.get("threat_type") or "").strip().lower()
    if any(phrase in verdict for phrase in benign_phrases):
        return False
    return any(token in verdict for token in bad_tokens)
def _has_authoritative_bad_provider_verdict(summary: Dict[str, Any]) -> bool:
    # „dns_security" = bloc autoritar de DNS de securitate (Cloudflare/Quad9),
    # tratat ca provider hard-bad (status malicious), la fel ca Web Risk/URLhaus.
    for name in (
        "google_web_risk",
        "asf_investor_alerts",
        "phishing_database",
        "phishtank_online_valid",
        "openphish",
        "urlscan",
        "urlscan.io",
        "urlhaus",
        "dns_security",
    ):
        raw = summary.get(name)
        if isinstance(raw, dict) and _provider_payload_is_hard_bad(raw):
            return True
    return False
def _has_bad_provider_verdict(summary: Dict[str, Any]) -> bool:
    if _has_authoritative_bad_provider_verdict(summary):
        return True

    provider_names = (
        "google_web_risk",
        "asf_investor_alerts",
        "phishing_database",
        "phishtank_online_valid",
        "openphish",
        "urlscan",
        "urlscan.io",
        "urlhaus",
        "dns_security",
    )
    for name in provider_names:
        raw = summary.get(name)
        if isinstance(raw, dict) and _provider_payload_is_hard_bad(raw):
            return True
    return False
def _strip_url_tokens_for_brand_match(raw_text: str) -> str:
    text = str(raw_text or "")
    text = re.sub(r"https?://\S+", " ", text, flags=re.IGNORECASE)
    text = re.sub(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/[^\s]*)?", " ", text, flags=re.IGNORECASE)
    return text
def _domain_base_for_first_party_match(entry: Dict[str, Any]) -> str:
    raw_domain = str(
        entry.get("final_registered_domain")
        or entry.get("registered_domain")
        or entry.get("final_hostname")
        or entry.get("hostname")
        or ""
    ).strip().lower()
    if not raw_domain:
        raw_url = str(entry.get("final_url") or entry.get("url") or "").strip()
        raw_domain = urllib.parse.urlparse(raw_url).hostname or ""
    if not raw_domain:
        return ""
    extracted = tldextract.extract(raw_domain)
    return str(extracted.domain or "").strip().lower()
def _first_party_domain_claim_from_text(raw_text: str, resolved_urls: List[Dict[str, Any]]) -> Optional[str]:
    """Infer a weak first-party identity only when text names the final domain.

    This is intentionally not a broad allowlist. It prevents false positives for
    real small/unknown brands like Hipo or Cetelem, while avoiding the classic
    phishing bypass where a compound domain such as fancurier-relivrare.com
    merely contains a protected brand string.
    """

    narrative = _strip_url_tokens_for_brand_match(raw_text)
    compact_text = _compact_brand_match_token(narrative)
    if not compact_text:
        return None

    ignored_bases = {"www", "http", "https", "login", "secure", "account", "app", "link"}
    for entry in resolved_urls or []:
        if not isinstance(entry, dict):
            continue
        base = _domain_base_for_first_party_match(entry)
        compact_base = _compact_brand_match_token(base)
        if len(compact_base) < 4 or compact_base in ignored_bases:
            continue
        if "-" in base or "_" in base:
            continue
        if compact_base in compact_text:
            return base
    return None
def _claimed_brand_exact_domain_match(claimed_brand: str, resolved_urls: List[Dict[str, Any]]) -> Optional[str]:
    normalized = _normalize_claimed_brand(claimed_brand)
    if not normalized:
        return None
    ignored_tokens = {
        "romania",
        "românia",
        "romanian",
        "official",
        "oficial",
        "bank",
        "banca",
        "srl",
        "sa",
        "spa",
        "ltd",
        "gmbh",
    }
    brand_tokens = {
        _compact_brand_match_token(token)
        for token in re.split(r"[^a-zA-Z0-9ăâîșțĂÂÎȘȚ]+", normalized)
        if token
    }
    brand_tokens = {token for token in brand_tokens if len(token) >= 4 and token not in ignored_tokens}
    if not brand_tokens:
        return None

    for entry in resolved_urls or []:
        if not isinstance(entry, dict):
            continue
        base = _domain_base_for_first_party_match(entry)
        compact_base = _compact_brand_match_token(base)
        if len(compact_base) < 4:
            continue
        if "-" in base or "_" in base:
            continue
        if compact_base in brand_tokens:
            return base
    return None
def _has_positive_user_action_request(raw_text: str) -> bool:
    normalized = _normalise_obfuscated_text(raw_text or "").lower()
    if not normalized or _looks_like_official_safety_education(normalized):
        return False
    action_pattern = re.compile(
        r"\b("
        r"acces(?:eaz[ăa]|a[țt]i|ati)|deschid(?:e|e[țt]i|eti)|intr[ăa]|intra[țt]i|intrati|"
        r"logheaz[ăa][-\s]?te|autentific[ăa][-\s]?te|login|"
        r"introdu\w*|completeaz\w*|trimite\w*|r[ăa]spunde\w*|spune\w*|comunic\w*|"
        r"d[ăa](?:[-\s]?(?:mi|ne))?|da[țt]i(?:[-\s]?(?:mi|ne))?|dati(?:[-\s]?(?:mi|ne))?|"
        r"furnizeaz\w*|ofer[ăa]\w*|cite[șs]te|citeste|captur\w*|screenshot|poz[ăa]|"
        r"scan(?:eaz[ăa]|a[țt]i|ati)|"
        r"confirm\w*|valideaz\w*|verific\w*|activeaz\w*|reactiveaz\w*|"
        r"pl[ăa]t(?:e[șs]te|i[țt]i|iti)|achit(?:[ăa]|a[țt]i|ati)|transfer(?:[ăa]|a[țt]i|ati)|"
        r"depune\w*|instal\w*|descarc\w*|sun[ăa]|suna[țt]i|sunati|apeleaz\w*"
        r")\b",
        re.IGNORECASE,
    )
    for match in action_pattern.finditer(normalized):
        window_before = normalized[max(0, match.start() - 32) : match.start()]
        if re.search(r"\b(nu|niciodat[ăa]|f[ăa]r[ăa]|evit[ăa]|evita[țt]i|evitati)\b", window_before):
            continue
        return True
    return False
def _normalise_counterparty_name(value: str) -> str:
    normalized = _normalise_obfuscated_text(value or "").lower()
    normalized = re.sub(
        r"\b(?:s\.?r\.?l\.?|sa|s\.?a\.?|srl|pfa|ii|if|ltd|limited|gmbh|ag|bv|s\.?c\.?)\b",
        " ",
        normalized,
        flags=re.IGNORECASE,
    )
    normalized = re.sub(r"[^a-z0-9ăâîșț]+", " ", normalized, flags=re.IGNORECASE)
    return " ".join(normalized.split())
def _has_invoice_payment_beneficiary_mismatch(raw_text: str) -> bool:
    normalized = _normalise_obfuscated_text(raw_text or "")
    issuer = re.search(r"\bemitent\s*:\s*([^\n\r;|]{3,100})", normalized, re.IGNORECASE)
    payment_beneficiary = re.search(
        r"\bbeneficiar\s+plat[ăa]\s*:\s*([^\n\r;|]{3,100})",
        normalized,
        re.IGNORECASE,
    )
    if not issuer or not payment_beneficiary:
        return False
    issuer_name = _normalise_counterparty_name(issuer.group(1))
    beneficiary_name = _normalise_counterparty_name(payment_beneficiary.group(1))
    return bool(issuer_name and beneficiary_name and issuer_name != beneficiary_name)
def _local_request_intent_analysis(raw_text: str) -> Dict[str, Any]:
    official_safety_education = _looks_like_official_safety_education(raw_text)
    positive_action_request = _has_positive_user_action_request(raw_text)
    descriptive_context = _looks_like_descriptive_or_status_context(raw_text)
    if official_safety_education:
        positive_action_request = False
    elif descriptive_context and not _has_direct_sensitive_request(raw_text):
        # Audit/status snippets often say "furnizorul trimite factura" or
        # "IBAN HMAC match"; that describes evidence, not an instruction.
        positive_action_request = _has_explicit_user_directed_action(raw_text)
    return {
        "status": "done",
        "positive_action_request": bool(positive_action_request),
        "protective_warning": bool(official_safety_education),
        "descriptive_context": bool(descriptive_context),
        "source": "local_request_intent_v1",
    }
def _has_investment_money_risk(raw_text: str) -> bool:
    normalized = _normalise_obfuscated_text(raw_text or "").lower()
    if not normalized:
        return False

    investment_context = bool(re.search(
        r"\b("
        r"investi[țt]i(?:e|i|ilor|ilor)?|investit(?:i|e|or)|trading|broker|randament|profit|"
        r"platform[ăa]\s+(?:de\s+)?(?:investi[țt]ii|trading)|portofoliu|crypto|wallet|asf|"
        r"grup(?:ul)?\s+(?:educa[țt]ional|de\s+investi[țt]ii)|whatsapp|telegram"
        r")\b",
        normalized,
        re.IGNORECASE,
    ))
    if not investment_context:
        return False

    positive_money_action = bool(re.search(
        r"\b("
        r"depune(?:[țt]i|ti)?|depun(?:e|e[țt]i|eti)|depozit(?:eaz[ăa])?|alimenteaz[ăa]|"
        r"investi[țt]i(?:[țt]i|ti)?|achit(?:a|[ăa]|a[țt]i|ati)|pl[ăa]t(?:e[șs]te|i[țt]i|iti)|"
        r"transfer(?:a|[ăa]|a[țt]i|ati)|tax[ăa]|comision|validare|retragere|wallet|crypto|"
        r"ron|lei|eur|euro|usd|dolari|\d+\s*%"
        r")\b",
        normalized,
        re.IGNORECASE,
    ))
    guaranteed_return = bool(re.search(
        r"\b(randament|profit|c[âa]știg|castig|venit)\b.{0,50}\b(garantat|fix|sigur|\d+\s*%)\b",
        normalized,
        re.IGNORECASE,
    ))
    withdrawal_fee = bool(re.search(
        r"\b(tax[ăa]|comision|validare)\b.{0,60}\b(retragere|profit|c[âa]știg|castig)\b",
        normalized,
        re.IGNORECASE,
    ))
    direct_warning = bool(re.search(
        r"\b(nu\s+(?:investi|depune|achita|pl[ăa]ti|transfera)|nu\s+da\s+curs)\b",
        normalized,
        re.IGNORECASE,
    ))
    if direct_warning and not (positive_money_action or guaranteed_return or withdrawal_fee):
        return False
    return positive_money_action or guaranteed_return or withdrawal_fee
def _resolved_urls_have_suspicious_public_tld(resolved_urls: List[Dict[str, Any]]) -> bool:
    suspicious_suffixes = (
        ".top",
        ".xyz",
        ".click",
        ".work",
        ".quest",
        ".icu",
        ".shop",
        ".live",
        ".site",
        ".info",
    )
    for entry in resolved_urls:
        if not isinstance(entry, dict):
            continue
        for key in ("final_registered_domain", "registered_domain", "final_hostname", "hostname"):
            host = str(entry.get(key) or "").strip().lower()
            if host.endswith(suspicious_suffixes):
                return True
    return False
def _source_is_suspicious(summary: Dict[str, Any], name: str) -> bool:
    raw = summary.get(name)
    if not isinstance(raw, dict) or not _source_consulted(summary, name):
        return False
    status = str(raw.get("status") or "").strip().lower()
    verdict_status = _source_status(summary, name)
    return status == "suspicious" or verdict_status == "suspicious"
def _provider_verdict_for_decision_bundle(
    summary: Dict[str, Any],
    *,
    has_urls: bool,
    resolved_urls: Optional[List[Dict[str, Any]]] = None,
    official_destination: bool = False,
    pillars: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    if _has_bad_provider_verdict(summary):
        return {"verdict": "malicious", "hits": ["provider_malicious"], "completeness": True}

    suspicious_hits = []
    for name in ("scam_blocklist_nrd", "phishdestroy_destroylist"):
        if _source_is_suspicious(summary, name):
            suspicious_hits.append(name)
    if has_urls and not official_destination and _resolved_urls_have_suspicious_public_tld(resolved_urls or []):
        for name in ("infra_dns", "infra_url_behaviour", "infra_url_transport", "sigurscan_lexical"):
            if _source_is_suspicious(summary, name):
                suspicious_hits.append(name)
    if suspicious_hits:
        return {
            "verdict": "suspicious",
            "hits": suspicious_hits,
            "completeness": True,
        }

    if isinstance(pillars, dict):
        pending_required = []
        error_required = []
        for name, pillar in pillars.items():
            if not isinstance(pillar, dict) or not pillar.get("required", True):
                continue
            status = str(pillar.get("status") or "").strip().lower()
            if status == "pending":
                pending_required.append(name)
            elif status == "error":
                error_required.append(name)
        if pending_required:
            return {"verdict": "pending", "hits": [], "completeness": False, "pending": pending_required}
        if error_required:
            return {"verdict": "unknown", "hits": [], "completeness": True, "errors": error_required}

    if not has_urls:
        return {"verdict": "unknown", "hits": [], "completeness": True}

    consulted = []
    unknown = []
    for name in (
        "google_web_risk",
        "asf_investor_alerts",
        "phishing_database",
        "phishtank_online_valid",
        "openphish",
        "urlscan",
        "urlscan.io",
        "urlhaus",
        "scam_blocklist_nrd",
        "phishdestroy_destroylist",
        "ai_offer_web_check",
    ):
        raw = summary.get(name)
        if not isinstance(raw, dict):
            continue
        status = _source_status(summary, name)
        if raw.get("consulted") or status not in {"missing", ""}:
            consulted.append(name)
        if status in {"missing", "unknown", "error"}:
            unknown.append(name)
    urlscan_optional = False
    if isinstance(pillars, dict):
        urlscan_pillar = pillars.get("urlscan")
        urlscan_optional = isinstance(urlscan_pillar, dict) and not urlscan_pillar.get("required", True)
    if not any(name in consulted for name in ("urlscan", "urlscan.io")) and not urlscan_optional:
        return {"verdict": "pending", "hits": sorted(set(consulted)), "completeness": False, "pending": ["urlscan"]}
    if consulted and len(unknown) < len(consulted):
        return {"verdict": "clean", "hits": sorted(set(consulted)), "completeness": True}
    return {"verdict": "pending", "hits": [], "completeness": False}
def _brand_token_lookalike_in_resolved_urls(resolved_urls: List[Dict[str, Any]]) -> Optional[str]:
    """Detectează domenii care conțin un token de brand cunoscut dar NU sunt oficiale.

    General: orice domeniu care conține un brand token (ex: 'anaf', 'bcr', 'bt', 'ing')
    dar NU e în BRAND_REGISTRY pentru acel brand = lookalike.

    Returnează brandul impersonat sau None.
    Prinde: anaf-spv.info, bcr-secure.info, bt-login.xyz, revolut-verify.top, etc.
    NU prinde: smart-menu.ro, restaurant.example (nu conțin brand tokens).
    """
    if not resolved_urls:
        return None
    try:
        from services.scam_atlas import BRAND_REGISTRY, OFFICIAL_REGISTRY_LOOKALIKE_TOKENS, TRUSTED_BASE_NAMES
    except Exception:
        return None
    for entry in resolved_urls:
        if not isinstance(entry, dict):
            continue
        hostname = str(entry.get("final_hostname") or entry.get("hostname") or "").strip().lower()
        registered_domain = str(entry.get("final_registered_domain") or entry.get("registered_domain") or "").strip().lower()
        final_url = str(entry.get("final_url") or entry.get("url") or "").strip()
        if not hostname and not registered_domain:
            continue
        candidate = registered_domain or hostname
        # Extrage base name (fără TLD) și tokenizează pe -, _, .
        try:
            extracted = tldextract.extract(hostname or candidate)
            base = (extracted.domain or "").strip().lower()
            subdomain = (extracted.subdomain or "").strip().lower()
        except Exception:
            base = candidate.split(".")[0] if "." in candidate else candidate
            subdomain = ""
        if not base or len(base) < 2:
            continue
        tokens = set()
        # Tokenize base (registered domain)
        for sep in ("-", "_", "."):
            if sep in base:
                tokens.update(t for t in base.split(sep) if t and len(t) >= 2)
        tokens.add(base)
        # Tokenize și subdomeniul (prinde bcr.secure-login.atacator.com)
        if subdomain:
            for sep in ("-", "_", "."):
                if sep in subdomain:
                    tokens.update(t for t in subdomain.split(sep) if t and len(t) >= 2)
            tokens.add(subdomain)
        compact_base = _compact_brand_match_token(base)
        if compact_base:
            tokens.add(compact_base)
        tokens = {token for token in tokens if token}
        # Verifică fiecare token contra TRUSTED_BASE_NAMES
        for token in sorted(tokens, key=len, reverse=True):
            normalized_token = str(token or "").strip().lower()
            if normalized_token in GENERIC_LOOKALIKE_TOKENS:
                continue
            brand = TRUSTED_BASE_NAMES.get(normalized_token) or OFFICIAL_REGISTRY_LOOKALIKE_TOKENS.get(normalized_token)
            if not brand:
                continue
            official_domains = BRAND_REGISTRY.get(brand, [])
            # Domeniul e oficial dacă registered_domain sau hostname e în listă
            is_official = any(
                candidate == d or candidate.endswith(f".{d}") or hostname == d or hostname.endswith(f".{d}")
                for d in official_domains
            )
            if not is_official:
                is_official = engine._is_context_allowed_domain(
                    registered_domain,
                    hostname=hostname,
                    claimed_brand=brand,
                    url=final_url,
                )
            if not is_official:
                return brand
    return None
def _brand_userinfo_spoof_in_resolved_urls(resolved_urls: List[Dict[str, Any]]) -> Optional[str]:
    """Detect URLs abusing userinfo to display a trusted brand before '@'.

    Example: https://bt.ro@secure-beneficiar.example/ shows "bt.ro" first but
    the real host is secure-beneficiar.example. This is a generic credential/
    brand-spoof primitive, not a domain-specific exception.
    """
    if not resolved_urls:
        return None
    try:
        from services.scam_atlas import OFFICIAL_REGISTRY_LOOKALIKE_TOKENS, TRUSTED_BASE_NAMES
    except Exception:
        OFFICIAL_REGISTRY_LOOKALIKE_TOKENS = {}
        TRUSTED_BASE_NAMES = {}

    for entry in resolved_urls:
        if not isinstance(entry, dict):
            continue
        privacy = entry.get("url_privacy") if isinstance(entry.get("url_privacy"), dict) else {}
        if privacy.get("reason") == "url_credentials_removed":
            return "url_userinfo"
        for key in ("final_url", "url", "original_url"):
            candidate_url = str(entry.get(key) or "").strip()
            if not candidate_url:
                continue
            try:
                parsed = urllib.parse.urlparse(candidate_url)
            except Exception:
                continue
            userinfo = parsed.username or ""
            if parsed.password:
                userinfo = f"{userinfo}:{parsed.password}" if userinfo else parsed.password
            if not userinfo:
                continue
            host = (parsed.hostname or "").strip().lower()
            userinfo_lower = urllib.parse.unquote(userinfo).strip().lower()
            userinfo_tokens = {
                token
                for token in re.split(r"[^a-z0-9ăâîșț]+", userinfo_lower)
                if len(token) >= 2
            }
            extracted = tldextract.extract(userinfo_lower)
            if extracted.domain:
                userinfo_tokens.add(extracted.domain.lower())
                compact = _compact_brand_match_token(extracted.domain)
                if compact:
                    userinfo_tokens.add(compact)
            for token in sorted(userinfo_tokens, key=len, reverse=True):
                brand = TRUSTED_BASE_NAMES.get(token) or OFFICIAL_REGISTRY_LOOKALIKE_TOKENS.get(token)
                if brand:
                    return brand
            if "." in userinfo_lower and host and not userinfo_lower.endswith(host):
                return userinfo_lower
    return None
def _identity_status_for_decision_bundle(
    analysis: Dict[str, Any],
    resolved_urls: List[Dict[str, Any]],
    *,
    claimed_brand: str,
    official_destination: bool,
    infra_flags: Dict[str, Any],
    raw_text: str = "",
) -> Dict[str, Any]:
    evidence = analysis.get("evidence", {}) if isinstance(analysis.get("evidence"), dict) else {}
    domain_age_days = _first_domain_age_days(resolved_urls)
    domain_reputation = _domain_reputation_from_age(domain_age_days)

    # Merge WHOIS/RDAP+SSL deterministic signals into the identity context.
    domain_signals = evidence.get("domain_signals") if isinstance(evidence.get("domain_signals"), dict) else {}
    rdap_age = domain_signals.get("domain_age_days")
    if rdap_age is not None and domain_age_days is None:
        domain_age_days = rdap_age
        domain_reputation = _domain_reputation_from_age(domain_age_days)

    def _with_domain_context(payload: Dict[str, Any]) -> Dict[str, Any]:
        if domain_age_days is not None:
            payload["domain_age_days"] = domain_age_days
            payload["domain_reputation"] = domain_reputation
        if domain_signals:
            terminal_host_unreachable = bool(
                domain_signals.get("unreachable")
                and (
                    not official_destination
                    or domain_signals.get("dns_nxdomain")
                    or domain_signals.get("rdap_404")
                )
            )
            if domain_signals.get("rdap_404"):
                payload["rdap_inexistent"] = True
            if domain_signals.get("ssl_valid") is False:
                payload["ssl_invalid"] = True
            if terminal_host_unreachable:
                payload["host_unreachable"] = True
        return payload

    def _domain_from_signals_suspicious() -> bool:
        return bool(
            domain_signals.get("rdap_404")
            or domain_signals.get("domain_young")
            or domain_signals.get("ssl_valid") is False
        )

    if official_destination:
        raw_registered = ""
        final_registered = ""
        if resolved_urls:
            raw_registered = str(resolved_urls[0].get("registered_domain") or "").lower()
            final_registered = str(resolved_urls[0].get("final_registered_domain") or "").lower()
        return _with_domain_context({
            "claimed_brand": claimed_brand if _normalize_claimed_brand(claimed_brand) else None,
            "status": "delegated" if raw_registered and final_registered and raw_registered != final_registered else "official",
            "tld_suspicious": _domain_from_signals_suspicious(),
            "completeness": True,
        })

    normalized_claim = _normalize_claimed_brand(claimed_brand)
    has_resolved_destination = bool(_first_final_url(resolved_urls))
    userinfo_brand_mismatch = _brand_userinfo_spoof_in_resolved_urls(resolved_urls)
    if userinfo_brand_mismatch and has_resolved_destination:
        return _with_domain_context({
            "claimed_brand": userinfo_brand_mismatch,
            "status": "lookalike",
            "tld_suspicious": True,
            "brand_token_mismatch": userinfo_brand_mismatch,
            "userinfo_spoof": True,
            "completeness": True,
        })
    if normalized_claim and has_resolved_destination:
        exact_domain_claim = _claimed_brand_exact_domain_match(claimed_brand, resolved_urls)
        if exact_domain_claim and not (
            infra_flags.get("homoglyph")
            or infra_flags.get("punycode")
            or infra_flags.get("very_new_domain")
            or infra_flags.get("suspicious_domain_age")
            or _domain_from_signals_suspicious()
        ):
            return _with_domain_context({
                "claimed_brand": claimed_brand,
                "status": "coherent",
                "matched_domain_base": exact_domain_claim,
                "tld_suspicious": False,
                "completeness": True,
            })
        return _with_domain_context({
            "claimed_brand": claimed_brand,
            "status": "lookalike" if infra_flags.get("typosquat") or infra_flags.get("homoglyph") or infra_flags.get("punycode") else "unrelated",
            "tld_suspicious": bool(
                infra_flags.get("typosquat")
                or infra_flags.get("homoglyph")
                or infra_flags.get("punycode")
                or infra_flags.get("very_new_domain")
                or _domain_from_signals_suspicious()
            ),
            "completeness": True,
        })

    inferred_first_party = _first_party_domain_claim_from_text(raw_text, resolved_urls)
    if inferred_first_party and has_resolved_destination and not (
        infra_flags.get("typosquat")
        or infra_flags.get("homoglyph")
        or infra_flags.get("punycode")
        or infra_flags.get("very_new_domain")
        or infra_flags.get("suspicious_domain_age")
        or _domain_from_signals_suspicious()
    ):
        return _with_domain_context({
            "claimed_brand": inferred_first_party,
            "status": "coherent",
            "tld_suspicious": False,
            "completeness": True,
        })

    brand_token_mismatch = _brand_token_lookalike_in_resolved_urls(resolved_urls)
    return _with_domain_context({
        "claimed_brand": claimed_brand if _normalize_claimed_brand(claimed_brand) else None,
        "status": "unknown",
        "tld_suspicious": bool(
            infra_flags.get("typosquat")
            or infra_flags.get("homoglyph")
            or infra_flags.get("punycode")
            or infra_flags.get("very_new_domain")
            or _domain_from_signals_suspicious()
        ),
        "brand_token_mismatch": brand_token_mismatch,
        "completeness": True,
    })
def _request_channel_for_decision_bundle(
    *,
    source_channel: Optional[str],
    input_type: Optional[str],
    official_destination: bool,
    has_urls: bool,
) -> str:
    if official_destination:
        return "official"
    normalized = str(source_channel or input_type or "").strip().lower()
    if "whatsapp" in normalized:
        return "whatsapp"
    if "phone" in normalized or "call" in normalized or "apel" in normalized:
        return "phone"
    if "email" in normalized or "mail" in normalized:
        return "reply"
    if has_urls:
        return "unofficial_site"
    return "reply"
def _local_high_risk_semantic_review(raw_text: str) -> Optional[Dict[str, Any]]:
    if _data_url_contains_sensitive_form(raw_text):
        return {
            "status": "done",
            "claim_matches_known_scam_family": True,
            "matched_family": "data_url_credential_form",
            "claim_matches_legit_template": False,
            "matched_template": None,
            "reason_codes": ["semantic:data_url_credential_form", "semantic:local_high_risk_pattern"],
            "risk_class": "high",
            "confidence_class": "high",
            "family_confidence": 0.88,
            "completeness": True,
            "source": "local_high_risk_semantic_patterns",
        }
    normalized = _normalise_obfuscated_text(raw_text or "").lower()
    if not normalized or _looks_like_official_safety_education(normalized):
        return None
    decoded_data_url = _decoded_data_url_text(normalized).lower()
    decoded_url_text = normalized
    for _ in range(3):
        next_decoded = urllib.parse.unquote(decoded_url_text)
        if next_decoded == decoded_url_text:
            break
        decoded_url_text = next_decoded
    semantic_text_parts = [normalized]
    if decoded_url_text != normalized:
        semantic_text_parts.append(decoded_url_text)
    if decoded_data_url:
        semantic_text_parts.append(decoded_data_url)
    semantic_text = re.sub(r"\s+", " ", "\n".join(semantic_text_parts)).strip()

    checks: List[Tuple[str, str, str]] = [
        (
            "semantic:family_emergency_money_request",
            "family_emergency_money_request",
            r"\b(mam[ăa]|tata|tat[ăa]|fiule|fiica|copilul)\b"
            r"(?=.{0,220}\b(telefon|num[ăa]r(?:ul)?\s+nou|stricat|pierdut)\b)"
            r"(?=.{0,260}\b(urgent|acum|disear[ăa]|azi)\b)"
            r"(?=.{0,300}\b(iban|bani|lei|ron|transfer)\b)",
        ),
        (
            "semantic:otp_code_exfiltration",
            "otp_code_exfiltration",
            r"(\b(cod|otp)\b.{0,80}\b(sms|whatsapp|verificare|confirmare)\b.{0,100}\b(trimite|spune|comunic[ăa]|d[ăa][-\s]?mi|da[-\s]?mi)\b)"
            r"|(\b(trimite|spune|comunic[ăa]|d[ăa][-\s]?mi|da[-\s]?mi)\b.{0,100}\b(cod|otp)\b.{0,80}\b(sms|whatsapp|verificare|confirmare)\b)",
        ),
        (
            "semantic:esim_qr_exfiltration",
            "esim_qr_exfiltration",
            r"(?=.{0,220}\b(?:esim|e-sim|profil(?:ul)?\s+sim|sim)\b)"
            r"(?=.{0,220}\b(?:cod(?:ul)?\s+qr|qr)\b)"
            r"(?=.{0,220}\b(?:trimite|captur\w*|screenshot|poz[ăa]|agent(?:ului)?|recuperare|confirmare)\b)",
        ),
        (
            "semantic:bank_app_code_exfiltration",
            "bank_app_code_exfiltration",
            r"(?=.{0,220}\b(?:cod(?:ul)?\s+unic|cod(?:ul)?.{0,50}afi[șs]at|cod(?:ul)?.{0,50}aplica[țt]ia\s+bancar[ăa])\b)"
            r"(?=.{0,220}\b(?:cite[șs]te|citeste|spune|comunic[ăa]|sun[ăa]|suna|num[ăa]rul\s+din\s+mesaj|agent)\b)",
        ),
        (
            "semantic:partial_code_exfiltration",
            "partial_code_exfiltration",
            r"(?=.{0,220}\b(?:cod(?:ul)?|otp)\b)"
            r"(?=.{0,220}\b(?:nu\s+(?:imi|îmi|ne)\s+spune\s+codul\s+complet|doar\s+(?:prima|primele|ultimele)|a\s+treia|a\s+cincea|cifr[ăa])\b)"
            r"(?=.{0,220}\b(?:trimite|spune|comunic[ăa]|verificare|confirmare)\b)",
        ),
        (
            "semantic:split_message_code_exfiltration",
            "otp_code_exfiltration",
            r"(?=.{0,260}\b(?:identificare|verificare|alert[ăa])\b)"
            r"(?=.{0,260}\b(?:cod(?:ul)?\s+primit|cod\s+sms|otp)\b)"
            r"(?=.{0,260}\b(?:trimite[-\s]?l|trimite\s+codul|spune[-\s]?l|aici)\b)",
        ),
        (
            "semantic:userinfo_url_spoof",
            "userinfo_url_spoof",
            r"\bhttps?://[^/\s<>()\"']{2,120}@[a-z0-9.-]+\.[a-z]{2,}\b",
        ),
        (
            "semantic:data_url_credential_form",
            "data_url_credential_form",
            r"(?=.{0,400}\bdata:text/(?:html|plain)\b|.{0,400}<\s*(?:form|input)\b)"
            r"(?=.{0,800}\b(?:login|auth|password|parol[ăa]|otp|cod|card|cvv|cvc|utilizator|user)\b)",
        ),
        (
            "semantic:deeplink_fallback_login_or_install",
            "deeplink_fallback_login_or_install",
            r"(?=.{0,400}\b(?:_dl|deeplink|fallback(?:_redirect)?|browser_fallback_url|intent://|bankapp%3a|bank-secure|bankapp)\b)"
            r"(?=.{0,500}\b(?:login|beneficiary|beneficiar|install|actualizare|securitate|security|verify|verifica)\b)",
        ),
        (
            "semantic:hidden_redirect_sensitive_target",
            "deeplink_fallback_login_or_install",
            r"(?=.{0,700}\b(?:dest|next|redirect|redirect_url|fallback(?:_redirect)?|browser_fallback_url|target|url)\s*=\s*https?://)"
            r"(?=.{0,900}\b(?:login|auth|plata|plată|pay|confirm|verify|validare|install|actualizare|securitate|security)\b)",
        ),
        (
            "semantic:hidden_html_svg_click_target",
            "hidden_click_payment_or_confirm_cta",
            r"(?=.{0,900}(?:<\s*svg\b|xlink:href\s*[:=]|<\s*v:roundrect\b|<\s*v:rect\b))"
            r"(?=.{0,900}https?://)"
            r"(?=.{0,900}\b(?:sold(?:ul)?|plata|plată|pay|confirm|verify|verific[ăa]|validare|beneficiar|iban|cont)\b)",
        ),
        (
            "semantic:hidden_sensitive_form_action",
            "hidden_click_payment_or_confirm_cta",
            r"(?=.{0,900}\bFORM\s+action\b)"
            r"(?=.{0,900}https?://)"
            r"(?=.{0,900}\bfields?:.{0,180}\b(?:card|cvv|cvc|otp|password|parol[ăa]|pin|cnp)\b)",
        ),
        (
            "semantic:css_overlay_click_target",
            "hidden_click_payment_or_confirm_cta",
            r"(?=.{0,900}\bCTA\s+a/href_overlay\b)"
            r"(?=.{0,900}https?://)"
            r"(?=.{0,900}\b(?:plata|plată|pay|confirm|verify|verific[ăa]|validare|beneficiar|iban|cont|factur[ăa])\b)",
        ),
        (
            "semantic:security_update_install_link",
            "security_update_install_link",
            r"(?=.{0,240}\b(?:actualizare|update|securitate|security|bank-alert|alert[ăa]\s+bancar[ăa])\b)"
            r"(?=.{0,240}\b(?:install|instalare|instaleaz[ăa]|descarc[ăa]|apk|package|aplica[țt]ie)\b)",
        ),
        (
            # "Protect your card -> install our security app + follow the activation
            # steps" (fake bank/security app, remote-control/NFC malware). The family
            # above misses the imperative + inflected forms: "instalați aplicația"
            # (instala[țt]i + aplica[țt]ia) and "activare/pașii de activare". Anchor on
            # a security/bank/card pretext + install-app verb + an app/remote/activation
            # target. Maps to the `remote` token like security_update_install_link;
            # escalation stays channel-gated (official app-store / official destination
            # is not escalated).
            "semantic:fake_security_app_install",
            "fake_security_app_install",
            # Scam-specific app type: a "security/protection/antifraud app" OR a
            # remote-control tool. (Legit "install our official BT Pay app from
            # Google Play" matches none of these -> no FP.)
            r"(?=.{0,260}\b(?:aplica[țt]i\w*\s+(?:oficial\w*\s+)?(?:de\s+)?(?:securitate|protec[țt]\w*|antifraud\w*)|anydesk|teamviewer|rustdesk|control\s+(?:de\s+)?la\s+distan[țt]\w*|acces\s+la\s+distan[țt]\w*|\bremote\b)\b)"
            r"(?=.{0,300}\b(?:instala[țt]i?|instaleaz[ăa]|instalare|descarca[țt]i?|descarc[ăa]|activa[țt]i?|preia\w*\s+control\w*)\b)"
            # Dangerous distribution / control cue: sideload link, apk, access code,
            # activation steps, taking control. (Official app store has none.)
            r"(?=.{0,340}\b(?:de\s+la\s+link\w*|linkul\s+de\s+mai\s+jos|din\s+link\w*|\bapk\b|cod(?:ul)?\s+de\s+acces|pa[șs]ii\s+de\s+activare|s[ăa]\s+preiau)\b)",
        ),
        (
            "semantic:qr_epc_safe_account_payment",
            "safe_account_or_protective_transfer",
            r"(?=.{0,500}\bBCD\b)"
            r"(?=.{0,500}\bSCT\b)"
            r"(?=.{0,500}\b(?:AGENT\s+SECURITATE|PROTEC[ȚT]IE\s+CONT|CONT\s+SIGUR|SECURITY\s+AGENT)\b)"
            r"(?=.{0,500}(?:\bRO[A-Z0-9]{16,30}\b|\[IBAN_REDACTED\]|IBAN_REDACTED))"
            r"(?=.{0,500}\b(?:RON|EUR)\s*\d)",
        ),
        (
            "semantic:qr_totp_enrollment_takeover",
            "otp_code_exfiltration",
            r"\botpauth://totp/[^\s<>()\"']{3,400}\bsecret=",
        ),
        (
            "semantic:qr_prefilled_sensitive_email",
            "bank_data_collection",
            r"(?=.{0,500}\bmailto:[^\s<>()\"']+)"
            r"(?=.{0,700}\b(?:body=|subject=))"
            r"(?=.{0,900}\b(?:CUI|IBAN|card|cvv|otp|cod|parol[ăa])\b)",
        ),
        (
            "semantic:qr_wifi_captive_payment_pretext",
            "qr_wifi_captive_payment_pretext",
            r"(?=.{0,500}wifi:)"
            r"(?=.{0,500}(?:parcare|parking|oficial|official))"
            r"(?=.{0,500}(?:plata\s*acum|plataacum|pay\s*now|paynow|captiv|captive|portal|confirm))",
        ),
        (
            "semantic:official_poster_payment_qr_overlay",
            "official_poster_payment_qr_overlay",
            r"(?=.{0,500}\b(?:portal\s+oficial|afi[șs]\s+actualizat|poster\s+oficial)\b)"
            r"(?=.{0,500}\b(?:scaneaz[ăa]|scana[țt]i|afi[șs]\s+actualizat|poster\s+oficial)\b)"
            r"(?=.{0,500}\b(?:plata\s+rapid[ăa]|factur[ăa]|confirm)\b)",
        ),
        (
            "semantic:safety_education_login_pretext",
            "safety_education_login_pretext",
            r"(?=.{0,180}\b(?:nu\s+(?:comunica|trimite|introdu|da)\w*.{0,40}(?:parol[ăa]|otp|cod|card)|alert[ăa]\s+de\s+siguran[țt][ăa])\b)"
            r"(?=.{0,240}\b(?:pentru\s+a\s+(?:demonstra|confirma|verifica)|simulator|test\s+de\s+(?:siguran[țt][ăa]|securitate))\b)"
            r"(?=.{0,260}\b(?:autentific[ăa][-\s]?te|logheaz[ăa][-\s]?te|login|introdu|completeaz[ăa])\b)",
        ),
        (
            "semantic:safety_negation_exception_code_entry",
            "safety_education_login_pretext",
            r"(?=.{0,180}\bnu\s+(?:trimite|comunica|spune)\w*.{0,80}\bcod(?:ul)?\b)"
            r"(?=.{0,220}\b(?:introdu|introduce|trimite)[-\s]?(?:l|le)?\s+doar\b)"
            r"(?=.{0,240}\b(?:caseta|formular|verificarea\s+automat[ăa]|cod\s+sms|otp)\b)",
        ),
        (
            "semantic:fake_authority_safe_account",
            "fake_authority_safe_account",
            r"\b(poli[țt]i[ae]|bnr|antifraud[ăa]|dosar\s+de\s+fraud[ăa]|fraud[ăa]\s+bancar[ăa])\b"
            r"(?=.{0,260}\b(cont\s+(?:sigur|seif)|transfer|nu\s+[îi]nchide|exact\s+ce\s+spun)\b)",
        ),
        (
            "semantic:remote_access_install_request",
            "remote_access_install_request",
            r"\b(instaleaz[ăa]|descarc[ăa]|ruleaz[ăa]|porne[șs]te)\b"
            r"(?=.{0,180}\b(anydesk|teamviewer|rustdesk|control\s+la\s+distan[țt][ăa]|asisten[țt][ăa]\s+la\s+distan[țt][ăa]|remote\s+access)\b)",
        ),
        (
            "semantic:gift_card_payment",
            "gift_card_payment",
            r"\b(gift\s*card|carduri?\s+cadou|voucher)\b(?=.{0,140}\b(pl[ăa]t|achit|cump[ăa]r|cite[șs]te|cod\w*)\b)",
        ),
        (
            "semantic:voucher_code_payment",
            "voucher_code_payment",
            r"(?=.{0,180}\b(?:voucher|carduri?\s+cadou|gift\s*card)\b)"
            r"(?=.{0,180}\b(?:achit|pl[ăa]t|cump[ăa]r|penalizare)\b)"
            r"(?=.{0,180}\b(?:cod\w*|validare|r[ăa]spunde)\b)",
        ),
        (
            "semantic:safe_account_or_protective_transfer",
            "safe_account_or_protective_transfer",
            r"(?=.{0,220}\b(?:cont(?:ul)?\s+(?:sigur|temporar|seif)|transfer\s+preventiv|banii\s+[îi]n\s+siguran[țt][ăa])\b)"
            r"(?=.{0,240}\b(?:compromis|proteja|verific[ăa]ri|transfer[ăa]?|achit[ăa]?|trimite|mut[ăa])\b)",
        ),
        (
            "semantic:safe_beneficiary_test_transfer",
            "safe_beneficiary_test_transfer",
            r"(?=.{0,220}\b(?:beneficiar(?:ul)?\s+(?:de\s+)?(?:siguran[țt][ăa]|temporar)|beneficiar\s+nou|cont(?:ul)?\s+(?:de\s+)?siguran[țt][ăa])\b)"
            r"(?=.{0,260}\b(?:transfer(?:ul)?\s+(?:de\s+)?test|test\s+de\s+(?:1|un)\s+leu|trimite|adauga|adaug[ăa]|ad[ăa]ug[ăa]m|ad[ăa]ugi|confirm[ăa])\b)"
            r"(?=.{0,260}\b(?:clon[ăa]|blocarea|proteja|siguran[țt][ăa])\b)",
        ),
        (
            "semantic:digital_custody_transfer",
            "digital_custody_transfer",
            r"(?=.{0,240}\b(?:sesizare|executare|suspendarea|poli[țt]ie|parchet|agent)\b)"
            r"(?=.{0,260}\b(?:suma|banii|fondurile)\b)"
            r"(?=.{0,260}\b(?:mutat[ăa]?|transferat[ăa]?|transfer|muta[țt]i?)\b)"
            r"(?=.{0,260}\b(?:custodie\s+digital[ăa]|cont\s+de\s+custodie|cont\s+temporar|comunicat\s+de\s+agent)\b)",
        ),
        (
            "semantic:anti_verification_pressure",
            "anti_verification_pressure",
            r"\b(?:nu\s+(?:suna|sun[ăa]|verifica|face\s+callback|[îi]nchide|inchide)|r[ăa]m[aâ]ne[țt]i\s+la\s+telefon)\b"
            r"(?=.{0,220}\b(?:agent|aici|confirm|transfer|pl[ăa]t|iban|banc[ăa]|cont|termin[ăa]m)\b)",
        ),
        (
            "semantic:new_iban_callback_suppression",
            "new_iban_callback_suppression",
            r"(?=.{0,160}\b(?:(?:iban|cont)\s+nou|cont\s+bancar\s+nou)\b)"
            r"(?=.{0,220}\b(?:nu\s+(?:face\s+callback|suna|sun[ăa]|verifica|mai\s+folosi)|contul\s+vechi\s+nu\s+mai\s+este\s+valid)\b)",
        ),
        (
            "semantic:courier_payment_link_pressure",
            "courier_payment_link_pressure",
            r"(?=.{0,180}\b(?:colet\w*|livrare|tracking|curier)\b)"
            r"(?=.{0,180}\b(?:pl[ăa]te[șs]te|achit[ăa]|tax[ăa])\b)"
            r"(?=.{0,180}\b(?:link|nu\s+verifica|10\s+minute|pierde)\b)",
        ),
        (
            "semantic:courier_refundable_deposit_link",
            "courier_refundable_deposit_link",
            r"(?=.{0,220}\b(?:colet\w*|livrare|curier|ambalaj)\b)"
            r"(?=.{0,220}\b(?:depozit(?:ul)?\s+rambursabil|garan[țt]ie\s+rambursabil[ăa]|rambursarea)\b)"
            r"(?=.{0,220}\b(?:achit[ăa]|pl[ăa]te[șs]te|plata|https?://|aici)\b)",
        ),
        (
            "semantic:bec_urgent_confidential_transfer",
            "bec_urgent_confidential_transfer",
            r"(?=.{0,180}\b(?:plat[ăa]|aprob[ăa]|transfer)\b)"
            r"(?=.{0,220}\b(?:urgent|confiden[țt]ial|f[ăa]r[ăa]\s+tichet|director|[șs]edin[țt][ăa])\b)",
        ),
        (
            "semantic:cfo_approval_bypass_payment",
            "cfo_approval_bypass_payment",
            r"(?=.{0,220}\b(?:director(?:ul)?\s+financiar|cfo|manager(?:ul)?|șef(?:ul)?|sef(?:ul)?)\b)"
            r"(?=.{0,220}\b(?:achit[ăa]|pl[ăa]te[șs]te|transfer[ăa]?|avans|partener(?:ul)?\s+nou)\b)"
            r"(?=.{0,260}\b(?:nu\s+porni|f[ăa]r[ăa]\s+aprobare|aprobarea\s+intern[ăa]|documentele\s+vor\s+veni\s+dup[ăa]|confiden[țt]ial)\b)",
        ),
        (
            "semantic:executable_invoice_attachment",
            "executable_invoice_attachment",
            r"(?=.{0,180}\b(?:factur[ăa]|viewer|fi[șs]ier)\b)"
            r"(?=.{0,180}\b(?:\\.exe|executabil|ata[șs]at[ăa]?|descarc[ăa])\b)",
        ),
        (
            "semantic:investment_guaranteed_deposit",
            "investment_guaranteed_deposit",
            r"(?=.{0,220}\b(?:broker|profit|randament|investi[țt]ii?)\b)"
            r"(?=.{0,220}\b(?:garanteaz[ăa]|garantat)\b)"
            r"(?=.{0,220}\b(?:depunere|depun[ei]|trimite|cont\s+de\s+activare)\b)",
        ),
        (
            "semantic:recovery_audit_fee_before_refund",
            "recovery_audit_fee_before_refund",
            r"(?=.{0,240}\b(?:fondurile\s+pierdute|recuper(?:are|[ăa]m|ezi)|rambursare|blockchain|traseul)\b)"
            r"(?=.{0,260}\b(?:tax[ăa]\s+de\s+audit|tax[ăa]|comision|achit[ăa]|pl[ăa]te[șs]te)\b)"
            r"(?=.{0,260}\b(?:[îi]nainte\s+de\s+rambursare|semna|audit|deblocare)\b)",
        ),
        (
            "semantic:authority_unavailable_payment_pressure",
            "authority_unavailable_payment_pressure",
            r"(?=.{0,160}\b(?:anaf|autoritate|fisc)\b)"
            r"(?=.{0,180}\b(?:nu\s+r[ăa]spunde|indisponibil|nu\s+poate\s+fi\s+contactat)\b)"
            r"(?=.{0,180}\b(?:pl[ăa]tit[ăa]|pl[ăa]te[șs]te|urgent)\b)",
        ),
        (
            "semantic:bank_data_collection",
            "bank_data_collection",
            r"(?=.{0,140}\b(?:introdu|completeaz[ăa]|trimite)\b)"
            r"(?=.{0,140}\b(?:date\s+bancare|date\s+financiare|conturi?\s+bancare)\b)",
        ),
        (
            "semantic:courier_fee_payment_link",
            "courier_fee_payment_link",
            r"(?=.{0,160}\b(?:tax[ăa]\s+de\s+livrare|taxa\s+de\s+livrare|colet\w*|livrare)\b)"
            r"(?=.{0,160}\b(?:achit\w*|achi[țt]\w*|pl[ăa]t\w*)\b)"
            r"(?=.{0,160}\blink\w*\b)",
        ),
        (
            "semantic:exclusive_new_iban_payment",
            "exclusive_new_iban_payment",
            r"(?=.{0,160}\b(?:plat[ăa]|factur[ăa])\b)"
            r"(?=.{0,160}\b(?:exclusiv|doar)\b)"
            r"(?=.{0,160}\b(?:iban\s+nou|cont\s+nou)\b)",
        ),
        (
            "semantic:migrated_account_new_iban",
            "migrated_account_new_iban",
            r"(?=.{0,280}\b(?:migrat|migrare|contul\s+(?:a\s+fost\s+)?schimbat|conturile\s+(?:au\s+fost\s+)?(?:schimbate|migrat[ea]?)|banca\s+nou[ăa])\b)"
            r"(?=.{0,320}\b(?:plata|achit[ăa]|ref[ăa]cut[ăa]?|folosi[țt]i|utiliza[țt]i|iban|cont(?:ul)?\s+nou)\b)",
        ),
        (
            "semantic:callback_poison_new_payment_destination",
            "new_iban_callback_suppression",
            r"(?=.{0,340}\b(?:num[ăa]r(?:ul)?\s+nou|semn[ăa]tura\s+acestui\s+mesaj|vechiul\s+departament|nu\s+mai\s+are\s+acces)\b)"
            r"(?=.{0,360}\b(?:confirma(?:re)?\s+telefonic[ăa]?|pot\s+confirma|suna|telefonic)\b)"
            r"(?=.{0,380}\b(?:iban\s+nou|noul\s+iban|plata\s+trebuie\s+ref[ăa]cut[ăa]?|cont(?:ul)?\s+nou)\b)",
        ),
        (
            "semantic:supplier_bank_details_change",
            "supplier_bank_details_change",
            r"(?=.{0,160}\b(?:se\s+modific[ăa]|modificare)\b)"
            r"(?=.{0,160}\b(?:datele\s+bancare|iban|cont)\b)"
            r"(?=.{0,160}\b(?:furnizor\w*|factur)\b)",
        ),
        (
            "semantic:proforma_new_account_before_delivery",
            "proforma_new_account_before_delivery",
            r"(?=.{0,180}\b(?:proform[ăa]|ofert[ăa]|factur[ăa])\b)"
            r"(?=.{0,180}\b(?:achitat[ăa]?|pl[ăa]tit[ăa]?|contul\s+nou|cont\s+nou)\b)"
            r"(?=.{0,180}\b(?:[îi]nainte\s+de\s+livrare|expir[ăa]|azi)\b)",
        ),
        (
            # BEC P0 hole: the bank-change families above key on "contul schimbat" /
            # "banca noua" and on the literal word "iban". A real BEC that writes
            # "ne-am schimbat banca ... in noul nostru cont: RO49..." (verb form +
            # IBAN *format*, no "iban" keyword) slipped through to UNVERIFIED. Anchor
            # on the change pretext + a payment + an IBAN-format / new-account ref.
            "semantic:bank_change_iban_format",
            "bank_change_iban_format",
            r"(?=.{0,220}\b(?:ne-am\s+schimbat|am\s+schimbat|s-a\s+schimbat|schimbat\s+(?:banca|contul|sediul|iban)|schimbare(?:a)?\s+(?:de\s+)?(?:banc[ăa]|cont|sediu|iban)|audit\s+intern)\b)"
            r"(?=.{0,300}\b(?:plat[ăa]|achit\w*|factur[ăa]|virament|transfer\w*)\b)"
            r"(?=.{0,360}(?:\bRO[A-Z0-9]{16,30}\b|\biban\b|cont(?:ul)?\s+nou|noul\s+(?:nostru\s+)?cont))",
        ),
        (
            # OSIM/EUIPO/IP & judicial bodies never request a fee paid to an
            # indicated/private account inside a message. Anchor on such an institution
            # + a fee/invoice + a payment action + an account/IBAN -> protected fee
            # impersonation. Legit invoices (no such institution as payee) do not match.
            "semantic:institution_fee_to_account",
            "institution_fee_to_account",
            r"(?=.{0,320}\b(?:osim|euipo|oapi|oepm|parchet\w*|tribunal\w*|judec[ăa]tor\w*|instan[țt]\w*|diicot|inspectorat\w*)\b)"
            r"(?=.{0,320}\b(?:tax[ăa]|tarif|factur[ăa]|cerere\s+de\s+marc[ăa]|[îi]nregistrare|publicare)\b)"
            r"(?=.{0,320}\b(?:efectua\w*\s+plata|achit\w*|plata\s+[îi]n\s+cont|pl[ăa]ti[țt]i|virament|plata\s+unei)\b)"
            r"(?=.{0,380}(?:\bRO[A-Z0-9]{16,30}\b|cont(?:ul)?(?:\s+indicat)?|\biban\b))",
        ),
        (
            "semantic:hospital_bail_no_call_money_request",
            "hospital_bail_no_call_money_request",
            r"(?=.{0,180}\b(?:spital|cau[țt]iune|cautiune|accident)\b)"
            r"(?=.{0,180}\b(?:nu\s+suna|nu\s+sun[ăa]|nu\s+spune)\b)"
            r"(?=.{0,180}\b(?:trimite|transfer[ăa]?|banii|bani|imediat)\b)",
        ),
        (
            "semantic:family_voice_clone_emergency_payment",
            "family_voice_clone_emergency_payment",
            r"(?=.{0,280}\b(?:sunt\s+eu|parola\s+noastr[ăa]\s+de\s+familie|vocea\s+mea|vocea\s+pe\s+care\s+o\s+cuno[șs]ti|nu\s+merge\s+bine\s+vocea|accident|opera[țt]ie|externare)\b)"
            r"(?=.{0,320}\b(?:urgent|acum|imediat|azi|dup[ăa])\b)"
            r"(?=.{0,340}\b(?:bani|lei|ron|transfer|trimite|garan[țt]ia|am\s+nevoie)\b)",
        ),
        (
            "semantic:package_release_token_fee",
            "package_release_token_fee",
            r"(?=.{0,280}\b(?:pachet|colet|vamal|destinatar|medical|robotul\s+vamal)\b)"
            r"(?=.{0,300}\b(?:token(?:ul)?|cod|asocia|eliberare|release)\b)"
            r"(?=.{0,340}\b(?:tax[ăa]|pl[ăa]te[șs]te|achit[ăa]|comision|lei|ron|transfer|rambursez)\b)",
        ),
        (
            "semantic:tech_support_gift_card_payment",
            "tech_support_gift_card_payment",
            r"(?=.{0,180}\b(?:microsoft|security|suport|deblocare|virus)\b)"
            r"(?=.{0,180}\b(?:carduri?\s+cadou|gift\s*card|voucher)\b)",
        ),
        (
            "semantic:urgent_payment_link_pressure",
            "urgent_payment_link_pressure",
            r"(?=.{0,180}\b(?:nu\s+exist[ăa]\s+timp|10\s+minute|urgent|expir[ăa])\b)"
            r"(?=.{0,180}\b(?:pl[ăa]te[șs]te|achit[ăa]|plata|tax[ăa])\b)"
            r"(?=.{0,180}\blink\w*\b)",
        ),
        (
            "semantic:brand_login_update_link",
            "brand_login_update_link",
            r"(?=.{0,180}\b(?:ing|bcr|brd|bt|banca|home.?bank)\b)"
            r"(?=.{0,180}\b(?:logheaz[ăa]|autentific[ăa]|actualizarea\s+datelor|link)\b)",
        ),
        (
            # Bank credential-update phishing. brand_login_update_link above is too
            # narrow: "actualizarea/confirmarea datelor" breaks the exact
            # "actualizarea datelor" anchor, and `link\b` misses the inflected
            # "linkul". Anchor on bank/internet-banking + an update/confirm verb +
            # an account/credentials target + an access/link/restriction cue.
            # Maps to the `password` (credential) token like brand_login_update_link;
            # escalation stays channel-gated -> an email whose link resolves to the
            # bank's OFFICIAL domain (official_destination) is NOT escalated.
            "semantic:bank_credential_update_phish",
            "bank_credential_update_phish",
            r"(?=.{0,200}\b(?:ing|bcr|brd|bt|raiffeisen|unicredit|cec|banca|internet\s+banking|home.?bank|net\s*bank)\b)"
            r"(?=.{0,240}\b(?:confirma[țt]i?|confirmarea|actualiza[țt]i?|actualizarea|verifica[țt]i?|reactiva[țt]i?)\b)"
            r"(?=.{0,260}\b(?:datel\w*\s+(?:contului|de\s+autentificare|de\s+acces)|internet\s+banking|cont(?:ul)?\s+de\s+internet)\b)"
            r"(?=.{0,300}\b(?:link\w*|acces\w*|restric[țt]ion\w*|blocat|suspendat|limitat|dezactivat)\b)",
        ),
        (
            "semantic:external_card_cvv_otp_collection",
            "external_card_cvv_otp_collection",
            r"(?=.{0,180}\b(?:completarea|completeaz[ăa]|introdu)\b)"
            r"(?=.{0,180}\b(?:card|cvv|cvc|otp)\b)"
            r"(?=.{0,180}\b(?:link|extern)\b)",
        ),
        (
            "semantic:visual_homoglyph_brand_collection",
            "brand_login_update_link",
            r"(?=.{0,260}\b(?:paypai|paypa1|paypaI|g00gle|go0gle|micros0ft|faceb00k|app1e|revo1ut)\b)"
            r"(?=.{0,320}\b(?:card|cont|login|verify|confirm|parol[ăa]|otp|cvv|blocarea)\b)",
        ),
        (
            "semantic:beneficiary_mismatch_new_account",
            "beneficiary_mismatch_new_account",
            r"(?=.{0,180}\b(?:beneficiar\w*)\b)"
            r"(?=.{0,180}\b(?:difer[ăa]|diferit|afi[șs]at)\b)"
            r"(?=.{0,180}\b(?:cont(?:ul)?\s+nou|iban\s+nou|departamentul\s+financiar)\b)",
        ),
        (
            "semantic:password_update_link",
            "password_update_link",
            r"(?=.{0,180}\b(?:actualizarea\s+parolei|parol[ăa])\b)"
            r"(?=.{0,180}\b(?:link|autentific[ăa]|acceseaz[ăa])\b)",
        ),
        (
            "semantic:job_task_topup",
            "job_task_topup",
            r"\b(like|review|recenzi[ei]|task|lucrezi\s+de\s+acas[ăa])\b"
            r"(?=.{0,240}\b(top[-\s]?up|vip|depun[ei]|transfer|lei|ron|c[âa]știg|castig)\b)",
        ),
        (
            "semantic:domain_or_trademark_scare_payment",
            "domain_or_trademark_scare_payment",
            r"\b(osim|tmview|marc[ăa]|marca|domeniul|domeniu)\b"
            r"(?=.{0,260}\b(achit|pl[ăa]t|tax[ăa]|pierde[țt]i|competitor|v[âa]ndut|vandut)\b)",
        ),
    ]
    for reason_code, family_id, pattern in checks:
        if re.search(pattern, semantic_text, re.IGNORECASE):
            return {
                "status": "done",
                "claim_matches_known_scam_family": True,
                "matched_family": family_id,
                "claim_matches_legit_template": False,
                "matched_template": None,
                "reason_codes": [reason_code, "semantic:local_high_risk_pattern"],
                "risk_class": "high",
                "confidence_class": "high",
                "family_confidence": 0.86,
                "completeness": True,
                "source": "local_high_risk_semantic_patterns",
            }
    return None
def _semantic_review_for_decision_bundle(
    analysis: Dict[str, Any],
    *,
    raw_text: str,
    official_destination: bool,
    provider_verdict: str,
) -> Dict[str, Any]:
    evidence = analysis.get("evidence", {}) if isinstance(analysis.get("evidence"), dict) else {}
    if _looks_like_official_safety_education(raw_text) and provider_verdict != "malicious":
        return {
            "status": "done",
            "claim_matches_known_scam_family": False,
            "matched_family": None,
            "claim_matches_legit_template": True,
            "matched_template": "safety_education",
            "reason_codes": ["semantic:benign", "semantic:safety_education_scope"],
            "risk_class": "benign",
            "confidence_class": "high",
            "family_confidence": 0.0,
            "completeness": True,
            "source": "safety_education_scope_guard",
        }
    existing = evidence.get("semantic_review")
    local_high_risk = _local_high_risk_semantic_review(raw_text)
    if isinstance(existing, dict) and existing.get("status"):
        if local_high_risk and _semantic_risk_rank(existing.get("risk_class")) < _semantic_risk_rank("high"):
            return local_high_risk
        return existing

    family = evidence.get("scam_family") if isinstance(evidence.get("scam_family"), dict) else {}
    family_id = str(family.get("id") or analysis.get("detected_family_id") or "").strip()
    family_name = str(family.get("family") or analysis.get("detected_family") or "").strip()
    try:
        confidence = float(evidence.get("family_confidence") or 0.0)
    except Exception:
        confidence = 0.0
    supports_high_text_only = bool(evidence.get("family_high_risk_text_only"))
    known = bool(family_id) and family_id != "unknown-scam"
    confidence_class = "high" if confidence >= 0.5 else "medium" if confidence >= 0.25 else "low"

    if official_destination and provider_verdict == "clean":
        return {
            "status": "done",
            "claim_matches_known_scam_family": False,
            "matched_family": None,
            "claim_matches_legit_template": True,
            "matched_template": "official_clean_destination",
            "reason_codes": ["semantic:benign", "identity:official_clean"],
            "risk_class": "benign",
            "confidence_class": confidence_class,
            "family_confidence": round(confidence, 3),
            "completeness": True,
            "source": "official_clean_destination",
        }
    if provider_verdict == "malicious":
        return {
            "status": "done",
            "claim_matches_known_scam_family": False,
            "matched_family": None,
            "claim_matches_legit_template": False,
            "matched_template": None,
            "reason_codes": ["semantic:unknown", "provider:malicious_decisive"],
            "risk_class": "unknown",
            "confidence_class": confidence_class,
            "family_confidence": round(confidence, 3),
            "completeness": True,
            "source": "provider_decisive_no_semantic_needed",
        }
    if local_high_risk:
        return local_high_risk

    if known and confidence >= 0.35 and supports_high_text_only:
        risk_class = "high"
    elif known and confidence >= 0.25:
        risk_class = "medium"
    else:
        risk_class = "unknown"

    # Preserve high atlas risk even when the family classifier cannot name a specific scam family.
    # A strong local risk score should not degrade to unknown only because taxonomy matching missed.
    risk_from_score_only = False
    if risk_class == "unknown":
        try:
            atlas_score = int(analysis.get("risk_score") or 0)
        except (TypeError, ValueError):
            atlas_score = 0
        if atlas_score >= 75:
            risk_class = "medium"
            risk_from_score_only = True
        elif atlas_score >= 50:
            risk_class = "low"
            risk_from_score_only = True

    matched = risk_class in {"high", "medium"} and not risk_from_score_only
    return {
        "status": "done",
        "claim_matches_known_scam_family": matched,
        "matched_family": (family_id or family_name or None) if matched else None,
        "claim_matches_legit_template": False,
        "matched_template": None,
        "reason_codes": [f"semantic:{risk_class}", f"family:{(family_id or 'none').lower()}"],
        "risk_class": risk_class,
        "confidence_class": confidence_class,
        "family_confidence": round(confidence, 3),
        "completeness": True,
        "source": "scam_atlas_structured",
    }
def _semantic_risk_rank(value: Any) -> int:
    return {
        "benign": 0,
        "unknown": 1,
        "medium": 2,
        "high": 3,
    }.get(str(value or "").strip().lower(), 1)
def _se_pattern(text: str, pattern: str) -> bool:
    return bool(re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL))
def _se_list(values: Any, allowed: set[str]) -> List[str]:
    if not values:
        return []
    if isinstance(values, (str, int, float)):
        values = [values]
    if not isinstance(values, list):
        return []
    out: List[str] = []
    for value in values:
        item = str(value or "").strip().lower()
        if item in allowed and item not in out:
            out.append(item)
    return out
def _se_float(value: Any, default: float = 0.0) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    return max(0.0, min(1.0, number))
def _se_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "da", "y"}
    return False
def _normalize_model_intent_analysis(raw: Any, fallback: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    fallback = fallback if isinstance(fallback, dict) else {}
    if not isinstance(raw, dict):
        return fallback

    confidence = _se_float(raw.get("confidence"), _se_float(fallback.get("confidence"), 0.0))
    model_positive = _se_bool(raw.get("positive_action_request"))
    model_protective = _se_bool(raw.get("is_protective_warning")) or _se_bool(raw.get("protective_warning"))
    model_descriptive = _se_bool(raw.get("is_descriptive_or_status")) or _se_bool(raw.get("descriptive_context"))
    negation_resolved = _se_bool(raw.get("negation_scope_resolved"))

    positive_action_request = bool(fallback.get("positive_action_request", False))
    local_descriptive_non_action = bool(
        fallback.get("descriptive_context", False)
        and not fallback.get("positive_action_request", False)
    )
    if confidence >= 0.55 and model_positive and not local_descriptive_non_action:
        positive_action_request = True
    elif (
        confidence >= 0.80
        and negation_resolved
        and (model_protective or model_descriptive or _se_bool(raw.get("describes_fraud_without_request")))
        and not model_positive
    ):
        positive_action_request = False

    return {
        "status": "done",
        "positive_action_request": bool(positive_action_request),
        "protective_warning": bool(fallback.get("protective_warning", False) or model_protective),
        "descriptive_context": bool(fallback.get("descriptive_context", False) or model_descriptive),
        "negation_scope_resolved": bool(negation_resolved),
        "invoice_or_payment_document": _se_bool(raw.get("invoice_or_payment_document")),
        "payment_instruction_present": _se_bool(raw.get("payment_instruction_present")),
        "payment_instruction_is_requested": _se_bool(raw.get("payment_instruction_is_requested")),
        "payment_instruction_is_descriptive": _se_bool(raw.get("payment_instruction_is_descriptive")),
        "describes_fraud_without_request": _se_bool(raw.get("describes_fraud_without_request")),
        "confidence": round(confidence, 2),
        "source": "mistral_intent_analysis" if confidence else str(fallback.get("source") or "mistral_intent_analysis"),
        "fallback_source": fallback.get("source"),
    }
def _social_engineering_signal_for_decision_bundle(
    raw_text: str,
    *,
    request_sensitive: str = "none",
    source_channel: Optional[str] = None,
    semantic_review: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    text = _normalise_obfuscated_text(raw_text or "").lower()
    semantic_review = semantic_review if isinstance(semantic_review, dict) else {}

    if _looks_like_official_safety_education(raw_text):
        return {
            "status": "done",
            "intent": "benign",
            "ask_present": False,
            "ask_type": ["none"],
            "levers": [],
            "persona_targeting": "generic",
            "channel_coherence": "coherent",
            "urgency_score": 0.0,
            "confidence": 0.1,
            "model": "local_social_engineering_v1",
            "provenance": "pipeline_only",
        }

    levers: List[str] = []
    ask_types: List[str] = []

    def add_lever(value: str) -> None:
        if value in SOCIAL_ENGINEERING_LEVERS and value not in levers:
            levers.append(value)

    def add_ask(value: str) -> None:
        if value in SOCIAL_ENGINEERING_ASK_TYPES and value not in ask_types:
            ask_types.append(value)

    if _se_pattern(text, r"\b(parchet|procuror|comisar|poli[țt]i[ae]|politi[ae]|diicot|dna|anaf|bnr|antifraud[ăa]|dosar\s+penal|anchet[ăa])\b"):
        add_lever("authority")
    if _se_pattern(text, r"\b(arest|aresta(?:t|re)|re[țt]inere|re[țt]inut|dosar\s+penal|atacator|fraud[ăa]|bloc(?:at|are)|suspend(?:at|are)|compromis)\b"):
        add_lever("fear")
    if _se_pattern(text, r"\b(dezactivat|clon[ăa]|blocarea\s+clonei|profilul\s+sim\s+va\s+fi\s+dezactivat)\b"):
        add_lever("fear")
    if _se_pattern(text, r"\b(urgent|imediat|acum|azi|10\s+minute|24\s*(?:de\s*)?ore|expir[ăa]|ultima\s+[șs]ans[ăa])\b"):
        add_lever("urgency")
    if _se_pattern(text, r"\b(nu\s+spune(?:ti|ți)?\s+nim[ăa]nui|confiden[țt]ial|clasificat[ăa]?|nu\s+(?:discuta(?:ti|ți)?|spune(?:ti|ți)?).{0,40}\b(?:familie|colegi|superiori|nim[ăa]nui))\b"):
        add_lever("secrecy")
    if _se_pattern(text, r"\b(profit|randament|c[âa]știg|castig|bonus|garantat|oportunitate|trading|investi[țt]ii|investitii|crypto)\b"):
        add_lever("greed")
    if _se_pattern(text, r"\b(membrii|grup(?:ul)?|to[țt]i|dovad[ăa]|profituri\s+zilnice|testimoniale|rezultatele\s+altora)\b"):
        add_lever("social_proof")
    if _se_pattern(text, r"\b(prieten|nepot|fiul|fiica|mama|tata|accident|spital|ajutor|opera[țt]ie)\b"):
        add_lever("compassion")
    if _se_pattern(text, r"\b(doar\s+pentru\s+tine|te\s+ajut|mentor|consultant|agentul\s+nostru)\b"):
        add_lever("liking")
    if _se_pattern(text, r"\b(ai\s+depus\s+deja|recuperezi\s+investi[țt]ia|nu\s+pierde\s+suma|tax[ăa]\s+de\s+retragere)\b"):
        add_lever("sunk_cost")
    if _se_pattern(text, r"\b(pierzi|blocat\s+definitiv|confiscat|inchis|[îi]nchis)\b"):
        add_lever("loss_aversion")

    sensitive = str(request_sensitive or "none").strip().lower()
    if sensitive in {"card", "cvv"}:
        add_ask("card")
    elif sensitive in {"otp", "password", "pin", "banking_pin", "cnp", "id_document"}:
        add_ask(sensitive if sensitive in SOCIAL_ENGINEERING_ASK_TYPES else "otp")
    elif sensitive == "remote":
        add_ask("remote_install")
    elif sensitive == "crypto":
        add_ask("seed_phrase")
    elif sensitive == "transfer":
        add_ask("transfer")

    # Attacker-directed callback always counts; a generic "suna la <numar>" counts
    # only when it is NOT self-directed legitimate verification ("suna la numarul
    # de pe spatele cardului", "deschide aplicatia", "numarul oficial / din
    # contract") — that guidance is the X2 twin discriminator for real bank alerts.
    strong_callback = _se_pattern(
        text,
        r"\b(suna(?:ti|ți)?[-\s]?ne|suna(?:ti|ți)?\s+(?:urgent|acum)|reveni(?:ti|ți)\s+telefonic|"
        r"r[ăa]m(?:a|â)ne(?:ti|ți)?\s+pe\s+(?:linie|fir)|nu\s+[îi]nchide(?:ti|ți)?)\b",
    )
    generic_callback = _se_pattern(text, r"\bsuna(?:ti|ți)?\s+la\b")
    self_directed_verification = _se_pattern(
        text,
        r"\b(num[ăa]r(?:ul)?\s+(?:de\s+pe\s+(?:spatele\s+)?card(?:ului)?|oficial|din\s+contract)|"
        r"de\s+pe\s+spatele\s+card(?:ului)?|de\s+pe\s+site-?ul\s+oficial|"
        r"deschide(?:ti|ți)?\s+aplica[țt]ia|din\s+aplica[țt]ia)\b",
    )
    if strong_callback or (generic_callback and not self_directed_verification):
        add_ask("callback")
    if _se_pattern(text, r"\b(anydesk|teamviewer|rustdesk|remote\s+access|control\s+la\s+distan[țt][ăa]|instaleaz[ăa].{0,30}(?:aplica[țt]ia|apk))\b"):
        add_ask("remote_install")
    if _se_pattern(text, r"\b(seed\s+phrase|fraza\s+seed|cheia\s+privat[ăa]|wallet|portofel\s+crypto)\b"):
        add_ask("seed_phrase")
    if _se_pattern(text, r"\b(carduri?\s+cadou|gift\s*card|voucher)\b"):
        add_ask("gift_card")
    if _se_pattern(
        text,
        r"\b(?:cod(?:ul)?\s+unic|cod(?:ul)?.{0,50}aplica[țt]ia\s+bancar[ăa]|"
        r"(?:prima|a\s+treia|a\s+cincea|primele|ultimele).{0,60}(?:cifr[ăa]|cifre).{0,60}cod|"
        r"(?:cod\s+qr|qr).{0,50}(?:esim|e-sim|profil(?:ul)?\s+sim)|"
        r"(?:esim|e-sim|profil(?:ul)?\s+sim).{0,50}(?:cod\s+qr|qr))\b",
    ):
        add_ask("otp")
    if _se_pattern(text, r"\b(transfera(?:ti|ți)?|muta(?:ti|ți)?|trimite(?:ti|ți)?|depune(?:ti|ți)?|achit(?:a|[ăa])|pl[ăa]te(?:[șs]te|sti|[șs]ti)?)\b.{0,90}\b(sold|bani|suma|lei|ron|eur|cont(?:ul)?\s+(?:nou|sigur|de\s+protec[țt]ie|temporar|seif)|iban\s+nou)\b"):
        add_ask("transfer")
    if _se_pattern(text, r"\bcont(?:ul)?\s+(?:de\s+)?(?:siguran[țt][ăa]|protec[țt]ie|seif|temporar)\b"):
        add_ask("transfer")
    if _se_pattern(text, r"\bbeneficiar(?:ul)?\s+(?:de\s+)?(?:siguran[țt][ăa]|temporar)\b.{0,100}\b(?:transfer\s+test|trimite|adauga|adaug[ăa])\b"):
        add_ask("transfer")

    ask_present = bool([ask for ask in ask_types if ask != "none"])
    semantic_risk = str(semantic_review.get("risk_class") or "").strip().lower()
    if semantic_risk in {"high", "medium"} and _has_social_engineering_pressure(raw_text):
        ask_present = ask_present or "callback" in ask_types

    if "remote_install" in ask_types:
        intent = "remote_access"
    elif "seed_phrase" in ask_types or _se_pattern(text, r"\b(tax[ăa]\s+de\s+retragere|recuper(?:are|ezi).{0,80}(?:profit|fonduri|bani|crypto))\b"):
        intent = "recovery_scam"
    elif "transfer" in ask_types and (
        _se_pattern(text, r"\b(cont(?:ul)?\s+(?:nou|sigur|de\s+protec[țt]ie|temporar|seif)|iban\s+nou|beneficiar\s+diferit|datele\s+bancare\s+s-au\s+modificat)\b")
        or "authority" in levers
        or "secrecy" in levers
    ):
        intent = "payment_redirection"
    elif _se_pattern(text, r"\b(trading|investi[țt]ii|investitii|crypto|randament|profituri\s+zilnice|broker|platform[ăa])\b"):
        intent = "investment_fraud"
    elif set(ask_types) & {"card", "otp"}:
        intent = "credential_theft"
    elif set(ask_types) & {"callback"} and ({"authority", "fear", "secrecy"} & set(levers)):
        intent = "credential_theft"
    elif "authority" in levers:
        intent = "impersonation"
    elif semantic_review.get("claim_matches_legit_template"):
        intent = "benign"
    elif levers:
        intent = "unknown"
    else:
        intent = "unknown"

    if intent == "investment_fraud" and not ask_present:
        ask_types = ask_types or ["none"]
    elif not ask_types:
        ask_types = ["none"]

    confidence = 0.1
    if intent in {"credential_theft", "payment_redirection", "remote_access", "investment_fraud", "recovery_scam"}:
        confidence = 0.45
    elif intent == "impersonation":
        confidence = 0.38
    elif intent == "benign":
        confidence = 0.1
    confidence += min(len(levers) * 0.08, 0.24)
    if ask_present:
        confidence += 0.25
    if semantic_risk == "high":
        confidence += 0.1
    elif semantic_risk == "medium":
        confidence += 0.05
    if intent == "investment_fraud" and {"greed", "social_proof"} & set(levers):
        confidence += 0.05

    persona = "generic"
    if _se_pattern(text, r"\b(nepot|mama|tata|fiul|fiica|accident|spital)\b"):
        persona = "parent"
    elif _se_pattern(text, r"\b(job|task|angajare|recrutare|lucrezi\s+de\s+acas[ăa])\b"):
        persona = "jobseeker"
    elif intent == "investment_fraud":
        persona = "investor"
    elif _se_pattern(text, r"\b(mostenire|decedat|v[ăa]duv[ăa]|funerar)\b"):
        persona = "bereaved"

    channel = str(source_channel or "").strip().lower()
    channel_coherence = "unknown"
    if channel in {"sms", "whatsapp", "telegram", "messenger", "social_dm", "phone"} and ("authority" in levers or "secrecy" in levers):
        channel_coherence = "mismatch"
    elif channel in {"official", "official_website", "official_app"}:
        channel_coherence = "coherent"

    urgency_score = 0.0
    if "urgency" in levers:
        urgency_score += 0.6
    if "fear" in levers:
        urgency_score += 0.2
    if ask_present:
        urgency_score += 0.1

    return {
        "status": "done",
        "intent": intent if intent in SOCIAL_ENGINEERING_INTENTS else "unknown",
        "ask_present": ask_present,
        "ask_type": _dedupe_preserve_order(ask_types),
        "levers": _dedupe_preserve_order(levers),
        "persona_targeting": persona,
        "channel_coherence": channel_coherence,
        "urgency_score": round(min(1.0, urgency_score), 2),
        "confidence": round(min(1.0, confidence), 2),
        "model": "local_social_engineering_v1",
        "provenance": "pipeline_only",
    }
def _normalize_model_social_engineering_signal(raw: Any, fallback: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(raw, dict):
        return fallback
    intent = str(raw.get("intent") or fallback.get("intent") or "unknown").strip().lower()
    if intent not in SOCIAL_ENGINEERING_INTENTS:
        intent = fallback.get("intent") or "unknown"
    ask_type = _dedupe_preserve_order(
        _se_list(raw.get("ask_type"), SOCIAL_ENGINEERING_ASK_TYPES)
        + _se_list(fallback.get("ask_type"), SOCIAL_ENGINEERING_ASK_TYPES)
    )
    if not ask_type:
        ask_type = ["none"]
    levers = _dedupe_preserve_order(
        _se_list(raw.get("levers"), SOCIAL_ENGINEERING_LEVERS)
        + _se_list(fallback.get("levers"), SOCIAL_ENGINEERING_LEVERS)
    )
    confidence = max(_se_float(raw.get("confidence")), _se_float(fallback.get("confidence")))
    ask_present = _se_bool(raw.get("ask_present")) or _se_bool(fallback.get("ask_present")) or bool(set(ask_type) - {"none"})
    return {
        "status": "done",
        "intent": intent,
        "ask_present": ask_present,
        "ask_type": ask_type,
        "levers": levers,
        "persona_targeting": str(raw.get("persona_targeting") or fallback.get("persona_targeting") or "generic").strip().lower(),
        "channel_coherence": str(raw.get("channel_coherence") or fallback.get("channel_coherence") or "unknown").strip().lower(),
        "urgency_score": round(max(_se_float(raw.get("urgency_score")), _se_float(fallback.get("urgency_score"))), 2),
        "confidence": round(confidence, 2),
        "model": str(raw.get("model") or "mistral_semantic_pillar").strip(),
        "provenance": "pipeline_only",
    }
def _has_explicit_user_directed_action_impl(raw_text: str) -> bool:
    normalized = _normalise_obfuscated_text(raw_text or "").lower()
    if not normalized:
        return False
    return bool(
        re.search(
            r"\b("
            r"v[ăa]\s+rug[ăa]m|te\s+rug[ăa]m|te\s+rog|trebuie\s+s[ăa]|"
            r"acces(?:eaz[ăa]|a[țt]i|ati)|deschid(?:e|e[țt]i|eti)|apas[ăa]|"
            r"logheaz[ăa][-\s]?te|autentific[ăa][-\s]?te|introdu\w*|completeaz\w*|"
            r"r[ăa]spunde\w*|comunic\w*|confirm(?:[ăa]|a[țt]i|ati|i)|verific(?:[ăa]|a[țt]i|ati|i)|"
            r"scan(?:eaz[ăa]|a[țt]i|ati)|"
            r"pl[ăa]t(?:e[șs]te|i[țt]i|iti)|achit(?:[ăa]|a[țt]i|ati)|"
            r"transfer(?:[ăa]|a[țt]i|ati)|instal\w*|descarc\w*|sun[ăa]|suna[țt]i|sunati"
            r")\b",
            normalized,
            re.IGNORECASE,
        )
    )


def _has_explicit_user_directed_action(raw_text: str) -> bool:
    return _has_explicit_user_directed_action_impl(raw_text)

def _looks_like_descriptive_or_status_context(raw_text: str) -> bool:
    normalized = _normalise_obfuscated_text(raw_text or "").lower()
    if not normalized:
        return False
    if _has_invoice_payment_beneficiary_mismatch(normalized):
        return False
    negated_red_flag_explainer = bool(
        re.search(r"\bnu\s+(?:[îi]nseamn[ăa]|inseamna)\s+c[ăa]\b", normalized, re.IGNORECASE)
        and re.search(
            r"\b(?:ghid|articol|newsletter|material\s+educa[țt]ional|red\s+flag)\b"
            r"(?=[\s\S]{0,180}\b(?:scam|fraud|phishing|iban|cont|plat[ăa]|factur[ăa])\b)",
            normalized,
            re.IGNORECASE,
        )
    )
    if re.search(
        r"\bscan(?:eaz[ăa]|a[țt]i|ati)\b(?=[\s\S]{0,80}\bqr\b)(?=[\s\S]{0,120}\bplat[ăa]\b)",
        normalized,
        re.IGNORECASE,
    ):
        return False
    known_control_context = bool(
        re.search(
            r"\b(ticket\s+intern|two[-\s]?person\s+approval|dkim\s+pass|spf\s+pass|dmarc\s+pass|"
            r"hmac\s+match|vendor\s+profile|vendor(?:/|\s+și\s+|\s+si\s+)?iban\s+cunoscut)\b",
            normalized,
            re.IGNORECASE,
        )
    )
    if re.search(
        r"\b(reply[-\s]?to\s+diferit|cont(?:ul)?\s+bancar\s+nou|iban(?:ul)?\s+nou|noul\s+iban|"
        r"cere\s+plata\s+azi|plata\s+azi)\b",
        normalized,
        re.IGNORECASE,
    ) and not negated_red_flag_explainer and not re.search(
        r"\bf[ăa]r[ăa]\s+(?:schimbare|modificare)\s+(?:de\s+)?(?:iban|cont(?:\s+bancar)?)\b",
        normalized,
        re.IGNORECASE,
    ):
        return False
    if (
        re.search(r"\bplat[ăa]\s+(?:urgent[ăa]|[îi]n\s+24h?)\b", normalized, re.IGNORECASE)
        and not known_control_context
        and not re.search(
            r"\bf[ăa]r[ăa]\s+(?:schimbare|modificare)\s+(?:de\s+)?(?:iban|cont(?:\s+bancar)?)\b",
            normalized,
            re.IGNORECASE,
        )
    ):
        return False
    patterns = (
        r"\btranzac[țt]ie\s+autorizat[ăa]\b",
        r"\bsold\s+disponibil\b",
        r"\b(dkim\s+pass|spf\s+pass|dmarc\s+pass|hmac\s+match|vendor\s+profile|total\s+coerent|"
        r"two[-\s]?person\s+approval|ticket\s+intern|vendor(?:/|\s+și\s+|\s+si\s+)?iban\s+cunoscut)\b",
        r"\b(corespunde\s+pdf-?ului|corespunde\s+pdf|se\s+potrive[șs]te\s+cu\s+pdf|"
        r"match\s+vendor\s+local|vendor\s+registry\s+local|iban[-\s]ul\s+match|iban\s+identice?)\b",
        r"\bportal(?:ul)?\s+oficial\b(?=[\s\S]{0,160}\bf[ăa]r[ăa]\s+(?:link|cont\s+ter[țt]|cont\s+tert)\b)",
        r"\b(?:prima|nou[ăa])\s+factur[ăa]\b(?=[\s\S]{0,220}\b(?:pfa|srl|furnizor|contract|iban|neverificat|neconfirmat)\b)",
        r"\biban\s+(?:valid|confirmat|verificat)\b"
        r"(?=[\s\S]{0,160}\bcui\s+(?:valid|confirmat|verificat)\b)"
        r"(?=[\s\S]{0,220}\b(?:dar|[îi]ns[ăa]|insa|totu[șs]i)\b)"
        r"(?=[\s\S]{0,240}\b(?:neverificat|neconfirmat|necunoscut|istoric(?:ul)?|banc[ăa]\s+necunoscut[ăa])\b)",
        r"\b(?:cui|iban)\s+(?:aparent\s+)?valid(?:e)?\b"
        r"(?=[\s\S]{0,180}\b(?:cui|iban)\s+(?:aparent\s+)?valid(?:e)?\b)"
        r"(?=[\s\S]{0,260}\b(?:first[-\s]?time\s+vendor|furnizor(?:ul)?(?:\s+nou)?|"
        r"registry\s+nu\s+are|registr(?:y|ul)\s+nu\s+are|indisponibil(?:[ăa])?)\b)",
        r"\b(?:cui\s+(?:[șs]i|si)\s+iban|iban\s+(?:[șs]i|si)\s+cui)\s+(?:aparent\s+)?valid(?:e)?\b"
        r"(?=[\s\S]{0,260}\b(?:first[-\s]?time\s+vendor|furnizor(?:ul)?(?:\s+nou)?|"
        r"registry\s+nu\s+are|registr(?:y|ul)\s+nu\s+are|indisponibil(?:[ăa])?)\b)",
        r"\bfactur[ăa]\s+nr\.?\b(?=[\s\S]{0,220}\b(?:emitent|cui|total|iban|beneficiar)\b)",
        r"\b(articol|ghid|newsletter|material\s+educa[țt]ional|red\s+flag)\b[\s\S]{0,120}\b(scam|fraud|phishing|sextortion|tech\s+support|iban)\b",
        r"\bnu\s+(?:[îi]nseamn[ăa]|inseamna)\s+c[ăa]\b",
        r"\bf[ăa]r[ăa]\s+(?:wallet|plat[ăa]|plata|link\s+card|cerere\s+de\s+(?:bani|date|card|otp)|crypto)\b",
        r"\bf[ăa]r[ăa]\s+(?:linkuri?|cerere|solicitare)\s+(?:de\s+)?(?:plat[ăa]|date|card|otp|login)\b",
        r"\bf[ăa]r[ăa]\s+(?:schimbare|modificare)\s+(?:de\s+)?(?:iban|cont(?:\s+bancar)?)\b",
        r"\bf[ăa]r[ăa]\s+link\s+extern\b",
        r"\bfactur[ăa]\s+num[ăa]r\s+deja\s+v[ăa]zut\b",
        r"\breminder\s+plat[ăa]\b(?=.{0,120}\bf[ăa]r[ăa]\b)",
        r"\b(?:cui|iban)\s+(?:activ|valid|confirmat|verificat)\b[\s\S]{0,80}\b(?:anaf|mod-?97|registry|registru)\b",
        r"\b(?:furnizor|platform[ăa]|document|factur[ăa])\s+(?:cunoscut|autorizat|oficial|verificat)\b",
    )
    return any(re.search(pattern, normalized, re.IGNORECASE) for pattern in patterns)
def _brand_warning_rule_for_claimed_brand(claimed_brand: str) -> Optional[Dict[str, Any]]:
    normalized = _normalize_claimed_brand(claimed_brand)
    if not normalized:
        return None

    for brand_id, display_name in BRAND_ID_TO_DISPLAY_NAME.items():
        if normalized == str(display_name).strip().lower():
            return BRAND_WARNING_RULES.get(brand_id)

    for brand_id, display_name in BRAND_ID_TO_DISPLAY_NAME.items():
        if normalized in {str(display_name).strip().lower(), brand_id.lower(), brand_id.replace("_", " ").lower()}:
            return BRAND_WARNING_RULES.get(brand_id)
        if normalized in str(display_name).strip().lower():
            return BRAND_WARNING_RULES.get(brand_id)

    return None

def _brand_warning_matches_text(claimed_brand: str, raw_text: str) -> Dict[str, Any]:
    rule = _brand_warning_rule_for_claimed_brand(claimed_brand)
    if not isinstance(rule, dict):
        return {"triggered": False, "matched_assets": [], "brand_id": None}

    never_ask_for = rule.get("never_ask_for")
    if not isinstance(never_ask_for, dict):
        return {"triggered": False, "matched_assets": [], "brand_id": rule.get("brand_id")}

    # Brand warnings must be grounded in user input only. Feeding prior atlas
    # reasons back into this detector creates circular evidence: a weak family
    # match can mention an asset that the original message never requested.
    combined = _normalise_obfuscated_text(raw_text or "").lower()
    matched_assets: List[str] = []

    def _hit_card_request() -> bool:
        if "card" not in combined:
            return False
        benign_card_context = (
            "ai suficienti bani pe card",
            "ai suficienți bani pe card",
            "bani pe card",
            "plata abonamentului",
            "plată abonamentului",
            "se va efectua automat plata",
            "plata se va efectua automat",
            "plată se va efectua automat",
        )
        if any(token in combined for token in benign_card_context) and not re.search(
            r"(?:introdu|completeaz[aă]|completeaza|trimite|actualiz|verific[aă]|valideaz[aă]|confirm[aă])"
            r"(?:\W+\w+){0,8}\W+(?:date(?:le)?\s+(?:de\s+)?card|num[aă]r(?:ul)?\s+(?:de\s+)?card|cardul|cvv|cvc)",
            combined,
            re.IGNORECASE,
        ):
            return False
        return bool(
            re.search(
                r"(?:introdu|completeaz[aă]|completeaza|trimite|actualiz|verific[aă]|valideaz[aă]|confirm[aă])"
                r"(?:\W+\w+){0,8}\W+(?:date(?:le)?\s+(?:de\s+)?card|num[aă]r(?:ul)?\s+(?:de\s+)?card|cardul|cvv|cvc)",
                combined,
                re.IGNORECASE,
            )
            or re.search(
                r"(?:date(?:le)?\s+(?:de\s+)?card|num[aă]r(?:ul)?\s+(?:de\s+)?card|cvv|cvc)"
                r"(?:\W+\w+){0,8}\W+(?:introdu|completeaz[aă]|completeaza|trimite|actualiz|verific[aă]|valideaz[aă]|confirm[aă])",
                combined,
                re.IGNORECASE,
            )
        )

    detectors = {
        "card_number": _hit_card_request,
        "cvv": lambda: "cvv" in combined or "cvc" in combined,
        "otp": lambda: (
            "otp" in combined
            or "cod otp" in combined
            or "cod sms" in combined
            or "codul de verificare" in combined
            or ("trimite" in combined and "cod" in combined)
            or ("introdu" in combined and "cod" in combined)
        ),
        "whatsapp_code": lambda: "whatsapp" in combined and "cod" in combined,
        "banking_pin": lambda: " pin" in f" {combined}" or "cod pin" in combined,
        "password": lambda: "parola" in combined or "parolă" in combined or "password" in combined,
        "cnp": lambda: "cnp" in combined,
        "iban": lambda: "iban" in combined,
        "remote_access": lambda: any(token in combined for token in ("anydesk", "teamviewer", "rustdesk", "control la distanta", "control la distanță", "asistenta la distanta", "asistență la distanță", "remote access")),
        "apk_install": lambda: "apk" in combined or ("instale" in combined and "aplic" in combined) or ("descarca" in combined and "aplic" in combined) or ("descarcă" in combined and "aplic" in combined),
        "safe_account_transfer": lambda: "cont sigur" in combined or "transfer sigur" in combined,
        "crypto_atm_deposit": lambda: any(token in combined for token in ("crypto atm", "bitcoin atm", "depunere crypto")),
    }

    for asset, enabled in never_ask_for.items():
        if not enabled:
            continue
        detector = detectors.get(str(asset))
        if detector and detector():
            matched_assets.append(str(asset))

    matched_assets = sorted(set(matched_assets))
    return {
        "triggered": bool(matched_assets),
        "matched_assets": matched_assets,
        "brand_id": rule.get("brand_id"),
        "source_url": rule.get("source_url"),
        "summary": rule.get("exact_official_statement_summary"),
        "signal": rule.get("evidence_gate_signal_suggested"),
    }



def _brand_warning_rule_for_claimed_brand_impl(claimed_brand: str) -> Optional[Dict[str, Any]]:
    return _brand_warning_rule_for_claimed_brand(claimed_brand)


def _brand_warning_matches_text_impl(claimed_brand: str, raw_text: str) -> Dict[str, Any]:
    return _brand_warning_matches_text(claimed_brand, raw_text)

def _looks_like_official_safety_education(raw_text: str) -> bool:
    normalized = _normalise_obfuscated_text(raw_text or "").lower()
    if not normalized:
        return False
    scope_trick = (
        r"\b("
        r"doar\s+(?:aici|acest(?:ui)?\s+agent|codul)|"
        r"doar\s+(?:primele|ultimele|\d+)|"
        r"(?:introdu|introduce|trimite)[-\s]?(?:l|le)?\s+doar|"
        r"doar\s+(?:[îi]n|in)\s+(?:caseta|formularul|c[âa]mpul)\b|"
        r"(?:[îi]n|in)\s+afar[ăa]\s+de|"
        r"folose[șs]te\s+noul\s+cont|"
        r"nu\s+(?:suna|sun[aă]|verifica|face\s+callback|[îi]nchide|inchide)|"
        r"r[ăa]m[aâ]ne[țt]i\s+la\s+telefon"
        r")\b"
    )
    if re.search(scope_trick, normalized, re.IGNORECASE):
        return False
    action_after_warning = (
        r"(?:pentru\s+a\s+(?:demonstra|confirma|verifica)|ca\s+s[ăa]\s+(?:demonstrezi|confirmi|verifici)|"
        r"simulator|test\s+de\s+(?:siguran[țt][ăa]|securitate))"
        r".{0,140}\b(?:autentific[ăa][-\s]?te|logheaz[ăa][-\s]?te|login|introdu|completeaz[ăa]|"
        r"trimite|cod|otp|parol[ăa]|date(?:le)?\s+(?:de\s+)?card)\b"
    )
    if re.search(action_after_warning, normalized, re.IGNORECASE):
        return False
    sensitive_terms = (
        r"(?:cnp|pin|cvv|cvc|otp|cod(?:ul|uri?)?(?:\s+sms)?|parol[ăa]|date\s+de\s+card|date(?:le)?\s+bancare|"
        r"datele\s+cardului|num[aă]r(?:ul)?\s+(?:de\s+)?card|iban|cont\s+(?:nou|sigur|temporar|seif)|"
        r"conturi\s+(?:noi|sigure|temporare|seif)|"
        r"acces(?:ul)?\s+la\s+(?:dispozitiv|telefon|calculator)|"
        r"transfer(?:[ăa]|a)?\s+bani|transfer\s+preventiv|bani|crypto\s+atm|usdt|tax(?:[ăa]|e)\s+de\s+retragere|profit\s+garantat|"
        r"obliga[țt]ii?\s+de\s+plat[ăa]|schimbare\s+de\s+iban|"
        r"copie\s+(?:ci|act)|ci\s+fa[țt][ăa][-\s]?verso|act(?:ul)?\s+(?:de\s+)?identitate|"
        r"carduri?\s+cadou|gift\s*card|voucher|autentificare\s+bancar[ăa]|actualizarea\s+parolei|link\s+primit|home.?bank|logare|login|"
        r"anydesk|teamviewer|rustdesk|control\s+la\s+distan[țt][ăa]|asisten[țt][ăa]\s+la\s+distan[țt][ăa]|remote\s+access|"
        r"aplica[țt]i[ei]?\s+(?:de\s+)?(?:(?:acces|asisten[țt][ăa])\s+la\s+distan[țt][ăa]|remote))"
    )
    ask_verbs = r"(?:cer(?:e|em)|solicit(?:[ăa]|[aă]m)|trimitem|pretindem)"
    negative_claim = (
        rf"(?:nu\s+(?:iti|îți|va|vă|iti\s+|vom\s+|vei\s+|veți\s+|veti\s+)?\s*{ask_verbs}"
        r"|nu\s+(?:ti|ți|vi|vă)?\s*se\s+solicit[aă]"
        r"|nu\s+exist[ăa]"
        r"|nu\s+con[țt]ine"
        r"|nu\s+anun[țt][ăa]"
        r"|nu\s+se\s+modific[ăa]"
        r"|nu\s+pune"
        r"|nu\s+permitem"
        r"|nu\s+permite\w*"
        r"|nu\s+r[ăa]spunde"
        r"|nu\s+te\s+loga"
        r"|nu\s+acces\w*"
        r"|nu\s+deschid\w*"
        r"|nu\s+introdu\w*"
        r"|nu\s+instal\w*"
        r"|nu\s+desc[aă]rc\w*"
        r"|nu\s+folos\w*"
        r"|nu\s+pl[ăa]t\w*"
        r"|nu\s+schimb\w*"
        r"|nu\s+depun\w*"
        r"|nu\s+transfer\w*"
        r"|nu\s+(?:(?:il|îl|le)\s+)?comunic\w*"
        r"|nu\s+(?:(?:il|îl|le)\s+)?trimite\w*"
        r"|nu\s+(?:(?:il|îl|le|i|o)\s+)?da(?:ti|ți|u)?\b"
        r"|nu\s+divulg\w*"
        r"|nu\s+dezv[ăa]lu\w*"
        r"|nu\s+furniz\w*"
        rf"|nu\s+{ask_verbs}"
        rf"|niciodat[aă]\s+nu\s+{ask_verbs})"
    )
    window = r"(?:\W+\w+){0,12}\W*"
    if (
        re.search(negative_claim + window + sensitive_terms, normalized, re.IGNORECASE)
        or re.search(sensitive_terms + window + negative_claim, normalized, re.IGNORECASE)
    ):
        return True
    if re.search(
        r"nu\s+(?:îți|[îi]ti|iti)\s+va\s+cere\b(?=.{0,160}\b(?:transfer\s+preventiv|cont\s+sigur|iban|bani|datele\s+cardului|otp|cod|parol[ăa])\b)",
        normalized,
        re.IGNORECASE,
    ):
        return True
    if re.search(
        r"nu\s+(?:îți|[îi]ti|iti|v[ăa])\s+(?:(?:va|vom)\s+)?cere(?:m)?\s+niciodat[aă]\b"
        r"(?=.{0,180}\b(?:introdu\w*|trimite\w*|comunic\w*|parol[ăa]|otp|cod|pin|cvv|date(?:le)?\s+bancare|date(?:le)?\s+card)\b)",
        normalized,
        re.IGNORECASE,
    ):
        return True
    if re.search(
        r"nu\s+(?:acces\w*|deschid\w*)\b(?=.{0,120}\b(?:linkuri?|ata[șs]amente?|fi[șs]iere?)\b)"
        r"(?=.{0,160}\b(?:false|suspecte|nesolicitate|neoficiale|date\s+bancare|date\s+card|fraud)\b)",
        normalized,
        re.IGNORECASE,
    ):
        return True
    if re.search(
        r"nu\s+deschid\w*\b(?=.{0,80}\bfi[șs]iere?\b)(?=.{0,160}\b(?:email|mail|solicitat\s+explicit|solicitate\s+explicit)\b)",
        normalized,
        re.IGNORECASE,
    ):
        return True
    if re.search(
        r"nu\s+permite\w*(?:\s+niciodat[aă])?\b(?=.{0,140}\bacces(?:ul)?\s+la\s+(?:dispozitiv|telefon|calculator)\b)",
        normalized,
        re.IGNORECASE,
    ):
        return True
    if re.search(
        r"\biban(?:-ul|ul)?\b(?=.{0,120}\b(?:identic|neschimbat|r[ăa]m[aâ]n(?:e|)\s+cel|contractul\s+ini[țt]ial)\b)",
        normalized,
        re.IGNORECASE,
    ):
        return True
    if re.search(
        r"(?:niciun|niciun\s+suport|avertizare).{0,120}\bnu\s+cere\b(?=.{0,160}\b(?:carduri?\s+cadou|gift\s*card|voucher|sun[ăa]|num[ăa]r\s+din\s+pop-up)\b)",
        normalized,
        re.IGNORECASE,
    ):
        return True
    if re.search(
        r"nu\s+se\s+solicit[ăa]\b(?=.{0,160}\b(?:actualizarea\s+parolei|parol[ăa]|link|logare)\b)",
        normalized,
        re.IGNORECASE,
    ):
        return True
    if re.search(
        r"\b(?:otp|cod(?:ul)?(?:\s+(?:sms|de\s+(?:verificare|confirmare|autorizare)))?)\b"
        r"(?=.{0,100}\bnu\s+(?:(?:il|îl|le)\s+)?(?:divulg\w*|dezv[ăa]lu\w*|trimite\w*|comunic\w*)\b)",
        normalized,
        re.IGNORECASE,
    ):
        return True
    if (
        re.search(r"\bdac[ăa]\b", normalized, re.IGNORECASE)
        and re.search(r"\b(?:cere|prime[șs]ti|solicit[ăa])\b", normalized, re.IGNORECASE)
        and re.search(sensitive_terms, normalized, re.IGNORECASE)
        and re.search(
            r"(?:opre[șs]te|nu\s+(?:trimite|pl[ăa]ti|continua|introdu)|sun[ăa]|confirm[ăa])",
            normalized,
            re.IGNORECASE,
        )
    ):
        return True
    if re.search(
        r"\bconfirm[ăa]\b(?=.{0,120}\b(?:iban|cont|schimbare)\b)"
        r"(?=.{0,180}\b(?:num[ăa]rul\s+deja\s+cunoscut|canalul\s+oficial|telefonic|apel)\b)",
        normalized,
        re.IGNORECASE,
    ):
        return True
    if re.search(
        r"\bmesaj(?:ele|e)?\s+de\s+tip\b(?=.{0,180}\b(?:fraud|nu\s+le\s+urma|nu\s+r[ăa]spunde)\b)",
        normalized,
        re.IGNORECASE,
    ):
        return True
    if re.search(
        r"\bexemplu\s+de\s+fraud[ăa]\b(?=.{0,180}\b(?:nu\s+continua|nu\s+r[ăa]spunde|nu\s+urma|dac[ăa]\s+vezi)\b)",
        normalized,
        re.IGNORECASE,
    ):
        return True
    if re.search(
        r"\bdocument(?:ul)?\s+educa[țt]ional\b(?=.{0,180}\b(?:nu|fraud|neoficial)\b)",
        normalized,
        re.IGNORECASE,
    ):
        return True
    return False


def _looks_like_official_safety_education_impl(raw_text: str) -> bool:
    return _looks_like_official_safety_education(raw_text)
def _has_direct_sensitive_request_impl(raw_text: str) -> bool:
    if _data_url_contains_sensitive_form(raw_text):
        return True
    normalized = _normalise_obfuscated_text(raw_text or "").lower()
    if not normalized or _looks_like_official_safety_education(normalized):
        return False
    if _looks_like_descriptive_or_status_context(normalized) and not _has_explicit_user_directed_action(normalized):
        return False
    verbs = (
        r"(?:introdu\w*|completeaz\w*|trimite\w*|r[ăa]spunde\w*|spune\w*|comunic\w*|"
        r"d[ăa](?:[-\s]?(?:mi|ne))?|da[țt]i(?:[-\s]?(?:mi|ne))?|dati(?:[-\s]?(?:mi|ne))?|"
        r"furnizeaz\w*|ofer[ăa]\w*|cite[șs]te|citeste|captur\w*|poz[ăa]|screenshot|"
        r"confirm\w*|valideaz\w*|verific\w*|"
        r"logheaz[ăa][-\s]?te|autentific[ăa][-\s]?te)"
    )
    sensitive = (
        r"(?:parol[ăa]|password|otp|cod(?:ul)?(?:\s+(?:pe\s+)?(?:sms|whatsapp)|"
        r"\s+de\s+(?:verificare|confirmare|autorizare|autentificare)|\s+3ds)?|cod(?:ul)?\s+unic|"
        r"cod(?:ul)?.{0,40}aplica[țt]ia\s+bancar[ăa]|"
        r"(?:prima|a\s+treia|a\s+cincea|ultimele|primele).{0,50}(?:cifr[ăa]|cifre).{0,50}cod|"
        r"(?:cod\s+qr|qr).{0,40}(?:esim|e-sim|profil(?:ul)?\s+sim)|"
        r"(?:esim|e-sim|profil(?:ul)?\s+sim).{0,40}(?:cod\s+qr|qr)|"
        r"pin(?:-ul|ul)?|cvv|cvc|date(?:le)?\s+(?:de\s+)?card(?:ului)?|datele\s+cardului|"
        r"num[aă]r(?:ul)?\s+(?:de\s+)?card(?:ului)?|"
        r"ultimele\s+\d+\s+cifre\s+(?:ale\s+)?card(?:ului)?|"
        r"cnp|iban|copie\s+(?:ci|act)|act(?:ul)?\s+(?:de\s+)?identitate)"
    )
    return bool(
        re.search(verbs + r"(?:\W+\w+){0,8}\W+" + sensitive, normalized, re.IGNORECASE)
        or re.search(sensitive + r"(?:\W+\w+){0,8}\W+" + verbs, normalized, re.IGNORECASE)
    )


def _has_direct_sensitive_request(raw_text: str) -> bool:
    return _has_direct_sensitive_request_impl(
raw_text,

    )


def _has_sensitive_url_path_impl(resolved_urls: List[Dict[str, Any]]) -> bool:
    sensitive_path_tokens = (
        "card", "cvv", "cvc", "otp", "cod", "login", "auth", "parola", "password", "date",
        "formular", "form", "identitate", "pay", "plata", "plată", "checkout", "achita",
        "securitate", "security", "update", "install", "session",
    )
    for entry in resolved_urls or []:
        url = str(entry.get("final_url") or entry.get("url") or "")
        parsed = urllib.parse.urlparse(url)
        target = urllib.parse.unquote(f"{parsed.path or ''}?{parsed.query or ''}").lower()
        if any(token in target for token in sensitive_path_tokens):
            return True
    return False


def _has_sensitive_url_path(resolved_urls: List[Dict[str, Any]]) -> bool:
    return _has_sensitive_url_path_impl(
resolved_urls,

    )


def _claim_verifier_required_impl(analysis: Dict[str, Any]) -> bool:
    claimed = str(analysis.get("claimed_brand") or "").strip().lower()
    if claimed and claimed not in {"nespecificat", "unknown", "none"}:
        return True
    evidence = analysis.get("evidence", {}) if isinstance(analysis.get("evidence"), dict) else {}
    if evidence.get("has_domain_mismatch"):
        return True
    family_text = " ".join(
        str(value).lower()
        for value in (analysis.get("detected_family_id"), analysis.get("detected_family"))
        if value
    )
    markers = (
        "ofert",
        "promo",
        "voucher",
        "campanie",
        "catalog",
        "curier",
        "colet",
        "anaf",
        "banc",
        "otp",
        "card",
        "plata",
        "plată",
        "cont",
    )
    return any(marker in family_text for marker in markers)


def _claim_verifier_required(analysis: Dict[str, Any]) -> bool:
    return _claim_verifier_required_impl(
analysis,

    )


def _attach_brand_warning_summary_impl(summary: Dict[str, Any], brand_warning: Dict[str, Any]) -> None:
    if not isinstance(summary, dict):
        return
    if not isinstance(brand_warning, dict) or not brand_warning.get("triggered"):
        summary.pop("brand_warning_corpus", None)
        return

    matched_assets = list(brand_warning.get("matched_assets") or [])
    high_risk_assets = {"card_number", "cvv", "otp", "whatsapp_code", "banking_pin", "password", "remote_access", "apk_install"}
    severity = "high" if any(asset in high_risk_assets for asset in matched_assets) else "medium"
    summary["brand_warning_corpus"] = {
        "status": "triggered",
        "verdict": "brand_warning",
        "severity": severity,
        "summary": brand_warning.get("summary", ""),
        "details": brand_warning.get("summary", ""),
        "brand_id": brand_warning.get("brand_id"),
        "matched_assets": matched_assets,
        "source_url": brand_warning.get("source_url"),
        "signal": brand_warning.get("signal"),
    }


def _attach_brand_warning_summary(summary: Dict[str, Any], brand_warning: Dict[str, Any]) -> None:
    return _attach_brand_warning_summary_impl(
summary,
        brand_warning,

    )


def _source_status(summary: Dict[str, Any], source_name: str) -> str:
    return _source_status_impl(
summary,
        source_name,

    )


def _source_consulted(summary: Dict[str, Any], source_name: str) -> bool:
    return _source_consulted_impl(
summary,
        source_name,

    )


# Explicit *request* for identity data ("furnizați datele de identificare",
# "transmiteți CNP-ul"). Authority/vishing scams ask for generic "date de
# identificare" / "date personale" rather than "act de identitate"/"buletin",
# so without this the request never lights HARD_SENSITIVE_REQUESTS and the gate
# cannot escalate sensitive-on-wrong-channel. Gated on a 2nd-person request verb
# adjacent to the identity-data target so benign/legal/negated mentions
# ("nu transmitem date personale", "prelucrarea datelor personale conform GDPR",
# "datele personale sunt protejate") do NOT fire. Shared by both the provider-gate
# and scan-analysis sensitivity derivations to keep them from diverging.
_IDENTITY_DATA_REQUEST_RE = re.compile(
    r"\b(?:furniza[țt]i|transmite[țt]i|confirma[țt]i|trimite[țt]i|comunica[țt]i|"
    r"valida[țt]i|prezenta[țt]i|introduce[țt]i|spune[țt]i|da[țt]i|dicta[țt]i)\b"
    r"[^.?!]{0,40}?"
    r"\b(?:date(?:le)?\s+(?:de\s+)?identificare|date(?:le)?\s+de\s+identitate|"
    r"date(?:le)?\s+personale|cnp)\b",
    re.IGNORECASE,
)
_IDENTITY_DATA_CNP_RE = re.compile(r"\bcnp\b", re.IGNORECASE)


def _identity_data_request_token(normalized: str) -> Optional[str]:
    """Return ``cnp``/``id_document`` when text explicitly *requests* identity data,
    else ``None``. Operates on already-normalised (lowercased) text."""
    match = _IDENTITY_DATA_REQUEST_RE.search(normalized or "")
    if not match:
        return None
    return "cnp" if _IDENTITY_DATA_CNP_RE.search(match.group(0)) else "id_document"


def _request_sensitivity_from_signals_impl(
    *,
    raw_text: str,
    brand_warning: Dict[str, Any],
    direct_sensitive_request: bool,
    sensitive_url_path: bool,
    official_destination: bool,
    resolved_urls: List[Dict[str, Any]],
) -> str:
    normalized = _normalise_obfuscated_text(raw_text or "").lower()
    official_safety_education = _looks_like_official_safety_education(normalized)
    if official_safety_education:
        direct_sensitive_request = False
        brand_warning = {"triggered": False, "matched_assets": []}
    matched_assets = set(brand_warning.get("matched_assets") or []) if isinstance(brand_warning, dict) else set()
    local_high_risk = _local_high_risk_semantic_review(normalized)
    if local_high_risk:
        matched_family = str(local_high_risk.get("matched_family") or "")
        if matched_family == "otp_code_exfiltration":
            return "otp"
        if matched_family in {
            "esim_qr_exfiltration",
            "bank_app_code_exfiltration",
            "partial_code_exfiltration",
        }:
            return "otp"
        if matched_family == "remote_access_install_request":
            return "remote"
        if matched_family in {
            "family_emergency_money_request",
            "family_voice_clone_emergency_payment",
            "fake_authority_safe_account",
            "digital_custody_transfer",
            "cfo_approval_bypass_payment",
            "recovery_audit_fee_before_refund",
            "gift_card_payment",
            "job_task_topup",
            "domain_or_trademark_scare_payment",
            "safe_account_or_protective_transfer",
            "new_iban_callback_suppression",
            "voucher_code_payment",
            "courier_payment_link_pressure",
            "bec_urgent_confidential_transfer",
            "investment_guaranteed_deposit",
            "authority_unavailable_payment_pressure",
            "courier_fee_payment_link",
            "exclusive_new_iban_payment",
            "supplier_bank_details_change",
            "proforma_new_account_before_delivery",
            "hospital_bail_no_call_money_request",
            "tech_support_gift_card_payment",
            "urgent_payment_link_pressure",
            "beneficiary_mismatch_new_account",
            "safe_beneficiary_test_transfer",
            "courier_refundable_deposit_link",
            "package_release_token_fee",
            "migrated_account_new_iban",
            "bank_change_iban_format",
            "institution_fee_to_account",
        }:
            return "transfer"
        if matched_family in {"bank_data_collection", "external_card_cvv_otp_collection"}:
            return "card"
        if matched_family in {"brand_login_update_link", "bank_credential_update_phish", "password_update_link", "safety_education_login_pretext", "data_url_credential_form"}:
            return "password"
        if matched_family in {"executable_invoice_attachment", "security_update_install_link", "fake_security_app_install", "deeplink_fallback_login_or_install"}:
            return "remote"
        if matched_family == "anti_verification_pressure":
            if re.search(r"\b(transfer\w*|iban|cont\w*|pl[ăa]t\w*|achit\w*|bani|lei|ron)\b", normalized):
                return "transfer"
            return "password"

    logistics_pin_context = official_destination and bool(
        re.search(r"\b(pin|cod)\b", normalized)
        and re.search(r"\b(awb|locker|colet|ridicare|livrare|curier)\b", normalized)
    )
    if not logistics_pin_context:
        if matched_assets.intersection({"otp", "whatsapp_code", "banking_pin"}):
            return "otp"

    if matched_assets.intersection({"password"}):
        return "password"
    if matched_assets.intersection({"remote_access", "apk_install"}):
        return "remote"
    if matched_assets.intersection({"card_number", "cvv"}):
        return "card"
    if matched_assets.intersection({"safe_account_transfer", "iban", "crypto_atm_deposit"}):
        return "crypto" if "crypto_atm_deposit" in matched_assets else "transfer"

    if official_safety_education:
        return "none"

    if re.search(r"\b(anydesk|teamviewer|rustdesk|apk|control la distan[țt][ăa]|asisten[țt][ăa] la distan[țt][ăa]|remote access)\b", normalized):
        return "remote"
    if re.search(r"\bremote\b", normalized) and re.search(r"\b(agent|calculator|descarc[ăa]|tool|intra|intr[ăa])\b", normalized):
        return "remote"
    if re.search(r"\b(crypto|bitcoin|usdt|binance|wallet|seed phrase)\b", normalized):
        return "crypto"
    if re.search(r"\b(parol[ăa]|password)\b", normalized) and direct_sensitive_request:
        return "password"
    if re.search(
        r"\b(cvv|cvc|date(?:le)?\s+(?:de\s+)?card(?:ului)?|datele\s+cardului|"
        r"num[aă]r(?:ul)?\s+(?:de\s+)?card(?:ului)?|"
        r"\w{0,24}card(?:ul|ului|uri|urile)?\w{0,8})\b",
        normalized,
    ) and direct_sensitive_request:
        return "card"
    if re.search(
        r"\b(otp|cod(?:ul)?\s+(?:sms|whatsapp|de\s+(?:verificare|confirmare|autorizare|autentificare)|3ds)|2fa)\b",
        normalized,
    ) and direct_sensitive_request:
        return "otp"
    if re.search(
        r"\b(?:cod(?:ul)?\s+unic|cod(?:ul)?.{0,40}aplica[țt]ia\s+bancar[ăa]|"
        r"(?:prima|a\s+treia|a\s+cincea|primele|ultimele).{0,60}(?:cifr[ăa]|cifre).{0,60}cod|"
        r"(?:cod\s+qr|qr).{0,50}(?:esim|e-sim|profil(?:ul)?\s+sim)|"
        r"(?:esim|e-sim|profil(?:ul)?\s+sim).{0,50}(?:cod\s+qr|qr))\b",
        normalized,
    ) and direct_sensitive_request:
        return "otp"
    if _data_url_contains_sensitive_form(raw_text):
        return "password"
    if re.search(r"\b(logheaz[ăa][-\s]?te|autentific[ăa][-\s]?te|login|session)\b", normalized) and (
        direct_sensitive_request or (sensitive_url_path and not official_destination)
    ):
        return "password"
    if re.search(r"\b(copie\s+(?:ci|act)|ci\s+fa[țt][ăa][-\s]?verso|selfie|act(?:ul)?\s+(?:de\s+)?identitate|buletin)\b", normalized):
        return "id_document"
    identity_data_token = _identity_data_request_token(normalized)
    if identity_data_token:
        return identity_data_token
    if re.search(r"\b(gift\s*card|carduri?\s+cadou|voucher)\b", normalized) and re.search(r"\b(cump[ăa]r|cite[șs]te|cod|pl[ăa]t|achit)\b", normalized):
        return "transfer"
    if _has_investment_money_risk(normalized):
        return "transfer"

    payment_url_context = False
    for entry in resolved_urls or []:
        url = str(entry.get("final_url") or entry.get("url") or "")
        parsed = urllib.parse.urlparse(url)
        target = urllib.parse.unquote(f"{parsed.path or ''}?{parsed.query or ''}").lower()
        if any(token in target for token in ("pay", "plata", "plată", "checkout", "achita")):
            payment_url_context = True
            break
    non_url_text = URL_REGEX.sub(" ", normalized)
    if payment_url_context and re.search(
        r"\b(?:colet\w*|livrare|curier|vamal[ăa]?|tax[ăa]|factur[ăa]|abonament|restan[țt][ăa]|"
        r"sum[ăa]|ron|lei|eur|euro|usd|dolari)\b",
        non_url_text,
        re.IGNORECASE,
    ):
        return "transfer"

    if sensitive_url_path and not official_destination:
        for entry in resolved_urls or []:
            url = str(entry.get("final_url") or entry.get("url") or "")
            path = urllib.parse.unquote(urllib.parse.urlparse(url).path or "").lower()
            if any(token in path for token in ("card", "cvv", "cvc")):
                return "card"
            if any(token in path for token in ("otp", "cod")):
                return "otp"
            if any(token in path for token in ("login", "auth", "password", "parola", "session")):
                return "password"

    money_request_pattern = (
        r"(?:bani|lei|ron|eur|euro|usd|dolari|cash|numerar|sum[ăa]|garan[țt]ie|opera[țt]ie|"
        r"cau[țt]iune|cautiune|tax[ăa]|comision|validare|retragere|profit|randament)"
    )
    money_action_pattern = (
        r"(?:transfer[aă]?|transfera[țt]i?|transferati|trimite[țt]i?|trimite|trimit|achit[aă]?|"
        r"achita[țt]i?|achitati|pl[ăa]te[șs]te|plati[țt]i?|platiti|depune|depune[țt]i?|depuneti|"
        r"depun[eă]|depoziteaz[ăa]?|alimenteaz[ăa]?|virament|iban)"
    )
    currency_amount_pattern = (
        r"(?:\b\d[\d\s.,]*(?:ron|lei|eur|euro|usd|dolari)\b|[€$]\s*\d)"
    )
    money_destination_pattern = (
        r"(?:cont(?:ul)?\s+(?:nou|sigur)|iban|beneficiar(?:ul)?|partener(?:ul)?)"
    )
    if (
        re.search(r"\b(cont sigur|cont(?:ul)?\s+nou|transfer[aă] fondurile|transfer[aă] bani|iban)\b", normalized)
        or re.search(rf"\b{money_action_pattern}\b.{{0,80}}\b{money_request_pattern}\b", normalized)
        or re.search(rf"\b{money_request_pattern}\b.{{0,80}}\b{money_action_pattern}\b", normalized)
        or re.search(rf"\b{money_action_pattern}\b.{{0,100}}{currency_amount_pattern}", normalized)
        or re.search(rf"{currency_amount_pattern}.{{0,100}}\b{money_action_pattern}\b", normalized)
        or re.search(rf"\b{money_action_pattern}\b.{{0,100}}\b{money_destination_pattern}\b", normalized)
        or re.search(
            r"\b(mu[țt][ăa]|muta[țt]i?|mutati|transfer[aă]?|trimite[țt]i?)\b"
            r".{0,60}\b(sold(?:ul)?|fonduri(?:le)?|bani(?:i)?|suma)\b"
            r".{0,60}\b(cont(?:ul)?\s+(?:nou|sigur|de\s+protectie|seif|temporar))\b",
            normalized,
        )
        or re.search(
            r"\b(cont(?:ul)?\s+(?:de\s+)?(?:protectie|seif|temporar))\b",
            normalized,
        )
        or re.search(
            r"\b(dezactiv[ăa][tz]?|bloc[ăa][tz]?|suspend[ăa][tz]?)\b"
            r".{0,60}\b(cont(?:ul)?\s+(?:vechi|actual|existent))\b",
            normalized,
        )
    ):
        return "transfer"

    return "none"


def _request_sensitivity_from_signals(
    *,
    raw_text: str,
    brand_warning: Dict[str, Any],
    direct_sensitive_request: bool,
    sensitive_url_path: bool,
    official_destination: bool,
    resolved_urls: List[Dict[str, Any]],
) -> str:
    return _request_sensitivity_from_signals_impl(
        raw_text=raw_text,
        brand_warning=brand_warning,
        direct_sensitive_request=direct_sensitive_request,
        sensitive_url_path=sensitive_url_path,
        official_destination=official_destination,
        resolved_urls=resolved_urls,
    )

def _detect_person_never_does_violations_impl(
    raw_text: str, effective_channel: str,
    result: Any, violated_never_does: list,
) -> None:
    if not result.manifest_id or effective_channel in ("official", "official_website", "official_app"):
        return
    manifest = brand_truth_registry.get(result.manifest_id)
    if not manifest or manifest.type != "person":
        return
    text_lower = (raw_text or "").lower()
    _never_does_content_signals = {
        "investment_endorsement": ["investiții", "investitii", "oportunitate", "randament", "profit", "castig", "depozit", "dividend"],
        "investment_recommendation": ["recomand", "sfat", "sugerez", "personal", "exclusiv"],
        "crypto_promotion": ["crypto", "bitcoin", "btc", "ethereum", "coin", "token"],
    }
    for claim, signals in _never_does_content_signals.items():
        if claim not in manifest.never_does:
            continue
        for signal in signals:
            if signal in text_lower:
                if claim not in violated_never_does:
                    violated_never_does.append(claim)
                break


def _detect_person_never_does_violations(
    raw_text: str,
    effective_channel: str,
    result: Any,
    violated_never_does: list,
) -> None:
    return _detect_person_never_does_violations_impl(
        raw_text,
        effective_channel,
        result,
        violated_never_does,
    )

def _enrich_with_btr_provenance_impl(
    analysis: Dict[str, Any],
    claimed_brand: str,
    raw_text: str,
    resolved_urls: List[Dict[str, Any]],
) -> None:
    evidence = analysis.setdefault("evidence", {})
    if evidence.get("provenance"):
        return
    first_url = _first_final_url(resolved_urls)
    observed_domain = None
    if first_url:
        try:
            parsed = urllib.parse.urlparse(first_url)
            observed_domain = parsed.hostname
        except Exception:
            pass
    official_destination = _official_destination_confirmed(resolved_urls, claimed_brand)
    sensitive = _request_sensitivity_from_signals(
        raw_text=raw_text,
        brand_warning=evidence.get("brand_warning") or {"triggered": False, "matched_assets": []},
        direct_sensitive_request=evidence.get("direct_sensitive_request") or False,
        sensitive_url_path=_has_sensitive_url_path(resolved_urls),
        official_destination=official_destination,
        resolved_urls=resolved_urls,
    )
    effective_channel = "official_website" if official_destination else str(evidence.get("source_channel") or "unknown")
    sensitive_asks = []
    if sensitive and sensitive != "none":
        sensitive_asks.append(sensitive)
    result = brand_truth_registry.provenance_check(
        claimed_brand=claimed_brand if claimed_brand != "Nespecificat" else None,
        observed_channel=effective_channel,
        observed_domain=observed_domain,
        observed_phone_e164=None,
        sensitive_asks=sensitive_asks,
        payment_method=None,
        final_url=first_url,
    )
    violated_never_does = list(result.violated_never_does)
    _detect_person_never_does_violations_impl(
        raw_text,
        effective_channel,
        result,
        violated_never_does,
    )
    evidence["provenance"] = {
        "official_domain_match": result.official_match,
        "manifest_id": result.manifest_id,
        "manifest_version": brand_truth_registry.version,
        "provenance": result.provenance,
        "identity_status": result.identity_status,
        "violated_never_asks": result.violated_never_asks,
        "violated_never_does": violated_never_does,
        "evidence_power": result.evidence_power,
        "reason_codes": result.reason_codes,
    }
    if result.violated_never_asks:
        analysis["violated_never_asks"] = result.violated_never_asks
    if violated_never_does:
        analysis["violated_never_does"] = violated_never_does


def _enrich_with_btr_provenance(
    analysis: Dict[str, Any],
    claimed_brand: str,
    raw_text: str,
    resolved_urls: List[Dict[str, Any]],
) -> None:
    return _enrich_with_btr_provenance_impl(
analysis,
        claimed_brand,
        raw_text,
        resolved_urls,

    )


def _maybe_add_dns_reputation(summary: Dict[str, Any], resolved_urls: List[Dict[str, Any]]) -> None:
    """Pilon DNS reputation (gratis, fără cheie). Opt-in prin ENABLE_DNS_REPUTATION;
    implicit OFF → fără rețea/latență. `blocked` → provider hard (dns_security);
    `suspended`/`nxdomain` → semnal ponderat (infra_dns). Best-effort, nu aruncă."""
    if not ENABLE_DNS_REPUTATION or not resolved_urls:
        return
    domain = ""
    for entry in resolved_urls:
        if isinstance(entry, dict):
            domain = dns_reputation.domain_from_url(entry.get("final_url") or entry.get("url") or "")
            if domain:
                break
    if not domain:
        return
    try:
        rep = dns_reputation.check_dns_reputation(domain)
    except Exception:
        return
    hard = dns_reputation.dns_summary_entry(rep)
    if hard:
        summary["dns_security"] = hard
    weak = dns_reputation.dns_infra_entry(rep)
    if weak:
        summary["infra_dns"] = weak


def _apply_provider_gate_verdict(
    analysis: Dict[str, Any],
    resolved_urls: List[Dict[str, Any]],
    *,
    raw_text: str = "",
    pillars: Optional[Dict[str, Dict[str, Any]]] = None,
    scan_id: Optional[str] = None,
) -> Dict[str, Any]:
    evidence = analysis.setdefault("evidence", {})
    summary = evidence.get("external_intel_summary")
    if not isinstance(summary, dict):
        summary = {}
    claimed_brand = str(analysis.get("claimed_brand") or "Nespecificat")
    official_destination = _official_destination_confirmed(resolved_urls, claimed_brand)
    infra_flags = _collect_infrastructure_flags(
        analysis,
        resolved_urls,
        official_destination=official_destination,
    )
    _augment_summary_with_infra_flags(summary, infra_flags)
    _maybe_add_dns_reputation(summary, resolved_urls)
    evidence["external_intel_summary"] = summary

    source_channel = evidence.get("source_channel") if isinstance(evidence, dict) else None
    existing_cross_scan = evidence.get("cross_scan_knowledge") if isinstance(evidence.get("cross_scan_knowledge"), dict) else {}
    try:
        from services.cross_scan_knowledge import evaluate_cross_scan_knowledge

        computed_cross_scan = evaluate_cross_scan_knowledge(
            text=raw_text,
            claimed_brand=None if claimed_brand == "Nespecificat" else claimed_brand,
            source_channel=source_channel,
        )
    except Exception:
        computed_cross_scan = {}
    if existing_cross_scan:
        merged_cross_scan = dict(computed_cross_scan or {})
        merged_cross_scan.update(existing_cross_scan)
        computed_flags = list((computed_cross_scan or {}).get("fraud_flags") or [])
        for flag in existing_cross_scan.get("fraud_flags") or []:
            if flag not in computed_flags:
                computed_flags.append(flag)
        if computed_flags:
            merged_cross_scan["fraud_flags"] = computed_flags
        evidence["cross_scan_knowledge"] = merged_cross_scan
    else:
        evidence["cross_scan_knowledge"] = computed_cross_scan or {}
    has_urls = bool(resolved_urls)
    offer = evidence.get("offer_claim_verification")
    offer_status = str(offer.get("status", "")).lower() if isinstance(offer, dict) else ""
    web_risk_consulted = _source_ready(summary, "google_web_risk")
    asf_investor_alerts_consulted = _source_ready(summary, "asf_investor_alerts")
    phishing_database_consulted = _source_ready(summary, "phishing_database")
    phishtank_consulted = _source_ready(summary, "phishtank_online_valid")
    openphish_consulted = _source_ready(summary, "openphish")
    urlscan_consulted = any(_source_ready(summary, name) for name in ("urlscan", "urlscan.io"))
    sensitive_url_path = _has_sensitive_url_path(resolved_urls)
    brand_warning = _brand_warning_matches_text(claimed_brand, raw_text)
    official_safety_education = _looks_like_official_safety_education(raw_text)
    direct_sensitive_request = _has_direct_sensitive_request(raw_text)
    if official_safety_education:
        brand_warning = {"triggered": False, "matched_assets": []}
    evidence["brand_warning"] = brand_warning
    _attach_brand_warning_summary(summary, brand_warning)
    claim_required = _claim_verifier_required(analysis)
    claim_consulted = (not claim_required) or offer_status in {"confirmed", "not_found", "inconclusive", "skipped"}
    missing_required_pillars = []
    if has_urls and not web_risk_consulted:
        missing_required_pillars.append("Google Web Risk")
    if has_urls and not claim_consulted:
        missing_required_pillars.append("verificare oferta/claim")
    consulted_sources = [
        name
        for name in (
            "google_web_risk",
            "asf_investor_alerts",
            "phishing_database",
            "phishtank_online_valid",
            "openphish",
            "urlscan",
            "urlscan.io",
            "urlhaus",
            "infra_dns",
            "infra_domain_age",
            "infra_rdap",
            "infra_ssl",
            "infra_url_behaviour",
            "infra_url_transport",
            "sigurscan_lexical",
            "scam_blocklist_nrd",
            "phishdestroy_destroylist",
        )
        if _source_ready(summary, name)
    ]
    consulted_sources = sorted(set(consulted_sources))
    consulted_count = len(consulted_sources)

    provider_gate = {
        "version": "verdict_gate_v2",
        "official_destination": official_destination,
        "web_risk_consulted": web_risk_consulted,
        "asf_investor_alerts_consulted": asf_investor_alerts_consulted,
        "phishing_database_consulted": phishing_database_consulted,
        "phishtank_consulted": phishtank_consulted,
        "openphish_consulted": openphish_consulted,
        "urlscan_consulted": urlscan_consulted,
        "claim_required": claim_required,
        "claim_consulted": claim_consulted,
        "missing_required_pillars": missing_required_pillars,
        "consulted_sources": consulted_sources,
        "consulted_count": consulted_count,
        "offer_status": offer_status or "unknown",
        "infrastructure_flags": infra_flags,
        "brand_warning": brand_warning,
        "official_safety_education": official_safety_education,
        "direct_sensitive_request": direct_sensitive_request,
        "sensitive_url_path": sensitive_url_path,
    }

    _enrich_with_btr_provenance(analysis, claimed_brand, raw_text, resolved_urls)

    decision_bundle = _build_decision_evidence_bundle(
        analysis,
        resolved_urls,
        raw_text=raw_text,
        pillars=pillars,
        summary=summary,
        infra_flags=infra_flags,
        brand_warning=brand_warning,
        official_destination=official_destination,
        direct_sensitive_request=direct_sensitive_request,
        sensitive_url_path=sensitive_url_path,
    )
    gate_result = reduce_verdict(decision_bundle)
    # Observable-only: emit telemetry when the SE high-confidence branch decided,
    # so we can measure live classifier (dis)agreement. Never changes the verdict.
    if isinstance(gate_result, dict) and "social_engineering_high_confidence_intent" in (gate_result.get("reason_codes") or []):
        try:
            from services import telemetry as _telemetry
            _telemetry.log_se_high_confidence_fire(
                decision_bundle,
                gate_result,
                scan_id=(scan_id or str(analysis.get("scan_id") or analysis.get("id") or "") or None),
            )
        except Exception:
            pass
    return _apply_decision_contract_result(analysis, decision_bundle, gate_result, provider_gate)


def _project_provider_gate_verdict(
    analysis: Dict[str, Any],
    resolved_urls: List[Dict[str, Any]],
    *,
    raw_text: str = "",
    pillars: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Pure projection of the provider gate decision over a snapshot of evidence.

    The orchestrator can call this in tests or diagnostics without mutating the
    live scan job. It intentionally reuses the same gate implementation on deep
    copies so the projection cannot drift from the production path.
    """
    analysis_copy = _deep_copy_jsonable(analysis if isinstance(analysis, dict) else {})
    resolved_copy = _deep_copy_jsonable(resolved_urls if isinstance(resolved_urls, list) else [])
    pillars_copy = _deep_copy_jsonable(pillars) if isinstance(pillars, dict) else None
    projected = _apply_provider_gate_verdict(
        analysis_copy,
        resolved_copy,
        raw_text=raw_text,
        pillars=pillars_copy,
    )
    evidence = projected.get("evidence") if isinstance(projected.get("evidence"), dict) else {}
    return {
        "risk_level": projected.get("risk_level"),
        "risk_score": projected.get("risk_score"),
        "detected_family": projected.get("detected_family"),
        "detected_family_id": projected.get("detected_family_id"),
        "reasons": list(projected.get("reasons") or []),
        "safe_actions": list(projected.get("safe_actions") or []),
        "provider_gate": _deep_copy_jsonable(evidence.get("provider_gate") or {}),
        "external_intel_summary": _deep_copy_jsonable(evidence.get("external_intel_summary") or {}),
        "brand_warning": _deep_copy_jsonable(evidence.get("brand_warning") or {}),
    }


def _build_decision_evidence_bundle(
    analysis: Dict[str, Any],
    resolved_urls: List[Dict[str, Any]],
    *,
    raw_text: str,
    pillars: Optional[Dict[str, Dict[str, Any]]] = None,
    summary: Optional[Dict[str, Any]] = None,
    infra_flags: Optional[Dict[str, Any]] = None,
    brand_warning: Optional[Dict[str, Any]] = None,
    official_destination: bool = False,
    direct_sensitive_request: bool = False,
    sensitive_url_path: bool = False,
) -> Dict[str, Any]:
    summary = summary if isinstance(summary, dict) else {}
    infra_flags = infra_flags if isinstance(infra_flags, dict) else {}
    brand_warning = brand_warning if isinstance(brand_warning, dict) else {"triggered": False, "matched_assets": []}
    claimed_brand = str(analysis.get("claimed_brand") or "Nespecificat")
    has_urls = bool(resolved_urls)
    first_url = _first_final_url(resolved_urls) if has_urls else None
    provider_section = _provider_verdict_for_decision_bundle(
        summary,
        has_urls=has_urls,
        resolved_urls=resolved_urls,
        official_destination=official_destination,
        pillars=pillars,
    )
    identity_section = _identity_status_for_decision_bundle(
        analysis,
        resolved_urls,
        claimed_brand=claimed_brand,
        official_destination=official_destination,
        infra_flags=infra_flags,
        raw_text=raw_text,
    )
    request_sensitive = _request_sensitivity_from_signals(
        raw_text=raw_text,
        brand_warning=brand_warning,
        direct_sensitive_request=direct_sensitive_request,
        sensitive_url_path=sensitive_url_path,
        official_destination=official_destination,
        resolved_urls=resolved_urls,
    )
    source_channel = None
    evidence = analysis.get("evidence", {}) if isinstance(analysis.get("evidence"), dict) else {}
    if isinstance(evidence, dict):
        source_channel = evidence.get("source_channel")
    request_intent = _local_request_intent_analysis(raw_text)
    request_channel = _request_channel_for_decision_bundle(
        source_channel=source_channel,
        input_type=None,
        official_destination=official_destination,
        has_urls=has_urls,
    )
    semantic_review = _semantic_review_for_decision_bundle(
        analysis,
        raw_text=raw_text,
        official_destination=official_destination,
        provider_verdict=str(provider_section.get("verdict") or "unknown"),
    )
    request_intent = _normalize_model_intent_analysis(semantic_review.get("intent_analysis"), request_intent)
    if sensitive_url_path and not official_destination:
        request_intent = {
            **request_intent,
            "positive_action_request": True,
            "source": "local_request_intent_v1:sensitive_url_path",
        }
    local_social_engineering = _social_engineering_signal_for_decision_bundle(
        raw_text,
        request_sensitive=request_sensitive,
        source_channel=str(source_channel or ""),
        semantic_review=semantic_review,
    )
    social_engineering_proto = evidence.get("social_engineering") if isinstance(evidence.get("social_engineering"), dict) else {}
    social_engineering = _normalize_model_social_engineering_signal(
        social_engineering_proto,
        local_social_engineering,
    )
    provenance_proto = evidence.get("provenance") if isinstance(evidence.get("provenance"), dict) else {}
    cross_scan = evidence.get("cross_scan_knowledge") if isinstance(evidence.get("cross_scan_knowledge"), dict) else {}
    cross_never_asks = cross_scan.get("brand_never_asks") if isinstance(cross_scan.get("brand_never_asks"), dict) else {}
    cross_violated_never_asks = list(cross_never_asks.get("violated_never_asks") or [])
    fraud_flags = set(cross_scan.get("fraud_flags") or [])
    payment_destinations = cross_scan.get("payment_destinations") if isinstance(cross_scan.get("payment_destinations"), list) else []
    primary_payment_destination = next((item for item in payment_destinations if isinstance(item, dict)), None)
    if primary_payment_destination:
        provider_section["payment_destination"] = dict(primary_payment_destination)
    official_safety_education = _looks_like_official_safety_education(raw_text)
    if provenance_proto.get("violated_never_asks") and not official_safety_education:
        identity_section["violated_never_asks"] = provenance_proto["violated_never_asks"]
    if cross_violated_never_asks and not official_destination and not official_safety_education:
        merged = list(identity_section.get("violated_never_asks") or [])
        for item in cross_violated_never_asks:
            if item not in merged:
                merged.append(item)
        identity_section["violated_never_asks"] = merged
    if provenance_proto.get("violated_never_does"):
        identity_section["violated_never_does"] = provenance_proto["violated_never_does"]
    if "PAYMENT_DESTINATION_BRAND_MISMATCH" in fraud_flags:
        identity_section["status"] = "lookalike"
        identity_section["reason"] = "IBAN-ul aparține altei destinații oficiale decât brandul pretins."
    elif "UNKNOWN_PAYMENT_DESTINATION" in fraud_flags and identity_section.get("status") == "official":
        identity_section["status"] = "unknown"
        identity_section["reason"] = "IBAN-ul este valid, dar nu este confirmat pentru brandul pretins."
    provenance_section = {
        "official_domain_match": provenance_proto.get("official_domain_match", False),
        "manifest_id": provenance_proto.get("manifest_id"),
        "manifest_version": provenance_proto.get("manifest_version", brand_truth_registry.version),
        "provenance": provenance_proto.get("provenance", "unknown"),
        "evidence_power": provenance_proto.get("evidence_power", "none"),
    }
    resolution_status = "resolved" if first_url else ("failed" if has_urls else "not_required")
    community_data = evidence.get("community") if isinstance(evidence.get("community"), dict) else None
    non_http_deeplink = _non_http_deeplink_context(raw_text)
    bundle = {
        "schema": "sigurscan_evidence_bundle_v2",
        "input": {
            "type": str(source_channel or "unknown"),
            "redacted_text": str(raw_text or "")[:4000],
        },
        "resolution": {
            "final_url": first_url,
            "status": resolution_status,
            "completeness": not has_urls or bool(first_url),
        },
        "providers": provider_section,
        "identity": identity_section,
        "request": {
            "sensitive": request_sensitive,
            "channel": request_channel,
            "positive_action_request": request_intent.get("positive_action_request", False),
            "protective_warning": request_intent.get("protective_warning", False),
            "descriptive_context": request_intent.get("descriptive_context", False),
            "completeness": True,
        },
        "provenance": provenance_section,
        "context": {
            "urgency": bool(re.search(r"\b(urgent|azi|acum|24\s*de\s*ore|ultima|expir[ăa])\b", str(raw_text or ""), re.IGNORECASE)),
            "passive_payment": bool(re.search(r"\b(plata abonamentului|se va efectua automat plata|factur[ăa])\b", str(raw_text or ""), re.IGNORECASE)),
            "apk_or_remote_mention": bool(re.search(r"\b(apk|anydesk|teamviewer|remote access|control la distan[țt][ăa])\b", str(raw_text or ""), re.IGNORECASE)),
            "non_http_deeplink": non_http_deeplink,
            "cross_scan_knowledge": cross_scan,
            "intent_analysis": request_intent,
        },
        "semantic_review": semantic_review,
        "social_engineering": social_engineering,
    }
    if community_data:
        bundle["community"] = community_data
    canonical = json.dumps(bundle, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    bundle["evidence_hash"] = "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    # Observable-only side-channel for SE telemetry: carry the RAW pre-merge local
    # and Mistral sub-signals (lost by _normalize_model_social_engineering_signal)
    # so the call-site can log classifier (dis)agreement. Attached AFTER the
    # evidence_hash so it cannot change the hash, and never read by verdict_gate.
    bundle["_se_signals_raw"] = {
        "local": local_social_engineering,
        "model": social_engineering_proto,
        "source_channel": source_channel,
    }
    return bundle
def _apply_decision_contract_result(
    analysis: Dict[str, Any],
    decision_bundle: Dict[str, Any],
    gate_result: Dict[str, Any],
    provider_gate: Dict[str, Any],
) -> Dict[str, Any]:
    evidence = analysis.setdefault("evidence", {})
    provider_gate = dict(provider_gate)
    provider_gate.update(
        {
            "version": "verdict_gate_v2",
            "decision_contract": "sigurscan_evidence_bundle_v2",
            "risk_level": gate_result.get("risk_level"),
            "risk_score": gate_result.get("risk_score"),
            "reason": ", ".join(gate_result.get("reason_codes") or []),
            "label": gate_result.get("label"),
        }
    )
    evidence["provider_gate"] = provider_gate
    evidence["decision_bundle"] = decision_bundle
    evidence["verdict_gate"] = gate_result

    label = str(gate_result.get("label") or "UNVERIFIED").upper()
    family_id_by_reason = {
        "provider_malicious": "provider-gate-bad-provider",
        "provider_suspicious": "provider-gate-suspicious-provider",
        "identity_spoof": "provider-gate-decisive-structural-danger",
        "identity_spoof_value_request": "provider-gate-decisive-structural-danger",
        "sensitive_wrong_channel": "provider-gate-sensitive-wrong-channel",
        "semantic_high_value_request": "provider-gate-semantic-high-risk",
        "semantic_high_risk_match": "provider-gate-semantic-high-risk",
        "positive_provenance_clean": "provider-gate-official-clean",
        "clean_public_navigation_qr": "provider-gate-clean-public-navigation",
        "clean_public_navigation_url": "provider-gate-clean-public-navigation",
        "unknown_but_clean": "provider-gate-unofficial-inconclusive",
        "unknown_but_clean_established": "provider-gate-unofficial-inconclusive",
        "value_request_needs_verification": "provider-gate-value-request-review",
        "non_http_deeplink_unverified": "provider-gate-unofficial-inconclusive",
        "insufficient_evidence": "provider-gate-pending",
        "provider_error": "provider-gate-pending",
        "campaign_match_only": "provider-gate-campaign-match",
        "never_does_violated": "provider-gate-decisive-structural-danger",
        "never_asks_violated": "provider-gate-decisive-structural-danger",
        "young_domain_invalid_ssl_impersonation": "provider-gate-decisive-structural-danger",
        "residual": "provider-gate-residual",
    }
    reason_codes = list(gate_result.get("reason_codes") or [])
    primary_reason = reason_codes[0] if reason_codes else "residual"
    gate_family_id = family_id_by_reason.get(primary_reason, "provider-gate-residual")
    if primary_reason == "semantic_high_value_request" and provider_gate.get("sensitive_url_path"):
        gate_family_id = "provider-gate-decisive-structural-danger"
    if primary_reason in {"clean_public_navigation_qr", "clean_public_navigation_url"}:
        gate_family_name = "Navigare publică verificată"
    else:
        gate_family_name = {
            "SAFE": "Destinație verificată cu proveniență",
            "SUSPECT": "Verificare necesară",
            "DANGEROUS": "Risc confirmat",
            "UNVERIFIED": "Fără dovadă de proveniență",
        }.get(label, "Verificare necesară")
    provider_gate["detected_family_id"] = gate_family_id
    provider_gate["detected_family"] = gate_family_name

    semantic_review = decision_bundle.get("semantic_review") if isinstance(decision_bundle.get("semantic_review"), dict) else {}
    matched_family = str(semantic_review.get("matched_family") or "").strip()
    scam_family = evidence.get("scam_family") if isinstance(evidence.get("scam_family"), dict) else {}
    if matched_family and not (label == "SAFE" and primary_reason == "positive_provenance_clean"):
        family_id = matched_family
        family_name = str(scam_family.get("family") or matched_family).strip()
    else:
        family_id = gate_family_id
        family_name = gate_family_name

    if primary_reason in {"clean_public_navigation_qr", "clean_public_navigation_url"}:
        reasons = [
            "Domeniul este stabil, providerii de reputație sunt curați și nu există cereri sensibile."
        ]
    elif primary_reason == "non_http_deeplink_unverified":
        reasons = [
            "Linkul deschide o aplicație sau o destinație care nu poate fi previzualizată în browser; verifică în aplicația oficială înainte să continui."
        ]
    else:
        reasons = {
            "SAFE": ["Proveniența pozitivă confirmată, providerii curați, fără cereri sensibile."],
            "SUSPECT": ["Nu avem dovezi suficiente pentru a marca mesajul ca sigur; verifică pe canalul oficial înainte de acțiune."],
            "DANGEROUS": ["Dovezile indică risc ridicat: nu continua și nu introduce date."],
            "UNVERIFIED": ["Scanarea nu a găsit semnale de risc dar nici proveniență pozitivă."],
        }.get(label, ["Verifică pe canalul oficial înainte de acțiune."])

    analysis["risk_level"] = gate_result.get("risk_level")
    analysis["risk_score"] = gate_result.get("risk_score")
    analysis["detected_family"] = family_name
    analysis["detected_family_id"] = family_id
    analysis["reasons"] = reasons
    analysis["safe_actions"] = (
        ["Poți continua cu prudență doar dacă recunoști contextul și nu ți se cer date sensibile."]
        if label == "SAFE"
        else ["Verifică mesajul în aplicația/site-ul oficial, nu din linkul primit."]
        if label == "SUSPECT"
        else ["Nu apăsa linkul.", "Nu introduce date.", "Raportează/șterge mesajul."]
        if label == "DANGEROUS"
        else ["Fii atent: lipsa semnalelor de risc nu înseamnă că e sigur."]
    )
    return analysis
def _skipped_offer_claim_payload_impl(reason: str) -> Dict[str, Any]:
    return {
        "provider": "ai_offer_web_check",
        "status": "skipped",
        "verdict": "skipped",
        "severity": "unknown",
        "summary": reason,
        "details": reason,
        "confidence": 0,
        "evidence_urls": [],
        "method": "skipped",
    }


def _skipped_offer_claim_payload(reason: str) -> Dict[str, Any]:
    return _skipped_offer_claim_payload_impl(reason)
