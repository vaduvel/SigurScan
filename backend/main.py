import os
import importlib
import asyncio
import re
import ipaddress
import time
import json
import urllib.parse
from pathlib import Path
from collections import Counter, defaultdict, deque
import hashlib
import traceback  # noqa: used in _on_startup for debug
import requests
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Callable

try:
    from dotenv import load_dotenv

    load_dotenv(Path(__file__).resolve().parent / ".env")
except Exception:
    pass

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel
from bs4 import BeautifulSoup
import email
from email import policy, message_from_bytes
from email.message import Message
from email.utils import parseaddr
import logging
import html
from starlette.concurrency import run_in_threadpool
import tldextract

# Import our custom services
from services.pii_redactor import redact_pii
from services.redirect_resolver import (
    resolve_redirects_safely,
    is_known_shortener,
    _is_scan_target_blocked,
    get_spf_dns_record,
    get_dmarc_policy,
    check_dkim_dns_record,
)
from services.scam_atlas import BRAND_ID_TO_DISPLAY_NAME, BRAND_REGISTRY, BRAND_WARNING_RULES, ScamAtlasEngine
from services.gemini_explainer import generate_ai_explanation, generate_fallback_explanation
from services.evidence_bundle import build_evidence_bundle
from services.verdict_gate import verdict as reduce_verdict
from services.mistral_shadow_adjudicator import maybe_run_shadow_adjudication
from services.offer_claim_verifier import verify_offer_claim
from services.url_reputation import get_reputation_cache_stats, get_reputation_for_urls
from services.telemetry import (
    build_feedback_evaluation_rows,
    summarize_feedback_trend,
    load_feedback_records,
    load_scan_records,
    log_scan_event,
    log_feedback_event,
    find_scan_record_by_id,
    run_feedback_threshold_sweep,
    summarize_feedback_records,
)
from services import supabase_store
from services.google_vision_ocr import (
    has_vision_key,
    extract_text_with_vision,
    extract_text_from_pdf_with_vision,
)

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("main")

app = FastAPI(
    title="SigurScan API",
    description="Anti-scam detection engine localized for Romania (2025-2026)",
    version="1.0"
)

MAX_IMAGE_BYTES = 10 * 1024 * 1024
MAX_PDF_BYTES = 12 * 1024 * 1024
MAX_TEXT_CHARS = int(os.getenv("MAX_TEXT_CHARS", "12000"))
MAX_URLS_PER_SCAN = int(os.getenv("MAX_URLS_PER_SCAN", "15"))
RISK_THRESHOLD = int(os.getenv("RISK_THRESHOLD", "50"))
PRIVACY_SAFE_MODE = (
    os.getenv("SIGURSCAN_SAFE_MODE")
    or os.getenv("NUDACLICK_SAFE_MODE")
    or "false"
).strip().lower() in {"1", "true", "yes", "on"}
ALLOWED_IMAGE_MIME_TYPES = {"image/jpeg", "image/png", "image/webp"}
ALLOWED_IMAGE_EXTS = {".jpg", ".jpeg", ".png", ".webp"}
ALLOWED_PDF_EXTS = {".pdf"}
ALLOWED_MOCK_OCR = os.getenv("ALLOW_MOCK_OCR", "false").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
EMAIL_AUTH_STATUS_FAILS = {"fail", "softfail", "permerror"}
EMAIL_AUTH_STATUS_UNKNOWN = {"neutral", "none", "policy", "unknown", "temperror", "deferred", "error"}

# Plain-text URL extraction noise list:
# Some short Romanian tokens include a dot and can be wrongly matched as URLs by regex.
PLAIN_URL_NOISE_LABELS = {
    "dvs",
    "eu",
    "rog",
}

REQUIRE_API_KEY = os.getenv("REQUIRE_API_KEY", "false").strip().lower() in {"1", "true", "yes", "on"}
ALLOWED_API_KEYS = {
    key.strip()
    for key in (
        os.getenv("SIGURSCAN_API_KEYS")
        or os.getenv("NUDACLICK_API_KEYS")
        or ""
    ).split(",")
    if key.strip()
}

ENABLE_RATE_LIMIT = os.getenv("ENABLE_RATE_LIMIT", "true").strip().lower() in {"1", "true", "yes", "on"}
RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))
RATE_LIMIT_WINDOW_SECONDS = 60
URLSCAN_API_KEY = (
    os.getenv("SIGURSCAN_URLSCAN_API_KEY")
    or os.getenv("NUDACLICK_URLSCAN_API_KEY")
    or os.getenv("URLSCAN_API_KEY")
    or ""
).strip()
URLSCAN_TIMEOUT_SECONDS = float(os.getenv("URLSCAN_TIMEOUT_SECONDS", "8.0"))
URLSCAN_VISIBILITY_DEFAULT = os.getenv("URLSCAN_VISIBILITY_DEFAULT", "private").strip().lower() or "private"
URLSCAN_COUNTRY_DEFAULT = os.getenv("URLSCAN_COUNTRY_DEFAULT", "").strip().lower()
URLSCAN_CUSTOM_AGENT_DEFAULT = os.getenv("URLSCAN_CUSTOM_AGENT", "").strip()
ENABLE_CLOUD_AI_EXPLANATION = os.getenv("ENABLE_CLOUD_AI_EXPLANATION", "true").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
AI_EXPLANATION_TIMEOUT_SECONDS = float(os.getenv("AI_EXPLANATION_TIMEOUT_SECONDS", "2.5"))
AI_OFFER_CLAIM_TIMEOUT_SECONDS = float(os.getenv("AI_OFFER_CLAIM_TIMEOUT_SECONDS", "5.0"))
ENABLE_MISTRAL_SEMANTIC_PILLAR = os.getenv("ENABLE_MISTRAL_SEMANTIC_PILLAR", "true").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
MISTRAL_SEMANTIC_API_KEY = os.getenv("MISTRAL_API_KEY", "").strip()
MISTRAL_SEMANTIC_MODEL = (
    os.getenv("MISTRAL_SEMANTIC_MODEL")
    or os.getenv("MISTRAL_MODEL")
    or "mistral-small-2503"
).strip()
MISTRAL_SEMANTIC_TIMEOUT_SECONDS = float(os.getenv("MISTRAL_SEMANTIC_TIMEOUT_SECONDS", "3.0"))
FAST_REPUTATION_MODE = os.getenv("FAST_REPUTATION_MODE", "true").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
FAST_REPUTATION_INCLUDE_URLHAUS = os.getenv("FAST_REPUTATION_INCLUDE_URLHAUS", "false").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
ENABLE_VT_FALLBACK = os.getenv("ENABLE_VT_FALLBACK", "true").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
VT_FALLBACK_RISK_SCORE = int(os.getenv("VT_FALLBACK_RISK_SCORE", "50"))
VIRUSTOTAL_HARD_MALICIOUS_MIN_ENGINES = max(
    1,
    int(os.getenv("VIRUSTOTAL_HARD_MALICIOUS_MIN_ENGINES", "2")),
)

DEFAULT_ALLOWED_ORIGINS = (
    "https://sigurscan.ro,"
    "https://www.sigurscan.ro,"
    "https://sigurscan-backend.vercel.app,"
    "https://nudaclick-backend.vercel.app"
)
ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv("ALLOWED_ORIGINS", DEFAULT_ALLOWED_ORIGINS).split(",")
    if origin.strip()
]
if not ALLOWED_ORIGINS:
    ALLOWED_ORIGINS = DEFAULT_ALLOWED_ORIGINS.split(",")

_request_buckets: Dict[tuple, deque] = defaultdict(deque)


def _env_present(*names: str) -> bool:
    return any(os.getenv(name, "").strip() for name in names)


def _provider_config_status() -> Dict[str, Any]:
    """Expose provider readiness without leaking secrets."""

    web_risk_configured = _env_present("GOOGLE_WEB_RISK_API_KEY", "GOOGLE_API_KEY")
    virustotal_configured = _env_present("VIRUSTOTAL_API_KEY")
    mistral_configured = _env_present("MISTRAL_API_KEY")
    gemini_configured = _env_present("GEMINI_API_KEY")
    offer_claim_configured = gemini_configured
    return {
        "privacy_safe_mode": PRIVACY_SAFE_MODE,
        "rate_limit_enabled": ENABLE_RATE_LIMIT,
        "api_key_required": REQUIRE_API_KEY,
        "providers": {
            "urlscan": {
                "configured": bool(URLSCAN_API_KEY) and not PRIVACY_SAFE_MODE,
                "visibility": URLSCAN_VISIBILITY_DEFAULT,
            },
            "google_web_risk": {
                "configured": web_risk_configured and not PRIVACY_SAFE_MODE,
                "extended_threat_types_env": bool(os.getenv("GOOGLE_WEB_RISK_THREAT_TYPES", "").strip()),
            },
            "virustotal": {
                "configured": virustotal_configured and not PRIVACY_SAFE_MODE and ENABLE_VT_FALLBACK,
                "policy": "fallback_or_required_by_orchestrated_reputation",
            },
            "ai_explanation": {
                "configured": (mistral_configured or gemini_configured) and ENABLE_CLOUD_AI_EXPLANATION,
                "mistral_configured": mistral_configured,
                "gemini_configured": gemini_configured,
            },
            "offer_claim_verifier": {
                "configured": offer_claim_configured and not PRIVACY_SAFE_MODE,
                "timeout_seconds": AI_OFFER_CLAIM_TIMEOUT_SECONDS,
            },
        },
    }

TRACKING_QUERY_PARAMS = {
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "utm_id",
    "utm_referrer",
    "gclid",
    "fbclid",
    "mc_eid",
}
_BACKEND_DIR = Path(__file__).resolve().parent
EVAL_DATASET_DEFAULT_PATH = _BACKEND_DIR / "data" / "eval_dataset.jsonl"
if PRIVACY_SAFE_MODE:
    logger.warning("SIGURSCAN_SAFE_MODE activ: verificările externe pentru URL/reputație și Gemini sunt dezactivate.")

# Enable CORS for local testing from React Native/Expo web
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials="*" not in ALLOWED_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_guard(request: Request, call_next):
    if request.url.path in {"/", "/health", "/healthz", "/privacy", "/privacy-policy", "/docs", "/openapi.json", "/redoc"}:
        return await call_next(request)

    # Optional shared API key gate
    if REQUIRE_API_KEY:
        api_key = request.headers.get("X-API-KEY")
        if not api_key and request.headers.get("Authorization"):
            candidate = request.headers.get("Authorization", "").strip()
            if candidate.lower().startswith("bearer "):
                api_key = candidate.split(" ", 1)[1]

        if not api_key or (ALLOWED_API_KEYS and api_key not in ALLOWED_API_KEYS):
            return JSONResponse(status_code=401, content={"detail": "Missing or invalid API key."})

    # Basic per-client rate limit (best effort in single-instance mode)
    if ENABLE_RATE_LIMIT:
        client_key = (request.client.host if request.client else "anonymous", request.url.path)
        now = time.time()
        bucket = _request_buckets[client_key]
        while bucket and now - bucket[0] > RATE_LIMIT_WINDOW_SECONDS:
            bucket.popleft()

        if len(bucket) >= RATE_LIMIT_PER_MINUTE:
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many requests. Try again later."},
                headers={"Retry-After": str(RATE_LIMIT_WINDOW_SECONDS)},
            )

        bucket.append(now)

    return await call_next(request)

# Initialize engine
engine = ScamAtlasEngine()

# Regular expression to extract URLs from text
URL_REGEX = re.compile(
    r'(?:(?:https?://)|www\.|(?:[a-zA-Z0-9][a-zA-Z0-9+.-]*\.[a-zA-Z]{2,}))'
    r'[a-zA-Z0-9-._~:/?#\[\]@!$&\'()*+,;=%]*',
    re.IGNORECASE
)
_AUTH_RESULT_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)
_DKIM_SIGNATURE_DOMAIN_RE = re.compile(r"\bd=([^;\\s]+)", re.IGNORECASE)
_DKIM_SIGNATURE_SELECTOR_RE = re.compile(r"\bs=([^;\\s]+)", re.IGNORECASE)
_OBFUSCATED_DOT_RE = re.compile(r"\[\.\]|\(\.\)|\{\.\}")
_BUTTON_TYPES = {"button", "submit", "image"}
_INLINE_CLICK_URL_RE = re.compile(r"https?://[^\s\"'<>]+|//[^\s\"'<>]+")
_RE_LINK_TOKEN = re.compile(r"[\"']([^\"']+)[\"']")
_JS_QUOTED_VALUE_RE = re.compile(r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"|`(?:[^`\\]|\\.)*`")
_JS_VARIABLE_RE = re.compile(
    r"\b(?:var|let|const)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*("
    r"'(?:[^'\\]|\\.)*'|\"(?:[^\"]|\\.)*\"|`(?:[^`\\\\]|\\\\.)*`"
    r")"
)
_JS_NAV_ASSIGN_RE = re.compile(
    r"""
    (?:(?:window|top|self)\s*
      (?:\.\s*location|\[\s*['\"]location['\"]\s*\])
      |
      document\s*
      (?:\.\s*location|\[\s*['\"]location['\"]\s*\])
      |
      location
      |
      document\.location
    )
    (?:\s*(?:\.\s*href|\[\s*['\"]href['\"]\s*\]))?\s*
    =\s*([^;]+)
    """,
    re.IGNORECASE | re.VERBOSE,
)
_JS_NAV_ASSIGN_ALT_RE = re.compile(
    r"(?:window\.|top\.|self\.)?(?:location\.(?:assign|replace)|open)\s*\(\s*([^,\)]+)",
    re.IGNORECASE,
)
_JS_CLICK_LIKE_RE = re.compile(
    r"""
    \b(?:javascript:|window|document|top|self)\b
    |
    (?:^|\s)(?:var|let|const)\s+location\s*=
    |
    (?:^|\s)location\s*(?:=|\.|\[)
    |
    \b(?:open|assign|replace)\s*\(
    """,
    re.IGNORECASE | re.MULTILINE | re.VERBOSE,
)
_CLICKABLE_ROLES = {"button", "link"}
_GENERIC_CLICK_ATTRS = ("onclick", "data-href", "data-url", "data-action", "data-link", "data-target")


def _get_registrable_domain(extracted: "tldextract.ExtractResult") -> str:
    domain = getattr(extracted, "top_domain_under_public_suffix", "")
    if isinstance(domain, str) and domain.strip():
        return domain.strip().lower()
    return ""


def _is_relative_click_url(raw_url: str) -> bool:
    normalized = (raw_url or "").strip()
    return normalized.startswith(("/", "./", "../", "?"))


def _is_likely_js_url_token(token: str) -> bool:
    """
    Best-effort gate for string tokens extracted from JS snippets.
    """
    normalized = (token or "").strip().strip("`'\"")
    if not normalized:
        return False
    lowered = normalized.lower()
    if lowered.startswith(("http://", "https://", "//", "/", "./", "../", "?")):
        return True
    if any(char.isspace() for char in normalized):
        return False
    if "://" in lowered:
        return True
    return "." in normalized


def _normalize_click_target_url(raw_url: str, base_url: str | None = None) -> Optional[str]:
    """
    Normalize click targets without dropping relative URLs.

    If a relative target (like /verify) is found and no base is available, keep it
    as-is so it can still be treated as a risky unresolved destination.
    """
    normalized = (raw_url or "").strip().strip(" ;\")'`")
    if not normalized:
        return None

    if normalized.lower().startswith("javascript:"):
        normalized = normalized[len("javascript:") :].strip()

    if normalized.startswith("//"):
        normalized = f"https:{normalized}"

    if base_url and _is_relative_click_url(normalized):
        normalized = urllib.parse.urljoin(base_url, normalized)

    if _is_relative_click_url(normalized):
        return normalized

    return _canonicalize_url(normalized)


def _normalise_obfuscated_text(value: str) -> str:
    """
    Make phishing-style obfuscated URLs more detectable.

    Handles common tricks:
    - hxxp:// / hxxps://
    - example[.]com, example(.)com, example{.}com
    - "http ://" spaces around separators
    """
    if not value:
        return value

    normalized = re.sub(
        r"hxxp(s?)\s*://",
        lambda match: f"http{'s' if match.group(1) else ''}://",
        value,
        flags=re.IGNORECASE,
    )
    normalized = _OBFUSCATED_DOT_RE.sub(".", normalized)
    # Keep phishing-style "brand . ro" detectable, but do not join normal
    # sentence boundaries such as "nu pot vorbi. Am nevoie" into fake domains.
    normalized = re.sub(
        r"(?<=[A-Za-z0-9-])\s*\.\s*(?=(?:[a-z]{2,24}|[A-Z]{2,24})(?:\b|/))",
        ".",
        normalized,
    )
    normalized = re.sub(
        r"\b(https?)\s*:\s*/\s*/",
        lambda match: f"{match.group(1)}://",
        normalized,
        flags=re.IGNORECASE,
    )
    return normalized


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


def _is_noise_plain_url(raw_url: str, host: str) -> bool:
    normalized_raw = (raw_url or "").strip().lower()
    normalized_host = (host or "").lower()

    if not normalized_raw:
        return True

    # We only hard-filter plain domain-like tokens without protocol/www prefix.
    # This keeps protocol-based links and clear URI-like tokens intact.
    if normalized_raw.startswith(("http://", "https://", "www.")):
        return False

    first_label = normalized_host.split(".")[0]
    if first_label in PLAIN_URL_NOISE_LABELS:
        return True

    return False


def _extract_domain(raw_address: str | None) -> str | None:
    if not raw_address:
        return None
    parsed = parseaddr(raw_address)[1]
    if "@" not in parsed:
        return None
    return parsed.split("@", 1)[1].strip().lower()


def _extract_domain_root(raw_domain: str | None) -> str | None:
    """Return the registrable/root domain used for relaxed alignment checks."""
    if not raw_domain:
        return None

    normalized = str(raw_domain).strip().lower().strip(".")
    if not normalized:
        return None

    extracted = tldextract.extract(normalized)
    registrable_domain = _get_registrable_domain(extracted)
    if registrable_domain:
        return registrable_domain

    return normalized


def _coerce_int(raw_value: Any, default: int = 0) -> int:
    try:
        return int(raw_value)
    except Exception:
        return default


def _is_domain_aligned(
    left_domain: str | None,
    right_domain: str | None,
    alignment_mode: str | None = "r",
) -> bool | None:
    """
    Evaluate SPF/DKIM domain alignment.

    - strict: must match full domain exactly
    - relaxed: must match registrable domain (org-domain)
    """
    mode = (alignment_mode or "r").lower().strip()
    if mode not in {"r", "s", "strict", "relaxed"}:
        mode = "r"

    if not left_domain or not right_domain:
        return None

    left = str(left_domain).strip().lower().strip(".")
    right = str(right_domain).strip().lower().strip(".")
    if not left or not right:
        return None

    if left == right:
        return True

    if mode in {"s", "strict"}:
        return False

    return _extract_domain_root(left) == _extract_domain_root(right)


def _normalize_auth_status(raw_status: str) -> str:
    status = (raw_status or "").lower().strip()
    if status in {"pass", "bestguesspass"}:
        return "pass"
    if status in EMAIL_AUTH_STATUS_FAILS:
        return "fail"
    if status in EMAIL_AUTH_STATUS_UNKNOWN:
        return "unknown"
    return "unknown"


def _parse_auth_statuses(header_value: str, auth_results: Dict[str, str]) -> None:
    for match in _AUTH_RESULT_RE.finditer(header_value or ""):
        mechanism = match.group(1).lower()
        normalized = _normalize_auth_status(match.group(2))
        current = auth_results.get(mechanism, "missing")
        # Prefer explicit fail signals over pass
        if normalized == "fail":
            auth_results[mechanism] = "fail"
        elif normalized == "pass" and current != "fail":
            auth_results[mechanism] = "pass"
        elif mechanism not in auth_results:
            auth_results[mechanism] = normalized


def _parse_dkim_signature_fields(signature: str) -> Dict[str, str]:
    parsed: Dict[str, str] = {}
    if not signature:
        return parsed

    domain_match = _DKIM_SIGNATURE_DOMAIN_RE.search(signature)
    selector_match = _DKIM_SIGNATURE_SELECTOR_RE.search(signature)
    if domain_match:
        parsed["domain"] = domain_match.group(1).strip().lower()
    if selector_match:
        parsed["selector"] = selector_match.group(1).strip().lower()
    return parsed


def _normalize_dns_text(value: str | None) -> str | None:
    if not value:
        return None
    normalized = value.strip().lower()
    return normalized or None


def _extract_spf_all_mechanism(spf_record: str | None) -> str | None:
    if not spf_record:
        return None
    normalized = spf_record.lower()
    # SPF all mechanism appears usually at end: +all / -all / ~all / ?all
    match = re.search(r"([+\-~?])all", normalized)
    if match:
        return match.group(1)
    if " all" in normalized and normalized.split()[-1].endswith("all"):
        return "all"
    return None


def _dmarc_policy_action_label(dmarc_policy: Dict[str, Any] | None) -> str:
    if not isinstance(dmarc_policy, dict):
        return "none"
    return _normalize_dns_text(dmarc_policy.get("p")) or "none"


def _build_auth_action_plan(email_ctx: Dict[str, Any]) -> Dict[str, Any]:
    dns_checks = email_ctx.get("dns_checks", {}) or {}
    if not isinstance(dns_checks, dict):
        dns_checks = {}

    dmarc_policy = dns_checks.get("dmarc_policy")
    dmarc_action = _dmarc_policy_action_label(dmarc_policy)
    spf_record = dns_checks.get("spf_record") or ""
    spf_all = _extract_spf_all_mechanism(spf_record)

    auth_status = email_ctx.get("auth_status", {})
    if not isinstance(auth_status, dict):
        auth_status = {}

    dns_spf_present = bool(dns_checks.get("spf_record"))
    dns_dkim_present = bool(dns_checks.get("dkim_dns"))
    dns_dmarc_present = bool(dns_checks.get("dmarc_policy"))
    dmarc_pct = _coerce_int(dmarc_policy.get("pct", 100), 100) if isinstance(dmarc_policy, dict) else 100

    dkim_signature_domain = dns_checks.get("dkim_signature_domain")
    return_path_domain = dns_checks.get("return_path_domain")
    spf_alignment_mode = str(dns_checks.get("spf_alignment_mode", "r")).lower() or "r"
    dkim_alignment_mode = str(dns_checks.get("dkim_alignment_mode", "r")).lower() or "r"
    spf_aligned = dns_checks.get("spf_aligned")
    dkim_aligned = dns_checks.get("dkim_aligned")
    if not isinstance(spf_aligned, bool) and dns_checks.get("from_domain") and return_path_domain:
        spf_aligned = _is_domain_aligned(
            dns_checks.get("from_domain"),
            return_path_domain,
            spf_alignment_mode,
        )
    if not isinstance(dkim_aligned, bool) and dns_checks.get("from_domain") and dkim_signature_domain:
        dkim_aligned = _is_domain_aligned(
            dns_checks.get("from_domain"),
            dkim_signature_domain,
            dkim_alignment_mode,
        )

    spf_aligned = bool(spf_aligned) if isinstance(spf_aligned, bool) else None
    dkim_aligned = bool(dkim_aligned) if isinstance(dkim_aligned, bool) else None

    fails = {k: v for k, v in auth_status.items() if v == "fail"}
    has_any_fail = bool(fails)
    has_partial_or_missing = any(v in {"missing", "unknown"} for v in auth_status.values())

    action = "monitor"
    severity = "low"
    score = 0
    reasons = []

    if has_any_fail:
        action = "reject"
        severity = "high"
        score += 42
        reasons.append("Autentificare SPF/DKIM/DMARC incompletă sau invalidă — risc de spoofing.")
        reasons.extend([
            f"{mechanism.upper()}={status}"
            for mechanism, status in sorted(fails.items())
        ])

    # If strict DMARC is enabled but SPF/DKIM/DKIM not fully aligned, we escalate.
    if dmarc_action == "reject":
        if has_any_fail:
            # Already rejected above; keep strong action and add explicit DMARC reason.
            reasons.append("DMARC='reject' combinat cu autentificare eșuată: blocare recomandată.")
        elif has_partial_or_missing:
            action = "reject"
            severity = "high"
            score += 32
            reasons.append("DMARC='reject' fără dovezi complete de autentificare: tratează mesajul ca potențial spoof.")
        elif action == "monitor":
            action = "monitor"
            reasons.append("DMARC='reject' detectat și mesajul pare aliniat; păstrezi monitorizare activă.")

    elif dmarc_action == "quarantine":
        if has_any_fail or has_partial_or_missing:
            action = "quarantine"
            severity = "medium" if severity != "high" else severity
            score += 20
            reasons.append("DMARC='quarantine' + autentificare incompletă: mesaj nesigur.")

    # If headers indicate pass but DNS checks are missing, keep this as medium-risk.
    if not dns_spf_present:
        score += 6
        reasons.append("SPF DNS indisponibil: nu putem confirma politicile expeditorului.")

    # DMARC alignment hints: even when SPF/DKIM pass, misalignment is a strong spoof signal.
    if auth_status.get("spf") == "pass" and spf_aligned is False:
        score += 10
        reasons.append("SPF pass fără aliniere DMARC (SPF/From diferite).")
    if email_ctx.get("has_dkim_signature") and auth_status.get("dkim") == "pass" and dkim_aligned is False:
        score += 10
        reasons.append("DKIM pass fără aliniere DMARC (semnătură din alt domeniu).")
    if not dns_dkim_present and email_ctx.get("has_dkim_signature"):
        score += 6
        reasons.append("Semnătură DKIM prezentă fără înregistrare DNS validă.")
    if not dns_dmarc_present:
        score += 6
        reasons.append("DMARC DNS lipsă: nu există politică de aliniere verificabilă.")

    if dmarc_action == "reject" and not has_any_fail and (spf_aligned is False or dkim_aligned is False):
        action = "reject"
        severity = "high"
        score += 18
        reasons.append("DMARC='reject' + mecanisme non-aliniate: risc ridicat de phishing.")

    # Strict SPF (-all) lowers residual risk when all checks passed.
    if spf_all == "-" and "fail" not in (auth_status.get("spf"),):
        score -= 4
        reasons.append("SPF strict (-all) detectat: cadru de autentificare mai rigid.")

    if not has_any_fail and not has_partial_or_missing and action == "monitor":
        action = "monitor"
        severity = "low"
        score = max(score, 0)

    # Strong sender policy with partial/missing headers is still suspicious even when DMARC is absent.
    if not dmarc_action and has_partial_or_missing:
        severity = "medium" if severity == "low" else severity
        score += 10
        reasons.append("DMARC absent + autentificare incompletă: risc moderat pentru e-mail nevalidat.")

    return {
        "dmarc_policy": dmarc_action,
        "spf_all": spf_all,
        "spf_dns_present": dns_spf_present,
        "dkim_dns_present": dns_dkim_present,
        "dmarc_dns_present": dns_dmarc_present,
        "dmarc_pct": dmarc_pct,
        "action": action,
        "severity": severity,
        "risk_score_delta": max(score, 0),
        "policy_context": {
            "adkim": str(dmarc_policy.get("adkim")) if isinstance(dmarc_policy, dict) else None,
            "aspf": str(dmarc_policy.get("aspf")) if isinstance(dmarc_policy, dict) else None,
            "provider": email_ctx.get("from_domain"),
            "pct": dmarc_pct,
            "spf_alignment_mode": spf_alignment_mode,
            "dkim_alignment_mode": dkim_alignment_mode,
            "spf_aligned": spf_aligned,
            "dkim_aligned": dkim_aligned,
        },
        "reasons": _dedupe_preserve_order(reasons),
    }


def _extract_email_auth_context(msg: Message | None, is_forwarded_guess: bool = True) -> Dict[str, Any]:
    """
    Build authentication evidence from raw RFC822 headers.
    If msg is None, returns a "missing" profile, to avoid false confidence.
    """
    if msg is None:
        email_ctx = {
            "auth_strength": "unavailable" if is_forwarded_guess else "missing",
            "sender_auth_confidence": "low",
            "auth_fail_reasons": [],
            "has_dkim_signature": False,
            "auth_status": {"spf": "missing", "dkim": "missing", "dmarc": "missing"},
            "dkim_signature_fields": {},
            "from_domain": None,
            "reply_to_domain": None,
            "alignment": {
                "from_domain": None,
                "return_path_domain": None,
                "dkim_signature_domain": None,
                "spf_alignment_mode": "r",
                "dkim_alignment_mode": "r",
                "spf_aligned": None,
                "dkim_aligned": None,
            },
            "dns_checks": {
                "spf_record": None,
                "dmarc_policy": None,
                "dkim_dns": None,
                "dkim_signature": {},
                "spf_dns_present": False,
                "dkim_dns_present": False,
                "dmarc_dns_present": False,
            },
            "is_forwarded_guess": is_forwarded_guess,
            "headers_present": False,
        }
        email_ctx["auth_action_plan"] = {
            "dmarc_policy": "none",
            "spf_all": None,
            "action": "monitor",
            "severity": "low",
            "risk_score_delta": 0,
            "spf_dns_present": False,
            "dkim_dns_present": False,
            "dmarc_dns_present": False,
            "policy_context": {
                "provider": None,
                "pct": None,
                "adkim": None,
                "aspf": None,
                "spf_alignment_mode": "r",
                "dkim_alignment_mode": "r",
                "spf_aligned": None,
                "dkim_aligned": None,
            },
            "reasons": [
                "Antetele originale SPF/DKIM/DMARC nu au fost disponibile în conținutul partajat."
            ],
        }
        return email_ctx

    auth_results = {"spf": "missing", "dkim": "missing", "dmarc": "missing"}
    auth_fail_reasons = []

    from_domain = _extract_domain(msg.get("From"))
    reply_to_domain = _extract_domain(msg.get("Reply-To"))

    auth_headers = msg.get_all("Authentication-Results", [])
    for auth_header in auth_headers:
        _parse_auth_statuses(auth_header, auth_results)

    received_spf = msg.get_all("Received-SPF") or []
    for header in received_spf:
        _parse_auth_statuses(f"spf={header}", auth_results)

    dkim_signature = msg.get("DKIM-Signature") or ""
    dkim_signature_fields = _parse_dkim_signature_fields(dkim_signature)
    dkim_selector = dkim_signature_fields.get("selector", "default")
    dkim_signature_domain = dkim_signature_fields.get("domain")
    has_dkim_signature = bool(dkim_signature)
    if has_dkim_signature and auth_results.get("dkim", "missing") == "missing":
        auth_results["dkim"] = "unknown"

    # DNS-level checks (SPF/DMARC/DKIM) increase confidence versus false positives.
    # In privacy-safe mode, skip DNS lookups to avoid external lookups for message analysis.
    aspf_mode = "r"
    adkim_mode = "r"
    spf_record = None
    dmarc_policy: Dict[str, Any] = {}
    dns_dkim_record = None

    if PRIVACY_SAFE_MODE:
        auth_fail_reasons.append(
            "SIGURSCAN_SAFE_MODE: verificările DNS SPF/DMARC/DKIM sunt dezactivate pentru confidențialitate."
        )
        for mechanism in ("spf", "dkim", "dmarc"):
            if auth_results.get(mechanism) == "pass":
                auth_results[mechanism] = "unknown"
    else:
        spf_record = get_spf_dns_record(from_domain or "")
        dmarc_policy = get_dmarc_policy(from_domain or "")
        if has_dkim_signature and dkim_signature_domain and dkim_selector:
            dns_dkim_record = check_dkim_dns_record(dkim_selector, dkim_signature_domain)
        aspf_mode = str(dmarc_policy.get("aspf", "r") if isinstance(dmarc_policy, dict) else "r").lower().strip() or "r"
        adkim_mode = str(dmarc_policy.get("adkim", "r") if isinstance(dmarc_policy, dict) else "r").lower().strip() or "r"

    if reply_to_domain and from_domain and reply_to_domain != from_domain:
        auth_fail_reasons.append(
            f"Domain diferit în Reply-To ({reply_to_domain}) față de From ({from_domain})"
        )
        if auth_results.get("dmarc", "missing") == "pass":
            auth_results["dmarc"] = "unknown"

    return_path_domain = _extract_domain(msg.get("Return-Path"))
    spf_aligned = _is_domain_aligned(from_domain, return_path_domain, aspf_mode)
    dkim_aligned = None
    if dkim_signature_domain:
        dkim_aligned = _is_domain_aligned(from_domain, dkim_signature_domain, adkim_mode)

    if from_domain and not spf_record:
        auth_fail_reasons.append(
            "SPF DNS nu a răspuns cu o politică validă pentru domeniul From."
        )
        if auth_results.get("spf", "missing") == "pass":
            auth_results["spf"] = "unknown"

    if from_domain and not dmarc_policy:
        auth_fail_reasons.append(
            "DMARC nu este publicat sau nu a putut fi verificat pentru domeniul From."
        )
        if auth_results.get("dmarc", "missing") == "pass":
            auth_results["dmarc"] = "unknown"

    if has_dkim_signature and dkim_signature_domain and not dns_dkim_record:
        auth_fail_reasons.append(
            f"Cheie DKIM DNS lipsă la {dkim_signature_domain} (selector {dkim_selector})."
        )
        if auth_results.get("dkim", "missing") == "pass":
            auth_results["dkim"] = "unknown"

    for mechanism, status in auth_results.items():
        if status == "fail":
            auth_fail_reasons.append(
                f"{mechanism.upper()} nu validează: {status}"
            )

    failed_count = sum(1 for status in auth_results.values() if status == "fail")
    passed_count = sum(1 for status in auth_results.values() if status == "pass")

    if failed_count > 0:
        auth_strength = "fail"
        sender_confidence = "low"
    elif (
        from_domain
        and spf_record
        and dmarc_policy
        and has_dkim_signature
        and dns_dkim_record
        and all(auth_results.get(key) == "pass" for key in ("spf", "dkim", "dmarc"))
    ):
        auth_strength = "pass"
        sender_confidence = "high"
    elif passed_count >= 2 and not failed_count:
        auth_strength = "pass"
        sender_confidence = "high"
    elif passed_count > 0:
        auth_strength = "partial"
        sender_confidence = "medium"
    elif "unknown" in auth_results.values():
        auth_strength = "partial"
        sender_confidence = "medium"
    else:
        auth_strength = "missing"
        sender_confidence = "low"

    email_ctx = {
        "auth_strength": auth_strength,
        "sender_auth_confidence": sender_confidence,
        "auth_fail_reasons": auth_fail_reasons,
        "has_dkim_signature": has_dkim_signature,
        "dkim_signature_fields": dkim_signature_fields,
        "auth_status": auth_results,
        "dns_checks": {
            "spf_record": spf_record,
            "spf_dns_present": bool(spf_record),
            "dmarc_policy": dmarc_policy,
            "dmarc_dns_present": bool(dmarc_policy),
            "dkim_dns": dns_dkim_record,
            "dkim_signature": dkim_signature_fields,
            "dkim_dns_present": bool(dns_dkim_record),
            "from_domain": from_domain,
            "return_path_domain": return_path_domain,
            "spf_record_present": bool(spf_record),
            "dkim_selector": dkim_selector,
            "dkim_signature_domain": dkim_signature_domain,
            "spf_record_source": "dns" if not PRIVACY_SAFE_MODE else "privacy_safe_disabled",
            "dmarc_policy_source": "dns" if not PRIVACY_SAFE_MODE else "privacy_safe_disabled",
            "dkim_dns_source": "dns" if not PRIVACY_SAFE_MODE else "privacy_safe_disabled",
            "dns_checks_disabled": bool(PRIVACY_SAFE_MODE),
            "reply_to_mismatch": bool(
                reply_to_domain and from_domain and reply_to_domain != from_domain
            ),
            "policy_checks": {
                "dkim_signature_present": bool(dkim_signature),
                "spf_all": _extract_spf_all_mechanism(spf_record),
                "spf_alignment_mode": aspf_mode,
                "dkim_alignment_mode": adkim_mode,
            },
            "spf_alignment_mode": aspf_mode,
            "dkim_alignment_mode": adkim_mode,
            "spf_aligned": spf_aligned,
            "dkim_aligned": dkim_aligned,
        },
        "from_domain": from_domain,
        "reply_to_domain": reply_to_domain,
        "alignment": {
            "from_domain": from_domain,
            "return_path_domain": return_path_domain,
            "dkim_signature_domain": dkim_signature_domain,
            "spf_alignment_mode": aspf_mode,
            "dkim_alignment_mode": adkim_mode,
            "spf_aligned": spf_aligned,
            "dkim_aligned": dkim_aligned,
        },
        "is_forwarded_guess": is_forwarded_guess,
        "headers_present": True,
    }
    email_ctx["auth_action_plan"] = _build_auth_action_plan(email_ctx)
    return email_ctx


def _is_allowed_origin(url: str) -> bool:
    parsed = urllib.parse.urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if scheme not in {"http", "https"}:
        return False
    if not parsed.hostname:
        return False
    return True


def _canonicalize_url(raw_url: str) -> Optional[str]:
    if not raw_url:
        return None

    # Remove trailing punctuation introduced by copy/paste or markdown
    cleaned = raw_url.strip().strip(") ]}>;,:.!?")
    if cleaned.startswith("//"):
        cleaned = f"https:{cleaned}"
    if not cleaned:
        return None

    # Handle bare domains or urls copied without scheme
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", cleaned):
        cleaned = f"https://{cleaned}"

    parsed = urllib.parse.urlparse(cleaned)
    if not _is_allowed_origin(cleaned):
        return None

    # Keep only security-relevant query params and strip noisy marketing ones
    query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    filtered_query = [
        (key, value)
        for key, value in query_pairs
        if (key or "").lower() not in TRACKING_QUERY_PARAMS
    ]

    normalized_path = parsed.path or ""
    if not normalized_path:
        normalized_path = "/"
    normalized = parsed._replace(
        query=urllib.parse.urlencode(filtered_query, doseq=True),
        fragment="",
        path=normalized_path.rstrip("/") or "/",
    )
    return urllib.parse.urlunparse(normalized)


def extract_urls(text: str) -> List[str]:
    """Helper to extract and sanitize HTTP/HTTPS links from text."""
    normalized_text = _normalise_obfuscated_text(text or "")
    # Some SMS clients/copy flows collapse whitespace after punctuation, producing
    # strings like "0371237475.https://brand.ro/path". Split before URL schemes so
    # the phone/previous sentence is not swallowed as part of the URL candidate.
    normalized_text = re.sub(r"(?<!\s)(https?://|www\.)", r" \1", normalized_text, flags=re.IGNORECASE)
    raw_urls = URL_REGEX.findall(normalized_text)
    urls: List[str] = []
    seen = set()

    for raw_url in raw_urls:
        url = _canonicalize_url(raw_url)
        if not url or not _is_allowed_origin(url):
            continue
        parsed = urllib.parse.urlparse(url)
        host = (parsed.hostname or "").lower()
        if not host or _is_noise_plain_url(raw_url, host):
            continue
        try:
            ipaddress.ip_address(host)
        except Exception:
            tld_suffix = tldextract.extract(host).suffix
            has_explicit_scheme = bool(re.match(r"^https?://", str(raw_url).strip(), re.IGNORECASE))
            if not tld_suffix and not has_explicit_scheme:
                logger.debug("Skipping extracted token without valid public suffix: %s", host)
                continue
        if url not in seen:
            seen.add(url)
            urls.append(url)
        if len(urls) >= MAX_URLS_PER_SCAN:
            break
    return urls


def _extract_button_text(node: Any) -> str:
    """
    Extract an actionable label for a clickable node, using the most likely
    human-visible text.
    """
    if node is None:
        return ""
    if getattr(node, "name", "").lower() == "input":
        return (
            (node.get("value") or "").strip()
            or (node.get("alt") or "").strip()
            or (node.get("aria-label") or "").strip()
            or (node.get("title") or "").strip()
        )

    text = (node.get("aria-label") or node.get("title") or "").strip()
    if text:
        return text
    return (node.get_text(separator=" ", strip=True) or "").strip()


def _decode_js_string_literal(raw: str) -> str:
    """
    Decode a quoted JS string literal into a raw string.
    """
    if not raw:
        return ""
    quote = raw[0]
    if quote not in {"'", '"', "`"} or len(raw) < 2:
        return ""
    body = raw[1:-1]
    if quote == "`":
        body = re.sub(r"\$\{[^}]*\}", "", body)
    try:
        return bytes(body, "utf-8").decode("unicode_escape")
    except Exception:
        return body


def _split_js_plus_expression(expression: str) -> List[str]:
    """
    Best-effort split for JS concatenations around +, respecting quoted strings.
    """
    parts: List[str] = []
    current = []
    in_quote: str | None = None
    escape = False
    for ch in expression:
        if escape:
            current.append(ch)
            escape = False
            continue
        if ch == "\\" and in_quote:
            current.append(ch)
            escape = True
            continue
        if in_quote:
            current.append(ch)
            if ch == in_quote:
                in_quote = None
            continue
        if ch in {"'", '"', "`"}:
            in_quote = ch
            current.append(ch)
            continue
        if ch == "+":
            segment = "".join(current).strip()
            if segment:
                parts.append(segment)
            current = []
            continue
        current.append(ch)

    segment = "".join(current).strip()
    if segment:
        parts.append(segment)
    return parts


def _resolve_js_concat_expression(expression: str, var_values: Dict[str, str]) -> List[str]:
    """
    Resolve simple JS concat expressions into concrete URL strings.
    """
    if not expression:
        return []
    normalized_expression = expression.strip().strip("()")
    parts = _split_js_plus_expression(normalized_expression)
    if not parts:
        return []

    resolved_parts: List[str] = []
    has_unresolved = False
    for part in parts:
        token = part.strip().strip("()")
        if not token:
            continue
        if token[0] in {"'", '"', "`"} and token[-1] == token[0]:
            resolved_parts.append(_decode_js_string_literal(token))
            continue
        if token in var_values:
            resolved_parts.append(var_values[token])
            continue
        # Ignore bare `window.location` or placeholder values we cannot evaluate
        if token.lower().replace(" ", "") in {
            "window.location",
            "location",
            "document.location",
            "window.location.href",
            "location.href",
            "self.location",
            "top.location",
        }:
            continue
        has_unresolved = True

    if has_unresolved:
        return []
    if not resolved_parts:
        return []
    return ["".join(resolved_parts)]


def _extract_urls_from_js_code(raw_js: str, base_url: str | None = None) -> List[str]:
    """
    Extract URLs from JS snippets used in event handlers.
    """
    normalized = _normalise_obfuscated_text(html.unescape(raw_js or ""))
    if not normalized:
        return []

    normalized = normalized.strip()
    if normalized.lower().startswith("javascript:"):
        normalized = normalized[len("javascript:") :].strip()

    if normalized.startswith("(") and normalized.endswith(")"):
        normalized = normalized[1:-1].strip()

    variable_values: Dict[str, str] = {}
    for match in _JS_VARIABLE_RE.finditer(normalized):
        var_name = match.group(1)
        raw_value = match.group(2)
        if not raw_value:
            continue
        variable_values[var_name] = _decode_js_string_literal(raw_value)

    expressions: List[str] = []
    for match in _JS_NAV_ASSIGN_RE.finditer(normalized):
        lhs = normalized[match.start():match.end()].split("=")[0].strip()
        if re.search(r"\b(?:var|let|const)\s+location\b", lhs, re.IGNORECASE):
            continue
        expressions.append(match.group(1).strip())
    expressions.extend(match.group(1).strip() for match in _JS_NAV_ASSIGN_ALT_RE.finditer(normalized))

    url_candidates: List[str] = []
    if not expressions:
        # Fall back to quoted URLs inside function args or inline snippets.
        for token in _RE_LINK_TOKEN.findall(normalized):
            if not _is_likely_js_url_token(token):
                continue
            url_candidates.append(token)

    for expr in expressions:
        expr = expr.strip().strip(" ;")
        if not expr:
            continue
        resolved = _resolve_js_concat_expression(expr, variable_values)
        for resolved_expr in resolved:
            candidate = _normalize_click_target_url(resolved_expr, base_url=base_url)
            if candidate:
                url_candidates.append(candidate)

    seen_urls: set[str] = set()
    urls: List[str] = []
    for raw_url in url_candidates:
        url = _normalize_click_target_url(raw_url, base_url=base_url)
        if not url or url in seen_urls:
            continue
        seen_urls.add(url)
        urls.append(url)
    return urls


def _extract_urls_from_click_attr(raw_value: str, base_url: str | None = None) -> List[str]:
    normalized = _normalise_obfuscated_text(html.unescape(raw_value or ""))
    if _is_relative_click_url(normalized):
        resolved = _normalize_click_target_url(normalized, base_url=base_url)
        if resolved:
            return [resolved]

    if normalized.lower().startswith("javascript:"):
        normalized = normalized[len("javascript:") :].strip()

    direct_urls = _extract_urls_from_js_code(raw_value, base_url=base_url)
    is_inline_like = _JS_CLICK_LIKE_RE.search(normalized) is None
    if not direct_urls and is_inline_like:
        direct_urls = _INLINE_CLICK_URL_RE.findall(normalized)
    if base_url and is_inline_like:
        if normalized.startswith(("/", "./", "../", "?")):
            direct_urls.append(urllib.parse.urljoin(base_url, normalized))

    if base_url and is_inline_like:
        for token in _RE_LINK_TOKEN.findall(normalized):
            token = token.strip()
            if not token:
                continue
            token = _normalise_obfuscated_text(token)
            if token.lower().startswith(("http://", "https://")):
                direct_urls.append(token)
            elif token.startswith(("/", "./", "../", "?")):
                direct_urls.append(urllib.parse.urljoin(base_url, token))

    if direct_urls:
        urls: List[str] = []
        seen = set()
        for raw_url in direct_urls:
            url = _normalize_click_target_url(raw_url, base_url=base_url)
            if not url or url in seen:
                continue
            seen.add(url)
            urls.append(url)
        return urls
    return extract_urls(normalized)


def _collect_click_targets_from_html(soup: BeautifulSoup) -> list[Dict[str, Any]]:
    """
    Extract actionable links hidden in HTML call-to-action elements, not only `<a href>`.
    """
    targets: list[Dict[str, Any]] = []
    base_url = None
    base_tag = soup.find("base", href=True)
    if base_tag:
        base_url = _canonicalize_url(base_tag.get("href") or "")
        if base_url:
            parsed_base = urllib.parse.urlparse(base_url)
            if not parsed_base.scheme or not parsed_base.netloc:
                base_url = None
    seen_urls = set()

    def append_target(button_text: str, raw_url: str, source_tag: str, source_attr: str) -> None:
        for url in _extract_urls_from_click_attr(raw_url, base_url=base_url):
            if url in seen_urls:
                continue
            seen_urls.add(url)
            targets.append(
                {
                    "button_text": button_text,
                    "original_url": url,
                    "source_tag": source_tag,
                    "source_attr": source_attr,
                }
            )

    # Standard links
    for link in soup.find_all("a"):
        button_text = _extract_button_text(link) or "[Buton/Imagine fără text]"
        href = link.get("href")
        if href:
            append_target(button_text, href, "a", "href")
        for attr in ("data-href", "data-url", "data-action", "data-link", "data-target", "onclick"):
            value = link.get(attr)
            if value:
                append_target(button_text, value, "a", attr)

    # <button> and CTA-like input controls
    for btn in soup.find_all("button"):
        button_text = _extract_button_text(btn) or "[Buton/Imagine fără text]"
        if btn.get("formaction"):
            append_target(button_text, btn.get("formaction"), "button", "formaction")
        if btn.get("onclick"):
            append_target(button_text, btn.get("onclick"), "button", "onclick")
        for attr in ("data-href", "data-url", "data-action", "data-link", "data-target"):
            value = btn.get(attr)
            if value:
                append_target(button_text, value, "button", attr)

    for inp in soup.find_all("input"):
        input_type = (inp.get("type") or "").lower().strip()
        if input_type and input_type not in _BUTTON_TYPES:
            continue
        button_text = _extract_button_text(inp) or "[Buton/Imagine fără text]"
        if inp.get("formaction"):
            append_target(button_text, inp.get("formaction"), "input", "formaction")
        if inp.get("onclick"):
            append_target(button_text, inp.get("onclick"), "input", "onclick")
        for attr in ("data-href", "data-url", "data-action", "data-link", "data-target"):
            value = inp.get(attr)
            if value:
                append_target(button_text, value, "input", attr)

    # Clickable image maps and other semantic areas
    for area in soup.find_all("area"):
        button_text = _extract_button_text(area) or "[Buton/Imagine fără text]"
        if area.get("href"):
            append_target(button_text, area.get("href"), "area", "href")
        if area.get("onclick"):
            append_target(button_text, area.get("onclick"), "area", "onclick")

    # Generic click-capable elements commonly used in branded phishing templates
    for tag in soup.find_all(True):
        tag_name = tag.name.lower()
        if tag_name in {"a", "button", "input", "area", "form"}:
            continue

        role = (tag.get("role") or "").lower().strip()
        has_interaction_attr = tag.has_attr("onclick") or any(tag.get(attr) for attr in _GENERIC_CLICK_ATTRS)
        if role not in _CLICKABLE_ROLES and not has_interaction_attr:
            continue

        button_text = _extract_button_text(tag) or "[Buton/Imagine fără text]"
        if tag.get("href"):
            append_target(button_text, tag.get("href"), tag_name, "href")
        if tag.get("onclick"):
            append_target(button_text, tag.get("onclick"), tag_name, "onclick")
        for attr in _GENERIC_CLICK_ATTRS:
            value = tag.get(attr)
            if value:
                append_target(button_text, value, tag_name, attr)

    # Fallback for form actions when no direct button action was found
    for form in soup.find_all("form"):
        if not form.get("action"):
            continue
        submit_like = form.find_all(["button", "input"], recursive=True)
        button_text = "[Buton/Imagine fără text]"
        for node in submit_like:
            node_type = (node.get("type") or "").lower()
            if not node_type or node_type in _BUTTON_TYPES or node.name == "button":
                extracted = _extract_button_text(node)
                if extracted:
                    button_text = extracted
                    break
        append_target(button_text, form.get("action"), "form", "action")

    return targets


_APP_SCHEME_BRAND_HINTS = {
    "uber": "Uber",
    "ubereats": "Uber",
    "revolut": "Revolut",
    "whatsapp": "WhatsApp",
}


def _decode_repeated_url_value(value: str, max_rounds: int = 3) -> str:
    current = value or ""
    for _ in range(max_rounds):
        decoded = urllib.parse.unquote(html.unescape(current))
        if decoded == current:
            break
        current = decoded
    return current


def _brand_from_official_url(candidate: str) -> Optional[str]:
    parsed = urllib.parse.urlparse(candidate if "://" in candidate else f"https://{candidate}")
    host = (parsed.hostname or "").lower().removeprefix("www.")
    if not host:
        return None
    for brand, domains in BRAND_REGISTRY.items():
        for domain in domains:
            normalized_domain = domain.lower().removeprefix("www.")
            if host == normalized_domain or host.endswith(f".{normalized_domain}"):
                return brand
    return None


def _infer_brand_hints_from_url(url: str) -> List[str]:
    """
    Extracts brand context from app deep-links and official fallback URLs.

    This is not a whitelist: the inferred brand is used so downstream mismatch
    checks can compare the target against official/partner domains. A malicious
    domain with `fallback=https://brand.com` still becomes a brand-mismatch case.
    """
    hints: List[str] = []
    parsed = urllib.parse.urlparse(url)
    query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)

    def add_hint(value: Optional[str]) -> None:
        if value and value not in hints:
            hints.append(value)

    for key, raw_value in query_pairs:
        key_norm = key.lower().strip()
        value = _decode_repeated_url_value(raw_value)
        scheme = urllib.parse.urlparse(value).scheme.lower()

        if key_norm in {"_dl", "deep_link", "deeplink", "app_link", "applink"}:
            add_hint(_APP_SCHEME_BRAND_HINTS.get(scheme))

        if key_norm in {
            "_fallback_redirect",
            "fallback_redirect",
            "fallback",
            "redirect",
            "redirect_url",
            "url",
            "u",
            "target",
            "destination",
        }:
            add_hint(_brand_from_official_url(value))

    return hints


def _infer_brand_hints_from_click_targets(click_targets: List[Dict[str, Any]]) -> List[str]:
    hints: List[str] = []
    for target in click_targets:
        raw_url = str(target.get("original_url") or "")
        for hint in _infer_brand_hints_from_url(raw_url):
            if hint not in hints:
                hints.append(hint)
    return hints


def _safe_scan_url_list(urls: List[str]) -> List[Dict[str, Any]]:
    resolved_urls: List[Dict[str, Any]] = []
    if PRIVACY_SAFE_MODE:
        for url in urls:
            resolved_urls.append(_safe_mode_url_entry(url))
        return resolved_urls
    for url in urls:
        try:
            resolved_urls.append(resolve_redirects_safely(url))
        except Exception as exc:
            logger.warning(f"Redirect resolution failed for {url}: {exc}")
            resolved_urls.append({
                "original_url": url,
                "final_url": url,
                "final_hostname": urllib.parse.urlparse(url).hostname,
                "final_registered_domain": urllib.parse.urlparse(url).hostname,
                "domain_age_days": None,
                "domain_created_date": None,
                "has_mx_records": None,
                "redirect_chain": [],
                "redirect_count": 0,
                "shortener_count": 0,
                "uses_shortener": False,
                "detected_soft_redirects": [],
                "success": False,
                "error_message": str(exc),
            })
    return resolved_urls


def _resolve_eval_dataset_path(dataset_path: Optional[str]) -> Path:
    if not dataset_path:
        candidate = EVAL_DATASET_DEFAULT_PATH
    else:
        cleaned = str(dataset_path).strip()
        if not cleaned:
            candidate = EVAL_DATASET_DEFAULT_PATH
        else:
            candidate = Path(cleaned)
            if not candidate.is_absolute():
                candidate = (_BACKEND_DIR / candidate)

    resolved = candidate.expanduser().resolve()
    if not resolved.exists() or not resolved.is_file():
        raise HTTPException(
            status_code=404,
            detail=(
                f"Dataset file not found: {resolved}"
                if os.path.isabs(str(resolved))
                else "Dataset file not found"
            ),
        )
    return resolved


def _feedback_sample_payload(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "scan_id": row.get("scan_id"),
        "feedback": row.get("feedback"),
        "actual_is_scam": row.get("actual_is_scam"),
        "predicted_is_scam": row.get("predicted_is_scam"),
        "predicted_risk_score": row.get("predicted_risk_score"),
        "risk_score": row.get("risk_score"),
        "risk_level": row.get("risk_level"),
        "signal_ids": row.get("signal_ids", []),
        "timestamp": row.get("timestamp"),
        "scan_context": row.get("scan_context", {}),
        "detected_family_id": row.get("detected_family_id"),
        "detected_family": row.get("detected_family"),
        "claimed_brand": row.get("claimed_brand"),
        "input_type": row.get("input_type"),
        "url_count": row.get("url_count", 0),
        "error_category": row.get("error_category"),
        "source_channel": row.get("source_channel"),
    }


def _gather_external_intel(
    resolved_urls: List[Dict[str, Any]],
    *,
    include_virustotal: bool = True,
    include_urlhaus: bool = True,
    persist_partial: bool = False,
) -> Dict[str, Dict[str, Any]]:
    if PRIVACY_SAFE_MODE:
        return {}
    final_urls = [
        entry.get("final_url")
        for entry in resolved_urls
        if isinstance(entry.get("final_url"), str) and entry.get("final_url")
    ]
    return get_reputation_for_urls(
        final_urls,
        include_virustotal=include_virustotal,
        include_urlhaus=include_urlhaus,
        persist_partial=persist_partial,
    )


def _gather_external_intel_safe(
    resolved_urls: List[Dict[str, Any]],
    *,
    include_virustotal: bool,
    include_urlhaus: bool,
    persist_partial: bool = False,
) -> Dict[str, Dict[str, Any]]:
    try:
        return _gather_external_intel(
            resolved_urls,
            include_virustotal=include_virustotal,
            include_urlhaus=include_urlhaus,
            persist_partial=persist_partial,
        )
    except TypeError:
        # Compatibility for tests that monkeypatch the helper with the older
        # single-argument signature.
        return _gather_external_intel(resolved_urls)  # type: ignore[call-arg]


def _analysis_needs_vt_fallback(analysis: Dict[str, Any]) -> bool:
    if PRIVACY_SAFE_MODE or not ENABLE_VT_FALLBACK:
        return False
    if not os.getenv("VIRUSTOTAL_API_KEY", "").strip():
        return False

    evidence = analysis.get("evidence", {}) if isinstance(analysis.get("evidence"), dict) else {}
    if evidence.get("has_domain_mismatch") or evidence.get("url_behaviour") or evidence.get("url_transport"):
        return True

    family_text = " ".join(
        str(value).lower()
        for value in (analysis.get("detected_family_id"), analysis.get("detected_family"))
        if value
    )
    sensitive_markers = (
        "card",
        "cvv",
        "cvc",
        "otp",
        "parol",
        "login",
        "plată",
        "plata",
        "cnp",
        "iban",
        "apk",
        "remote",
        "domeniu",
        "neoficial",
        "mismatch",
    )
    return any(marker in family_text for marker in sensitive_markers)


def _analyze_with_reputation(
    redacted_text: str,
    resolved_urls: List[Dict[str, Any]],
    *,
    email_context: Optional[Dict[str, Any]] = None,
    fast_reputation: bool = True,
    threat_intel_override: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    use_fast = bool(fast_reputation)
    threat_intel = threat_intel_override
    if threat_intel is None:
        threat_intel = _gather_external_intel_safe(
            resolved_urls,
            include_virustotal=True,
            include_urlhaus=(not use_fast) or FAST_REPUTATION_INCLUDE_URLHAUS,
            persist_partial=False,
        )
    analyze_kwargs: Dict[str, Any] = {
        "urls": resolved_urls,
        "external_threat_intel": threat_intel,
    }
    if email_context is not None:
        analyze_kwargs["email_context"] = email_context
    analysis = engine.analyze(redacted_text, **analyze_kwargs)

    if use_fast and _analysis_needs_vt_fallback(analysis):
        deep_threat_intel = _gather_external_intel_safe(
            resolved_urls,
            include_virustotal=True,
            include_urlhaus=True,
            persist_partial=True,
        )
        if deep_threat_intel:
            analyze_kwargs["external_threat_intel"] = deep_threat_intel
            analysis = engine.analyze(redacted_text, **analyze_kwargs)
            analysis.setdefault("evidence", {})["vt_fallback"] = True
    else:
        analysis.setdefault("evidence", {})["vt_fallback"] = False

    analysis.setdefault("evidence", {})["fast_reputation_mode"] = use_fast
    return analysis


def _external_intel_summary_from_threat_intel(threat_intel: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    summary: Dict[str, Dict[str, Any]] = {}

    def severity_rank(status: str) -> int:
        normalized = status.strip().lower()
        if normalized in {"malicious", "phishing", "malware"}:
            return 4
        if normalized == "suspicious":
            return 3
        if normalized in {"clean", "no_match", "no-match"}:
            return 2
        if normalized in {"error", "unknown"}:
            return 1
        return 0

    for threat in threat_intel.values():
        if not isinstance(threat, dict):
            continue
        sources = threat.get("sources")
        if not isinstance(sources, dict):
            continue
        for source_name, source_data in sources.items():
            if not isinstance(source_data, dict):
                continue
            status = str(source_data.get("status") or "unknown").strip().lower()
            existing = summary.get(source_name)
            existing_status = str(existing.get("status") or "unknown") if isinstance(existing, dict) else "unknown"
            if not isinstance(existing, dict) or severity_rank(status) >= severity_rank(existing_status):
                malicious_hit_count = (
                    _virustotal_malicious_hit_count(source_data)
                    if source_name == "virustotal"
                    else 1
                    if status in {"malicious", "phishing", "malware"}
                    else 0
                )
                summary[source_name] = {
                    "source": source_name,
                    "status": status,
                    "verdict": str(source_data.get("verdict") or status),
                    "consulted": bool(source_data.get("consulted", False)),
                    "risk_score": int(source_data.get("score") or source_data.get("risk_score") or 0),
                    "threat_type": str(source_data.get("threat_type") or "unknown"),
                    "details": source_data.get("details") if isinstance(source_data.get("details"), dict) else {},
                    "url_count": 1,
                    "malicious_hit_count": malicious_hit_count,
                }
            elif existing is not None:
                existing["url_count"] = int(existing.get("url_count") or 0) + 1
                if source_name == "virustotal":
                    existing["malicious_hit_count"] = int(existing.get("malicious_hit_count") or 0) + _virustotal_malicious_hit_count(source_data)
                elif status in {"malicious", "phishing", "malware"}:
                    existing["malicious_hit_count"] = int(existing.get("malicious_hit_count") or 0) + 1
    return summary


def _provider_reputation_context_analysis(
    redacted_text: str,
    resolved_urls: List[Dict[str, Any]],
    summary: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    """Create analysis context for a hard provider hit.

    This is intentionally not a verdict. The final label is still emitted only
    by services.verdict_gate.verdict() after this summary is normalized into the
    Evidence Bundle v2.
    """

    return {
        "risk_score": 0,
        "risk_level": "unknown",
        "detected_family": "Context reputatie provider",
        "detected_family_id": "provider-context-reputation-hit",
        "claimed_brand": "Nespecificat",
        "reasons": [
            "Providerii de reputatie au raportat semnale pe destinatie; verdictul final este calculat de verdict_gate.",
        ],
        "safe_actions": [],
        "key_dangers": [
            "Providerii de reputatie au marcat destinatia ca risc.",
        ],
        "evidence": {
            "external_intel_summary": summary,
            "provider_reputation_context": True,
            "has_domain_mismatch": False,
            "extracted_urls": resolved_urls,
        },
    }


def _source_status(summary: Dict[str, Any], source_name: str) -> str:
    raw = summary.get(source_name)
    if not isinstance(raw, dict):
        return "missing"
    return str(raw.get("verdict") or raw.get("status") or "unknown").strip().lower()


def _source_consulted(summary: Dict[str, Any], source_name: str) -> bool:
    raw = summary.get(source_name)
    return bool(isinstance(raw, dict) and raw.get("consulted", False))


def _source_ready(summary: Dict[str, Any], source_name: str) -> bool:
    status = _source_status(summary, source_name)
    return _source_consulted(summary, source_name) and status not in {"missing", "unknown", "error"}


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


def _virustotal_malicious_hit_count(raw: Dict[str, Any]) -> int:
    candidates: List[int] = []
    for key in ("malicious_hit_count", "malicious"):
        try:
            candidates.append(int(raw.get(key) or 0))
        except Exception:
            pass
    details = raw.get("details") if isinstance(raw.get("details"), dict) else {}
    stats = details.get("stats") if isinstance(details.get("stats"), dict) else {}
    try:
        candidates.append(int(stats.get("malicious") or 0))
    except Exception:
        pass
    if not isinstance(raw.get("details"), dict):
        details_text = str(raw.get("details") or "")
        match = re.search(r"\b(\d{1,3})\s+(?:engines?|vendors?)\s+malicious\b", details_text, re.IGNORECASE)
        if match:
            try:
                candidates.append(int(match.group(1)))
            except Exception:
                pass
    direct_stats = raw.get("stats") if isinstance(raw.get("stats"), dict) else {}
    try:
        candidates.append(int(direct_stats.get("malicious") or 0))
    except Exception:
        pass
    return max(candidates or [0])


def _has_authoritative_bad_provider_verdict(summary: Dict[str, Any]) -> bool:
    for name in ("google_web_risk", "urlscan", "urlscan.io", "urlhaus", "google_safe_browsing"):
        raw = summary.get(name)
        if isinstance(raw, dict) and _provider_payload_is_hard_bad(raw):
            return True
    return False


def _has_bad_provider_verdict(summary: Dict[str, Any]) -> bool:
    if _has_authoritative_bad_provider_verdict(summary):
        return True
    raw_vt = summary.get("virustotal")
    if isinstance(raw_vt, dict):
        malicious_hits = _virustotal_malicious_hit_count(raw_vt)
        if malicious_hits >= VIRUSTOTAL_HARD_MALICIOUS_MIN_ENGINES:
            return True
        # VirusTotal is an aggregator. A single/flaky engine or a plain
        # suspicious label remains diagnostic context, not a hard block.
        return False

    provider_names = ("google_web_risk", "urlscan", "urlscan.io", "urlhaus", "google_safe_browsing")
    for name in provider_names:
        raw = summary.get(name)
        if isinstance(raw, dict) and _provider_payload_is_hard_bad(raw):
            return True
    return False


def _official_destination_confirmed(resolved_urls: List[Dict[str, Any]], claimed_brand: str) -> bool:
    for entry in resolved_urls:
        reg_domain = str(entry.get("final_registered_domain") or entry.get("registered_domain") or "").lower()
        hostname = str(entry.get("final_hostname") or entry.get("hostname") or "").lower()
        if not hostname and (entry.get("final_url") or entry.get("url")):
            hostname = urllib.parse.urlparse(str(entry.get("final_url") or entry.get("url") or "")).hostname or ""
        if engine._is_context_allowed_domain(reg_domain, hostname=hostname, claimed_brand=claimed_brand):
            return True
        original_hostname = str(entry.get("hostname") or "").lower()
        original_reg_domain = str(entry.get("registered_domain") or "").lower()
        if not original_hostname and entry.get("url"):
            original_hostname = urllib.parse.urlparse(str(entry.get("url") or "")).hostname or ""
        original_is_brand_delegated = engine._is_context_allowed_domain(
            original_reg_domain,
            hostname=original_hostname,
            claimed_brand=claimed_brand,
        )
        final_url = str(entry.get("final_url") or "")
        final_hostname = str(entry.get("final_hostname") or hostname or "").lower()
        normalized_brand = _normalize_claimed_brand(claimed_brand)
        if (
            original_is_brand_delegated
            and "yoxo" in normalized_brand
            and final_hostname in {"apps.apple.com", "play.google.com"}
            and "yoxo" in urllib.parse.unquote(final_url).lower()
        ):
            return True
    return False


def _normalize_claimed_brand(raw_brand: str) -> str:
    normalized = str(raw_brand or "").strip().lower()
    if not normalized or normalized in {"nespecificat", "unknown", "none"}:
        return ""
    return normalized


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
        "remote_access": lambda: any(token in combined for token in ("anydesk", "teamviewer", "rustdesk", "control la distanta", "control la distanță", "remote access")),
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


def _looks_like_official_safety_education(raw_text: str) -> bool:
    normalized = _normalise_obfuscated_text(raw_text or "").lower()
    if not normalized:
        return False
    sensitive_terms = r"(?:cnp|pin|cvv|cvc|otp|cod(?:ul|uri?)?(?:\s+sms)?|parol[ăa]|date\s+de\s+card|date\s+bancare)"
    negative_claim = (
        r"(?:nu\s+(?:iti|îți|va|vă|iti\s+)?\s*(?:cerem|solicit[aă]m|trimitem|pretindem)"
        r"|nu\s+(?:ti|ți|vi|vă)?\s*se\s+solicit[aă]"
        r"|nu\s+introduc\w*"
        r"|nu\s+(?:(?:il|îl|le)\s+)?comunic\w*"
        r"|nu\s+(?:(?:il|îl|le)\s+)?trimite\w*"
        r"|nu\s+(?:cerem|solicit[aă]m)"
        r"|niciodat[aă]\s+nu\s+(?:cerem|solicit[aă]m))"
    )
    window = r"(?:\W+\w+){0,12}\W+"
    return bool(
        re.search(negative_claim + window + sensitive_terms, normalized, re.IGNORECASE)
        or re.search(sensitive_terms + window + negative_claim, normalized, re.IGNORECASE)
    )


def _has_direct_sensitive_request(raw_text: str) -> bool:
    normalized = _normalise_obfuscated_text(raw_text or "").lower()
    if not normalized or _looks_like_official_safety_education(normalized):
        return False
    verbs = r"(?:introdu\w*|completeaz\w*|trimite\w*|spune\w*|comunic\w*|confirm\w*|valideaz\w*|verific\w*)"
    sensitive = (
        r"(?:parol[ăa]|password|otp|cod(?:ul)?(?:\s+sms|\s+de\s+verificare|\s+de\s+confirmare)?|"
        r"pin(?:-ul|ul)?|cvv|cvc|date(?:le)?\s+(?:de\s+)?card(?:ului)?|"
        r"num[aă]r(?:ul)?\s+(?:de\s+)?card(?:ului)?|"
        r"ultimele\s+\d+\s+cifre\s+(?:ale\s+)?card(?:ului)?|"
        r"cnp|iban|copie\s+act|act(?:ul)?\s+(?:de\s+)?identitate)"
    )
    return bool(
        re.search(verbs + r"(?:\W+\w+){0,8}\W+" + sensitive, normalized, re.IGNORECASE)
        or re.search(sensitive + r"(?:\W+\w+){0,8}\W+" + verbs, normalized, re.IGNORECASE)
    )


def _has_decisive_sensitive_intent(text: str) -> bool:
    normalized = _normalise_obfuscated_text(text or "").lower()
    money_or_delivery_markers = (
        "taxa",
        "taxă",
        "vamala",
        "vamală",
        "neachit",
        "plata",
        "plată",
        "plateste",
        "plătește",
        "platiti",
        "plătiți",
        "plati",
        "plăti",
        "achita",
        "achită",
        "card",
        "cvv",
        "cvc",
        "iban",
        "otp",
        "parola",
        "parolă",
        "pin",
        "login",
        "autent",
        "cnp",
        "reprogram",
        "relivrare",
        "livrare",
        "colet",
        "awb",
    )
    return any(marker in normalized for marker in money_or_delivery_markers)


def _has_sensitive_url_path(resolved_urls: List[Dict[str, Any]]) -> bool:
    sensitive_path_tokens = (
        "card",
        "cvv",
        "cvc",
        "otp",
        "cod",
        "login",
        "auth",
        "parola",
        "password",
        "date",
        "formular",
        "form",
        "pay",
        "plata",
        "plată",
        "identitate",
        "confirmare",
        "validare",
    )
    for entry in resolved_urls or []:
        url = str(entry.get("final_url") or entry.get("url") or "")
        parsed = urllib.parse.urlparse(url)
        path = urllib.parse.unquote(parsed.path or "").lower()
        if any(token in path for token in sensitive_path_tokens):
            return True
    return False


def _collect_infrastructure_flags(
    analysis: Dict[str, Any],
    resolved_urls: List[Dict[str, Any]],
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
    return {
        "typosquat": "typosquatting" in lexical_text or "lookalike" in lexical_text or "mismatch critic" in lexical_text,
        "homoglyph": "homoglif" in lexical_text or "homoglyph" in lexical_text,
        "punycode": "punycode" in lexical_text or "idn/punycode" in lexical_text,
        "dga_entropy": "entropie ridicat" in lexical_text or "entropie mare" in lexical_text or "entropy" in lexical_text or "dga" in lexical_text,
        "very_new_domain": youngest_domain_age_days is not None and youngest_domain_age_days < 7,
        "suspicious_domain_age": youngest_domain_age_days is not None and youngest_domain_age_days < 30,
        "url_behaviour": bool(url_behaviour),
        "url_transport": bool(url_transport),
        "youngest_domain_age_days": youngest_domain_age_days,
    }


def _augment_summary_with_infra_flags(summary: Dict[str, Any], infra_flags: Dict[str, Any]) -> None:
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


def _provider_verdict_for_decision_bundle(
    summary: Dict[str, Any],
    *,
    has_urls: bool,
    pillars: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    if _has_bad_provider_verdict(summary):
        return {"verdict": "malicious", "hits": ["provider_malicious"], "completeness": True}

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
    for name in ("google_web_risk", "virustotal", "urlscan", "urlscan.io", "urlhaus", "ai_offer_web_check"):
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


def _identity_status_for_decision_bundle(
    analysis: Dict[str, Any],
    resolved_urls: List[Dict[str, Any]],
    *,
    claimed_brand: str,
    official_destination: bool,
    infra_flags: Dict[str, Any],
) -> Dict[str, Any]:
    evidence = analysis.get("evidence", {}) if isinstance(analysis.get("evidence"), dict) else {}
    if official_destination:
        raw_registered = ""
        final_registered = ""
        if resolved_urls:
            raw_registered = str(resolved_urls[0].get("registered_domain") or "").lower()
            final_registered = str(resolved_urls[0].get("final_registered_domain") or "").lower()
        return {
            "claimed_brand": claimed_brand if _normalize_claimed_brand(claimed_brand) else None,
            "status": "delegated" if raw_registered and final_registered and raw_registered != final_registered else "official",
            "tld_suspicious": False,
            "completeness": True,
        }

    normalized_claim = _normalize_claimed_brand(claimed_brand)
    has_resolved_destination = bool(_first_final_url(resolved_urls))
    if normalized_claim and has_resolved_destination:
        return {
            "claimed_brand": claimed_brand,
            "status": "lookalike" if infra_flags.get("typosquat") or infra_flags.get("homoglyph") or infra_flags.get("punycode") else "unrelated",
            "tld_suspicious": bool(
                infra_flags.get("typosquat")
                or infra_flags.get("homoglyph")
                or infra_flags.get("punycode")
                or infra_flags.get("very_new_domain")
            ),
            "completeness": True,
        }

    return {
        "claimed_brand": claimed_brand if _normalize_claimed_brand(claimed_brand) else None,
        "status": "unknown",
        "tld_suspicious": bool(
            infra_flags.get("typosquat")
            or infra_flags.get("homoglyph")
            or infra_flags.get("punycode")
            or infra_flags.get("very_new_domain")
        ),
        "completeness": True,
    }


def _request_sensitivity_from_signals(
    *,
    raw_text: str,
    brand_warning: Dict[str, Any],
    direct_sensitive_request: bool,
    sensitive_url_path: bool,
    official_destination: bool,
    resolved_urls: List[Dict[str, Any]],
) -> str:
    normalized = _normalise_obfuscated_text(raw_text or "").lower()
    matched_assets = set(brand_warning.get("matched_assets") or []) if isinstance(brand_warning, dict) else set()

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

    if re.search(r"\b(anydesk|teamviewer|rustdesk|apk|control la distan[țt][ăa]|remote access)\b", normalized):
        return "remote"
    if re.search(r"\b(crypto|bitcoin|usdt|binance|wallet|seed phrase)\b", normalized):
        return "crypto"
    if re.search(r"\b(parol[ăa]|password)\b", normalized) and direct_sensitive_request:
        return "password"
    if re.search(r"\b(otp|cod sms|cod whatsapp|codul de verificare|2fa)\b", normalized) and direct_sensitive_request:
        return "otp"
    if re.search(r"\b(cvv|cvc|date(?:le)? de card|num[aă]r(?:ul)? de card)\b", normalized) and direct_sensitive_request:
        return "card"

    if sensitive_url_path and not official_destination:
        for entry in resolved_urls or []:
            url = str(entry.get("final_url") or entry.get("url") or "")
            path = urllib.parse.unquote(urllib.parse.urlparse(url).path or "").lower()
            if any(token in path for token in ("card", "cvv", "cvc", "pay", "plata", "plată")):
                return "card"
            if any(token in path for token in ("otp", "login", "auth", "password", "parola")):
                return "password"

    money_request_pattern = (
        r"(?:bani|lei|euro|cash|numerar|sum[ăa]|garan[țt]ie|opera[țt]ie|cau[țt]iune|cautiune)"
    )
    money_action_pattern = (
        r"(?:transfer[aă]?|trimite[țt]i?|trimite|trimit|achit[aă]?|pl[ăa]te[șs]te|plati[țt]i?|depune|depun[eă]|virament|iban)"
    )
    if (
        re.search(r"\b(cont sigur|transfer[aă] fondurile|transfer[aă] bani|iban)\b", normalized)
        or re.search(rf"\b{money_action_pattern}\b.{{0,80}}\b{money_request_pattern}\b", normalized)
        or re.search(rf"\b{money_request_pattern}\b.{{0,80}}\b{money_action_pattern}\b", normalized)
    ):
        return "transfer"

    return "none"


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


def _semantic_review_for_decision_bundle(
    analysis: Dict[str, Any],
    *,
    official_destination: bool,
    provider_verdict: str,
) -> Dict[str, Any]:
    evidence = analysis.get("evidence", {}) if isinstance(analysis.get("evidence"), dict) else {}
    existing = evidence.get("semantic_review")
    if isinstance(existing, dict) and existing.get("status"):
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

    if known and confidence >= 0.20 and supports_high_text_only:
        risk_class = "high"
    elif known and confidence >= 0.20:
        risk_class = "medium"
    else:
        risk_class = "unknown"
    matched = risk_class in {"high", "medium"}
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


MISTRAL_SEMANTIC_SYSTEM_PROMPT = """
Ești pilonul semantic SigurScan pentru mesaje în limba română.
Nu ai voie să dai verdict final și nu ai voie să folosești etichete SIGUR/SUSPECT/PERICULOS.
Primești text redactat, domenii finale și context atlas/corpus. Întorci doar semantic_review structurat.
Reguli:
- Marchează high doar când claim-ul seamănă clar cu o familie scam sau cere acțiuni sensibile/social-engineering.
- Marchează benign doar când claim-ul seamănă cu un șablon legitim/marketing normal și nu cere date sensibile.
- Marketing language, CTA, reduceri, catalog, newsletter sau link sub buton nu sunt suficiente pentru high.
- Nu inventa branduri, domenii, provider hits sau fapte lipsă.
Răspunde strict JSON:
{
  "risk_class": "high|medium|benign|unknown",
  "claim_matches_known_scam_family": false,
  "matched_family": null,
  "claim_matches_legit_template": false,
  "matched_template": null,
  "reason_codes": ["semantic:..."]
}
""".strip()


def _semantic_review_from_analysis(analysis: Dict[str, Any]) -> Dict[str, Any]:
    evidence = analysis.get("evidence", {}) if isinstance(analysis.get("evidence"), dict) else {}
    review = evidence.get("semantic_review")
    return review if isinstance(review, dict) else {}


def _normalize_mistral_semantic_review(raw: Dict[str, Any], fallback: Dict[str, Any]) -> Dict[str, Any]:
    risk_class = str(raw.get("risk_class") or raw.get("severity") or "unknown").strip().lower()
    if risk_class not in {"high", "medium", "benign", "unknown"}:
        risk_class = "unknown"
    reason_codes = [
        str(item).strip()
        for item in raw.get("reason_codes") or []
        if str(item).strip()
    ]
    if not reason_codes:
        reason_codes = [f"semantic:{risk_class}"]

    return {
        "status": "done",
        "claim_matches_known_scam_family": bool(raw.get("claim_matches_known_scam_family")) or risk_class in {"high", "medium"},
        "matched_family": raw.get("matched_family") or fallback.get("matched_family"),
        "claim_matches_legit_template": bool(raw.get("claim_matches_legit_template")) or risk_class == "benign",
        "matched_template": raw.get("matched_template") or fallback.get("matched_template"),
        "reason_codes": _dedupe_preserve_order(reason_codes + ["semantic:mistral_pillar"]),
        "risk_class": risk_class,
        "confidence": raw.get("confidence"),
        "completeness": True,
        "source": "mistral_semantic_pillar",
        "fallback_source": fallback.get("source"),
    }


def _call_mistral_semantic_review(payload: Dict[str, Any]) -> Dict[str, Any]:
    response = requests.post(
        "https://api.mistral.ai/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {MISTRAL_SEMANTIC_API_KEY}",
            "Content-Type": "application/json",
        },
        json={
            "model": MISTRAL_SEMANTIC_MODEL,
            "temperature": 0,
            "max_tokens": 420,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system", "content": MISTRAL_SEMANTIC_SYSTEM_PROMPT},
                {"role": "user", "content": json.dumps(payload, ensure_ascii=False, sort_keys=True)},
            ],
        },
        timeout=MISTRAL_SEMANTIC_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    body = response.json()
    content = (
        body.get("choices", [{}])[0]
        .get("message", {})
        .get("content", "")
        .strip()
    )
    parsed = json.loads(content)
    return parsed if isinstance(parsed, dict) else {}


async def _enrich_semantic_review_async(
    redacted_text: str,
    analysis: Dict[str, Any],
    resolved_urls: List[Dict[str, Any]],
) -> None:
    evidence = analysis.setdefault("evidence", {})
    fallback = _semantic_review_from_analysis(analysis)
    if not fallback:
        fallback = {
            "status": "pending",
            "risk_class": "unknown",
            "claim_matches_known_scam_family": False,
            "claim_matches_legit_template": False,
            "reason_codes": ["semantic:pending"],
            "completeness": False,
            "source": "semantic_review_missing",
        }

    if PRIVACY_SAFE_MODE or not ENABLE_MISTRAL_SEMANTIC_PILLAR or not MISTRAL_SEMANTIC_API_KEY:
        evidence["semantic_review"] = fallback
        return

    payload = {
        "redacted_text": (redacted_text or "")[:2500],
        "claimed_brand": analysis.get("claimed_brand"),
        "atlas_semantic_review": fallback,
        "family": {
            "id": analysis.get("detected_family_id"),
            "name": analysis.get("detected_family"),
        },
        "final_destinations": [
            {
                "final_url": item.get("final_url"),
                "final_registered_domain": item.get("final_registered_domain"),
                "success": item.get("success"),
            }
            for item in (resolved_urls or [])[:5]
            if isinstance(item, dict)
        ],
        "external_intel_summary": evidence.get("external_intel_summary") if isinstance(evidence.get("external_intel_summary"), dict) else {},
    }
    try:
        raw_review = await run_in_threadpool(_call_mistral_semantic_review, payload)
        evidence["semantic_review"] = _normalize_mistral_semantic_review(raw_review, fallback)
    except Exception as exc:
        fallback = dict(fallback)
        fallback["source"] = fallback.get("source") or "scam_atlas_family_match"
        fallback["mistral_status"] = "failed"
        fallback["mistral_error"] = type(exc).__name__
        fallback["reason_codes"] = _dedupe_preserve_order(list(fallback.get("reason_codes") or []) + ["semantic:mistral_fallback"])
        evidence["semantic_review"] = fallback


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
    provider_section = _provider_verdict_for_decision_bundle(summary, has_urls=has_urls, pillars=pillars)
    identity_section = _identity_status_for_decision_bundle(
        analysis,
        resolved_urls,
        claimed_brand=claimed_brand,
        official_destination=official_destination,
        infra_flags=infra_flags,
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
    request_channel = _request_channel_for_decision_bundle(
        source_channel=source_channel,
        input_type=None,
        official_destination=official_destination,
        has_urls=has_urls,
    )
    semantic_review = _semantic_review_for_decision_bundle(
        analysis,
        official_destination=official_destination,
        provider_verdict=str(provider_section.get("verdict") or "unknown"),
    )
    resolution_status = "resolved" if first_url else ("failed" if has_urls else "not_required")
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
            "completeness": True,
        },
        "context": {
            "urgency": bool(re.search(r"\b(urgent|azi|acum|24\s*de\s*ore|ultima|expir[ăa])\b", str(raw_text or ""), re.IGNORECASE)),
            "passive_payment": bool(re.search(r"\b(plata abonamentului|se va efectua automat plata|factur[ăa])\b", str(raw_text or ""), re.IGNORECASE)),
            "apk_or_remote_mention": bool(re.search(r"\b(apk|anydesk|teamviewer|remote access|control la distan[țt][ăa])\b", str(raw_text or ""), re.IGNORECASE)),
        },
        "semantic_review": semantic_review,
    }
    canonical = json.dumps(bundle, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    bundle["evidence_hash"] = "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
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

    label = str(gate_result.get("label") or "PENDING").upper()
    family_id_by_reason = {
        "provider_malicious": "provider-gate-bad-provider",
        "identity_spoof": "provider-gate-decisive-structural-danger",
        "identity_spoof_value_request": "provider-gate-decisive-structural-danger",
        "sensitive_wrong_channel": "provider-gate-sensitive-wrong-channel",
        "semantic_high_value_request": "provider-gate-semantic-high-risk",
        "semantic_high_risk_match": "provider-gate-semantic-high-risk",
        "official_clean": "provider-gate-official-clean",
        "unknown_but_clean": "provider-gate-unofficial-inconclusive",
        "value_request_needs_verification": "provider-gate-value-request-review",
        "insufficient_evidence": "provider-gate-pending",
    }
    reason_codes = list(gate_result.get("reason_codes") or [])
    primary_reason = reason_codes[0] if reason_codes else "residual"
    gate_family_id = family_id_by_reason.get(primary_reason, "provider-gate-residual")
    gate_family_name = {
        "SIGUR": "Destinație oficială verificată",
        "SUSPECT": "Verificare necesară",
        "PERICULOS": "Risc confirmat",
        "PENDING": "Scanare în curs",
    }.get(label, "Verificare necesară")
    provider_gate["detected_family_id"] = gate_family_id
    provider_gate["detected_family"] = gate_family_name

    semantic_review = decision_bundle.get("semantic_review") if isinstance(decision_bundle.get("semantic_review"), dict) else {}
    matched_family = str(semantic_review.get("matched_family") or "").strip()
    scam_family = evidence.get("scam_family") if isinstance(evidence.get("scam_family"), dict) else {}
    if matched_family:
        family_id = matched_family
        family_name = str(scam_family.get("family") or matched_family).strip()
    else:
        family_id = gate_family_id
        family_name = gate_family_name

    reasons = {
        "SIGUR": ["Linkul ajunge pe o destinație oficială/delegată, providerii sunt curați și nu există cerere sensibilă pe canal greșit."],
        "SUSPECT": ["Nu avem dovezi suficiente pentru a marca mesajul ca sigur; verifică pe canalul oficial înainte de acțiune."],
        "PERICULOS": ["Dovezile din piloni indică risc ridicat: nu continua și nu introduce date."],
        "PENDING": ["Scanarea nu are încă toate dovezile necesare pentru un verdict final."],
    }.get(label, ["Verifică pe canalul oficial înainte de acțiune."])

    analysis["risk_level"] = gate_result.get("risk_level")
    analysis["risk_score"] = gate_result.get("risk_score")
    analysis["detected_family"] = family_name
    analysis["detected_family_id"] = family_id
    analysis["reasons"] = reasons
    analysis["safe_actions"] = (
        ["Poți continua cu prudență doar dacă recunoști contextul și nu ți se cer date sensibile."]
        if label == "SIGUR"
        else ["Verifică mesajul în aplicația/site-ul oficial, nu din linkul primit."]
        if label == "SUSPECT"
        else ["Nu apăsa linkul.", "Nu introduce date.", "Raportează/șterge mesajul."]
        if label == "PERICULOS"
        else ["Așteaptă finalizarea scanării."]
    )
    return analysis


def _apply_provider_gate_verdict(
    analysis: Dict[str, Any],
    resolved_urls: List[Dict[str, Any]],
    *,
    raw_text: str = "",
    pillars: Optional[Dict[str, Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    evidence = analysis.setdefault("evidence", {})
    summary = evidence.get("external_intel_summary")
    if not isinstance(summary, dict):
        summary = {}
    infra_flags = _collect_infrastructure_flags(analysis, resolved_urls)
    _augment_summary_with_infra_flags(summary, infra_flags)
    evidence["external_intel_summary"] = summary

    claimed_brand = str(analysis.get("claimed_brand") or "Nespecificat")
    has_urls = bool(resolved_urls)
    offer = evidence.get("offer_claim_verification")
    offer_status = str(offer.get("status", "")).lower() if isinstance(offer, dict) else ""
    official_destination = _official_destination_confirmed(resolved_urls, claimed_brand)
    web_risk_consulted = _source_ready(summary, "google_web_risk")
    vt_consulted = _source_ready(summary, "virustotal")
    urlscan_consulted = any(_source_ready(summary, name) for name in ("urlscan", "urlscan.io"))
    sensitive_url_path = _has_sensitive_url_path(resolved_urls)
    brand_warning = _brand_warning_matches_text(claimed_brand, raw_text)
    official_safety_education = _looks_like_official_safety_education(raw_text)
    direct_sensitive_request = _has_direct_sensitive_request(raw_text)
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
        for name in ("google_web_risk", "virustotal", "urlscan", "urlscan.io", "urlhaus")
        if _source_ready(summary, name)
    ]
    consulted_sources = sorted(set(consulted_sources))
    consulted_count = len(consulted_sources)

    provider_gate = {
        "version": "verdict_gate_v2",
        "official_destination": official_destination,
        "web_risk_consulted": web_risk_consulted,
        "virustotal_consulted": vt_consulted,
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


def _build_feedback_quality_payload(
    source_channel: Optional[str] = None,
    since_ts: Optional[int] = None,
    until_ts: Optional[int] = None,
    include_uncertain: bool = False,
    include_examples: bool = True,
    max_examples_per_type: int = 50,
    run_sweep: bool = True,
    sweep_start: int = 0,
    sweep_end: int = 100,
    sweep_step: int = 5,
    sweep_metric: str = "f1",
) -> Dict[str, Any]:
    feedback_rows = load_feedback_records()
    scan_rows = load_scan_records()
    dataset_rows = build_feedback_evaluation_rows(
        feedback_rows,
        scan_rows,
        source_channel=source_channel,
        since_ts=since_ts,
        until_ts=until_ts,
        include_uncertain=include_uncertain,
        fallback_threshold=RISK_THRESHOLD,
    )

    summary = summarize_feedback_records(
        dataset_rows,
        since_ts=None,
        until_ts=None,
        include_examples=include_examples,
        max_examples_per_type=max_examples_per_type,
    )

    response = {
        "items_evaluated": len(dataset_rows),
        "source_channel": source_channel,
        "prediction_baseline_threshold": RISK_THRESHOLD,
        "summary": summary,
    }

    if run_sweep and dataset_rows:
        sweep = run_feedback_threshold_sweep(
            dataset_rows,
            sweep_start=sweep_start,
            sweep_end=sweep_end,
            sweep_step=sweep_step,
            optimize_metric=sweep_metric,
        )
        response["threshold_sweep"] = sweep
        response["recommended_threshold"] = sweep["best"]["risk_threshold"]

    return response


def _safe_pct(value: Any, total: int) -> float:
    if not total:
        return 0.0
    try:
        return float(value) / total
    except Exception:
        return 0.0


def _build_readiness_payload(
    source_channel: Optional[str] = None,
    since_ts: Optional[int] = None,
    until_ts: Optional[int] = None,
    include_uncertain: bool = False,
    bucket_size_days: int = 1,
    trend_top_signals: int = 10,
    trend_min_bucket_support: int = 1,
    trend_min_signal_support: int = 1,
) -> Dict[str, Any]:
    bucket_size_days = max(1, bucket_size_days)
    feedback_rows = load_feedback_records()
    scan_rows = load_scan_records()
    dataset_rows = build_feedback_evaluation_rows(
        feedback_rows,
        scan_rows,
        source_channel=source_channel,
        since_ts=since_ts,
        until_ts=until_ts,
        include_uncertain=include_uncertain,
        fallback_threshold=RISK_THRESHOLD,
    )

    feedback_summary = summarize_feedback_records(
        dataset_rows,
        source_channel=source_channel,
        since_ts=None,
        until_ts=None,
        include_examples=False,
        max_examples_per_type=0,
    )

    drift = summarize_feedback_trend(
        dataset_rows,
        source_channel=source_channel,
        since_ts=None,
        until_ts=None,
        bucket_size_days=bucket_size_days,
        include_uncertain=include_uncertain,
        min_bucket_support=trend_min_bucket_support,
        top_signals=trend_top_signals,
        min_signal_support=trend_min_signal_support,
    )

    reputation_cache = get_reputation_cache_stats()
    cache_items = max(1, int(reputation_cache.get("items", 0) or 0))
    cache_valid_items = int(reputation_cache.get("valid_items", 0) or 0)
    provider_error_rate = _safe_pct(
        sum(int(v) for v in reputation_cache.get("provider_errors", {}).values()),
        cache_items,
    )

    confusion = feedback_summary.get("confusion_matrix", {})
    tp = int(confusion.get("tp", 0) or 0)
    fp = int(confusion.get("fp", 0) or 0)
    fn = int(confusion.get("fn", 0) or 0)
    tn = int(confusion.get("tn", 0) or 0)
    labeled_total = int(feedback_summary.get("coverage", {}).get("labeled_both", 0) or 0)

    precision = float(feedback_summary.get("precision", 0.0) or 0.0)
    recall = float(feedback_summary.get("recall", 0.0) or 0.0)
    accuracy = float(feedback_summary.get("accuracy", 0.0) or 0.0)
    f1 = float(feedback_summary.get("f1", 0.0) or 0.0)
    quality_readiness = round((precision * 0.4 + recall * 0.25 + accuracy * 0.2 + f1 * 0.15), 4)

    coverage_readiness = min(1.0, labeled_total / max(1, len(dataset_rows)))
    reputation_readiness = 0.0
    if reputation_cache.get("enabled") is True and cache_items > 0:
        reputation_readiness = 1.0 - provider_error_rate
    elif reputation_cache.get("enabled") is True:
        reputation_readiness = 0.6

    readiness_score = round(
        0.65 * quality_readiness + 0.25 * coverage_readiness + 0.1 * reputation_readiness,
        4,
    )

    critical_drifts = [
        trend
        for trend in drift.get("signal_trends", [])
        if trend.get("trend") == "worsening"
    ]

    degraded_signals = [
        item
        for item in feedback_summary.get("signal_feedback_performance", [])
        if (item.get("feedback_error_rate") or 0) >= 0.25
    ]

    if not dataset_rows:
        status = "no_feedback"
    elif readiness_score >= 0.8:
        status = "healthy"
    elif readiness_score >= 0.6:
        status = "watch"
    else:
        status = "degraded"

    return {
        "status": status,
        "readiness_score": readiness_score,
        "readiness_components": {
            "quality_score": quality_readiness,
            "coverage_score": round(coverage_readiness, 4),
            "reputation_score": round(reputation_readiness, 4),
        },
        "query": {
            "source_channel": source_channel,
            "since_ts": since_ts,
            "until_ts": until_ts,
            "include_uncertain": include_uncertain,
            "bucket_size_days": bucket_size_days,
            "trend_top_signals": trend_top_signals,
            "trend_min_bucket_support": trend_min_bucket_support,
            "trend_min_signal_support": trend_min_signal_support,
        },
        "feedback": {
            "items": len(dataset_rows),
            "items_labeled": labeled_total,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "accuracy": accuracy,
            "confusion_matrix": {
                "tp": tp,
                "fp": fp,
                "fn": fn,
                "tn": tn,
            },
            "top_degraded_signals_by_feedback_error": degraded_signals[:trend_top_signals],
            "coverage": feedback_summary.get("coverage", {}),
        },
        "trend": {
            "bucket_size_days": bucket_size_days,
            "bucket_count": drift.get("bucket_count", 0),
            "critical_signal_drifts": critical_drifts[:trend_top_signals],
            "signal_trends": drift.get("signal_trends", [])[:trend_top_signals],
            "overall": drift.get("overall", {}),
        },
        "reputation": {
            "enabled": bool(reputation_cache.get("enabled", False)),
            "cache_items": cache_items,
            "cache_valid_items": cache_valid_items,
            "provider_errors": reputation_cache.get("provider_errors", {}),
            "provider_error_rate": round(provider_error_rate, 4),
            "cache_ttl_seconds": reputation_cache.get("ttl_seconds"),
            "source_stats": reputation_cache.get("source_stats", {}),
        },
    }


def _build_orchestration_telemetry_payload(
    *,
    limit: int = 1000,
    urlscan_timeout_rate_alert: float = 0.15,
) -> Dict[str, Any]:
    records = [
        row
        for row in load_scan_records(limit)
        if isinstance(row, dict) and str(row.get("event_type") or "").startswith("orchestrated_")
    ]
    by_event: Counter[str] = Counter()
    by_stage: Counter[str] = Counter()
    scan_ids: set[str] = set()
    final_poll_counts: List[int] = []
    final_age_ms: List[int] = []
    stage_durations: Dict[str, List[int]] = defaultdict(list)
    conflict_merge_events = 0
    conflict_retry_failures = 0
    reclaim_events = 0
    reservation_guard_hits = 0
    urlscan_timeout_events = 0

    for row in records:
        event_type = str(row.get("event_type") or "unknown")
        by_event[event_type] += 1
        scan_id = str(row.get("scan_id") or "").strip()
        if scan_id:
            scan_ids.add(scan_id)
        metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
        stage = str(metadata.get("pipeline_stage") or metadata.get("stage") or "").strip().lower()
        if stage:
            by_stage[stage] += 1

        if event_type == "orchestrated_conflict_merge":
            conflict_merge_events += 1
        if event_type == "orchestrated_urlscan_reclaimed":
            reclaim_events += 1
        if event_type == "orchestrated_urlscan_reservation_guard":
            reservation_guard_hits += 1
        if event_type in {"orchestrated_urlscan_polled", "orchestrated_verdict_final"}:
            if str(metadata.get("urlscan_status") or "").strip().lower() == "timeout":
                urlscan_timeout_events += 1

        conflict_retry_failures += int(metadata.get("conflict_merge_retry_failures") or 0)

        if event_type == "orchestrated_verdict_final":
            try:
                final_poll_counts.append(int(metadata.get("poll_count") or 0))
            except Exception:
                pass
            try:
                final_age_ms.append(int(metadata.get("age_ms") or 0))
            except Exception:
                pass

        durations = metadata.get("stage_durations_ms")
        if isinstance(durations, dict):
            for stage_name, duration_ms in durations.items():
                try:
                    stage_durations[str(stage_name)].append(int(duration_ms))
                except Exception:
                    continue

    total_scans = max(1, len(scan_ids))
    urlscan_timeout_rate = urlscan_timeout_events / total_scans
    alerts = []
    if reservation_guard_hits > 0:
        alerts.append({
            "severity": "watch",
            "code": "urlscan_reservation_guard_hits",
            "message": "Au aparut poll-uri concurente care au fost oprite de guard-ul anti-dublu-submit.",
            "count": reservation_guard_hits,
        })
    if conflict_retry_failures > 0:
        alerts.append({
            "severity": "high",
            "code": "conflict_merge_retry_failures",
            "message": "Exista conflict-merge care nu a putut fi persistat dupa retry bounded.",
            "count": conflict_retry_failures,
        })
    if urlscan_timeout_rate > urlscan_timeout_rate_alert:
        alerts.append({
            "severity": "watch",
            "code": "urlscan_timeout_rate_high",
            "message": "Rata urlscan pending->timeout este peste pragul configurat.",
            "rate": round(urlscan_timeout_rate, 4),
            "threshold": urlscan_timeout_rate_alert,
        })

    def avg(values: List[int]) -> Optional[float]:
        return round(sum(values) / len(values), 2) if values else None

    return {
        "generated_at": int(time.time()),
        "events_considered": len(records),
        "scan_count": len(scan_ids),
        "by_event_type": dict(by_event),
        "by_stage": dict(by_stage),
        "polls_to_final": {
            "avg": avg(final_poll_counts),
            "max": max(final_poll_counts) if final_poll_counts else None,
            "samples": len(final_poll_counts),
        },
        "time_to_final_ms": {
            "avg": avg(final_age_ms),
            "max": max(final_age_ms) if final_age_ms else None,
            "samples": len(final_age_ms),
        },
        "stage_latency_ms": {
            stage_name: {
                "avg": avg(values),
                "max": max(values) if values else None,
                "samples": len(values),
            }
            for stage_name, values in sorted(stage_durations.items())
        },
        "urlscan": {
            "reservation_guard_hits": reservation_guard_hits,
            "reclaim_events": reclaim_events,
            "pending_timeout_events": urlscan_timeout_events,
            "pending_timeout_rate": round(urlscan_timeout_rate, 4),
        },
        "conflicts": {
            "merge_events": conflict_merge_events,
            "retry_failures": conflict_retry_failures,
        },
        "alerts": alerts,
}


def _label_to_shadow_prediction(label: Any) -> Optional[bool]:
    normalized = str(label or "").strip().upper()
    if normalized == "PERICULOS":
        return True
    if normalized in {"SIGUR", "SUSPECT", "NECUNOSCUT"}:
        return False
    return None


def _shadow_feedback_actual(feedback_row: Dict[str, Any], gate_prediction: Optional[bool]) -> Optional[bool]:
    raw_actual = feedback_row.get("actual_is_scam")
    if isinstance(raw_actual, bool):
        return raw_actual
    if isinstance(raw_actual, str):
        normalized_actual = raw_actual.strip().lower()
        if normalized_actual in {"true", "1", "yes", "scam"}:
            return True
        if normalized_actual in {"false", "0", "no", "legit"}:
            return False

    feedback = str(feedback_row.get("feedback") or "").strip().lower()
    if feedback == "false_positive":
        return False
    if feedback == "false_negative":
        return True
    if feedback == "correct":
        return gate_prediction
    return None


def _latest_feedback_by_scan_id(rows: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    latest: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        scan_id = str(row.get("scan_id") or "").strip()
        if not scan_id:
            continue
        try:
            row_ts = int(row.get("timestamp") or row.get("event_ts") or 0)
        except Exception:
            row_ts = 0
        existing = latest.get(scan_id)
        try:
            existing_ts = int(existing.get("timestamp") or existing.get("event_ts") or 0) if existing else -1
        except Exception:
            existing_ts = -1
        if existing is None or row_ts >= existing_ts:
            latest[scan_id] = row
    return latest


def _int_percentile(values: List[int], percentile: float) -> Optional[int]:
    if not values:
        return None
    ordered = sorted(int(value) for value in values)
    if len(ordered) == 1:
        return ordered[0]
    clamped = max(0.0, min(1.0, percentile))
    index = int(round((len(ordered) - 1) * clamped))
    return ordered[index]


def _build_shadow_adjudication_payload(
    *,
    limit: int = 1000,
    fallback_rate_alert: float = 0.05,
    disagreement_rate_alert: float = 0.25,
    latency_p95_alert_ms: int = 2500,
    max_examples: int = 20,
) -> Dict[str, Any]:
    records = [
        row
        for row in load_scan_records(limit)
        if isinstance(row, dict) and str(row.get("event_type") or "") == "adjudication_shadow"
    ]
    feedback_by_scan = _latest_feedback_by_scan_id(load_feedback_records())

    by_gate_label: Counter[str] = Counter()
    by_shadow_label: Counter[str] = Counter()
    by_fallback_reason: Counter[str] = Counter()
    by_model: Counter[str] = Counter()
    latencies: List[int] = []
    total = valid = fallback = cache_hits = agreements = disagreements = 0
    labeled_feedback = gate_errors = shadow_errors = shadow_would_improve = shadow_would_regress = 0
    disagreement_examples: List[Dict[str, Any]] = []
    fallback_examples: List[Dict[str, Any]] = []
    feedback_examples: List[Dict[str, Any]] = []

    for row in records:
        total += 1
        metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
        scan_id = str(metadata.get("parent_scan_id") or row.get("scan_id") or "").strip()
        evidence = row.get("evidence") if isinstance(row.get("evidence"), dict) else {}
        gate = evidence.get("gate") if isinstance(evidence.get("gate"), dict) else {}
        shadow = evidence.get("shadow") if isinstance(evidence.get("shadow"), dict) else None
        gate_label = str(gate.get("label") or row.get("user_risk_label") or "NECUNOSCUT").strip().upper()
        by_gate_label[gate_label] += 1

        try:
            latencies.append(int(evidence.get("latency_ms")))
        except Exception:
            pass
        if evidence.get("cache_hit"):
            cache_hits += 1
        model = str(evidence.get("model") or "").strip()
        if model:
            by_model[model] += 1

        if shadow is not None and evidence.get("valid") is not False:
            valid += 1
            shadow_label = str(shadow.get("label") or "NECUNOSCUT").strip().upper()
            by_shadow_label[shadow_label] += 1
            if gate_label == shadow_label:
                agreements += 1
            else:
                disagreements += 1
                if len(disagreement_examples) < max_examples:
                    disagreement_examples.append({
                        "scan_id": scan_id,
                        "gate_label": gate_label,
                        "shadow_label": shadow_label,
                        "confidence": shadow.get("confidence"),
                        "reason": shadow.get("motiv_ro"),
                        "evidence_hash": evidence.get("evidence_hash"),
                    })
        else:
            fallback += 1
            reason = str(evidence.get("fallback_reason") or "unknown").strip()
            by_fallback_reason[reason] += 1
            if len(fallback_examples) < max_examples:
                fallback_examples.append({
                    "scan_id": scan_id,
                    "gate_label": gate_label,
                    "fallback_reason": reason,
                    "evidence_hash": evidence.get("evidence_hash"),
                })

        feedback_row = feedback_by_scan.get(scan_id)
        if isinstance(feedback_row, dict) and shadow is not None:
            gate_pred = _label_to_shadow_prediction(gate_label)
            shadow_pred = _label_to_shadow_prediction(shadow.get("label"))
            actual = _shadow_feedback_actual(feedback_row, gate_pred)
            if actual is not None and gate_pred is not None and shadow_pred is not None:
                labeled_feedback += 1
                gate_wrong = gate_pred != actual
                shadow_wrong = shadow_pred != actual
                gate_errors += int(gate_wrong)
                shadow_errors += int(shadow_wrong)
                if gate_wrong and not shadow_wrong:
                    shadow_would_improve += 1
                if not gate_wrong and shadow_wrong:
                    shadow_would_regress += 1
                if (gate_wrong or shadow_wrong) and len(feedback_examples) < max_examples:
                    feedback_examples.append({
                        "scan_id": scan_id,
                        "actual_is_scam": actual,
                        "gate_label": gate_label,
                        "shadow_label": shadow.get("label"),
                        "feedback": feedback_row.get("feedback"),
                        "shadow_would_improve": gate_wrong and not shadow_wrong,
                        "shadow_would_regress": (not gate_wrong) and shadow_wrong,
                    })

    valid_rate = valid / total if total else 0.0
    fallback_rate = fallback / total if total else 0.0
    disagreement_rate = disagreements / valid if valid else 0.0
    cache_hit_rate = cache_hits / total if total else 0.0
    latency_avg = int(sum(latencies) / len(latencies)) if latencies else None
    latency_p95 = _int_percentile(latencies, 0.95)
    alerts: List[Dict[str, Any]] = []
    if fallback_rate > fallback_rate_alert:
        alerts.append({
            "severity": "watch",
            "code": "mistral_shadow_fallback_rate_high",
            "message": "Rata de fallback/validator reject este peste prag; promptul sau bundle-ul trebuie inspectat.",
            "rate": round(fallback_rate, 4),
        })
    if disagreement_rate > disagreement_rate_alert:
        alerts.append({
            "severity": "watch",
            "code": "mistral_shadow_disagreement_rate_high",
            "message": "Mistral diferă des de gate pe cazuri ambigue; verifică exemplele înainte de promovare.",
            "rate": round(disagreement_rate, 4),
        })
    if latency_p95 is not None and latency_p95 > latency_p95_alert_ms:
        alerts.append({
            "severity": "watch",
            "code": "mistral_shadow_latency_p95_high",
            "message": "Latența p95 a adjudicatorului shadow depășește bugetul.",
            "p95_ms": latency_p95,
        })
    if shadow_would_regress:
        alerts.append({
            "severity": "high",
            "code": "mistral_shadow_feedback_regressions",
            "message": "Pe feedback etichetat există cazuri unde shadow ar fi fost mai slab decât gate-ul.",
            "count": shadow_would_regress,
        })

    return {
        "generated_at": int(time.time()),
        "events_considered": total,
        "valid": valid,
        "fallback": fallback,
        "valid_rate": round(valid_rate, 4),
        "fallback_rate": round(fallback_rate, 4),
        "agreement": {
            "agreements": agreements,
            "disagreements": disagreements,
            "disagreement_rate": round(disagreement_rate, 4),
        },
        "latency_ms": {
            "avg": latency_avg,
            "p95": latency_p95,
            "max": max(latencies) if latencies else None,
            "samples": len(latencies),
        },
        "cache": {
            "hits": cache_hits,
            "hit_rate": round(cache_hit_rate, 4),
        },
        "by_gate_label": dict(by_gate_label),
        "by_shadow_label": dict(by_shadow_label),
        "by_fallback_reason": dict(by_fallback_reason),
        "by_model": dict(by_model),
        "feedback_comparison": {
            "labeled": labeled_feedback,
            "gate_errors": gate_errors,
            "shadow_errors": shadow_errors,
            "shadow_would_improve": shadow_would_improve,
            "shadow_would_regress": shadow_would_regress,
        },
        "examples": {
            "disagreements": disagreement_examples,
            "fallbacks": fallback_examples,
            "feedback_deltas": feedback_examples,
        },
        "alerts": alerts,
        "promotion_gate": {
            "min_labeled_real_messages": 150,
            "current_labeled_real_messages": labeled_feedback,
            "fallback_rate_target": 0.05,
            "latency_p95_target_ms": latency_p95_alert_ms,
            "can_promote": (
                labeled_feedback >= 150
                and fallback_rate <= 0.05
                and shadow_would_regress == 0
                and (latency_p95 is None or latency_p95 <= latency_p95_alert_ms)
                and shadow_errors <= gate_errors
            ),
        },
    }


def _validate_text_input(field_name: str, value: str, max_chars: int) -> None:
    if not value or not value.strip():
        raise HTTPException(status_code=400, detail=f"{field_name} nu poate fi gol.")
    if len(value) > max_chars:
        raise HTTPException(
            status_code=413,
            detail=f"{field_name} depășește limita de {max_chars} caractere."
        )


def _new_scan_id(prefix: str) -> str:
    return f"{prefix}_{int(time.time())}_{os.urandom(4).hex()}"


def _normalize_user_facing_risk_level(risk_level: Optional[str]) -> str:
    normalized = (risk_level or "unknown").strip().lower()
    if normalized in {"high", "critical"}:
        return "dangerous"
    if normalized == "medium":
        return "suspect"
    if normalized in {"low", "safe"}:
        return "safe"
    return "unknown"


def _user_risk_level_label(risk_level: str) -> str:
    normalized = (risk_level or "").strip().lower()
    if normalized in {"safe", "suspect", "dangerous"}:
        user_level = normalized
    else:
        user_level = _normalize_user_facing_risk_level(normalized)

    return {
        "dangerous": "PERICULOS",
        "suspect": "SUSPECT",
        "safe": "SIGUR",
    }.get(user_level, "NECUNOSCUT")


def _user_risk_level_text(risk_level: str) -> str:
    normalized = (risk_level or "").strip().lower()
    if normalized in {"dangerous", "high", "critical"}:
        return "Periculos"
    if normalized in {"suspect", "medium"}:
        return "Suspect"
    if normalized in {"safe", "low"}:
        return "Probabil sigur"
    return "Neclar"


def _user_recommended_action(risk_level: str) -> str:
    normalized = (risk_level or "").strip().lower()
    if normalized in {"dangerous", "high", "critical"}:
        return "Nu apăsați pe nimic, nu introduceți date. Blocați mesajul și verificați direct în aplicația oficială."
    if normalized in {"suspect", "medium"}:
        return "Verificați cu atenție și confirmați doar prin canalele oficiale înainte de a accesa linkuri sau a acționa."
    if normalized in {"safe", "low"}:
        return "Mesajul pare mai puțin riscant, dar verificați întotdeauna expeditorul și linkul înainte de accesare."
    return "Trimiteți mesajul în format original (sau emailul .eml) pentru o verificare completă."


def _build_scan_response(
    scan_id_prefix: str,
    analysis_results: Dict[str, Any],
    redacted_text: str,
    ai_explanation: Dict[str, Any],
    risk_score: Optional[int] = None,
    risk_level: Optional[str] = None,
    scan_id: Optional[str] = None,
    reasons: Optional[List[str]] = None,
    extra_fields: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    normalized_risk_level = risk_level if risk_level is not None else analysis_results.get("risk_level", "unknown")
    user_facing_risk_level = _normalize_user_facing_risk_level(normalized_risk_level)
    user_facing_risk_text = _user_risk_level_text(user_facing_risk_level)
    payload = {
        "scan_id": scan_id or _new_scan_id(scan_id_prefix),
        "risk_score": risk_score if risk_score is not None else analysis_results.get("risk_score", 0),
        "risk_level": normalized_risk_level,
        "user_risk_level": user_facing_risk_level,
        "user_risk_label": _user_risk_level_label(user_facing_risk_level),
        "user_risk_text": user_facing_risk_text,
        "user_recommended_action": _user_recommended_action(user_facing_risk_level),
        "detected_family": analysis_results.get("detected_family", "Necunoscut"),
        "detected_family_id": analysis_results.get("detected_family_id"),
        "claimed_brand": analysis_results.get("claimed_brand", "Nespecificat"),
        "reasons": _dedupe_preserve_order(
            reasons if reasons is not None else analysis_results.get("reasons", [])
        ),
        "privacy_safe_mode": PRIVACY_SAFE_MODE,
        "processing_mode": "privacy_safe" if PRIVACY_SAFE_MODE else "full",
        "evidence": _deep_copy_jsonable(analysis_results.get("evidence", {})),
        "redacted_text": redacted_text,
        "ai_verdict": ai_explanation.get("verdict_summary"),
        "ai_explanation": ai_explanation.get("explanation"),
        "offer_analysis": ai_explanation.get("offer_analysis"),
        "key_dangers": ai_explanation.get("key_dangers"),
        "safe_actions": ai_explanation.get("safe_actions", analysis_results.get("safe_actions", [])),
    }
    if extra_fields:
        payload.update(extra_fields)
    return payload


def _collect_signal_ids(analysis: Dict[str, Any]) -> List[str]:
    signal_ids: List[str] = []
    evidence = analysis.get("evidence", {})

    if evidence.get("has_domain_mismatch"):
        signal_ids.append("email_domain_mismatch")
    if evidence.get("url_behaviour"):
        signal_ids.append("url_behavior")
    if evidence.get("url_transport"):
        signal_ids.append("url_transport")
    external_intel_hits = int(evidence.get("external_intel_hits", 0) or 0)
    if external_intel_hits:
        signal_ids.append("external_url_reputation")
    external_intel_summary = analysis.get("evidence", {}).get("external_intel_summary") or {}
    if isinstance(external_intel_summary, dict):
        for src, details in external_intel_summary.items():
            if not isinstance(details, dict):
                continue
            status = str(details.get("status", "")).lower()
            if status in {"malicious", "suspicious", "clean"}:
                signal_ids.append(f"ext_src:{src}:{status}")

    if evidence.get("email_auth"):
        email_auth = evidence.get("email_auth") or {}
        if isinstance(email_auth, dict):
            auth_status = email_auth.get("auth_status") or {}
            if isinstance(auth_status, dict):
                for mechanism in ("spf", "dkim", "dmarc"):
                    status = str(auth_status.get(mechanism, "")).lower()
                    if status == "fail":
                        signal_ids.append(f"email_{mechanism}_fail")
                    elif status == "pass":
                        signal_ids.append(f"email_{mechanism}_pass")

            policy = email_auth.get("auth_action_plan")
            if isinstance(policy, dict):
                action = str(policy.get("action", "")).lower()
                if action:
                    signal_ids.append(f"email_action_{action}")
                severity = str(policy.get("severity", "")).lower()
                if severity:
                    signal_ids.append(f"email_action_severity_{severity}")
                if policy.get("policy_context", {}).get("pct") is not None:
                    signal_ids.append(f"email_dmarc_pct_{policy['policy_context']['pct']}")

            dns_checks = email_auth.get("dns_checks")
            if isinstance(dns_checks, dict):
                dmarc_policy = dns_checks.get("dmarc_policy")
                if isinstance(dmarc_policy, dict):
                    dmarc_action = str(dmarc_policy.get("p", "")).lower()
                    if dmarc_action:
                        signal_ids.append(f"email_dmarc_{dmarc_action}")
                if dns_checks.get("spf_dns_present"):
                    signal_ids.append("email_spf_dns_present")
                if dns_checks.get("dkim_dns_present"):
                    signal_ids.append("email_dkim_dns_present")
                if dns_checks.get("dmarc_dns_present"):
                    signal_ids.append("email_dmarc_dns_present")
                if dns_checks.get("reply_to_mismatch"):
                    signal_ids.append("email_reply_to_mismatch")
                if dns_checks.get("spf_aligned") is False:
                    signal_ids.append("email_spf_alignment_mismatch")
                if dns_checks.get("dkim_aligned") is False:
                    signal_ids.append("email_dkim_alignment_mismatch")
        signal_ids.append("email_authenticity")
    if analysis.get("detected_family_id"):
        signal_ids.append(f"family:{analysis.get('detected_family_id')}")
    return _dedupe_preserve_order(signal_ids)


def _extract_url_signal(payload: Dict[str, Any]) -> Dict[str, Any]:
    final_url = payload.get("final_url") or ""
    return {
        "url_hash": hashlib.sha256(str(final_url).encode("utf-8")).hexdigest() if final_url else None,
        "host": payload.get("final_hostname"),
        "registered_domain": payload.get("final_registered_domain"),
        "shortener_count": payload.get("shortener_count", 0),
        "redirect_count": payload.get("redirect_count", 0),
        "success": payload.get("success", True),
    }


def _emit_scan_event(
    scan_id: str,
    scan_payload: Dict[str, Any],
    analysis: Dict[str, Any],
    resolved_urls: List[Dict[str, Any]],
    input_channel: str,
    source_channel: Optional[str] = None,
) -> None:
    risk_score = scan_payload.get("risk_score")
    try:
        risk_score_int = int(risk_score) if risk_score is not None else 0
    except (TypeError, ValueError):
        risk_score_int = 0
    risk_level = str(scan_payload.get("risk_level") or "low").lower()
    predicted_is_scam = bool(risk_score_int >= RISK_THRESHOLD or risk_level in {"high", "critical"})

    event = {
        "scan_id": scan_id,
        "input_type": input_channel,
        "source_channel": source_channel,
        "risk_score": risk_score_int,
        "risk_level": scan_payload.get("risk_level"),
        "user_risk_level": scan_payload.get("user_risk_level"),
        "user_risk_label": scan_payload.get("user_risk_label"),
        "detected_family_id": scan_payload.get("detected_family_id"),
        "detected_family": scan_payload.get("detected_family"),
        "claimed_brand": scan_payload.get("claimed_brand"),
        "predicted_is_scam": predicted_is_scam,
        "signal_ids": _collect_signal_ids(analysis),
        "url_count": len(resolved_urls),
        "urls": [_extract_url_signal(item) for item in resolved_urls],
        "redacted_text_snippet": (scan_payload.get("redacted_text") or "")[:120],
        "evidence": {
            "external_intel": analysis.get("evidence", {}).get("external_intel", False),
            "external_intel_hits": analysis.get("evidence", {}).get("external_intel_hits", 0),
            "email_auth_strength": analysis.get("evidence", {}).get("email_auth", {}).get("auth_strength"),
            "external_intel_sources": analysis.get("evidence", {}).get("external_intel_sources", []),
            "external_intel_summary": analysis.get("evidence", {}).get("external_intel_summary", {}),
            "external_intel_source_status": analysis.get("evidence", {}).get("external_intel_source_status", {}),
            "email_auth_action": analysis.get("evidence", {}).get("email_auth", {}).get("auth_action_plan"),
        },
    }
    log_scan_event(event)
    if scan_payload.get("is_final") is not False:
        evidence_bundle = build_evidence_bundle(
            input_type=input_channel,
            redacted_text=str(scan_payload.get("redacted_text") or ""),
            analysis=analysis,
            resolved_urls=resolved_urls,
            scan_payload=scan_payload,
        )
        maybe_run_shadow_adjudication(
            scan_id=scan_id,
            input_type=input_channel,
            source_channel=source_channel,
            evidence=evidence_bundle,
        )


class TextScanRequest(BaseModel):
    text: str
    source_channel: Optional[str] = "manual"
    consent_store_sample: Optional[bool] = False

class URLScanRequest(BaseModel):
    url: str
    source_channel: Optional[str] = "url_scan"


class UrlscanSandboxRequest(BaseModel):
    url: str
    visibility: Optional[str] = URLSCAN_VISIBILITY_DEFAULT
    country: Optional[str] = URLSCAN_COUNTRY_DEFAULT or None
    customagent: Optional[str] = URLSCAN_CUSTOM_AGENT_DEFAULT or None
    source_channel: Optional[str] = "android_native"


class OrchestratedScanRequest(BaseModel):
    input_type: str = "text"
    text: Optional[str] = None
    url: Optional[str] = None
    html_content: Optional[str] = None
    source_channel: Optional[str] = "android_native"
    visibility: Optional[str] = URLSCAN_VISIBILITY_DEFAULT
    country: Optional[str] = URLSCAN_COUNTRY_DEFAULT or None
    customagent: Optional[str] = URLSCAN_CUSTOM_AGENT_DEFAULT or None


class FeedbackRequest(BaseModel):
    scan_id: str
    feedback: str
    actual_is_scam: Optional[bool] = None
    predicted_is_scam: Optional[bool] = None
    predicted_risk_score: Optional[int] = None
    risk_level: Optional[str] = None
    signal_ids: Optional[List[str]] = None
    notes: Optional[str] = None


def mock_ocr_text_by_filename(filename: str) -> str:
    """
    Fallback text used when OCR cloud is unavailable.
    Kept for deterministic demo/test behavior on common scam themes.
    """
    filename_lower = filename.lower()

    if "anaf" in filename_lower or "spv" in filename_lower:
        return (
            "ANAF: Notificare de plata urgenta. Aveti o obligatie fiscala neachitata in valoare de 450 RON. "
            "Neplata va atrage penalizări. Conectati-va in SPV si plătiti aici: http://anaf-spv-plati.info/login"
        )
    if "posta" in filename_lower:
        return (
            "Posta Romana: Pachetul dvs. a sosit in depozit dar adresa este incompleta. "
            "Va rugam completati adresa corecta si achitati taxa de 2.45 RON: http://posta-romana-taxe.top"
        )
    if "revolut" in filename_lower:
        return (
            "Revolut: Contul tau a fost blocat temporar din motive de securitate. "
            "Va rugam confirmati identitatea si deblocati aplicatia accesand link-ul: http://revolut-security.net/verify"
        )
    if "olx" in filename_lower:
        return (
            "Buna ziua, am efectuat plata prin OLX. Pentru a incasa banii de pe produs, va rugam faceti click pe link "
            "si introduceti datele cardului dvs.: http://olx-ro-tranzactii.online/payment"
        )
    if "whatsapp" in filename_lower:
        return (
            "WhatsApp: Codul tau de verificare este [492-385]. Nu distribui acest cod cu nimeni."
        )

    return (
        "Stimate client, coletul tau nr. RO-5829-X9 nu a putut fi livrat din cauza adresei incomplete. "
        "Va rugam actualizati adresa si alegeti lockerul de ridicare aici: http://fan-locker-ridicare.ru/awb"
    )


def _validate_file_upload(
    filename: str,
    content_type: str | None,
    file_bytes: bytes,
    *,
    max_bytes: int,
    allowed_exts: set[str],
    allowed_mime_types: set[str],
) -> None:
    if len(file_bytes) > max_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"Fisierul este prea mare. Limita maxima este {max_bytes // 1024 // 1024} MB."
        )

    ext = os.path.splitext(filename.lower())[1]
    if ext not in allowed_exts and (not content_type or content_type.lower() not in allowed_mime_types):
        raise HTTPException(
            status_code=400,
            detail=(
                "Tipul fisierului nu este acceptat. "
                f"Extensii permise: {', '.join(sorted(allowed_exts))}"
            )
        )


async def extract_text_for_scan(
    filename: str,
    file_bytes: bytes,
    extract_fn: Callable[[bytes], str],
) -> tuple[str, Optional[str]]:
    """
    Runs OCR through Google Vision when configured, with deterministic fallback.
    Returns extracted text and an OCR warning if OCR was unavailable or partial.
    """
    ocr_warning: Optional[str] = None
    ocr_text = ""

    if PRIVACY_SAFE_MODE:
        ocr_warning = "Mod sigur activ: OCR cloud dezactivat."
    elif has_vision_key():
        try:
            ocr_text = await run_in_threadpool(extract_fn, file_bytes)
            if not ocr_text.strip():
                ocr_warning = "OCR cloud nu a extras text din fișier."
        except Exception as exc:
            logger.warning(f"Vision OCR failed for {filename}: {exc}")
            ocr_warning = f"Fallback OCR pe nume fișier: {str(exc)}"
    else:
        ocr_warning = (
            "Lipsește GOOGLE_CLOUD_VISION_API_KEY. Se folosește scenariu mock pe nume fișier."
        )

    if not ocr_text.strip() and ALLOWED_MOCK_OCR:
        ocr_text = mock_ocr_text_by_filename(filename)
    if not ocr_text.strip():
        if ocr_warning is None:
            ocr_warning = "OCR-ul nu a returnat niciun text din acest fisier."
        raise HTTPException(
            status_code=503,
            detail=ocr_warning
        )

    return ocr_text, ocr_warning


def _safe_mode_url_entry(url: str) -> Dict[str, Any]:
    raw_url = (url or "").strip()
    final_url = _canonicalize_url(raw_url) or raw_url
    parsed = urllib.parse.urlparse(final_url)
    hostname = (parsed.hostname or "").lower()
    is_shortener = False
    try:
        is_shortener = is_known_shortener(final_url)
    except Exception:
        is_shortener = False

    return {
        "original_url": raw_url,
        "final_url": final_url,
        "final_hostname": hostname,
        "final_registered_domain": _extract_domain_root(hostname),
        "domain_age_days": None,
        "domain_created_date": None,
        "has_mx_records": None,
        "redirect_chain": [],
        "redirect_count": 0,
        "shortener_count": 1 if is_shortener else 0,
        "uses_shortener": is_shortener,
        "detected_soft_redirects": [],
        "success": True,
        "error_message": (
            "SIGURSCAN_SAFE_MODE: nu se face verificare externă a URL-ului."
            if PRIVACY_SAFE_MODE
            else None
        ),
    }


def _build_ai_explanation(
    text: str,
    analysis: Dict[str, Any],
    resolved_urls: List[Dict[str, Any]],
) -> Dict[str, Any]:
    if PRIVACY_SAFE_MODE:
        return generate_fallback_explanation(text, analysis)
    return generate_ai_explanation(text, analysis, resolved_urls)


async def _build_ai_explanation_async(
    text: str,
    analysis: Dict[str, Any],
    resolved_urls: List[Dict[str, Any]],
) -> Dict[str, Any]:
    if PRIVACY_SAFE_MODE or not ENABLE_CLOUD_AI_EXPLANATION or AI_EXPLANATION_TIMEOUT_SECONDS <= 0:
        return generate_fallback_explanation(text, analysis)

    try:
        return await asyncio.wait_for(
            run_in_threadpool(generate_ai_explanation, text, analysis, resolved_urls),
            timeout=AI_EXPLANATION_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        logger.warning("AI explanation timed out; using deterministic fallback.")
    except Exception as exc:
        logger.warning("AI explanation failed; using deterministic fallback: %s", exc)
    return generate_fallback_explanation(text, analysis)


def _attach_offer_claim_verification(
    analysis: Dict[str, Any],
    offer_claim: Dict[str, Any],
) -> None:
    evidence = analysis.setdefault("evidence", {})
    evidence["offer_claim_verification"] = offer_claim
    summary = evidence.setdefault("external_intel_summary", {})
    if isinstance(summary, dict):
        summary["ai_offer_web_check"] = {
            "status": offer_claim.get("status", "inconclusive"),
            "verdict": offer_claim.get("verdict", offer_claim.get("status", "inconclusive")),
            "severity": offer_claim.get("severity", "unknown"),
            "summary": offer_claim.get("summary", ""),
            "details": offer_claim.get("details", ""),
            "confidence": offer_claim.get("confidence", 0),
            "claimed_brand": offer_claim.get("claimed_brand"),
            "official_domains": offer_claim.get("official_domains", []),
            "evidence_urls": offer_claim.get("evidence_urls", []),
            "method": offer_claim.get("method", "unknown"),
            "knowledge_target": offer_claim.get("knowledge_target"),
        }


def _skipped_offer_claim_payload(reason: str) -> Dict[str, Any]:
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


def _attach_brand_warning_summary(
    summary: Dict[str, Any],
    brand_warning: Dict[str, Any],
) -> None:
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


async def _enrich_offer_claim_verification_async(
    text: str,
    analysis: Dict[str, Any],
    resolved_urls: List[Dict[str, Any]],
) -> Dict[str, Any]:
    if PRIVACY_SAFE_MODE or AI_OFFER_CLAIM_TIMEOUT_SECONDS <= 0:
        offer_claim = _skipped_offer_claim_payload("Claim web check skipped by privacy/timeout policy.")
        _attach_offer_claim_verification(analysis, offer_claim)
        return offer_claim

    try:
        offer_claim = await asyncio.wait_for(
            run_in_threadpool(
                verify_offer_claim,
                text,
                analysis,
                resolved_urls,
                brand_registry=BRAND_REGISTRY,
            ),
            timeout=AI_OFFER_CLAIM_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        logger.warning("Offer claim web check timed out.")
        offer_claim = {
            "provider": "ai_offer_web_check",
            "status": "inconclusive",
            "verdict": "inconclusive",
            "severity": "unknown",
            "summary": "Offer claim web check timed out.",
            "details": "Offer claim web check timed out.",
            "confidence": 0,
            "evidence_urls": [],
            "method": "timeout",
        }
    except Exception as exc:
        logger.warning("Offer claim web check failed: %s", exc)
        offer_claim = {
            "provider": "ai_offer_web_check",
            "status": "inconclusive",
            "verdict": "inconclusive",
            "severity": "unknown",
            "summary": f"Offer claim web check failed: {type(exc).__name__}.",
            "details": f"Offer claim web check failed: {type(exc).__name__}.",
            "confidence": 0,
            "evidence_urls": [],
            "method": "error",
        }

    _attach_offer_claim_verification(analysis, offer_claim)
    return offer_claim


@app.get("/")
def read_root():
    return {
        "project": "SigurScan",
        "status": "active",
        "version": "1.0",
        "api_docs": "/docs",
        "privacy_policy": "/privacy",
    }


PRIVACY_POLICY_HTML = """<!doctype html>
<html lang="ro">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Politica de confidentialitate SigurScan</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; line-height: 1.6; margin: 0; color: #172033; background: #f7f9fc; }
    main { max-width: 860px; margin: 0 auto; padding: 40px 20px 64px; }
    section { background: #fff; border: 1px solid #dfe7f3; border-radius: 18px; padding: 24px; margin: 18px 0; }
    h1, h2 { line-height: 1.2; }
    h1 { font-size: 2rem; margin-bottom: 8px; }
    h2 { font-size: 1.2rem; margin-top: 0; }
    .muted { color: #647089; }
    li { margin: 8px 0; }
    code { background: #eef3ff; border-radius: 6px; padding: 2px 6px; }
  </style>
</head>
<body>
<main>
  <h1>Politica de confidentialitate SigurScan</h1>
  <p class="muted">Ultima actualizare: 3 iunie 2026</p>

  <section>
    <h2>Principiul de baza</h2>
    <p>SigurScan scaneaza doar continut pe care utilizatorul alege explicit sa il verifice. Aplicatia nu citeste automat notificari, SMS-uri, inbox Gmail/Outlook/Yahoo, clipboard sau alte aplicatii in fundal.</p>
  </section>

  <section>
    <h2>Ce date pot fi procesate</h2>
    <ul>
      <li>text sau link introdus manual;</li>
      <li>continut primit prin Android Share Intent, inclusiv HTML daca aplicatia sursa il furnizeaza;</li>
      <li>URL-uri vizibile si URL-uri ascunse in HTML sub butoane/linkuri;</li>
      <li>imagini, coduri QR, PDF-uri sau fisiere selectate manual de utilizator;</li>
      <li>feedback trimis explicit de utilizator despre un verdict.</li>
    </ul>
  </section>

  <section>
    <h2>Cum folosim datele</h2>
    <p>Datele sunt folosite pentru a extrage linkuri, a urmari redirecturi, a verifica reputatia URL-urilor si a afisa un verdict simplu de risc. Inainte de analiza, backend-ul aplica redactare pentru date precum email, telefon, IBAN si coduri OTP unde este posibil.</p>
  </section>

  <section>
    <h2>Servicii terte</h2>
    <p>Pentru scanari declansate de utilizator, SigurScan poate folosi servicii terte prin backend:</p>
    <ul>
      <li><strong>urlscan.io</strong> pentru sandbox si preview securizat al paginii finale;</li>
      <li><strong>Google Web Risk</strong> pentru verificari de malware/phishing/social engineering;</li>
      <li><strong>VirusTotal</strong> doar ca fallback/intaritor cand este configurat cu licenta potrivita;</li>
      <li><strong>Supabase</strong> pentru evenimente agregate, feedback si campanii comunitare;</li>
      <li>provider AI optional pentru explicatii, cu fallback local cand este dezactivat.</li>
    </ul>
  </section>

  <section>
    <h2>Ce nu facem</h2>
    <ul>
      <li>nu monitorizam automat inbox, SMS-uri, notificari sau clipboard;</li>
      <li>nu cerem permisiuni de citire SMS, contacte, apeluri sau media larga;</li>
      <li>nu vindem date personale;</li>
      <li>nu trimitem scanari fara actiunea explicita a utilizatorului.</li>
    </ul>
  </section>

  <section>
    <h2>Securitate si retentie</h2>
    <p>Comunicarea cu backend-ul se face prin HTTPS. Cheile providerilor nu sunt incluse in aplicatia Android de productie. Cache-ul de reputatie foloseste hash-uri si TTL-uri pentru a reduce apelurile repetate la provideri.</p>
  </section>

  <section>
    <h2>Contact</h2>
    <p>Pentru solicitari privind confidentialitatea sau stergerea feedbackului trimis, contacteaza echipa SigurScan la <code>privacy@sigurscan.ro</code>.</p>
  </section>
</main>
</body>
</html>"""


@app.get("/privacy", response_class=HTMLResponse)
@app.get("/privacy-policy", response_class=HTMLResponse)
def privacy_policy() -> HTMLResponse:
    return HTMLResponse(content=PRIVACY_POLICY_HTML)


@app.get("/health")
@app.get("/healthz")
def read_health():
    return {
        "status": "ok",
        "service": "SigurScan API",
        "version": "1.0",
        "timestamp": int(time.time()),
        "config": _provider_config_status(),
    }


def _require_urlscan_key() -> None:
    if PRIVACY_SAFE_MODE:
        raise HTTPException(
            status_code=503,
            detail="Sandbox dezactivat in SIGURSCAN_SAFE_MODE.",
        )
    if not URLSCAN_API_KEY:
        raise HTTPException(
            status_code=503,
            detail="urlscan.io nu este configurat pe backend.",
        )


def _validate_sandbox_url(raw_url: str) -> str:
    url = _canonicalize_url(_normalise_obfuscated_text(raw_url or ""))
    if not url:
        raise HTTPException(status_code=400, detail="URL invalid sau format neacceptat.")
    blocked_reason = _is_scan_target_blocked(url)
    if blocked_reason:
        raise HTTPException(status_code=400, detail=f"URL blocat pentru sandbox: {blocked_reason}")
    return url


def _safe_urlscan_visibility(raw_visibility: str | None) -> str:
    visibility = (raw_visibility or URLSCAN_VISIBILITY_DEFAULT or "private").strip().lower()
    if visibility not in {"private", "unlisted", "public"}:
        return "private"
    # Public submissions can expose user URLs. Keep backend default privacy-first.
    return "unlisted" if visibility == "public" else visibility


def _urlscan_headers() -> Dict[str, str]:
    return {
        "api-key": URLSCAN_API_KEY,
        "accept": "application/json",
    }


def _safe_urlscan_tag(raw_tag: Any) -> Optional[str]:
    tag = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(raw_tag or "").strip().lower())
    tag = re.sub(r"-{2,}", "-", tag).strip("-._")
    if not tag:
        return None
    # urlscan.io rejects tags longer than 30 chars with HTTP 400. Keep tags observability-only.
    return tag[:30].strip("-._") or None


def _urlscan_tags(source_channel: Optional[str]) -> List[str]:
    tags: List[str] = []
    for raw_tag in ("sigurscan", "android", source_channel or "android_native"):
        tag = _safe_urlscan_tag(raw_tag)
        if tag and tag not in tags:
            tags.append(tag)
    return tags


def _urlscan_error_detail(response: requests.Response) -> str:
    detail = f"urlscan.io submission failed: HTTP {response.status_code}"
    try:
        body = response.json()
    except Exception:
        body = None
    message = None
    if isinstance(body, dict):
        message = body.get("message") or body.get("description") or body.get("detail")
    if not message:
        try:
            message = (response.text or "").strip()
        except Exception:
            message = ""
    if message:
        safe_message = re.sub(r"\s+", " ", str(message))[:240]
        detail = f"{detail}: {safe_message}"
    return detail


def _urlscan_report_url(uuid: str) -> str:
    return f"https://urlscan.io/result/{uuid}/"


def _urlscan_direct_screenshot_url(uuid: str) -> str:
    safe_uuid = re.sub(r"[^A-Za-z0-9._-]", "", uuid or "")
    return f"https://urlscan.io/screenshots/{safe_uuid}.png"


async def _urlscan_screenshot_is_ready(uuid: str) -> bool:
    safe_uuid = re.sub(r"[^A-Za-z0-9._-]", "", uuid or "")
    if not safe_uuid:
        return False

    def fetch_headline() -> bool:
        response = requests.get(
            _urlscan_direct_screenshot_url(safe_uuid),
            headers={"api-key": URLSCAN_API_KEY},
            timeout=min(URLSCAN_TIMEOUT_SECONDS, 4.0),
            stream=True,
        )
        try:
            content_type = (response.headers.get("content-type") or "").lower()
            return response.status_code < 400 and ("image/" in content_type or "png" in content_type)
        finally:
            close = getattr(response, "close", None)
            if callable(close):
                close()

    return bool(await run_in_threadpool(fetch_headline))


def _summarize_urlscan_payload(payload: Dict[str, Any], uuid: str, request: Request) -> Dict[str, Any]:
    page = payload.get("page") if isinstance(payload.get("page"), dict) else {}
    task = payload.get("task") if isinstance(payload.get("task"), dict) else {}
    verdicts = payload.get("verdicts") if isinstance(payload.get("verdicts"), dict) else {}
    overall = verdicts.get("overall") if isinstance(verdicts.get("overall"), dict) else {}
    urlscan = verdicts.get("urlscan") if isinstance(verdicts.get("urlscan"), dict) else {}
    brands = payload.get("brands") if isinstance(payload.get("brands"), list) else []
    lists = overall.get("categories") or urlscan.get("categories") or []
    if not isinstance(lists, list):
        lists = []

    malicious = bool(overall.get("malicious") or urlscan.get("malicious"))
    suspicious = bool(overall.get("suspicious") or urlscan.get("suspicious"))
    score = int(overall.get("score") or urlscan.get("score") or 0)
    categories = [str(item) for item in lists if item]

    if malicious:
        verdict = "Malicious phishing" if any("phish" in item.lower() for item in categories) else "Malicious"
        severity = "high"
    elif suspicious or score >= 50:
        verdict = "Suspicious"
        severity = "medium"
    else:
        verdict = "No malicious classification"
        severity = "low"

    final_url = page.get("url") or task.get("url")
    server = page.get("server")
    ip_address = page.get("ip")
    country = page.get("country")
    detail_parts = [
        f"urlscan verdict={verdict}",
        f"score={score}",
    ]
    if categories:
        detail_parts.append(f"categories={','.join(categories[:4])}")
    if brands:
        detail_parts.append(f"brands={','.join(str(item) for item in brands[:4])}")
    if ip_address:
        detail_parts.append(f"ip={ip_address}")
    if country:
        detail_parts.append(f"country={country}")
    if server:
        detail_parts.append(f"server={server}")

    return {
        "uuid": uuid,
        "status": "finished",
        "verdict": verdict,
        "severity": severity,
        "details": "; ".join(detail_parts),
        "final_url": final_url,
        "report_url": _urlscan_report_url(uuid),
        "screenshot_url": str(request.url_for("urlscan_screenshot", uuid=uuid)),
        "score": score,
        "categories": categories,
        "brands": brands[:4],
    }


ORCHESTRATED_JOB_TTL_SECONDS = int(os.getenv("ORCHESTRATED_JOB_TTL_SECONDS", "900"))
ORCHESTRATED_URLSCAN_PENDING_TIMEOUT_SECONDS = int(
    os.getenv("ORCHESTRATED_URLSCAN_PENDING_TIMEOUT_SECONDS", "120")
)
ORCHESTRATED_REQUIRED_PILLAR_TIMEOUT_SECONDS = int(
    os.getenv("ORCHESTRATED_REQUIRED_PILLAR_TIMEOUT_SECONDS", "90")
)
ORCHESTRATED_URLSCAN_SUBMIT_RESERVATION_TIMEOUT_SECONDS = int(
    os.getenv("ORCHESTRATED_URLSCAN_SUBMIT_RESERVATION_TIMEOUT_SECONDS", "30")
)
_ORCHESTRATED_SCAN_JOBS: Dict[str, Dict[str, Any]] = {}
_ORCHESTRATED_SCAN_LOCKS: Dict[str, asyncio.Lock] = {}


_ORCHESTRATED_STAGE_RANK = {
    "queued": 0,
    "resolved": 10,
    "reputation_ready": 20,
    "semantic_ready": 25,
    "claim_ready": 28,
    "analysis_ready": 30,
    "urlscan_submitting": 35,
    "urlscan_submitted": 40,
    "done": 100,
}


def _orchestrated_stage_rank(stage: Any) -> int:
    return _ORCHESTRATED_STAGE_RANK.get(str(stage or "").strip().lower(), -1)


def _orchestrated_metrics(job: Dict[str, Any]) -> Dict[str, Any]:
    metrics = job.get("orchestration_metrics")
    if not isinstance(metrics, dict):
        metrics = {}
        job["orchestration_metrics"] = metrics
    metrics.setdefault("poll_count", 0)
    metrics.setdefault("stage_durations_ms", {})
    metrics.setdefault("stage_sequence", [])
    metrics.setdefault("conflict_merge_count", 0)
    metrics.setdefault("conflict_merge_retry_count", 0)
    metrics.setdefault("conflict_merge_retry_failures", 0)
    metrics.setdefault("urlscan_reclaim_count", 0)
    metrics.setdefault("urlscan_reservation_guard_hits", 0)
    metrics.setdefault("urlscan_timeout_count", 0)
    metrics.setdefault("stage_entered_at", int(job.get("created_at") or int(time.time())))
    return metrics


def _increment_orchestrated_metric(job: Dict[str, Any], key: str, amount: int = 1) -> None:
    metrics = _orchestrated_metrics(job)
    try:
        metrics[key] = int(metrics.get(key, 0) or 0) + int(amount)
    except Exception:
        metrics[key] = int(amount)


def _set_orchestrated_stage(job: Dict[str, Any], next_stage: str) -> None:
    if not isinstance(job, dict):
        return
    next_stage = str(next_stage or "").strip().lower() or "queued"
    now = int(time.time())
    metrics = _orchestrated_metrics(job)
    previous_stage = str(job.get("pipeline_stage") or "").strip().lower()
    previous_entered_at = int(metrics.get("stage_entered_at") or job.get("created_at") or now)
    if previous_stage and previous_stage != next_stage:
        durations = metrics.setdefault("stage_durations_ms", {})
        durations[previous_stage] = int(durations.get(previous_stage, 0) or 0) + max(0, now - previous_entered_at) * 1000
        metrics["stage_entered_at"] = now
        sequence = metrics.setdefault("stage_sequence", [])
        if isinstance(sequence, list):
            sequence.append({"stage": next_stage, "at": now})
    elif not previous_stage:
        metrics["stage_entered_at"] = now
        sequence = metrics.setdefault("stage_sequence", [])
        if isinstance(sequence, list):
            sequence.append({"stage": next_stage, "at": now})
    job["pipeline_stage"] = next_stage


def _emit_orchestrated_telemetry(event_type: str, job: Dict[str, Any], **metadata: Any) -> None:
    if not isinstance(job, dict):
        return
    scan_id = str(job.get("scan_id") or "").strip()
    if not scan_id:
        return
    try:
        metrics = _orchestrated_metrics(job)
        urlscan_state = job.get("urlscan") if isinstance(job.get("urlscan"), dict) else {}
        log_scan_event(
            {
                "scan_id": scan_id,
                "event_type": event_type,
                "input_type": job.get("input_type", "unknown"),
                "source_channel": job.get("source_channel"),
                "risk_score": 0,
                "risk_level": None,
                "url_count": len(job.get("urls") if isinstance(job.get("urls"), list) else []),
                "metadata": {
                    "pipeline_stage": job.get("pipeline_stage"),
                    "status": job.get("status"),
                    "poll_count": metrics.get("poll_count"),
                    "age_ms": max(0, int(time.time()) - int(job.get("created_at") or int(time.time()))) * 1000,
                    "stage_durations_ms": metrics.get("stage_durations_ms", {}),
                    "urlscan_status": urlscan_state.get("status"),
                    "urlscan_uuid": urlscan_state.get("uuid"),
                    "conflict_merge_count": metrics.get("conflict_merge_count", 0),
                    "conflict_merge_retry_count": metrics.get("conflict_merge_retry_count", 0),
                    "conflict_merge_retry_failures": metrics.get("conflict_merge_retry_failures", 0),
                    "urlscan_reclaim_count": metrics.get("urlscan_reclaim_count", 0),
                    "urlscan_reservation_guard_hits": metrics.get("urlscan_reservation_guard_hits", 0),
                    "urlscan_timeout_count": metrics.get("urlscan_timeout_count", 0),
                    **metadata,
                },
            }
        )
    except Exception:
        return


def _deep_copy_jsonable(value: Any) -> Any:
    try:
        return json.loads(json.dumps(value))
    except Exception:
        return value


def _merge_missing_dict_values(target: Dict[str, Any], source: Dict[str, Any]) -> None:
    for key, value in source.items():
        if value in (None, "", [], {}):
            continue
        current = target.get(key)
        if current in (None, "", [], {}):
            target[key] = _deep_copy_jsonable(value)


def _merge_orchestrated_conflict_job(reloaded: Dict[str, Any], local: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(reloaded)
    local_urlscan = local.get("urlscan") if isinstance(local.get("urlscan"), dict) else {}
    local_is_unpersisted_urlscan_reservation = (
        str(local_urlscan.get("status") or "").strip().lower() == "submitting"
        and not local_urlscan.get("uuid")
    )

    if (
        not local_is_unpersisted_urlscan_reservation
        and _orchestrated_stage_rank(local.get("pipeline_stage")) > _orchestrated_stage_rank(merged.get("pipeline_stage"))
    ):
        merged["pipeline_stage"] = local.get("pipeline_stage")

    for key in ("resolved_urls", "primary_final_url", "threat_intel", "analysis", "result", "claim_verifier_required"):
        local_value = local.get(key)
        if local_value not in (None, "", [], {}) and merged.get(key) in (None, "", [], {}):
            merged[key] = _deep_copy_jsonable(local_value)

    merged_urlscan = merged.get("urlscan") if isinstance(merged.get("urlscan"), dict) else {}
    if local_urlscan and not local_is_unpersisted_urlscan_reservation:
        merged_urlscan = dict(merged_urlscan)
        local_has_uuid = bool(local_urlscan.get("uuid"))
        merged_has_uuid = bool(merged_urlscan.get("uuid"))
        if local_has_uuid and not merged_has_uuid:
            merged_urlscan = _deep_copy_jsonable(local_urlscan)
        else:
            _merge_missing_dict_values(merged_urlscan, local_urlscan)
        merged["urlscan"] = merged_urlscan

    local_preview = local.get("preview") if isinstance(local.get("preview"), dict) else {}
    if local_preview:
        merged_preview = dict(merged.get("preview") if isinstance(merged.get("preview"), dict) else {})
        _merge_missing_dict_values(merged_preview, local_preview)
        merged["preview"] = merged_preview

    local_metrics = local.get("orchestration_metrics") if isinstance(local.get("orchestration_metrics"), dict) else {}
    if local_metrics:
        merged_metrics = dict(merged.get("orchestration_metrics") if isinstance(merged.get("orchestration_metrics"), dict) else {})
        for key, value in local_metrics.items():
            if key == "stage_durations_ms" and isinstance(value, dict):
                durations = dict(merged_metrics.get("stage_durations_ms") if isinstance(merged_metrics.get("stage_durations_ms"), dict) else {})
                for stage_name, duration_ms in value.items():
                    try:
                        durations[str(stage_name)] = max(int(durations.get(stage_name, 0) or 0), int(duration_ms))
                    except Exception:
                        continue
                merged_metrics["stage_durations_ms"] = durations
            elif key == "stage_sequence" and isinstance(value, list):
                existing_sequence = merged_metrics.get("stage_sequence")
                if not isinstance(existing_sequence, list) or len(value) > len(existing_sequence):
                    merged_metrics["stage_sequence"] = _deep_copy_jsonable(value)
            else:
                try:
                    merged_metrics[key] = max(int(merged_metrics.get(key, 0) or 0), int(value))
                except Exception:
                    if merged_metrics.get(key) in (None, "", [], {}):
                        merged_metrics[key] = _deep_copy_jsonable(value)
        merged["orchestration_metrics"] = merged_metrics

    return merged


def _orchestrated_result_fingerprint(
    job: Dict[str, Any],
    analysis: Dict[str, Any],
    pillars: Dict[str, Dict[str, Any]],
    resolved_urls: List[Dict[str, Any]],
) -> str:
    payload = {
        "redacted_text": job.get("redacted_text", ""),
        "analysis": analysis,
        "pillars": pillars,
        "resolved_urls": resolved_urls,
        "primary_final_url": job.get("primary_final_url"),
        "urlscan": job.get("urlscan") if isinstance(job.get("urlscan"), dict) else {},
    }
    serialized = json.dumps(payload, sort_keys=True, default=str, ensure_ascii=False)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _sync_resolved_urls_with_urlscan_final(job: Dict[str, Any]) -> None:
    if not isinstance(job, dict):
        return
    analysis = job.get("analysis") if isinstance(job.get("analysis"), dict) else {}
    evidence = analysis.get("evidence", {}) if isinstance(analysis.get("evidence"), dict) else {}
    summary = evidence.get("external_intel_summary") if isinstance(evidence.get("external_intel_summary"), dict) else {}
    urlscan_summary = summary.get("urlscan") if isinstance(summary.get("urlscan"), dict) else {}
    preview = job.get("preview") if isinstance(job.get("preview"), dict) else {}
    final_url = str(urlscan_summary.get("final_url") or preview.get("final_url") or "").strip()
    if not final_url:
        return

    parsed = urllib.parse.urlparse(final_url)
    final_hostname = (parsed.hostname or "").lower()
    final_registered_domain = _extract_domain_root(final_hostname)
    resolved_urls = job.get("resolved_urls") if isinstance(job.get("resolved_urls"), list) else []
    if not resolved_urls:
        original_url = (job.get("urls") or [final_url])[0] if isinstance(job.get("urls"), list) and job.get("urls") else final_url
        resolved_urls = [{"url": original_url, "original_url": original_url}]
        job["resolved_urls"] = resolved_urls
    if resolved_urls:
        entry = resolved_urls[0]
        if isinstance(entry, dict):
            entry["final_url"] = final_url
            entry["final_hostname"] = final_hostname
            entry["final_registered_domain"] = final_registered_domain
            if not entry.get("hostname"):
                original_url = str(entry.get("url") or entry.get("original_url") or "")
                entry["hostname"] = (urllib.parse.urlparse(original_url).hostname or "").lower()
            if not entry.get("registered_domain"):
                entry["registered_domain"] = _extract_domain_root(entry.get("hostname"))
    job["primary_final_url"] = final_url
    extra_fields = job.setdefault("extra_fields", {})
    if isinstance(extra_fields, dict):
        extra_fields["resolved_urls"] = resolved_urls


def _persist_orchestrated_job(job: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(job, dict) or not job.get("scan_id"):
        return job
    scan_id = str(job["scan_id"])
    saved = supabase_store.save_scan_job(job)
    if saved is False:
        _increment_orchestrated_metric(job, "conflict_merge_count")
        reloaded = supabase_store.load_scan_job(scan_id)
        if isinstance(reloaded, dict):
            merged = _merge_orchestrated_conflict_job(reloaded, job)
            if merged != reloaded:
                retry_saved = False
                for _ in range(2):
                    _increment_orchestrated_metric(merged, "conflict_merge_retry_count")
                    retry_saved = supabase_store.save_scan_job(merged)
                    if retry_saved is not False:
                        break
                    latest = supabase_store.load_scan_job(scan_id)
                    if isinstance(latest, dict):
                        merged = _merge_orchestrated_conflict_job(latest, merged)
                if retry_saved is False:
                    _increment_orchestrated_metric(merged, "conflict_merge_retry_failures")
                _emit_orchestrated_telemetry(
                    "orchestrated_conflict_merge",
                    merged,
                    retry_saved=retry_saved is not False,
                )
            _ORCHESTRATED_SCAN_JOBS[scan_id] = merged
            return merged
        return job
    _ORCHESTRATED_SCAN_JOBS[scan_id] = job
    return job


def _load_orchestrated_job(scan_id: str) -> Optional[Dict[str, Any]]:
    job = supabase_store.load_scan_job(scan_id)
    if isinstance(job, dict):
        _ORCHESTRATED_SCAN_JOBS[scan_id] = job
        return job
    job = _ORCHESTRATED_SCAN_JOBS.get(scan_id)
    if isinstance(job, dict):
        return job
    return None


def _prune_orchestrated_jobs() -> None:
    now = int(time.time())
    expired = [
        scan_id
        for scan_id, job in _ORCHESTRATED_SCAN_JOBS.items()
        if now - int(job.get("created_at", now)) > ORCHESTRATED_JOB_TTL_SECONDS
    ]
    for scan_id in expired:
        _ORCHESTRATED_SCAN_JOBS.pop(scan_id, None)
        _ORCHESTRATED_SCAN_LOCKS.pop(scan_id, None)


def _pillar(status: str, *, required: bool = True, details: str = "", ref: Optional[str] = None) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "status": status,
        "required": bool(required),
    }
    if details:
        payload["details"] = details
    if ref:
        payload["ref"] = ref
    return payload


def _provider_pillar_from_summary(summary: Dict[str, Any], source_name: str) -> Dict[str, Any]:
    raw = summary.get(source_name)
    if not isinstance(raw, dict):
        return _pillar("pending", details=f"{source_name} asteapta scanarea.")
    status = _source_status(summary, source_name)
    consulted = bool(raw.get("consulted", False))
    if consulted and status not in {"missing", "unknown", "error"}:
        return _pillar("ok", details=status)
    if status == "error":
        return _pillar("error", details=str(raw.get("error") or raw.get("details") or "provider error"))
    return _pillar("pending" if not consulted else "error", details=status or "unknown")


def _urlscan_scan_prevented(details: Any) -> bool:
    try:
        if isinstance(details, dict):
            details_text = json.dumps(details, ensure_ascii=False)
        else:
            details_text = str(details or "")
    except Exception:
        details_text = str(details or "")
    normalized = details_text.strip().lower()
    return "scan prevented" in normalized or "submission blocked" in normalized


def _claim_verifier_required(analysis: Dict[str, Any]) -> bool:
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


def _build_orchestrated_pillars(job: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    analysis = job.get("analysis") if isinstance(job.get("analysis"), dict) else {}
    evidence = analysis.get("evidence", {}) if isinstance(analysis.get("evidence"), dict) else {}
    summary = evidence.get("external_intel_summary") if isinstance(evidence.get("external_intel_summary"), dict) else {}
    resolved_urls = job.get("resolved_urls") if isinstance(job.get("resolved_urls"), list) else []
    raw_urls = job.get("urls") if isinstance(job.get("urls"), list) else []
    has_urls = bool(raw_urls or resolved_urls)
    final_url = job.get("primary_final_url") or _first_final_url(resolved_urls)

    claim = evidence.get("offer_claim_verification") if isinstance(evidence.get("offer_claim_verification"), dict) else {}
    claim_status = str(claim.get("status") or "").strip().lower()
    claim_required = bool(job.get("claim_verifier_required", _claim_verifier_required(analysis)))
    semantic_review = evidence.get("semantic_review") if isinstance(evidence.get("semantic_review"), dict) else {}
    semantic_status = str(semantic_review.get("status") or "").strip().lower()
    claimed_brand = str(analysis.get("claimed_brand") or "Nespecificat")
    official_destination = _official_destination_confirmed(resolved_urls, claimed_brand)
    provider_projection = _provider_verdict_for_decision_bundle(summary, has_urls=has_urls)
    provider_projection_verdict = str(provider_projection.get("verdict") or "unknown").strip().lower()
    semantic_complete = (
        (semantic_status == "done" and semantic_review.get("completeness") is not False)
        or provider_projection_verdict == "malicious"
        or (official_destination and provider_projection_verdict == "clean")
    )
    semantic_details = semantic_status or "atlas/corpus semantic review pending"
    if provider_projection_verdict == "malicious":
        semantic_details = "provider malicious decisive; semantic review not blocking"
    elif official_destination and provider_projection_verdict == "clean" and not semantic_status:
        semantic_details = "official clean destination accepted as legit semantic template"

    urlscan_state = job.get("urlscan") if isinstance(job.get("urlscan"), dict) else {}
    urlscan_status = str(urlscan_state.get("status") or "").strip().lower()
    screenshot_ready = bool(urlscan_state.get("screenshot_ready"))
    if urlscan_status == "finished":
        details = str(urlscan_state.get("verdict") or "finished")
        if not screenshot_ready:
            details = f"{details}; captura inca se proceseaza"
        urlscan_pillar = _pillar("ok", required=False, details=details, ref=urlscan_state.get("uuid"))
    elif urlscan_status == "skipped" and not has_urls:
        urlscan_pillar = _pillar("not_required", required=False, details="nu exista URL pentru preview")
    elif urlscan_status in {"error", "timeout", "rate_limited", "skipped"}:
        urlscan_details = str(urlscan_state.get("details") or urlscan_status)
        if official_destination and _urlscan_scan_prevented(urlscan_details):
            urlscan_pillar = _pillar(
                "ok",
                required=False,
                details="urlscan a refuzat sandbox-ul pentru o destinatie oficiala; preview indisponibil.",
                ref=urlscan_state.get("uuid"),
            )
        else:
            urlscan_pillar = _pillar("error", required=False, details=urlscan_details, ref=urlscan_state.get("uuid"))
    elif urlscan_state.get("uuid"):
        urlscan_pillar = _pillar("pending", required=False, details="urlscan verdict este in procesare.", ref=urlscan_state.get("uuid"))
    else:
        urlscan_pillar = _pillar("pending", required=False, details="urlscan verdict nu a pornit.")

    if not has_urls:
        final_url_pillar = _pillar("not_required", required=False, details="mesajul nu contine URL verificabil")
        web_risk_pillar = _pillar("not_required", required=False, details="nu exista URL pentru Web Risk")
        virustotal_pillar = _pillar("not_required", required=False, details="nu exista URL pentru VirusTotal")
    else:
        final_url_pillar = _pillar("ok" if final_url else "pending", details=str(final_url or "se rezolva destinatia finala"))
        web_risk_pillar = _provider_pillar_from_summary(summary, "google_web_risk")
        virustotal_pillar = _provider_pillar_from_summary(summary, "virustotal")

    return {
        "final_url": final_url_pillar,
        "google_web_risk": web_risk_pillar,
        "virustotal": virustotal_pillar,
        "urlscan": urlscan_pillar,
        "claim_verifier": _pillar(
            (
                "not_required"
                if not claim_required
                else "ok"
                if claim_status in {"confirmed", "not_found", "inconclusive", "skipped"}
                else "pending"
            ),
            required=claim_required,
            details=claim_status or ("required" if claim_required else "not required"),
        ),
        "semantic_review": _pillar(
            "ok" if semantic_complete else "pending",
            required=True,
            details=semantic_details,
        ),
    }


def _all_required_pillars_ok(pillars: Dict[str, Dict[str, Any]]) -> bool:
    return all(
        not pillar.get("required", True) or pillar.get("status") == "ok"
        for pillar in pillars.values()
    )


def _all_required_pillars_terminal(pillars: Dict[str, Dict[str, Any]]) -> bool:
    terminal = {"ok", "error", "timeout", "rate_limited", "skipped", "not_required"}
    return all(
        not pillar.get("required", True) or str(pillar.get("status") or "").lower() in terminal
        for pillar in pillars.values()
    )


def _has_required_pillar_error(pillars: Dict[str, Dict[str, Any]]) -> bool:
    return any(
        pillar.get("required", True) and pillar.get("status") == "error"
        for pillar in pillars.values()
    )


def _urlscan_pending_has_timed_out(job: Dict[str, Any]) -> bool:
    urlscan_state = job.get("urlscan") if isinstance(job.get("urlscan"), dict) else {}
    if str(urlscan_state.get("status") or "").strip().lower() != "pending":
        return False
    created_at = int(job.get("created_at") or int(time.time()))
    return int(time.time()) - created_at >= ORCHESTRATED_URLSCAN_PENDING_TIMEOUT_SECONDS


def _urlscan_enhancement_done(job: Dict[str, Any]) -> bool:
    raw_urls = job.get("urls") if isinstance(job.get("urls"), list) else []
    if not raw_urls:
        return True
    urlscan_state = job.get("urlscan") if isinstance(job.get("urlscan"), dict) else {}
    status = str(urlscan_state.get("status") or "").strip().lower()
    return status in {"finished", "error", "timeout", "rate_limited", "skipped"}


def _baseline_pillars_ready_without_urlscan(pillars: Dict[str, Dict[str, Any]]) -> bool:
    required_names = ("final_url", "google_web_risk", "virustotal", "claim_verifier")
    for name in required_names:
        pillar = pillars.get(name)
        if not isinstance(pillar, dict):
            return False
        if pillar.get("required", True) and pillar.get("status") != "ok":
            return False
    return True


def _orchestrated_required_pillars_timed_out(job: Dict[str, Any]) -> bool:
    created_at = int(job.get("created_at") or int(time.time()))
    return int(time.time()) - created_at >= ORCHESTRATED_REQUIRED_PILLAR_TIMEOUT_SECONDS


def _mark_required_pillars_timeout(job: Dict[str, Any]) -> Dict[str, Any]:
    analysis = job.get("analysis") if isinstance(job.get("analysis"), dict) and job.get("analysis") else {}
    if not analysis:
        analysis = {
            "risk_score": 50,
            "risk_level": "medium",
            "detected_family": "Verificare incompletă",
            "detected_family_id": "provider-gate-required-timeout",
            "claimed_brand": "Nespecificat",
            "reasons": [
                "Nu am putut finaliza piloanele obligatorii in timpul maxim permis.",
            ],
            "safe_actions": [
                "Nu introduce date sensibile până nu verifici pe canalul oficial.",
            ],
            "evidence": {
                "external_intel_summary": {},
                "provider_gate": {
                    "version": "verdict_gate_v2",
                    "risk_level": "medium",
                    "risk_score": 50,
                    "reason": "Piloanele obligatorii nu au finalizat la timp.",
                    "required_timeout": True,
                },
            },
        }
    else:
        analysis["risk_score"] = max(int(analysis.get("risk_score") or 0), 50)
        analysis["risk_level"] = "medium"
        analysis["detected_family"] = "Verificare incompletă"
        analysis["detected_family_id"] = "provider-gate-required-timeout"
        analysis["reasons"] = [
            "Nu am putut finaliza piloanele obligatorii in timpul maxim permis.",
        ]
        analysis.setdefault("evidence", {}).setdefault("provider_gate", {})["required_timeout"] = True
    job["analysis"] = analysis
    _set_orchestrated_stage(job, "done")
    _emit_orchestrated_telemetry("orchestrated_required_timeout", job)
    return job


def _first_final_url(resolved_urls: List[Dict[str, Any]]) -> Optional[str]:
    for entry in resolved_urls:
        final_url = entry.get("final_url") or entry.get("url") or entry.get("original_url")
        if isinstance(final_url, str) and final_url.strip():
            return final_url.strip()
    return None


def _select_primary_resolved_url(resolved_urls: List[Dict[str, Any]], analysis: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not resolved_urls:
        return None
    claimed_brand = str(analysis.get("claimed_brand") or "Nespecificat")

    def suspicion_score(entry: Dict[str, Any]) -> int:
        final_url = str(entry.get("final_url") or entry.get("url") or "")
        parsed = urllib.parse.urlparse(final_url)
        hostname = (entry.get("final_hostname") or parsed.hostname or "").lower()
        reg_domain = str(entry.get("final_registered_domain") or entry.get("registered_domain") or "").lower()
        score = 0
        if not engine._is_context_allowed_domain(reg_domain, hostname=hostname, claimed_brand=claimed_brand):
            score += 90
        if entry.get("uses_shortener"):
            score += 30
        try:
            score += min(int(entry.get("redirect_count") or 0), 5) * 5
        except Exception:
            pass
        if any(token in final_url.lower() for token in ("unsubscribe", "dezabon", "privacy", "terms")):
            score -= 40
        return score

    return max(resolved_urls, key=suspicion_score)


def _urlscan_provider_payload(summary: Dict[str, Any]) -> Dict[str, Any]:
    verdict = str(summary.get("verdict") or "").strip()
    severity = str(summary.get("severity") or "unknown").strip().lower()
    verdict_lower = verdict.lower()
    normalized_status = "clean"
    benign_verdict = any(
        phrase in verdict_lower
        for phrase in ("no malicious", "not malicious", "no classification", "no malicious classification")
    )
    if not benign_verdict and (
        severity == "high" or any(token in verdict_lower for token in ("malicious", "phishing", "malware"))
    ):
        normalized_status = "malicious"
    elif not benign_verdict and (severity == "medium" or "suspicious" in verdict_lower):
        normalized_status = "suspicious"

    return {
        "status": normalized_status,
        "verdict": verdict or normalized_status,
        "severity": severity or "unknown",
        "consulted": True,
        "details": summary.get("details", ""),
        "score": summary.get("score", 0),
        "final_url": summary.get("final_url"),
        "report_url": summary.get("report_url"),
        "screenshot_url": summary.get("screenshot_url"),
    }


def _orchestrated_status_payload(job: Dict[str, Any]) -> Dict[str, Any]:
    pillars = _build_orchestrated_pillars(job)
    preview = job.get("preview") if isinstance(job.get("preview"), dict) else {}
    result = job.get("result") if isinstance(job.get("result"), dict) else None
    if result is not None and result.get("is_final", True) is not False:
        status = "complete"
    elif _has_required_pillar_error(pillars):
        status = "incomplete"
    else:
        status = "scanning"
    job["status"] = status
    return {
        "scan_id": job["scan_id"],
        "status": status,
        "status_message": (
            "Scanarea este finalizata."
            if status == "complete"
            else "Scanarea continua pana cand pilonii necesari returneaza date."
            if status == "scanning"
            else "Scanarea nu are toti pilonii necesari pentru verdict sigur."
        ),
        "pillars": pillars,
        "preview": preview,
        "result": result,
    }


def _orchestrated_can_finalize_result(job: Dict[str, Any], pillars: Dict[str, Dict[str, Any]]) -> bool:
    if str(job.get("pipeline_stage") or "").strip().lower() == "done":
        return True
    return _all_required_pillars_terminal(pillars)


def _orchestrated_result_is_final(job: Dict[str, Any], analysis: Dict[str, Any]) -> bool:
    evidence = analysis.get("evidence", {}) if isinstance(analysis.get("evidence"), dict) else {}
    gate = evidence.get("verdict_gate") if isinstance(evidence.get("verdict_gate"), dict) else {}
    return str(gate.get("label") or "").upper() in {"SIGUR", "SUSPECT", "PERICULOS"}


async def _finalize_orchestrated_job_if_ready(job: Dict[str, Any], request: Request) -> Dict[str, Any]:
    _sync_resolved_urls_with_urlscan_final(job)
    pillars = _build_orchestrated_pillars(job)
    existing_result = job.get("result") if isinstance(job.get("result"), dict) else None
    if existing_result and existing_result.get("is_final", True) is not False:
        if not _urlscan_enhancement_done(job):
            return job
    if not _orchestrated_can_finalize_result(job, pillars):
        return job

    analysis = job.get("analysis") if isinstance(job.get("analysis"), dict) else {}
    resolved_urls = job.get("resolved_urls") if isinstance(job.get("resolved_urls"), list) else []
    _apply_provider_gate_verdict(
        analysis,
        resolved_urls,
        raw_text=str(job.get("redacted_text") or ""),
        pillars=pillars,
    )
    evidence = analysis.get("evidence", {}) if isinstance(analysis.get("evidence"), dict) else {}
    gate = evidence.get("verdict_gate") if isinstance(evidence.get("verdict_gate"), dict) else {}
    if str(gate.get("label") or "").upper() == "PENDING":
        if existing_result and existing_result.get("is_final", True) is not False:
            _emit_orchestrated_telemetry("orchestrated_verdict_pending_preserved_final", job)
            return job
        job.pop("result", None)
        job.pop("result_fingerprint", None)
        _emit_orchestrated_telemetry("orchestrated_verdict_pending", job)
        return job
    fingerprint = _orchestrated_result_fingerprint(job, analysis, pillars, resolved_urls)
    if existing_result and job.get("result_fingerprint") == fingerprint:
        return job

    explanation_cache = job.get("ai_explanation_cache") if isinstance(job.get("ai_explanation_cache"), dict) else {}
    ai_explanation = explanation_cache.get("payload") if explanation_cache.get("fingerprint") == fingerprint else None
    if not isinstance(ai_explanation, dict):
        ai_explanation = await _build_ai_explanation_async(job.get("redacted_text", ""), analysis, resolved_urls)
        job["ai_explanation_cache"] = {
            "fingerprint": fingerprint,
            "payload": ai_explanation,
        }
    scan_id = job["scan_id"]
    response_payload = _build_scan_response(
        "scan",
        analysis,
        job.get("redacted_text", ""),
        ai_explanation,
        scan_id=scan_id,
        extra_fields=job.get("extra_fields") if isinstance(job.get("extra_fields"), dict) else {},
    )
    response_payload.setdefault("evidence", {}).setdefault("orchestration", {})
    response_payload["evidence"]["orchestration"] = {
        "pillars": pillars,
        "preview": job.get("preview", {}),
    }
    response_payload["is_final"] = _orchestrated_result_is_final(job, analysis)
    job["result"] = response_payload
    job["result_fingerprint"] = fingerprint
    _emit_orchestrated_telemetry(
        "orchestrated_verdict_final",
        job,
        user_risk_label=response_payload.get("user_risk_label"),
        risk_level=response_payload.get("risk_level"),
        result_fingerprint=fingerprint,
    )
    _emit_scan_event(
        scan_id=scan_id,
        scan_payload=response_payload,
        analysis=analysis,
        resolved_urls=resolved_urls,
        input_channel=job.get("input_type", "text"),
        source_channel=job.get("source_channel"),
    )
    return job


async def _submit_orchestrated_urlscan(
    url: str,
    payload: OrchestratedScanRequest,
    request: Request,
) -> Dict[str, Any]:
    try:
        submission = await submit_urlscan_sandbox(
            UrlscanSandboxRequest(
                url=url,
                visibility=payload.visibility,
                country=payload.country,
                customagent=payload.customagent,
                source_channel=payload.source_channel,
            ),
            request,
        )
        return {
            "uuid": submission.get("uuid"),
            "status": "pending",
            "submitted_url": submission.get("submitted_url") or url,
            "report_url": submission.get("report_url"),
            "result_url": submission.get("result_url"),
            "screenshot_url": submission.get("screenshot_url"),
        }
    except HTTPException as exc:
        return {
            "status": "error",
            "details": str(exc.detail),
            "submitted_url": url,
        }


def _build_orchestrated_text_context(payload: OrchestratedScanRequest) -> Dict[str, Any]:
    input_type = (payload.input_type or "text").strip().lower()
    source_channel = payload.source_channel or "android_native"

    if input_type == "url":
        url = _canonicalize_url(_normalise_obfuscated_text(payload.url or payload.text or ""))
        if not url:
            raise HTTPException(status_code=400, detail="URL invalid sau format neacceptat.")
        return {
            "input_type": "url",
            "source_channel": source_channel,
            "raw_text": f"Link: {url}",
            "urls": [url],
            "extra_fields": {"input_url": payload.url or payload.text, "canonical_url": url},
        }

    if input_type in {"email", "email_html", "html"}:
        html_to_parse = _normalise_obfuscated_text(payload.html_content or payload.text or "")
        _validate_text_input("Conținutul HTML trimis", html_to_parse, MAX_TEXT_CHARS * 8)
        soup = BeautifulSoup(html_to_parse, "html.parser")
        click_targets = _collect_click_targets_from_html(soup)
        discovered_urls: List[str] = []
        buttons: List[Dict[str, Any]] = []
        cta_words = ["verific", "confirm", "plăte", "plate", "cont", "login", "conect", "intrare", "detalii", "colet", "awb", "reactivare", "urgent"]
        for target in click_targets:
            raw_url = target.get("original_url")
            if not raw_url or raw_url in discovered_urls:
                continue
            discovered_urls.append(raw_url)
            button_text = str(target.get("button_text") or "")
            buttons.append(
                {
                    "button_text": button_text,
                    "original_url": raw_url,
                    "is_sensitive_cta": any(word in button_text.lower() for word in cta_words),
                    "source_tag": target.get("source_tag"),
                    "source_attr": target.get("source_attr"),
                }
            )
        visible_text = soup.get_text(separator=" ", strip=True)
        for url in extract_urls(visible_text):
            if url not in discovered_urls:
                discovered_urls.append(url)
        inferred_brand_hints = _infer_brand_hints_from_click_targets(click_targets)
        raw_text = "\n".join(part for part in [visible_text, " ".join(inferred_brand_hints)] if part.strip())
        return {
            "input_type": "email",
            "source_channel": source_channel,
            "raw_text": raw_text,
            "urls": discovered_urls,
            "extra_fields": {
                "buttons": buttons,
                "inferred_brand_hints": inferred_brand_hints,
                "is_forwarded_warning": True,
            },
        }

    raw_text = _normalise_obfuscated_text((payload.text or payload.url or "").strip())
    _validate_text_input("Textul trimis", raw_text, MAX_TEXT_CHARS)
    return {
        "input_type": "text",
        "source_channel": source_channel,
        "raw_text": raw_text,
        "urls": extract_urls(raw_text),
        "extra_fields": {},
    }


async def _create_orchestrated_job(payload: OrchestratedScanRequest) -> Dict[str, Any]:
    context = _build_orchestrated_text_context(payload)
    redacted_text = redact_pii(context["raw_text"])
    scan_id = _new_scan_id("orch")
    urls = list(context.get("urls") or [])
    extra_fields = dict(context.get("extra_fields") or {})
    extra_fields.update(
        {
            "resolved_urls": [],
            "orchestrated": True,
        }
    )
    job = {
        "scan_id": scan_id,
        "created_at": int(time.time()),
        "expires_at": int(time.time()) + ORCHESTRATED_JOB_TTL_SECONDS,
        "status": "scanning",
        "pipeline_stage": "queued",
        "input_type": context["input_type"],
        "source_channel": context["source_channel"],
        "urls": urls,
        "redacted_text": redacted_text,
        "analysis": {},
        "resolved_urls": [],
        "primary_final_url": None,
        "claim_verifier_required": False,
        "urlscan": (
            {"status": "queued", "details": "urlscan preview asteapta rezolvarea URL-ului."}
            if urls
            else {"status": "skipped", "details": "Nu exista URL pentru preview."}
        ),
        "preview": {
            "screenshot_url": None,
            "report_url": None,
            "final_url": None,
        },
        "extra_fields": extra_fields,
        "sandbox_options": {
            "visibility": payload.visibility,
            "country": payload.country,
            "customagent": payload.customagent,
        },
        "orchestration_metrics": {
            "poll_count": 0,
            "stage_entered_at": int(time.time()),
            "stage_sequence": [{"stage": "queued", "at": int(time.time())}],
            "stage_durations_ms": {},
            "conflict_merge_count": 0,
            "conflict_merge_retry_count": 0,
            "conflict_merge_retry_failures": 0,
            "urlscan_reclaim_count": 0,
            "urlscan_reservation_guard_hits": 0,
            "urlscan_timeout_count": 0,
        },
    }
    job = _persist_orchestrated_job(job)
    _emit_orchestrated_telemetry("orchestrated_created", job)
    return job


async def _refresh_orchestrated_job(job: Dict[str, Any], request: Request) -> Dict[str, Any]:
    _increment_orchestrated_metric(job, "poll_count")
    stage = str(job.get("pipeline_stage") or "queued").strip().lower()
    _emit_orchestrated_telemetry("orchestrated_poll", job, stage=stage)
    existing_result = job.get("result") if isinstance(job.get("result"), dict) else None
    if not existing_result and _orchestrated_required_pillars_timed_out(job):
        job = _mark_required_pillars_timeout(job)
        return await _finalize_orchestrated_job_if_ready(job, request)

    if stage == "queued":
        urls = job.get("urls") if isinstance(job.get("urls"), list) else []
        resolved_urls = _safe_scan_url_list([str(url) for url in urls if str(url).strip()])
        job["resolved_urls"] = resolved_urls
        job.setdefault("extra_fields", {})["resolved_urls"] = resolved_urls
        _set_orchestrated_stage(job, "resolved")
        job = _persist_orchestrated_job(job)
        _emit_orchestrated_telemetry("orchestrated_stage_resolved", job)
        return job

    if stage == "resolved":
        redacted_text = str(job.get("redacted_text") or "")
        resolved_urls = job.get("resolved_urls") if isinstance(job.get("resolved_urls"), list) else []
        threat_intel = _gather_external_intel_safe(
            resolved_urls,
            include_virustotal=True,
            include_urlhaus=False,
            persist_partial=False,
        )
        summary = _external_intel_summary_from_threat_intel(threat_intel)
        primary_entry = _select_primary_resolved_url(resolved_urls, {"claimed_brand": "Nespecificat"})
        primary_final_url = None
        if primary_entry:
            primary_final_url = primary_entry.get("final_url") or primary_entry.get("url") or primary_entry.get("original_url")
        job["threat_intel"] = threat_intel
        job["primary_final_url"] = primary_final_url
        preview = job.setdefault("preview", {})
        preview["final_url"] = primary_final_url

        if _has_bad_provider_verdict(summary):
            analysis = _provider_reputation_context_analysis(redacted_text, resolved_urls, summary)
            analysis.setdefault("evidence", {})["source_channel"] = job.get("source_channel")
            await _enrich_semantic_review_async(redacted_text, analysis, resolved_urls)
            _attach_offer_claim_verification(
                analysis,
                _skipped_offer_claim_payload("Claim web check skipped because hard reputation evidence is already decisive."),
            )
            job["analysis"] = analysis
            job["claim_verifier_required"] = False
            _set_orchestrated_stage(job, "analysis_ready")
            job = _persist_orchestrated_job(job)
            _emit_orchestrated_telemetry("orchestrated_stage_analysis_ready", job, decisive_provider=True)
            return await _finalize_orchestrated_job_if_ready(job, request)

        job["analysis"] = {
            "risk_score": 0,
            "risk_level": "low",
            "detected_family": "Reputatie in curs",
            "detected_family_id": "provider-gate-reputation-ready",
            "claimed_brand": "Nespecificat",
            "reasons": [],
            "safe_actions": [],
            "evidence": {
                "external_intel_summary": summary,
                "source_channel": job.get("source_channel"),
            },
        }
        job["claim_verifier_required"] = False
        _set_orchestrated_stage(job, "reputation_ready")
        job = _persist_orchestrated_job(job)
        _emit_orchestrated_telemetry("orchestrated_stage_reputation_ready", job)
        return job

    if stage == "reputation_ready":
        redacted_text = str(job.get("redacted_text") or "")
        resolved_urls = job.get("resolved_urls") if isinstance(job.get("resolved_urls"), list) else []
        threat_intel = job.get("threat_intel") if isinstance(job.get("threat_intel"), dict) else None
        analysis = _analyze_with_reputation(
            redacted_text,
            resolved_urls,
            fast_reputation=True,
            threat_intel_override=threat_intel,
        )
        analysis.setdefault("evidence", {})["source_channel"] = job.get("source_channel")
        claim_required = _claim_verifier_required(analysis)

        primary_entry = _select_primary_resolved_url(resolved_urls, analysis)
        primary_final_url = None
        if primary_entry:
            primary_final_url = primary_entry.get("final_url") or primary_entry.get("url") or primary_entry.get("original_url")

        job["analysis"] = analysis
        job["claim_verifier_required"] = claim_required
        job["primary_final_url"] = primary_final_url
        preview = job.setdefault("preview", {})
        preview["final_url"] = primary_final_url
        _set_orchestrated_stage(job, "semantic_ready")
        job = _persist_orchestrated_job(job)
        _emit_orchestrated_telemetry("orchestrated_stage_semantic_ready", job, claim_required=claim_required)
        return job

    if stage == "semantic_ready":
        redacted_text = str(job.get("redacted_text") or "")
        resolved_urls = job.get("resolved_urls") if isinstance(job.get("resolved_urls"), list) else []
        analysis = job.get("analysis") if isinstance(job.get("analysis"), dict) else {}
        await _enrich_semantic_review_async(redacted_text, analysis, resolved_urls)
        job["analysis"] = analysis
        _set_orchestrated_stage(job, "claim_ready")
        job = _persist_orchestrated_job(job)
        _emit_orchestrated_telemetry("orchestrated_stage_claim_ready", job)
        return job

    if stage == "claim_ready":
        redacted_text = str(job.get("redacted_text") or "")
        resolved_urls = job.get("resolved_urls") if isinstance(job.get("resolved_urls"), list) else []
        analysis = job.get("analysis") if isinstance(job.get("analysis"), dict) else {}
        claim_required = bool(job.get("claim_verifier_required", _claim_verifier_required(analysis)))
        evidence = analysis.get("evidence", {}) if isinstance(analysis.get("evidence"), dict) else {}
        summary = evidence.get("external_intel_summary") if isinstance(evidence.get("external_intel_summary"), dict) else {}
        if claim_required and not _has_bad_provider_verdict(summary):
            await _enrich_offer_claim_verification_async(redacted_text, analysis, resolved_urls)
        else:
            reason = (
                "Claim web check skipped because hard reputation evidence is already decisive."
                if _has_bad_provider_verdict(summary)
                else "Claim web check skipped because no concrete offer/brand claim was detected."
            )
            _attach_offer_claim_verification(analysis, _skipped_offer_claim_payload(reason))
        job["analysis"] = analysis
        job["claim_verifier_required"] = claim_required
        _set_orchestrated_stage(job, "analysis_ready")
        job = _persist_orchestrated_job(job)
        _emit_orchestrated_telemetry("orchestrated_stage_analysis_ready", job, claim_required=claim_required)
        return await _finalize_orchestrated_job_if_ready(job, request)

    if stage == "analysis_ready":
        primary_final_url = job.get("primary_final_url")
        urlscan_state = job.get("urlscan") if isinstance(job.get("urlscan"), dict) else {}
        urlscan_status = str(urlscan_state.get("status") or "").strip().lower()
        if primary_final_url and urlscan_status in {"queued", "", "skipped"}:
            submit_owner = f"urlscan_{os.urandom(6).hex()}"
            job["urlscan"] = {
                "status": "submitting",
                "submitted_url": str(primary_final_url),
                "submit_owner": submit_owner,
                "submit_started_at": int(time.time()),
                "details": "urlscan submit rezervat pentru instanta curenta.",
            }
            _set_orchestrated_stage(job, "urlscan_submitting")
            job = _persist_orchestrated_job(job)
            urlscan_state = job.get("urlscan") if isinstance(job.get("urlscan"), dict) else {}
            if urlscan_state.get("submit_owner") != submit_owner or urlscan_state.get("uuid"):
                _increment_orchestrated_metric(job, "urlscan_reservation_guard_hits")
                _emit_orchestrated_telemetry("orchestrated_urlscan_reservation_guard", job)
                return await _finalize_orchestrated_job_if_ready(job, request)

            primary_final_url = job.get("primary_final_url")
            options = job.get("sandbox_options") if isinstance(job.get("sandbox_options"), dict) else {}
            urlscan_payload = OrchestratedScanRequest(
                input_type=str(job.get("input_type") or "text"),
                source_channel=str(job.get("source_channel") or "android_native"),
                visibility=options.get("visibility") or URLSCAN_VISIBILITY_DEFAULT,
                country=options.get("country") or URLSCAN_COUNTRY_DEFAULT or None,
                customagent=options.get("customagent") or URLSCAN_CUSTOM_AGENT_DEFAULT or None,
            )
            submitted_urlscan = await _submit_orchestrated_urlscan(str(primary_final_url), urlscan_payload, request)
            submitted_urlscan["submit_owner"] = submit_owner
            submitted_urlscan["submit_started_at"] = urlscan_state.get("submit_started_at")
            job["urlscan"] = submitted_urlscan
            preview = job.setdefault("preview", {})
            preview["screenshot_url"] = None
            preview["report_url"] = job["urlscan"].get("report_url")
            preview["final_url"] = primary_final_url
        elif not primary_final_url:
            job["urlscan"] = {"status": "skipped", "details": "Nu exista URL pentru preview."}
        _set_orchestrated_stage(job, "urlscan_submitted")
        job = _persist_orchestrated_job(job)
        _emit_orchestrated_telemetry("orchestrated_urlscan_submitted", job)
        return await _finalize_orchestrated_job_if_ready(job, request)

    if stage == "urlscan_submitting":
        urlscan_state = job.get("urlscan") if isinstance(job.get("urlscan"), dict) else {}
        submit_started_at = int(urlscan_state.get("submit_started_at") or int(time.time()))
        submit_age = int(time.time()) - submit_started_at
        if (
            str(urlscan_state.get("status") or "").strip().lower() == "submitting"
            and not urlscan_state.get("uuid")
            and submit_age >= ORCHESTRATED_URLSCAN_SUBMIT_RESERVATION_TIMEOUT_SECONDS
        ):
            job["urlscan"] = {
                "status": "queued",
                "details": "Rezervarea anterioara pentru urlscan a expirat; submitul va fi reluat.",
            }
            _increment_orchestrated_metric(job, "urlscan_reclaim_count")
            _set_orchestrated_stage(job, "analysis_ready")
            job = _persist_orchestrated_job(job)
            _emit_orchestrated_telemetry("orchestrated_urlscan_reclaimed", job, submit_age_seconds=submit_age)
            return job
        return await _finalize_orchestrated_job_if_ready(job, request)

    urlscan_state = job.get("urlscan") if isinstance(job.get("urlscan"), dict) else {}
    urlscan_status = str(urlscan_state.get("status") or "").lower()
    should_refresh_urlscan = bool(urlscan_state.get("uuid")) and (
        urlscan_status in {"pending", "error", "timeout"}
        or (urlscan_status == "finished" and not urlscan_state.get("screenshot_ready"))
    )
    if should_refresh_urlscan:
        try:
            if urlscan_status == "finished" and not urlscan_state.get("screenshot_ready"):
                screenshot_ready = await _urlscan_screenshot_is_ready(str(urlscan_state["uuid"]))
                urlscan_state["screenshot_ready"] = screenshot_ready
                if screenshot_ready:
                    urlscan_state["details"] = str(urlscan_state.get("verdict") or "urlscan result este gata")
                    preview = job.setdefault("preview", {})
                    preview["screenshot_url"] = urlscan_state.get("screenshot_url") or preview.get("screenshot_url")
                job["urlscan"] = urlscan_state
                result = None
            else:
                result = await get_urlscan_result(str(urlscan_state["uuid"]), request)
        except HTTPException as exc:
            if urlscan_status not in {"finished", "timeout"}:
                urlscan_state["status"] = "error"
                urlscan_state["details"] = str(exc.detail)
            job["urlscan"] = urlscan_state
            result = None
        if result is not None:
            if str(result.get("status") or "").lower() != "pending":
                urlscan_state.update(result)
                urlscan_state["screenshot_ready"] = False
                urlscan_state["status"] = "finished"
                urlscan_state["details"] = "urlscan result este gata, dar captura inca se proceseaza."
                job["urlscan"] = urlscan_state
                preview = job.setdefault("preview", {})
                preview["screenshot_url"] = preview.get("screenshot_url")
                preview["report_url"] = result.get("report_url") or preview.get("report_url")
                preview["final_url"] = result.get("final_url") or preview.get("final_url")
                if result.get("final_url"):
                    job["primary_final_url"] = result.get("final_url")
                    resolved_urls = job.get("resolved_urls") if isinstance(job.get("resolved_urls"), list) else []
                    if resolved_urls:
                        resolved_urls[0]["final_url"] = result.get("final_url")
                        resolved_urls[0]["final_hostname"] = urllib.parse.urlparse(str(result.get("final_url"))).hostname
                        resolved_urls[0]["final_registered_domain"] = _extract_domain_root(resolved_urls[0].get("final_hostname"))

                analysis = job.get("analysis") if isinstance(job.get("analysis"), dict) else {}
                evidence = analysis.setdefault("evidence", {})
                summary = evidence.setdefault("external_intel_summary", {})
                if isinstance(summary, dict):
                    summary["urlscan"] = _urlscan_provider_payload(result)
            elif _urlscan_pending_has_timed_out(job):
                urlscan_state["status"] = "timeout"
                _increment_orchestrated_metric(job, "urlscan_timeout_count")
                urlscan_state["details"] = (
                    "urlscan preview nu a finalizat captura in timpul maxim permis; "
                    "verdictul ramane bazat pe piloanele blocking."
                )
                job["urlscan"] = urlscan_state
        elif _urlscan_pending_has_timed_out(job):
            urlscan_state["status"] = "timeout"
            _increment_orchestrated_metric(job, "urlscan_timeout_count")
            urlscan_state["details"] = (
                "urlscan preview nu a finalizat captura in timpul maxim permis; "
                "verdictul ramane bazat pe piloanele blocking."
            )
            job["urlscan"] = urlscan_state

    job = _persist_orchestrated_job(job)
    _emit_orchestrated_telemetry("orchestrated_urlscan_polled", job)
    return await _finalize_orchestrated_job_if_ready(job, request)


@app.post("/v1/scan/orchestrated")
async def start_orchestrated_scan(payload: OrchestratedScanRequest, request: Request):
    """
    Starts the product-grade scan pipeline:
    intake -> persistent queued scan_id. Provider work is advanced idempotently by GET polling.
    """
    _prune_orchestrated_jobs()
    job = await _create_orchestrated_job(payload)
    response = _orchestrated_status_payload(job)
    job = _persist_orchestrated_job(job)
    return response


@app.get("/v1/scan/orchestrated/{scan_id}")
async def get_orchestrated_scan(scan_id: str, request: Request):
    _prune_orchestrated_jobs()
    lock = _ORCHESTRATED_SCAN_LOCKS.setdefault(scan_id, asyncio.Lock())
    async with lock:
        job = _load_orchestrated_job(scan_id)
        if not job:
            raise HTTPException(status_code=404, detail="Scanarea nu a fost gasita sau a expirat.")
        job = await _refresh_orchestrated_job(job, request)
        response = _orchestrated_status_payload(job)
        job = _persist_orchestrated_job(job)
        return response


@app.post("/v1/sandbox/urlscan")
async def submit_urlscan_sandbox(payload: UrlscanSandboxRequest, request: Request):
    _require_urlscan_key()
    url = _validate_sandbox_url(payload.url)
    visibility = _safe_urlscan_visibility(payload.visibility)

    def build_submit_payload(selected_visibility: str, include_persona: bool = True) -> Dict[str, Any]:
        submit_payload: Dict[str, Any] = {
            "url": url,
            "visibility": selected_visibility,
            "tags": _urlscan_tags(payload.source_channel),
        }
        if include_persona:
            country = (payload.country or URLSCAN_COUNTRY_DEFAULT or "").strip().lower()
            customagent = (payload.customagent or URLSCAN_CUSTOM_AGENT_DEFAULT or "").strip()
            if country:
                submit_payload["country"] = country[:2]
            if customagent:
                submit_payload["customagent"] = customagent[:512]
        return submit_payload

    def submit(selected_visibility: str, include_persona: bool = True) -> requests.Response:
        return requests.post(
            "https://urlscan.io/api/v1/scan/",
            headers=_urlscan_headers(),
            json=build_submit_payload(selected_visibility, include_persona=include_persona),
            timeout=URLSCAN_TIMEOUT_SECONDS,
        )

    response = await run_in_threadpool(submit, visibility)
    if response.status_code in {400, 422} and (payload.country or payload.customagent or URLSCAN_COUNTRY_DEFAULT or URLSCAN_CUSTOM_AGENT_DEFAULT):
        response = await run_in_threadpool(submit, visibility, False)
    if response.status_code in {400, 403, 422} and visibility == "private":
        response = await run_in_threadpool(submit, "unlisted")

    if response.status_code >= 400:
        raise HTTPException(
            status_code=502,
            detail=_urlscan_error_detail(response),
        )

    body = response.json()
    uuid = body.get("uuid")
    if not uuid:
        raise HTTPException(status_code=502, detail="urlscan.io nu a returnat uuid.")

    return {
        "uuid": uuid,
        "status": "pending",
        "report_url": _urlscan_report_url(uuid),
        "result_url": str(request.url_for("get_urlscan_result", uuid=uuid)),
        "screenshot_url": str(request.url_for("urlscan_screenshot", uuid=uuid)),
        "submitted_url": url,
    }


@app.get("/v1/sandbox/urlscan/{uuid}", name="get_urlscan_result")
async def get_urlscan_result(uuid: str, request: Request):
    _require_urlscan_key()
    safe_uuid = re.sub(r"[^A-Za-z0-9._-]", "", uuid or "")
    if not safe_uuid:
        raise HTTPException(status_code=400, detail="uuid invalid.")

    def fetch_result() -> requests.Response:
        return requests.get(
            f"https://urlscan.io/api/v1/result/{safe_uuid}/",
            headers=_urlscan_headers(),
            timeout=URLSCAN_TIMEOUT_SECONDS,
        )

    response = await run_in_threadpool(fetch_result)
    if response.status_code == 404:
        return {
            "uuid": safe_uuid,
            "status": "pending",
            "verdict": "Pending",
            "severity": "unknown",
            "details": "urlscan.io sandbox inca proceseaza rezultatul.",
            "report_url": _urlscan_report_url(safe_uuid),
            "screenshot_url": str(request.url_for("urlscan_screenshot", uuid=safe_uuid)),
        }
    if response.status_code >= 400:
        raise HTTPException(
            status_code=502,
            detail=f"urlscan.io result failed: HTTP {response.status_code}",
        )

    payload = response.json()
    return _summarize_urlscan_payload(payload, safe_uuid, request)


@app.get("/v1/sandbox/urlscan/{uuid}/screenshot", name="urlscan_screenshot")
async def urlscan_screenshot(uuid: str):
    _require_urlscan_key()
    safe_uuid = re.sub(r"[^A-Za-z0-9._-]", "", uuid or "")
    if not safe_uuid:
        raise HTTPException(status_code=400, detail="uuid invalid.")

    def fetch_screenshot() -> requests.Response:
        return requests.get(
            f"https://urlscan.io/screenshots/{safe_uuid}.png",
            headers={"api-key": URLSCAN_API_KEY},
            timeout=URLSCAN_TIMEOUT_SECONDS,
        )

    response = await run_in_threadpool(fetch_screenshot)
    if response.status_code >= 400:
        raise HTTPException(
            status_code=502,
            detail=f"urlscan.io screenshot failed: HTTP {response.status_code}",
        )
    return Response(
        content=response.content,
        media_type=response.headers.get("content-type") or "image/png",
        headers={"Cache-Control": "private, max-age=300"},
    )


@app.post("/v1/extract/image")
async def extract_image_for_orchestration(
    image_file: UploadFile = File(...),
    source_channel: Optional[str] = Form("image_upload"),
):
    """Extract OCR text/URLs from an image. Final verdict is handled by /v1/scan/orchestrated."""

    filename = image_file.filename or "screenshot.jpg"
    image_bytes = await image_file.read()
    if not image_bytes:
        raise HTTPException(status_code=400, detail="Imaginea încărcată este goală.")

    _validate_file_upload(
        filename=filename,
        content_type=image_file.content_type,
        file_bytes=image_bytes,
        max_bytes=MAX_IMAGE_BYTES,
        allowed_exts=ALLOWED_IMAGE_EXTS,
        allowed_mime_types=ALLOWED_IMAGE_MIME_TYPES,
    )

    ocr_text, ocr_warning = await extract_text_for_scan(
        filename=filename,
        file_bytes=image_bytes,
        extract_fn=extract_text_with_vision,
    )
    redacted_text = redact_pii(ocr_text)
    extracted_urls = _dedupe_preserve_order(extract_urls(ocr_text) + extract_urls(redacted_text))
    return {
        "input_type": "image_ocr",
        "source_channel": source_channel,
        "redacted_text": redacted_text,
        "extracted_urls": extracted_urls,
        "html_content": None,
        "warning": ocr_warning,
        "hidden_url_visibility": False,
    }


@app.post("/v1/extract/pdf")
async def extract_pdf_for_orchestration(
    pdf_file: UploadFile = File(...),
    source_channel: Optional[str] = Form("pdf_upload"),
):
    """Extract OCR text/URLs from a PDF. Final verdict is handled by /v1/scan/orchestrated."""

    filename = pdf_file.filename or "document.pdf"
    pdf_bytes = await pdf_file.read()
    if not pdf_bytes:
        raise HTTPException(status_code=400, detail="PDF-ul încărcat este gol.")

    _validate_file_upload(
        filename=filename,
        content_type=pdf_file.content_type,
        file_bytes=pdf_bytes,
        max_bytes=MAX_PDF_BYTES,
        allowed_exts=ALLOWED_PDF_EXTS,
        allowed_mime_types={"application/pdf"},
    )

    if not pdf_bytes.startswith(b"%PDF-"):
        raise HTTPException(status_code=400, detail="Format PDF invalid.")

    ocr_text, ocr_warning = await extract_text_for_scan(
        filename=filename,
        file_bytes=pdf_bytes,
        extract_fn=extract_text_from_pdf_with_vision,
    )
    redacted_text = redact_pii(ocr_text)
    extracted_urls = _dedupe_preserve_order(extract_urls(ocr_text) + extract_urls(redacted_text))
    return {
        "input_type": "pdf_ocr",
        "source_channel": source_channel,
        "redacted_text": redacted_text,
        "extracted_urls": extracted_urls,
        "html_content": None,
        "warning": ocr_warning,
        "hidden_url_visibility": False,
    }


@app.post("/v1/extract/email")
async def extract_email_for_orchestration(
    email_file: Optional[UploadFile] = File(None),
    html_content: Optional[str] = Form(None),
    source_channel: Optional[str] = Form("email"),
):
    """Extract visible text, HTML, and clickable targets from email/HTML without producing a verdict."""

    html_to_parse = ""
    is_forwarded = True
    parsed_message: Optional[Message] = None

    if email_file is None and not html_content:
        raise HTTPException(status_code=400, detail="Trebuie trimis email_file sau html_content.")

    if email_file:
        content = await email_file.read()
        if len(content) > MAX_TEXT_CHARS * 4:
            raise HTTPException(status_code=413, detail="Fișierul este prea mare.")
        try:
            parsed_message = message_from_bytes(content, policy=policy.default)
            is_forwarded = False
            html_part = parsed_message.get_body(preferencelist=("html",))
            if html_part:
                html_to_parse = html_part.get_content()
            else:
                text_part = parsed_message.get_body(preferencelist=("plain",))
                if text_part:
                    html_to_parse = text_part.get_content()
        except Exception as exc:
            logger.error(f"Error parsing .eml for extraction: {exc}")
            raise HTTPException(status_code=400, detail=f"Invalid .eml file format: {exc}")
    elif html_content:
        if len(html_content) > MAX_TEXT_CHARS * 8:
            raise HTTPException(status_code=413, detail="Conținutul HTML este prea mare.")
        html_to_parse = html_content

    html_to_parse = _normalise_obfuscated_text(html_to_parse)
    email_context = _extract_email_auth_context(parsed_message, is_forwarded_guess=is_forwarded)
    if not html_to_parse.strip():
        return {
            "input_type": "email",
            "source_channel": source_channel,
            "redacted_text": "",
            "html_content": None,
            "extracted_urls": [],
            "buttons": [],
            "email_auth": email_context,
            "warning": "Corpul e-mailului este gol sau nu a putut fi citit.",
        }

    soup = BeautifulSoup(html_to_parse, "html.parser")
    click_targets = _collect_click_targets_from_html(soup)
    discovered_urls: List[str] = []
    buttons: List[Dict[str, Any]] = []
    cta_words = ["verific", "confirm", "plăte", "plate", "cont", "login", "conect", "intrare", "detalii", "colet", "awb", "reactivare", "urgent"]

    for target in click_targets:
        raw_url = target.get("original_url")
        if not raw_url or raw_url in discovered_urls:
            continue
        discovered_urls.append(raw_url)
        button_text = str(target.get("button_text") or "")
        buttons.append(
            {
                "button_text": button_text,
                "original_url": raw_url,
                "is_sensitive_cta": any(word in button_text.lower() for word in cta_words),
                "source_tag": target.get("source_tag"),
                "source_attr": target.get("source_attr"),
            }
        )

    visible_text = soup.get_text(separator=" ", strip=True)
    for url in extract_urls(visible_text):
        if url not in discovered_urls:
            discovered_urls.append(url)

    email_subject = parsed_message.get("Subject", "") if parsed_message else ""
    inferred_brand_hints = _infer_brand_hints_from_click_targets(click_targets)
    content_for_analysis = "\n".join(
        part
        for part in [
            email_subject,
            visible_text,
            " ".join(inferred_brand_hints),
        ]
        if part.strip()
    )
    return {
        "input_type": "email",
        "source_channel": source_channel,
        "redacted_text": redact_pii(content_for_analysis),
        "html_content": html_to_parse,
        "extracted_urls": discovered_urls,
        "buttons": buttons,
        "email_auth": email_context,
        "subject": email_subject,
        "from": parsed_message.get("From") if parsed_message else None,
        "reply_to": parsed_message.get("Reply-To") if parsed_message else None,
        "message_id": parsed_message.get("Message-ID") if parsed_message else None,
        "inferred_brand_hints": inferred_brand_hints,
        "warning": None,
    }


def _assemble_extracted_text_for_orchestration(extraction: Dict[str, Any], fallback_label: str) -> str:
    text = str(extraction.get("redacted_text") or "").strip()
    urls = [
        str(url).strip()
        for url in extraction.get("extracted_urls") or []
        if str(url).strip()
    ]
    parts = [text or f"Conținut extras din {fallback_label}."]
    if urls:
        parts.append("Linkuri extrase:")
        parts.extend(urls)
    return "\n".join(parts).strip()


async def _start_orchestrated_from_extraction(
    extraction: Dict[str, Any],
    *,
    fallback_label: str,
    default_input_type: str,
    source_channel: Optional[str],
) -> Dict[str, Any]:
    html_content = str(extraction.get("html_content") or "").strip() or None
    text = _assemble_extracted_text_for_orchestration(extraction, fallback_label)
    input_type = "email_html" if html_content else "text"
    if default_input_type in {"image_ocr", "pdf_ocr"} and not html_content:
        input_type = "text"

    job = await _create_orchestrated_job(
        OrchestratedScanRequest(
            input_type=input_type,
            text=text,
            html_content=html_content,
            source_channel=source_channel or str(extraction.get("source_channel") or default_input_type),
        )
    )
    response = _orchestrated_status_payload(job)
    response.setdefault("extraction", {})
    response["extraction"] = {
        "input_type": extraction.get("input_type") or default_input_type,
        "source_channel": extraction.get("source_channel") or source_channel,
        "extracted_url_count": len(extraction.get("extracted_urls") or []),
        "has_html": bool(html_content),
        "warning": extraction.get("warning"),
    }
    return response


async def _start_orchestrated_compat(payload: OrchestratedScanRequest) -> Dict[str, Any]:
    job = await _create_orchestrated_job(payload)
    return _orchestrated_status_payload(job)


@app.post("/v1/scan/text")
async def scan_text(request: TextScanRequest):
    """
    Compatibility wrapper. Starts the product-grade orchestrated scan and returns scan_id/status.
    """
    raw_text = _normalise_obfuscated_text((request.text or "").strip())
    _validate_text_input("Textul trimis", raw_text, MAX_TEXT_CHARS)
    return await _start_orchestrated_compat(
        OrchestratedScanRequest(
            input_type="text",
            text=raw_text,
            source_channel=request.source_channel or "manual",
        )
    )

@app.post("/v1/scan/url")
async def scan_url(request: URLScanRequest):
    """
    Compatibility wrapper. Starts the product-grade orchestrated URL scan and returns scan_id/status.
    """
    url = _canonicalize_url(_normalise_obfuscated_text(request.url or ""))
    if not url:
        raise HTTPException(status_code=400, detail="URL invalid sau format neacceptat.")
    return await _start_orchestrated_compat(
        OrchestratedScanRequest(
            input_type="url",
            url=url,
            source_channel=request.source_channel or "url_scan",
        )
    )

@app.post("/v1/scan/email")
async def scan_email(
    email_file: Optional[UploadFile] = File(None),
    html_content: Optional[str] = Form(None),
    source_channel: Optional[str] = Form("email"),
):
    """
    Compatibility wrapper. Extracts email evidence, then starts orchestrated scan.
    """
    extraction = await extract_email_for_orchestration(
        email_file=email_file,
        html_content=html_content,
        source_channel=source_channel,
    )
    return await _start_orchestrated_from_extraction(
        extraction,
        fallback_label="email",
        default_input_type="email",
        source_channel=source_channel,
    )

@app.post("/v1/scan/image")
async def scan_image(
    image_file: UploadFile = File(...),
    source_channel: Optional[str] = Form("image_upload"),
):
    """
    Compatibility wrapper. Extracts OCR evidence, then starts orchestrated scan.
    """
    extraction = await extract_image_for_orchestration(
        image_file=image_file,
        source_channel=source_channel,
    )
    return await _start_orchestrated_from_extraction(
        extraction,
        fallback_label="imagine",
        default_input_type="image_ocr",
        source_channel=source_channel,
    )


@app.post("/v1/scan/pdf")
async def scan_pdf(
    pdf_file: UploadFile = File(...),
    source_channel: Optional[str] = Form("pdf_upload"),
):
    """
    Compatibility wrapper. Extracts PDF OCR evidence, then starts orchestrated scan.
    """
    extraction = await extract_pdf_for_orchestration(
        pdf_file=pdf_file,
        source_channel=source_channel,
    )
    return await _start_orchestrated_from_extraction(
        extraction,
        fallback_label="PDF",
        default_input_type="pdf_ocr",
        source_channel=source_channel,
    )


@app.post("/v1/feedback")
async def submit_feedback(payload: FeedbackRequest):
    normalized = (payload.feedback or "").strip().lower()
    if normalized not in {"correct", "false_positive", "false_negative", "uncertain"}:
        raise HTTPException(
            status_code=400,
            detail="feedback trebuie sa fie: correct, false_positive, false_negative sau uncertain.",
        )

    scan_record = find_scan_record_by_id(payload.scan_id)
    predicted_is_scam = payload.predicted_is_scam
    predicted_risk_score = payload.predicted_risk_score
    risk_level = payload.risk_level
    signal_ids = payload.signal_ids
    actual_is_scam = payload.actual_is_scam

    if scan_record:
        if predicted_is_scam is None:
            scan_predicted = scan_record.get("predicted_is_scam")
            if isinstance(scan_predicted, bool):
                predicted_is_scam = scan_predicted
        if predicted_risk_score is None:
            predicted_risk_score = scan_record.get("risk_score")
        if risk_level is None:
            risk_level = scan_record.get("risk_level")
        if not signal_ids:
            signal_ids = scan_record.get("signal_ids")

    if actual_is_scam is None:
        if normalized == "false_positive":
            actual_is_scam = False
        elif normalized == "false_negative":
            actual_is_scam = True
        elif normalized == "correct" and isinstance(predicted_is_scam, bool):
            actual_is_scam = predicted_is_scam

    log_feedback_event(
        {
            "scan_id": payload.scan_id,
            "feedback": normalized,
            "actual_is_scam": actual_is_scam,
            "predicted_is_scam": predicted_is_scam,
            "predicted_risk_score": predicted_risk_score,
            "risk_level": risk_level,
            "signal_ids": signal_ids or [],
            "source_channel": scan_record.get("source_channel") if scan_record else None,
            "notes": payload.notes,
        }
    )
    return {
        "status": "ok",
        "scan_id": payload.scan_id,
        "feedback": normalized,
    }


@app.get("/v1/feedback/summary")
def feedback_summary(
    source_channel: Optional[str] = None,
    since_ts: Optional[int] = None,
    until_ts: Optional[int] = None,
    include_examples: bool = False,
    max_examples_per_type: int = 20,
):
    rows = load_feedback_records()
    summary = summarize_feedback_records(
        rows,
        source_channel=source_channel,
        since_ts=since_ts,
        until_ts=until_ts,
        include_examples=include_examples,
        max_examples_per_type=max_examples_per_type,
    )
    return {"summary": summary}


@app.get("/v1/reputation/cache/stats")
def reputation_cache_stats() -> Dict[str, Any]:
    return {"cache": get_reputation_cache_stats()}


@app.get("/v1/orchestration/telemetry")
def orchestration_telemetry(
    limit: int = 1000,
    urlscan_timeout_rate_alert: float = 0.15,
) -> Dict[str, Any]:
    if limit <= 0:
        raise HTTPException(status_code=400, detail="limit trebuie sa fie strict pozitiv.")
    if limit > 10000:
        raise HTTPException(status_code=400, detail="limit maxim este 10000.")
    if urlscan_timeout_rate_alert < 0 or urlscan_timeout_rate_alert > 1:
        raise HTTPException(status_code=400, detail="urlscan_timeout_rate_alert trebuie sa fie intre 0 si 1.")
    return {"orchestration": _build_orchestration_telemetry_payload(
        limit=limit,
        urlscan_timeout_rate_alert=urlscan_timeout_rate_alert,
    )}


def _html_escape(value: Any) -> str:
    return (
        str(value if value is not None else "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


@app.get("/v1/orchestration/dashboard", response_class=HTMLResponse)
def orchestration_dashboard(
    limit: int = 1000,
    urlscan_timeout_rate_alert: float = 0.15,
) -> HTMLResponse:
    if limit <= 0:
        raise HTTPException(status_code=400, detail="limit trebuie sa fie strict pozitiv.")
    if limit > 10000:
        raise HTTPException(status_code=400, detail="limit maxim este 10000.")
    payload = _build_orchestration_telemetry_payload(
        limit=limit,
        urlscan_timeout_rate_alert=urlscan_timeout_rate_alert,
    )
    alerts = payload.get("alerts") if isinstance(payload.get("alerts"), list) else []
    stage_latency = payload.get("stage_latency_ms") if isinstance(payload.get("stage_latency_ms"), dict) else {}
    by_event = payload.get("by_event_type") if isinstance(payload.get("by_event_type"), dict) else {}

    def card(title: str, value: Any, hint: str = "") -> str:
        return (
            "<section class='card'>"
            f"<span>{_html_escape(title)}</span>"
            f"<strong>{_html_escape(value)}</strong>"
            f"<small>{_html_escape(hint)}</small>"
            "</section>"
        )

    alert_html = "".join(
        f"<li class='{_html_escape(alert.get('severity', 'watch'))}'>"
        f"<strong>{_html_escape(alert.get('code'))}</strong> - {_html_escape(alert.get('message'))}"
        "</li>"
        for alert in alerts
    ) or "<li class='ok'>Nu există alerte pe fereastra curentă.</li>"

    latency_rows = "".join(
        "<tr>"
        f"<td>{_html_escape(stage)}</td>"
        f"<td>{_html_escape(values.get('avg'))}</td>"
        f"<td>{_html_escape(values.get('max'))}</td>"
        f"<td>{_html_escape(values.get('samples'))}</td>"
        "</tr>"
        for stage, values in stage_latency.items()
    ) or "<tr><td colspan='4'>Nu există încă date de latență pe stage.</td></tr>"

    event_rows = "".join(
        f"<tr><td>{_html_escape(event)}</td><td>{_html_escape(count)}</td></tr>"
        for event, count in sorted(by_event.items())
    ) or "<tr><td colspan='2'>Nu există evenimente orchestrated.</td></tr>"

    urlscan = payload.get("urlscan", {}) if isinstance(payload.get("urlscan"), dict) else {}
    conflicts = payload.get("conflicts", {}) if isinstance(payload.get("conflicts"), dict) else {}
    polls = payload.get("polls_to_final", {}) if isinstance(payload.get("polls_to_final"), dict) else {}
    time_to_final = payload.get("time_to_final_ms", {}) if isinstance(payload.get("time_to_final_ms"), dict) else {}

    html = f"""
<!doctype html>
<html lang="ro">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SigurScan Orchestration Dashboard</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f6f8fc;
      --card: #ffffff;
      --ink: #172033;
      --muted: #62708a;
      --line: #dde5f1;
      --blue: #316bff;
      --red: #c7332f;
      --amber: #ad6500;
      --green: #087f5b;
    }}
    body {{
      margin: 0;
      padding: 32px;
      background: var(--bg);
      color: var(--ink);
      font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }}
    header {{ margin-bottom: 24px; }}
    h1 {{ margin: 0 0 6px; font-size: 28px; }}
    p {{ margin: 0; color: var(--muted); }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 14px;
      margin: 24px 0;
    }}
    .card {{
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: 18px;
      padding: 18px;
      box-shadow: 0 12px 30px rgba(24, 39, 75, .06);
    }}
    .card span, small {{ color: var(--muted); display: block; }}
    .card strong {{ display: block; font-size: 30px; margin: 8px 0; }}
    section.panel {{
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: 18px;
      padding: 20px;
      margin: 16px 0;
    }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ border-bottom: 1px solid var(--line); padding: 10px; text-align: left; }}
    th {{ color: var(--muted); font-weight: 700; }}
    li {{ margin: 8px 0; }}
    .high {{ color: var(--red); }}
    .watch {{ color: var(--amber); }}
    .ok {{ color: var(--green); }}
    code {{ background: #eef3ff; color: var(--blue); padding: 2px 6px; border-radius: 8px; }}
  </style>
</head>
<body>
  <header>
    <h1>SigurScan Orchestration Dashboard</h1>
    <p>Dashboard minimal peste <code>scan_events</code>. Nu expune secrete și nu rulează providerii.</p>
  </header>
  <div class="grid">
    {card("Scanări urmărite", payload.get("scan_count"), f"limit={limit} evenimente")}
    {card("Evenimente", payload.get("events_considered"), "orchestrated_*")}
    {card("Poll-uri până la verdict", polls.get("avg"), f"max={polls.get('max')}")}
    {card("Timp până la verdict", time_to_final.get("avg"), f"max={time_to_final.get('max')} ms")}
    {card("urlscan timeout rate", urlscan.get("pending_timeout_rate"), f"events={urlscan.get('pending_timeout_events')}")}
    {card("Conflict merge", conflicts.get("merge_events"), f"retry failures={conflicts.get('retry_failures')}")}
  </div>
  <section class="panel">
    <h2>Alerte</h2>
    <ul>{alert_html}</ul>
  </section>
  <section class="panel">
    <h2>Latențe pe stage</h2>
    <table><thead><tr><th>Stage</th><th>Avg ms</th><th>Max ms</th><th>Samples</th></tr></thead><tbody>{latency_rows}</tbody></table>
  </section>
  <section class="panel">
    <h2>Evenimente</h2>
    <table><thead><tr><th>Event</th><th>Count</th></tr></thead><tbody>{event_rows}</tbody></table>
  </section>
</body>
</html>
"""
    return HTMLResponse(content=html)


@app.get("/v1/adjudication/shadow")
def shadow_adjudication_telemetry(
    limit: int = 1000,
    fallback_rate_alert: float = 0.05,
    disagreement_rate_alert: float = 0.25,
    latency_p95_alert_ms: int = 2500,
) -> Dict[str, Any]:
    if limit <= 0:
        raise HTTPException(status_code=400, detail="limit trebuie sa fie strict pozitiv.")
    if limit > 10000:
        raise HTTPException(status_code=400, detail="limit maxim este 10000.")
    if fallback_rate_alert < 0 or fallback_rate_alert > 1:
        raise HTTPException(status_code=400, detail="fallback_rate_alert trebuie sa fie intre 0 si 1.")
    if disagreement_rate_alert < 0 or disagreement_rate_alert > 1:
        raise HTTPException(status_code=400, detail="disagreement_rate_alert trebuie sa fie intre 0 si 1.")
    if latency_p95_alert_ms <= 0:
        raise HTTPException(status_code=400, detail="latency_p95_alert_ms trebuie sa fie strict pozitiv.")
    return {
        "shadow_adjudication": _build_shadow_adjudication_payload(
            limit=limit,
            fallback_rate_alert=fallback_rate_alert,
            disagreement_rate_alert=disagreement_rate_alert,
            latency_p95_alert_ms=latency_p95_alert_ms,
        )
    }


@app.get("/v1/adjudication/dashboard", response_class=HTMLResponse)
def shadow_adjudication_dashboard(
    limit: int = 1000,
    fallback_rate_alert: float = 0.05,
    disagreement_rate_alert: float = 0.25,
    latency_p95_alert_ms: int = 2500,
) -> HTMLResponse:
    if limit <= 0:
        raise HTTPException(status_code=400, detail="limit trebuie sa fie strict pozitiv.")
    if limit > 10000:
        raise HTTPException(status_code=400, detail="limit maxim este 10000.")
    payload = _build_shadow_adjudication_payload(
        limit=limit,
        fallback_rate_alert=fallback_rate_alert,
        disagreement_rate_alert=disagreement_rate_alert,
        latency_p95_alert_ms=latency_p95_alert_ms,
    )
    agreement = payload.get("agreement", {}) if isinstance(payload.get("agreement"), dict) else {}
    latency = payload.get("latency_ms", {}) if isinstance(payload.get("latency_ms"), dict) else {}
    cache = payload.get("cache", {}) if isinstance(payload.get("cache"), dict) else {}
    feedback = payload.get("feedback_comparison", {}) if isinstance(payload.get("feedback_comparison"), dict) else {}
    promotion = payload.get("promotion_gate", {}) if isinstance(payload.get("promotion_gate"), dict) else {}
    alerts = payload.get("alerts") if isinstance(payload.get("alerts"), list) else []
    examples = payload.get("examples", {}) if isinstance(payload.get("examples"), dict) else {}

    def card(title: str, value: Any, hint: str = "") -> str:
        return (
            "<section class='card'>"
            f"<span>{_html_escape(title)}</span>"
            f"<strong>{_html_escape(value)}</strong>"
            f"<small>{_html_escape(hint)}</small>"
            "</section>"
        )

    alert_html = "".join(
        f"<li class='{_html_escape(alert.get('severity', 'watch'))}'>"
        f"<strong>{_html_escape(alert.get('code'))}</strong> - {_html_escape(alert.get('message'))}"
        "</li>"
        for alert in alerts
    ) or "<li class='ok'>Nu există alerte pe fereastra curentă.</li>"

    disagreement_rows = "".join(
        "<tr>"
        f"<td>{_html_escape(item.get('scan_id'))}</td>"
        f"<td>{_html_escape(item.get('gate_label'))}</td>"
        f"<td>{_html_escape(item.get('shadow_label'))}</td>"
        f"<td>{_html_escape(item.get('confidence'))}</td>"
        f"<td>{_html_escape(item.get('reason'))}</td>"
        "</tr>"
        for item in examples.get("disagreements", [])
        if isinstance(item, dict)
    ) or "<tr><td colspan='5'>Nu există dezacorduri validate.</td></tr>"

    fallback_rows = "".join(
        "<tr>"
        f"<td>{_html_escape(item.get('scan_id'))}</td>"
        f"<td>{_html_escape(item.get('gate_label'))}</td>"
        f"<td>{_html_escape(item.get('fallback_reason'))}</td>"
        "</tr>"
        for item in examples.get("fallbacks", [])
        if isinstance(item, dict)
    ) or "<tr><td colspan='3'>Nu există fallback-uri.</td></tr>"

    html = f"""
<!doctype html>
<html lang="ro">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SigurScan Shadow Adjudication</title>
  <style>
    :root {{
      color-scheme: light;
      --bg: #f6f8fc;
      --card: #ffffff;
      --ink: #172033;
      --muted: #62708a;
      --line: #dde5f1;
      --blue: #316bff;
      --red: #c7332f;
      --amber: #ad6500;
      --green: #087f5b;
    }}
    body {{
      margin: 0;
      padding: 32px;
      background: var(--bg);
      color: var(--ink);
      font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }}
    header {{ margin-bottom: 24px; }}
    h1 {{ margin: 0 0 6px; font-size: 28px; }}
    p {{ margin: 0; color: var(--muted); }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 14px;
      margin: 24px 0;
    }}
    .card, section.panel {{
      background: var(--card);
      border: 1px solid var(--line);
      border-radius: 18px;
      box-shadow: 0 12px 30px rgba(24, 39, 75, .06);
    }}
    .card {{ padding: 18px; }}
    section.panel {{ padding: 20px; margin: 16px 0; }}
    .card span, small {{ color: var(--muted); display: block; }}
    .card strong {{ display: block; font-size: 30px; margin: 8px 0; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ border-bottom: 1px solid var(--line); padding: 10px; text-align: left; vertical-align: top; }}
    th {{ color: var(--muted); font-weight: 700; }}
    li {{ margin: 8px 0; }}
    .high {{ color: var(--red); }}
    .watch {{ color: var(--amber); }}
    .ok {{ color: var(--green); }}
    code {{ background: #eef3ff; color: var(--blue); padding: 2px 6px; border-radius: 8px; }}
  </style>
</head>
<body>
  <header>
    <h1>SigurScan Shadow Adjudication</h1>
    <p>Compară gate-ul determinist cu Mistral shadow. Nu schimbă verdictul userului și nu rulează providerii.</p>
  </header>
  <div class="grid">
    {card("Evenimente shadow", payload.get("events_considered"), f"limit={limit}")}
    {card("Validate", payload.get("valid"), f"fallback={payload.get('fallback')}")}
    {card("Dezacorduri", agreement.get("disagreements"), f"rate={agreement.get('disagreement_rate')}")}
    {card("Fallback rate", payload.get("fallback_rate"), "validator reject / timeout")}
    {card("Latență p95", latency.get("p95"), f"avg={latency.get('avg')} ms")}
    {card("Cache hit rate", cache.get("hit_rate"), f"hits={cache.get('hits')}")}
    {card("Feedback etichetat", feedback.get("labeled"), f"improve={feedback.get('shadow_would_improve')} regress={feedback.get('shadow_would_regress')}")}
    {card("Promovabil", promotion.get("can_promote"), f"{promotion.get('current_labeled_real_messages')}/{promotion.get('min_labeled_real_messages')} mesaje")}
  </div>
  <section class="panel">
    <h2>Alerte</h2>
    <ul>{alert_html}</ul>
  </section>
  <section class="panel">
    <h2>Dezacorduri validate</h2>
    <table><thead><tr><th>Scan</th><th>Gate</th><th>Mistral</th><th>Confidence</th><th>Motiv</th></tr></thead><tbody>{disagreement_rows}</tbody></table>
  </section>
  <section class="panel">
    <h2>Fallback / Validator Reject</h2>
    <table><thead><tr><th>Scan</th><th>Gate</th><th>Motiv fallback</th></tr></thead><tbody>{fallback_rows}</tbody></table>
  </section>
</body>
</html>
"""
    return HTMLResponse(content=html)


@app.get("/v1/evaluation/feedback")
def feedback_evaluation_quality(
    source_channel: Optional[str] = None,
    since_ts: Optional[int] = None,
    until_ts: Optional[int] = None,
    include_uncertain: bool = False,
    include_examples: bool = True,
    max_examples_per_type: int = 50,
    run_sweep: bool = True,
    sweep_start: int = 0,
    sweep_end: int = 100,
    sweep_step: int = 5,
    sweep_metric: str = "f1",
):
    return _build_feedback_quality_payload(
        source_channel=source_channel,
        since_ts=since_ts,
        until_ts=until_ts,
        include_uncertain=include_uncertain,
        include_examples=include_examples,
        max_examples_per_type=max_examples_per_type,
        run_sweep=run_sweep,
        sweep_start=sweep_start,
        sweep_end=sweep_end,
        sweep_step=sweep_step,
        sweep_metric=sweep_metric,
    )


@app.get("/v1/evaluation/run")
def run_evaluation_endpoint(
    dataset_path: Optional[str] = None,
    risk_threshold: int = RISK_THRESHOLD,
    max_rows: Optional[int] = None,
    disable_redirects: bool = False,
    disable_reputation: bool = False,
    run_sweep: bool = False,
    sweep_start: int = 0,
    sweep_end: int = 100,
    sweep_step: int = 5,
    sweep_metric: str = "f1",
):
    if max_rows is not None and max_rows <= 0:
        raise HTTPException(status_code=400, detail="max_rows trebuie sa fie strict pozitiv.")
    if sweep_step <= 0:
        raise HTTPException(status_code=400, detail="sweep_step trebuie sa fie strict pozitiv.")
    if sweep_end < sweep_start:
        raise HTTPException(status_code=400, detail="sweep_end trebuie sa fie mai mare sau egal cu sweep_start.")

    path = _resolve_eval_dataset_path(dataset_path)
    evaluate_module = importlib.import_module("eval.evaluate")
    run_evaluation = getattr(evaluate_module, "run_evaluation")
    run_threshold_sweep = getattr(evaluate_module, "run_threshold_sweep")

    baseline = run_evaluation(
        path,
        risk_threshold=risk_threshold,
        max_rows=max_rows,
        disable_redirects=disable_redirects,
        disable_reputation=disable_reputation,
    )

    response = {
        "dataset_path": str(path),
        "generated_at": int(time.time()),
        "run_options": {
            "risk_threshold": risk_threshold,
            "max_rows": max_rows,
            "disable_redirects": disable_redirects,
            "disable_reputation": disable_reputation,
        },
        "baseline": baseline,
    }

    if run_sweep:
        sweep = run_threshold_sweep(
            path,
            disable_redirects=disable_redirects,
            disable_reputation=disable_reputation,
            sweep_start=sweep_start,
            sweep_end=sweep_end,
            sweep_step=sweep_step,
            optimize_metric=sweep_metric,
            max_rows=max_rows,
        )
        response["threshold_sweep"] = sweep
        response["recommended_threshold"] = sweep["best"]["risk_threshold"]

        best_threshold = sweep["best"].get("risk_threshold")
        if isinstance(best_threshold, int):
            response["best_eval"] = run_evaluation(
                path,
                risk_threshold=best_threshold,
                max_rows=max_rows,
                disable_redirects=disable_redirects,
                disable_reputation=disable_reputation,
            )

    return response


@app.get("/v1/feedback/samples")
def feedback_samples(
    source_channel: Optional[str] = None,
    since_ts: Optional[int] = None,
    until_ts: Optional[int] = None,
    include_uncertain: bool = False,
    include_examples: bool = True,
    max_examples_per_type: int = 50,
    error_category: Optional[str] = None,
):
    feedback_rows = load_feedback_records()
    scan_rows = load_scan_records()
    dataset_rows = build_feedback_evaluation_rows(
        feedback_rows,
        scan_rows,
        source_channel=source_channel,
        since_ts=since_ts,
        until_ts=until_ts,
        include_uncertain=include_uncertain,
        fallback_threshold=RISK_THRESHOLD,
    )

    normalized_error_category = (error_category or "").strip().lower() or None
    if normalized_error_category and normalized_error_category not in {
        "correct",
        "false_positive",
        "false_negative",
        "uncertain",
    }:
        raise HTTPException(status_code=400, detail="error_category trebuie sa fie: correct, false_positive, false_negative sau uncertain.")

    sample_buckets: Dict[str, List[Dict[str, Any]]] = {
        "correct": [],
        "false_positive": [],
        "false_negative": [],
        "uncertain": [],
    }
    category_counts: Counter[str] = Counter()

    if max_examples_per_type < 0:
        max_examples_per_type = 0

    for row in dataset_rows:
        if not isinstance(row, dict):
            continue

        category = row.get("error_category") or "uncertain"
        if category not in sample_buckets:
            continue

        if normalized_error_category is not None and category != normalized_error_category:
            continue

        category_counts[category] += 1
        if not include_examples:
            continue
        bucket = sample_buckets[category]
        if len(bucket) >= max_examples_per_type:
            continue

        bucket.append(_feedback_sample_payload(row))

    samples: Dict[str, Any] = {}
    if normalized_error_category is not None:
        samples[normalized_error_category] = sample_buckets[normalized_error_category]
    else:
        for category_name, bucket in sample_buckets.items():
            if bucket:
                samples[category_name] = bucket

    response = {
        "items_evaluated": len(dataset_rows),
        "source_channel": source_channel,
        "category_counts": dict(category_counts),
        "samples": samples,
    }
    if normalized_error_category is not None:
        response["error_category"] = normalized_error_category
    return response


@app.get("/v1/feedback/quality")
def feedback_quality(
    source_channel: Optional[str] = None,
    since_ts: Optional[int] = None,
    until_ts: Optional[int] = None,
    include_uncertain: bool = False,
    include_examples: bool = True,
    max_examples_per_type: int = 50,
    run_sweep: bool = True,
    sweep_start: int = 0,
    sweep_end: int = 100,
    sweep_step: int = 5,
    sweep_metric: str = "f1",
    ):
    return _build_feedback_quality_payload(
        source_channel=source_channel,
        since_ts=since_ts,
        until_ts=until_ts,
        include_uncertain=include_uncertain,
        include_examples=include_examples,
        max_examples_per_type=max_examples_per_type,
        run_sweep=run_sweep,
        sweep_start=sweep_start,
        sweep_end=sweep_end,
        sweep_step=sweep_step,
        sweep_metric=sweep_metric,
    )


@app.get("/v1/evaluation/feedback/trend")
def feedback_trend(
    source_channel: Optional[str] = None,
    since_ts: Optional[int] = None,
    until_ts: Optional[int] = None,
    include_uncertain: bool = False,
    bucket_size_days: int = 1,
    min_bucket_support: int = 1,
    top_signals: int = 10,
    min_signal_support: int = 1,
):
    if bucket_size_days <= 0:
        raise HTTPException(status_code=400, detail="bucket_size_days trebuie sa fie mai mare ca 0.")
    if min_bucket_support < 0:
        raise HTTPException(status_code=400, detail="min_bucket_support trebuie sa fie >= 0.")
    if top_signals < 0:
        raise HTTPException(status_code=400, detail="top_signals trebuie sa fie >= 0.")
    if min_signal_support < 0:
        raise HTTPException(status_code=400, detail="min_signal_support trebuie sa fie >= 0.")

    feedback_rows = load_feedback_records()
    scan_rows = load_scan_records()
    dataset_rows = build_feedback_evaluation_rows(
        feedback_rows,
        scan_rows,
        source_channel=source_channel,
        since_ts=since_ts,
        until_ts=until_ts,
        include_uncertain=include_uncertain,
        fallback_threshold=RISK_THRESHOLD,
    )

    trend = summarize_feedback_trend(
        dataset_rows,
        source_channel=source_channel,
        since_ts=None,
        until_ts=None,
        bucket_size_days=bucket_size_days,
        include_uncertain=include_uncertain,
        min_bucket_support=min_bucket_support,
        top_signals=top_signals,
        min_signal_support=min_signal_support,
    )

    return {
        "source_channel": source_channel,
        "query": {
            "since_ts": since_ts,
            "until_ts": until_ts,
            "include_uncertain": include_uncertain,
            "bucket_size_days": bucket_size_days,
            "min_bucket_support": min_bucket_support,
            "top_signals": top_signals,
            "min_signal_support": min_signal_support,
        },
        "items_evaluated": len(dataset_rows),
        "trend": trend,
    }


@app.get("/v1/evaluation/readiness")
def evaluation_readiness(
    source_channel: Optional[str] = None,
    since_ts: Optional[int] = None,
    until_ts: Optional[int] = None,
    include_uncertain: bool = False,
    bucket_size_days: int = 1,
    trend_top_signals: int = 10,
    trend_min_bucket_support: int = 1,
    trend_min_signal_support: int = 1,
):
    if bucket_size_days <= 0:
        raise HTTPException(status_code=400, detail="bucket_size_days trebuie sa fie mai mare ca 0.")
    if trend_top_signals < 0:
        raise HTTPException(status_code=400, detail="trend_top_signals trebuie sa fie >= 0.")
    if trend_min_bucket_support < 0:
        raise HTTPException(status_code=400, detail="trend_min_bucket_support trebuie sa fie >= 0.")
    if trend_min_signal_support < 0:
        raise HTTPException(status_code=400, detail="trend_min_signal_support trebuie sa fie >= 0.")

    return _build_readiness_payload(
        source_channel=source_channel,
        since_ts=since_ts,
        until_ts=until_ts,
        include_uncertain=include_uncertain,
        bucket_size_days=bucket_size_days,
        trend_top_signals=trend_top_signals,
        trend_min_bucket_support=trend_min_bucket_support,
        trend_min_signal_support=trend_min_signal_support,
    )


# ---------------------------------------------------------------------------
# Community endpoints (for iOS app)
# ---------------------------------------------------------------------------

class CommunityReportRequest(BaseModel):
    hash: str
    risk_level: str
    family: Optional[str] = None
    source: str = "ios"
    timestamp: Optional[str] = None


class PushRegisterRequest(BaseModel):
    token: str
    platform: str = "ios"
    locale: str = "ro-RO"


@app.post("/v1/community/report")
def community_report(payload: CommunityReportRequest):
    has_supabase = supabase_store.is_supabase_enabled()
    if not has_supabase:
        return {"status": "ok", "note": "supabase not configured, report stored locally"}

    try:
        existing = supabase_store._get_json("community_reports", {"hash": f"eq.{payload.hash}"})
        if existing:
            row_id = existing[0]["id"]
            requests.patch(
                supabase_store._table_url("community_reports") + f"?id=eq.{row_id}",
                headers=supabase_store._headers("return=minimal"),
                json={
                    "report_count": existing[0].get("report_count", 0) + 1,
                    "last_reported_at": datetime.now(timezone.utc).isoformat(),
                },
                timeout=supabase_store.SUPABASE_TIMEOUT_SECONDS,
            )
        else:
            supabase_store._post_json("community_reports", {
                "hash": payload.hash,
                "risk_level": payload.risk_level,
                "family": payload.family,
                "source": payload.source,
            })
    except Exception:
        pass
    return {"status": "ok"}


@app.get("/v1/community/campaigns")
def community_campaigns(status: str = "active", limit: int = 20):
    has_supabase = supabase_store.is_supabase_enabled()
    if not has_supabase:
        logger.warning("community_campaigns: supabase not enabled")
        return []

    _status_map = {
        "active": "activă",
        "confirmed": "confirmată",
        "watch": "monitorizare",
    }

    try:
        params: Dict[str, Any] = {"select": "*", "order": "last_seen.desc"}
        if status:
            mapped = _status_map.get(status, status)
            params["status"] = f"eq.{mapped}"
        if limit > 0:
            params["limit"] = str(limit)
        rows = supabase_store._get_json("scam_campaigns", params)
        logger.info(f"community_campaigns: got {len(rows)} rows for status={status}")
        if not rows:
            logger.warning(f"community_campaigns: empty result. url={supabase_store.SUPABASE_URL}")
            try:
                debug_resp = requests.get(
                    supabase_store._table_url("scam_campaigns"),
                    headers=supabase_store._headers(),
                    params={"select": "count", "limit": "1"},
                    timeout=supabase_store.SUPABASE_TIMEOUT_SECONDS,
                )
                logger.warning(f"community_campaigns debug: status={debug_resp.status_code} body={debug_resp.text[:200]}")
            except Exception as e:
                logger.warning(f"community_campaigns debug error: {e}")
        return [
            {
                "id": r.get("id", ""),
                "title": r.get("title", ""),
                "brand": r.get("brand", ""),
                "riskLevel": r.get("risk_level", "dangerous"),
                "region": r.get("region"),
                "lat": r.get("lat"),
                "lon": r.get("lon"),
                "scanCount": r.get("scan_count", 0),
                "firstSeen": r.get("first_seen", ""),
                "lastSeen": r.get("last_seen", ""),
                "status": r.get("status", "activă"),
                "description": r.get("description", ""),
                "safeAction": r.get("safe_action", ""),
            }
            for r in rows
        ]
    except Exception as e:
        logger.error(f"community_campaigns error: {e}")
        return []


@app.post("/v1/push/register")
def push_register(payload: PushRegisterRequest):
    if not supabase_store.is_supabase_enabled():
        return {"status": "ok", "note": "supabase not configured"}

    try:
        supabase_store._post_json("push_devices", {
            "token": payload.token,
            "platform": payload.platform,
            "locale": payload.locale,
            "last_seen_at": datetime.now(timezone.utc).isoformat(),
        }, prefer="resolution=merge-duplicates,return=minimal")
    except Exception:
        pass
    return {"status": "ok"}
