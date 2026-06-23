import os
import importlib
import asyncio
import re
import ipaddress
import time
import json
import urllib.parse
import base64
import secrets
from pathlib import Path
from collections import Counter, defaultdict, deque
import hashlib
import traceback  # noqa: used in _on_startup for debug
import requests
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any, Callable, Tuple

try:
    from dotenv import load_dotenv

    load_dotenv(Path(__file__).resolve().parent / ".env")
except Exception:
    pass

from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel
from api_models import *  # re-export API request models
from bs4 import BeautifulSoup
import email
from email import policy, message_from_bytes
from email.message import Message
import logging
import html
from starlette.concurrency import run_in_threadpool
import tldextract
from pypdf import PdfReader
from core.serialization import _deep_copy_jsonable, _merge_missing_dict_values, _merge_progress_dict
from core.text_utils import _normalise_obfuscated_text
from core.identity import _new_scan_id
from core.email_auth import (
    _AUTH_RESULT_RE,
    _DKIM_SIGNATURE_DOMAIN_RE,
    _DKIM_SIGNATURE_SELECTOR_RE,
    _build_auth_action_plan,
    _coerce_int,
    _dmarc_policy_action_label,
    _extract_domain,
    _extract_domain_root,
    _extract_spf_all_mechanism,
    _get_registrable_domain,
    _is_domain_aligned,
    _normalize_auth_status,
    _normalize_dns_text,
    _parse_auth_statuses,
    _parse_dkim_signature_fields,
    EMAIL_AUTH_STATUS_FAILS,
    EMAIL_AUTH_STATUS_UNKNOWN,
)
from core.url_intelligence import (
    URL_REGEX,
    _dedupe_preserve_order,
    extract_urls,
    _canonicalize_url,
    _data_url_contains_sensitive_form,
    _decoded_data_url_text,
    _extract_image_qr_payloads,
    _extract_pdf_annotation_links,
    _extract_pdf_embedded_text,
    _extract_pdf_qr_payloads,
    _merge_ocr_and_embedded_text,
    _non_http_deeplink_context,
    _normalize_sanb_attestation,
)
from core.click_intelligence import _collect_click_targets_from_html, _collect_form_context_from_html
from core.scan_context import (
    _attach_initial_url_privacy,
    EVAL_DATASET_ALLOWED_ROOT,
    EVAL_DATASET_DEFAULT_PATH,
    _decode_repeated_url_value,
    _extract_email_mime_parts,
    _feedback_sample_payload,
    _resolve_eval_dataset_path,
    _safe_mode_url_entry as _core_safe_mode_url_entry,
    _safe_scan_url_list as _core_safe_scan_url_list,
    _infer_brand_hints_from_click_targets,
    _merge_url_privacy,
)
from core.request_security import (
    _env_present,
    _provider_config_status,
    _extract_api_key,
    _extract_client_instance_id,
    _play_integrity_client_binding,
    _internal_worker_token_matches,
    _require_internal_worker_auth,
    _is_screenshot_proxy_path,
    _is_integrity_guarded_path,
    _is_play_integrity_nonce_path,
)

# Import our custom services
from services.pii_redactor import redact_pii
from services.external_url_privacy import (
    prepare_external_url,
    prepare_external_urls,
    prepare_reputation_lookup_url,
    sanitize_resolved_url_entries,
    sanitize_external_text,
)
from services.redirect_resolver import (
    resolve_redirects_safely,
    is_known_shortener,
    _is_scan_target_blocked,
    get_spf_dns_record,
    get_dmarc_policy,
    check_dkim_dns_record,
)
from services.reputation_enrich import (
    _analysis_needs_deep_reputation_fallback,
    _analyze_with_reputation,
    _attach_reputation_lookup_hashes,
    _attach_reputation_lookup_urls,
    _external_intel_provider_error,
    _external_intel_summary_from_threat_intel,
    _gather_external_intel,
    _gather_external_intel_safe,
    _has_authoritative_bad_provider_verdict,
    _has_bad_provider_verdict,
    _normalize_reputation_hashes,
    _provider_payload_is_hard_bad,
    _reputation_lookup_hashes_by_url_from_resolved_entries,
    _reputation_lookup_urls_from_resolved_entries,
    _sanitize_external_intel_results,
)
from services.provider_gate import _apply_provider_gate_verdict, _maybe_add_dns_reputation, _project_provider_gate_verdict
from services.scam_atlas import BRAND_ID_TO_DISPLAY_NAME, BRAND_REGISTRY, BRAND_WARNING_RULES, ScamAtlasEngine
from services.tier1_classifier import LEGIT_LABELS as TIER1_LEGIT_LABELS
from services.tier1_classifier import Tier1Classifier
from services.gemini_explainer import generate_ai_explanation, generate_fallback_explanation
from services.evidence_bundle import build_evidence_bundle
from services.verdict_gate import verdict as reduce_verdict
from services.cfx_engine import extract_fingerprint, CampaignFingerprint, FingerprintMatch
from app_stores import brand_truth_registry, campaign_store, urechea_ingester, cfx_store
from services.mistral_shadow_adjudicator import maybe_run_shadow_adjudication
from services.offer_claim_verifier import verify_offer_claim
from services.url_reputation import get_reputation_cache_stats, get_reputation_for_urls, reputation_url_hash_variants
from services.whois_ssl_signals import check_domain_ssl_parallel, domain_risk_from_signals
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
from services import play_integrity, play_integrity_nonce, rate_limiter, supabase_store
from services.google_vision_ocr import (
    has_vision_key,
    extract_text_with_vision,
    extract_text_from_pdf_with_vision,
)
from config import *  # noqa: F401,F403
from config import (
    _LEGACY_SCREENSHOT_PROXY_HOSTS,
    _SCREENSHOT_PROXY_PATH_RE,
    _INTEGRITY_GUARDED_PREFIXES,
    _ORCHESTRATED_STAGE_RANK,
    _VERDICT_SEVERITY_RANK,
)

from runtime_state import _URLSCAN_PREVIEW_CACHE, _FAST_PREVIEW_CACHE

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("main")

app = FastAPI(
    title="SigurScan API",
    description="Anti-scam detection engine localized for Romania (2025-2026)",
    version="1.0",
    docs_url="/docs" if EXPOSE_API_DOCS else None,
    redoc_url="/redoc" if EXPOSE_API_DOCS else None,
    openapi_url="/openapi.json" if EXPOSE_API_DOCS else None,
)

if PRIVACY_SAFE_MODE:
    logger.warning("SIGURSCAN_SAFE_MODE activ: verificările externe pentru URL/reputație și Gemini sunt dezactivate.")

# Enable CORS for local testing from React Native/Expo web
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials="*" not in ALLOWED_ORIGINS,
    allow_methods=ALLOWED_CORS_METHODS,
    allow_headers=ALLOWED_CORS_HEADERS,
)


@app.middleware("http")
async def security_guard(request: Request, call_next):
    path = request.url.path
    if path in PUBLIC_PATHS or request.method == "OPTIONS":
        return await call_next(request)

    api_key = _extract_api_key(request)
    internal_worker_authorized = path.startswith("/internal/") and _internal_worker_token_matches(request)
    integrity_verdict = None
    integrity_can_authorize_client = False
    should_check_integrity = (
        play_integrity.mode() != "off"
        and request.method == "POST"
        and _is_integrity_guarded_path(path)
    )
    if should_check_integrity:
        integrity_verdict = play_integrity.evaluate_request_token(
            request.headers.get(play_integrity.INTEGRITY_TOKEN_HEADER, ""),
            _play_integrity_client_binding(request, api_key),
        )
        integrity_can_authorize_client = (
            play_integrity.mode() == "enforce"
            and not integrity_verdict["block"]
            and (integrity_verdict.get("result") or {}).get("status") == "valid"
        )

    # Operator endpoints: separate admin keys, fail closed when unconfigured.
    if internal_worker_authorized:
        return await call_next(request)
    if path in ADMIN_ONLY_PATHS:
        if not ADMIN_API_KEYS:
            return JSONResponse(
                status_code=403,
                content={"detail": "Admin access is not configured on this deployment."},
            )
        if not api_key or api_key not in ADMIN_API_KEYS:
            return JSONResponse(status_code=401, content={"detail": "Missing or invalid admin API key."})
    elif REQUIRE_API_KEY and not (request.method == "GET" and _is_screenshot_proxy_path(path)):
        # Fail closed: requiring a key while configuring none is a deployment
        # error and must not silently open the API.
        nonce_request_allowed = _is_play_integrity_nonce_path(path) and play_integrity.mode() != "off"
        api_key_authorized = bool(api_key and api_key in ALLOWED_API_KEYS)
        if not api_key_authorized and not integrity_can_authorize_client and not nonce_request_allowed:
            return JSONResponse(status_code=401, content={"detail": "Missing or invalid API key."})

    if integrity_verdict is not None:
        if integrity_verdict["block"]:
            return JSONResponse(
                status_code=401,
                content={"detail": "Play Integrity verification failed.", "integrity": integrity_verdict["result"]},
            )

    if ENABLE_RATE_LIMIT:
        decision = await asyncio.to_thread(
            rate_limiter.check_sync,
            api_key or None,
            request.client.host if request.client else "anonymous",
            path,
            RATE_LIMIT_PER_MINUTE,
            path in ADMIN_ONLY_PATHS and api_key in ADMIN_API_KEYS,
        )
        if not decision.allowed:
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many requests. Try again later."},
                headers={"Retry-After": str(decision.retry_after_seconds or RATE_LIMIT_WINDOW_SECONDS)},
            )

    return await call_next(request)

# Initialize engine, registries, and OSINT pipeline
engine = ScamAtlasEngine()
tier1_classifier = Tier1Classifier.load_default()



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


def _safe_mode_url_entry(url: str) -> Dict[str, Any]:
    return _core_safe_mode_url_entry(url, privacy_safe_mode=PRIVACY_SAFE_MODE)


def _safe_scan_url_list(urls: List[str]) -> List[Dict[str, Any]]:
    return _core_safe_scan_url_list(
        urls,
        privacy_safe_mode=PRIVACY_SAFE_MODE,
        resolve_redirects_safely_fn=resolve_redirects_safely,
    )


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


def _official_destination_confirmed(resolved_urls: List[Dict[str, Any]], claimed_brand: str) -> bool:
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


def _normalize_claimed_brand(raw_brand: str) -> str:
    normalized = str(raw_brand or "").strip().lower()
    if not normalized or normalized in {"nespecificat", "unknown", "none"}:
        return ""
    return normalized


def _compact_brand_match_token(raw: str) -> str:
    text = _normalise_obfuscated_text(str(raw or "")).lower()
    return re.sub(r"[^a-z0-9]+", "", text)


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


def _has_direct_sensitive_request(raw_text: str) -> bool:
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


def _has_explicit_user_directed_action(raw_text: str) -> bool:
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
        "identitate",
        "pay",
        "plata",
        "plată",
        "checkout",
        "achita",
        "securitate",
        "security",
        "update",
        "install",
        "session",
    )
    for entry in resolved_urls or []:
        url = str(entry.get("final_url") or entry.get("url") or "")
        parsed = urllib.parse.urlparse(url)
        target = urllib.parse.unquote(f"{parsed.path or ''}?{parsed.query or ''}").lower()
        if any(token in target for token in sensitive_path_tokens):
            return True
    return False


def _collect_infrastructure_flags(
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

    # Merge RDAP/SSL deterministic signals from WHOIS/RDAP parallel check.
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

    # host_unreachable intentionally does NOT enter the provider summary: a
    # pseudo-provider entry with unknown status would block official_clean on
    # transient network errors. The signal still flows via identity context
    # (host_unreachable) and the weighted risk score.


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
        }:
            return "transfer"
        if matched_family in {"bank_data_collection", "external_card_cvv_otp_collection"}:
            return "card"
        if matched_family in {"brand_login_update_link", "password_update_link", "safety_education_login_pretext", "data_url_credential_form"}:
            return "password"
        if matched_family in {"executable_invoice_attachment", "security_update_install_link", "deeplink_fallback_login_or_install"}:
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


MISTRAL_SEMANTIC_SYSTEM_PROMPT = """
Ești pilonul semantic SigurScan pentru mesaje în limba română.
Nu ai voie să dai verdict final și nu ai voie să folosești etichete SIGUR/SUSPECT/PERICULOS.
Primești text redactat, domenii finale și context atlas/corpus. Întorci doar semantic_review structurat.
Reguli:
- Marchează high doar când claim-ul seamănă clar cu o familie scam sau cere acțiuni sensibile/social-engineering.
- Marchează benign doar când claim-ul seamănă cu un șablon legitim/marketing normal și nu cere date sensibile.
- Marketing language, CTA, reduceri, catalog, newsletter sau link sub buton nu sunt suficiente pentru high.
- Tratează ca high cererile de cod/OTP parțial sau complet, cod unic din aplicația bancară, captură/screenshot de cod QR eSIM, PIN/CVV/card, parole, seed phrase sau date de identitate.
- Tratează ca high pretextele de siguranță care cer login/autentificare într-un simulator, link extern, formular data: sau deeplink de aplicație.
- Tratează ca high transferurile către cont/beneficiar de siguranță, cont nou, IBAN migrat, transfer test, depozit rambursabil de colet sau taxă/token de eliberare pachet.
- Tratează ca high URL-urile cu userinfo spoofing de forma brand.ro@alt-domeniu și deeplink-urile/native/data URL care cer acțiuni sensibile.
- Textul educațional legitim de tip "nu comunica OTP/parola, sună canalul oficial" este benign doar dacă nu cere apoi login, transfer, cod, instalare sau contact prin canal neoficial.
- Separă intenția de textul descriptiv: un articol, ghid, status de tranzacție, control de audit sau factură care doar menționează OTP/card/IBAN/scam NU este cerere de acțiune.
- Marchează positive_action_request=true doar când utilizatorului i se cere să facă ceva: să introducă/dateze/trimită coduri, card, parolă, să plătească/transfere, să instaleze, să sune/continue apelul sau să apese un link pentru verificare.
- Rezolvă negațiile: "nu comunica OTP", "nu accesa linkuri", "IBAN-ul nu s-a schimbat", "fără plată/link/card" sunt protective/descriptive dacă nu există o cerere opusă după ele.
- Nu inventa branduri, domenii, provider hits sau fapte lipsă.
Răspunde strict JSON:
{
  "risk_class": "high|medium|benign|unknown",
  "claim_matches_known_scam_family": false,
  "matched_family": null,
  "claim_matches_legit_template": false,
  "matched_template": null,
  "reason_codes": ["semantic:..."],
  "social_engineering": {
    "intent": "credential_theft|payment_redirection|remote_access|investment_fraud|impersonation|recovery_scam|benign|unknown",
    "ask_present": false,
    "ask_type": ["transfer|otp|card|remote_install|gift_card|seed_phrase|callback|none"],
    "levers": ["authority|fear|urgency|scarcity|liking|reciprocity|social_proof|loss_aversion|sunk_cost|compassion|greed|secrecy"],
    "persona_targeting": "elderly|parent|jobseeker|investor|employee|bereaved|generic",
    "channel_coherence": "coherent|mismatch|unknown",
    "urgency_score": 0.0,
    "confidence": 0.0
  },
  "intent_analysis": {
    "positive_action_request": false,
    "is_protective_warning": false,
    "is_descriptive_or_status": false,
    "negation_scope_resolved": true,
    "invoice_or_payment_document": false,
    "payment_instruction_present": false,
    "payment_instruction_is_requested": false,
    "payment_instruction_is_descriptive": false,
    "describes_fraud_without_request": false,
    "confidence": 0.0
  }
}
""".strip()


def _semantic_review_from_analysis(analysis: Dict[str, Any]) -> Dict[str, Any]:
    evidence = analysis.get("evidence", {}) if isinstance(analysis.get("evidence"), dict) else {}
    review = evidence.get("semantic_review")
    return review if isinstance(review, dict) else {}


def _semantic_risk_rank(value: Any) -> int:
    return {
        "benign": 0,
        "unknown": 1,
        "medium": 2,
        "high": 3,
    }.get(str(value or "").strip().lower(), 1)


def _unwrap_mistral_semantic_payload(raw: Dict[str, Any]) -> Dict[str, Any]:
    if isinstance(raw, dict) and isinstance(raw.get("semantic_review"), dict):
        nested = dict(raw["semantic_review"])
        if "social_engineering" not in nested and isinstance(raw.get("social_engineering"), dict):
            nested["social_engineering"] = raw["social_engineering"]
        if "intent_analysis" not in nested and isinstance(raw.get("intent_analysis"), dict):
            nested["intent_analysis"] = raw["intent_analysis"]
        return nested
    return raw if isinstance(raw, dict) else {}


def _normalize_mistral_semantic_review(raw: Dict[str, Any], fallback: Dict[str, Any]) -> Dict[str, Any]:
    raw = _unwrap_mistral_semantic_payload(raw)
    risk_class = str(raw.get("risk_class") or raw.get("severity") or "unknown").strip().lower()
    if risk_class not in {"high", "medium", "benign", "unknown"}:
        risk_class = "unknown"
    fallback_risk_class = str(fallback.get("risk_class") or "unknown").strip().lower()
    reason_codes = [
        str(item).strip()
        for item in raw.get("reason_codes") or []
        if str(item).strip()
    ]
    if not reason_codes:
        reason_codes = [f"semantic:{risk_class}"]
    matched_template_raw = str(raw.get("matched_template") or "").strip().lower()
    model_says_protective_education = (
        risk_class == "benign"
        and not bool(raw.get("claim_matches_known_scam_family"))
        and (
            bool(raw.get("claim_matches_legit_template"))
            or matched_template_raw in {"safety_education", "educational_warning", "protective_warning"}
            or any("educat" in code.lower() or "safety" in code.lower() for code in reason_codes)
        )
    )
    preserve_atlas_high = (
        fallback_risk_class == "high"
        and _semantic_risk_rank(risk_class) < _semantic_risk_rank("high")
        and not model_says_protective_education
    )
    if preserve_atlas_high:
        risk_class = "high"
        reason_codes = _dedupe_preserve_order(reason_codes + ["semantic:atlas_high_preserved"])

    legit_template = (bool(raw.get("claim_matches_legit_template")) or risk_class == "benign") and risk_class == "benign"

    intent_analysis = _normalize_model_intent_analysis(raw.get("intent_analysis"), {})

    review = {
        "status": "done",
        "claim_matches_known_scam_family": (
            bool(raw.get("claim_matches_known_scam_family"))
            or risk_class in {"high", "medium"}
            or (preserve_atlas_high and bool(fallback.get("claim_matches_known_scam_family")))
        ),
        "matched_family": raw.get("matched_family") or fallback.get("matched_family"),
        "claim_matches_legit_template": legit_template,
        "matched_template": (raw.get("matched_template") or fallback.get("matched_template")) if legit_template else None,
        "reason_codes": _dedupe_preserve_order(reason_codes + ["semantic:mistral_pillar"]),
        "risk_class": risk_class,
        "confidence": raw.get("confidence"),
        "completeness": True,
        "source": "mistral_semantic_pillar",
        "fallback_source": fallback.get("source"),
    }
    if intent_analysis.get("status") == "done":
        review["intent_analysis"] = intent_analysis
    return review


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


def _calibrate_semantic_review_with_tier1(
    review: Dict[str, Any],
    classifier_result: Dict[str, Any],
    *,
    raw_text: str,
) -> Dict[str, Any]:
    if not isinstance(review, dict) or not isinstance(classifier_result, dict):
        return review

    label = str(classifier_result.get("label") or "").strip().lower()
    try:
        confidence = float(classifier_result.get("confidence") or 0.0)
    except (TypeError, ValueError):
        confidence = 0.0

    # P0 guard: tier1 may calm a false-positive on genuine marketing text, but it
    # must NEVER calm genuine social-engineering pressure (authority, secrecy,
    # out-of-band callback, safe-account, threat). Without this an authority/
    # safe-account scam gets stomped to benign — the root cause of SE blindness.
    # (Severity is NOT used as a guard: a high atlas false-positive on plain
    # marketing must still be downgradable — see tier1 FP calibration test.)
    if (
        label not in TIER1_LEGIT_LABELS
        or confidence < 0.55
        or _has_social_engineering_pressure(raw_text)
        or _has_direct_sensitive_request(raw_text)
        or _has_investment_money_risk(raw_text)
    ):
        return review

    calibrated = dict(review)
    calibrated["risk_class"] = "benign"
    calibrated["claim_matches_known_scam_family"] = False
    calibrated["matched_family"] = None
    calibrated["claim_matches_legit_template"] = True
    calibrated["matched_template"] = label
    calibrated["tier1_classifier"] = classifier_result
    calibrated["calibration_source"] = "tier1_local_classifier"
    calibrated["reason_codes"] = _dedupe_preserve_order(
        list(calibrated.get("reason_codes") or [])
        + [f"semantic:tier1_{label}", "semantic:tier1_legit_override"]
    )
    return calibrated


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
            "max_tokens": 620,
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
    provider_safe_text = sanitize_external_text(redacted_text)
    provider_safe_resolved_urls = sanitize_resolved_url_entries(resolved_urls)
    fallback = _semantic_review_from_analysis(analysis)
    tier1_result = tier1_classifier.classify(redacted_text or "")
    evidence["tier1_classifier"] = tier1_result
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
        evidence["semantic_review"] = _calibrate_semantic_review_with_tier1(
            fallback,
            tier1_result,
            raw_text=provider_safe_text,
        )
        evidence["social_engineering"] = _social_engineering_signal_for_decision_bundle(
            provider_safe_text,
            request_sensitive="none",
            source_channel=str(evidence.get("source_channel") or ""),
            semantic_review=evidence["semantic_review"],
        )
        return

    payload = {
        "redacted_text": (provider_safe_text or "")[:2500],
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
            for item in (provider_safe_resolved_urls or [])[:5]
            if isinstance(item, dict)
        ],
        "external_intel_summary": evidence.get("external_intel_summary") if isinstance(evidence.get("external_intel_summary"), dict) else {},
    }
    try:
        raw_review = await run_in_threadpool(_call_mistral_semantic_review, payload)
        raw_semantic_review = _unwrap_mistral_semantic_payload(raw_review)
        normalized_review = _normalize_mistral_semantic_review(raw_review, fallback)
        evidence["semantic_review"] = _calibrate_semantic_review_with_tier1(
            normalized_review,
            tier1_result,
            raw_text=provider_safe_text,
        )
        local_social_engineering = _social_engineering_signal_for_decision_bundle(
            provider_safe_text,
            request_sensitive="none",
            source_channel=str(evidence.get("source_channel") or ""),
            semantic_review=evidence["semantic_review"],
        )
        evidence["social_engineering"] = _normalize_model_social_engineering_signal(
            raw_semantic_review.get("social_engineering"),
            local_social_engineering,
        )
    except Exception as exc:
        fallback = dict(fallback)
        fallback["source"] = fallback.get("source") or "scam_atlas_family_match"
        fallback["mistral_status"] = "failed"
        fallback["mistral_error"] = type(exc).__name__
        fallback["reason_codes"] = _dedupe_preserve_order(list(fallback.get("reason_codes") or []) + ["semantic:mistral_fallback"])
        evidence["semantic_review"] = _calibrate_semantic_review_with_tier1(
            fallback,
            tier1_result,
            raw_text=provider_safe_text,
        )
        evidence["social_engineering"] = _social_engineering_signal_for_decision_bundle(
            provider_safe_text,
            request_sensitive="none",
            source_channel=str(evidence.get("source_channel") or ""),
            semantic_review=evidence["semantic_review"],
        )


def _enrich_local_semantic_review(redacted_text: str, analysis: Dict[str, Any]) -> None:
    evidence = analysis.setdefault("evidence", {})
    fallback = _semantic_review_from_analysis(analysis)
    tier1_result = tier1_classifier.classify(redacted_text or "")
    evidence["tier1_classifier"] = tier1_result
    if not fallback:
        fallback = {
            "status": "done",
            "risk_class": "unknown",
            "claim_matches_known_scam_family": False,
            "claim_matches_legit_template": False,
            "reason_codes": ["semantic:atlas_local_fast_lane"],
            "completeness": True,
            "source": "atlas_local_fast_lane",
        }
    evidence["semantic_review"] = _calibrate_semantic_review_with_tier1(
        fallback,
        tier1_result,
        raw_text=redacted_text,
    )
    evidence["social_engineering"] = _social_engineering_signal_for_decision_bundle(
        redacted_text,
        request_sensitive="none",
        source_channel=str(evidence.get("source_channel") or ""),
        semantic_review=evidence["semantic_review"],
    )


def _detect_person_never_does_violations(
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


def _enrich_with_btr_provenance(
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
    _detect_person_never_does_violations(raw_text, effective_channel, result, violated_never_does)
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
    if normalized == "DANGEROUS":
        return True
    if normalized in {"SAFE", "SUSPECT", "UNVERIFIED", "NECUNOSCUT"}:
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


def _normalize_user_facing_risk_level(risk_level: Optional[str]) -> str:
    normalized = (risk_level or "unknown").strip().lower()
    if normalized in {"high", "critical"}:
        return "dangerous"
    if normalized == "medium":
        return "suspect"
    if normalized in {"low", "safe"}:
        return "safe"
    if normalized in {"info", "unverified"}:
        return "unverified"
    return "unknown"


def _user_risk_level_label(risk_level: str) -> str:
    normalized = (risk_level or "").strip().lower()
    if normalized in {"safe", "suspect", "dangerous"}:
        user_level = normalized
    else:
        user_level = _normalize_user_facing_risk_level(normalized)

    return {
        "dangerous": "DANGEROUS",
        "suspect": "SUSPECT",
        "safe": "SAFE",
        "unverified": "UNVERIFIED",
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


def _preventive_action_plan_for_scan(analysis_results: Dict[str, Any], user_label: str) -> Optional[Dict[str, Any]]:
    if str(user_label or "").upper() not in {"DANGEROUS", "SUSPECT"}:
        return None
    if isinstance(analysis_results.get("action_plan"), dict):
        return analysis_results.get("action_plan")
    try:
        from services.legal_action_plan import build_action_plan

        return build_action_plan(
            verdict=str(user_label or "SUSPECT").upper(),
            family=analysis_results.get("detected_family_id") or analysis_results.get("detected_family"),
            impacts=["none"],
        )
    except Exception:
        return None


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
    user_facing_label = _user_risk_level_label(user_facing_risk_level)
    user_facing_risk_text = _user_risk_level_text(user_facing_risk_level)
    payload = {
        "scan_id": scan_id or _new_scan_id(scan_id_prefix),
        "risk_score": risk_score if risk_score is not None else analysis_results.get("risk_score", 0),
        "risk_level": normalized_risk_level,
        "user_risk_level": user_facing_risk_level,
        "user_risk_label": user_facing_label,
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
        # Strat educativ „Ce spune legea" (PR5): {label, cards[], disclaimer}.
        # Prezent doar pe ruta ofertă; clientul îl randează verbatim, sub verdict.
        "legal": analysis_results.get("legal"),
        # PR-8: plan de acțiune preventiv (TriageScreen), prezent pe verdicte de risc.
        "action_plan": _preventive_action_plan_for_scan(analysis_results, user_facing_label),
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
    safe_resolved_urls = sanitize_resolved_url_entries(resolved_urls)
    safe_text = sanitize_external_text(scan_payload.get("redacted_text") or "")

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
        "url_count": len(safe_resolved_urls),
        "urls": [_extract_url_signal(item) for item in safe_resolved_urls],
        "redacted_text_snippet": safe_text[:120],
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
            redacted_text=safe_text,
            analysis=analysis,
            resolved_urls=safe_resolved_urls,
            scan_payload=scan_payload,
        )
        maybe_run_shadow_adjudication(
            scan_id=scan_id,
            input_type=input_channel,
            source_channel=source_channel,
            evidence=evidence_bundle,
        )











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
    magic_validator: Optional[Callable[[bytes], bool]] = None,
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
    if magic_validator is not None and not magic_validator(file_bytes):
        raise HTTPException(
            status_code=400,
            detail="Fișierul nu pare să fie un format valid pentru tipul declarat.",
        )


def _is_allowed_image_bytes(file_bytes: bytes) -> bool:
    if file_bytes.startswith(b"\xff\xd8\xff"):
        return True
    if file_bytes.startswith(b"\x89PNG\r\n\x1a\n"):
        return True
    return len(file_bytes) >= 12 and file_bytes[:4] == b"RIFF" and file_bytes[8:12] == b"WEBP"


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
def _build_ai_explanation(
    text: str,
    analysis: Dict[str, Any],
    resolved_urls: List[Dict[str, Any]],
) -> Dict[str, Any]:
    provider_safe_text = sanitize_external_text(text)
    provider_safe_resolved_urls = sanitize_resolved_url_entries(resolved_urls)
    if PRIVACY_SAFE_MODE:
        return generate_fallback_explanation(provider_safe_text, analysis)
    return generate_ai_explanation(provider_safe_text, analysis, provider_safe_resolved_urls)


async def _build_ai_explanation_async(
    text: str,
    analysis: Dict[str, Any],
    resolved_urls: List[Dict[str, Any]],
) -> Dict[str, Any]:
    provider_safe_text = sanitize_external_text(text)
    provider_safe_resolved_urls = sanitize_resolved_url_entries(resolved_urls)
    if PRIVACY_SAFE_MODE or not ENABLE_CLOUD_AI_EXPLANATION or AI_EXPLANATION_TIMEOUT_SECONDS <= 0:
        return generate_fallback_explanation(provider_safe_text, analysis)

    try:
        return await asyncio.wait_for(
            run_in_threadpool(generate_ai_explanation, provider_safe_text, analysis, provider_safe_resolved_urls),
            timeout=AI_EXPLANATION_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        logger.warning("AI explanation timed out; using deterministic fallback.")
    except Exception as exc:
        logger.warning("AI explanation failed; using deterministic fallback: %s", exc)
    return generate_fallback_explanation(provider_safe_text, analysis)


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
        provider_safe_text = sanitize_external_text(text)
        provider_safe_resolved_urls = sanitize_resolved_url_entries(resolved_urls)
        offer_claim = await asyncio.wait_for(
            run_in_threadpool(
                verify_offer_claim,
                provider_safe_text,
                analysis,
                provider_safe_resolved_urls,
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
    privacy = prepare_external_url(url)
    safe_url = privacy.get("external_url")
    if not isinstance(safe_url, str) or not safe_url:
        raise HTTPException(status_code=400, detail="URL invalid sau format neacceptat.")
    if privacy.get("preview_allowed") is False or privacy.get("action") in {"origin_only", "blocked"}:
        raise HTTPException(
            status_code=400,
            detail="URL blocat pentru sandbox din motive de privacy: contine date sensibile in path.",
        )
    url = safe_url
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
        "screenshot_url": _public_route_url(request, "urlscan_screenshot", uuid=uuid),
        "score": score,
        "categories": categories,
        "brands": brands[:4],
    }


def _canonical_urlscan_preview_cache_url(raw_url: Any) -> Optional[str]:
    url = str(raw_url or "").strip()
    if not url:
        return None
    try:
        parsed = urllib.parse.urlsplit(url)
    except Exception:
        return None
    if not parsed.scheme or not parsed.netloc:
        return url
    return urllib.parse.urlunsplit(
        (
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path or "/",
            parsed.query,
            "",
        )
    )


def _urlscan_preview_cache_key(final_url: Any) -> Optional[str]:
    canonical_url = _canonical_urlscan_preview_cache_url(final_url)
    if not canonical_url:
        return None
    return hashlib.sha256(canonical_url.encode("utf-8")).hexdigest()


def _fast_preview_cache_lookup_keys(final_url: Any) -> List[str]:
    canonical_url = _canonical_urlscan_preview_cache_url(final_url)
    if not canonical_url:
        return []
    candidates = [canonical_url]
    try:
        parsed = urllib.parse.urlsplit(canonical_url)
    except Exception:
        parsed = None
    if parsed and parsed.query:
        queryless_url = urllib.parse.urlunsplit(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path or "/",
                "",
                "",
            )
        )
        if queryless_url and queryless_url not in candidates:
            candidates.append(queryless_url)
    keys: List[str] = []
    for candidate in candidates:
        cache_key = _urlscan_preview_cache_key(candidate)
        if cache_key and cache_key not in keys:
            keys.append(cache_key)
    return keys


def _urlscan_preview_cache_is_fresh(entry: Dict[str, Any]) -> bool:
    raw_expires_at = entry.get("expires_at")
    try:
        expires_at = int(raw_expires_at or 0)
    except Exception:
        try:
            expires_at = int(datetime.fromisoformat(str(raw_expires_at).replace("Z", "+00:00")).timestamp())
        except Exception:
            expires_at = 0
    return not expires_at or expires_at > int(time.time())


def _trim_preview_cache(cache: Dict[str, Dict[str, Any]], max_entries: int) -> None:
    try:
        limit = max(0, int(max_entries))
    except Exception:
        limit = 0

    for cache_key, entry in list(cache.items()):
        if not isinstance(entry, dict) or not _urlscan_preview_cache_is_fresh(entry):
            cache.pop(cache_key, None)

    if limit <= 0:
        cache.clear()
        return

    while len(cache) > limit:
        oldest_key = next(iter(cache), None)
        if oldest_key is None:
            break
        cache.pop(oldest_key, None)


def _remember_preview_cache_entry(
    cache: Dict[str, Dict[str, Any]],
    cache_key: str,
    entry: Dict[str, Any],
    max_entries: int,
) -> None:
    if not cache_key or not isinstance(entry, dict):
        return
    cache.pop(cache_key, None)
    cache[cache_key] = entry
    _trim_preview_cache(cache, max_entries)


def _normalize_screenshot_proxy_url(raw_url: Any) -> str:
    value = str(raw_url or "").strip()
    if not value:
        return ""
    public_base = SIGURSCAN_PUBLIC_API_BASE_URL or "https://api.sigurscan.com"
    parsed_public = urllib.parse.urlparse(public_base)
    public_host = (parsed_public.hostname or "").lower()
    parsed = urllib.parse.urlparse(value)

    if parsed.scheme and parsed.netloc:
        host = (parsed.hostname or "").lower()
        if _SCREENSHOT_PROXY_PATH_RE.match(parsed.path) and (
            host in _LEGACY_SCREENSHOT_PROXY_HOSTS or host == public_host
        ):
            return f"{public_base}{parsed.path}"
        return value

    if value.startswith("/") and _SCREENSHOT_PROXY_PATH_RE.match(value):
        return f"{public_base}{value}"

    return value


def _supabase_signed_preview_object_path(raw_url: Any, *, bucket: str = "previews") -> Optional[str]:
    value = str(raw_url or "").strip()
    if not value:
        return None
    try:
        parsed = urllib.parse.urlparse(value)
    except Exception:
        return None
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    path = parsed.path or ""
    marker = f"/storage/v1/object/sign/{bucket}/"
    if marker not in path:
        return None
    object_path = path.split(marker, 1)[1].strip("/")
    if not object_path:
        return None
    return urllib.parse.unquote(object_path)


def _public_route_url(request: Request, route_name: str, **path_params: Any) -> str:
    generated = str(request.url_for(route_name, **path_params))
    public_base = SIGURSCAN_PUBLIC_API_BASE_URL or "https://api.sigurscan.com"
    parsed = urllib.parse.urlparse(generated)
    path = parsed.path or "/"
    query = f"?{parsed.query}" if parsed.query else ""
    return f"{public_base}{path}{query}"




def _cloud_tasks_access_token() -> str:
    response = requests.get(
        CLOUD_TASKS_METADATA_TOKEN_URL,
        headers={"Metadata-Flavor": "Google"},
        timeout=CLOUD_TASKS_REQUEST_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    token = str((response.json() or {}).get("access_token") or "").strip()
    if not token:
        raise RuntimeError("Cloud Tasks metadata token is empty")
    return token






def _normalize_urlscan_preview_cache_entry(entry: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(entry, dict):
        return None
    final_url = str(entry.get("final_url") or entry.get("canonical_url") or "").strip()
    report_url = str(entry.get("report_url") or "").strip()
    screenshot_url = _normalize_screenshot_proxy_url(entry.get("screenshot_url"))
    if not final_url or not report_url:
        return None
    final_privacy = prepare_external_url(final_url)
    if (
        final_privacy.get("preview_allowed") is False
        or final_privacy.get("action") != "unchanged"
    ):
        return None
    safe_final_url = str(final_privacy.get("external_url") or "").strip()
    submitted_url = str(entry.get("submitted_url") or entry.get("canonical_url") or final_url).strip()
    submitted_privacy = prepare_external_url(submitted_url)
    if (
        submitted_privacy.get("preview_allowed") is False
        or submitted_privacy.get("action") != "unchanged"
    ):
        return None
    safe_submitted_url = str(submitted_privacy.get("external_url") or safe_final_url).strip()
    if not safe_final_url or not safe_submitted_url:
        return None
    normalized = dict(entry)
    normalized["status"] = "finished"
    normalized["final_url"] = safe_final_url
    normalized["submitted_url"] = safe_submitted_url
    if normalized.get("canonical_url"):
        normalized["canonical_url"] = safe_submitted_url
    normalized["url_privacy"] = _merge_url_privacy(
        final_privacy,
        submitted_privacy,
    )
    normalized["screenshot_url"] = screenshot_url
    normalized["report_url"] = report_url
    normalized["screenshot_ready"] = bool(normalized.get("screenshot_ready")) and bool(screenshot_url)
    normalized["cache_hit"] = True
    normalized.setdefault("verdict", "No malicious classification")
    normalized.setdefault("severity", "low")
    normalized.setdefault("details", "urlscan preview cache hit")
    normalized.setdefault("score", 0)
    normalized.setdefault("categories", [])
    normalized.setdefault("brands", [])
    if not _urlscan_preview_cache_is_fresh(normalized):
        return None
    return normalized


def _load_urlscan_preview_cache(final_url: Any) -> Optional[Dict[str, Any]]:
    cache_key = _urlscan_preview_cache_key(final_url)
    if not cache_key:
        return None
    cached = _normalize_urlscan_preview_cache_entry(_URLSCAN_PREVIEW_CACHE.get(cache_key))
    if cached:
        _remember_preview_cache_entry(
            _URLSCAN_PREVIEW_CACHE,
            cache_key,
            cached,
            URLSCAN_PREVIEW_CACHE_MAX_ENTRIES,
        )
        return cached
    persisted = _normalize_urlscan_preview_cache_entry(supabase_store.load_urlscan_preview_cache(cache_key))
    if persisted:
        _remember_preview_cache_entry(
            _URLSCAN_PREVIEW_CACHE,
            cache_key,
            persisted,
            URLSCAN_PREVIEW_CACHE_MAX_ENTRIES,
        )
    return persisted


def _normalize_fast_preview_cache_entry(entry: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(entry, dict):
        return None
    if entry.get("visual_only") is False or str(entry.get("verdict_role") or "none").strip().lower() != "none":
        return None
    status = str(entry.get("status") or "").strip().lower()
    final_url = str(entry.get("final_url") or "").strip()
    screenshot_path = str(entry.get("screenshot_path") or "").strip()
    if status != "ready" or not final_url or not screenshot_path or not entry.get("reachable"):
        return None
    final_privacy = prepare_external_url(final_url)
    if (
        final_privacy.get("preview_allowed") is False
        or final_privacy.get("action") != "unchanged"
    ):
        return None
    if not _urlscan_preview_cache_is_fresh(entry):
        return None

    now = int(time.time())
    cached_image_url = str(entry.get("image_url") or entry.get("screenshot_url") or "").strip()
    signed_object_path = (
        _supabase_signed_preview_object_path(screenshot_path)
        or _supabase_signed_preview_object_path(cached_image_url)
    )
    durable_screenshot_path = signed_object_path or screenshot_path
    image_url = None if signed_object_path else (
        screenshot_path if screenshot_path.startswith(("http://", "https://")) else None
    )
    try:
        signed_url_expires_at = int(entry.get("_signed_url_expires_at") or 0)
    except (TypeError, ValueError):
        signed_url_expires_at = 0
    if not image_url and cached_image_url and signed_url_expires_at > now + 5:
        image_url = cached_image_url
    if not image_url:
        image_url = supabase_store.create_preview_signed_url(
            durable_screenshot_path,
            bucket="previews",
            expires_in_seconds=FAST_PREVIEW_SIGNED_URL_TTL_SECONDS,
        )
    if not image_url:
        return None

    normalized = dict(entry)
    normalized["status"] = "ready"
    normalized["source"] = "precapture_worker"
    normalized["final_url"] = final_url
    normalized["image_url"] = image_url
    normalized["screenshot_url"] = image_url
    if signed_object_path or not screenshot_path.startswith(("http://", "https://")):
        normalized["_signed_url_expires_at"] = now + max(1, FAST_PREVIEW_SIGNED_URL_TTL_SECONDS - 30)
    normalized["cache_hit"] = True
    normalized["reason"] = None
    return normalized


def _load_fast_preview_cache(final_url: Any) -> Optional[Dict[str, Any]]:
    cache_keys = _fast_preview_cache_lookup_keys(final_url)
    if not cache_keys:
        return None

    for cache_key in cache_keys:
        cached = _normalize_fast_preview_cache_entry(_FAST_PREVIEW_CACHE.get(cache_key))
        if cached:
            _remember_preview_cache_entry(
                _FAST_PREVIEW_CACHE,
                cache_key,
                cached,
                FAST_PREVIEW_CACHE_MAX_ENTRIES,
            )
            return cached

    persisted = None
    persisted_key = None
    for cache_key in cache_keys:
        persisted = _normalize_fast_preview_cache_entry(supabase_store.load_fast_preview_cache(cache_key))
        persisted_key = cache_key if persisted else None
        if not persisted:
            alias = supabase_store.load_fast_preview_alias_cache(cache_key)
            final_hash = str((alias or {}).get("final_url_hash") or "").strip()
            if final_hash and final_hash != cache_key:
                persisted = _normalize_fast_preview_cache_entry(supabase_store.load_fast_preview_cache(final_hash))
                persisted_key = final_hash if persisted else None
        if persisted:
            break

    if persisted:
        _remember_preview_cache_entry(
            _FAST_PREVIEW_CACHE,
            cache_keys[0],
            persisted,
            FAST_PREVIEW_CACHE_MAX_ENTRIES,
        )
        if persisted_key:
            _remember_preview_cache_entry(
                _FAST_PREVIEW_CACHE,
                persisted_key,
                persisted,
                FAST_PREVIEW_CACHE_MAX_ENTRIES,
            )
    return persisted


def _apply_fast_preview_cache_hit(job: Dict[str, Any], cached: Dict[str, Any]) -> Dict[str, Any]:
    cached_preview = _normalize_fast_preview_cache_entry(cached)
    if not cached_preview:
        return job
    preview = job.setdefault("preview", {})
    # This is visual-only. Do not write to job["urlscan"] or provider evidence.
    preview["status"] = "ready"
    preview["source"] = "precapture_worker"
    preview["final_url"] = cached_preview.get("final_url")
    preview["image_url"] = cached_preview.get("image_url")
    preview["screenshot_url"] = cached_preview.get("screenshot_url")
    preview["page_title"] = cached_preview.get("page_title")
    preview["captured_at"] = cached_preview.get("captured_at")
    preview["width"] = cached_preview.get("screenshot_w")
    preview["height"] = cached_preview.get("screenshot_h")
    preview["cache_hit"] = True
    preview["fast_cache_hit"] = True
    preview["reason"] = None
    orchestrated_engine._increment_orchestrated_metric(job, "fast_preview_cache_hit_count")
    return job


def _apply_best_preview_cache_hit(job: Dict[str, Any], final_url: Any) -> Dict[str, Any]:
    if not final_url:
        return job
    cached_fast = _load_fast_preview_cache(final_url)
    cached_urlscan = _load_urlscan_preview_cache(final_url)
    if cached_urlscan:
        job = _apply_urlscan_preview_cache_hit(job, cached_urlscan)
        if cached_fast:
            return _apply_fast_preview_cache_hit(job, cached_fast)
        preview = job.get("preview") if isinstance(job.get("preview"), dict) else {}
        if preview.get("status") == "ready" and (
            preview.get("image_url") or preview.get("screenshot_url")
        ):
            return job
    if cached_fast:
        return _apply_fast_preview_cache_hit(job, cached_fast)
    return job


def _save_urlscan_preview_cache(entry: Dict[str, Any]) -> None:
    if not isinstance(entry, dict):
        return
    final_url = str(entry.get("final_url") or entry.get("submitted_url") or "").strip()
    submitted_url = str(entry.get("submitted_url") or "").strip()
    report_url = str(entry.get("report_url") or "").strip()
    screenshot_url = str(entry.get("screenshot_url") or "").strip()
    screenshot_ready = bool(entry.get("screenshot_ready", bool(screenshot_url))) and bool(screenshot_url)
    if not final_url or not report_url:
        return
    final_privacy = prepare_external_url(final_url)
    submitted_privacy = prepare_external_url(submitted_url or final_url)
    if (
        final_privacy.get("preview_allowed") is False
        or final_privacy.get("action") != "unchanged"
        or submitted_privacy.get("preview_allowed") is False
        or submitted_privacy.get("action") != "unchanged"
    ):
        return
    hostname = (urllib.parse.urlparse(final_url).hostname or "").lower()
    lookup_urls = [final_url]
    if submitted_url and _canonical_urlscan_preview_cache_url(submitted_url) != _canonical_urlscan_preview_cache_url(final_url):
        lookup_urls.append(submitted_url)

    for lookup_url in lookup_urls:
        cache_key = _urlscan_preview_cache_key(lookup_url)
        canonical_url = _canonical_urlscan_preview_cache_url(lookup_url)
        if not cache_key or not canonical_url:
            continue
        cache_entry = {
            "url_hash": cache_key,
            "canonical_url": canonical_url,
            "final_url": final_url,
            "final_registered_domain": _extract_domain_root(hostname),
            "uuid": entry.get("uuid"),
            "status": "finished",
            "submitted_url": submitted_url or final_url,
            "report_url": report_url,
            "screenshot_url": screenshot_url,
            "screenshot_ready": screenshot_ready,
            "verdict": entry.get("verdict") or "No malicious classification",
            "severity": entry.get("severity") or "low",
            "details": entry.get("details") or "urlscan preview cached",
            "score": entry.get("score") or 0,
            "categories": entry.get("categories") or [],
            "brands": entry.get("brands") or [],
            "expires_at": int(time.time()) + URLSCAN_PREVIEW_CACHE_TTL_SECONDS,
        }
        _remember_preview_cache_entry(
            _URLSCAN_PREVIEW_CACHE,
            cache_key,
            cache_entry,
            URLSCAN_PREVIEW_CACHE_MAX_ENTRIES,
        )
        supabase_store.save_urlscan_preview_cache(cache_entry)


def _merge_threat_intel_sources(
    base: Optional[Dict[str, Dict[str, Any]]],
    overlay: Optional[Dict[str, Dict[str, Any]]],
) -> Dict[str, Dict[str, Any]]:
    merged: Dict[str, Dict[str, Any]] = _deep_copy_jsonable(base or {})

    def should_replace_source(current: Any, incoming: Dict[str, Any]) -> bool:
        if not isinstance(current, dict):
            return True
        current_consulted = bool(current.get("consulted"))
        incoming_consulted = bool(incoming.get("consulted"))
        if current_consulted and not incoming_consulted:
            return False
        return True

    for key, overlay_entry in (overlay or {}).items():
        if not isinstance(overlay_entry, dict):
            continue
        current_entry = merged.get(key)
        if not isinstance(current_entry, dict):
            merged[key] = _deep_copy_jsonable(overlay_entry)
            continue
        current_sources = current_entry.setdefault("sources", {})
        overlay_sources = overlay_entry.get("sources")
        if isinstance(current_sources, dict) and isinstance(overlay_sources, dict):
            for source_name, source_payload in overlay_sources.items():
                if isinstance(source_payload, dict) and should_replace_source(current_sources.get(source_name), source_payload):
                    current_sources[source_name] = _deep_copy_jsonable(source_payload)
        for field in ("verdict", "risk_score", "active_sources", "consulted_sources", "consulted_source_count"):
            if field in overlay_entry:
                current_entry[field] = _deep_copy_jsonable(overlay_entry[field])
    return merged

def _urlscan_merge_rank(state: Dict[str, Any]) -> int:
    status = str((state or {}).get("status") or "").strip().lower()
    if status == "finished" and bool((state or {}).get("screenshot_ready")):
        return 6
    if status == "finished" and _urlscan_state_has_risk(state):
        return 6
    if status == "timeout":
        return 5
    if status in {"error", "rate_limited", "skipped"}:
        return 4
    if status == "finished":
        return 3
    if status == "pending":
        return 2
    if status in {"queued", "submitting"}:
        return 1
    return 0


def _urlscan_state_has_risk(state: Dict[str, Any]) -> bool:
    verdict = str((state or {}).get("verdict") or "").strip().lower()
    severity = str((state or {}).get("severity") or "").strip().lower()
    try:
        score = int((state or {}).get("score") or 0)
    except Exception:
        score = 0
    benign_verdict = any(
        phrase in verdict
        for phrase in (
            "no malicious",
            "not malicious",
            "no classification",
            "no malicious classification",
        )
    )
    if benign_verdict and severity not in {"high", "critical", "medium"} and score < 50:
        return False
    return (
        "malicious" in verdict
        or "phishing" in verdict
        or "suspicious" in verdict
        or severity in {"high", "critical", "medium"}
        or score >= 50
    )


def _preview_merge_rank(state: Dict[str, Any]) -> int:
    status = str((state or {}).get("status") or "").strip().lower()
    has_image = bool((state or {}).get("image_url") or (state or {}).get("screenshot_url"))
    if status == "ready" and has_image:
        return 4
    if status == "unavailable":
        return 3
    if status == "pending":
        return 2
    if status == "ready":
        return 1
    return 0


def _ai_explanation_fingerprint(analysis: Dict[str, Any]) -> str:
    """Keyed by what the explanation text actually depends on, not by pillar
    statuses, so a deferred explanation survives the urlscan report landing
    as long as the verdict itself did not change."""
    evidence = analysis.get("evidence", {}) if isinstance(analysis.get("evidence"), dict) else {}
    gate = evidence.get("verdict_gate") if isinstance(evidence.get("verdict_gate"), dict) else {}
    basis = {
        "label": gate.get("label"),
        "reason_codes": gate.get("reason_codes"),
        "risk_level": analysis.get("risk_level"),
        "family": analysis.get("detected_family_id") or analysis.get("detected_family"),
        "brand": analysis.get("claimed_brand"),
        "reasons": analysis.get("reasons"),
    }
    serialized = json.dumps(basis, sort_keys=True, default=str, ensure_ascii=False)
    return "analysis:" + hashlib.sha256(serialized.encode("utf-8")).hexdigest()


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
    final_privacy = prepare_external_url(final_url)
    safe_final_url = str(final_privacy.get("external_url") or "").strip()
    if not safe_final_url:
        return
    if isinstance(urlscan_summary, dict) and urlscan_summary.get("final_url"):
        urlscan_summary["final_url"] = safe_final_url
    if isinstance(preview, dict) and preview.get("final_url"):
        preview["final_url"] = safe_final_url

    parsed = urllib.parse.urlparse(safe_final_url)
    final_hostname = (parsed.hostname or "").lower()
    final_registered_domain = _extract_domain_root(final_hostname)
    resolved_urls = job.get("resolved_urls") if isinstance(job.get("resolved_urls"), list) else []
    if not resolved_urls:
        original_url = (
            (job.get("urls") or [safe_final_url])[0]
            if isinstance(job.get("urls"), list) and job.get("urls")
            else safe_final_url
        )
        resolved_urls = [{"url": original_url, "original_url": original_url}]
        job["resolved_urls"] = resolved_urls
    if resolved_urls:
        entry = resolved_urls[0]
        if isinstance(entry, dict):
            entry["final_url"] = safe_final_url
            entry["final_hostname"] = final_hostname
            entry["final_registered_domain"] = final_registered_domain
            entry["url_privacy"] = _merge_url_privacy(
                entry.get("url_privacy") if isinstance(entry.get("url_privacy"), dict) else None,
                final_privacy,
            )
            if not entry.get("hostname"):
                original_url = str(entry.get("url") or entry.get("original_url") or "")
                entry["hostname"] = (urllib.parse.urlparse(original_url).hostname or "").lower()
            if not entry.get("registered_domain"):
                entry["registered_domain"] = _extract_domain_root(entry.get("hostname"))
    job["primary_final_url"] = safe_final_url
    job["primary_url_privacy"] = _merge_url_privacy(
        job.get("primary_url_privacy")
        if isinstance(job.get("primary_url_privacy"), dict)
        else None,
        final_privacy,
    )
    extra_fields = job.setdefault("extra_fields", {})
    if isinstance(extra_fields, dict):
        extra_fields["resolved_urls"] = resolved_urls












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
        if not _provider_required_for_runtime(source_name):
            return _pillar("not_required", required=False, details=f"{source_name} dezactivat sau neconfigurat.")
        return _pillar("pending", details=f"{source_name} asteapta scanarea.")
    status = _source_status(summary, source_name)
    consulted = bool(raw.get("consulted", False))
    if not consulted and not _provider_required_for_runtime(source_name):
        return _pillar("not_required", required=False, details=f"{source_name} dezactivat sau neconfigurat.")
    if consulted and status not in {"missing", "unknown", "error"}:
        return _pillar("ok", details=status)
    if status == "error":
        return _pillar("error", details=str(raw.get("error") or raw.get("details") or "provider error"))
    return _pillar("pending" if not consulted else "error", details=status or "unknown")


def _provider_required_for_runtime(source_name: str) -> bool:
    if PRIVACY_SAFE_MODE:
        return False
    normalized = str(source_name or "").strip().lower()
    if normalized == "google_web_risk":
        return _env_present("GOOGLE_WEB_RISK_API_KEY")
    if normalized == "phishing_database":
        return os.getenv("ENABLE_PHISHING_DATABASE", "true").strip().lower() in {"1", "true", "yes", "on"}
    if normalized == "phishtank_online_valid":
        return os.getenv("ENABLE_PHISHTANK", "true").strip().lower() in {"1", "true", "yes", "on"}
    if normalized == "openphish":
        return os.getenv("ENABLE_OPENPHISH", "true").strip().lower() in {"1", "true", "yes", "on"}
    if normalized == "asf_investor_alerts":
        return os.getenv("ENABLE_ASF_INVESTOR_ALERTS", "true").strip().lower() in {"1", "true", "yes", "on"}
    return True


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


def _mark_urlscan_screenshot_unavailable(
    preview: Dict[str, Any],
    *,
    report_url: Any = None,
    final_url: Any = None,
) -> None:
    if report_url and not preview.get("report_url"):
        preview["report_url"] = report_url
    if final_url and not preview.get("final_url"):
        preview["final_url"] = final_url
    preview["status"] = "unavailable"
    preview["source"] = None
    preview["screenshot_url"] = None
    preview["image_url"] = None
    preview["reason"] = "urlscan_screenshot_timeout"
    preview["details"] = URLSCAN_SCREENSHOT_UNAVAILABLE_DETAILS


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
    status = str(urlscan_state.get("status") or "").strip().lower()
    waiting_for_result = status == "pending"
    waiting_for_screenshot = status == "finished" and not urlscan_state.get("screenshot_ready")
    if not waiting_for_result and not waiting_for_screenshot:
        return False
    created_at = int(job.get("created_at") or int(time.time()))
    return int(time.time()) - created_at >= ORCHESTRATED_URLSCAN_PENDING_TIMEOUT_SECONDS


def _urlscan_enhancement_done(job: Dict[str, Any]) -> bool:
    analysis = job.get("analysis") if isinstance(job.get("analysis"), dict) else {}
    evidence = analysis.get("evidence") if isinstance(analysis.get("evidence"), dict) else {}
    summary = evidence.get("external_intel_summary") if isinstance(evidence.get("external_intel_summary"), dict) else {}
    if _has_bad_provider_verdict(summary):
        # Hard provider evidence is already decisive. A screenshot remains useful,
        # but it must never delay a protective PERICULOS result.
        return True
    raw_urls = job.get("urls") if isinstance(job.get("urls"), list) else []
    if not raw_urls:
        return True
    urlscan_state = job.get("urlscan") if isinstance(job.get("urlscan"), dict) else {}
    status = str(urlscan_state.get("status") or "").strip().lower()
    if status == "finished":
        return bool(urlscan_state.get("screenshot_ready"))
    return status in {"error", "timeout", "rate_limited", "skipped"}


def _urlscan_result_ready_for_verdict(job: Dict[str, Any]) -> bool:
    raw_urls = job.get("urls") if isinstance(job.get("urls"), list) else []
    if not raw_urls:
        return True
    urlscan_state = job.get("urlscan") if isinstance(job.get("urlscan"), dict) else {}
    status = str(urlscan_state.get("status") or "").strip().lower()
    return status in {"finished", "error", "timeout", "rate_limited", "skipped"}


def _urlscan_finished_with_risk(job: Dict[str, Any]) -> bool:
    urlscan_state = job.get("urlscan") if isinstance(job.get("urlscan"), dict) else {}
    if str(urlscan_state.get("status") or "").strip().lower() != "finished":
        return False
    return _urlscan_state_has_risk(urlscan_state)


def _official_clean_can_finalize_before_urlscan(
    job: Dict[str, Any],
    analysis: Dict[str, Any],
    pillars: Optional[Dict[str, Dict[str, Any]]] = None,
) -> bool:
    if not isinstance(analysis, dict):
        return False
    evidence = analysis.get("evidence", {}) if isinstance(analysis.get("evidence"), dict) else {}
    gate = evidence.get("verdict_gate") if isinstance(evidence.get("verdict_gate"), dict) else {}
    provider_gate = evidence.get("provider_gate") if isinstance(evidence.get("provider_gate"), dict) else {}
    summary = evidence.get("external_intel_summary") if isinstance(evidence.get("external_intel_summary"), dict) else {}
    resolved_urls = job.get("resolved_urls") if isinstance(job.get("resolved_urls"), list) else []
    raw_urls = job.get("urls") if isinstance(job.get("urls"), list) else []
    claimed_brand = str(analysis.get("claimed_brand") or "Nespecificat")
    family_id = str(
        analysis.get("detected_family_id")
        or provider_gate.get("detected_family_id")
        or gate.get("detected_family_id")
        or ""
    )
    provider_projection = _provider_verdict_for_decision_bundle(
        summary,
        has_urls=bool(raw_urls or resolved_urls),
        pillars=pillars,
    )
    return (
        str(gate.get("label") or "").upper() == "SAFE"
        and family_id == "provider-gate-official-clean"
        and (
            provider_gate.get("official_destination") is True
            or _official_destination_confirmed(resolved_urls, claimed_brand)
        )
        and str(provider_projection.get("verdict") or "").strip().lower() == "clean"
        and not _has_bad_provider_verdict(summary)
    )


def _public_navigation_clean_can_finalize_before_urlscan(
    job: Dict[str, Any],
    analysis: Dict[str, Any],
    pillars: Optional[Dict[str, Dict[str, Any]]] = None,
) -> bool:
    if not isinstance(analysis, dict):
        return False
    evidence = analysis.get("evidence", {}) if isinstance(analysis.get("evidence"), dict) else {}
    gate = evidence.get("verdict_gate") if isinstance(evidence.get("verdict_gate"), dict) else {}
    provider_gate = evidence.get("provider_gate") if isinstance(evidence.get("provider_gate"), dict) else {}
    summary = evidence.get("external_intel_summary") if isinstance(evidence.get("external_intel_summary"), dict) else {}
    family_id = str(
        analysis.get("detected_family_id")
        or provider_gate.get("detected_family_id")
        or gate.get("detected_family_id")
        or ""
    )
    return (
        str(gate.get("label") or "").upper() == "SAFE"
        and family_id == "provider-gate-clean-public-navigation"
        and _baseline_pillars_ready_without_urlscan(pillars or {})
        and not _has_bad_provider_verdict(summary)
    )


def _baseline_pillars_ready_without_urlscan(pillars: Dict[str, Dict[str, Any]]) -> bool:
    required_names = ("final_url", "google_web_risk", "phishing_database", "phishtank_online_valid", "claim_verifier")
    for name in required_names:
        pillar = pillars.get(name)
        if not isinstance(pillar, dict):
            return False
        if pillar.get("required", True) and pillar.get("status") != "ok":
            return False
    return True




def _mark_required_pillars_timeout(job: Dict[str, Any]) -> Dict[str, Any]:
    analysis = job.get("analysis") if isinstance(job.get("analysis"), dict) and job.get("analysis") else {}
    timeout_semantic_review = {
        "status": "done",
        "claim_matches_known_scam_family": False,
        "matched_family": None,
        "claim_matches_legit_template": False,
        "matched_template": None,
        "reason_codes": ["semantic:timeout", "orchestration:required_timeout"],
        "risk_class": "unknown",
        "confidence_class": "low",
        "family_confidence": 0.0,
        "completeness": True,
        "source": "required_pillar_timeout",
    }
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
    evidence = analysis.setdefault("evidence", {})
    existing_semantic = evidence.get("semantic_review") if isinstance(evidence.get("semantic_review"), dict) else {}
    if str(existing_semantic.get("status") or "").strip().lower() != "done":
        evidence["semantic_review"] = timeout_semantic_review
    else:
        existing_semantic["completeness"] = True
        reason_codes = [
            str(item)
            for item in existing_semantic.get("reason_codes") or []
            if str(item).strip()
        ]
        if "orchestration:required_timeout" not in reason_codes:
            reason_codes.append("orchestration:required_timeout")
        existing_semantic["reason_codes"] = reason_codes
    job["analysis"] = analysis
    job["required_pillars_timed_out"] = True
    orchestrated_engine._set_orchestrated_stage(job, "done")
    orchestrated_engine._emit_orchestrated_telemetry("orchestrated_required_timeout", job)
    return job


def _first_final_url(resolved_urls: List[Dict[str, Any]]) -> Optional[str]:
    for entry in resolved_urls:
        final_url = entry.get("final_url") or entry.get("url") or entry.get("original_url")
        if isinstance(final_url, str) and final_url.strip():
            return final_url.strip()
    return None


_FINAL_URL_UNRESOLVED_ERROR_MARKERS = (
    "nameresolutionerror",
    "failed to resolve",
    "temporary failure in name resolution",
    "nodename nor servname",
    "nxdomain",
)


_FINAL_URL_UNRESOLVED_SUSPICIOUS_DNS_VERDICTS = {
    "nxdomain",
    "registrar_suspended",
    "suspended_nameserver",
    "domain_suspended",
}


def _final_url_unresolved_entry(job: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    resolved_urls = job.get("resolved_urls") if isinstance(job.get("resolved_urls"), list) else []
    analysis = job.get("analysis") if isinstance(job.get("analysis"), dict) else {}
    evidence = analysis.get("evidence") if isinstance(analysis.get("evidence"), dict) else {}
    summary = evidence.get("external_intel_summary") if isinstance(evidence.get("external_intel_summary"), dict) else {}
    infra_dns = summary.get("infra_dns") if isinstance(summary.get("infra_dns"), dict) else {}
    infra_verdict = str(infra_dns.get("verdict") or "").strip().lower()
    dns_infra_unresolved = infra_verdict in {"nxdomain", "registrar_suspended"}

    for entry in resolved_urls:
        if not isinstance(entry, dict) or entry.get("success") is not False:
            continue
        final_url = entry.get("final_url") or entry.get("url") or entry.get("original_url")
        if not isinstance(final_url, str) or not final_url.strip():
            continue
        redirect_chain = entry.get("redirect_chain") if isinstance(entry.get("redirect_chain"), list) else []
        chain_text = " ".join(
            str(item.get("status_code") or item.get("error") or item.get("error_message") or "")
            for item in redirect_chain
            if isinstance(item, dict)
        )
        error_text = " ".join(
            str(value or "")
            for value in (
                entry.get("error"),
                entry.get("error_message"),
                entry.get("failure_reason"),
                chain_text,
            )
        ).lower()
        if dns_infra_unresolved or any(marker in error_text for marker in _FINAL_URL_UNRESOLVED_ERROR_MARKERS):
            return entry
    return None


def _entry_or_job_uses_shortener(job: Dict[str, Any], entry: Dict[str, Any]) -> bool:
    if entry.get("uses_shortener") or entry.get("shortener_count"):
        return True

    candidate_urls: List[str] = []
    for key in ("original_url", "url"):
        value = entry.get(key)
        if isinstance(value, str) and value.strip():
            candidate_urls.append(value.strip())
    for value in job.get("urls") if isinstance(job.get("urls"), list) else []:
        if isinstance(value, str) and value.strip():
            candidate_urls.append(value.strip())
    redirect_chain = entry.get("redirect_chain") if isinstance(entry.get("redirect_chain"), list) else []
    for hop in redirect_chain:
        if not isinstance(hop, dict):
            continue
        value = hop.get("url")
        if isinstance(value, str) and value.strip():
            candidate_urls.append(value.strip())

    return any(is_known_shortener(url) for url in candidate_urls)


def _final_url_unresolved_shortener_dns_suspicious(job: Dict[str, Any]) -> bool:
    entry = _final_url_unresolved_entry(job)
    if not entry or not _entry_or_job_uses_shortener(job, entry):
        return False
    analysis = job.get("analysis") if isinstance(job.get("analysis"), dict) else {}
    evidence = analysis.get("evidence") if isinstance(analysis.get("evidence"), dict) else {}
    summary = evidence.get("external_intel_summary") if isinstance(evidence.get("external_intel_summary"), dict) else {}
    infra_dns = summary.get("infra_dns") if isinstance(summary.get("infra_dns"), dict) else {}
    verdict = str(infra_dns.get("verdict") or "").strip().lower()
    status = str(infra_dns.get("status") or "").strip().lower()
    return status == "suspicious" and verdict in _FINAL_URL_UNRESOLVED_SUSPICIOUS_DNS_VERDICTS


def _apply_final_url_unresolved_shortener_fail_safe(job: Dict[str, Any], analysis: Dict[str, Any]) -> None:
    if not _final_url_unresolved_shortener_dns_suspicious(job):
        return
    evidence = analysis.setdefault("evidence", {})
    gate = evidence.get("verdict_gate") if isinstance(evidence.get("verdict_gate"), dict) else {}
    if str(gate.get("label") or "").upper() not in {"UNVERIFIED", "SUSPECT"}:
        return

    reason_code = "final_url_unresolved_dns_suspicious_shortener"
    reason_codes = _dedupe_preserve_order(list(gate.get("reason_codes") or []) + [reason_code])
    updated_gate = dict(gate)
    updated_gate.update(
        {
            "label": "SUSPECT",
            "risk_level": "medium",
            "risk_score": max(int(gate.get("risk_score") or 0), 55),
            "reason_codes": reason_codes,
            "confidence": max(int(gate.get("confidence") or 0), 70),
            "is_final": True,
        }
    )
    evidence["verdict_gate"] = updated_gate

    provider_gate = evidence.get("provider_gate") if isinstance(evidence.get("provider_gate"), dict) else {}
    provider_gate = dict(provider_gate)
    provider_reasons = [
        item.strip()
        for item in str(provider_gate.get("reason") or "").split(",")
        if item.strip()
    ]
    provider_gate.update(
        {
            "label": "SUSPECT",
            "risk_level": "medium",
            "risk_score": updated_gate["risk_score"],
            "reason": ", ".join(_dedupe_preserve_order(provider_reasons + [reason_code])),
            "detected_family_id": "provider-gate-final-url-unresolved",
            "detected_family": "Destinație finală neverificabilă",
            "final_url_unresolved_fail_safe": True,
        }
    )
    evidence["provider_gate"] = provider_gate
    evidence["final_url_unresolved_fail_safe"] = {
        "applied": True,
        "reason": reason_code,
    }

    analysis["risk_level"] = "medium"
    analysis["risk_score"] = updated_gate["risk_score"]
    analysis["detected_family"] = "Destinație finală neverificabilă"
    analysis["detected_family_id"] = "provider-gate-final-url-unresolved"
    analysis["reasons"] = [
        "Linkul scurtat redirecționează către o destinație finală care nu poate fi încărcată/verificată.",
        "DNS-ul destinației finale indică un domeniu nerezolvabil sau suspendat.",
    ]
    analysis["safe_actions"] = [
        "Nu continua din linkul primit.",
        "Verifică oferta sau pagina direct în aplicația/site-ul oficial.",
    ]


def _preview_for_final_url_unresolved(job: Dict[str, Any], preview: Dict[str, Any]) -> Dict[str, Any]:
    entry = _final_url_unresolved_entry(job)
    if not entry:
        return preview
    final_url = (
        entry.get("final_url")
        or entry.get("url")
        or entry.get("original_url")
        or job.get("primary_final_url")
        or preview.get("final_url")
    )
    patched = dict(preview)
    patched.update(
        {
            "status": "unavailable",
            "source": "redirect_resolver",
            "image_url": None,
            "screenshot_url": None,
            "report_url": None,
            "reason": "final_url_unresolved",
            "final_url": final_url,
            "details": (
                "Destinatia finala nu poate fi incarcata/verificata. "
                "Nu continua fara verificare oficiala."
            ),
        }
    )
    return patched




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


def _apply_primary_resolved_url(
    job: Dict[str, Any],
    primary_entry: Optional[Dict[str, Any]],
) -> Optional[str]:
    primary_final_url = None
    if isinstance(primary_entry, dict):
        primary_final_url = (
            primary_entry.get("final_url")
            or primary_entry.get("url")
            or primary_entry.get("original_url")
        )
        job["primary_url_privacy"] = _merge_url_privacy(
            job.get("primary_url_privacy")
            if isinstance(job.get("primary_url_privacy"), dict)
            else None,
            primary_entry.get("url_privacy")
            if isinstance(primary_entry.get("url_privacy"), dict)
            else None,
        )
    job["primary_final_url"] = primary_final_url
    preview = job.setdefault("preview", {})
    if isinstance(preview, dict):
        preview["final_url"] = primary_final_url
    return primary_final_url


def _sanitize_urlscan_result_payload(result: Dict[str, Any]) -> Dict[str, Any]:
    sanitized = dict(result if isinstance(result, dict) else {})
    final_url = sanitized.get("final_url")
    if not isinstance(final_url, str) or not final_url.strip():
        return sanitized
    privacy = prepare_external_url(final_url)
    sanitized["final_url"] = privacy.get("external_url")
    sanitized["url_privacy"] = _merge_url_privacy(
        sanitized.get("url_privacy")
        if isinstance(sanitized.get("url_privacy"), dict)
        else None,
        privacy,
    )
    if (
        sanitized["url_privacy"].get("preview_allowed") is False
        or sanitized["url_privacy"].get("action") != "unchanged"
    ):
        sanitized["url_privacy"]["preview_allowed"] = False
        sanitized["report_url"] = None
        sanitized["result_url"] = None
        sanitized["screenshot_url"] = None
        sanitized["screenshot_ready"] = False
        sanitized["privacy_blocked_preview"] = True
    return sanitized


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


def _apply_urlscan_preview_cache_hit(job: Dict[str, Any], cached: Dict[str, Any]) -> Dict[str, Any]:
    cached_summary = _normalize_urlscan_preview_cache_entry(cached)
    if not cached_summary:
        return job
    job["urlscan"] = cached_summary
    preview = job.setdefault("preview", {})
    preview["final_url"] = cached_summary.get("final_url")
    preview["report_url"] = cached_summary.get("report_url")
    screenshot_url = cached_summary.get("screenshot_url")
    screenshot_ready = bool(cached_summary.get("screenshot_ready")) and bool(screenshot_url)
    if screenshot_ready:
        preview["status"] = "ready"
        preview["source"] = "urlscan"
        preview["image_url"] = screenshot_url
        preview["screenshot_url"] = screenshot_url
        preview["reason"] = None
    else:
        preview["status"] = "pending"
        preview["source"] = "urlscan"
        preview["image_url"] = None
        preview["screenshot_url"] = None
        preview["reason"] = cached_summary.get("reason") or "urlscan_screenshot_pending"
    preview["cache_hit"] = True
    preview.setdefault("reason", "urlscan_screenshot_pending")
    analysis = job.get("analysis") if isinstance(job.get("analysis"), dict) else {}
    evidence = analysis.setdefault("evidence", {})
    summary = evidence.setdefault("external_intel_summary", {})
    if isinstance(summary, dict):
        summary["urlscan"] = _urlscan_provider_payload(cached_summary)
        summary["urlscan"]["cache_hit"] = True
    _sync_resolved_urls_with_urlscan_final(job)
    orchestrated_engine._increment_orchestrated_metric(job, "urlscan_preview_cache_hit_count")
    return job


def _urlscan_preview_cache_entry_from_job(job: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not isinstance(job, dict):
        return None
    urlscan_state = job.get("urlscan") if isinstance(job.get("urlscan"), dict) else {}
    preview = job.get("preview") if isinstance(job.get("preview"), dict) else {}
    final_url = (
        urlscan_state.get("final_url")
        or preview.get("final_url")
        or job.get("primary_final_url")
        or urlscan_state.get("submitted_url")
    )
    screenshot_ready = bool(urlscan_state.get("screenshot_ready"))
    screenshot_url = (urlscan_state.get("screenshot_url") or preview.get("screenshot_url")) if screenshot_ready else None
    report_url = urlscan_state.get("report_url") or preview.get("report_url")
    if not final_url or not report_url:
        return None
    return {
        "uuid": urlscan_state.get("uuid"),
        "status": "finished",
        "submitted_url": urlscan_state.get("submitted_url") or final_url,
        "final_url": final_url,
        "report_url": report_url,
        "screenshot_url": screenshot_url,
        "screenshot_ready": screenshot_ready and bool(screenshot_url),
        "verdict": urlscan_state.get("verdict") or "No malicious classification",
        "severity": urlscan_state.get("severity") or "low",
        "details": urlscan_state.get("details") or "urlscan preview cached",
        "score": urlscan_state.get("score") or 0,
        "categories": urlscan_state.get("categories") or [],
        "brands": urlscan_state.get("brands") or [],
    }




























def _looks_like_structured_invoice_text(raw_text: str) -> bool:
    """Detects an actual invoice/proforma body, not a generic "view invoice" SMS.

    This is deliberately conservative: auto-routing to the invoice reducer only
    happens when the text has both invoice semantics and payment/document fields
    such as IBAN/CUI/amount/e-Factura markers. A plain URL notification stays on
    the generic URL/text route.
    """
    text = _normalise_obfuscated_text(raw_text or "")
    if len(text.strip()) < 40:
        return False
    lower = text.lower()
    has_invoice_term = bool(
        re.search(r"\b(factur[ăa]?|factura|proform[ăa]?|proforma|invoice|e[-\s]?factura|roefactura|spv)\b", lower)
    )
    if not has_invoice_term:
        return False

    def _has_valid_iban_candidate(candidate_text: str) -> bool:
        try:
            from services.iban_validator import IBAN_LENGTH_BY_COUNTRY, normalize_iban, validate_iban
            from services.invoice_parser import ANY_IBAN_PATTERN
        except Exception:
            return False
        for match in ANY_IBAN_PATTERN.finditer(candidate_text or ""):
            normalized = normalize_iban(match.group(0))
            if not normalized:
                continue
            expected_len = IBAN_LENGTH_BY_COUNTRY.get(normalized[:2])
            candidates = [normalized]
            if expected_len and len(normalized) > expected_len:
                candidates.append(normalized[:expected_len])
            for candidate in candidates:
                if validate_iban(candidate).valid_structure:
                    return True
        return False

    try:
        from services.invoice_parser import AMOUNT_FALLBACK, AMOUNT_PATTERN, CUI_PATTERN

        has_iban = _has_valid_iban_candidate(text) or bool(
            re.search(r"\biban\b\s*[:#-]?\s*[A-Z]{2}\s*\d{2}(?:[\s-]*[A-Z0-9]){11,30}\b", text, re.IGNORECASE)
        )
        has_cui = bool(CUI_PATTERN.search(text))
        has_amount = bool(AMOUNT_PATTERN.search(text) or AMOUNT_FALLBACK.search(text))
    except Exception:
        has_iban = _has_valid_iban_candidate(text)
        has_cui = bool(re.search(r"\b(?:CUI|CIF)\s*:?\s*(?:RO\s*)?\d{2,10}\b", text, re.IGNORECASE))
        has_amount = bool(re.search(r"\b\d+(?:[.,]\d{1,2})?\s*(?:RON|LEI|EUR|USD|GBP)\b", text, re.IGNORECASE))
    has_invoice_number = bool(
        re.search(r"\bfactur[ăa]?\s+(?:seria\s+\S+\s*/\s*)?(?:nr\.?|num[ăa]r|#)\s*[:#]?\s*[A-Z0-9][A-Z0-9._/-]{2,}\b", lower, re.IGNORECASE)
        or re.search(r"\bnr\.?\s*factur[ăa]\s*[:#]?\s*[A-Z0-9][A-Z0-9._/-]{2,}\b", lower, re.IGNORECASE)
    )
    has_due_or_issue_date = bool(
        re.search(r"\b(data\s+(?:emiterii|facturii)|scaden[țt][ăa]|termen\s+plat[ăa]|due\s+date|issued\s+on)\b", lower)
    )
    has_official_invoice_artifact = bool(
        re.search(r"\b(xml|semnat(?:[ăa])?\s+electronic|num[ăa]r\s+de\s+[îi]nregistrare|roefactura|spv|peppol)\b", lower)
    )
    structural_score = sum(
        bool(value)
        for value in (
            has_iban,
            has_cui,
            has_amount,
            has_invoice_number,
            has_due_or_issue_date,
            has_official_invoice_artifact,
        )
    )
    if has_iban and structural_score >= 2:
        return True
    if has_official_invoice_artifact and structural_score >= 3:
        return True
    return False


def _invoice_auto_route_context(
    *,
    source_channel: str,
    raw_text: str,
    urls: List[str],
    extra_fields: Optional[Dict[str, Any]] = None,
    original_input_type: str = "text",
) -> Optional[Dict[str, Any]]:
    if not _looks_like_structured_invoice_text(raw_text):
        return None
    fields = dict(extra_fields or {})
    fields.update(
        {
            "invoice_scan": True,
            "auto_invoice_route": True,
            "original_input_type": original_input_type,
        }
    )
    return {
        "input_type": "invoice",
        "source_channel": source_channel,
        "raw_text": raw_text,
        "urls": urls,
        "extra_fields": fields,
    }






def _invoice_payment_destination_for_client(
    result: Any,
    invoice_gate: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    raw = getattr(result, "payment_destination", None) if result else None
    payload = dict(raw) if isinstance(raw, dict) else None
    bundle = invoice_gate.get("bundle") if isinstance(invoice_gate, dict) else None
    providers = bundle.get("providers") if isinstance(bundle, dict) else {}
    evidence_payment = providers.get("payment_destination") if isinstance(providers, dict) else None
    if isinstance(evidence_payment, dict):
        promotes_destination = bool(
            evidence_payment.get("matched") is True
            or evidence_payment.get("can_contribute_to_safe") is True
            or evidence_payment.get("trust_tier") == "T2_OFFICIAL_DOCUMENT_CHAIN"
        )
        if promotes_destination or payload is None:
            payload = {**(payload or {}), **evidence_payment}
    if not isinstance(payload, dict):
        return None

    trust_tier = str(payload.get("trust_tier") or "")
    if not payload.get("display"):
        if payload.get("can_contribute_to_safe") is True:
            if trust_tier == "T2_OFFICIAL_DOCUMENT_CHAIN":
                payload["display"] = "IBAN confirmat prin document oficial"
            elif trust_tier in {"T0_PARTNER_SIGNED", "T1_PUBLIC_OFFICIAL"}:
                payload["display"] = "IBAN publicat de furnizor într-o sursă oficială"
            else:
                payload["display"] = "Destinație de plată confirmată"
        elif payload.get("cui_matches") is False or (
            payload.get("brand_matches") is False
            and payload.get("cui_matches") is not True
        ):
            # cui_matches=True => same legal entity; don't claim the IBAN belongs
            # to someone else just because the brand-name string differed.
            payload["display"] = "IBAN asociat altei entități"
        elif payload.get("matched") is False:
            payload["display"] = "IBAN valid, dar destinație neconfirmată"
        else:
            payload["display"] = "Destinație verificată parțial"
    return payload





async def _run_offer_web_claim_enrichment(job: Dict[str, Any]) -> Dict[str, Any]:
    """PR6: enrichment web post-verdict pentru oferte. Atașează dovezi; verdictul
    poate DOAR crește în severitate, exclusiv prin reduce_verdict (gate unic).
    not_found/inconclusive = doar context (max SUSPECT solo, niciodată escaladare).
    """
    from services.brand_registry import BRAND_REGISTRY as OFFER_BRAND_REGISTRY
    from services.offer_claim_verifier import verify_offer_web_claim
    from services.verdict_gate import verdict as reduce_verdict

    analysis = job.get("analysis") if isinstance(job.get("analysis"), dict) else {}
    evidence = analysis.get("evidence") if isinstance(analysis.get("evidence"), dict) else {}
    offer_evidence = evidence.get("offer") if isinstance(evidence.get("offer"), dict) else {}
    offer_fields = offer_evidence.get("fields") if isinstance(offer_evidence.get("fields"), dict) else {}

    # Ruta ofertă folosește DOAR brand_registry (regula #5), ca domenii oficiale.
    offer_domains = {key: list(entry.domains) for key, entry in OFFER_BRAND_REGISTRY.items()}

    try:
        claim = await asyncio.wait_for(
            run_in_threadpool(
                verify_offer_web_claim,
                str(job.get("redacted_text") or ""),
                analysis,
                job.get("resolved_urls") if isinstance(job.get("resolved_urls"), list) else [],
                brand_registry=offer_domains,
                family_code=str(analysis.get("detected_family_id") or "OP-00"),
                issuer_name=offer_fields.get("issuer_name"),
                platform_name=offer_fields.get("platform_name") or offer_fields.get("document_type"),
            ),
            timeout=AI_OFFER_CLAIM_TIMEOUT_SECONDS,
        )
    except Exception as exc:  # timeout/erori → inconcludent, nu blocăm nimic
        claim = _skipped_offer_claim_payload(f"Offer web check unavailable: {type(exc).__name__}.")

    _attach_offer_claim_verification(analysis, claim)
    job["offer_web_claim"] = {"status": "done", "claim_status": claim.get("status")}

    # Escaladare DOAR la severity=high (dovadă web decisivă), prin gate-ul unic.
    bundle = evidence.get("decision_bundle") if isinstance(evidence.get("decision_bundle"), dict) else None
    old_gate = evidence.get("verdict_gate") if isinstance(evidence.get("verdict_gate"), dict) else {}
    old_label = str(old_gate.get("label") or "").upper()
    if bundle and str(claim.get("severity") or "").lower() == "high":
        enriched = json.loads(json.dumps(bundle, ensure_ascii=False))
        enriched.setdefault("providers", {})["verdict"] = "malicious"
        enriched.setdefault("context", {})["web_claim"] = {
            "status": claim.get("status"),
            "severity": claim.get("severity"),
        }
        new_gate = reduce_verdict(enriched)
        new_label = str(new_gate.get("label") or "").upper()
        if _VERDICT_SEVERITY_RANK.get(new_label, 0) > _VERDICT_SEVERITY_RANK.get(old_label, 0):
            evidence["verdict_gate"] = new_gate
            evidence["decision_bundle"] = enriched
            analysis["risk_level"] = new_gate.get("risk_level")
            analysis["risk_score"] = new_gate.get("risk_score")
            # Republicare cu severitate crescută: golim rezultatul și lăsăm
            # finalize-ul apelantului să-l reconstruiască din analysis-ul nou
            # (același pattern ca stadiile rutei text: persist înainte de finalize).
            job["result"] = None
            job["result_fingerprint"] = None
            job["analysis"] = analysis
            orchestrated_engine._emit_orchestrated_telemetry(
                "orchestrated_offer_web_claim", job, claim_status=claim.get("status"), escalated=True
            )
            return orchestrated_engine._persist_orchestrated_job(job)

    job["analysis"] = analysis
    orchestrated_engine._emit_orchestrated_telemetry("orchestrated_offer_web_claim", job, claim_status=claim.get("status"))
    return orchestrated_engine._persist_orchestrated_job(job)








from services.extract_pipeline import (
    _assemble_extracted_text_for_orchestration,
    extract_email_for_orchestration,
    extract_image_for_orchestration,
    extract_pdf_for_orchestration,
)
from services.orchestrated_pipeline import (
    advance_orchestrated_scan_worker,
    get_orchestrated_scan,
    get_orchestrated_scan_status,
    start_orchestrated_scan,
)
from services.scan_pipeline import scan_email, scan_invoice_endpoint, scan_image, scan_pdf, scan_text, scan_url
from services.urlscan_pipeline import get_urlscan_result, submit_urlscan_sandbox, urlscan_screenshot


# Orchestrated-scan engine functions live in services/orchestrated_scan.py;
# re-exported so existing references and test monkeypatching (main.<fn>) keep working.
from services.orchestrated_scan import orchestrated_engine

# ── API routers ─────────────────────────────────────────────────────────────
# Registered last so router handlers that reference the fully-initialized main
# module (import main; main.X) resolve correctly and avoid import-time cycles.
from routers import circle, community, intel, analytics, pages, scan  # noqa: E402
app.include_router(pages.router)
app.include_router(circle.router)
app.include_router(community.router)
app.include_router(intel.router)
app.include_router(analytics.router)
app.include_router(scan.router)
