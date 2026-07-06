"""Scan analysis functions extracted from the legacy runtime module."""

import os
import sys
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
import hashlib
import traceback  # noqa: used in _on_startup for debug
import requests
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
from services.provider_gate import _apply_provider_gate_verdict, _maybe_add_dns_reputation, _project_provider_gate_verdict, _identity_data_request_token
from services.scam_atlas import BRAND_ID_TO_DISPLAY_NAME, BRAND_REGISTRY, BRAND_WARNING_RULES
from services.tier1_classifier import LEGIT_LABELS as TIER1_LEGIT_LABELS
from services.gemini_explainer import generate_ai_explanation, generate_fallback_explanation
from services.evidence_bundle import build_evidence_bundle
from services.verdict_gate import verdict as reduce_verdict
from services.cfx_engine import extract_fingerprint, CampaignFingerprint, FingerprintMatch
from app_stores import brand_truth_registry, campaign_store, urechea_ingester, cfx_store
from services.mistral_shadow_adjudicator import maybe_run_shadow_adjudication
from services.offer_claim_verifier import verify_offer_claim
from services.url_reputation import get_reputation_cache_stats, get_reputation_for_urls, reputation_url_hash_variants
from services.urlscan_helpers import (
    _fast_preview_cache_lookup_keys,
    _remember_preview_cache_entry,
    _load_urlscan_preview_cache,
    _urlscan_preview_cache_is_fresh,
    _supabase_signed_preview_object_path,
)
from services.urlscan_logic import _apply_urlscan_preview_cache_hit
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
    _build_feedback_quality_payload,
    _build_readiness_payload,
    _build_orchestration_telemetry_payload,
    _build_shadow_adjudication_payload,
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
    _SOCIAL_ENGINEERING_PRESSURE_PATTERNS,
    _VERDICT_SEVERITY_RANK,
    _FINAL_URL_UNRESOLVED_ERROR_MARKERS,
    _FINAL_URL_UNRESOLVED_SUSPICIOUS_DNS_VERDICTS,
)

from runtime_state import _URLSCAN_PREVIEW_CACHE, _FAST_PREVIEW_CACHE, engine, tier1_classifier

# P-DUP: sursă unică de adevăr în services.provider_gate (vezi audit).
from services.provider_gate import (
    _apply_decision_contract_result,
    _attach_brand_warning_summary,
    _augment_summary_with_infra_flags,
    _brand_token_lookalike_in_resolved_urls,
    _brand_userinfo_spoof_in_resolved_urls,
    _brand_warning_matches_text,
    _brand_warning_rule_for_claimed_brand,
    _build_decision_evidence_bundle,
    _claim_verifier_required,
    _claimed_brand_exact_domain_match,
    _collect_infrastructure_flags,
    _compact_brand_match_token,
    _detect_person_never_does_violations,
    _domain_base_for_first_party_match,
    _domain_reputation_from_age,
    _enrich_with_btr_provenance,
    _first_domain_age_days,
    _first_final_url,
    _first_party_domain_claim_from_text,
    _has_direct_sensitive_request,
    _has_explicit_user_directed_action,
    _has_investment_money_risk,
    _has_invoice_payment_beneficiary_mismatch,
    _has_positive_user_action_request,
    _has_sensitive_url_path,
    _has_social_engineering_pressure,
    _identity_status_for_decision_bundle,
    _local_high_risk_semantic_review,
    _local_request_intent_analysis,
    _looks_like_descriptive_or_status_context,
    _looks_like_official_safety_education,
    _normalise_counterparty_name,
    _normalize_claimed_brand,
    _normalize_model_intent_analysis,
    _normalize_model_social_engineering_signal,
    _official_destination_confirmed,
    _provider_verdict_for_decision_bundle,
    _request_channel_for_decision_bundle,
    _request_sensitivity_from_signals,
    _resolved_urls_have_suspicious_public_tld,
    _se_bool,
    _se_float,
    _se_list,
    _se_pattern,
    _semantic_review_for_decision_bundle,
    _semantic_risk_rank,
    _skipped_offer_claim_payload,
    _social_engineering_signal_for_decision_bundle,
    _source_consulted,
    _source_is_suspicious,
    _source_ready,
    _source_status,
    _strip_url_tokens_for_brand_match,
)

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("main")

logger = logging.getLogger("scan_analysis")

# ── Analysis functions ────────────────────────────────────────────

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
        spf_lookup = get_spf_dns_record
        dmarc_lookup = get_dmarc_policy
        dkim_lookup = check_dkim_dns_record

        spf_record = spf_lookup(from_domain or "")
        dmarc_policy = dmarc_lookup(from_domain or "")
        if has_dkim_signature and dkim_signature_domain and dkim_selector:
            dns_dkim_record = dkim_lookup(dkim_selector, dkim_signature_domain)
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







    # host_unreachable intentionally does NOT enter the provider summary: a
    # pseudo-provider entry with unknown status would block official_clean on
    # transient network errors. The signal still flows via identity context
    # (host_unreachable) and the weighted risk score.
























def _semantic_review_from_analysis(analysis: Dict[str, Any]) -> Dict[str, Any]:
    evidence = analysis.get("evidence", {}) if isinstance(analysis.get("evidence"), dict) else {}
    review = evidence.get("semantic_review")
    return review if isinstance(review, dict) else {}




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
                {
                    "role": "system",
                    "content": MISTRAL_SEMANTIC_SYSTEM_PROMPT,
                },
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

    if (
        PRIVACY_SAFE_MODE
        or not ENABLE_MISTRAL_SEMANTIC_PILLAR
        or not bool(MISTRAL_SEMANTIC_API_KEY)
    ):
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
        raw_review = await run_in_threadpool(
            _call_mistral_semantic_review,
            payload,
        )
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










# Analytics payload builders moved to services.telemetry.
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

    if not ocr_text.strip() and bool(ALLOWED_MOCK_OCR):
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
        return generate_fallback_explanation(
            provider_safe_text,
            analysis,
        )
    return generate_ai_explanation(
        provider_safe_text,
        analysis,
        provider_safe_resolved_urls,
    )


async def _build_ai_explanation_async(
    text: str,
    analysis: Dict[str, Any],
    resolved_urls: List[Dict[str, Any]],
) -> Dict[str, Any]:
    provider_safe_text = sanitize_external_text(text)
    provider_safe_resolved_urls = sanitize_resolved_url_entries(resolved_urls)
    if (
        PRIVACY_SAFE_MODE
        or not ENABLE_CLOUD_AI_EXPLANATION
        or AI_EXPLANATION_TIMEOUT_SECONDS <= 0
    ):
        return generate_fallback_explanation(
            provider_safe_text,
            analysis,
        )

    try:
        return await asyncio.wait_for(
            run_in_threadpool(
                generate_ai_explanation,
                provider_safe_text,
                analysis,
                provider_safe_resolved_urls,
            ),
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
    from services.orchestrated_scan import orchestrated_engine
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
    load_fast = _load_fast_preview_cache
    load_urlscan = _load_urlscan_preview_cache
    cached_fast = load_fast(final_url)
    cached_urlscan = load_urlscan(final_url)
    if cached_urlscan:
        apply_urlscan = _apply_urlscan_preview_cache_hit
        apply_fast = _apply_fast_preview_cache_hit
        job = apply_urlscan(job, cached_urlscan)
        if cached_fast:
            return apply_fast(job, cached_fast)
        preview = job.get("preview") if isinstance(job.get("preview"), dict) else {}
        if preview.get("status") == "ready" and (
            preview.get("image_url") or preview.get("screenshot_url")
        ):
            return job
    if cached_fast:
        apply_fast = _apply_fast_preview_cache_hit
        return apply_fast(job, cached_fast)
    return job


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
    from services.orchestrated_scan import orchestrated_engine
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
    from services.orchestrated_scan import orchestrated_engine

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


