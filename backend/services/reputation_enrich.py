"""Reputation + threat-intel helpers extracted from runtime.py."""

from __future__ import annotations

import hashlib
import re
from typing import Any, Dict, List, Optional

from config import (
    ENABLE_DEEP_REPUTATION_FALLBACK,
    FAST_REPUTATION_INCLUDE_URLHAUS,
    PRIVACY_SAFE_MODE,
)
from runtime_state import engine
from services.external_url_privacy import (
    prepare_reputation_lookup_url,
    sanitize_external_text,
    sanitize_resolved_url_entries,
)
from services.url_reputation import get_reputation_for_urls



def _gather_external_intel(
    resolved_urls: List[Dict[str, Any]],
    *,
    include_phishing_database: bool = True,
    include_phishtank: bool = True,
    include_openphish: bool = True,
    include_urlhaus: bool = True,
    include_scam_blocklist_nrd: bool = True,
    include_phishdestroy: bool = True,
    persist_partial: bool = False,
) -> Dict[str, Dict[str, Any]]:
    if PRIVACY_SAFE_MODE:
        return {}
    reputation_urls = _reputation_lookup_urls_from_resolved_entries(resolved_urls)
    reputation_hashes_by_url = _reputation_lookup_hashes_by_url_from_resolved_entries(resolved_urls)
    threat_intel = get_reputation_for_urls(
        reputation_urls,
        include_phishing_database=include_phishing_database,
        include_phishtank=include_phishtank,
        include_openphish=include_openphish,
        include_urlhaus=include_urlhaus,
        include_scam_blocklist_nrd=include_scam_blocklist_nrd,
        include_phishdestroy=include_phishdestroy,
        persist_partial=persist_partial,
        lookup_url_hashes_by_url=reputation_hashes_by_url,
    )
    return _sanitize_external_intel_results(threat_intel)


def _sanitize_external_intel_results(
    threat_intel: Dict[str, Dict[str, Any]],
) -> Dict[str, Dict[str, Any]]:

    def sanitize_value(value: Any) -> Any:
        if isinstance(value, dict):
            return {str(key): sanitize_value(inner) for key, inner in value.items()}
        if isinstance(value, list):
            return [sanitize_value(item) for item in value]
        if isinstance(value, str):
            return sanitize_external_text(value)
        return value

    sanitized: Dict[str, Dict[str, Any]] = {}
    for key, payload in (threat_intel or {}).items():
        if not isinstance(payload, dict):
            continue
        safe_payload = sanitize_value(payload)
        if isinstance(payload.get("url"), str):
            safe_payload["url"] = prepare_reputation_lookup_url(payload["url"]).get("external_url")
        sanitized[str(key)] = safe_payload
    return sanitized


def _reputation_lookup_urls_from_resolved_entries(
    resolved_urls: List[Dict[str, Any]],
) -> List[str]:
    candidates: List[str] = []

    def add_candidate(raw_value: Any) -> None:
        if not isinstance(raw_value, str) or not raw_value.strip():
            return
        prepared = prepare_reputation_lookup_url(raw_value.strip())
        safe_url = prepared.get("external_url")
        if isinstance(safe_url, str) and safe_url.strip():
            candidates.append(safe_url.strip())

    for entry in resolved_urls:
        if not isinstance(entry, dict):
            continue
        explicit_lookup_urls = entry.get("reputation_lookup_urls")
        if isinstance(explicit_lookup_urls, list):
            for raw_value in explicit_lookup_urls:
                add_candidate(raw_value)
        for field_name in ("url", "original_url", "final_url"):
            add_candidate(entry.get(field_name))
        redirect_chain = entry.get("redirect_chain")
        if isinstance(redirect_chain, list):
            for hop in redirect_chain:
                if not isinstance(hop, dict):
                    continue
                add_candidate(hop.get("url"))
    return list(dict.fromkeys(candidates))


def _normalize_reputation_hashes(raw_hashes: Any) -> List[str]:
    values = raw_hashes if isinstance(raw_hashes, list) else []
    output: List[str] = []
    for value in values:
        candidate = str(value or "").strip().lower()
        if re.fullmatch(r"[a-f0-9]{64}", candidate) and candidate not in output:
            output.append(candidate)
    return output


def _reputation_lookup_hashes_by_url_from_resolved_entries(
    resolved_urls: List[Dict[str, Any]],
) -> Dict[str, List[str]]:
    output: Dict[str, List[str]] = {}

    def add_hashes(raw_url: Any, raw_hashes: Any) -> None:
        if not isinstance(raw_url, str) or not raw_url.strip():
            return
        safe_url = prepare_reputation_lookup_url(raw_url.strip()).get("external_url")
        if not isinstance(safe_url, str) or not safe_url.strip():
            return
        bucket = output.setdefault(safe_url.strip(), [])
        for value in _normalize_reputation_hashes(raw_hashes):
            if value not in bucket:
                bucket.append(value)

    for entry in resolved_urls:
        if not isinstance(entry, dict):
            continue
        explicit_map = entry.get("reputation_lookup_url_hashes_by_url")
        if isinstance(explicit_map, dict):
            for raw_url, raw_hashes in explicit_map.items():
                add_hashes(raw_url, raw_hashes)
        explicit_hashes = entry.get("reputation_lookup_url_hashes")
        if isinstance(explicit_hashes, list):
            for field_name in ("url", "original_url", "final_url"):
                add_hashes(entry.get(field_name), explicit_hashes)
    return output


def _attach_reputation_lookup_urls(
    resolved_urls: List[Dict[str, Any]],
    reputation_lookup_urls: Any,
) -> List[Dict[str, Any]]:
    if not isinstance(reputation_lookup_urls, list) or not reputation_lookup_urls:
        return resolved_urls
    safe_lookup_urls = _reputation_lookup_urls_from_resolved_entries(
        [{"reputation_lookup_urls": reputation_lookup_urls}]
    )
    if not safe_lookup_urls or not resolved_urls:
        return resolved_urls
    attached = [dict(entry) if isinstance(entry, dict) else {} for entry in resolved_urls]
    first = attached[0]
    existing = first.get("reputation_lookup_urls")
    merged = list(existing) if isinstance(existing, list) else []
    for lookup_url in safe_lookup_urls:
        if lookup_url not in merged:
            merged.append(lookup_url)
    first["reputation_lookup_urls"] = merged
    return attached


def _attach_reputation_lookup_hashes(
    resolved_urls: List[Dict[str, Any]],
    reputation_lookup_hashes_by_url: Any,
) -> List[Dict[str, Any]]:
    if not isinstance(reputation_lookup_hashes_by_url, dict) or not reputation_lookup_hashes_by_url:
        return resolved_urls
    safe_hashes_by_url = _reputation_lookup_hashes_by_url_from_resolved_entries(
        [{"reputation_lookup_url_hashes_by_url": reputation_lookup_hashes_by_url}]
    )
    if not safe_hashes_by_url or not resolved_urls:
        return resolved_urls
    attached = [dict(entry) if isinstance(entry, dict) else {} for entry in resolved_urls]
    first = attached[0]
    existing = first.get("reputation_lookup_url_hashes_by_url")
    merged: Dict[str, List[str]] = {
        str(url): list(hashes) for url, hashes in existing.items()
    } if isinstance(existing, dict) else {}
    for url, hashes in safe_hashes_by_url.items():
        bucket = merged.setdefault(url, [])
        for value in hashes:
            if value not in bucket:
                bucket.append(value)
    first["reputation_lookup_url_hashes_by_url"] = merged
    return attached


def _external_intel_provider_error(
    resolved_urls: List[Dict[str, Any]],
    exc: Exception,
    *,
    include_phishing_database: bool,
    include_phishtank: bool,
    include_openphish: bool,
    include_urlhaus: bool,
    include_scam_blocklist_nrd: bool,
    include_phishdestroy: bool,
) -> Dict[str, Dict[str, Any]]:
    safe_resolved_urls = sanitize_resolved_url_entries(resolved_urls)
    final_urls = [
        str(entry.get("final_url") or "").strip()
        for entry in safe_resolved_urls
        if isinstance(entry, dict) and str(entry.get("final_url") or "").strip()
    ]
    error_type = type(exc).__name__
    error_message = str(exc)[:300]
    output: Dict[str, Dict[str, Any]] = {}
    for final_url in list(dict.fromkeys(final_urls)):
        key = hashlib.sha256(final_url.encode("utf-8")).hexdigest()
        sources: Dict[str, Dict[str, Any]] = {
            "google_web_risk": {
                "status": "error",
                "consulted": True,
                "threat_type": "error",
                "score": 0,
                "details": {
                    "provider": "google_web_risk",
                    "error_type": error_type,
                    "error": error_message,
                },
            }
        }
        if include_phishing_database:
            sources["phishing_database"] = {
                "status": "error",
                "consulted": True,
                "threat_type": "error",
                "score": 0,
                "details": {
                    "provider": "phishing_database",
                    "error_type": error_type,
                    "error": error_message,
                },
            }
        if include_phishtank:
            sources["phishtank_online_valid"] = {
                "status": "error",
                "consulted": True,
                "threat_type": "error",
                "score": 0,
                "details": {
                    "provider": "phishtank_online_valid",
                    "error_type": error_type,
                    "error": error_message,
                },
            }
        if include_openphish:
            sources["openphish"] = {
                "status": "error",
                "consulted": True,
                "threat_type": "error",
                "score": 0,
                "details": {
                    "provider": "openphish",
                    "error_type": error_type,
                    "error": error_message,
                },
            }
        if include_urlhaus:
            sources["urlhaus"] = {
                "status": "error",
                "consulted": True,
                "threat_type": "error",
                "score": 0,
                "details": {
                    "provider": "urlhaus",
                    "error_type": error_type,
                    "error": error_message,
                },
            }
        if include_scam_blocklist_nrd:
            sources["scam_blocklist_nrd"] = {
                "status": "error",
                "consulted": True,
                "threat_type": "error",
                "score": 0,
                "details": {
                    "provider": "scam_blocklist_nrd",
                    "error_type": error_type,
                    "error": error_message,
                },
            }
        if include_phishdestroy:
            sources["phishdestroy_destroylist"] = {
                "status": "error",
                "consulted": True,
                "threat_type": "error",
                "score": 0,
                "details": {
                    "provider": "phishdestroy_destroylist",
                    "error_type": error_type,
                    "error": error_message,
                },
            }
        output[key] = {
            "url": final_url,
            "verdict": "unknown",
            "risk_score": 0,
            "confidence": 0.0,
            "signals": ["provider_error"],
            "signal_count": 1,
            "active_sources": [],
            "sources": sources,
            "source_count": len(sources),
            "consulted_sources": sorted(sources.keys()),
            "consulted_source_count": len(sources),
            "provider_error": True,
        }
    return output


def _gather_external_intel_safe(
    resolved_urls: List[Dict[str, Any]],
    *,
    include_phishing_database: bool,
    include_urlhaus: bool,
    include_phishtank: bool = True,
    include_openphish: bool = True,
    include_scam_blocklist_nrd: bool = True,
    include_phishdestroy: bool = True,
    persist_partial: bool = False,
) -> Dict[str, Dict[str, Any]]:
    try:
        return _gather_external_intel(
            resolved_urls,
            include_phishing_database=include_phishing_database,
            include_phishtank=include_phishtank,
            include_openphish=include_openphish,
            include_urlhaus=include_urlhaus,
            include_scam_blocklist_nrd=include_scam_blocklist_nrd,
            include_phishdestroy=include_phishdestroy,
            persist_partial=persist_partial,
        )
    except TypeError:
        # Compatibility for tests that monkeypatch the helper with the older
        # single-argument signature.
        try:
            return _gather_external_intel(resolved_urls)  # type: ignore[call-arg]
        except Exception as exc:
            return _external_intel_provider_error(
                resolved_urls,
                exc,
                include_phishing_database=include_phishing_database,
                include_phishtank=include_phishtank,
                include_openphish=include_openphish,
                include_urlhaus=include_urlhaus,
                include_scam_blocklist_nrd=include_scam_blocklist_nrd,
                include_phishdestroy=include_phishdestroy,
            )
    except Exception as exc:
        return _external_intel_provider_error(
            resolved_urls,
            exc,
            include_phishing_database=include_phishing_database,
            include_phishtank=include_phishtank,
            include_openphish=include_openphish,
            include_urlhaus=include_urlhaus,
            include_scam_blocklist_nrd=include_scam_blocklist_nrd,
            include_phishdestroy=include_phishdestroy,
        )


def _analysis_needs_deep_reputation_fallback(analysis: Dict[str, Any]) -> bool:
    if PRIVACY_SAFE_MODE or not ENABLE_DEEP_REPUTATION_FALLBACK:
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
    allow_deep_fallback: bool = True,
) -> Dict[str, Any]:
    use_fast = bool(fast_reputation)
    threat_intel = threat_intel_override
    if threat_intel is None:
        threat_intel = _gather_external_intel_safe(
            resolved_urls,
            include_phishing_database=True,
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

    if use_fast and allow_deep_fallback and _analysis_needs_deep_reputation_fallback(analysis):
        deep_threat_intel = _gather_external_intel_safe(
            resolved_urls,
            include_phishing_database=True,
            include_urlhaus=True,
            persist_partial=True,
        )
        if deep_threat_intel:
            analyze_kwargs["external_threat_intel"] = deep_threat_intel
            analysis = engine.analyze(redacted_text, **analyze_kwargs)
            analysis.setdefault("evidence", {})["deep_reputation_fallback"] = True
    else:
        analysis.setdefault("evidence", {})["deep_reputation_fallback"] = False

    analysis.setdefault("evidence", {})["fast_reputation_mode"] = use_fast
    return analysis


def _external_intel_summary_from_threat_intel(
    threat_intel: Dict[str, Dict[str, Any]],
) -> Dict[str, Dict[str, Any]]:
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
                    1 if status in {"malicious", "phishing", "malware"} else 0
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
                if status in {"malicious", "phishing", "malware"}:
                    existing["malicious_hit_count"] = int(existing.get("malicious_hit_count") or 0) + 1
    return summary


def _provider_payload_is_hard_bad(
    raw: Dict[str, Any],
    *,
    include_suspicious: bool = False,
) -> bool:
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
