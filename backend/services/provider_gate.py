"""Provider-gate helpers extracted from ``runtime.py``.

The implementation intentionally mirrors the original behavior and resolves all
runtime symbols via ``main`` at call time. This keeps monkeypatching on
``runtime.<symbol>`` functional for existing tests and callers.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import importlib
import sys



class _RuntimeProxy:
    def __getattr__(self, name: str):
        runtime = sys.modules.get("main")
        if runtime is None:
            runtime = importlib.import_module("app")
        return getattr(runtime, name)


runtime = _RuntimeProxy()


def _maybe_add_dns_reputation(summary: Dict[str, Any], resolved_urls: List[Dict[str, Any]]) -> None:
    """Pilon DNS reputation (gratis, fără cheie). Opt-in prin ENABLE_DNS_REPUTATION;
    implicit OFF → fără rețea/latență. `blocked` → provider hard (dns_security);
    `suspended`/`nxdomain` → semnal ponderat (infra_dns). Best-effort, nu aruncă."""
    if not runtime.ENABLE_DNS_REPUTATION or not resolved_urls:
        return
    from services import dns_reputation

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
) -> Dict[str, Any]:
    evidence = analysis.setdefault("evidence", {})
    summary = evidence.get("external_intel_summary")
    if not isinstance(summary, dict):
        summary = {}
    claimed_brand = str(analysis.get("claimed_brand") or "Nespecificat")
    official_destination = runtime._official_destination_confirmed(resolved_urls, claimed_brand)
    infra_flags = runtime._collect_infrastructure_flags(
        analysis,
        resolved_urls,
        official_destination=official_destination,
    )
    runtime._augment_summary_with_infra_flags(summary, infra_flags)
    runtime._maybe_add_dns_reputation(summary, resolved_urls)
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
    web_risk_consulted = runtime._source_ready(summary, "google_web_risk")
    asf_investor_alerts_consulted = runtime._source_ready(summary, "asf_investor_alerts")
    phishing_database_consulted = runtime._source_ready(summary, "phishing_database")
    phishtank_consulted = runtime._source_ready(summary, "phishtank_online_valid")
    openphish_consulted = runtime._source_ready(summary, "openphish")
    urlscan_consulted = any(runtime._source_ready(summary, name) for name in ("urlscan", "urlscan.io"))
    sensitive_url_path = runtime._has_sensitive_url_path(resolved_urls)
    brand_warning = runtime._brand_warning_matches_text(claimed_brand, raw_text)
    official_safety_education = runtime._looks_like_official_safety_education(raw_text)
    direct_sensitive_request = runtime._has_direct_sensitive_request(raw_text)
    if official_safety_education:
        brand_warning = {"triggered": False, "matched_assets": []}
    evidence["brand_warning"] = brand_warning
    runtime._attach_brand_warning_summary(summary, brand_warning)
    claim_required = runtime._claim_verifier_required(analysis)
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
        if runtime._source_ready(summary, name)
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

    runtime._enrich_with_btr_provenance(analysis, claimed_brand, raw_text, resolved_urls)

    decision_bundle = runtime._build_decision_evidence_bundle(
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
    gate_result = runtime.reduce_verdict(decision_bundle)
    return runtime._apply_decision_contract_result(analysis, decision_bundle, gate_result, provider_gate)


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
    analysis_copy = runtime._deep_copy_jsonable(analysis if isinstance(analysis, dict) else {})
    resolved_copy = runtime._deep_copy_jsonable(resolved_urls if isinstance(resolved_urls, list) else [])
    pillars_copy = runtime._deep_copy_jsonable(pillars) if isinstance(pillars, dict) else None
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
        "provider_gate": runtime._deep_copy_jsonable(evidence.get("provider_gate") or {}),
        "external_intel_summary": runtime._deep_copy_jsonable(evidence.get("external_intel_summary") or {}),
        "brand_warning": runtime._deep_copy_jsonable(evidence.get("brand_warning") or {}),
    }
