"""Orchestrated-scan engine, extracted from py incrementally."""

import os
import re
import json
import time
import asyncio
import hashlib
import base64
import secrets
import urllib.parse
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import HTTPException, Request
from starlette.concurrency import run_in_threadpool
from bs4 import BeautifulSoup, Comment
import tldextract
from pypdf import PdfReader

from api_models import OrchestratedScanRequest, UrlscanSandboxRequest
from services.provider_gate import _apply_decision_contract_result, _apply_provider_gate_verdict, _claim_verifier_required, _skipped_offer_claim_payload
from services.reputation_enrich import _attach_reputation_lookup_hashes, _attach_reputation_lookup_urls, _has_bad_provider_verdict
from services.external_url_privacy import prepare_external_url, prepare_external_urls, prepare_reputation_lookup_url
from services.artifact_envelope import build_artifact_envelope
from services.payment_case import (
    build_payment_case_facts_from_scan,
    client_owner_fingerprint,
    enrich_payment_case_facts_with_final_gate,
)
from services import payment_case_store
from services.protected_action_shadow import (
    build_action_asset_shadow,
    evaluate_protected_action_shadow,
)
from services.email_evidence_ledger import sanitize_email_evidence_ledger
from services.pre_redaction_evidence import (
    pre_redaction_context_text,
    pre_redaction_primary_cui,
    pre_redaction_summary,
    sanitize_pre_redaction_evidence,
)
from services.threat_enrichment import build_threat_enrichment
from services.scan_helpers import _invoice_payment_destination_for_client, _validate_text_input
from services.url_reputation import reputation_url_hash_variants
from services.verdict_gate import verdict as reduce_verdict
from core.click_intelligence import _collect_click_targets_from_html, _collect_form_context_from_html
from core.identity import _new_scan_id
from core.scan_context import _attach_initial_url_privacy, _safe_scan_url_list, _infer_brand_hints_from_click_targets
from core.text_utils import _normalise_obfuscated_text
from core.url_intelligence import _canonicalize_url, extract_urls
from config import URLSCAN_VISIBILITY_DEFAULT, URLSCAN_COUNTRY_DEFAULT, URLSCAN_CUSTOM_AGENT_DEFAULT, MAX_TEXT_CHARS


import logging
import requests as _requests

from services.scan_analysis import (
    _ai_explanation_fingerprint,
    _all_required_pillars_terminal,
    _apply_best_preview_cache_hit,
    _apply_fast_preview_cache_hit,
    _apply_final_url_unresolved_shortener_fail_safe,
    _apply_primary_resolved_url,
    _attach_offer_claim_verification,
    _build_ai_explanation_async,
    _build_scan_response,
    _cloud_tasks_access_token,
    _collect_signal_ids,
    _emit_scan_event,
    _enrich_local_semantic_review,
    _enrich_offer_claim_verification_async,
    _enrich_semantic_review_async,
    _final_url_unresolved_entry,
    _first_final_url,
    _has_required_pillar_error,
    _invoice_auto_route_context,
    _load_fast_preview_cache,
    _mark_required_pillars_timeout,
    _merge_threat_intel_sources,
    _official_clean_can_finalize_before_urlscan,
    _official_destination_confirmed,
    _pillar,
    _preview_for_final_url_unresolved,
    _preview_merge_rank,
    _provider_pillar_from_summary,
    _provider_reputation_context_analysis,
    _provider_verdict_for_decision_bundle,
    _public_navigation_clean_can_finalize_before_urlscan,
    _run_offer_web_claim_enrichment,
    _select_primary_resolved_url,
    logger,
)
from config import (
    CLOUD_TASKS_LOCATION,
    CLOUD_TASKS_PROJECT,
    CLOUD_TASKS_QUEUE,
    CLOUD_TASKS_REQUEST_TIMEOUT_SECONDS,
    INTERNAL_WORKER_TOKEN,
    ORCHESTRATED_CLOUD_TASKS_ENABLED,
    ORCHESTRATED_DEFER_AI_EXPLANATION,
    ORCHESTRATED_EARLY_VERDICT,
    ORCHESTRATED_JOB_TTL_SECONDS,
    ORCHESTRATED_REFRESH_LOCK_TTL_SECONDS,
    ORCHESTRATED_REQUIRED_PILLAR_TIMEOUT_SECONDS,
    ORCHESTRATED_URLSCAN_PENDING_TIMEOUT_SECONDS,
    ORCHESTRATED_URLSCAN_SUBMIT_RESERVATION_TIMEOUT_SECONDS,
    EMAIL_COMPOUND_EVIDENCE_ACTIVE,
    PRIVACY_SAFE_MODE,
    SIGURSCAN_PUBLIC_API_BASE_URL,
    _ORCHESTRATED_STAGE_RANK,
)
from services.reputation_enrich import (
    _analyze_with_reputation,
    _external_intel_summary_from_threat_intel,
    _gather_external_intel_safe,
)
from services.urlscan_logic import (
    _apply_urlscan_preview_cache_hit,
    _mark_urlscan_screenshot_unavailable,
    _sanitize_urlscan_result_payload,
    _save_urlscan_preview_cache,
    _sync_resolved_urls_with_urlscan_final,
    _urlscan_enhancement_done,
    _urlscan_finished_with_risk,
    _urlscan_merge_rank,
    _urlscan_pending_has_timed_out,
    _urlscan_preview_cache_entry_from_job,
    _urlscan_provider_payload,
    _urlscan_result_ready_for_verdict,
    _urlscan_scan_prevented,
    _urlscan_state_has_risk,
)
from services.urlscan_helpers import (
    _load_urlscan_preview_cache,
    _normalize_screenshot_proxy_url,
    _urlscan_screenshot_is_ready,
)
from services.extract_pipeline import _assemble_extracted_text_for_orchestration
from services.whois_ssl_signals import check_domain_ssl_parallel, domain_risk_from_signals
from services.gemini_explainer import generate_fallback_explanation
from services.urlscan_pipeline import get_urlscan_result, submit_urlscan_sandbox
from services.telemetry import log_scan_event
from services.pii_redactor import redact_pii
from services.scam_atlas import BRAND_REGISTRY as SCAM_ATLAS_BRAND_REGISTRY
from core.serialization import _deep_copy_jsonable, _merge_progress_dict
from core.request_security import _env_present
from core.email_auth import _extract_domain_root
from core.scan_context import _extract_email_mime_parts, _merge_url_privacy
from services import supabase_store

requests = _requests
class OrchestratedScanEngine:
    """Orchestrated-scan engine: owns the in-memory job store/locks and the full
    scan pipeline. Helpers/config that remain in py are referenced via X."""

    def __init__(self) -> None:
        self._ORCHESTRATED_SCAN_JOBS: Dict[str, Dict[str, Any]] = {}
        self._ORCHESTRATED_SCAN_LOCKS: Dict[str, asyncio.Lock] = {}
        self._ORCHESTRATED_SCAN_LOCKS: Dict[str, asyncio.Lock] = {}


    def _orchestrated_metrics(self, job: Dict[str, Any]) -> Dict[str, Any]:
        metrics = job.get("orchestration_metrics")
        if not isinstance(metrics, dict):
            metrics = {}
            job["orchestration_metrics"] = metrics
        metrics.setdefault("poll_count", 0)
        metrics.setdefault("stage_durations_ms", {})
        metrics.setdefault("component_durations_ms", {})
        metrics.setdefault("stage_sequence", [])
        metrics.setdefault("conflict_merge_count", 0)
        metrics.setdefault("conflict_merge_retry_count", 0)
        metrics.setdefault("conflict_merge_retry_failures", 0)
        metrics.setdefault("urlscan_reclaim_count", 0)
        metrics.setdefault("urlscan_reservation_guard_hits", 0)
        metrics.setdefault("urlscan_timeout_count", 0)
        metrics.setdefault("stage_entered_at", int(job.get("created_at") or int(time.time())))
        return metrics


    def _increment_orchestrated_metric(self, job: Dict[str, Any], key: str, amount: int = 1) -> None:
        metrics = self._orchestrated_metrics(job)
        try:
            metrics[key] = int(metrics.get(key, 0) or 0) + int(amount)
        except Exception:
            metrics[key] = int(amount)


    def _record_orchestrated_component_duration(self, job: Dict[str, Any], component: str, started_at: float) -> None:
        if not isinstance(job, dict):
            return
        elapsed_ms = max(0, int((time.perf_counter() - started_at) * 1000))
        metrics = self._orchestrated_metrics(job)
        durations = metrics.setdefault("component_durations_ms", {})
        if not isinstance(durations, dict):
            durations = {}
            metrics["component_durations_ms"] = durations
        key = str(component or "unknown")
        try:
            durations[key] = int(durations.get(key, 0) or 0) + elapsed_ms
        except Exception:
            durations[key] = elapsed_ms


    def _timed_orchestrated_component(self, job: Dict[str, Any], component: str, fn):
        started_at = time.perf_counter()
        try:
            return fn()
        finally:
            self._record_orchestrated_component_duration(job, component, started_at)


    def _set_orchestrated_stage(self, job: Dict[str, Any], next_stage: str) -> None:
        if not isinstance(job, dict):
            return
        next_stage = str(next_stage or "").strip().lower() or "queued"
        now = int(time.time())
        metrics = self._orchestrated_metrics(job)
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


    def _emit_orchestrated_telemetry(self, event_type: str, job: Dict[str, Any], **metadata: Any) -> None:
        if not isinstance(job, dict):
            return
        scan_id = str(job.get("scan_id") or "").strip()
        if not scan_id:
            return
        try:
            metrics = self._orchestrated_metrics(job)
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
                        "component_durations_ms": metrics.get("component_durations_ms", {}),
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


    def _persist_orchestrated_job(self, job: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(job, dict) or not job.get("scan_id"):
            return job
        scan_id = str(job["scan_id"])
        saved = supabase_store.save_scan_job(job)
        if saved is False:
            self._increment_orchestrated_metric(job, "conflict_merge_count")
            reloaded = supabase_store.load_scan_job(scan_id)
            if isinstance(reloaded, dict):
                merged = self._merge_orchestrated_conflict_job(reloaded, job)
                if merged != reloaded:
                    retry_saved = False
                    for _ in range(2):
                        self._increment_orchestrated_metric(merged, "conflict_merge_retry_count")
                        retry_saved = supabase_store.save_scan_job(merged)
                        if retry_saved is not False:
                            break
                        latest = supabase_store.load_scan_job(scan_id)
                        if isinstance(latest, dict):
                            merged = self._merge_orchestrated_conflict_job(latest, merged)
                    if retry_saved is False:
                        self._increment_orchestrated_metric(merged, "conflict_merge_retry_failures")
                    self._emit_orchestrated_telemetry(
                        "orchestrated_conflict_merge",
                        merged,
                        retry_saved=retry_saved is not False,
                    )
                self._ORCHESTRATED_SCAN_JOBS[scan_id] = merged
                return merged
            self._increment_orchestrated_metric(job, "persist_fallback_memory_count")
            self._ORCHESTRATED_SCAN_JOBS[scan_id] = job
            self._emit_orchestrated_telemetry("orchestrated_persist_memory_fallback", job)
            return job
        self._ORCHESTRATED_SCAN_JOBS[scan_id] = job
        return job


    def _load_orchestrated_job(self, scan_id: str) -> Optional[Dict[str, Any]]:
        job = supabase_store.load_scan_job(scan_id)
        if isinstance(job, dict):
            self._ORCHESTRATED_SCAN_JOBS[scan_id] = job
            return job
        job = self._ORCHESTRATED_SCAN_JOBS.get(scan_id)
        if isinstance(job, dict):
            return job
        return None


    def _orchestrated_lock_owner(self, scan_id: str) -> str:
        return f"cloudrun:{os.getenv('K_REVISION', 'local')}:{os.getpid()}:{scan_id}:{time.time_ns()}"


    def _claim_distributed_orchestrated_refresh(self, job: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        revision = job.get("_storage_revision")
        scan_id = str(job.get("scan_id") or "")
        if not scan_id or not isinstance(revision, int):
            return None
        claimed = supabase_store.claim_scan_job(
            scan_id,
            expected_revision=revision,
            owner=self._orchestrated_lock_owner(scan_id),
            active_step=str(job.get("pipeline_stage") or "queued"),
            lock_seconds=ORCHESTRATED_REFRESH_LOCK_TTL_SECONDS,
        )
        if not isinstance(claimed, dict):
            return None
        claimed_job = supabase_store.scan_job_from_record(claimed)
        if isinstance(claimed_job, dict):
            self._ORCHESTRATED_SCAN_JOBS[scan_id] = claimed_job
            return claimed_job
        return job


    def _prune_orchestrated_jobs(self) -> None:
        now = int(time.time())
        expired = [
            scan_id
            for scan_id, job in self._ORCHESTRATED_SCAN_JOBS.items()
            if now - int(job.get("created_at", now)) > ORCHESTRATED_JOB_TTL_SECONDS
        ]
        for scan_id in expired:
            self._ORCHESTRATED_SCAN_JOBS.pop(scan_id, None)
            self._ORCHESTRATED_SCAN_LOCKS.pop(scan_id, None)


    def _orchestrated_stage_rank(self, stage: Any) -> int:
        return _ORCHESTRATED_STAGE_RANK.get(str(stage or "").strip().lower(), -1)


    def _merge_orchestrated_conflict_job(self, reloaded: Dict[str, Any], local: Dict[str, Any]) -> Dict[str, Any]:
        merged = dict(reloaded)
        local_urlscan = local.get("urlscan") if isinstance(local.get("urlscan"), dict) else {}
        local_is_unpersisted_urlscan_reservation = (
            str(local_urlscan.get("status") or "").strip().lower() == "submitting"
            and not local_urlscan.get("uuid")
        )

        if (
            not local_is_unpersisted_urlscan_reservation
            and self._orchestrated_stage_rank(local.get("pipeline_stage")) > self._orchestrated_stage_rank(merged.get("pipeline_stage"))
        ):
            merged["pipeline_stage"] = local.get("pipeline_stage")

        for key in (
            "resolved_urls",
            "primary_final_url",
            "threat_intel",
            "analysis",
            "result",
            "claim_verifier_required",
            "offer_web_claim",
            "invoice_analysis_text",
            "action_asset_shadow",
        ):
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
                merged_urlscan = _merge_progress_dict(
                    merged_urlscan,
                    local_urlscan,
                    ranker=_urlscan_merge_rank,
                )
            merged["urlscan"] = merged_urlscan

        local_preview = local.get("preview") if isinstance(local.get("preview"), dict) else {}
        if local_preview:
            merged_preview = dict(merged.get("preview") if isinstance(merged.get("preview"), dict) else {})
            merged_preview = _merge_progress_dict(
                merged_preview,
                local_preview,
                ranker=_preview_merge_rank,
            )
            merged["preview"] = merged_preview

        local_metrics = local.get("orchestration_metrics") if isinstance(local.get("orchestration_metrics"), dict) else {}
        if local_metrics:
            merged_metrics = dict(merged.get("orchestration_metrics") if isinstance(merged.get("orchestration_metrics"), dict) else {})
            for key, value in local_metrics.items():
                if key in {"stage_durations_ms", "component_durations_ms"} and isinstance(value, dict):
                    durations = dict(merged_metrics.get("stage_durations_ms") if isinstance(merged_metrics.get("stage_durations_ms"), dict) else {})
                    if key == "component_durations_ms":
                        durations = dict(merged_metrics.get("component_durations_ms") if isinstance(merged_metrics.get("component_durations_ms"), dict) else {})
                    for stage_name, duration_ms in value.items():
                        try:
                            durations[str(stage_name)] = max(int(durations.get(stage_name, 0) or 0), int(duration_ms))
                        except Exception:
                            continue
                    merged_metrics[key] = durations
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


    def _orchestrated_result_fingerprint(self,
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


    def _build_orchestrated_pillars(self, job: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        analysis = job.get("analysis") if isinstance(job.get("analysis"), dict) else {}
        evidence = analysis.get("evidence", {}) if isinstance(analysis.get("evidence"), dict) else {}
        summary = evidence.get("external_intel_summary") if isinstance(evidence.get("external_intel_summary"), dict) else {}
        resolved_urls = job.get("resolved_urls") if isinstance(job.get("resolved_urls"), list) else []
        raw_urls = job.get("urls") if isinstance(job.get("urls"), list) else []
        has_urls = bool(raw_urls or resolved_urls)
        final_url = job.get("primary_final_url") or _first_final_url(resolved_urls)
        job_input_type = str(job.get("input_type") or "").strip().lower()

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
            or (job_input_type == "invoice" and semantic_status == "done")
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
            if urlscan_status == "timeout" and urlscan_state.get("verdict") and urlscan_state.get("report_url"):
                urlscan_pillar = _pillar(
                    "ok",
                    required=False,
                    details=f"{urlscan_state.get('verdict')}; captura indisponibila la provider",
                    ref=urlscan_state.get("uuid"),
                )
            elif official_destination and _urlscan_scan_prevented(urlscan_details):
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
            asf_pillar = _pillar("not_required", required=False, details="nu exista URL pentru ASF")
            phishing_database_pillar = _pillar("not_required", required=False, details="nu exista URL pentru Phishing.Database")
            phishtank_pillar = _pillar("not_required", required=False, details="nu exista URL pentru PhishTank")
            openphish_pillar = _pillar("not_required", required=False, details="nu exista URL pentru OpenPhish")
        else:
            final_url_pillar = _pillar("ok" if final_url else "pending", details=str(final_url or "se rezolva destinatia finala"))
            web_risk_pillar = _provider_pillar_from_summary(summary, "google_web_risk")
            asf_pillar = _provider_pillar_from_summary(summary, "asf_investor_alerts")
            asf_pillar["required"] = False
            phishing_database_pillar = _provider_pillar_from_summary(summary, "phishing_database")
            phishtank_pillar = _provider_pillar_from_summary(summary, "phishtank_online_valid")
            openphish_pillar = _provider_pillar_from_summary(summary, "openphish")
            openphish_pillar["required"] = False

        return {
            "final_url": final_url_pillar,
            "google_web_risk": web_risk_pillar,
            "asf_investor_alerts": asf_pillar,
            "phishing_database": phishing_database_pillar,
            "phishtank_online_valid": phishtank_pillar,
            "openphish": openphish_pillar,
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


    def _orchestrated_required_pillars_timed_out(self, job: Dict[str, Any]) -> bool:
        created_at = int(job.get("created_at") or int(time.time()))
        return int(time.time()) - created_at >= ORCHESTRATED_REQUIRED_PILLAR_TIMEOUT_SECONDS


    def _normalize_orchestrated_preview_status(self, job: Dict[str, Any], preview: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(preview, dict):
            return {}
        normalized = dict(preview)
        status = str(normalized.get("status") or "").strip().lower()
        has_visual = bool(normalized.get("image_url") or normalized.get("screenshot_url"))
        if status != "ready" or has_visual:
            return normalized

        urlscan_state = job.get("urlscan") if isinstance(job.get("urlscan"), dict) else {}
        looks_like_urlscan_preview = (
            str(normalized.get("source") or "").strip().lower() == "urlscan"
            or bool(normalized.get("report_url"))
            or bool(urlscan_state.get("uuid"))
            or str(urlscan_state.get("status") or "").strip().lower() in {"pending", "finished", "timeout"}
        )
        if not looks_like_urlscan_preview:
            return normalized

        # Read-boundary deadline: even if the worker step that applies the urlscan
        # timeout has not advanced, never report "pending" forever. After the budget
        # the screenshot is treated as unavailable so the client stops spinning and
        # keeps the verdict (a final verdict never waits for a screenshot).
        created_at = int(job.get("created_at") or int(time.time()))
        if int(time.time()) - created_at >= ORCHESTRATED_URLSCAN_PENDING_TIMEOUT_SECONDS:
            normalized["status"] = "unavailable"
            normalized["source"] = "urlscan"
            normalized["image_url"] = None
            normalized["screenshot_url"] = None
            normalized["reason"] = "urlscan_screenshot_timeout"
            normalized["details"] = normalized.get("details") or (
                "Captura paginii nu a putut fi generată la timp (preview indisponibil). "
                "Verdictul rămâne valabil."
            )
            return normalized

        normalized["status"] = "pending"
        normalized["source"] = "urlscan"
        normalized["image_url"] = None
        normalized["screenshot_url"] = None
        normalized["reason"] = normalized.get("reason") or "urlscan_screenshot_pending"
        return normalized


    def _orchestrated_status_payload(self, job: Dict[str, Any]) -> Dict[str, Any]:
        pillars = self._build_orchestrated_pillars(job)
        raw_preview = job.get("preview") if isinstance(job.get("preview"), dict) else {}
        preview = self._normalize_orchestrated_preview_status(job, _preview_for_final_url_unresolved(job, raw_preview))
        result = job.get("result") if isinstance(job.get("result"), dict) else None
        metrics = self._orchestrated_metrics(job)
        result_is_final = result is not None and result.get("is_final", True) is not False
        final_url_unresolved = preview.get("reason") == "final_url_unresolved"
        enhancement_done = _urlscan_enhancement_done(job) or final_url_unresolved
        if result_is_final:
            status = "complete"
        elif _has_required_pillar_error(pillars):
            status = "incomplete"
        else:
            status = "scanning"
        job["status"] = status
        preview_pending = preview.get("status") == "pending" or preview.get("reason") in {
            "urlscan_pending",
            "urlscan_screenshot_pending",
        } or not (preview.get("image_url") or preview.get("screenshot_url"))
        poll_after_ms = 3000 if (
            status in {"scanning", "complete"}
            and isinstance(job.get("urlscan"), dict)
            and str(job["urlscan"].get("status") or "").lower() == "pending"
            and job["urlscan"].get("uuid")
            and preview_pending
        ) else 1000
        return {
            "scan_id": job["scan_id"],
            "status": status,
            "status_message": (
                "Scanarea este finalizata. Destinatia finala nu poate fi incarcata/verificata; nu continua fara verificare oficiala."
                if status == "complete" and final_url_unresolved
                else
                "Scanarea este finalizata."
                if status == "complete" and enhancement_done
                else "Verdictul este finalizat. Preview-ul securizat se poate actualiza separat."
                if status == "complete" and not enhancement_done
                else "Verdict preliminar disponibil. Verificarea suplimentara (sandbox) continua si poate doar creste nivelul de risc."
                if status == "scanning" and result is not None
                else "Scanarea continua pana cand verificarile necesare returneaza date."
                if status == "scanning"
                else "Scanarea nu are inca toate verificarile necesare pentru verdict sigur."
            ),
            "poll_after_ms": poll_after_ms,
            "pillars": pillars,
            "preview": preview,
            "result": result,
            "diagnostics": {
                "pipeline_stage": job.get("pipeline_stage"),
                "poll_count": metrics.get("poll_count", 0),
                "stage_durations_ms": metrics.get("stage_durations_ms", {}),
                "component_durations_ms": metrics.get("component_durations_ms", {}),
                "urlscan_status": (job.get("urlscan") if isinstance(job.get("urlscan"), dict) else {}).get("status"),
            },
        }


    def _attach_payment_case_artifact_ref(
        self,
        job: Dict[str, Any],
        response_payload: Dict[str, Any],
        gate: Dict[str, Any],
    ) -> None:
        payment_case_owner = str(job.get("payment_case_owner_fingerprint") or "")
        payment_case_facts = job.get("payment_case_facts")
        if (
            response_payload.get("is_final") is not True
            or not payment_case_owner
            or not isinstance(payment_case_facts, dict)
        ):
            return
        artifact_ref = str(job.get("payment_case_artifact_ref") or "")
        if not artifact_ref:
            try:
                artifact = payment_case_store.register_server_artifact_for_owner(
                    owner_fingerprint=payment_case_owner,
                    artifact_type=str(
                        (job.get("artifact_envelope") or {}).get("artifact_type")
                        if isinstance(job.get("artifact_envelope"), dict)
                        else job.get("input_type") or "unknown"
                    ),
                    verdict=str(gate.get("label") or response_payload.get("user_risk_label") or "UNVERIFIED"),
                    is_final=True,
                    reason_codes=gate.get("reason_codes") if isinstance(gate.get("reason_codes"), list) else [],
                    facts=enrich_payment_case_facts_with_final_gate(
                        payment_case_facts,
                        gate.get("reason_codes") if isinstance(gate.get("reason_codes"), list) else [],
                    ),
                )
                artifact_ref = str(artifact.get("artifact_ref") or "")
                job["payment_case_artifact_ref"] = artifact_ref
            except Exception:
                self._emit_orchestrated_telemetry("payment_case_artifact_persist_failed", job)
        if artifact_ref:
            response_payload["payment_case_artifact_ref"] = artifact_ref


    def _orchestrated_revision(self, job: Dict[str, Any]) -> int:
        revision = job.get("_storage_revision")
        if revision is None:
            revision = job.get("revision")
        try:
            return int(revision)
        except (TypeError, ValueError):
            return 0


    def _orchestrated_verdict_state(self, status_payload: Dict[str, Any]) -> str:
        result = status_payload.get("result")
        status = str(status_payload.get("status") or "").strip().lower()
        if isinstance(result, dict):
            if result.get("is_final", True) is not False:
                return "verdict_done"
            return "verdict_pending"
        if status in {"incomplete", "error"}:
            return "verdict_error"
        return "running"


    def _orchestrated_preview_state(self, status_payload: Dict[str, Any]) -> str:
        preview = status_payload.get("preview") if isinstance(status_payload.get("preview"), dict) else {}
        preview_status = str(preview.get("status") or "").strip().lower()
        reason = str(preview.get("reason") or "").strip().lower()
        has_visual = bool(preview.get("image_url") or preview.get("screenshot_url"))
        if has_visual:
            return "ready"
        if preview_status == "ready" and not has_visual:
            return "pending"
        if reason in {"no_url", "privacy_safe_mode"}:
            return "not_applicable"
        if preview_status == "pending" or reason in {"urlscan_pending", "urlscan_screenshot_pending"}:
            return "pending"
        if preview_status == "unavailable" or reason in {
            "final_url_unresolved",
            "preview_unavailable",
            "urlscan_timeout",
            "urlscan_screenshot_timeout",
        }:
            return "timeout"
        return "unknown"


    def _orchestrated_read_status_payload(self, job: Dict[str, Any], *, changed: bool) -> Dict[str, Any]:
        payload = self._orchestrated_status_payload(job)
        payload["revision"] = self._orchestrated_revision(job)
        payload["changed"] = bool(changed)
        payload["verdict_state"] = self._orchestrated_verdict_state(payload)
        payload["preview_state"] = self._orchestrated_preview_state(payload)
        return payload


    def _orchestrated_status_changed(self, job: Dict[str, Any], after_revision: Optional[int]) -> bool:
        if after_revision is None:
            return True
        return self._orchestrated_revision(job) > after_revision


    def _orchestrated_worker_can_stop(self, status_payload: Dict[str, Any]) -> bool:
        if status_payload.get("verdict_state") != "verdict_done":
            return False
        return status_payload.get("preview_state") in {"ready", "timeout", "not_applicable"}


    async def _wait_for_orchestrated_status_read(self,
        scan_id: str,
        *,
        after_revision: Optional[int],
        wait_seconds: float,
    ) -> Tuple[Optional[Dict[str, Any]], bool]:
        deadline = time.monotonic() + max(0.0, min(wait_seconds, 20.0))
        while True:
            job = self._load_orchestrated_job(scan_id)
            if not isinstance(job, dict):
                return None, False
            changed = self._orchestrated_status_changed(job, after_revision)
            remaining = deadline - time.monotonic()
            if changed or remaining <= 0:
                return job, changed
            await asyncio.sleep(min(0.75, remaining))


    def _orchestrated_can_finalize_result(self, job: Dict[str, Any], pillars: Dict[str, Dict[str, Any]]) -> bool:
        if str(job.get("pipeline_stage") or "").strip().lower() == "done":
            return True
        if not _all_required_pillars_terminal(pillars):
            return False
        if ORCHESTRATED_EARLY_VERDICT:
            # The verdict publishes as soon as the required pillars are terminal.
            # It stays is_final=false until the urlscan report is terminal, and the
            # report can only raise severity when it lands.
            return True
        # Legacy pacing: user-facing verdicts wait for the urlscan report when a
        # URL exists, but not for screenshot availability. The screenshot is an
        # async visual enhancement and can fill in after the final label.
        return _urlscan_result_ready_for_verdict(job)


    def _orchestrated_result_is_final(self, job: Dict[str, Any], analysis: Dict[str, Any]) -> bool:
        evidence = analysis.get("evidence", {}) if isinstance(analysis.get("evidence"), dict) else {}
        gate = evidence.get("verdict_gate") if isinstance(evidence.get("verdict_gate"), dict) else {}
        if _final_url_unresolved_entry(job):
            return True
        label = str(gate.get("label") or "").upper()
        if label in {"SAFE", "SUSPECT", "DANGEROUS"}:
            return True
        if label != "UNVERIFIED":
            return False
        decision_bundle = evidence.get("decision_bundle") if isinstance(evidence.get("decision_bundle"), dict) else {}
        bundle_input = decision_bundle.get("input") if isinstance(decision_bundle.get("input"), dict) else {}
        if bundle_input.get("type") == "invoice":
            return True
        has_url_context = bool(job.get("urls")) or bool(job.get("resolved_urls"))
        if not has_url_context:
            provider_gate = evidence.get("provider_gate") if isinstance(evidence.get("provider_gate"), dict) else {}
            timeout_family = str(analysis.get("detected_family_id") or "") == "provider-gate-required-timeout"
            return (
                provider_gate.get("required_timeout") is not True
                and not timeout_family
                and job.get("required_pillars_timed_out") is not True
            )
        reason_codes = {str(item).strip() for item in gate.get("reason_codes") or []}
        return not (reason_codes & {"insufficient_evidence", "provider_error"})


    def _orchestrated_cloud_tasks_configured(self) -> bool:
        return bool(
            ORCHESTRATED_CLOUD_TASKS_ENABLED
            and CLOUD_TASKS_PROJECT
            and CLOUD_TASKS_LOCATION
            and CLOUD_TASKS_QUEUE
            and INTERNAL_WORKER_TOKEN
        )


    def _orchestrated_worker_task_url(self, scan_id: str, *, max_steps: int = 1) -> str:
        safe_scan_id = urllib.parse.quote(str(scan_id), safe="")
        step_budget = max(1, min(int(max_steps or 1), 3))
        public_base = SIGURSCAN_PUBLIC_API_BASE_URL or "https://api.sigurscan.com"
        return f"{public_base}/internal/orchestrated/{safe_scan_id}/advance?max_steps={step_budget}"


    def _enqueue_orchestrated_worker_task(self,
        scan_id: str,
        request: Request,
        *,
        delay_seconds: int = 0,
        max_steps: int = 1,
    ) -> bool:
        if not self._orchestrated_cloud_tasks_configured():
            return False
        try:
            access_token = _cloud_tasks_access_token()
            queue_url = (
                f"https://cloudtasks.googleapis.com/v2/projects/{CLOUD_TASKS_PROJECT}/"
                f"locations/{CLOUD_TASKS_LOCATION}/queues/{CLOUD_TASKS_QUEUE}/tasks"
            )
            body = json.dumps({"scan_id": str(scan_id)}, ensure_ascii=False).encode("utf-8")
            task: Dict[str, Any] = {
                "httpRequest": {
                    "httpMethod": "POST",
                    "url": self._orchestrated_worker_task_url(scan_id, max_steps=max_steps),
                    "headers": {
                        "Content-Type": "application/json",
                        "X-Internal-Worker-Token": INTERNAL_WORKER_TOKEN,
                    },
                    "body": base64.b64encode(body).decode("ascii"),
                }
            }
            if delay_seconds > 0:
                run_at = datetime.now(timezone.utc) + timedelta(seconds=delay_seconds)
                task["scheduleTime"] = run_at.isoformat().replace("+00:00", "Z")
            response = requests.post(
                queue_url,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json",
                },
                json={"task": task},
                timeout=CLOUD_TASKS_REQUEST_TIMEOUT_SECONDS,
            )
            response.raise_for_status()
            return True
        except Exception as exc:
            logger.warning("orchestrated Cloud Tasks enqueue failed: %s", type(exc).__name__)
            return False


    def _build_orchestrated_text_context(self, payload: OrchestratedScanRequest) -> Dict[str, Any]:
        input_type = (payload.input_type or "text").strip().lower()
        source_channel = payload.source_channel or "android_native"

        if input_type == "url":
            raw_input = _normalise_obfuscated_text(payload.url or payload.text or "").strip()
            embedded_urls = extract_urls(raw_input)
            if embedded_urls:
                first_url = embedded_urls[0]
                raw_text = raw_input if payload.text else f"Link: {first_url}"
                return {
                    "input_type": "url",
                    "source_channel": source_channel,
                    "raw_text": raw_text,
                    "urls": embedded_urls,
                    "extra_fields": {"input_url": payload.url or payload.text, "canonical_url": first_url},
                }

            url = _canonicalize_url(raw_input)
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
            raw_email_or_html = payload.html_content or payload.text or ""
            mime_parts = _extract_email_mime_parts(payload.text or "") if input_type == "email" and not payload.html_content else {}
            plain_text_context = _normalise_obfuscated_text(mime_parts.get("plain") or "")
            email_subject = _normalise_obfuscated_text(mime_parts.get("subject") or "")
            html_to_parse = _normalise_obfuscated_text(
                payload.html_content
                or mime_parts.get("html")
                or plain_text_context
                or payload.text
                or ""
            )
            _validate_text_input("Conținutul HTML trimis", raw_email_or_html, MAX_TEXT_CHARS * 8)
            soup = BeautifulSoup(html_to_parse, "html.parser")
            click_targets = _collect_click_targets_from_html(soup)
            form_context = _collect_form_context_from_html(soup)
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
            for url in extract_urls(plain_text_context):
                if url not in discovered_urls:
                    discovered_urls.append(url)
            for url in extract_urls(visible_text):
                if url not in discovered_urls:
                    discovered_urls.append(url)
            inferred_brand_hints = _infer_brand_hints_from_click_targets(
                click_targets,
                SCAM_ATLAS_BRAND_REGISTRY,
            )
            click_context = [
                f"CTA {button.get('source_tag')}/{button.get('source_attr')}: "
                f"{button.get('button_text')} -> {button.get('original_url')}"
                for button in buttons
                if button.get("original_url")
            ]
            raw_text = "\n".join(
                part
                for part in [
                    email_subject,
                    plain_text_context,
                    visible_text,
                    " ".join(inferred_brand_hints),
                    *form_context,
                    *click_context,
                ]
                if str(part or "").strip()
            )
            auto_invoice = _invoice_auto_route_context(
                source_channel=source_channel,
                raw_text=raw_text,
                urls=discovered_urls,
                extra_fields={
                    "buttons": buttons,
                    "inferred_brand_hints": inferred_brand_hints,
                    "email_mime_parsed": bool(mime_parts),
                    "form_context": form_context,
                    "is_forwarded_warning": True,
                },
                original_input_type=input_type,
            )
            if auto_invoice:
                return auto_invoice
            return {
                "input_type": "email",
                "source_channel": source_channel,
                "raw_text": raw_text,
                "urls": discovered_urls,
                "extra_fields": {
                    "buttons": buttons,
                    "inferred_brand_hints": inferred_brand_hints,
                    "email_mime_parsed": bool(mime_parts),
                    "form_context": form_context,
                    "is_forwarded_warning": True,
                },
            }

        if input_type == "invoice":
            raw_text = _normalise_obfuscated_text((payload.text or payload.url or "").strip())
            _validate_text_input("Textul facturii", raw_text, MAX_TEXT_CHARS)
            return {
                "input_type": "invoice",
                "source_channel": source_channel,
                "raw_text": raw_text,
                "urls": extract_urls(raw_text),
                "extra_fields": {"invoice_scan": True},
            }

        if input_type == "offer":
            raw_text = _normalise_obfuscated_text((payload.text or payload.url or "").strip())
            _validate_text_input("Textul ofertei", raw_text, MAX_TEXT_CHARS)
            return {
                "input_type": "offer",
                "source_channel": source_channel,
                "raw_text": raw_text,
                "urls": extract_urls(raw_text),
                "extra_fields": {"offer_scan": True},
            }

        raw_text = _normalise_obfuscated_text((payload.text or payload.url or "").strip())
        _validate_text_input("Textul trimis", raw_text, MAX_TEXT_CHARS)
        auto_invoice = _invoice_auto_route_context(
            source_channel=source_channel,
            raw_text=raw_text,
            urls=extract_urls(raw_text),
            original_input_type=input_type,
        )
        if auto_invoice:
            return auto_invoice
        return {
            "input_type": "text",
            "source_channel": source_channel,
            "raw_text": raw_text,
            "urls": extract_urls(raw_text),
            "extra_fields": {},
        }


    async def _start_orchestrated_compat(self, payload: OrchestratedScanRequest) -> Dict[str, Any]:
        job = await self._create_orchestrated_job(payload)
        return self._orchestrated_status_payload(job)


    async def _finalize_orchestrated_job_if_ready(self, job: Dict[str, Any], request: Request) -> Dict[str, Any]:
        _sync_resolved_urls_with_urlscan_final(job)
        pillars = self._build_orchestrated_pillars(job)
        existing_result = job.get("result") if isinstance(job.get("result"), dict) else None
        if existing_result and existing_result.get("is_final", True) is not False:
            if not _urlscan_enhancement_done(job) and not _urlscan_finished_with_risk(job):
                return job
        if not self._orchestrated_can_finalize_result(job, pillars):
            return job

        analysis = job.get("analysis") if isinstance(job.get("analysis"), dict) else {}
        resolved_urls = job.get("resolved_urls") if isinstance(job.get("resolved_urls"), list) else []
        # Rutele specializate (ofertă/factură) au deja bundle v2 + verdict din
        # reduce_verdict. Re-derivarea pe logica rutei text ar suprascrie verdictul
        # specializat (ex. factură coerentă -> "transfer" generic -> SUSPECT).
        _existing_bundle = (
            (analysis.get("evidence") or {}).get("decision_bundle")
            if isinstance(analysis.get("evidence"), dict)
            else None
        )
        _is_specialized_bundle = (
            isinstance(_existing_bundle, dict)
            and isinstance(_existing_bundle.get("input"), dict)
            and _existing_bundle["input"].get("type") in {"offer", "invoice"}
        )
        if not _is_specialized_bundle:
            job_cross_scan = job.get("cross_scan_knowledge") if isinstance(job.get("cross_scan_knowledge"), dict) else {}
            if job_cross_scan:
                evidence_for_gate = analysis.setdefault("evidence", {})
                if isinstance(evidence_for_gate, dict) and not isinstance(evidence_for_gate.get("cross_scan_knowledge"), dict):
                    evidence_for_gate["cross_scan_knowledge"] = job_cross_scan
            _apply_provider_gate_verdict(
                analysis,
                resolved_urls,
                raw_text=str(job.get("redacted_text") or ""),
                pillars=pillars,
                scan_id=str(job.get("scan_id") or "") or None,
            )
            _apply_final_url_unresolved_shortener_fail_safe(job, analysis)
        evidence = analysis.get("evidence", {}) if isinstance(analysis.get("evidence"), dict) else {}
        gate = evidence.get("verdict_gate") if isinstance(evidence.get("verdict_gate"), dict) else {}
        decision_bundle = evidence.get("decision_bundle") if isinstance(evidence.get("decision_bundle"), dict) else {}
        job["action_asset_shadow"] = evaluate_protected_action_shadow(
            job.get("action_asset_shadow"),
            decision_bundle=decision_bundle,
            actual_label=str(gate.get("label") or "") or None,
        )
        self._emit_orchestrated_telemetry(
            "orchestrated_action_asset_shadow",
            job,
            candidate_min_label=job["action_asset_shadow"].get("candidate_min_label"),
            actual_label=job["action_asset_shadow"].get("actual_label"),
            would_raise_actual=job["action_asset_shadow"].get("would_raise_actual"),
            protected_actions=job["action_asset_shadow"].get("contract", {}).get("protected_actions", []),
        )
        if str(gate.get("label") or "").upper() == "UNVERIFIED" and not self._orchestrated_result_is_final(job, analysis):
            if existing_result and existing_result.get("is_final", True) is not False:
                self._emit_orchestrated_telemetry("orchestrated_verdict_pending_preserved_final", job)
                return job
            job.pop("result", None)
            job.pop("result_fingerprint", None)
            self._emit_orchestrated_telemetry("orchestrated_verdict_pending", job)
            return job
        fingerprint = self._orchestrated_result_fingerprint(job, analysis, pillars, resolved_urls)
        explanation_key = _ai_explanation_fingerprint(analysis)
        explanation_pending = bool(job.get("ai_explanation_pending"))
        if existing_result and job.get("result_fingerprint") == fingerprint and not explanation_pending:
            return job

        explanation_cache = job.get("ai_explanation_cache") if isinstance(job.get("ai_explanation_cache"), dict) else {}
        cached_explanation_keys = {explanation_cache.get("fingerprint"), explanation_cache.get("analysis_fingerprint")}
        ai_explanation = (
            explanation_cache.get("payload")
            if {fingerprint, explanation_key} & cached_explanation_keys
            else None
        )
        deferred_explanation = False
        if not isinstance(ai_explanation, dict):
            if job.get("skip_cloud_ai_explanation"):
                ai_explanation = generate_fallback_explanation(job.get("redacted_text", ""), analysis)
            elif ORCHESTRATED_DEFER_AI_EXPLANATION and existing_result is None and not explanation_pending:
                # First publishable verdict: never block it on the explainer LLM.
                # The deterministic fallback ships now; the cloud explanation is
                # attached by a later poll via ai_explanation_pending.
                ai_explanation = generate_fallback_explanation(job.get("redacted_text", ""), analysis)
                deferred_explanation = True
            else:
                ai_explanation = await _build_ai_explanation_async(job.get("redacted_text", ""), analysis, resolved_urls)
            if not deferred_explanation:
                job["ai_explanation_cache"] = {
                    "fingerprint": fingerprint,
                    "analysis_fingerprint": explanation_key,
                    "payload": ai_explanation,
                }
        job["ai_explanation_pending"] = deferred_explanation
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
        response_payload["is_final"] = (
            self._orchestrated_result_is_final(job, analysis)
            and (
                _urlscan_result_ready_for_verdict(job)
                or _official_clean_can_finalize_before_urlscan(job, analysis, pillars)
                or _public_navigation_clean_can_finalize_before_urlscan(job, analysis, pillars)
            )
            and not deferred_explanation
        )
        self._attach_payment_case_artifact_ref(job, response_payload, gate)
        job["result"] = response_payload
        job["result_fingerprint"] = fingerprint
        self._emit_orchestrated_telemetry(
            "orchestrated_verdict_final" if response_payload["is_final"] else "orchestrated_verdict_provisional",
            job,
            user_risk_label=response_payload.get("user_risk_label"),
            risk_level=response_payload.get("risk_level"),
            result_fingerprint=fingerprint,
        )
        if response_payload["is_final"]:
            _emit_scan_event(
                scan_id=scan_id,
                scan_payload=response_payload,
                analysis=analysis,
                resolved_urls=resolved_urls,
                input_channel=job.get("input_type", "text"),
                source_channel=job.get("source_channel"),
            )
        return job


    async def _submit_orchestrated_urlscan(self,
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


    async def _submit_orchestrated_urlscan_preview_once(self, job: Dict[str, Any], request: Request) -> Dict[str, Any]:
        primary_final_url = job.get("primary_final_url")
        primary_url_privacy = (
            job.get("primary_url_privacy")
            if isinstance(job.get("primary_url_privacy"), dict)
            else {}
        )
        if primary_final_url and primary_url_privacy.get("preview_allowed") is False:
            job["urlscan"] = {
                "status": "skipped",
                "details": "Preview omis pentru a proteja datele sensibile din URL.",
            }
            preview = job.setdefault("preview", {})
            preview["status"] = "unavailable"
            preview["source"] = None
            preview["image_url"] = None
            preview["screenshot_url"] = None
            preview["report_url"] = None
            preview["reason"] = "privacy_protected_url"
            self._set_orchestrated_stage(job, "urlscan_submitted")
            job = self._persist_orchestrated_job(job)
            self._emit_orchestrated_telemetry("orchestrated_urlscan_privacy_skipped", job)
            return job

        urlscan_state = job.get("urlscan") if isinstance(job.get("urlscan"), dict) else {}
        urlscan_status = str(urlscan_state.get("status") or "").strip().lower()
        if primary_final_url and urlscan_status in {"queued", "", "skipped"}:
            cached_fast_preview = _load_fast_preview_cache(primary_final_url)
            cached_preview = _load_urlscan_preview_cache(primary_final_url)
            if cached_preview:
                job = _apply_urlscan_preview_cache_hit(job, cached_preview)
                if cached_fast_preview:
                    job = _apply_fast_preview_cache_hit(job, cached_fast_preview)
                    self._emit_orchestrated_telemetry("orchestrated_fast_preview_cache_hit", job)
                self._set_orchestrated_stage(job, "urlscan_submitted")
                job = self._persist_orchestrated_job(job)
                self._emit_orchestrated_telemetry("orchestrated_urlscan_preview_cache_hit", job)
                return job

            if cached_fast_preview:
                job = _apply_fast_preview_cache_hit(job, cached_fast_preview)
                self._emit_orchestrated_telemetry("orchestrated_fast_preview_cache_hit", job)

            submit_owner = f"urlscan_{os.urandom(6).hex()}"
            job["urlscan"] = {
                "status": "submitting",
                "submitted_url": str(primary_final_url),
                "submit_owner": submit_owner,
                "submit_started_at": int(time.time()),
                "details": "urlscan submit rezervat pentru instanta curenta.",
            }
            self._set_orchestrated_stage(job, "urlscan_submitting")
            job = self._persist_orchestrated_job(job)
            urlscan_state = job.get("urlscan") if isinstance(job.get("urlscan"), dict) else {}
            if urlscan_state.get("submit_owner") != submit_owner or urlscan_state.get("uuid"):
                self._increment_orchestrated_metric(job, "urlscan_reservation_guard_hits")
                self._emit_orchestrated_telemetry("orchestrated_urlscan_reservation_guard", job)
                return job

            primary_final_url = job.get("primary_final_url")
            options = job.get("sandbox_options") if isinstance(job.get("sandbox_options"), dict) else {}
            urlscan_payload = OrchestratedScanRequest(
                input_type=str(job.get("input_type") or "text"),
                source_channel=str(job.get("source_channel") or "android_native"),
                visibility=options.get("visibility") or URLSCAN_VISIBILITY_DEFAULT,
                country=options.get("country") or URLSCAN_COUNTRY_DEFAULT or None,
                customagent=options.get("customagent") or URLSCAN_CUSTOM_AGENT_DEFAULT or None,
            )
            started_at = time.perf_counter()
            try:
                submitted_urlscan = await self._submit_orchestrated_urlscan(str(primary_final_url), urlscan_payload, request)
            finally:
                self._record_orchestrated_component_duration(job, "urlscan.submit", started_at)
            submitted_urlscan["submit_owner"] = submit_owner
            submitted_urlscan["submit_started_at"] = urlscan_state.get("submit_started_at")
            job["urlscan"] = submitted_urlscan
            preview = job.setdefault("preview", {})
            preview["report_url"] = job["urlscan"].get("report_url")
            preview["final_url"] = primary_final_url
            has_ready_visual = preview.get("status") == "ready" and bool(
                preview.get("image_url") or preview.get("screenshot_url")
            )
            submitted_status = str(submitted_urlscan.get("status") or "").strip().lower()
            if submitted_status in {"error", "timeout", "rate_limited", "skipped"} and not has_ready_visual:
                preview["status"] = "unavailable"
                preview["source"] = None
                preview["screenshot_url"] = None
                preview["image_url"] = None
                preview["reason"] = "preview_unavailable"
                preview["details"] = str(submitted_urlscan.get("details") or submitted_status)
            elif not has_ready_visual:
                preview["status"] = "pending"
                preview["source"] = "urlscan"
                preview["screenshot_url"] = None
                preview["image_url"] = None
                preview["reason"] = "urlscan_pending"
        elif not primary_final_url:
            job["urlscan"] = {"status": "skipped", "details": "Nu exista URL pentru preview."}
        self._set_orchestrated_stage(job, "urlscan_submitted")
        job = self._persist_orchestrated_job(job)
        self._emit_orchestrated_telemetry("orchestrated_urlscan_submitted", job)
        return job


    async def _create_orchestrated_job(
        self,
        payload: OrchestratedScanRequest,
        *,
        artifact_metadata: Optional[Dict[str, Any]] = None,
        client_instance_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        context = self._build_orchestrated_text_context(payload)
        raw_urls = [str(url) for url in (context.get("urls") or []) if str(url).strip()]
        urls, url_privacy = prepare_external_urls(raw_urls)
        reputation_lookup_urls: List[str] = []
        reputation_lookup_url_hashes_by_url: Dict[str, List[str]] = {}
        for raw_url in raw_urls:
            reputation_entry = prepare_reputation_lookup_url(raw_url)
            reputation_url = reputation_entry.get("external_url")
            if isinstance(reputation_url, str) and reputation_url.strip() and reputation_url not in reputation_lookup_urls:
                reputation_lookup_urls.append(reputation_url.strip())
            if isinstance(reputation_url, str) and reputation_url.strip():
                bucket = reputation_lookup_url_hashes_by_url.setdefault(reputation_url.strip(), [])
                for value in reputation_url_hash_variants(raw_url):
                    if value not in bucket:
                        bucket.append(value)
        privacy_by_hash = {entry["input_url_hash"]: entry for entry in url_privacy}
        privacy_by_external_url = {
            str(entry.get("external_url")): entry
            for entry in url_privacy
            if entry.get("external_url")
        }

        privacy_safe_text = str(context["raw_text"])
        for raw_url in raw_urls:
            privacy_entry = privacy_by_hash.get(hashlib.sha256(raw_url.encode("utf-8")).hexdigest(), {})
            safe_url = str(privacy_entry.get("external_url") or "")
            privacy_safe_text = privacy_safe_text.replace(raw_url, safe_url)
        artifact_metadata = artifact_metadata if isinstance(artifact_metadata, dict) else {}
        if isinstance(artifact_metadata.get("pre_redaction_evidence"), dict):
            pre_redaction_evidence = sanitize_pre_redaction_evidence(
                artifact_metadata.get("pre_redaction_evidence"),
                transport="server_extracted",
            )
            pre_redaction_provenance = "server_extracted"
        else:
            pre_redaction_evidence = sanitize_pre_redaction_evidence(payload.pre_redaction_evidence)
            pre_redaction_provenance = (
                "client_roundtrip_unattested"
                if pre_redaction_evidence
                else "direct_input"
            )
        structured_context = pre_redaction_context_text(pre_redaction_evidence)
        knowledge_text = "\n".join(part for part in (privacy_safe_text, structured_context) if part)
        cross_scan_knowledge: Dict[str, Any] = {}
        try:
            from services.brand_registry import detect_claimed_brand, BRAND_REGISTRY
            from services.cross_scan_knowledge import evaluate_cross_scan_knowledge
            from services.invoice_parser import CUI_PATTERN

            cui_match = CUI_PATTERN.search(knowledge_text)
            cui = pre_redaction_primary_cui(pre_redaction_evidence)
            if cui_match:
                cui = cui or "".join(ch for ch in (cui_match.group("label") or cui_match.group("bare") or "") if ch.isdigit())
            claimed_brand = detect_claimed_brand(None, knowledge_text, raw_urls)
            cross_scan_knowledge = evaluate_cross_scan_knowledge(
                text=knowledge_text,
                claimed_brand=claimed_brand,
                cui=cui,
                source_channel=payload.source_channel,
                evidence_provenance=pre_redaction_provenance,
            )
        except Exception:
            cross_scan_knowledge = {}
        redacted_text = redact_pii(privacy_safe_text)
        if not isinstance(artifact_metadata.get("email_evidence_ledger"), dict):
            roundtrip_ledger = sanitize_email_evidence_ledger(payload.email_evidence_ledger)
            if isinstance(roundtrip_ledger, dict):
                artifact_metadata["email_evidence_ledger"] = roundtrip_ledger
                artifact_metadata["email_compound_active"] = bool(
                    EMAIL_COMPOUND_EVIDENCE_ACTIVE and payload.email_compound_active
                )
        artifact_envelope = build_artifact_envelope(
            artifact_type=str(artifact_metadata.get("artifact_type") or context["input_type"]),
            analysis_input_type=str(context["input_type"]),
            source_channel=str(context["source_channel"]),
            redacted_text=redacted_text,
            external_urls=raw_urls,
            qr_payloads=artifact_metadata.get("qr_payloads")
            if isinstance(artifact_metadata.get("qr_payloads"), list)
            else [],
            hidden_url_visibility=bool(artifact_metadata.get("hidden_url_visibility")),
            has_html=bool(artifact_metadata.get("has_html") or payload.html_content),
            email_auth=(
                artifact_metadata.get("email_auth")
                if isinstance(artifact_metadata.get("email_auth"), dict)
                else payload.email_auth
            ),
            compound_evidence=(
                artifact_metadata.get("email_evidence_ledger")
                if isinstance(artifact_metadata.get("email_evidence_ledger"), dict)
                else None
            ),
            extraction_warning=(
                "present" if artifact_metadata.get("extraction_warning") else None
            ),
            pre_redaction_evidence=pre_redaction_evidence,
        )
        action_asset_shadow = build_action_asset_shadow(
            privacy_safe_text,
            source_channel=str(context["source_channel"]),
            pre_redaction_summary=pre_redaction_summary(pre_redaction_evidence),
        )
        payment_case_owner = (
            client_owner_fingerprint(client_instance_id)
            if payload.payment_case_active is True and str(client_instance_id or "").strip()
            else None
        )
        payment_case_facts = (
            build_payment_case_facts_from_scan(
                artifact_type=str(artifact_metadata.get("artifact_type") or context["input_type"]),
                analysis_input_type=str(context["input_type"]),
                raw_text=privacy_safe_text,
                pre_redaction_evidence=pre_redaction_evidence,
                action_asset=action_asset_shadow,
                urls=raw_urls,
            )
            if payment_case_owner
            else None
        )
        scan_id = _new_scan_id("orch")
        extra_fields = dict(context.get("extra_fields") or {})
        for key in ("input_url", "canonical_url"):
            if isinstance(extra_fields.get(key), str):
                extra_fields[key] = prepare_external_url(extra_fields[key]).get("external_url")
        if isinstance(extra_fields.get("buttons"), list):
            sanitized_buttons = []
            for button in extra_fields["buttons"]:
                sanitized_button = dict(button) if isinstance(button, dict) else {}
                button_url = sanitized_button.get("original_url")
                if isinstance(button_url, str):
                    entry = prepare_external_url(button_url)
                    sanitized_button["original_url"] = entry.get("external_url")
                    sanitized_button["url_privacy_action"] = entry.get("action")
                sanitized_buttons.append(sanitized_button)
            extra_fields["buttons"] = sanitized_buttons
        extra_fields.update(
            {
                "resolved_urls": [],
                "orchestrated": True,
                "url_privacy": url_privacy,
                "reputation_lookup_urls": reputation_lookup_urls,
                "reputation_lookup_url_hashes_by_url": reputation_lookup_url_hashes_by_url,
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
            "artifact_envelope": artifact_envelope,
            "action_asset_shadow": action_asset_shadow,
            "payment_case_facts": payment_case_facts,
            "payment_case_owner_fingerprint": payment_case_owner,
            "threat_enrichment": build_threat_enrichment(
                artifact_envelope=artifact_envelope,
                resolved_urls=[],
                provider_summary={},
            ),
            "urls": urls,
            "redacted_text": redacted_text,
            "cross_scan_knowledge": cross_scan_knowledge,
            "analysis": {},
            "resolved_urls": [],
            "primary_final_url": None,
            "primary_url_privacy": (
                privacy_by_external_url.get(urls[0], {})
                if len(urls) == 1
                else {}
            ),
            "claim_verifier_required": False,
            "urlscan": (
                {"status": "queued", "details": "urlscan preview asteapta rezolvarea URL-ului."}
                if urls
                else {"status": "skipped", "details": "Nu exista URL pentru preview."}
            ),
            "preview": {
                "status": "pending" if urls else "unavailable",
                "source": None,
                "image_url": None,
                "screenshot_url": None,
                "report_url": None,
                "final_url": None,
                "reason": "urlscan_pending" if urls else "no_url",
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
        email_ledger = artifact_metadata.get("email_evidence_ledger")
        if isinstance(email_ledger, dict):
            summary = email_ledger.get("summary") if isinstance(email_ledger.get("summary"), dict) else {}
            coverage = email_ledger.get("coverage") if isinstance(email_ledger.get("coverage"), dict) else {}
            job["email_evidence_ledger"] = email_ledger
            job["email_compound_shadow"] = {
                "active": bool(artifact_metadata.get("email_compound_active")),
                "candidate_email_auth_present": bool(artifact_metadata.get("email_auth")),
                "attachment_count": int(summary.get("attachment_count") or 0),
                "candidate_url_count": int(summary.get("candidate_url_count") or 0),
                "candidate_qr_count": int(summary.get("candidate_qr_count") or 0),
                "coverage_status": str(coverage.get("status") or "unknown"),
            }
        if context["input_type"] == "invoice":
            # Invoice verdicts depend on exact payment identifiers. Keep the
            # privacy-safe URL-substituted text only until the invoice fast lane
            # parses IBAN/CUI, then remove it before final persistence.
            job["invoice_analysis_text"] = privacy_safe_text
        if isinstance(payload.email_auth, dict) and payload.email_auth:
            # Header pillar: carried through to the fast lane so the engine factors
            # SPF/DKIM/DMARC + alignment into the score (see scam_atlas email signals).
            job["email_auth"] = payload.email_auth
        job = self._persist_orchestrated_job(job)
        self._emit_orchestrated_telemetry("orchestrated_created", job)
        return job


    async def _run_orchestrated_fast_lane(self, job: Dict[str, Any], request: Request) -> Dict[str, Any]:
        redacted_text = str(job.get("redacted_text") or "")
        urls = job.get("urls") if isinstance(job.get("urls"), list) else []
        resolved_urls = self._timed_orchestrated_component(
            job,
            "fast_lane.resolve_urls",
            lambda: _safe_scan_url_list([str(url) for url in urls if str(url).strip()]),
        )
        resolved_urls = _attach_initial_url_privacy(
            resolved_urls,
            job.get("extra_fields", {}).get("url_privacy")
            if isinstance(job.get("extra_fields"), dict)
            else None,
        )
        resolved_urls = _attach_reputation_lookup_urls(
            resolved_urls,
            job.get("extra_fields", {}).get("reputation_lookup_urls")
            if isinstance(job.get("extra_fields"), dict)
            else None,
        )
        resolved_urls = _attach_reputation_lookup_hashes(
            resolved_urls,
            job.get("extra_fields", {}).get("reputation_lookup_url_hashes_by_url")
            if isinstance(job.get("extra_fields"), dict)
            else None,
        )
        job["resolved_urls"] = resolved_urls
        job.setdefault("extra_fields", {})["resolved_urls"] = resolved_urls
        self._set_orchestrated_stage(job, "resolved")
        self._emit_orchestrated_telemetry("orchestrated_stage_resolved", job, fast_lane=True)

        # WHOIS/RDAP + SSL: free deterministic signals in parallel with reputation intel
        domain_signals: Dict[str, Any] = {}
        primary_final_host = None
        primary_entry = _select_primary_resolved_url(resolved_urls, {"claimed_brand": "Nespecificat"})
        if primary_entry:
            primary_final_host = (primary_entry.get("final_hostname") or
                                  urllib.parse.urlparse(str(primary_entry.get("final_url") or "")).hostname or
                                  None)
        if primary_final_host:
            try:
                domain_check = await check_domain_ssl_parallel(primary_final_host)
                domain_signals = domain_risk_from_signals(
                    domain_check.get("ssl", {}),
                    domain_check.get("rdap", {}),
                    primary_final_host,
                )
            except Exception as exc:
                domain_signals = {"signal_score": 0, "flags": ["error"], "error": str(exc)}
            # DNS liveness check (NXDOMAIN = domeniu mort, posibil phishing luat jos)
            try:
                from services.dns_reputation import check_dns_reputation
                dns_rep = await asyncio.to_thread(check_dns_reputation, primary_final_host)
                if dns_rep.status in ("nxdomain", "blocked"):
                    domain_signals["unreachable"] = True
                    domain_signals["dns_nxdomain"] = True
                    domain_signals["dns_status"] = dns_rep.status
                    domain_signals["dns_reason_codes"] = dns_rep.reason_codes
            except Exception:
                pass

        threat_intel = self._timed_orchestrated_component(
            job,
            "fast_lane.reputation",
            lambda: _gather_external_intel_safe(
                resolved_urls,
                include_phishing_database=True,
                include_urlhaus=True,
                persist_partial=False,
            ),
        )
        summary = self._timed_orchestrated_component(
            job,
            "fast_lane.reputation_summary",
            lambda: _external_intel_summary_from_threat_intel(threat_intel),
        )
        job["threat_intel"] = threat_intel
        job["threat_enrichment"] = build_threat_enrichment(
            artifact_envelope=job.get("artifact_envelope")
            if isinstance(job.get("artifact_envelope"), dict)
            else {},
            resolved_urls=resolved_urls,
            provider_summary=summary,
        )

        if _has_bad_provider_verdict(summary):
            analysis = self._timed_orchestrated_component(
                job,
                "fast_lane.provider_context_analysis",
                lambda: _provider_reputation_context_analysis(redacted_text, resolved_urls, summary),
            )
            analysis.setdefault("evidence", {})["source_channel"] = job.get("source_channel")
            self._timed_orchestrated_component(
                job,
                "fast_lane.local_semantic_review",
                lambda: _enrich_local_semantic_review(redacted_text, analysis),
            )
            _attach_offer_claim_verification(
                analysis,
                _skipped_offer_claim_payload("Claim web check skipped because hard reputation evidence is already decisive."),
            )
            claim_required = False
        else:
            analysis = self._timed_orchestrated_component(
                job,
                "fast_lane.engine_analysis",
                lambda: _analyze_with_reputation(
                    redacted_text,
                    resolved_urls,
                    email_context=job.get("email_auth") if isinstance(job.get("email_auth"), dict) else None,
                    fast_reputation=True,
                    threat_intel_override=threat_intel,
                    allow_deep_fallback=False,
                ),
            )
            analysis.setdefault("evidence", {})["source_channel"] = job.get("source_channel")
            self._timed_orchestrated_component(
                job,
                "fast_lane.local_semantic_review",
                lambda: _enrich_local_semantic_review(redacted_text, analysis),
            )
            claim_required = self._timed_orchestrated_component(
                job,
                "fast_lane.claim_required_check",
                lambda: _claim_verifier_required(analysis),
            )
            _attach_offer_claim_verification(
                analysis,
                _skipped_offer_claim_payload(
                    "Claim web check deferred by fast lane; verdict uses provider reputation, identity, atlas and local Tier1."
                ),
            )

        if domain_signals:
            analysis.setdefault("evidence", {})["domain_signals"] = domain_signals
            signal_score = domain_signals.get("signal_score", 0)
            existing_score = analysis.get("risk_score", 0)
            if isinstance(existing_score, (int, float)):
                analysis["risk_score"] = min(max(int(existing_score) + signal_score, 0), 100)
            if domain_signals.get("rdap_404"):
                analysis.setdefault("reasons", []).append("Domeniul nu exista in registru (RDAP 404)")
            if domain_signals.get("domain_young"):
                analysis.setdefault("reasons", []).append("Domeniul este foarte tanar (sub 30 de zile)")
            if domain_signals.get("ssl_valid") is False:
                analysis.setdefault("reasons", []).append("Certificatul SSL este invalid sau auto-semnat")
            signal_flags = list(domain_signals.get("flags") or [])
            if signal_flags:
                existing_rag = analysis.get("rag_signals")
                if isinstance(existing_rag, list):
                    existing_rag.extend(signal_flags)
                else:
                    analysis["rag_signals"] = signal_flags

        primary_entry = self._timed_orchestrated_component(
            job,
            "fast_lane.primary_url_picker",
            lambda: _select_primary_resolved_url(resolved_urls, analysis),
        )

        job["analysis"] = analysis
        job["claim_verifier_required"] = claim_required
        primary_final_url = _apply_primary_resolved_url(job, primary_entry)
        if primary_final_url:
            job = _apply_best_preview_cache_hit(job, primary_final_url)
        next_stage = "analysis_ready" if _has_bad_provider_verdict(summary) else "semantic_ready"
        self._set_orchestrated_stage(job, next_stage)
        job = self._timed_orchestrated_component(
            job,
            f"fast_lane.persist_{next_stage}",
            lambda: self._persist_orchestrated_job(job),
        )
        self._emit_orchestrated_telemetry(
            f"orchestrated_stage_{next_stage}",
            job,
            fast_lane=True,
            claim_required=claim_required,
            decisive_provider=next_stage == "analysis_ready",
        )
        if ORCHESTRATED_EARLY_VERDICT and next_stage == "semantic_ready":
            # Publish the provisional verdict from the local semantic pillar
            # (status=done) before any cloud-LLM stage runs. The first poll then
            # returns a verdict in fast-lane time even when LLMs are slow; the
            # semantic/claim enrichment and urlscan can only refine or raise it.
            job = await self._finalize_orchestrated_job_if_ready(job, request)
        return job


    async def _run_orchestrated_invoice_fast_lane(self, job: Dict[str, Any], request: Request) -> Dict[str, Any]:
        from services.invoice_orchestrator import evaluate_invoice_verdict, scan_invoice
        from services.verdict_gate import verdict as reduce_verdict

        redacted_text = str(job.get("redacted_text") or "")
        invoice_analysis_text = str(job.get("invoice_analysis_text") or redacted_text)
        urls = job.get("urls") if isinstance(job.get("urls"), list) else []
        resolved_urls: List[Dict[str, Any]] = []
        external_intel_summary: Dict[str, Any] = {}
        if urls:
            resolved_urls = self._timed_orchestrated_component(
                job,
                "invoice_fast_lane.resolve_urls",
                lambda: _safe_scan_url_list([str(url) for url in urls if str(url).strip()]),
            )
            resolved_urls = _attach_initial_url_privacy(
                resolved_urls,
                job.get("extra_fields", {}).get("url_privacy")
                if isinstance(job.get("extra_fields"), dict)
                else None,
            )
            resolved_urls = _attach_reputation_lookup_urls(
                resolved_urls,
                job.get("extra_fields", {}).get("reputation_lookup_urls")
                if isinstance(job.get("extra_fields"), dict)
                else None,
            )
            resolved_urls = _attach_reputation_lookup_hashes(
                resolved_urls,
                job.get("extra_fields", {}).get("reputation_lookup_url_hashes_by_url")
                if isinstance(job.get("extra_fields"), dict)
                else None,
            )
            job["resolved_urls"] = resolved_urls
            job.setdefault("extra_fields", {})["resolved_urls"] = resolved_urls
            primary_entry = _select_primary_resolved_url(resolved_urls, {"claimed_brand": "Nespecificat"})
            primary_final_url = _apply_primary_resolved_url(job, primary_entry)
            if primary_final_url:
                job = _apply_best_preview_cache_hit(job, primary_final_url)
            threat_intel = self._timed_orchestrated_component(
                job,
                "invoice_fast_lane.reputation",
                lambda: _gather_external_intel_safe(
                    resolved_urls,
                    include_phishing_database=True,
                    include_urlhaus=True,
                    persist_partial=False,
                ),
            )
            external_intel_summary = self._timed_orchestrated_component(
                job,
                "invoice_fast_lane.reputation_summary",
                lambda: _external_intel_summary_from_threat_intel(threat_intel),
            )
            job["threat_intel"] = threat_intel
        job["threat_enrichment"] = build_threat_enrichment(
            artifact_envelope=job.get("artifact_envelope")
            if isinstance(job.get("artifact_envelope"), dict)
            else {},
            resolved_urls=resolved_urls,
            provider_summary=external_intel_summary,
        )
        self._set_orchestrated_stage(job, "invoice_parse")
        try:
            result = await self._timed_orchestrated_component(
                job,
                "invoice_fast_lane.scan_invoice",
                lambda: scan_invoice(invoice_analysis_text, links=urls),
            )
        except Exception as exc:
            result = None
            self._emit_orchestrated_telemetry("orchestrated_invoice_error", job, error=str(exc))

        # Build evidence bundle sections for the existing verdict_gate.
        readiness = result.readiness if result else None
        brand_match = result.brand_match if result else None
        fields = result.fields if result else None
        coherence = result.coherence if result else None
        anaf = result.anaf_cui_check if result else None
        iban_result = result.iban_valid if result else None

        readiness_blocks_safe = (readiness and readiness.blocks_safe_verdict) or False
        impersonation_risk = (brand_match and brand_match.impersonation_risk) or False
        cui_matches = (brand_match and brand_match.cui_matches) or False
        iban_matches = (brand_match and brand_match.iban_matches) or False
        claimed_brand = (result.brand if result else None) or "Nespecificat"

        # Provider section: ANAF + IBAN + coherence as evidence sources.
        anaf_status = "clean"
        anaf_reasons = []
        if anaf:
            if anaf.get("checked") is False:
                anaf_status = "unknown"
                anaf_reasons.append("ANAF temporar indisponibil")
            elif not anaf.get("exists"):
                anaf_status = "unknown"
                anaf_reasons.append("CUI negăsit în registru")
            elif not anaf.get("activ"):
                anaf_status = "malicious"
                anaf_reasons.append("Firmă inactivă")

        iban_status = "clean"
        iban_reasons = []
        if iban_result:
            if not iban_result.valid_structure:
                iban_status = "suspicious"
                iban_reasons.append("IBAN invalid MOD-97")

        coherence_status = "clean"
        coherence_reasons = []
        if coherence:
            if not coherence.totals_match:
                coherence_status = "suspicious"
                coherence_reasons.append("Totalul nu corespunde cu subtotal+TVA")
            if not coherence.dates_plausible:
                coherence_status = "suspicious"
                coherence_reasons.append("Date incoerente (scadența înaintea emiterii)")

        provider_section = {
            "verdict": "malicious" if anaf_status == "malicious" else "suspicious" if "suspicious" in (iban_status, coherence_status) else "clean",
            "anaf": {"status": anaf_status, "verdict": anaf_status, "reasons": anaf_reasons, "completeness": anaf is not None},
            "iban": {"status": iban_status, "verdict": iban_status, "reasons": iban_reasons, "completeness": iban_result is not None},
            "coherence": {"status": coherence_status, "verdict": coherence_status, "reasons": coherence_reasons, "completeness": coherence is not None},
        }
        if anaf_reasons:
            provider_section.setdefault("reasons", []).extend(anaf_reasons)

        # Identity section: brand match status.
        if impersonation_risk:
            identity_status = "lookalike"
            identity_reason = "CUI/IBAN nealiniat cu brandul declarat"
        elif cui_matches and iban_matches:
            identity_status = "official"
            identity_reason = "Brand confirmat prin CUI și IBAN"
        elif claimed_brand != "Nespecificat":
            identity_status = "unknown"
            identity_reason = "Brand declarat dar neverificat complet"
        else:
            identity_status = "unknown"
            identity_reason = "Brand nedeclarat"

        identity_section = {
            "status": identity_status,
            "claimed_brand": claimed_brand,
            "domain_reputation": "established" if (brand_match and brand_match.domain_matches) else "unknown",
            "reason": identity_reason,
            "completeness": brand_match is not None,
        }

        # Request section: invoices ask for payment transfer.
        request_sensitive = "transfer"
        request_section = {
            "sensitive": request_sensitive,
            "channel": "invoice",
            "completeness": True,
        }

        # Semantic review: coherence + readiness.
        semantic_risk = "low"
        semantic_reasons = []
        if impersonation_risk:
            semantic_risk = "high"
            semantic_reasons.append("Impersonation risk detected")
        if readiness_blocks_safe:
            semantic_risk = "medium"
            semantic_reasons.append("Date insuficiente")
        if coherence and not coherence.all_ok:
            semantic_reasons.append("Document incoherent")

        semantic_section = {
            "status": "done",
            "risk_class": semantic_risk,
            "reasons": semantic_reasons,
            "completeness": readiness is not None,
        }

        # Resolution: invoices don't need URL resolution.
        resolution_section = {
            "status": "not_required",
            "completeness": True,
        }

        bundle = {
            "schema": "sigurscan_evidence_bundle_v2",
            "input": {
                "type": "invoice",
                "redacted_text": str(redacted_text or "")[:4000],
            },
            "resolution": resolution_section,
            "providers": provider_section,
            "identity": identity_section,
            "request": request_section,
            "semantic_review": semantic_section,
            "context": {
                "urgency": bool(re.search(r"\b(urgent|azi|acum|24\s*de\s*ore|ultima|expir[ăa])\b", str(redacted_text or ""), re.IGNORECASE)),
                "passive_payment": bool(re.search(r"\b(plata abonamentului|se va efectua automat plata|factur[ăa])\b", str(redacted_text or ""), re.IGNORECASE)),
                "apk_or_remote_mention": False,
            },
        }
        import hashlib, json
        canonical = json.dumps(bundle, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        bundle["evidence_hash"] = "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()

        invoice_truth = None
        try:
            from services.invoice_orchestrator import evaluate_invoice_verdict

            invoice_gate = evaluate_invoice_verdict(
                result,
                redacted_text,
                source_channel=job.get("source_channel"),
            )
            bundle = invoice_gate["bundle"]
            gate_result = invoice_gate["gate"]
            invoice_truth = invoice_gate.get("invoice_truth")
            semantic_section = bundle.get("semantic_review") or semantic_section
        except Exception:
            gate_result = reduce_verdict(bundle)
        if _has_bad_provider_verdict(external_intel_summary) and str(gate_result.get("label") or "").upper() != "DANGEROUS":
            gate_result = {
                "label": "DANGEROUS",
                "risk_level": "high",
                "risk_score": 90,
                "reason_codes": ["provider_malicious"],
                "confidence": 95,
                "is_final": True,
            }
            if isinstance(invoice_truth, dict):
                invoice_truth = {
                    **invoice_truth,
                    "verdict": "NU_PLATI",
                    "decision_status": "DO_NOT_PAY",
                    "safe_to_pay": False,
                    "primary_reason_code": "provider_malicious",
                    "display": {
                        "title": "Nu plăti",
                        "message": "Un provider de securitate a raportat risc ridicat. Nu continua plata.",
                        "tone": "danger",
                    },
                    "hard_conflicts": list(invoice_truth.get("hard_conflicts") or [])
                    + [{"code": "PROVIDER_MALICIOUS", "label": "Provider de securitate a raportat risc"}],
                }
        invoice_client_payment_destination = _invoice_payment_destination_for_client(
            result,
            {"bundle": bundle, "gate": gate_result},
        )

        # Build analysis dict compatible with the existing contract.
        analysis: Dict[str, Any] = {
            "risk_score": 0,
            "risk_level": "low",
            "detected_family": "Factura",
            "detected_family_id": "invoice",
            "claimed_brand": claimed_brand,
            "reasons": [],
            "safe_actions": [],
            "evidence": {
                "source_channel": job.get("source_channel"),
                "invoice": {
                    "fields": {
                        "emitent": fields.emitent if fields else None,
                        "cui": fields.cui if fields else None,
                        "iban": fields.iban if fields else None,
                        "all_ibans": list(getattr(fields, "all_ibans", []) or []) if fields else [],
                        "payment_beneficiary": getattr(fields, "payment_beneficiary", None) if fields else None,
                        "nr_factura": fields.nr_factura if fields else None,
                        "data_emitere": fields.data_emitere if fields else None,
                        "scadenta": fields.scadenta if fields else None,
                        "subtotal": fields.subtotal if fields else None,
                        "tva": fields.tva if fields else None,
                        "total": fields.total if fields else None,
                    },
                    "brand_match": {
                        "claimed_brand": claimed_brand,
                        "domain_matches": brand_match.domain_matches if brand_match else None,
                        "cui_matches": cui_matches,
                        "iban_matches": iban_matches,
                        "impersonation_risk": impersonation_risk,
                    },
                    "payment_destination": invoice_client_payment_destination,
                    "beneficiary_name_check": getattr(result, "beneficiary_name_check", None) if result else None,
                    "anaf": {
                        "checked": anaf.get("checked"),
                        "exists": anaf.get("exists"),
                        "denumire": anaf.get("denumire"),
                        "activ": anaf.get("activ"),
                        "platitor_tva": anaf.get("platitor_tva"),
                        "enrolled_efactura": anaf.get("enrolled_efactura"),
                    } if anaf else None,
                    "coherence": {
                        "totals_match": coherence.totals_match if coherence else None,
                        "tva_rate_plausible": coherence.tva_rate_plausible if coherence else None,
                        "dates_plausible": coherence.dates_plausible if coherence else None,
                        "all_ok": coherence.all_ok if coherence else None,
                    },
                    "iban": {
                        "valid": iban_result.valid_structure,
                        "bank": iban_result.bank_name,
                        "is_trezorerie": iban_result.is_trezorerie,
                    } if iban_result else None,
                    "readiness": {
                        "state": readiness.state.value if readiness else None,
                        "blocks_safe_verdict": readiness_blocks_safe,
                    },
                    "fraud_flags": list(getattr(result, "fraud_flags", []) or []) if result else [],
                    "warnings": list(result.warnings) if result else [],
                    "verdict_gate": gate_result,
                    "invoice_truth": invoice_truth,
                },
            },
        }
        if external_intel_summary:
            analysis.setdefault("evidence", {})["external_intel_summary"] = external_intel_summary

        provider_gate = {
            "version": "verdict_gate_v2",
            "decision_contract": "sigurscan_evidence_bundle_v2",
            "risk_level": gate_result.get("risk_level"),
            "risk_score": gate_result.get("risk_score"),
            "reason": ", ".join(gate_result.get("reason_codes") or []),
            "label": gate_result.get("label"),
            "detected_family_id": "invoice",
            "detected_family": "Factură",
        }
        evidence = analysis.setdefault("evidence", {})
        evidence["provider_gate"] = provider_gate
        evidence["decision_bundle"] = bundle
        evidence["verdict_gate"] = gate_result
        evidence["semantic_review"] = semantic_section

        label = str(gate_result.get("label") or "UNVERIFIED").upper()
        if isinstance(invoice_truth, dict):
            display = invoice_truth.get("display") if isinstance(invoice_truth.get("display"), dict) else {}
            next_action = invoice_truth.get("next_action") if isinstance(invoice_truth.get("next_action"), dict) else {}
            hard_conflicts = [
                str(item.get("label") or item.get("code") or "").strip()
                for item in (invoice_truth.get("hard_conflicts") or [])
                if isinstance(item, dict) and str(item.get("label") or item.get("code") or "").strip()
            ]
            if label == "SAFE" and str(invoice_truth.get("verdict") or "") == "VERIFY_BEFORE_PAYING":
                reasons = [
                    "Firma și contul de plată sunt confirmate în verificările disponibile. "
                    "Nu putem confirma automat că această factură îți este destinată; "
                    "verifică suma și numărul facturii în portalul furnizorului."
                ]
                safe_actions = ["Verifică suma și numărul facturii în portalul furnizorului înainte de plată."]
            else:
                reasons = [str(display.get("message") or "Verifică factura înainte de plată.")]
                if hard_conflicts:
                    reasons.extend(hard_conflicts[:3])
                safe_actions = [str(next_action.get("title") or "Verifică pe canalul oficial înainte de plată.")]
        else:
            reasons = {
                "SAFE": ["Datele facturii sunt coerente și corespund unui emitent cunoscut."],
                "SUSPECT": ["Nu avem dovezi suficiente pentru a confirma factura ca sigură; verifică pe canalul oficial."],
                "DANGEROUS": ["Dovezile indică risc ridicat: nu efectua plata și nu furniza date."],
                "UNVERIFIED": ["Scanarea nu a găsit semnale de risc dar nici proveniență pozitivă."],
            }.get(label, ["Verifică pe canalul oficial înainte de plată."])
            safe_actions = {
                "SAFE": ["Poți efectua plata dacă recunoști emitentul și suma."],
                "SUSPECT": ["Verifică factura în aplicația/site-ul emitentului, nu din linkul din document."],
                "DANGEROUS": ["Nu plăti.", "Nu introduce date personale sau bancare.", "Raportează incidentul."],
                "UNVERIFIED": ["Fără proveniență confirmată; acționează cu prudență."],
            }.get(label, ["Așteaptă finalizarea scanării."])

        analysis["risk_level"] = gate_result.get("risk_level")
        analysis["risk_score"] = gate_result.get("risk_score")
        analysis["user_risk_label"] = label
        analysis["reasons"] = reasons
        analysis["safe_actions"] = safe_actions

        job["analysis"] = analysis
        job.pop("invoice_analysis_text", None)
        job["claim_verifier_required"] = False
        self._set_orchestrated_stage(job, "analysis_ready")
        job = self._persist_orchestrated_job(job)
        self._emit_orchestrated_telemetry("orchestrated_stage_analysis_ready", job, invoice_fast_lane=True)
        return job


    async def _run_orchestrated_offer_fast_lane(self, job: Dict[str, Any], request: Request) -> Dict[str, Any]:
        """Ruta ofertă: scan_offer (gate unic) → contract analysis. Ruta factură neatinsă."""
        from services.invoice_orchestrator import scan_offer
        from services.offer_evidence_gate_mapper import evaluate_offer_verdict
        from services.verdict_gate import verdict as reduce_verdict

        redacted_text = str(job.get("redacted_text") or "")
        urls = job.get("urls") if isinstance(job.get("urls"), list) else []
        cross_scan_knowledge = job.get("cross_scan_knowledge") if isinstance(job.get("cross_scan_knowledge"), dict) else {}
        self._set_orchestrated_stage(job, "offer_parse")
        try:
            result = await self._timed_orchestrated_component(
                job,
                "offer_fast_lane.scan_offer",
                lambda: scan_offer(redacted_text, links=urls),
            )
        except Exception as exc:
            result = None
            self._emit_orchestrated_telemetry("orchestrated_offer_error", job, error=str(exc))

        if result is not None:
            fields = result.fields
            entity = result.entity
            coherence = result.coherence
            if cross_scan_knowledge:
                out = evaluate_offer_verdict(
                    fields,
                    signals=result.signals,
                    entity=entity,
                    coherence=coherence,
                    family_code=result.family_code,
                    family_confidence=result.family_confidence,
                    readiness=result.readiness,
                    redacted_text=redacted_text,
                    registry_results=result.registry,
                    cross_scan_knowledge=cross_scan_knowledge,
                )
                gate_result = out["gate"]
                bundle = out["bundle"]
            else:
                gate_result = result.gate
                bundle = result.bundle
            claimed_brand = (entity.claimed_brand if entity else None) or "Nespecificat"
            family_id = result.family_code
            family_name = result.family_name
            warnings = list(result.warnings)
            offer_signals = list(result.signals)
        else:
            # Degradare grațioasă: niciun verdict hard, doar provizoriu.
            bundle = {
                "schema": "sigurscan_evidence_bundle_v2",
                "input": {"type": "offer"},
                "resolution": {"status": "failed", "completeness": False},
                "providers": {"verdict": "pending", "completeness": False},
                "identity": {"status": "unknown", "completeness": False},
                "request": {"sensitive": "none", "channel": "unknown", "completeness": False},
                "semantic_review": {"status": "pending", "completeness": False},
            }
            gate_result = reduce_verdict(bundle)
            fields = None
            entity = None
            coherence = None
            claimed_brand = "Nespecificat"
            family_id = "OP-00"
            family_name = "Necategorizat"
            warnings = ["Nu am putut analiza oferta."]
            offer_signals = []

        label = str(gate_result.get("label") or "UNVERIFIED").upper()
        reasons = {
            "SAFE": ["Nu am găsit semnale clare de fraudă."],
            "SUSPECT": ["Verifică pe canalul oficial înainte să plătești."],
            "DANGEROUS": ["Nu plăti. Datele ofertei nu se aliniază sau metoda de plată e riscantă."],
            "UNVERIFIED": ["Scanarea nu a găsit semnale de risc dar nici proveniență pozitivă."],
        }.get(label, ["Verifică pe canalul oficial înainte de plată."])
        safe_actions = {
            "SAFE": ["Poți continua dacă recunoști vânzătorul și datele de plată."],
            "SUSPECT": [
                "Verifică emitentul pe canalul oficial, nu din linkul din ofertă.",
                "Nu trimite avans înainte de a confirma.",
            ],
            "DANGEROUS": [
                "Nu plăti.",
                "Nu trimite copie după buletin/CI sau date de card.",
                "Raportează la DNSC (1911).",
            ],
            "UNVERIFIED": ["Fără proveniență confirmată; acționează cu prudență."],
        }.get(label, ["Așteaptă finalizarea scanării."])

        offer_fields_payload = {
            "issuer_name": (fields.issuer_name or fields.emitent) if fields else None,
            "issuer_cui": fields.cui if fields else None,
            "iban": fields.iban if fields else None,
            "payment_beneficiary": fields.payment_beneficiary if fields else None,
            "total_amount": fields.total if fields else None,
            "currency": fields.currency if fields else "RON",
            "payment_method": fields.payment_method if fields else None,
            "document_type": fields.document_type if fields else "offer",
            "family": family_id,
        }

        analysis: Dict[str, Any] = {
            "risk_score": gate_result.get("risk_score"),
            "risk_level": gate_result.get("risk_level"),
            "detected_family": family_name,
            "detected_family_id": family_id,
            "claimed_brand": claimed_brand,
            "reasons": reasons,
            "safe_actions": safe_actions,
            "evidence": {
                "source_channel": job.get("source_channel"),
                "offer": {
                    "fields": offer_fields_payload,
                    "signals": offer_signals,
                    "entity": {
                        "cui_checked": entity.cui_checked,
                        "cui_exists": entity.cui_exists,
                        "cui_active": entity.cui_active,
                        "denumire": entity.denumire,
                        "name_matches": entity.name_matches,
                        "brand_impersonation": entity.brand_impersonation,
                    } if entity else None,
                    "coherence": {"all_ok": coherence.all_ok} if coherence else None,
                    "warnings": warnings,
                    "verdict_gate": gate_result,
                },
                "provider_gate": {
                    "version": "verdict_gate_v2",
                    "decision_contract": "sigurscan_evidence_bundle_v2",
                    "risk_level": gate_result.get("risk_level"),
                    "risk_score": gate_result.get("risk_score"),
                    "reason": ", ".join(gate_result.get("reason_codes") or []),
                    "label": gate_result.get("label"),
                    "detected_family_id": family_id,
                    "detected_family": family_name,
                },
                "decision_bundle": bundle,
                "verdict_gate": gate_result,
                "semantic_review": bundle.get("semantic_review", {"status": "done", "completeness": True}),
            },
        }

        # Strat educativ „Ce spune legea" (PR5): rulează DUPĂ gate, doar informativ,
        # nu modifică niciodată verdictul. Carduri verbatim din data/legal_kb.json.
        from services.legal_layer import legal_cards_for

        analysis["legal"] = legal_cards_for(
            signals=offer_signals,
            family_code=family_id,
            document_type=(fields.document_type if fields else None),
        )

        # PR-8: plan de acțiune (TriageScreen) — atașat post-gate DOAR pentru verdicte
        # de risc, preventiv (impacts=["none"], scanarea nu știe ce a făcut userul).
        # Clientul poate re-cere /v1/legal/action-plan cu impacts reale. NU schimbă verdictul.
        gate_label = str(gate_result.get("label") or "").upper()
        if gate_label in {"DANGEROUS", "SUSPECT"}:
            from services.legal_action_plan import build_action_plan

            plan_target = None
            if fields and fields.iban:
                plan_target = {"type": "iban", "value_redacted": "[redactat]"}
            analysis["action_plan"] = build_action_plan(
                verdict=gate_label,
                family=family_id,
                impacts=["none"],
                target=plan_target,
                document_type=(fields.document_type if fields else None),
            )

        job["analysis"] = analysis
        job["claim_verifier_required"] = False
        # PR6: web-confirm async pentru oferte — rulează DUPĂ primul verdict (nu îl
        # blochează). Marcat „pending" doar când are sens și providerul e configurat.
        web_claim_warranted = (
            family_id != "OP-00"
            or (claimed_brand and claimed_brand != "Nespecificat")
            or bool(fields and fields.platform_name)
        )
        if web_claim_warranted and _env_present("GEMINI_API_KEY") and not PRIVACY_SAFE_MODE:
            job["offer_web_claim"] = {"status": "pending"}
        else:
            job["offer_web_claim"] = {"status": "skipped"}
        self._set_orchestrated_stage(job, "analysis_ready")
        job = self._persist_orchestrated_job(job)
        self._emit_orchestrated_telemetry("orchestrated_stage_analysis_ready", job, offer_fast_lane=True)
        return job


    def _mark_orchestrated_job_exception(self, job: Dict[str, Any], exc: Exception) -> Dict[str, Any]:
        error_type = type(exc).__name__
        error_message = str(exc)[:300]
        redacted_text = str(job.get("redacted_text") or "")
        input_type = str(job.get("input_type") or "text").strip().lower() or "text"
        bundle = {
            "schema": "sigurscan_evidence_bundle_v2",
            "input": {"type": input_type},
            "resolution": {"status": "failed", "completeness": False},
            "providers": {"verdict": "error", "completeness": False},
            "identity": {"status": "unknown", "completeness": False},
            "request": {"sensitive": "unknown", "channel": job.get("source_channel") or "unknown", "completeness": False},
            "semantic_review": {"status": "error", "completeness": False},
        }
        gate_result = reduce_verdict(bundle)
        analysis: Dict[str, Any] = {
            "risk_score": gate_result.get("risk_score", 25),
            "risk_level": gate_result.get("risk_level", "info"),
            "detected_family": "Verificare incompletă",
            "detected_family_id": "provider-gate-pending",
            "claimed_brand": "Nespecificat",
            "reasons": ["Scanarea nu a putut verifica complet mesajul; verifică pe canalul oficial înainte de acțiune."],
            "safe_actions": ["Nu introduce date sensibile până nu confirmi în aplicația sau site-ul oficial."],
            "evidence": {
                "decision_bundle": bundle,
                "verdict_gate": gate_result,
                "orchestration_error": {
                    "error_type": error_type,
                    "error": error_message,
                    "stage": str(job.get("pipeline_stage") or "unknown"),
                },
            },
        }
        _apply_decision_contract_result(analysis, bundle, gate_result, {})
        analysis["reasons"] = ["Scanarea nu a putut verifica complet mesajul; verifică pe canalul oficial înainte de acțiune."]
        analysis["safe_actions"] = ["Nu introduce date sensibile până nu confirmi în aplicația sau site-ul oficial."]
        analysis.setdefault("evidence", {})["orchestration_error"] = {
            "error_type": error_type,
            "error": error_message,
            "stage": str(job.get("pipeline_stage") or "unknown"),
        }
        job["analysis"] = analysis
        job["claim_verifier_required"] = False
        job["ai_explanation_pending"] = False
        urlscan_state = job.get("urlscan") if isinstance(job.get("urlscan"), dict) else {}
        if str(urlscan_state.get("status") or "").lower() not in {"finished", "clean", "malicious", "error", "skipped"}:
            job["urlscan"] = {
                **urlscan_state,
                "status": "error",
                "details": "Scanarea sandbox a fost oprită după o eroare internă controlată.",
            }
        preview = job.setdefault("preview", {})
        if not (preview.get("image_url") or preview.get("screenshot_url")):
            preview.update(
                {
                    "status": "unavailable",
                    "source": None,
                    "image_url": None,
                    "screenshot_url": None,
                    "report_url": preview.get("report_url"),
                    "reason": "orchestrator_error",
                    "details": "Preview-ul nu este disponibil pentru această scanare.",
                }
            )
        self._set_orchestrated_stage(job, "done")
        ai_explanation = generate_fallback_explanation(redacted_text, analysis)
        response_payload = _build_scan_response(
            "scan",
            analysis,
            redacted_text,
            ai_explanation,
            scan_id=job.get("scan_id"),
            extra_fields=job.get("extra_fields") if isinstance(job.get("extra_fields"), dict) else {},
        )
        response_payload.setdefault("evidence", {}).setdefault("orchestration", {})
        response_payload["evidence"]["orchestration"] = {
            "pillars": self._build_orchestrated_pillars(job),
            "preview": job.get("preview", {}),
        }
        response_payload["is_final"] = True
        job["result"] = response_payload
        job["result_fingerprint"] = self._orchestrated_result_fingerprint(
            job,
            analysis,
            self._build_orchestrated_pillars(job),
            job.get("resolved_urls") if isinstance(job.get("resolved_urls"), list) else [],
        )
        job["status"] = "complete"
        self._emit_orchestrated_telemetry("orchestrated_unhandled_exception_finalized", job, error_type=error_type)
        if response_payload.get("is_final"):
            try:
                _emit_scan_event(
                    scan_id=str(job.get("scan_id") or ""),
                    scan_payload=response_payload,
                    input_channel=job.get("input_type", "text"),
                    source_channel=job.get("source_channel"),
                )
            except Exception:
                pass
        return self._persist_orchestrated_job(job)


    async def _refresh_orchestrated_job(self, job: Dict[str, Any], request: Request) -> Dict[str, Any]:
        try:
            return await self._refresh_orchestrated_job_impl(job, request)
        except Exception as exc:
            return self._mark_orchestrated_job_exception(job, exc)


    async def _refresh_orchestrated_job_impl(self, job: Dict[str, Any], request: Request) -> Dict[str, Any]:
        self._increment_orchestrated_metric(job, "poll_count")
        stage = str(job.get("pipeline_stage") or "queued").strip().lower()
        self._emit_orchestrated_telemetry("orchestrated_poll", job, stage=stage)
        existing_result = job.get("result") if isinstance(job.get("result"), dict) else None
        # PR6: oferta cu verdict deja publicat + web-claim în așteptare → enrichment
        # acum (poll ulterior), fără să fi blocat vreodată primul verdict.
        if (
            existing_result is not None
            and str(job.get("input_type") or "").strip().lower() == "offer"
            and isinstance(job.get("offer_web_claim"), dict)
            and job["offer_web_claim"].get("status") == "pending"
        ):
            job = await _run_offer_web_claim_enrichment(job)
            return await self._finalize_orchestrated_job_if_ready(job, request)
        if not existing_result and self._orchestrated_required_pillars_timed_out(job):
            job = _mark_required_pillars_timeout(job)
            return await self._finalize_orchestrated_job_if_ready(job, request)

        if stage == "queued":
            job_input_type = str(job.get("input_type") or "").strip().lower()
            if job_input_type == "invoice":
                return await self._run_orchestrated_invoice_fast_lane(job, request)
            if job_input_type == "offer":
                return await self._run_orchestrated_offer_fast_lane(job, request)
            return await self._run_orchestrated_fast_lane(job, request)

        if stage == "resolved":
            redacted_text = str(job.get("redacted_text") or "")
            resolved_urls = job.get("resolved_urls") if isinstance(job.get("resolved_urls"), list) else []
            threat_intel = _gather_external_intel_safe(
                resolved_urls,
                include_phishing_database=True,
                include_urlhaus=False,
                persist_partial=False,
            )
            summary = _external_intel_summary_from_threat_intel(threat_intel)
            primary_entry = _select_primary_resolved_url(resolved_urls, {"claimed_brand": "Nespecificat"})
            job["threat_intel"] = threat_intel
            _apply_primary_resolved_url(job, primary_entry)

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
                self._set_orchestrated_stage(job, "analysis_ready")
                job = self._persist_orchestrated_job(job)
                self._emit_orchestrated_telemetry("orchestrated_stage_analysis_ready", job, decisive_provider=True)
                return await self._finalize_orchestrated_job_if_ready(job, request)

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
            self._set_orchestrated_stage(job, "urlhaus_ready")
            job = self._persist_orchestrated_job(job)
            self._emit_orchestrated_telemetry("orchestrated_stage_urlhaus_ready", job)
            return job

        if stage == "urlhaus_ready":
            resolved_urls = job.get("resolved_urls") if isinstance(job.get("resolved_urls"), list) else []
            existing_intel = job.get("threat_intel") if isinstance(job.get("threat_intel"), dict) else {}
            urlhaus_intel = _gather_external_intel_safe(
                resolved_urls,
                include_phishing_database=False,
                include_urlhaus=True,
                include_phishtank=False,
                include_openphish=False,
                include_scam_blocklist_nrd=False,
                include_phishdestroy=False,
                persist_partial=False,
            )
            threat_intel = _merge_threat_intel_sources(existing_intel, urlhaus_intel)
            summary = _external_intel_summary_from_threat_intel(threat_intel)
            job["threat_intel"] = threat_intel
            analysis = job.get("analysis") if isinstance(job.get("analysis"), dict) else {}
            analysis.setdefault("evidence", {})["external_intel_summary"] = summary
            job["analysis"] = analysis
            self._set_orchestrated_stage(job, "reputation_ready")
            job = self._persist_orchestrated_job(job)
            self._emit_orchestrated_telemetry("orchestrated_stage_reputation_ready", job)
            return job

        if stage == "reputation_ready":
            redacted_text = str(job.get("redacted_text") or "")
            resolved_urls = job.get("resolved_urls") if isinstance(job.get("resolved_urls"), list) else []
            threat_intel = job.get("threat_intel") if isinstance(job.get("threat_intel"), dict) else None
            analysis = _analyze_with_reputation(
                redacted_text,
                resolved_urls,
                email_context=job.get("email_auth") if isinstance(job.get("email_auth"), dict) else None,
                fast_reputation=True,
                threat_intel_override=threat_intel,
                allow_deep_fallback=False,
            )
            analysis.setdefault("evidence", {})["source_channel"] = job.get("source_channel")
            claim_required = _claim_verifier_required(analysis)

            primary_entry = _select_primary_resolved_url(resolved_urls, analysis)

            job["analysis"] = analysis
            job["claim_verifier_required"] = claim_required
            _apply_primary_resolved_url(job, primary_entry)
            self._set_orchestrated_stage(job, "semantic_ready")
            job = self._persist_orchestrated_job(job)
            self._emit_orchestrated_telemetry("orchestrated_stage_semantic_ready", job, claim_required=claim_required)
            return job

        if stage == "semantic_ready":
            redacted_text = str(job.get("redacted_text") or "")
            resolved_urls = job.get("resolved_urls") if isinstance(job.get("resolved_urls"), list) else []
            analysis = job.get("analysis") if isinstance(job.get("analysis"), dict) else {}
            claim_required = bool(job.get("claim_verifier_required", _claim_verifier_required(analysis)))
            evidence = analysis.get("evidence", {}) if isinstance(analysis.get("evidence"), dict) else {}
            summary = evidence.get("external_intel_summary") if isinstance(evidence.get("external_intel_summary"), dict) else {}
            if claim_required and not _has_bad_provider_verdict(summary):
                await asyncio.gather(
                    _enrich_semantic_review_async(redacted_text, analysis, resolved_urls),
                    _enrich_offer_claim_verification_async(redacted_text, analysis, resolved_urls),
                )
            else:
                await _enrich_semantic_review_async(redacted_text, analysis, resolved_urls)
                _attach_offer_claim_verification(
                    analysis,
                    _skipped_offer_claim_payload(
                        "Claim web check skipped because hard reputation evidence is already decisive."
                        if _has_bad_provider_verdict(summary)
                        else "Claim web check skipped because no concrete offer/brand claim was detected."
                    ),
                )
            job["analysis"] = analysis
            job["claim_verifier_required"] = claim_required
            self._set_orchestrated_stage(job, "analysis_ready")
            job = self._persist_orchestrated_job(job)
            self._emit_orchestrated_telemetry(
                "orchestrated_stage_analysis_ready",
                job,
                claim_required=claim_required,
                parallel_enrichment=claim_required and not _has_bad_provider_verdict(summary),
            )
            return await self._finalize_orchestrated_job_if_ready(job, request)

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
            self._set_orchestrated_stage(job, "analysis_ready")
            job = self._persist_orchestrated_job(job)
            self._emit_orchestrated_telemetry("orchestrated_stage_analysis_ready", job, claim_required=claim_required)
            return await self._finalize_orchestrated_job_if_ready(job, request)

        if stage == "analysis_ready":
            job = await self._submit_orchestrated_urlscan_preview_once(job, request)
            return await self._finalize_orchestrated_job_if_ready(job, request)

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
                self._increment_orchestrated_metric(job, "urlscan_reclaim_count")
                self._set_orchestrated_stage(job, "analysis_ready")
                job = self._persist_orchestrated_job(job)
                self._emit_orchestrated_telemetry("orchestrated_urlscan_reclaimed", job, submit_age_seconds=submit_age)
                return job
            return await self._finalize_orchestrated_job_if_ready(job, request)

        urlscan_state = job.get("urlscan") if isinstance(job.get("urlscan"), dict) else {}
        urlscan_status = str(urlscan_state.get("status") or "").lower()
        should_refresh_urlscan = bool(urlscan_state.get("uuid")) and (
            urlscan_status in {"pending", "error", "timeout"}
            or (urlscan_status == "finished" and not urlscan_state.get("screenshot_ready"))
        )
        if should_refresh_urlscan:
            try:
                if urlscan_status == "finished" and not urlscan_state.get("screenshot_ready"):
                    started_at = time.perf_counter()
                    try:
                        screenshot_ready = await _urlscan_screenshot_is_ready(str(urlscan_state["uuid"]))
                    finally:
                        self._record_orchestrated_component_duration(job, "urlscan.screenshot_probe", started_at)
                    urlscan_state["screenshot_ready"] = screenshot_ready
                    if screenshot_ready:
                        urlscan_state["details"] = str(urlscan_state.get("verdict") or "urlscan result este gata")
                        preview = job.setdefault("preview", {})
                        preview["status"] = "ready"
                        preview["source"] = "urlscan"
                        preview["screenshot_url"] = urlscan_state.get("screenshot_url") or preview.get("screenshot_url")
                        preview["image_url"] = preview.get("screenshot_url")
                        preview["reason"] = None
                        cache_entry = _urlscan_preview_cache_entry_from_job(job)
                        if cache_entry:
                            _save_urlscan_preview_cache(cache_entry)
                            preview["cache_saved"] = True
                    elif _urlscan_pending_has_timed_out(job):
                        urlscan_state["status"] = "timeout"
                        self._increment_orchestrated_metric(job, "urlscan_timeout_count")
                        urlscan_state["details"] = (
                            "urlscan a finalizat raportul, dar captura nu a devenit disponibila "
                            "in timpul maxim permis."
                        )
                        preview = job.setdefault("preview", {})
                        if not preview.get("image_url"):
                            _mark_urlscan_screenshot_unavailable(
                                preview,
                                report_url=urlscan_state.get("report_url"),
                                final_url=urlscan_state.get("final_url") or job.get("primary_final_url"),
                            )
                    job["urlscan"] = urlscan_state
                    result = None
                else:
                    started_at = time.perf_counter()
                    try:
                        result = await get_urlscan_result(str(urlscan_state["uuid"]), request)
                    finally:
                        self._record_orchestrated_component_duration(job, "urlscan.result_poll", started_at)
            except HTTPException as exc:
                if urlscan_status not in {"finished", "timeout"}:
                    urlscan_state["status"] = "error"
                    urlscan_state["details"] = str(exc.detail)
                job["urlscan"] = urlscan_state
                result = None
            if result is not None:
                if str(result.get("status") or "").lower() != "pending":
                    result = _sanitize_urlscan_result_payload(result)
                    result_screenshot_url = _normalize_screenshot_proxy_url(result.get("screenshot_url"))
                    timeout_screenshot_ready = False
                    if urlscan_status == "timeout" and result_screenshot_url:
                        started_at = time.perf_counter()
                        try:
                            timeout_screenshot_ready = await _urlscan_screenshot_is_ready(str(urlscan_state["uuid"]))
                        except Exception:
                            timeout_screenshot_ready = False
                        finally:
                            self._record_orchestrated_component_duration(job, "urlscan.screenshot_probe", started_at)
                    timeout_without_ready_screenshot = urlscan_status == "timeout" and not timeout_screenshot_ready
                    if timeout_without_ready_screenshot and not (
                        job.get("preview") if isinstance(job.get("preview"), dict) else {}
                    ).get("image_url"):
                        preview = job.setdefault("preview", {})
                        _mark_urlscan_screenshot_unavailable(
                            preview,
                            report_url=result.get("report_url") or urlscan_state.get("report_url"),
                            final_url=result.get("final_url") or urlscan_state.get("final_url"),
                        )
                    else:
                        if result_screenshot_url:
                            result["screenshot_url"] = result_screenshot_url
                        if timeout_screenshot_ready:
                            result["screenshot_ready"] = True
                if result is not None and str(result.get("status") or "").lower() != "pending":
                    result_privacy = (
                        result.get("url_privacy")
                        if isinstance(result.get("url_privacy"), dict)
                        else {}
                    )
                    urlscan_state.update(result)
                    urlscan_state["screenshot_ready"] = bool(result.get("screenshot_ready"))
                    result_has_risk = _urlscan_state_has_risk(result)
                    timeout_without_ready_screenshot = (
                        urlscan_status == "timeout"
                        and not urlscan_state["screenshot_ready"]
                        and not result_has_risk
                    )
                    urlscan_state["status"] = "timeout" if timeout_without_ready_screenshot else "finished"
                    if urlscan_state["screenshot_ready"]:
                        urlscan_state["details"] = str(result.get("details") or urlscan_state.get("verdict") or "urlscan result este gata")
                    elif timeout_without_ready_screenshot:
                        urlscan_state["details"] = (
                            "urlscan a finalizat raportul, dar captura nu a devenit disponibila "
                            "in timpul maxim permis."
                        )
                    else:
                        urlscan_state["details"] = "urlscan result este gata, dar captura inca se proceseaza."
                    job["urlscan"] = urlscan_state
                    preview = job.setdefault("preview", {})
                    preview["report_url"] = result.get("report_url") or preview.get("report_url")
                    preview["final_url"] = result.get("final_url") or preview.get("final_url")
                    if result_privacy.get("preview_allowed") is False:
                        preview["status"] = "unavailable"
                        preview["source"] = None
                        preview["report_url"] = None
                        preview["screenshot_url"] = None
                        preview["image_url"] = None
                        preview["reason"] = "privacy_protected_url"
                    else:
                        has_ready_visual = preview.get("status") == "ready" and bool(
                            preview.get("image_url") or preview.get("screenshot_url")
                        )
                        if urlscan_state["screenshot_ready"] and result.get("screenshot_url"):
                            preview["status"] = "ready"
                            preview["source"] = "urlscan"
                            preview["screenshot_url"] = result.get("screenshot_url")
                            preview["image_url"] = result.get("screenshot_url")
                            preview["reason"] = None
                        elif urlscan_status == "timeout" and not urlscan_state["screenshot_ready"]:
                            _mark_urlscan_screenshot_unavailable(
                                preview,
                                report_url=result.get("report_url") or urlscan_state.get("report_url"),
                                final_url=result.get("final_url") or urlscan_state.get("final_url"),
                            )
                        elif not has_ready_visual:
                            preview["status"] = "pending"
                            preview["source"] = "urlscan"
                            preview["screenshot_url"] = None
                            preview["image_url"] = None
                            preview["reason"] = "urlscan_screenshot_pending"
                        cache_entry = _urlscan_preview_cache_entry_from_job(job)
                        if cache_entry:
                            _save_urlscan_preview_cache(cache_entry)
                    if result.get("final_url"):
                        job["primary_final_url"] = result.get("final_url")
                        job["primary_url_privacy"] = _merge_url_privacy(
                            job.get("primary_url_privacy")
                            if isinstance(job.get("primary_url_privacy"), dict)
                            else None,
                            result_privacy,
                        )
                        resolved_urls = job.get("resolved_urls") if isinstance(job.get("resolved_urls"), list) else []
                        if resolved_urls:
                            resolved_urls[0]["final_url"] = result.get("final_url")
                            resolved_urls[0]["final_hostname"] = urllib.parse.urlparse(str(result.get("final_url"))).hostname
                            resolved_urls[0]["final_registered_domain"] = _extract_domain_root(resolved_urls[0].get("final_hostname"))
                            resolved_urls[0]["url_privacy"] = _merge_url_privacy(
                                resolved_urls[0].get("url_privacy")
                                if isinstance(resolved_urls[0].get("url_privacy"), dict)
                                else None,
                                result_privacy,
                            )

                    analysis = job.get("analysis") if isinstance(job.get("analysis"), dict) else {}
                    evidence = analysis.setdefault("evidence", {})
                    summary = evidence.setdefault("external_intel_summary", {})
                    if isinstance(summary, dict):
                        summary["urlscan"] = _urlscan_provider_payload(result)
                    _sync_resolved_urls_with_urlscan_final(job)
                elif _urlscan_pending_has_timed_out(job):
                    urlscan_state["status"] = "timeout"
                    self._increment_orchestrated_metric(job, "urlscan_timeout_count")
                    urlscan_state["details"] = (
                        "urlscan preview nu a finalizat captura in timpul maxim permis; "
                        "verdictul ramane bazat pe piloanele blocking."
                    )
                    job["urlscan"] = urlscan_state
                    preview = job.setdefault("preview", {})
                    if not preview.get("image_url"):
                        preview["status"] = "unavailable"
                        preview["source"] = None
                        preview["reason"] = "urlscan_timeout"
            elif _urlscan_pending_has_timed_out(job):
                urlscan_state["status"] = "timeout"
                self._increment_orchestrated_metric(job, "urlscan_timeout_count")
                urlscan_state["details"] = (
                    "urlscan preview nu a finalizat captura in timpul maxim permis; "
                    "verdictul ramane bazat pe piloanele blocking."
                )
                job["urlscan"] = urlscan_state
                preview = job.setdefault("preview", {})
                if not preview.get("image_url"):
                    preview["status"] = "unavailable"
                    preview["source"] = None
                    preview["reason"] = "urlscan_timeout"

        job = self._persist_orchestrated_job(job)
        self._emit_orchestrated_telemetry("orchestrated_urlscan_polled", job)
        return await self._finalize_orchestrated_job_if_ready(job, request)


    async def _start_orchestrated_from_extraction(self,
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

        job = await self._create_orchestrated_job(
            OrchestratedScanRequest(
                input_type=input_type,
                text=text,
                html_content=html_content,
                source_channel=source_channel or str(extraction.get("source_channel") or default_input_type),
                email_auth=extraction.get("email_auth")
                if isinstance(extraction.get("email_auth"), dict)
                else None,
                email_evidence_ledger=extraction.get("email_evidence_ledger")
                if isinstance(extraction.get("email_evidence_ledger"), dict)
                else None,
                email_compound_active=bool(extraction.get("email_compound_active")),
                pre_redaction_evidence=extraction.get("pre_redaction_evidence")
                if isinstance(extraction.get("pre_redaction_evidence"), dict)
                else None,
            ),
            artifact_metadata={
                "artifact_type": extraction.get("input_type") or default_input_type,
                "qr_payloads": extraction.get("qr_payloads")
                if isinstance(extraction.get("qr_payloads"), list)
                else [],
                "hidden_url_visibility": bool(extraction.get("hidden_url_visibility")),
                "has_html": bool(html_content),
                "email_auth": extraction.get("email_auth")
                if isinstance(extraction.get("email_auth"), dict)
                else None,
                "email_evidence_ledger": extraction.get("email_evidence_ledger")
                if isinstance(extraction.get("email_evidence_ledger"), dict)
                else None,
                "email_compound_active": bool(extraction.get("email_compound_active")),
                "extraction_warning": extraction.get("warning"),
                "pre_redaction_evidence": extraction.get("pre_redaction_evidence")
                if isinstance(extraction.get("pre_redaction_evidence"), dict)
                else None,
            },
        )
        response = self._orchestrated_status_payload(job)
        response.setdefault("extraction", {})
        response["extraction"] = {
            "input_type": extraction.get("input_type") or default_input_type,
            "source_channel": extraction.get("source_channel") or source_channel,
            "extracted_url_count": len(extraction.get("extracted_urls") or []),
            "has_html": bool(html_content),
            "warning": extraction.get("warning"),
            "attachment_count": int(
                (
                    extraction.get("email_evidence_ledger", {}).get("summary", {})
                    if isinstance(extraction.get("email_evidence_ledger"), dict)
                    else {}
                ).get("attachment_count")
                or 0
            ),
            "compound_coverage": str(
                (
                    extraction.get("email_evidence_ledger", {}).get("coverage", {})
                    if isinstance(extraction.get("email_evidence_ledger"), dict)
                    else {}
                ).get("status")
                or "not_applicable"
            ),
            "compound_active": bool(extraction.get("email_compound_active")),
        }
        return response


orchestrated_engine = OrchestratedScanEngine()
