"""URLscan orchestration helpers extracted from runtime.py."""

from __future__ import annotations

from typing import Any, Dict, Optional
import json
import time
import urllib.parse
import importlib
import sys

from services.urlscan_helpers import _normalize_urlscan_preview_cache_entry


class _RuntimeProxy:
    def __getattr__(self, name: str):
        runtime = sys.modules.get("main")
        if runtime is None:
            runtime = importlib.import_module("app")
        return getattr(runtime, name)


runtime = _RuntimeProxy()


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
    final_privacy = runtime.prepare_external_url(final_url)
    submitted_privacy = runtime.prepare_external_url(submitted_url or final_url)
    if (
        final_privacy.get("preview_allowed") is False
        or final_privacy.get("action") != "unchanged"
        or submitted_privacy.get("preview_allowed") is False
        or submitted_privacy.get("action") != "unchanged"
    ):
        return
    hostname = (urllib.parse.urlparse(final_url).hostname or "").lower()
    lookup_urls = [final_url]
    if submitted_url and runtime._canonical_urlscan_preview_cache_url(submitted_url) != runtime._canonical_urlscan_preview_cache_url(final_url):
        lookup_urls.append(submitted_url)

    for lookup_url in lookup_urls:
        cache_key = runtime._urlscan_preview_cache_key(lookup_url)
        canonical_url = runtime._canonical_urlscan_preview_cache_url(lookup_url)
        if not cache_key or not canonical_url:
            continue
        cache_entry = {
            "url_hash": cache_key,
            "canonical_url": canonical_url,
            "final_url": final_url,
            "final_registered_domain": runtime._extract_domain_root(hostname),
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
            "expires_at": int(time.time()) + runtime.URLSCAN_PREVIEW_CACHE_TTL_SECONDS,
        }
        runtime._remember_preview_cache_entry(
            runtime._URLSCAN_PREVIEW_CACHE,
            cache_key,
            cache_entry,
            runtime.URLSCAN_PREVIEW_CACHE_MAX_ENTRIES,
        )
        runtime.supabase_store.save_urlscan_preview_cache(cache_entry)


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
    final_privacy = runtime.prepare_external_url(final_url)
    safe_final_url = str(final_privacy.get("external_url") or "").strip()
    if not safe_final_url:
        return
    if isinstance(urlscan_summary, dict) and urlscan_summary.get("final_url"):
        urlscan_summary["final_url"] = safe_final_url
    if isinstance(preview, dict) and preview.get("final_url"):
        preview["final_url"] = safe_final_url

    parsed = urllib.parse.urlparse(safe_final_url)
    final_hostname = (parsed.hostname or "").lower()
    final_registered_domain = runtime._extract_domain_root(final_hostname)
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
            entry["url_privacy"] = runtime._merge_url_privacy(
                entry.get("url_privacy") if isinstance(entry.get("url_privacy"), dict) else None,
                final_privacy,
            )
            if not entry.get("hostname"):
                original_url = str(entry.get("url") or entry.get("original_url") or "")
                entry["hostname"] = (urllib.parse.urlparse(original_url).hostname or "").lower()
            if not entry.get("registered_domain"):
                entry["registered_domain"] = runtime._extract_domain_root(entry.get("hostname"))
    job["primary_final_url"] = safe_final_url
    job["primary_url_privacy"] = runtime._merge_url_privacy(
        job.get("primary_url_privacy")
        if isinstance(job.get("primary_url_privacy"), dict)
        else None,
        final_privacy,
    )
    extra_fields = job.setdefault("extra_fields", {})
    if isinstance(extra_fields, dict):
        extra_fields["resolved_urls"] = resolved_urls


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
    preview["details"] = runtime.URLSCAN_SCREENSHOT_UNAVAILABLE_DETAILS


def _urlscan_pending_has_timed_out(job: Dict[str, Any]) -> bool:
    urlscan_state = job.get("urlscan") if isinstance(job.get("urlscan"), dict) else {}
    status = str(urlscan_state.get("status") or "").strip().lower()
    waiting_for_result = status == "pending"
    waiting_for_screenshot = status == "finished" and not urlscan_state.get("screenshot_ready")
    if not waiting_for_result and not waiting_for_screenshot:
        return False
    created_at = int(job.get("created_at") or int(time.time()))
    return int(time.time()) - created_at >= runtime.ORCHESTRATED_URLSCAN_PENDING_TIMEOUT_SECONDS


def _urlscan_enhancement_done(job: Dict[str, Any]) -> bool:
    analysis = job.get("analysis") if isinstance(job.get("analysis"), dict) else {}
    evidence = analysis.get("evidence") if isinstance(analysis.get("evidence"), dict) else {}
    summary = evidence.get("external_intel_summary") if isinstance(evidence.get("external_intel_summary"), dict) else {}
    if runtime._has_bad_provider_verdict(summary):
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


def _sanitize_urlscan_result_payload(result: Dict[str, Any]) -> Dict[str, Any]:
    sanitized = dict(result if isinstance(result, dict) else {})
    final_url = sanitized.get("final_url")
    if not isinstance(final_url, str) or not final_url.strip():
        return sanitized
    privacy = runtime.prepare_external_url(final_url)
    sanitized["final_url"] = privacy.get("external_url")
    sanitized["url_privacy"] = runtime._merge_url_privacy(
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
    runtime.orchestrated_engine._increment_orchestrated_metric(job, "urlscan_preview_cache_hit_count")
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
