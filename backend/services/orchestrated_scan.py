"""Orchestrated-scan engine, extracted from main.py incrementally.

Functions reference their main-module siblings/helpers/config/state via `import main;
main.X` (resolved at call time). main.py re-exports these names, so existing test
monkeypatching of main.<symbol> keeps working unchanged.
"""

import os
import re
import json
import time
import asyncio
import hashlib
import base64
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import main


def _orchestrated_metrics(job: Dict[str, Any]) -> Dict[str, Any]:
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


def _increment_orchestrated_metric(job: Dict[str, Any], key: str, amount: int = 1) -> None:
    metrics = main._orchestrated_metrics(job)
    try:
        metrics[key] = int(metrics.get(key, 0) or 0) + int(amount)
    except Exception:
        metrics[key] = int(amount)


def _record_orchestrated_component_duration(job: Dict[str, Any], component: str, started_at: float) -> None:
    if not isinstance(job, dict):
        return
    elapsed_ms = max(0, int((time.perf_counter() - started_at) * 1000))
    metrics = main._orchestrated_metrics(job)
    durations = metrics.setdefault("component_durations_ms", {})
    if not isinstance(durations, dict):
        durations = {}
        metrics["component_durations_ms"] = durations
    key = str(component or "unknown")
    try:
        durations[key] = int(durations.get(key, 0) or 0) + elapsed_ms
    except Exception:
        durations[key] = elapsed_ms


def _timed_orchestrated_component(job: Dict[str, Any], component: str, fn):
    started_at = time.perf_counter()
    try:
        return fn()
    finally:
        main._record_orchestrated_component_duration(job, component, started_at)


def _set_orchestrated_stage(job: Dict[str, Any], next_stage: str) -> None:
    if not isinstance(job, dict):
        return
    next_stage = str(next_stage or "").strip().lower() or "queued"
    now = int(time.time())
    metrics = main._orchestrated_metrics(job)
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
        metrics = main._orchestrated_metrics(job)
        urlscan_state = job.get("urlscan") if isinstance(job.get("urlscan"), dict) else {}
        main.log_scan_event(
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


def _persist_orchestrated_job(job: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(job, dict) or not job.get("scan_id"):
        return job
    scan_id = str(job["scan_id"])
    saved = main.supabase_store.save_scan_job(job)
    if saved is False:
        main._increment_orchestrated_metric(job, "conflict_merge_count")
        reloaded = main.supabase_store.load_scan_job(scan_id)
        if isinstance(reloaded, dict):
            merged = main._merge_orchestrated_conflict_job(reloaded, job)
            if merged != reloaded:
                retry_saved = False
                for _ in range(2):
                    main._increment_orchestrated_metric(merged, "conflict_merge_retry_count")
                    retry_saved = main.supabase_store.save_scan_job(merged)
                    if retry_saved is not False:
                        break
                    latest = main.supabase_store.load_scan_job(scan_id)
                    if isinstance(latest, dict):
                        merged = main._merge_orchestrated_conflict_job(latest, merged)
                if retry_saved is False:
                    main._increment_orchestrated_metric(merged, "conflict_merge_retry_failures")
                main._emit_orchestrated_telemetry(
                    "orchestrated_conflict_merge",
                    merged,
                    retry_saved=retry_saved is not False,
                )
            main._ORCHESTRATED_SCAN_JOBS[scan_id] = merged
            return merged
        main._increment_orchestrated_metric(job, "persist_fallback_memory_count")
        main._ORCHESTRATED_SCAN_JOBS[scan_id] = job
        main._emit_orchestrated_telemetry("orchestrated_persist_memory_fallback", job)
        return job
    main._ORCHESTRATED_SCAN_JOBS[scan_id] = job
    return job


def _load_orchestrated_job(scan_id: str) -> Optional[Dict[str, Any]]:
    job = main.supabase_store.load_scan_job(scan_id)
    if isinstance(job, dict):
        main._ORCHESTRATED_SCAN_JOBS[scan_id] = job
        return job
    job = main._ORCHESTRATED_SCAN_JOBS.get(scan_id)
    if isinstance(job, dict):
        return job
    return None


def _orchestrated_lock_owner(scan_id: str) -> str:
    return f"cloudrun:{os.getenv('K_REVISION', 'local')}:{os.getpid()}:{scan_id}:{time.time_ns()}"


def _claim_distributed_orchestrated_refresh(job: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    revision = job.get("_storage_revision")
    scan_id = str(job.get("scan_id") or "")
    if not scan_id or not isinstance(revision, int):
        return None
    claimed = main.supabase_store.claim_scan_job(
        scan_id,
        expected_revision=revision,
        owner=main._orchestrated_lock_owner(scan_id),
        active_step=str(job.get("pipeline_stage") or "queued"),
        lock_seconds=main.ORCHESTRATED_REFRESH_LOCK_TTL_SECONDS,
    )
    if not isinstance(claimed, dict):
        return None
    claimed_job = main.supabase_store.scan_job_from_record(claimed)
    if isinstance(claimed_job, dict):
        main._ORCHESTRATED_SCAN_JOBS[scan_id] = claimed_job
        return claimed_job
    return job


def _prune_orchestrated_jobs() -> None:
    now = int(time.time())
    expired = [
        scan_id
        for scan_id, job in main._ORCHESTRATED_SCAN_JOBS.items()
        if now - int(job.get("created_at", now)) > main.ORCHESTRATED_JOB_TTL_SECONDS
    ]
    for scan_id in expired:
        main._ORCHESTRATED_SCAN_JOBS.pop(scan_id, None)
        main._ORCHESTRATED_SCAN_LOCKS.pop(scan_id, None)
