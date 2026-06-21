"""Orchestrated-scan engine, extracted from main.py incrementally.

Functions reference their main-module siblings/helpers/config/state via `import main;
main.X` (resolved at call time). main.py re-exports these names, so existing test
monkeypatching of main.<symbol> keeps working unchanged.
"""

import time
from typing import Any, Dict

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
