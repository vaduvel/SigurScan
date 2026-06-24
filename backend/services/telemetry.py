import json
import logging
import os
from datetime import datetime, timezone
from collections import Counter, defaultdict
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

_LOGGER = logging.getLogger("sigurscan.telemetry")

from config import RISK_THRESHOLD
from services import supabase_store
from services.pii_redactor import redact_pii
from services.url_reputation import get_reputation_cache_stats


_LOCK = threading.Lock()


def _resolve_path(env_name: str, default_rel_path: str) -> Path:
    return Path(os.getenv(env_name, str(Path(__file__).resolve().parents[1] / default_rel_path)))


SCAN_EVENTS_PATH = _resolve_path("SCAN_EVENTS_LOG_PATH", "data/scan_events.jsonl")
FEEDBACK_LOG_PATH = _resolve_path("SCAN_FEEDBACK_LOG_PATH", "data/scan_feedback.jsonl")


def _append_jsonl(path: Path, payload: Dict[str, Any]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with _LOCK:
            with path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(payload, ensure_ascii=False))
                f.write("\n")
    except Exception:
        # Telemetry is non-blocking.
        return


def _redact_log_value(value: Any) -> Any:
    """Best-effort final guard before telemetry reaches any persistence sink."""
    if isinstance(value, str):
        return redact_pii(value)
    if isinstance(value, list):
        return [_redact_log_value(item) for item in value]
    if isinstance(value, dict):
        return {key: _redact_log_value(item) for key, item in value.items()}
    return value


def log_scan_event(payload: Dict[str, Any]) -> None:
    if not isinstance(payload, dict):
        return

    base_payload = _redact_log_value(dict(payload))
    base_payload.setdefault("event_type", "scan_completed")
    base_payload.setdefault("timestamp", int(time.time()))
    supabase_store.log_scan_event(base_payload)
    _append_jsonl(SCAN_EVENTS_PATH, base_payload)


def log_feedback_event(payload: Dict[str, Any]) -> None:
    if not isinstance(payload, dict):
        return

    base_payload = _redact_log_value(dict(payload))
    base_payload.setdefault("event_type", "scan_feedback")
    base_payload.setdefault("timestamp", int(time.time()))
    supabase_store.log_feedback_event(base_payload)
    _append_jsonl(FEEDBACK_LOG_PATH, base_payload)


def log_se_high_confidence_fire(
    decision_bundle: Dict[str, Any],
    gate_result: Dict[str, Any],
    *,
    scan_id: Optional[str] = None,
    revision: Optional[str] = None,
) -> None:
    """Observable-only telemetry for the `social_engineering_high_confidence_intent`
    gate branch. It is the single source of truth for the event schema and is called
    from the verdict call-site (provider_gate). It captures the RAW pre-merge local
    vs Mistral sub-signals (carried on ``decision_bundle["_se_signals_raw"]``) so a
    later analysis can separate FP candidates (Mistral fires, local does not) from
    true positives (both agree). It NEVER raises and NEVER influences any verdict.
    """
    try:
        from services.verdict_gate_constants import (
            HARD_SENSITIVE_REQUESTS,
            MONEY_OR_VALUE_REQUESTS,
            WRONG_CHANNELS,
            DANGEROUS_SOCIAL_ENGINEERING_INTENTS,
            PROVIDER_CLEAN,
        )
        from services.verdict_gate import _has_positive_provenance, _providers_verdict

        raw = decision_bundle.get("_se_signals_raw") if isinstance(decision_bundle, dict) else None
        raw = raw if isinstance(raw, dict) else {}
        local = raw.get("local") if isinstance(raw.get("local"), dict) else {}
        model = raw.get("model") if isinstance(raw.get("model"), dict) else {}
        request = decision_bundle.get("request") if isinstance(decision_bundle.get("request"), dict) else {}
        identity = decision_bundle.get("identity") if isinstance(decision_bundle.get("identity"), dict) else {}
        provenance = decision_bundle.get("provenance") if isinstance(decision_bundle.get("provenance"), dict) else {}
        providers = decision_bundle.get("providers") if isinstance(decision_bundle.get("providers"), dict) else {}

        def _conf(sig: Dict[str, Any]) -> float:
            try:
                return float(sig.get("confidence") or 0.0)
            except (TypeError, ValueError):
                return 0.0

        def _se_high(sig: Dict[str, Any]) -> bool:
            return (
                bool(sig)
                and str(sig.get("intent") or "").strip().lower() in DANGEROUS_SOCIAL_ENGINEERING_INTENTS
                and _conf(sig) >= 0.78
            )

        mistral_present = bool(model)
        sensitive = str(request.get("sensitive") or "none").strip().lower()
        channel_mapped = str(request.get("channel") or "unknown").strip().lower()
        has_prov = bool(_has_positive_provenance(identity, provenance))
        provider_verdict = _providers_verdict(providers)

        payload = {
            "event": "se_high_confidence_fire",
            "event_type": "se_high_confidence_fire",
            "mistral_label": (str(model.get("intent") or "unknown").strip().lower() if mistral_present else None),
            "mistral_confidence": (round(_conf(model), 2) if mistral_present else None),
            "local_label": (str(local.get("intent") or "unknown").strip().lower() if local else None),
            "local_confidence": (round(_conf(local), 2) if local else None),
            "classifiers_agree": ((_se_high(model) and _se_high(local)) if mistral_present else False),
            "hard_sensitive": sensitive in HARD_SENSITIVE_REQUESTS,
            "hard_sensitive_token": (sensitive if sensitive in HARD_SENSITIVE_REQUESTS else None),
            "value_sensitive": sensitive in MONEY_OR_VALUE_REQUESTS,
            "positive_action_request": bool(request.get("positive_action_request")),
            "channel_raw": raw.get("source_channel"),
            "channel_mapped": channel_mapped,
            "wrong_channel": channel_mapped in WRONG_CHANNELS,
            "has_provenance": has_prov,
            "provenance_clean": bool(has_prov and provider_verdict in PROVIDER_CLEAN),
            "final_verdict": gate_result.get("label") if isinstance(gate_result, dict) else None,
            "scan_id": scan_id,
            "revision": revision or os.getenv("K_REVISION") or os.getenv("K_REVISION_NAME"),
        }
        # Emit to STDOUT as a structured JSON line -> Cloud Logging (queryable,
        # persistent, no key collision). Deliberately NOT log_scan_event/supabase:
        # that table is keyed on scan_id and would 409 against the scan_completed row
        # or merge-overwrite it. Redacted; observable-only; never changes a verdict.
        _LOGGER.info("se_high_confidence_fire %s", json.dumps(_redact_log_value(payload), ensure_ascii=False, sort_keys=True))
    except Exception:
        # Observable-only: telemetry must never break a scan or change a verdict.
        return


def _iter_jsonl(path: Path) -> Iterable[Dict[str, Any]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            try:
                obj = json.loads(line.strip())
                if isinstance(obj, dict):
                    yield obj
            except Exception:
                continue


def load_feedback_records() -> List[Dict[str, Any]]:
    remote_records = supabase_store.load_feedback_records()
    if remote_records:
        return remote_records
    return list(_iter_jsonl(FEEDBACK_LOG_PATH))


def load_scan_records(limit: int | None = None) -> List[Dict[str, Any]]:
    remote_records = supabase_store.load_scan_records(limit)
    if remote_records:
        return remote_records
    records = list(_iter_jsonl(SCAN_EVENTS_PATH))
    if isinstance(limit, int) and limit > 0:
        return records[-limit:]
    return records


def find_scan_record_by_id(scan_id: str) -> Dict[str, Any] | None:
    if not scan_id:
        return None

    for row in reversed(load_scan_records()):
        if not isinstance(row, dict):
            continue
        if row.get("scan_id") == scan_id and row.get("event_type", "scan_completed") == "scan_completed":
            return row
    return None


def _safe_pct(value: Any, total: int) -> float:
    if not total:
        return 0.0
    try:
        return float(value) / total
    except Exception:
        return 0.0


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


# Feedback evaluation / trend logic lives in telemetry_feedback.py; re-export the public
# API here so existing `from services.telemetry import ...` call sites keep working.
from services.telemetry_feedback import (  # noqa: E402
    build_feedback_evaluation_rows,
    run_feedback_threshold_sweep,
    summarize_feedback_records,
    summarize_feedback_trend,
)
