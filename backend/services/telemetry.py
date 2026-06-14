import json
import os
from datetime import datetime, timezone
from collections import Counter
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from services import supabase_store
from services.pii_redactor import redact_pii


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


def _coerce_optional_bool(value: Any) -> Optional[bool]:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes", "y", "on"}:
            return True
        if normalized in {"false", "0", "no", "n", "off"}:
            return False
    return None


def _safe_div(num: int, denom: int) -> float:
    return num / denom if denom else 0.0


def _coerce_feedback_ts(value: Any) -> int | None:
    if value is None:
        return None
    try:
        ts = int(value)
    except Exception:
        return None
    if ts <= 0:
        return None
    return ts


def _coerce_feedback_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes", "y", "on"}:
            return True
        if normalized in {"false", "0", "no", "n", "off"}:
            return False
    return None


def _coerce_signal_list(value: Any) -> List[str]:
    if not isinstance(value, list):
        return []
    signal_ids: List[str] = []
    for raw_signal in value:
        if not isinstance(raw_signal, str):
            continue
        signal = raw_signal.strip()
        if signal:
            signal_ids.append(signal)
    return signal_ids


def _coerce_positive_int(value: Any, default: int = 0) -> int:
    try:
        int_value = int(value)
    except Exception:
        return default
    return int_value if int_value >= 0 else default


def _coerce_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _slice_list(values: List[Any], limit: int = 5) -> List[Any]:
    if limit <= 0:
        return []
    if len(values) <= limit:
        return values
    return list(values[:limit])


def _extract_scan_context(scan_row: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(scan_row, dict):
        return {}

    evidence = scan_row.get("evidence") or {}
    evidence_payload: Dict[str, Any] = {}
    if isinstance(evidence, dict):
        email_auth = evidence.get("email_auth")
        email_auth_action = evidence.get("email_auth_action")
        email_auth_strength = evidence.get("email_auth_strength")

    evidence_payload = {
            "external_intel": evidence.get("external_intel", False),
            "external_intel_hits": _coerce_positive_int(evidence.get("external_intel_hits", 0), 0),
            "external_intel_sources": _slice_list(_coerce_signal_list(evidence.get("external_intel_sources", [])), 8),
            "external_intel_source_status": evidence.get("external_intel_source_status", {}),
            "email_auth_strength": _coerce_str(email_auth_strength) or (email_auth.get("auth_strength") if isinstance(email_auth, dict) else None),
            "email_auth_action": email_auth_action if isinstance(email_auth_action, dict) else None,
        }

    urls = scan_row.get("urls")
    url_samples: List[Dict[str, Any]] = []
    if isinstance(urls, list):
        for item in urls[:3]:
            if not isinstance(item, dict):
                continue
            url_samples.append({
                "final_url": item.get("final_url") or item.get("url"),
                "registered_domain": item.get("registered_domain") or item.get("final_registered_domain"),
                "shortener_count": _coerce_positive_int(item.get("shortener_count", 0), 0),
            })

    return {
        "scan_id": _coerce_str(scan_row.get("scan_id")),
        "input_type": _coerce_str(scan_row.get("input_type")) or None,
        "source_channel": _coerce_str(scan_row.get("source_channel")) or None,
        "risk_score": _coerce_positive_int(scan_row.get("risk_score", 0), 0),
        "risk_level": _coerce_str(scan_row.get("risk_level")) or None,
        "detected_family": _coerce_str(scan_row.get("detected_family")) or None,
        "detected_family_id": _coerce_str(scan_row.get("detected_family_id")) or None,
        "claimed_brand": _coerce_str(scan_row.get("claimed_brand")) or None,
        "url_count": _coerce_positive_int(scan_row.get("url_count", 0), 0),
        "evidence": evidence_payload,
        "url_samples": url_samples,
    }


def _derive_prediction_from_feedback_row(
    row: Dict[str, Any],
    *,
    fallback_threshold: int,
    scan_prediction: bool | None = None,
) -> bool | None:
    predicted = _coerce_feedback_bool(row.get("predicted_is_scam"))
    if predicted is not None:
        return predicted
    if scan_prediction is not None:
        return scan_prediction

    risk_score = row.get("predicted_risk_score")
    if _coerce_feedback_bool(risk_score) is not None and isinstance(risk_score, (int, float, str)):
        try:
            return int(risk_score) >= fallback_threshold
        except Exception:
            pass

    risk_level = str(row.get("risk_level") or "").lower()
    if risk_level in {"critical", "high"}:
        return True
    if risk_level in {"medium", "low", "unknown"}:
        return False

    risk_score = row.get("risk_score")
    if _coerce_feedback_bool(risk_score) is not None and isinstance(risk_score, (int, float, str)):
        try:
            return int(risk_score) >= fallback_threshold
        except Exception:
            return None

    return None


def _feedback_to_actual(feedback: str, predicted: bool | None) -> bool | None:
    normalized = (feedback or "").strip().lower()
    if normalized == "false_positive":
        return False
    if normalized == "false_negative":
        return True
    if normalized == "correct":
        return predicted
    return None


def _build_signal_feedback_stats(
    per_signal_stats: Dict[str, Dict[str, int]],
    signal: str,
    actual: Optional[bool],
    predicted: Optional[bool],
    feedback: str,
) -> None:
    stats = per_signal_stats.setdefault(
        signal,
        {
            "tp": 0,
            "fp": 0,
            "fn": 0,
            "tn": 0,
            "correct_feedback": 0,
            "incorrect_feedback": 0,
            "feedback_count": 0,
            "labeled_count": 0,
        },
    )

    if isinstance(actual, bool) and isinstance(predicted, bool):
        if predicted and actual:
            stats["tp"] += 1
        elif predicted and not actual:
            stats["fp"] += 1
        elif (not predicted) and actual:
            stats["fn"] += 1
        elif (not predicted) and (not actual):
            stats["tn"] += 1
        stats["labeled_count"] += 1

    normalized_feedback = feedback.strip().lower()
    if normalized_feedback not in {"correct", "false_positive", "false_negative"}:
        return

    if isinstance(actual, bool) and isinstance(predicted, bool):
        stats["feedback_count"] += 1
        if normalized_feedback == "correct" and actual == predicted:
            stats["correct_feedback"] += 1
        else:
            stats["incorrect_feedback"] += 1


def build_feedback_evaluation_rows(
    feedback_records: Iterable[Dict[str, Any]],
    scan_records: Iterable[Dict[str, Any]] | None = None,
    *,
    source_channel: Optional[str] = None,
    since_ts: Optional[int] = None,
    until_ts: Optional[int] = None,
    include_uncertain: bool = False,
    fallback_threshold: int = 50,
    dedupe_latest_per_scan: bool = True,
) -> List[Dict[str, Any]]:
    scans = list(load_scan_records()) if scan_records is None else list(scan_records)
    scan_index: Dict[str, Dict[str, Any]] = {}
    for row in scans:
        if not isinstance(row, dict):
            continue
        if row.get("event_type", "scan_completed") != "scan_completed":
            continue
        scan_id = str(row.get("scan_id") or "").strip()
        if not scan_id:
            continue
        scan_ts = _coerce_feedback_ts(row.get("timestamp")) or 0
        existing = scan_index.get(scan_id)
        existing_ts = _coerce_feedback_ts(existing.get("timestamp")) or 0 if existing else 0
        if existing is None or scan_ts >= existing_ts:
            scan_index[scan_id] = row

    target_source = str(source_channel).strip() if source_channel is not None else None
    rows: List[Dict[str, Any]] = []

    for row in feedback_records:
        if not isinstance(row, dict):
            continue
        scan_id = str(row.get("scan_id") or "").strip()
        if not scan_id:
            continue

        feedback = (row.get("feedback") or "").strip().lower()
        if not feedback:
            feedback = "uncertain"
        if feedback == "uncertain" and not include_uncertain:
            continue

        feedback_ts = _coerce_feedback_ts(row.get("timestamp")) or _coerce_feedback_ts(row.get("event_ts"))
        if since_ts is not None and feedback_ts is not None and feedback_ts < since_ts:
            continue
        if until_ts is not None and feedback_ts is not None and feedback_ts > until_ts:
            continue

        scan_row = scan_index.get(scan_id)
        scan_predicted = _coerce_feedback_bool(scan_row.get("predicted_is_scam")) if isinstance(scan_row, dict) else None
        predicted = _derive_prediction_from_feedback_row(
            row,
            fallback_threshold=fallback_threshold,
            scan_prediction=scan_predicted,
        )
        actual = _feedback_to_actual(feedback, predicted)
        if actual is None:
            actual = _coerce_feedback_bool(row.get("actual_is_scam"))
        if actual is None and isinstance(scan_row, dict):
            actual = _coerce_feedback_bool(scan_row.get("actual_is_scam"))

        raw_source = row.get("source_channel")
        scan_source = scan_row.get("source_channel") if isinstance(scan_row, dict) else None
        if target_source is not None:
            if (raw_source and str(raw_source) != target_source) and str(scan_source or "") != target_source:
                continue
        source = raw_source or scan_source

        risk_score = row.get("predicted_risk_score")
        if _coerce_feedback_bool(risk_score) is None and isinstance(scan_row, dict):
            risk_score = scan_row.get("risk_score")

        signal_ids = _coerce_signal_list(row.get("signal_ids"))
        if not signal_ids and isinstance(scan_row, dict):
            signal_ids = _coerce_signal_list(scan_row.get("signal_ids"))

        if actual is None and not include_uncertain:
            continue

        scan_context = _extract_scan_context(scan_row) if isinstance(scan_row, dict) else {}

        rows.append({
            "scan_id": scan_id,
            "feedback": feedback,
            "actual_is_scam": actual,
            "predicted_is_scam": predicted,
            "predicted_risk_score": row.get("predicted_risk_score"),
            "risk_score": risk_score,
            "risk_level": row.get("risk_level") or (scan_row.get("risk_level") if isinstance(scan_row, dict) else None),
            "signal_ids": signal_ids,
            "source_channel": source,
            "timestamp": feedback_ts,
            "scan_context": scan_context,
            "detected_family_id": scan_context.get("detected_family_id"),
            "detected_family": scan_context.get("detected_family"),
            "claimed_brand": scan_context.get("claimed_brand"),
            "input_type": scan_context.get("input_type"),
            "url_count": scan_context.get("url_count", 0),
            "error_category": (
                "false_positive"
                if actual is False and predicted is True
                else "false_negative"
                if actual is True and predicted is False
                else "correct"
                if actual is not None and predicted is not None and actual == predicted
                else "uncertain"
            ),
        })

    if not dedupe_latest_per_scan:
        return rows

    latest_by_scan: Dict[str, Dict[str, Any]] = {}
    for row in rows:
        scan_id = str(row.get("scan_id") or "").strip()
        if not scan_id:
            continue
        row_ts = _coerce_feedback_ts(row.get("timestamp"))
        existing = latest_by_scan.get(scan_id)
        existing_ts = _coerce_feedback_ts(existing.get("timestamp")) if isinstance(existing, dict) else None
        if existing is None or row_ts is None or existing_ts is None or row_ts >= existing_ts:
            latest_by_scan[scan_id] = row
    return list(latest_by_scan.values())


def _build_confusion_from_rows(rows: List[Dict[str, Any]], *, threshold: Optional[int] = None) -> Dict[str, Any]:
    tp = fp = fn = tn = 0
    false_positive_signal_hits: Counter[str] = Counter()
    false_negative_signal_hits: Counter[str] = Counter()
    total_rows = 0

    for row in rows:
        actual = _coerce_optional_bool(row.get("actual_is_scam"))
        if actual is None:
            continue

        predicted = _coerce_optional_bool(row.get("predicted_is_scam"))
        if threshold is not None:
            risk_score = row.get("risk_score")
            if isinstance(risk_score, (int, float)):
                predicted = int(risk_score) >= threshold
            elif isinstance(risk_score, str):
                try:
                    predicted = int(risk_score) >= threshold
                except Exception:
                    predicted = None
            elif isinstance(row.get("risk_level"), str):
                predicted = str(row.get("risk_level")).lower() in {"high", "critical"}
            elif predicted is None:
                predicted = None

        if predicted is None:
            continue
        predicted = bool(predicted)
        total_rows += 1

        if predicted and actual:
            tp += 1
        elif predicted and not actual:
            fp += 1
            for signal in _coerce_signal_list(row.get("signal_ids")):
                false_positive_signal_hits[signal] += 1
        elif (not predicted) and actual:
            fn += 1
            for signal in _coerce_signal_list(row.get("signal_ids")):
                false_negative_signal_hits[signal] += 1
        else:
            tn += 1

    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    accuracy = _safe_div(tp + tn, total_rows)

    return {
        "total": total_rows,
        "confusion_matrix": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
        "false_positive_signal_hits": false_positive_signal_hits,
        "false_negative_signal_hits": false_negative_signal_hits,
    }


def run_feedback_threshold_sweep(
    rows: List[Dict[str, Any]],
    *,
    sweep_start: int = 0,
    sweep_end: int = 100,
    sweep_step: int = 5,
    optimize_metric: str = "f1",
) -> Dict[str, Any]:
    if sweep_step <= 0:
        raise ValueError("sweep_step must be > 0")
    if sweep_end < sweep_start:
        raise ValueError("sweep_end must be >= sweep_start")

    base_rows = list(rows)
    if not base_rows:
        return {
            "items_evaluated": 0,
            "candidates": [],
            "best": {
                "risk_threshold": sweep_start,
                "precision": 0.0,
                "recall": 0.0,
                "f1": 0.0,
                "accuracy": 0.0,
                "tp": 0,
                "fp": 0,
                "fn": 0,
                "tn": 0,
            },
        }

    thresholds = list(range(sweep_start, sweep_end + 1, sweep_step))
    if thresholds[-1] != sweep_end:
        thresholds.append(sweep_end)

    candidates: List[Dict[str, Any]] = []
    for threshold in thresholds:
        metrics = _build_confusion_from_rows(base_rows, threshold=threshold)
        matrix = metrics["confusion_matrix"]
        candidates.append({
            "risk_threshold": threshold,
            "precision": metrics["precision"],
            "recall": metrics["recall"],
            "f1": metrics["f1"],
            "accuracy": metrics["accuracy"],
            "tp": matrix["tp"],
            "fp": matrix["fp"],
            "fn": matrix["fn"],
            "tn": matrix["tn"],
        })

    metric = optimize_metric.strip().lower()
    if metric not in {"precision", "recall", "f1", "accuracy"}:
        metric = "f1"
    candidates_sorted = sorted(
        candidates,
        key=lambda item: (
            item[metric],
            item["precision"],
            item["recall"],
            -item["fp"],
            -item["fn"],
        ),
        reverse=True,
    )

    return {
        "items_evaluated": len(base_rows),
        "options": {
            "sweep_start": sweep_start,
            "sweep_end": sweep_end,
            "sweep_step": sweep_step,
            "optimize_metric": metric,
        },
        "candidates": candidates,
        "best": candidates_sorted[0],
    }


def summarize_feedback_records(
    records: Iterable[Dict[str, Any]],
    *,
    source_channel: Optional[str] = None,
    since_ts: Optional[int] = None,
    until_ts: Optional[int] = None,
    include_examples: bool = True,
    max_examples_per_type: int = 50,
) -> Dict[str, Any]:
    rows = list(records)
    if source_channel is not None:
        rows = [
            record
            for record in rows
            if str(record.get("source_channel") or "") == str(source_channel)
        ]

    if since_ts is not None or until_ts is not None:
        filtered: List[Dict[str, Any]] = []
        for record in rows:
            ts = record.get("timestamp")
            if ts is None:
                continue
            if not isinstance(ts, (int, float)):
                try:
                    ts = int(ts)
                except Exception:
                    continue

            if since_ts is not None and ts < since_ts:
                continue
            if until_ts is not None and ts > until_ts:
                continue
            filtered.append(record)
        rows = filtered

    summary = {
        "total": len(rows),
        "by_feedback": {
            "correct": 0,
            "false_positive": 0,
            "false_negative": 0,
            "uncertain": 0,
            "other": 0,
        },
        "by_error_category": {
            "correct": 0,
            "false_positive": 0,
            "false_negative": 0,
            "uncertain": 0,
            "other": 0,
        },
        "by_signal_count": {
            "0": 0,
            "1": 0,
            "2": 0,
            "3": 0,
            "4+": 0,
        },
        "by_source_channel": {},
        "coverage": {
            "labeled_actual": 0,
            "labeled_prediction": 0,
            "labeled_both": 0,
        },
    }

    tp = fp = fn = tn = 0
    false_positive_signal_hits: Counter[str] = Counter()
    false_negative_signal_hits: Counter[str] = Counter()
    signal_feedback_totals: Counter[str] = Counter()
    per_signal_confusion: Dict[str, Dict[str, int]] = {}
    false_positive_samples: List[Dict[str, Any]] = []
    false_negative_samples: List[Dict[str, Any]] = []

    if max_examples_per_type < 0:
        max_examples_per_type = 0

    for row in rows:
        feedback = (row.get("feedback") or "").strip().lower()
        if not feedback:
            feedback = "uncertain"
        if feedback not in summary["by_feedback"]:
            summary["by_feedback"]["other"] += 1
        else:
            summary["by_feedback"][feedback] += 1

        error_category = str(row.get("error_category") or "").strip().lower()
        if not error_category:
            error_category = "uncertain"
        if error_category not in summary["by_error_category"]:
            summary["by_error_category"]["other"] += 1
        else:
            summary["by_error_category"][error_category] += 1

        signal_count = len(_coerce_signal_list(row.get("signal_ids")))
        if signal_count >= 4:
            summary["by_signal_count"]["4+"] += 1
        else:
            bucket = str(signal_count)
            summary["by_signal_count"][bucket] = summary["by_signal_count"].get(bucket, 0) + 1

        source_channel = _coerce_str(row.get("source_channel")) or "unknown"
        summary["by_source_channel"][source_channel] = summary["by_source_channel"].get(source_channel, 0) + 1

        predicted = _coerce_optional_bool(row.get("predicted_is_scam"))
        if predicted is None and isinstance(row.get("risk_level"), str):
            risk_level = row.get("risk_level", "").lower()
            if risk_level in {"high", "critical"}:
                predicted = True
            elif risk_level in {"low"}:
                predicted = False
            elif risk_level in {"medium"}:
                predicted = True

        actual = _coerce_optional_bool(row.get("actual_is_scam"))
        if actual is None:
            actual = _feedback_to_actual(feedback, predicted)

        if actual is not None:
            summary["coverage"]["labeled_actual"] += 1
        if predicted is not None:
            summary["coverage"]["labeled_prediction"] += 1
        if actual is not None and predicted is not None:
            summary["coverage"]["labeled_both"] += 1

        if actual is True and predicted is True:
            tp += 1
        elif actual is False and predicted is True:
            fp += 1
            if include_examples and len(false_positive_samples) < max_examples_per_type:
                false_positive_samples.append({
                    "scan_id": row.get("scan_id"),
                    "feedback": feedback,
                    "risk_level": row.get("risk_level"),
                    "risk_score": row.get("risk_score"),
                    "predicted_risk_score": row.get("predicted_risk_score"),
                    "predicted_is_scam": predicted,
                    "actual_is_scam": actual,
                    "timestamp": row.get("timestamp"),
                    "signal_ids": row.get("signal_ids", []),
                    "scan_context": row.get("scan_context", {}),
                    "detected_family_id": row.get("detected_family_id"),
                    "detected_family": row.get("detected_family"),
                    "claimed_brand": row.get("claimed_brand"),
                    "input_type": row.get("input_type"),
                })
        elif actual is True and predicted is False:
            fn += 1
            if include_examples and len(false_negative_samples) < max_examples_per_type:
                false_negative_samples.append({
                    "scan_id": row.get("scan_id"),
                    "feedback": feedback,
                    "risk_level": row.get("risk_level"),
                    "risk_score": row.get("risk_score"),
                    "predicted_risk_score": row.get("predicted_risk_score"),
                    "predicted_is_scam": predicted,
                    "actual_is_scam": actual,
                    "timestamp": row.get("timestamp"),
                    "signal_ids": row.get("signal_ids", []),
                    "scan_context": row.get("scan_context", {}),
                    "detected_family_id": row.get("detected_family_id"),
                    "detected_family": row.get("detected_family"),
                    "claimed_brand": row.get("claimed_brand"),
                    "input_type": row.get("input_type"),
                })
        elif actual is False and predicted is False:
            tn += 1

        signal_ids = row.get("signal_ids") or []
        if not isinstance(signal_ids, list):
            continue
        for raw_signal in signal_ids:
            if not isinstance(raw_signal, str):
                continue
            signal = raw_signal.strip().lower()
            if not signal:
                continue
            signal_feedback_totals[signal] += 1
            _build_signal_feedback_stats(
                per_signal_confusion,
                signal=signal,
                actual=actual,
                predicted=predicted,
                feedback=feedback,
            )

            if feedback == "false_positive":
                false_positive_signal_hits[signal] += 1
            elif feedback == "false_negative":
                false_negative_signal_hits[signal] += 1

    precision_denom = tp + fp
    recall_denom = tp + fn
    precision = _safe_div(tp, precision_denom)
    recall = _safe_div(tp, recall_denom)
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    accuracy = _safe_div(tp + tn, summary["coverage"]["labeled_both"])

    false_positive_by_signal = []
    false_negative_by_signal = []
    signal_feedback_performance = []
    for signal, total in sorted(signal_feedback_totals.items(), key=lambda item: item[0]):
        fp_count = false_positive_signal_hits.get(signal, 0)
        fn_count = false_negative_signal_hits.get(signal, 0)
        per_signal = per_signal_confusion.get(signal, {})
        tp_count = per_signal.get("tp", 0)
        fp_count_for_confusion = per_signal.get("fp", 0)
        fn_count_for_confusion = per_signal.get("fn", 0)
        tn_count = per_signal.get("tn", 0)
        correct_feedback = per_signal.get("correct_feedback", 0)
        incorrect_feedback = per_signal.get("incorrect_feedback", 0)
        feedback_count = per_signal.get("feedback_count", 0)

        false_positive_by_signal.append({
            "signal": signal,
            "false_positive_count": fp_count,
            "false_negative_count": fn_count,
            "feedback_count": total,
            "false_positive_rate": fp_count / total if total else 0.0,
            "false_negative_rate": fn_count / total if total else 0.0,
        })
        false_negative_by_signal.append({
            "signal": signal,
            "false_positive_count": fp_count,
            "false_negative_count": fn_count,
            "feedback_count": total,
            "false_positive_rate": fp_count / total if total else 0.0,
            "false_negative_rate": fn_count / total if total else 0.0,
        })

        signal_feedback_performance.append({
            "signal": signal,
            "tp": tp_count,
            "fp": fp_count_for_confusion,
            "fn": fn_count_for_confusion,
            "tn": tn_count,
            "support": tp_count + fp_count_for_confusion + fn_count_for_confusion + tn_count,
            "precision": _safe_div(tp_count, tp_count + fp_count_for_confusion),
            "recall": _safe_div(tp_count, tp_count + fn_count_for_confusion),
            "f1": (
                2 * _safe_div(tp_count, tp_count + fp_count_for_confusion)
                * _safe_div(tp_count, tp_count + fn_count_for_confusion)
                / (
                    _safe_div(tp_count, tp_count + fp_count_for_confusion)
                    + _safe_div(tp_count, tp_count + fn_count_for_confusion)
                )
                if tp_count
                else 0.0
            ),
            "correct_feedback_count": correct_feedback,
            "incorrect_feedback_count": incorrect_feedback,
            "feedback_error_rate": _safe_div(incorrect_feedback, feedback_count),
        })

    signal_feedback_performance.sort(
        key=lambda item: (item["feedback_error_rate"], item["support"]),
        reverse=True,
    )

    summary.update({
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
        "false_positive_by_signal": sorted(
            false_positive_by_signal,
            key=lambda item: item["false_positive_count"],
            reverse=True,
        ),
        "false_negative_by_signal": sorted(
            false_negative_by_signal,
            key=lambda item: item["false_negative_count"],
            reverse=True,
        ),
        "signal_feedback_performance": signal_feedback_performance,
        "false_positive_samples": false_positive_samples,
        "false_negative_samples": false_negative_samples,
    })
    return summary


def _bucket_label(bucket_start: int, bucket_seconds: int) -> str:
    if bucket_seconds >= 86400:
        return datetime.fromtimestamp(bucket_start, tz=timezone.utc).strftime("%Y-%m-%d")
    if bucket_seconds >= 3600:
        return datetime.fromtimestamp(bucket_start, tz=timezone.utc).strftime("%Y-%m-%d %H:00")
    return datetime.fromtimestamp(bucket_start, tz=timezone.utc).strftime("%Y-%m-%d %H:%M")


def summarize_feedback_trend(
    rows: Iterable[Dict[str, Any]],
    *,
    source_channel: Optional[str] = None,
    since_ts: Optional[int] = None,
    until_ts: Optional[int] = None,
    bucket_size_days: int = 1,
    include_uncertain: bool = False,
    min_bucket_support: int = 1,
    top_signals: int = 10,
    min_signal_support: int = 1,
) -> Dict[str, Any]:
    bucket_days = max(1, _coerce_positive_int(bucket_size_days, 1))
    bucket_seconds = bucket_days * 86400
    source_filter = str(source_channel).strip() if source_channel is not None else None

    candidate_rows = []
    for row in rows:
        if not isinstance(row, dict):
            continue

        record_source = str(row.get("source_channel") or "").strip()
        if source_filter is not None and record_source != source_filter:
            continue

        row_timestamp = _coerce_feedback_ts(row.get("timestamp"))
        if row_timestamp is None:
            continue

        if since_ts is not None and row_timestamp < since_ts:
            continue
        if until_ts is not None and row_timestamp > until_ts:
            continue

        row_copy = dict(row)
        row_copy.setdefault("timestamp", row_timestamp)
        candidate_rows.append(row_copy)

    if not candidate_rows:
        return {
            "items_evaluated": 0,
            "labeled_items": 0,
            "bucket_size_days": bucket_days,
            "bucket_count": 0,
            "buckets": [],
            "signal_trends": [],
            "overall": {
                "precision": 0.0,
                "recall": 0.0,
                "f1": 0.0,
                "accuracy": 0.0,
                "confusion_matrix": {"tp": 0, "fp": 0, "fn": 0, "tn": 0},
            },
        }

    rows_by_bucket: Dict[int, Dict[str, Any]] = {}
    per_signal_stats: Dict[str, Dict[int, Dict[str, int]]] = {}

    for row in candidate_rows:
        actual = _coerce_optional_bool(row.get("actual_is_scam"))
        predicted = _coerce_optional_bool(row.get("predicted_is_scam"))
        feedback = (str(row.get("feedback") or "")).strip().lower()
        if not feedback:
            feedback = "uncertain"
        if feedback == "uncertain" and not include_uncertain:
            continue

        if actual is None and predicted is None:
            continue

        if actual is None:
            actual = _feedback_to_actual(feedback, predicted)

        ts = _coerce_feedback_ts(row.get("timestamp"))
        if ts is None:
            continue
        bucket_start = (ts // bucket_seconds) * bucket_seconds

        bucket = rows_by_bucket.setdefault(
            bucket_start,
            {
                "bucket_start": bucket_start,
                "items": 0,
                "labeled_items": 0,
                "tp": 0,
                "fp": 0,
                "fn": 0,
                "tn": 0,
            },
        )

        bucket["items"] += 1

        if actual is None or predicted is None:
            continue

        bucket["labeled_items"] += 1
        if predicted and actual:
            bucket["tp"] += 1
        elif predicted and not actual:
            bucket["fp"] += 1
        elif (not predicted) and actual:
            bucket["fn"] += 1
        else:
            bucket["tn"] += 1

        signal_ids = _coerce_signal_list(row.get("signal_ids"))
        for signal in signal_ids:
            signal_bucket = per_signal_stats.setdefault(
                signal,
                {},
            )
            signal_row = signal_bucket.setdefault(
                bucket_start,
                {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "labeled": 0},
            )
            signal_row["labeled"] += 1
            if predicted and actual:
                signal_row["tp"] += 1
            elif predicted and not actual:
                signal_row["fp"] += 1
            elif (not predicted) and actual:
                signal_row["fn"] += 1
            else:
                signal_row["tn"] += 1

    if not rows_by_bucket:
        return {
            "items_evaluated": len(candidate_rows),
            "labeled_items": 0,
            "bucket_size_days": bucket_days,
            "bucket_count": 0,
            "buckets": [],
            "signal_trends": [],
            "overall": {
                "precision": 0.0,
                "recall": 0.0,
                "f1": 0.0,
                "accuracy": 0.0,
                "confusion_matrix": {"tp": 0, "fp": 0, "fn": 0, "tn": 0},
            },
        }

    ordered_buckets = sorted(rows_by_bucket.keys())
    min_bucket_rows = max(1, _coerce_positive_int(min_bucket_support, 1))

    bucket_summaries: List[Dict[str, Any]] = []
    for bucket_start in ordered_buckets:
        bucket = rows_by_bucket[bucket_start]
        total_rows = int(bucket.get("items", 0) or 0)
        labeled = int(bucket.get("labeled_items", 0) or 0)
        if total_rows < min_bucket_rows:
            continue

        tp = int(bucket.get("tp", 0) or 0)
        fp = int(bucket.get("fp", 0) or 0)
        fn = int(bucket.get("fn", 0) or 0)
        tn = int(bucket.get("tn", 0) or 0)
        precision = _safe_div(tp, tp + fp)
        recall = _safe_div(tp, tp + fn)
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
        accuracy = _safe_div(tp + tn, labeled)

        bucket_summaries.append({
            "bucket_start": bucket_start,
            "bucket_label": _bucket_label(bucket_start, bucket_seconds),
            "bucket_end": bucket_start + bucket_seconds,
            "items": total_rows,
            "labeled_items": labeled,
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "accuracy": accuracy,
            "false_positive_rate": _safe_div(fp, labeled),
            "false_negative_rate": _safe_div(fn, labeled),
        })

    overall = _build_confusion_from_rows(list(candidate_rows))

    max_signals = max(0, _coerce_positive_int(top_signals, 10))
    min_signal_rows = max(0, _coerce_positive_int(min_signal_support, 1))

    signal_trends: List[Dict[str, Any]] = []
    for signal, signal_buckets in per_signal_stats.items():
        ordered_signal_buckets = sorted(signal_buckets.keys())
        signal_total = 0
        for bucket_start in ordered_signal_buckets:
            signal_total += signal_buckets[bucket_start].get("labeled", 0)

        if signal_total < min_signal_rows:
            continue

        def _bucket_rates(bucket_row: Dict[str, int]) -> tuple[float, float]:
            lbl = int(bucket_row.get("labeled", 0) or 0)
            fp_rate = _safe_div(int(bucket_row.get("fp", 0) or 0), lbl)
            fn_rate = _safe_div(int(bucket_row.get("fn", 0) or 0), lbl)
            return fp_rate, fn_rate

        first = None
        last = None
        first_bucket = None
        last_bucket = None

        for bucket_start in ordered_signal_buckets:
            if signal_buckets[bucket_start].get("labeled", 0) <= 0:
                continue
            if first is None:
                first = bucket_start
                first_bucket = signal_buckets[bucket_start]
            last = bucket_start
            last_bucket = signal_buckets[bucket_start]

        if first is None or last is None or first_bucket is None or last_bucket is None:
            continue

        first_fp, first_fn = _bucket_rates(first_bucket)
        last_fp, last_fn = _bucket_rates(last_bucket)
        fp_shift = last_fp - first_fp
        fn_shift = last_fn - first_fn
        drift_score = max(abs(fp_shift), abs(fn_shift))

        signal_trends.append({
            "signal": signal,
            "support": signal_total,
            "first_bucket": first,
            "last_bucket": last,
            "first_fp_rate": first_fp,
            "first_fn_rate": first_fn,
            "latest_fp_rate": last_fp,
            "latest_fn_rate": last_fn,
            "fp_rate_shift": fp_shift,
            "fn_rate_shift": fn_shift,
            "drift_score": drift_score,
            "trend": (
                "worsening"
                if drift_score > 0 and (last_fp > first_fp or last_fn > first_fn)
                else "improving"
                if drift_score > 0
                else "stable"
            ),
        })

    signal_trends.sort(key=lambda item: item["drift_score"], reverse=True)
    if max_signals:
        signal_trends = signal_trends[:max_signals]

    return {
        "items_evaluated": len(candidate_rows),
        "labeled_items": int(overall.get("confusion_matrix", {}).get("tp", 0))
        + int(overall.get("confusion_matrix", {}).get("fp", 0))
        + int(overall.get("confusion_matrix", {}).get("fn", 0))
        + int(overall.get("confusion_matrix", {}).get("tn", 0)),
        "bucket_size_days": bucket_days,
        "bucket_count": len(bucket_summaries),
        "buckets": bucket_summaries,
        "signal_trends": signal_trends,
        "overall": {
            "precision": overall["precision"],
            "recall": overall["recall"],
            "f1": overall["f1"],
            "accuracy": overall["accuracy"],
            "confusion_matrix": overall["confusion_matrix"],
        },
    }
