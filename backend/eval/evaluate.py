#!/usr/bin/env python3
"""Run empiric evaluation on labeled messages (precision/recall/F1 + false-positive tracking)."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Dict, List, Tuple


ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from services.pii_redactor import redact_pii
from main import (
    _normalise_obfuscated_text,
    _safe_scan_url_list,
    _gather_external_intel,
    extract_urls,
    _collect_signal_ids,
    engine,
)


def _coerce_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        norm = value.strip().lower()
        if norm in {"1", "true", "t", "yes", "y", "scam", "malicious"}:
            return True
        if norm in {"0", "false", "f", "no", "n", "safe", "benign"}:
            return False
    return None


def _default_dataset_path() -> Path:
    return ROOT_DIR / "data" / "eval_dataset.jsonl"


def _derive_prediction(risk_score: int, risk_level: str, threshold: int) -> bool:
    if threshold is not None:
        return risk_score >= threshold
    return risk_level in {"medium", "high", "critical"}


def _load_dataset_records(dataset_path: Path, max_rows: int | None = None) -> List[Dict[str, Any]]:
    if not dataset_path.is_absolute():
        candidate = ROOT_DIR / dataset_path
        if candidate.exists():
            dataset_path = candidate
    if not dataset_path.exists():
        raise FileNotFoundError(f"Dataset missing: {dataset_path}")

    rows: List[Dict[str, Any]] = []
    seen_case_ids: set[str] = set()
    with dataset_path.open("r", encoding="utf-8") as f:
        for raw_line in f:
            text = raw_line.strip()
            if not text:
                continue
            record = json.loads(text)
            if not isinstance(record, dict):
                continue
            record_id = str(record.get("id") or "")
            if record_id:
                if record_id in seen_case_ids:
                    continue
                seen_case_ids.add(record_id)
            rows.append(record)
            if max_rows and len(rows) >= max_rows:
                break
    return rows


def _evaluate_record_core(
    record: Dict[str, Any],
    disable_redirects: bool,
    disable_reputation: bool,
) -> Dict[str, Any]:
    record_id = str(record.get("id") or record.get("case_id") or "unknown")
    kind = (record.get("kind") or "text").lower()

    raw_input = ""
    if kind == "url":
        raw_input = str(record.get("url") or "").strip()
    else:
        raw_input = str(record.get("text") or "").strip()

    if not raw_input:
        return {
            "id": record_id,
            "error": "empty_input",
            "actual_is_scam": None,
        }

    normalized_text = _normalise_obfuscated_text(raw_input)
    redacted_text = redact_pii(normalized_text)
    urls = extract_urls(redacted_text) if kind in {"text", "email", "html"} else ([redacted_text] if redacted_text else [])

    if disable_redirects:
        resolved_urls = [{"final_url": url, "url": url} for url in urls]
    else:
        resolved_urls = _safe_scan_url_list(urls)

    external_threat_intel = {}
    if not disable_reputation:
        external_threat_intel = _gather_external_intel(resolved_urls)

    analysis = engine.analyze(
        redacted_text,
        urls=resolved_urls,
        external_threat_intel=external_threat_intel,
    )

    risk_score = int(analysis.get("risk_score", 0))
    risk_level = str(analysis.get("risk_level", "unknown")).lower()
    signal_ids = _collect_signal_ids(analysis)

    expected = record.get("is_scam")
    if expected is None:
        expected = _coerce_bool(record.get("label"))
    elif isinstance(expected, str):
        expected = _coerce_bool(expected)

    return {
        "id": record_id,
        "kind": kind,
        "source": record.get("source"),
        "actual_is_scam": expected,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "signal_ids": signal_ids,
        "reasons_count": len(analysis.get("reasons", [])),
        "detected_family_id": analysis.get("detected_family_id"),
        "detected_family": analysis.get("detected_family"),
    }


def _evaluate_record(
    record: Dict[str, Any],
    risk_threshold: int,
    disable_redirects: bool,
    disable_reputation: bool,
) -> Dict[str, Any]:
    row = _evaluate_record_core(
        record,
        disable_redirects=disable_redirects,
        disable_reputation=disable_reputation,
    )
    predicted = _derive_prediction(
        int(row.get("risk_score", 0)),
        str(row.get("risk_level", "unknown")).lower(),
        risk_threshold,
    )
    row["predicted_is_scam"] = bool(predicted)
    return row


def _safe_div(num: float, denom: float) -> float:
    return num / denom if denom else 0.0


def _build_metrics(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    tp = fp = fn = tn = 0
    false_positive_rows: List[Dict[str, Any]] = []
    false_negative_rows: List[Dict[str, Any]] = []
    per_signal_fp: Dict[str, int] = {}
    per_signal_fn: Dict[str, int] = {}
    by_kind = {"text": 0, "url": 0, "email": 0, "unknown": 0}

    for row in rows:
        if "error" in row:
            continue
        actual = row.get("actual_is_scam")
        if actual is None:
            continue
        if not isinstance(actual, bool):
            continue

        by_kind[row.get("kind", "unknown")] = by_kind.get(row.get("kind", "unknown"), 0) + 1
        predicted = row["predicted_is_scam"]

        if predicted and actual:
            tp += 1
        elif predicted and not actual:
            fp += 1
            false_positive_rows.append(row)
            for signal in row.get("signal_ids", []):
                if isinstance(signal, str):
                    per_signal_fp[signal] = per_signal_fp.get(signal, 0) + 1
        elif not predicted and actual:
            fn += 1
            false_negative_rows.append(row)
            for signal in row.get("signal_ids", []):
                if isinstance(signal, str):
                    per_signal_fn[signal] = per_signal_fn.get(signal, 0) + 1
        else:
            tn += 1

    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1 = _safe_div(2 * precision * recall, precision + recall)
    accuracy = _safe_div(tp + tn, tp + fp + fn + tn)
    labeled = len([row for row in rows if "actual_is_scam" in row and isinstance(row["actual_is_scam"], bool)])

    top_fp_signals = sorted(
        (
            {"signal": signal, "count": count}
            for signal, count in per_signal_fp.items()
        ),
        key=lambda item: item["count"],
        reverse=True,
    )
    top_fn_signals = sorted(
        (
            {"signal": signal, "count": count}
            for signal, count in per_signal_fn.items()
        ),
        key=lambda item: item["count"],
        reverse=True,
    )

    return {
        "total": len([row for row in rows if "actual_is_scam" in row and isinstance(row["actual_is_scam"], bool)]),
        "labeled": labeled,
        "confusion_matrix": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
        "by_kind": by_kind,
        "false_positives": false_positive_rows[:200],
        "false_negatives": false_negative_rows[:200],
        "top_false_positive_signals": top_fp_signals,
        "top_false_negative_signals": top_fn_signals,
    }


def run_threshold_sweep(
    dataset_path: Path,
    disable_redirects: bool = False,
    disable_reputation: bool = False,
    sweep_start: int = 0,
    sweep_end: int = 100,
    sweep_step: int = 5,
    optimize_metric: str = "f1",
    max_rows: int | None = None,
) -> Dict[str, Any]:
    if sweep_step <= 0:
        raise ValueError("sweep_step must be > 0")
    if sweep_end < sweep_start:
        raise ValueError("sweep_end must be >= sweep_start")

    base_records = [
        _evaluate_record_core(record, disable_redirects, disable_reputation)
        for record in _load_dataset_records(dataset_path, max_rows=max_rows)
    ]

    thresholds = list(range(sweep_start, sweep_end + 1, sweep_step))
    if thresholds[-1] != sweep_end:
        thresholds.append(sweep_end)

    candidates: List[Dict[str, Any]] = []
    for threshold in thresholds:
        rows = []
        for base_row in base_records:
            row = dict(base_row)
            row["predicted_is_scam"] = _derive_prediction(
                int(row.get("risk_score", 0)),
                str(row.get("risk_level", "unknown")).lower(),
                threshold,
            )
            rows.append(row)

        metrics = _build_metrics(rows)
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
        "dataset_path": str(dataset_path),
        "items_evaluated": len(base_records),
        "options": {
            "sweep_start": sweep_start,
            "sweep_end": sweep_end,
            "sweep_step": sweep_step,
            "optimize_metric": metric,
            "disable_redirects": disable_redirects,
            "disable_reputation": disable_reputation,
        },
        "candidates": candidates,
        "best": candidates_sorted[0],
    }


def run_evaluation(
    dataset_path: Path,
    risk_threshold: int = 50,
    max_rows: int | None = None,
    disable_redirects: bool = False,
    disable_reputation: bool = False,
) -> Dict[str, Any]:
    records = _load_dataset_records(dataset_path, max_rows=max_rows)

    evaluated: List[Dict[str, Any]] = []
    for record in records:
        try:
            evaluated.append(
                _evaluate_record(
                    record,
                    risk_threshold=risk_threshold,
                    disable_redirects=disable_redirects,
                    disable_reputation=disable_reputation,
                )
            )
        except Exception as exc:
            evaluated.append(
                {
                    "id": str(record.get("id") or "unknown"),
                    "error": str(exc),
                    "predicted_is_scam": False,
                    "actual_is_scam": _coerce_bool(record.get("is_scam") or record.get("label")),
                }
            )

    metrics = _build_metrics(evaluated)
    return {
        "dataset_path": str(dataset_path),
        "items_evaluated": len(evaluated),
        "options": {
            "risk_threshold": risk_threshold,
            "disable_redirects": disable_redirects,
            "disable_reputation": disable_reputation,
        },
        "rows": evaluated,
        "metrics": metrics,
    }


def _write_output(result: Dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate ScamShield on labeled message set.")
    parser.add_argument(
        "--dataset",
        default=str(_default_dataset_path()),
        help="Path to JSONL dataset file.",
    )
    parser.add_argument("--risk-threshold", type=int, default=50, help="Risk score threshold for positive scam.")
    parser.add_argument("--max-items", type=int, default=None, help="Evaluate only first N items.")
    parser.add_argument("--disable-redirects", action="store_true", help="Skip network URL resolution.")
    parser.add_argument("--disable-reputation", action="store_true", help="Skip external URL reputation calls.")
    parser.add_argument("--sweep", action="store_true", help="Run a threshold sweep and show best threshold.")
    parser.add_argument("--sweep-start", type=int, default=0, help="Threshold sweep start.")
    parser.add_argument("--sweep-end", type=int, default=100, help="Threshold sweep end.")
    parser.add_argument("--sweep-step", type=int, default=5, help="Threshold sweep step.")
    parser.add_argument(
        "--sweep-metric",
        default="f1",
        choices=["f1", "precision", "recall", "accuracy"],
        help="Metric used to pick best threshold.",
    )
    parser.add_argument("--output", default="", help="Optional JSON output file path.")
    args = parser.parse_args()

    threshold_for_eval = args.risk_threshold
    result = run_evaluation(
        Path(args.dataset),
        risk_threshold=threshold_for_eval,
        max_rows=args.max_items,
        disable_redirects=args.disable_redirects,
        disable_reputation=args.disable_reputation,
    )
    if args.sweep:
        sweep = run_threshold_sweep(
            Path(args.dataset),
            disable_redirects=args.disable_redirects,
            disable_reputation=args.disable_reputation,
            sweep_start=args.sweep_start,
            sweep_end=args.sweep_end,
            sweep_step=args.sweep_step,
            optimize_metric=args.sweep_metric,
            max_rows=args.max_items,
        )
        result["threshold_sweep"] = sweep
        threshold_for_eval = sweep["best"]["risk_threshold"]
        result = run_evaluation(
            Path(args.dataset),
            risk_threshold=threshold_for_eval,
            max_rows=args.max_items,
            disable_redirects=args.disable_redirects,
            disable_reputation=args.disable_reputation,
        )
        result["threshold_sweep"] = sweep

    metrics = result["metrics"]
    print(f"Evaluat {result['items_evaluated']} inregistrari din {result['dataset_path']}")
    print(f"Using risc_threshold={threshold_for_eval}")
    print(
        f"Precision={metrics['precision']:.3f} Recall={metrics['recall']:.3f} "
        f"F1={metrics['f1']:.3f} Accuracy={metrics['accuracy']:.3f}"
    )
    print(
        f"Confusion: TP={metrics['confusion_matrix']['tp']} "
        f"FP={metrics['confusion_matrix']['fp']} FN={metrics['confusion_matrix']['fn']} "
        f"TN={metrics['confusion_matrix']['tn']}"
    )
    if metrics["top_false_positive_signals"]:
        print("Top semnale in false positives:")
        for item in metrics["top_false_positive_signals"][:5]:
            print(f"- {item['signal']}: {item['count']}")

    if args.sweep:
        best = result["threshold_sweep"]["best"]
        print(f"\nThreshold sweep ({args.sweep_metric}) - best: {best['risk_threshold']}")
        print(f"  F1={best['f1']:.3f} P={best['precision']:.3f} R={best['recall']:.3f} A={best['accuracy']:.3f}")
        print("Top candidates:")
        for candidate in sorted(result["threshold_sweep"]["candidates"], key=lambda item: item["risk_threshold"])[:5]:
            print(
                f"  - t={candidate['risk_threshold']} | "
                f"F1={candidate['f1']:.3f} P={candidate['precision']:.3f} "
                f"R={candidate['recall']:.3f} A={candidate['accuracy']:.3f}"
            )

    if args.output:
        _write_output(result, Path(args.output))


if __name__ == "__main__":
    main()
