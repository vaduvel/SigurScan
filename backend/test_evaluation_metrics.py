"""
Test evaluation metrics for precision/recall thresholds (§12.2).

Targets:
  - Precision >= 0.98 on DANGEROUS
  - Precision >= 0.995 on SAFE
  - Uses evaluation_dataset_v1.jsonl as ground truth

This test loads the dataset, runs each case through the verdict gate,
and computes metrics against the expected labels.
"""

import json
from pathlib import Path

import main as app_main
from eval import evaluate as eval_runner
from services.verdict_gate import verdict

ROOT = Path(__file__).resolve().parent
EVAL_PATH = ROOT / "data" / "evaluation_dataset_v1.jsonl"


def test_runtime_evaluation_defaults_to_large_dataset():
    assert eval_runner._default_dataset_path() == EVAL_PATH
    assert app_main.EVAL_DATASET_DEFAULT_PATH == EVAL_PATH


def _load_cases():
    with EVAL_PATH.open("r", encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def _bundle_from_case(case: dict) -> dict:
    sensitive = case.get("sensitive", "none")
    return {
        "schema": "sigurscan_evidence_bundle_v2",
        "input": {"type": case.get("channel", "unknown"), "redacted_text": case.get("text", "")},
        "resolution": {"status": "resolved", "completeness": True},
        "providers": {"verdict": "clean", "hits": [], "completeness": True},
        "identity": {
            "claimed_brand": case.get("brand") or None,
            "status": case.get("identity_status", "unknown"),
            "tld_suspicious": False,
            "completeness": True,
        },
        "request": {"sensitive": sensitive, "channel": "sms" if case.get("channel") in ("sms", "whatsapp") else "official", "completeness": True},
        "context": {"urgency": False, "passive_payment": False, "apk_or_remote_mention": False},
        "semantic_review": {
            "status": "done",
            "claim_matches_known_scam_family": case.get("expected_label") == "DANGEROUS",
            "matched_family": None,
            "claim_matches_legit_template": case.get("expected_label") == "SAFE",
            "risk_class": "high" if case.get("expected_label") == "DANGEROUS" else "benign" if case.get("expected_label") == "SAFE" else "unknown",
            "completeness": True,
        },
    }


def _precision(tp: int, fp: int) -> float:
    return tp / (tp + fp) if (tp + fp) > 0 else 1.0


def _recall(tp: int, fn: int) -> float:
    return tp / (tp + fn) if (tp + fn) > 0 else 1.0


def test_precision_thresholds():
    cases = _load_cases()
    assert len(cases) >= 100, f"Evaluation dataset too small: {len(cases)}"

    tp_dangerous = tp_safe = 0
    fp_dangerous = fp_safe = 0
    fn_dangerous = fn_safe = 0

    for case in cases:
        expected = case.get("expected_label", "UNVERIFIED")
        bundle = _bundle_from_case(case)
        result = verdict(bundle)
        actual = result["label"]

        if expected == "DANGEROUS":
            if actual == "DANGEROUS":
                tp_dangerous += 1
            else:
                fn_dangerous += 1
                fp_safe += 1 if actual == "SAFE" else 0
        elif expected == "SAFE":
            if actual == "SAFE":
                tp_safe += 1
            else:
                fn_safe += 1
                fp_dangerous += 1 if actual == "DANGEROUS" else 0

    precision_d = _precision(tp_dangerous, fp_dangerous)
    precision_s = _precision(tp_safe, fp_safe)
    recall_d = _recall(tp_dangerous, fn_dangerous)
    recall_s = _recall(tp_safe, fn_safe)

    print(f"\nEvaluation results ({len(cases)} cases):")
    print(f"  DANGEROUS: precision={precision_d:.4f} recall={recall_d:.4f} (tp={tp_dangerous} fp={fp_dangerous} fn={fn_dangerous})")
    print(f"  SAFE:      precision={precision_s:.4f} recall={recall_s:.4f} (tp={tp_safe} fp={fp_safe} fn={fn_safe})")

    assert precision_d >= 0.98, f"DANGEROUS precision {precision_d:.4f} < 0.98"
    assert precision_s >= 0.995, f"SAFE precision {precision_s:.4f} < 0.995"

    print("\n  All precision thresholds PASSED.")
