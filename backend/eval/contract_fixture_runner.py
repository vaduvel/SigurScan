#!/usr/bin/env python3
"""Evaluate strict Romania decision fixtures through the pure Verdict Gate v2.

This runner intentionally does not translate scam-atlas research fields into a
verdict. Each row must already contain a normalized Evidence Bundle. The only
judge is ``services.verdict_gate.verdict``.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


BACKEND_DIR = Path(__file__).resolve().parents[1]
REPO_DIR = BACKEND_DIR.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from services.verdict_gate import verdict  # noqa: E402


DEFAULT_DATASET = BACKEND_DIR / "data" / "eval" / "romania_decision_contract_eval_v2026_06_08.jsonl"


def _load_cases(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def _bundle_from_case(case: dict[str, Any]) -> dict[str, Any]:
    bundle = case.get("evidence_bundle")
    if not isinstance(bundle, dict):
        raise ValueError(f"{case.get('id') or '<missing-id>'}: missing evidence_bundle")
    return bundle


def run(dataset: Path) -> dict[str, Any]:
    rows = []
    for case in _load_cases(dataset):
        actual = verdict(_bundle_from_case(case))
        expected = str(case.get("expected_contract_label") or "").upper()
        rows.append(
            {
                "id": case.get("id"),
                "expected": expected,
                "actual": actual["label"],
                "passed": actual["label"] == expected,
                "reason_codes": actual.get("reason_codes") or [],
            }
        )
    failures = [row for row in rows if not row["passed"]]
    return {
        "dataset": str(dataset),
        "total": len(rows),
        "passed": len(rows) - len(failures),
        "failed": len(failures),
        "expected_counts": dict(Counter(row["expected"] for row in rows)),
        "actual_counts": dict(Counter(row["actual"] for row in rows)),
        "failures": failures,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Evidence Bundle fixtures through Verdict Gate v2.")
    parser.add_argument("--dataset", default=str(DEFAULT_DATASET))
    parser.add_argument("--output")
    parser.add_argument("--max-failures", type=int, default=0)
    args = parser.parse_args()

    report = run(Path(args.dataset))
    if args.output:
        output = Path(args.output)
        if not output.is_absolute():
            output = REPO_DIR / output
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    print(json.dumps({key: report[key] for key in ("dataset", "total", "passed", "failed", "expected_counts", "actual_counts")}, ensure_ascii=False, indent=2))
    return 1 if report["failed"] > args.max_failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
