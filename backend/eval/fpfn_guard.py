#!/usr/bin/env python3
"""FP/FN rate guard (R7-rest) — the safety net for verdict-touching changes.

Runs a committed, generic-path (SMS/text) corpus through the same offline
provider gate as large_offline_fixture_runner and measures:

- **false-PERICOL** — a BENIGN message flagged DANGEROUS. The project's cardinal
  sin (the Altex saga). Hard gate: must stay 0.
- **missed scam (FN)** — a SCAM message passed as SAFE. Hard gate: must stay 0.
- **scam_caught_rate** — fraction of scams reaching DANGEROUS (soft floor).

Why generic-path only: the offline runner stubs ANAF/CUI as unavailable, which
distorts invoice-routed cases (they can't be verified offline). The generic path
has no such dependency, so its offline verdict matches production — making it a
faithful, deterministic FP/FN signal. Invoice-route FP is already guarded by the
dedicated Altex tests (#116); rate-tracking it needs a live-CUI harness (later).

The corpus deliberately covers the FP-risk classes of the upcoming
verdict-touching sprints: benign phone<->IBAN co-occurrence (D6), benign use of
scam-adjacent morphology (P-MORPH-WIRE), benign call/number mentions (D3).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

CORPUS_PATH = BACKEND_DIR / "eval" / "fpfn_guard_corpus_ro.jsonl"

# Soft floor: at least this fraction of scams must reach DANGEROUS. Well below the
# current baseline so honest corpus growth (harder cases) never trips it; a real
# detection regression does.
MIN_SCAM_CAUGHT_RATE = 0.80


def _collapse(label: str) -> str:
    # UNVERIFIED == "needs verification" == the SUSPECT/VERIFY middle ground.
    return "SUSPECT" if str(label).upper() == "UNVERIFIED" else str(label).upper()


def load_corpus() -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for line in CORPUS_PATH.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        obj = json.loads(line)
        if "_meta" in obj:
            continue
        rows.append(obj)
    return rows


def evaluate_corpus(corpus: List[Dict[str, Any]] | None = None) -> List[Dict[str, Any]]:
    from eval.large_offline_fixture_runner import _run_case

    corpus = corpus if corpus is not None else load_corpus()
    out: List[Dict[str, Any]] = []
    for item in corpus:
        expected = "SAFE" if item["label"] == "BENIGN" else "DANGEROUS"
        result = _run_case({
            "source": "fpfn_guard",
            "id": item["id"],
            "expected": expected,
            "meta": {"channel": item.get("channel")},
            "text": item["text"],
        })
        out.append({
            "id": item["id"],
            "label": item["label"],
            "class": item.get("class"),
            "actual": _collapse(result["actual"]),
        })
    return out


def compute_metrics(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    benign = [r for r in rows if r["label"] == "BENIGN"]
    scam = [r for r in rows if r["label"] == "SCAM"]
    false_pericol = [r for r in benign if r["actual"] == "DANGEROUS"]
    missed_scam = [r for r in scam if r["actual"] == "SAFE"]
    scam_caught = [r for r in scam if r["actual"] == "DANGEROUS"]
    nb, ns = max(1, len(benign)), max(1, len(scam))
    return {
        "benign_total": len(benign),
        "scam_total": len(scam),
        "false_pericol_count": len(false_pericol),
        "false_pericol_rate": round(len(false_pericol) / nb, 4),
        "missed_scam_count": len(missed_scam),
        "missed_scam_rate": round(len(missed_scam) / ns, 4),
        "scam_caught_rate": round(len(scam_caught) / ns, 4),
        "false_pericol_examples": [r["id"] for r in false_pericol],
        "missed_scam_examples": [r["id"] for r in missed_scam],
    }


def run() -> Dict[str, Any]:
    rows = evaluate_corpus()
    metrics = compute_metrics(rows)
    return {"metrics": metrics, "rows": rows}


def main() -> int:
    report = run()
    metrics = report["metrics"]
    out = BACKEND_DIR.parent / "build" / "reports" / "fpfn_guard.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(metrics, ensure_ascii=False, indent=2))
    print(f"wrote {out}")
    # Same gates as the pytest guard, so the CI artifact job also fails on regression.
    ok = (
        metrics["false_pericol_count"] == 0
        and metrics["missed_scam_count"] == 0
        and metrics["scam_caught_rate"] >= MIN_SCAM_CAUGHT_RATE
    )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
