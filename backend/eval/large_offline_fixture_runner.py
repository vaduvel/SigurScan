#!/usr/bin/env python3
"""Run the broad local SigurScan fixture corpus through the offline provider gate.

This runner intentionally does not call live providers or cloud LLMs. It is a
local regression radar: atlas/engine analysis + production decision gate, with
URLs represented as already-resolved to themselves.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List


BACKEND_DIR = Path(__file__).resolve().parents[1]
REPO_DIR = BACKEND_DIR.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from main import (  # noqa: E402
    _apply_provider_gate_verdict,
    _canonicalize_url,
    _looks_like_structured_invoice_text,
    _normalise_obfuscated_text,
    engine,
    extract_urls,
)
from services.pii_redactor import redact_pii  # noqa: E402


DEFAULT_ZIPS = [
    "sigurscan_adversarial_negation_contrastive_ro_2026_06_17.zip",
    "sigurscan_imm_b2b_invoice_fraud_pack_2026_06_15.zip",
    "sigurscan_imm_b2b_invoice_fraud_round2_2026_06_15.zip",
    "sigurscan_imm_b2b_invoice_fraud_round3_2026_06_15.zip",
    "sigurscan_real_scam_cases_ro_2026_round1.zip",
    "sigurscan_real_scam_cases_ro_2026_round2_b2b_invoice.zip",
    "sigurscan_real_b2b_scam_cases_ro_eu_2026_round3_98_cases.zip",
    "sigurscan_novel_zero_day_holdout_ro_2026_06_18.zip",
    "sigurscan_ro_research_test_pack_2025_2026_v1.zip",
    "sigurscan_romania_minor_scam_families_addendum_2025_2026.zip",
]


def _map_expected(value: Any) -> str:
    text = str(value or "").strip().upper()
    aliases = {
        "PERICULOS": "DANGEROUS",
        "DANGEROUS": "DANGEROUS",
        "NU_PLATI": "DANGEROUS",
        "NO_REPLY": "DANGEROUS",
        "NO_ENTER_DATA": "DANGEROUS",
        "DO_NOT_CONTINUE": "DANGEROUS",
        "SIGUR": "SAFE",
        "SAFE": "SAFE",
        "CONTINUE_WITH_CAUTION": "SAFE",
        "SUSPECT": "SUSPECT",
        "NEVERIFICAT": "UNVERIFIED",
        "UNVERIFIED": "UNVERIFIED",
        "VERIFY_OFFICIAL": "SUSPECT",
        "INSUFFICIENT_EVIDENCE": "UNVERIFIED",
        "VERIFICA": "SUSPECT",
        "VERIFICĂ": "SUSPECT",
    }
    return aliases.get(text, text if text in {"SAFE", "SUSPECT", "DANGEROUS", "UNVERIFIED"} else "")


def _comparable_label(label: str) -> str:
    return "SUSPECT" if label == "UNVERIFIED" else label


def _final_label(analysis: Dict[str, Any]) -> str:
    evidence = analysis.get("evidence") if isinstance(analysis.get("evidence"), dict) else {}
    gate = evidence.get("verdict_gate") if isinstance(evidence.get("verdict_gate"), dict) else {}
    label = str(analysis.get("user_risk_label") or gate.get("label") or "").upper()
    if label:
        return label
    risk = str(analysis.get("risk_level") or "").lower()
    if risk in {"critical", "dangerous", "high"}:
        return "DANGEROUS"
    if risk in {"medium", "warning", "unknown", "pending", "info", "unverified"}:
        return "SUSPECT"
    return "SAFE"


def _case(
    cases: List[Dict[str, Any]],
    *,
    source: str,
    case_id: Any,
    text: Any,
    expected: Any = "",
    meta: Dict[str, Any] | None = None,
) -> None:
    raw_text = str(text or "").strip()
    if not raw_text:
        return
    cases.append(
        {
            "source": source,
            "id": str(case_id or f"{source}-{len(cases) + 1}"),
            "text": raw_text,
            "expected": _map_expected(expected),
            "meta": meta or {},
        }
    )


def _repo_jsonl_cases(cases: List[Dict[str, Any]]) -> None:
    for rel in (
        "backend/data/evaluation_dataset_v1.jsonl",
        "backend/data/eval_dataset.jsonl",
        "backend/data/hard_eval.jsonl",
        "backend/data/verdict_testset_ro.jsonl",
    ):
        path = REPO_DIR / rel
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            item = json.loads(line)
            if rel.endswith("verdict_testset_ro.jsonl"):
                _case(
                    cases,
                    source=rel,
                    case_id=item.get("id"),
                    text=item.get("input"),
                    expected=item.get("label"),
                    meta={"family": item.get("family")},
                )
                continue
            expected = item.get("expected_label")
            if expected is None and "is_scam" in item:
                expected = "DANGEROUS" if item.get("is_scam") else "SAFE"
            if expected is None and "actual_is_scam" in item:
                expected = "DANGEROUS" if item.get("actual_is_scam") else "SAFE"
            _case(
                cases,
                source=rel,
                case_id=item.get("id"),
                text=item.get("text") or item.get("input") or item.get("url"),
                expected=expected,
                meta={"kind": item.get("kind"), "channel": item.get("channel")},
            )


def _web_redteam_cases(cases: List[Dict[str, Any]]) -> None:
    path = REPO_DIR / "backend/testdata/web_redteam_scam_fixtures_2026_06_16.json"
    if not path.exists():
        return
    payload = json.loads(path.read_text(encoding="utf-8"))
    rows = payload if isinstance(payload, list) else payload.get("cases") or payload.get("fixtures") or []
    for item in rows:
        if not isinstance(item, dict):
            continue
        _case(
            cases,
            source=str(path.relative_to(REPO_DIR)),
            case_id=item.get("id") or item.get("case_id"),
            text=item.get("text") or item.get("input") or item.get("message"),
            expected=item.get("expected_label") or item.get("expected_final_verdict") or "DANGEROUS",
        )


def _expected_from_item(item: Dict[str, Any]) -> Any:
    expected = (
        item.get("expected_final_verdict")
        or item.get("expected_verdict")
        or item.get("expected_label")
        or item.get("expected_user_action")
    )
    if isinstance(expected, list):
        return "DANGEROUS"
    return expected


def _text_from_item(item: Dict[str, Any]) -> Any:
    return (
        item.get("sample_text")
        or item.get("input_text")
        or item.get("text")
        or item.get("input")
        or item.get("message")
        or item.get("html_mime_fragment")
    )


def _zip_cases(cases: List[Dict[str, Any]], downloads_dir: Path, zip_names: Iterable[str]) -> None:
    for zip_name in zip_names:
        zip_path = downloads_dir / zip_name
        if not zip_path.exists():
            continue
        with zipfile.ZipFile(zip_path) as archive:
            for member in archive.namelist():
                if not member.endswith(".json"):
                    continue
                try:
                    payload = json.loads(archive.read(member).decode("utf-8", "ignore"))
                except Exception:
                    continue
                source = f"{zip_name}:{member}"
                if isinstance(payload, dict) and isinstance(payload.get("pairs"), list):
                    for pair in payload["pairs"]:
                        if not isinstance(pair, dict):
                            continue
                        for side, expected in (("safe_case", "SAFE"), ("scam_case", "DANGEROUS")):
                            side_payload = pair.get(side) or {}
                            _case(
                                cases,
                                source=source,
                                case_id=f"{pair.get('id')}-{side}",
                                text=side_payload.get("input_text"),
                                expected=side_payload.get("expected_final_verdict") or expected,
                                meta={"category": pair.get("category"), "side": side},
                            )
                    continue
                if isinstance(payload, dict):
                    handled = False
                    for key in ("acceptance_tests", "test_cases", "cases", "fixtures"):
                        rows = payload.get(key)
                        if not isinstance(rows, list):
                            continue
                        for item in rows:
                            if isinstance(item, dict):
                                _case(
                                    cases,
                                    source=source,
                                    case_id=item.get("test_id") or item.get("id") or item.get("case_id"),
                                    text=_text_from_item(item),
                                    expected=_expected_from_item(item),
                                    meta={"family": item.get("family") or item.get("family_id"), "input_type": item.get("input_type")},
                                )
                        handled = True
                        break
                    if not handled and member.endswith("/answer_key/cases.json"):
                        for case_id, item in payload.items():
                            if isinstance(item, dict):
                                _case(
                                    cases,
                                    source=source,
                                    case_id=item.get("id") or case_id,
                                    text=item.get("input_text"),
                                    expected=item.get("expected_final_verdict") or "DANGEROUS",
                                    meta={"family": item.get("family")},
                                )
                elif isinstance(payload, list):
                    for item in payload:
                        if isinstance(item, dict):
                            _case(
                                cases,
                                source=source,
                                case_id=item.get("test_id") or item.get("id") or item.get("case_id"),
                                text=_text_from_item(item),
                                expected=_expected_from_item(item),
                                meta={"family": item.get("family") or item.get("family_id"), "input_type": item.get("input_type")},
                            )


def load_cases(downloads_dir: Path, zip_names: Iterable[str]) -> List[Dict[str, Any]]:
    cases: List[Dict[str, Any]] = []
    _repo_jsonl_cases(cases)
    _web_redteam_cases(cases)
    _zip_cases(cases, downloads_dir, zip_names)

    seen: set[tuple[str, str, str]] = set()
    unique: List[Dict[str, Any]] = []
    for case in cases:
        key = (case["source"], case["id"], case["text"][:200])
        if key in seen:
            continue
        seen.add(key)
        unique.append(case)
    return unique


def _resolved_urls(text: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for url in extract_urls(text):
        canonical = _canonicalize_url(url) or url
        out.append({"url": canonical, "input_url": canonical, "final_url": canonical, "success": True, "status_code": 200})
    return out


def _source_channel(case: Dict[str, Any]) -> str:
    meta = case.get("meta") if isinstance(case.get("meta"), dict) else {}
    return str(meta.get("input_type") or meta.get("channel") or "offline_eval")


def _should_route_invoice_case(case: Dict[str, Any], text: str) -> bool:
    meta = case.get("meta") if isinstance(case.get("meta"), dict) else {}
    if str(meta.get("input_type") or "").lower() == "invoice":
        return True
    return _looks_like_structured_invoice_text(text)


async def _offline_unchecked_cui(cui: str, *, allow_paid_fallback: bool = False):
    from services.anaf_cui import CuiResult

    return CuiResult(
        exists=False,
        checked=False,
        denumire=None,
        activ=False,
        data_inactivare=None,
        platitor_tva=False,
        enrolled_efactura=False,
        raw=None,
        source="offline_eval",
    )


def _run_invoice_route(text: str, resolved: List[Dict[str, Any]], source_channel: str) -> Dict[str, Any]:
    """Evaluate structured invoice fixtures through the invoice reducer.

    The large runner is explicitly offline, so CUI/ANAF lookup is stubbed as
    unavailable. This keeps the report useful for reducer/gate regressions
    without spending live provider calls or turning network availability into
    a test result.
    """
    os.environ.setdefault("INVOICE_CACHE_HMAC_KEY", "offline-eval-key")
    from services import invoice_orchestrator

    original_cui_check = getattr(invoice_orchestrator, "_check_cui_for_invoice", None)
    invoice_orchestrator._check_cui_for_invoice = _offline_unchecked_cui
    try:
        invoice_result = asyncio.run(
            invoice_orchestrator.scan_invoice(
                text,
                links=[str(item.get("final_url") or item.get("url") or "") for item in resolved],
            )
        )
        invoice_gate = invoice_orchestrator.evaluate_invoice_verdict(
            invoice_result,
            text,
            source_channel=source_channel,
        )
    finally:
        if original_cui_check is not None:
            invoice_orchestrator._check_cui_for_invoice = original_cui_check

    gate_result = invoice_gate.get("gate") if isinstance(invoice_gate.get("gate"), dict) else {}
    invoice_truth = invoice_gate.get("invoice_truth") if isinstance(invoice_gate.get("invoice_truth"), dict) else {}
    return {
        "risk_level": gate_result.get("risk_level"),
        "risk_score": gate_result.get("risk_score"),
        "detected_family_id": "invoice",
        "evidence": {
            "provider_gate": {
                "reason": ", ".join(gate_result.get("reason_codes") or []),
                "label": gate_result.get("label"),
            },
            "verdict_gate": gate_result,
            "invoice_truth": invoice_truth,
        },
    }


def _run_case(case: Dict[str, Any]) -> Dict[str, Any]:
    analysis_text = _normalise_obfuscated_text(case["text"])
    redacted_text = redact_pii(analysis_text)
    route_text = analysis_text
    resolved = _resolved_urls(redacted_text)
    source_channel = _source_channel(case)
    route = "invoice" if _should_route_invoice_case(case, route_text) else "generic"
    if route == "invoice":
        final = _run_invoice_route(analysis_text, resolved, source_channel)
    else:
        analysis = engine.analyze(redacted_text, urls=resolved, external_threat_intel={})
        evidence = analysis.setdefault("evidence", {})
        evidence["source_channel"] = source_channel
        final = _apply_provider_gate_verdict(analysis, resolved, raw_text=redacted_text, pillars={})

    actual = _final_label(final)
    expected = case["expected"]
    passed = (_comparable_label(actual) == _comparable_label(expected)) if expected else None
    final_evidence = final.get("evidence") if isinstance(final.get("evidence"), dict) else {}
    provider_gate = final_evidence.get("provider_gate") if isinstance(final_evidence.get("provider_gate"), dict) else {}
    verdict_gate = final_evidence.get("verdict_gate") if isinstance(final_evidence.get("verdict_gate"), dict) else {}
    return {
        "source": case["source"],
        "id": case["id"],
        "expected": expected,
        "actual": actual,
        "passed": passed,
        "route": route,
        "risk_level": final.get("risk_level"),
        "risk_score": final.get("risk_score"),
        "detected_family_id": final.get("detected_family_id"),
        "gate_reason": provider_gate.get("reason"),
        "reason_codes": verdict_gate.get("reason_codes"),
        "text_preview": case["text"][:240],
    }


def run(downloads_dir: Path, zip_names: Iterable[str]) -> Dict[str, Any]:
    rows: List[Dict[str, Any]] = []
    for case in load_cases(downloads_dir, zip_names):
        try:
            rows.append(_run_case(case))
        except Exception as exc:
            rows.append(
                {
                    "source": case["source"],
                    "id": case["id"],
                    "expected": case["expected"],
                    "actual": "ERROR",
                    "passed": False,
                    "error": f"{type(exc).__name__}: {exc}",
                    "text_preview": case["text"][:240],
                }
            )

    labeled = [row for row in rows if row["expected"]]
    failures = [row for row in labeled if row["passed"] is False]
    confusion: Dict[str, Counter[str]] = defaultdict(Counter)
    for row in labeled:
        confusion[_comparable_label(row["expected"])][_comparable_label(row["actual"])] += 1

    by_source: Dict[str, Dict[str, int]] = defaultdict(lambda: {"total": 0, "labeled": 0, "failed": 0})
    for row in rows:
        bucket = by_source[row["source"]]
        bucket["total"] += 1
        bucket["labeled"] += 1 if row["expected"] else 0
        bucket["failed"] += 1 if row.get("passed") is False else 0

    return {
        "mode": "offline_provider_gate_invoice_route_no_live_providers_no_mistral",
        "total_cases": len(rows),
        "labeled_cases": len(labeled),
        "passed": len(labeled) - len(failures),
        "failed": len(failures),
        "route_counts": dict(Counter(row.get("route") or "error" for row in rows)),
        "actual_counts": dict(Counter(row["actual"] for row in rows)),
        "expected_counts": dict(Counter(row["expected"] for row in labeled)),
        "confusion": {key: dict(value) for key, value in confusion.items()},
        "by_source": dict(sorted(by_source.items(), key=lambda item: (-item[1]["failed"], -item[1]["total"]))),
        "top_failed_family_ids": dict(Counter(row.get("detected_family_id") or "unknown" for row in failures).most_common(30)),
        "failures_sample": failures[:200],
        "rows": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run large offline SigurScan fixture corpus through provider gate.")
    parser.add_argument("--downloads-dir", default="/Users/vaduvageorge/Downloads")
    parser.add_argument("--output", default="build/reports/large_eval_2026-06-20/offline_big_provider_gate.json")
    args = parser.parse_args()

    report = run(Path(args.downloads_dir), DEFAULT_ZIPS)
    output = Path(args.output)
    if not output.is_absolute():
        output = REPO_DIR / output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(
        json.dumps(
            {
                key: report[key]
                for key in (
                    "mode",
                    "total_cases",
                    "labeled_cases",
                    "passed",
                    "failed",
                    "actual_counts",
                    "expected_counts",
                    "confusion",
                    "top_failed_family_ids",
                )
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    print(f"wrote {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
