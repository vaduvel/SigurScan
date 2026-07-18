#!/usr/bin/env python3
"""Measure the Action & Asset protected-action floor without activating it.

The runner reuses the broad offline corpus and the current production gate.
It stores aggregate counters only: no source text, URL, hostname, case id,
provider payload, or extracted secret is written to the report.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Tuple


BACKEND_DIR = Path(__file__).resolve().parents[1]
REPO_DIR = BACKEND_DIR.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from eval.large_offline_fixture_runner import (  # noqa: E402
    DEFAULT_ZIPS,
    _final_label,
    _resolved_urls,
    _run_invoice_route,
    _should_route_invoice_case,
    _source_channel,
    load_cases,
)
from main import (  # noqa: E402
    _apply_provider_gate_verdict,
    _normalise_obfuscated_text,
    engine,
)
from services.action_asset import build_action_asset_contract  # noqa: E402
from services.pii_redactor import redact_pii  # noqa: E402
from services.pre_redaction_evidence import (  # noqa: E402
    extract_pre_redaction_evidence,
    pre_redaction_summary,
)
from services.protected_action_shadow import (  # noqa: E402
    evaluate_protected_action_shadow,
)


LABEL_RANK = {"SAFE": 0, "UNVERIFIED": 1, "SUSPECT": 2, "DANGEROUS": 3}


def _git_commit() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"],
            cwd=REPO_DIR,
            text=True,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def _implementation_digest() -> str:
    digest = hashlib.sha256()
    for relative in (
        "backend/services/action_asset.py",
        "backend/services/protected_action_shadow.py",
    ):
        path = REPO_DIR / relative
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _deduplicated_cases(downloads_dir: Path, zip_names: Iterable[str]) -> List[Dict[str, Any]]:
    seen: set[Tuple[str, str, str]] = set()
    output: List[Dict[str, Any]] = []
    for case in load_cases(downloads_dir, zip_names):
        key = (str(case.get("source")), str(case.get("id")), str(case.get("text")))
        if key in seen:
            continue
        seen.add(key)
        output.append(case)
    return output


def _run_current_pipeline(
    case: Mapping[str, Any],
    analysis_text: str,
    redacted_text: str,
    source_channel: str,
) -> Tuple[str, Dict[str, Any], str]:
    resolved = _resolved_urls(redacted_text)
    if _should_route_invoice_case(dict(case), analysis_text):
        final = _run_invoice_route(analysis_text, resolved, source_channel)
        route = "invoice"
    else:
        analysis = engine.analyze(redacted_text, urls=resolved, external_threat_intel={})
        evidence = analysis.setdefault("evidence", {})
        evidence["source_channel"] = source_channel
        final = _apply_provider_gate_verdict(
            analysis,
            resolved,
            raw_text=redacted_text,
            pillars={},
        )
        route = "generic"
    evidence = final.get("evidence") if isinstance(final.get("evidence"), dict) else {}
    bundle = evidence.get("decision_bundle")
    return (
        _final_label(final),
        copy.deepcopy(bundle) if isinstance(bundle, dict) else {},
        route,
    )


def _effective_label(actual: str, candidate: str | None) -> str:
    if actual not in LABEL_RANK:
        return actual
    if candidate not in LABEL_RANK:
        return actual
    return candidate if LABEL_RANK[candidate] > LABEL_RANK[actual] else actual


def run(downloads_dir: Path, zip_names: Iterable[str]) -> Dict[str, Any]:
    cases = _deduplicated_cases(downloads_dir, zip_names)
    expected_counts: Counter[str] = Counter()
    actual_counts: Counter[str] = Counter()
    candidate_counts: Counter[str] = Counter()
    effective_counts: Counter[str] = Counter()
    transitions: Counter[str] = Counter()
    expected_transitions: Counter[str] = Counter()
    action_counts: Counter[str] = Counter()
    protected_counts: Counter[str] = Counter()
    composition_counts: Counter[str] = Counter()
    reason_counts: Counter[str] = Counter()
    proof_counts: Counter[str] = Counter()
    channel_counts: Counter[str] = Counter()
    route_counts: Counter[str] = Counter()
    by_source: Dict[str, Counter[str]] = defaultdict(Counter)
    errors: Counter[str] = Counter()

    evaluated = 0
    labeled = 0
    protected_positive = 0
    protected_floor_covered = 0
    protected_expected_risk = 0
    protected_expected_risk_false_safe = 0
    expected_safe = 0
    expected_safe_candidate_dangerous = 0
    expected_safe_candidate_suspect = 0
    recovered_expected_dangerous_from_safe = 0
    recovered_expected_dangerous_to_floor = 0

    for case in cases:
        try:
            analysis_text = _normalise_obfuscated_text(str(case.get("text") or ""))
            redacted_text = redact_pii(analysis_text)
            source_channel = _source_channel(dict(case))
            contract = build_action_asset_contract(
                analysis_text,
                source_channel=source_channel,
                pre_redaction_summary=pre_redaction_summary(
                    extract_pre_redaction_evidence(analysis_text)
                ),
            )
            actual, bundle, route = _run_current_pipeline(
                case,
                analysis_text,
                redacted_text,
                source_channel,
            )
            if actual not in LABEL_RANK:
                errors["unsupported_actual_label"] += 1
                continue
            shadow = evaluate_protected_action_shadow(
                contract,
                decision_bundle=bundle,
                actual_label=actual,
            )
        except Exception as exc:
            errors[type(exc).__name__] += 1
            continue

        candidate = shadow.get("candidate_min_label")
        candidate = str(candidate).upper() if candidate else None
        effective = _effective_label(actual, candidate)
        expected = str(case.get("expected") or "").upper()
        source = str(case.get("source") or "unknown")
        protected = list(contract.get("protected_actions") or [])

        evaluated += 1
        route_counts[route] += 1
        channel_counts[str(contract.get("channel") or "unknown")] += 1
        actual_counts[actual] += 1
        candidate_counts[candidate or "NONE"] += 1
        effective_counts[effective] += 1
        transitions[f"{actual}->{effective}"] += 1
        action_counts.update(str(value) for value in contract.get("requested_actions") or [])
        protected_counts.update(str(value) for value in protected)
        composition_counts.update(str(value) for value in contract.get("composition_rules") or [])
        reason_counts.update(str(value) for value in shadow.get("reason_codes") or [])
        proof = shadow.get("proof_before_safe")
        proof = proof if isinstance(proof, Mapping) else {}
        proof_counts[str(proof.get("status") or "unknown")] += 1
        by_source[source]["total"] += 1
        by_source[source]["protected_positive"] += 1 if protected else 0
        by_source[source]["changed"] += 1 if actual != effective else 0
        by_source[source][f"candidate_{(candidate or 'none').lower()}"] += 1

        if protected:
            protected_positive += 1
            if candidate in {"SUSPECT", "DANGEROUS"}:
                protected_floor_covered += 1

        if not expected:
            continue
        labeled += 1
        expected_counts[expected] += 1
        expected_transitions[f"{expected}:{actual}->{effective}"] += 1
        by_source[source][f"expected_{expected.lower()}"] += 1
        if expected == "SAFE":
            expected_safe += 1
            if candidate == "DANGEROUS" and actual != "DANGEROUS":
                expected_safe_candidate_dangerous += 1
                by_source[source]["expected_safe_candidate_dangerous"] += 1
            elif candidate == "SUSPECT" and LABEL_RANK[actual] < LABEL_RANK["SUSPECT"]:
                expected_safe_candidate_suspect += 1
        if protected and expected in {"SUSPECT", "DANGEROUS"}:
            protected_expected_risk += 1
            if effective == "SAFE":
                protected_expected_risk_false_safe += 1
        if expected == "DANGEROUS":
            if actual == "SAFE" and effective == "DANGEROUS":
                recovered_expected_dangerous_from_safe += 1
            if LABEL_RANK[actual] < LABEL_RANK["SUSPECT"] <= LABEL_RANK[effective]:
                recovered_expected_dangerous_to_floor += 1

    dangerous_fp_rate = (
        expected_safe_candidate_dangerous / expected_safe if expected_safe else 0.0
    )
    protected_coverage = (
        protected_floor_covered / protected_positive if protected_positive else 1.0
    )
    return {
        "schema": "sigurscan_action_asset_shadow_measurement_v1",
        "base_commit": _git_commit(),
        "implementation_sha256": _implementation_digest(),
        "mode": "offline_current_gate_plus_action_asset_shadow_no_live_providers_no_mistral",
        "privacy": (
            "Aggregate counts only; no text, URL, hostname, case id, provider payload, "
            "or extracted secret is stored."
        ),
        "corpus": {
            "deduplicated_case_count": len(cases),
            "evaluated_cases": evaluated,
            "labeled_cases": labeled,
            "errors": dict(errors),
            "route_counts": dict(route_counts),
            "expected_counts": dict(expected_counts),
        },
        "results": {
            "actual_counts": dict(actual_counts),
            "candidate_floor_counts": dict(candidate_counts),
            "effective_shadow_counts": dict(effective_counts),
            "transitions": dict(transitions),
            "expected_transitions": dict(expected_transitions),
            "requested_action_counts": dict(action_counts),
            "protected_action_counts": dict(protected_counts),
            "composition_counts": dict(composition_counts),
            "candidate_reason_counts": dict(reason_counts),
            "proof_status_counts": dict(proof_counts),
            "channel_counts": dict(channel_counts),
            "protected_positive_cases": protected_positive,
            "protected_floor_covered_cases": protected_floor_covered,
            "protected_floor_coverage": round(protected_coverage, 6),
            "protected_expected_risk_cases": protected_expected_risk,
            "protected_expected_risk_false_safe_after_shadow": protected_expected_risk_false_safe,
            "expected_safe_cases": expected_safe,
            "expected_safe_candidate_dangerous": expected_safe_candidate_dangerous,
            "expected_safe_candidate_dangerous_rate": round(dangerous_fp_rate, 6),
            "expected_safe_candidate_suspect": expected_safe_candidate_suspect,
            "expected_dangerous_recovered_safe_to_dangerous": recovered_expected_dangerous_from_safe,
            "expected_dangerous_recovered_below_floor_to_at_least_suspect": recovered_expected_dangerous_to_floor,
        },
        "by_source_aggregate": {
            source: dict(counts)
            for source, counts in sorted(by_source.items())
        },
        "acceptance": {
            "protected_expected_risk_false_safe_target": 0,
            "protected_expected_risk_false_safe_pass": protected_expected_risk_false_safe == 0,
            "expected_safe_candidate_dangerous_rate_target_lt": 0.01,
            "expected_safe_candidate_dangerous_rate_pass": dangerous_fp_rate < 0.01,
        },
        "decision": {
            "shadow_only": True,
            "active_flag_default": False,
            "activation_authorized": False,
            "requires_manual_fp_fn_review": True,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--downloads-dir", default="/Users/vaduvageorge/Downloads")
    parser.add_argument(
        "--output",
        default="backend/data/eval/action_asset_shadow_measurement_v2026_07_18.json",
    )
    args = parser.parse_args()

    report = run(Path(args.downloads_dir), DEFAULT_ZIPS)
    output = Path(args.output)
    if not output.is_absolute():
        output = REPO_DIR / output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print(f"wrote {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
