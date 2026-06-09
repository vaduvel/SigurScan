#!/usr/bin/env python3
"""Controlled live-provider smoke runner for SigurScan.

This is intentionally small and opt-in. It calls the production-like
orchestrated endpoint, waits for the async scan state, and validates only broad
user-facing verdict bands. It must not be used for bulk regression packs.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests


REPO_DIR = Path(__file__).resolve().parents[2]
DEFAULT_BASE_URL = os.getenv("SIGURSCAN_LIVE_SMOKE_BASE_URL", "https://nudaclick-backend.vercel.app").rstrip("/")
RUN_ENV = "SIGURSCAN_RUN_LIVE_PROVIDER_SMOKE"
API_KEY_ENV = "SIGURSCAN_LIVE_SMOKE_API_KEY"
DEFAULT_LIVE_MALICIOUS_URL = "https://00000000000000000000000000000000000000000.xyz"
DEFAULT_MOBILE_USER_AGENT = (
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36"
)


@dataclass(frozen=True)
class LiveSmokeCase:
    case_id: str
    title: str
    text: str
    expected_labels: List[str]
    max_seconds: int = 120


LIVE_SMOKE_CASES = [
    LiveSmokeCase(
        case_id="live_yoxo_buyback",
        title="YOXO buyback benign commercial SMS",
        text=(
            "Ai un telefon sau o tableta pe care nu le mai folosesti? Acum le poti transforma rapid in bani "
            "cu serviciul de buy-back YOXO. Beneficiezi de evaluare online in doar cateva minute, transport "
            "gratuit si plata in cont in maximum 48 de ore de la confirmarea dispozitivului. Simplu, sigur "
            "si fara batai de cap. Afla cat valoreaza dispozitivul tau si incepe procesul chiar acum: "
            "buyback.yoxo.ro"
        ),
        expected_labels=["SIGUR"],
    ),
    LiveSmokeCase(
        case_id="live_smyk_catalog",
        title="SMYK catalog benign marketing SMS",
        text=(
            "Rasfoieste catalogul de 1 iunie: https://smyk.ro/catalogul-ziua-copilului si vino in magazine "
            "sa alegi: jucarii, jocuri, haine si incaltaminte la super preturi."
        ),
        expected_labels=["SIGUR", "SUSPECT"],
    ),
    LiveSmokeCase(
        case_id="live_emag_tracking_official",
        title="eMAG official tracking URL",
        text="Comanda ta eMAG #4471122 a fost expediata. Urmareste coletul: https://www.emag.ro/order/tracking",
        expected_labels=["SIGUR", "SUSPECT"],
    ),
    LiveSmokeCase(
        case_id="live_google_webrisk_phishing_test",
        title="Google Web Risk phishing test URL",
        text=f"Verifica acest URL de test phishing: {DEFAULT_LIVE_MALICIOUS_URL}",
        expected_labels=["PERICULOS"],
    ),
    LiveSmokeCase(
        case_id="live_idroid_status",
        title="iDroid status benign service SMS",
        text=(
            "Dispozitivul dvs. (cod 8HXDX) nu a putut fi reparat. Informatii la 0371237475. "
            "https://idroid.ro/verificare-status Se percepe taxa de magazinaj la depasirea a 10 zile."
        ),
        expected_labels=["SIGUR", "SUSPECT"],
    ),
]


def _headers() -> Dict[str, str]:
    headers = {"Content-Type": "application/json"}
    api_key = os.getenv(API_KEY_ENV, "").strip()
    if api_key:
        headers["X-API-KEY"] = api_key
    return headers


def _blocked_live_target(text: str) -> Optional[str]:
    lowered = text.lower()
    for token in (".test", ".invalid", ".example"):
        if token in lowered:
            return token
    return None


def _load_cases_from_file(path: str) -> List[LiveSmokeCase]:
    cases_path = Path(path)
    raw = json.loads(cases_path.read_text(encoding="utf-8"))
    parsed: List[LiveSmokeCase] = []
    for idx, item in enumerate(raw if isinstance(raw, list) else []):
        if not isinstance(item, dict):
            continue

        case_id = str(item.get("case_id") or item.get("id") or f"custom_case_{idx + 1}")
        title = str(item.get("title") or item.get("case_name") or case_id)
        text = str(
            item.get("text")
            or item.get("input")
            or item.get("message")
            or item.get("content")
            or ""
        ).strip()
        if not text:
            continue

        expected = item.get("expected_labels") or item.get("expected_user_action_range") or ["SIGUR", "SUSPECT", "PERICULOS"]
        max_seconds = int(item.get("max_seconds") or item.get("max_timeout_seconds") or 120)
        parsed.append(
            LiveSmokeCase(
                case_id=case_id,
                title=title,
                text=text,
                expected_labels=list(expected) if isinstance(expected, list) else [str(expected)],
                max_seconds=max_seconds,
            )
        )
    return parsed


def _post_scan(base_url: str, case: LiveSmokeCase, timeout: float) -> Dict[str, Any]:
    payload = {
        "input_type": "text",
        "text": case.text,
        "source_channel": "live_provider_smoke",
        "visibility": os.getenv("SIGURSCAN_LIVE_SMOKE_URLSCAN_VISIBILITY", "private"),
        "country": os.getenv("SIGURSCAN_LIVE_SMOKE_URLSCAN_COUNTRY", "ro"),
        "customagent": os.getenv("SIGURSCAN_LIVE_SMOKE_USER_AGENT", DEFAULT_MOBILE_USER_AGENT),
    }
    response = requests.post(
        f"{base_url}/v1/scan/orchestrated",
        headers=_headers(),
        json=payload,
        timeout=timeout,
    )
    response.raise_for_status()
    return response.json()


def _poll_scan(base_url: str, scan_id: str, max_seconds: int, poll_interval: float, timeout: float) -> Dict[str, Any]:
    deadline = time.monotonic() + max_seconds
    last_payload: Dict[str, Any] = {}
    timings: Dict[str, float] = {}
    start_at = time.monotonic()

    while time.monotonic() < deadline:
        try:
            response = requests.get(
                f"{base_url}/v1/scan/orchestrated/{scan_id}",
                headers=_headers(),
                timeout=timeout,
            )
        except requests.Timeout:
            # A serverless instance can finish and persist a bounded stage after
            # the client-side request times out. Continue polling the durable job
            # instead of declaring the whole live smoke case failed.
            time.sleep(poll_interval)
            continue
        response.raise_for_status()
        last_payload = response.json()
        result = last_payload.get("result") if isinstance(last_payload.get("result"), dict) else None
        status = str(last_payload.get("status") or "").lower()
        now = time.monotonic()

        if result and result.get("is_final") is True and "time_to_verdict_sec" not in timings:
            timings["time_to_verdict_sec"] = round(now - start_at, 2)

        preview = last_payload.get("preview") if isinstance(last_payload.get("preview"), dict) else {}
        if preview.get("report_url") and "time_to_preview_report_sec" not in timings:
            timings["time_to_preview_report_sec"] = round(now - start_at, 2)
        if preview.get("screenshot_url") and "time_to_preview_screenshot_sec" not in timings:
            timings["time_to_preview_screenshot_sec"] = round(now - start_at, 2)

        if status in {"complete", "incomplete"}:
            if result and result.get("is_final") is True:
                timings.setdefault("time_to_verdict_sec", round(now - start_at, 2))
            return {"result_payload": last_payload, "timings": timings}
        if result and result.get("is_final") is True and status != "scanning":
            timings.setdefault("time_to_verdict_sec", round(now - start_at, 2))
            return {"result_payload": last_payload, "timings": timings}
        time.sleep(poll_interval)

    return {"result_payload": last_payload, "timings": timings}


def _run_case(base_url: str, case: LiveSmokeCase, poll_interval: float, timeout: float) -> Dict[str, Any]:
    started_at = time.monotonic()
    blocked = _blocked_live_target(case.text)
    if blocked:
        return {
            "id": case.case_id,
            "title": case.title,
            "passed": False,
            "error": f"Blocked reserved live target token: {blocked}",
        }

    try:
        post_start = time.monotonic()
        started = _post_scan(base_url, case, timeout)
        scan_id_time = time.monotonic()
    except requests.RequestException as exc:
        return {
            "id": case.case_id,
            "title": case.title,
            "passed": False,
            "error": f"POST failed: {type(exc).__name__}: {exc}",
        }

    scan_id = str(started.get("scan_id") or "").strip()
    if not scan_id:
        return {
            "id": case.case_id,
            "title": case.title,
            "passed": False,
            "error": "POST did not return scan_id",
            "post_response": started,
        }

    try:
        poll_result = _poll_scan(base_url, scan_id, case.max_seconds, poll_interval, timeout)
        final_payload = poll_result["result_payload"]
        poll_timings = poll_result["timings"]
    except requests.RequestException as exc:
        return {
            "id": case.case_id,
            "title": case.title,
            "scan_id": scan_id,
            "passed": False,
            "error": f"poll failed: {type(exc).__name__}: {exc}",
        }

    result = final_payload.get("result") if isinstance(final_payload.get("result"), dict) else {}
    end_at = time.monotonic()
    label = str(result.get("user_risk_label") or "NECUNOSCUT")
    preview = final_payload.get("preview") if isinstance(final_payload.get("preview"), dict) else {}
    evidence = result.get("evidence") if isinstance(result.get("evidence"), dict) else {}
    provider_summary = evidence.get("external_intel_summary") if isinstance(evidence.get("external_intel_summary"), dict) else {}
    provider_gate = evidence.get("provider_gate") if isinstance(evidence.get("provider_gate"), dict) else {}
    passed = label in set(case.expected_labels)
    return {
        "id": case.case_id,
        "title": case.title,
        "scan_id": scan_id,
        "passed": passed,
        "expected_labels": case.expected_labels,
        "actual_label": label,
        "status": final_payload.get("status"),
        "is_final": result.get("is_final"),
        "risk_level": result.get("risk_level"),
        "detected_family_id": result.get("detected_family_id"),
        "final_url": preview.get("final_url"),
        "screenshot_url": preview.get("screenshot_url"),
        "report_url": preview.get("report_url"),
        "provider_gate_reason": provider_gate.get("reason"),
        "provider_summary": provider_summary,
        "status_message": final_payload.get("status_message"),
        "timings": {
            "time_to_scan_id_sec": round(scan_id_time - post_start, 2),
            "time_to_verdict_sec": poll_timings.get("time_to_verdict_sec"),
            "time_to_preview_report_sec": poll_timings.get("time_to_preview_report_sec"),
            "time_to_preview_screenshot_sec": poll_timings.get("time_to_preview_screenshot_sec"),
            "time_to_completion_sec": round(end_at - started_at, 2),
        },
    }


def run_live_smoke(
    *,
    base_url: str,
    cases: List[LiveSmokeCase],
    poll_interval: float,
    timeout: float,
) -> Dict[str, Any]:
    rows = [_run_case(base_url, case, poll_interval, timeout) for case in cases]
    failed = [row for row in rows if not row.get("passed")]
    return {
        "base_url": base_url,
        "total": len(rows),
        "passed": len(rows) - len(failed),
        "failed": len(failed),
        "rows": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run capped live provider smoke tests against SigurScan orchestrated backend.")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--output", default="build/reports/live_provider_smoke.json")
    parser.add_argument("--case", action="append", help="Run only selected case id. Repeat for multiple cases.")
    parser.add_argument("--cases-file", help="JSON array with case records {case_id,title,text,input,expected_labels,max_seconds}.")
    parser.add_argument("--poll-interval", type=float, default=3.0)
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--dry-run", action="store_true", help="Print selected cases without calling live providers.")
    args = parser.parse_args()

    selected = LIVE_SMOKE_CASES
    if args.cases_file:
        selected = _load_cases_from_file(args.cases_file)
        if not selected:
            print(f"No valid cases loaded from file: {args.cases_file}", file=sys.stderr)
            return 2

    if args.case:
        wanted = set(args.case)
        selected = [case for case in selected if case.case_id in wanted]
    if not selected:
        print("No matching live smoke cases selected.", file=sys.stderr)
        return 2

    if args.dry_run or os.getenv(RUN_ENV, "").strip() != "1":
        print(json.dumps({
            "dry_run": True,
            "required_env_to_run": f"{RUN_ENV}=1",
            "base_url": args.base_url,
            "cases": [{"id": case.case_id, "title": case.title, "expected_labels": case.expected_labels} for case in selected],
        }, indent=2, ensure_ascii=False))
        return 0

    report = run_live_smoke(
        base_url=args.base_url.rstrip("/"),
        cases=selected,
        poll_interval=args.poll_interval,
        timeout=args.timeout,
    )
    output = Path(args.output)
    if not output.is_absolute():
        output = REPO_DIR / output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps({key: report[key] for key in ("base_url", "total", "passed", "failed")}, indent=2, ensure_ascii=False))
    return 0 if report["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
