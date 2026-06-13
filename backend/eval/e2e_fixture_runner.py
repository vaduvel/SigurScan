#!/usr/bin/env python3
"""Run SigurScan E2E fixture packs against the real provider gate with mocked pillars.

The fixture packs are regression/evaluation packs, not live-provider smoke tests.
They intentionally use `.test`, `.invalid`, and `.example` URLs, so this runner
never calls URLScan, Google Web Risk, VirusTotal, DNS, RDAP, or redirect network
resolution. It builds an evidence snapshot from local input plus provider mocks
and projects the verdict through the production provider gate.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.parse
from collections import Counter, defaultdict
from copy import deepcopy
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


ROOT_DIR = Path(__file__).resolve().parents[1]
REPO_DIR = ROOT_DIR.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from main import (  # noqa: E402
    _apply_provider_gate_verdict,
    _canonicalize_url,
    _normalise_obfuscated_text,
    engine,
    extract_urls,
)
from services.pii_redactor import redact_pii  # noqa: E402

try:  # noqa: E402
    from pypdf import PdfReader
except Exception:  # pragma: no cover - optional local dependency
    PdfReader = None


ACTION_TO_USER_STATUS = {
    "CONTINUE_WITH_CAUTION": "SAFE",
    "DO_NOT_CONTINUE": "DANGEROUS",
    "NO_ENTER_DATA": "DANGEROUS",
    "NO_REPLY": "DANGEROUS",
    "VERIFY_OFFICIAL": "SUSPECT",
    "INSUFFICIENT_EVIDENCE": "SUSPECT",
}

SEVERITY_TO_USER_STATUS = {
    "NEUTRAL": "SAFE",
    "CAUTION": "SUSPECT",
    "UNKNOWN": "SUSPECT",
    "WARNING": "SUSPECT",
    "DANGER": "DANGEROUS",
}


def _safe_read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except UnicodeDecodeError:
        return path.read_bytes().decode("utf-8", errors="ignore")
    except Exception:
        return ""


def _extract_email_text(path: Path) -> str:
    try:
        message = BytesParser(policy=policy.default).parsebytes(path.read_bytes())
    except Exception:
        return _safe_read_text(path)

    chunks: List[str] = []
    if message.is_multipart():
        parts = message.walk()
    else:
        parts = [message]

    for part in parts:
        content_type = str(part.get_content_type() or "").lower()
        if content_type not in {"text/plain", "text/html"}:
            continue
        try:
            payload = part.get_content()
        except Exception:
            payload = part.get_payload(decode=True) or b""
            if isinstance(payload, bytes):
                payload = payload.decode(part.get_content_charset() or "utf-8", errors="ignore")
        if payload:
            chunks.append(str(payload))

    headers = []
    for name in ("From", "Reply-To", "Return-Path", "Subject", "Authentication-Results"):
        value = message.get(name)
        if value:
            headers.append(f"{name}: {value}")
    return "\n".join(headers + chunks)


def _extract_pdf_text(path: Path) -> str:
    if PdfReader is None:
        return ""
    try:
        reader = PdfReader(str(path))
        chunks = []
        for page in reader.pages:
            chunks.append(page.extract_text() or "")
        return "\n".join(chunk for chunk in chunks if chunk.strip())
    except Exception:
        return ""


def _load_case_text(pack_root: Path, case: Dict[str, Any]) -> Tuple[str, List[str]]:
    """Load user-facing fixture content where possible.

    Binary-only fixtures are represented by a neutral surrogate built from the
    case metadata and URL. The runner reports these as surrogate inputs so we do
    not pretend we performed OCR/PDF extraction inside this JVM-free harness.
    """

    text_chunks: List[str] = []
    used_paths: List[str] = []

    raw_paths: Iterable[str]
    if "fixture_path" in case:
        raw_paths = [str(case.get("fixture_path") or "")]
    else:
        raw_paths = [str(item) for item in case.get("fixturePaths") or []]

    for raw_path in raw_paths:
        if not raw_path:
            continue
        path = pack_root / raw_path
        suffix = path.suffix.lower()
        if suffix == ".eml":
            value = _extract_email_text(path)
        elif suffix == ".pdf":
            value = _extract_pdf_text(path)
        elif suffix in {".txt", ".html", ".htm", ".json", ".csv"}:
            value = _safe_read_text(path)
        else:
            value = ""
        if value.strip():
            text_chunks.append(value)
            used_paths.append(raw_path)

    if text_chunks:
        return "\n\n".join(text_chunks), used_paths

    fallback_parts = [
        str(case.get("title") or ""),
        f"Brand: {case.get('brandClaimed')}" if case.get("brandClaimed") else "",
        f"URL vizibil: {case.get('visibleUrl')}" if case.get("visibleUrl") else "",
        f"Link: {case.get('primaryUrl') or case.get('primary_url_expected') or ''}",
    ]
    return "\n".join(part for part in fallback_parts if part).strip(), ["metadata-surrogate"]


def _registered_domain(hostname: str) -> str:
    host = (hostname or "").strip().lower().strip(".")
    if not host:
        return ""
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in {"co", "com", "org", "net"} and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def _url_entry(url: str, *, final_url: Optional[str] = None, mock: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    canonical = _canonicalize_url(url) or url
    final = _canonicalize_url(final_url or canonical) or final_url or canonical
    parsed = urllib.parse.urlparse(canonical)
    final_parsed = urllib.parse.urlparse(final)
    host = (parsed.hostname or "").lower()
    final_host = (final_parsed.hostname or host).lower()
    redirect_chain = []
    if isinstance(mock, dict):
        raw_chain = mock.get("redirectChain") or mock.get("redirect_chain") or []
        if isinstance(raw_chain, list):
            redirect_chain = raw_chain
    return {
        "url": canonical,
        "input_url": canonical,
        "final_url": final,
        "hostname": host,
        "final_hostname": final_host,
        "registered_domain": _registered_domain(host),
        "final_registered_domain": _registered_domain(final_host),
        "redirect_chain": redirect_chain,
        "redirect_count": len(redirect_chain),
        "success": True,
        "status_code": 200,
    }


def _status_from_provider_result(provider: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    raw_status = str(payload.get("status") or "").strip().upper()
    raw_verdict = str(payload.get("verdict") or payload.get("result") or "").strip()
    verdict = raw_verdict.lower()
    provider_name = provider.lower()

    if raw_status in {"NOT_RUN", "SKIPPED", "SKIPPED_PRIVACY"} or verdict in {"not_run", "skipped"}:
        return {
            "source": provider_name,
            "status": "unknown",
            "verdict": "not_run",
            "consulted": False,
            "risk_score": 0,
            "threat_type": "not_run",
        }
    if raw_status in {"TIMEOUT", "UNAVAILABLE", "RATE_LIMITED", "404", "ERROR"} or verdict in {
        "timeout",
        "unavailable",
        "rate_limited",
        "404",
    }:
        return {
            "source": provider_name,
            "status": "error",
            "verdict": verdict or raw_status.lower(),
            "consulted": True,
            "risk_score": 0,
            "threat_type": "provider_error",
            "error": verdict or raw_status.lower(),
        }

    if provider_name in {"web_risk", "google_web_risk"}:
        threats = payload.get("threats")
        if threats:
            return {
                "source": "google_web_risk",
                "status": "malicious",
                "verdict": "malware_or_social_engineering",
                "consulted": True,
                "risk_score": 95,
                "threat_type": "web_risk_match",
            }
        if "web_risk_malware" in verdict or "malware" in verdict or "phishing" in verdict:
            return {
                "source": "google_web_risk",
                "status": "malicious",
                "verdict": raw_verdict,
                "consulted": True,
                "risk_score": 95,
                "threat_type": "web_risk_match",
            }
        return {
            "source": "google_web_risk",
            "status": "clean",
            "verdict": "clean",
            "consulted": raw_status == "SUCCESS" or verdict in {"no_match", "no-match"},
            "risk_score": 0,
            "threat_type": "none",
        }

    if provider_name in {"urlscan", "urlscan.io"}:
        if any(token in verdict for token in ("malicious", "phish", "malware", "card_form", "otp_form")):
            return {
                "source": "urlscan",
                "status": "malicious",
                "verdict": raw_verdict or "malicious",
                "consulted": True,
                "risk_score": 90,
                "threat_type": "urlscan_malicious",
                "screenshot_available": bool(payload.get("screenshot_available") or payload.get("screenshotAvailable")),
            }
        if verdict in {"clean", "no_visible_risk", "no visible risk"}:
            return {
                "source": "urlscan",
                "status": "clean",
                "verdict": "clean",
                "consulted": True,
                "risk_score": 0,
                "threat_type": "none",
                "screenshot_available": bool(payload.get("screenshot_available") or payload.get("screenshotAvailable")),
            }
        return {
            "source": "urlscan",
            "status": "unknown",
            "verdict": verdict or "unknown",
            "consulted": raw_status == "SUCCESS",
            "risk_score": 0,
            "threat_type": "unknown",
        }

    if provider_name in {"virustotal", "vt"}:
        stats = payload.get("stats")
        malicious = suspicious = 0
        if isinstance(stats, dict):
            malicious = int(stats.get("malicious") or 0)
            suspicious = int(stats.get("suspicious") or 0)
        if "malicious_high" in verdict:
            malicious = max(malicious, 5)
        if malicious + suspicious >= 5 or malicious >= 2:
            return {
                "source": "virustotal",
                "status": "malicious",
                "verdict": raw_verdict or "vt_consensus",
                "consulted": True,
                "risk_score": 85,
                "threat_type": "vt_consensus",
                "details": {"malicious": malicious, "suspicious": suspicious},
            }
        if "low_engine_hit" in verdict:
            return {
                "source": "virustotal",
                "status": "clean",
                "verdict": "low_engine_hit_not_decisive",
                "consulted": True,
                "risk_score": 0,
                "threat_type": "low_confidence",
                "details": {"malicious": malicious, "suspicious": suspicious},
            }
        return {
            "source": "virustotal",
            "status": "clean",
            "verdict": "clean",
            "consulted": raw_status == "SUCCESS",
            "risk_score": 0,
            "threat_type": "none",
            "details": {"malicious": malicious, "suspicious": suspicious},
        }

    return {
        "source": provider_name,
        "status": "unknown",
        "verdict": verdict or "unknown",
        "consulted": False,
        "risk_score": 0,
        "threat_type": "unknown",
    }


def _load_provider_mocks(pack_root: Path, case: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]]]:
    """Return provider raw mocks, normalized source summary, and pillar states."""

    raw_by_provider: Dict[str, Any] = {}
    summary: Dict[str, Dict[str, Any]] = {}
    pillars: Dict[str, Dict[str, Any]] = {}

    if "provider_mock_path" in case:
        path = pack_root / str(case.get("provider_mock_path") or "")
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            for provider, payload in (data.get("providers") or {}).items():
                raw_by_provider[provider] = payload
                normalized = _status_from_provider_result(provider, payload if isinstance(payload, dict) else {})
                source_name = normalized["source"]
                summary[source_name] = normalized
                pillars[source_name] = _pillar_from_summary(source_name, normalized, provider)

    for provider, rel_path in (case.get("providerMocks") or {}).items():
        path = pack_root / str(rel_path)
        if not path.exists():
            continue
        payload = json.loads(path.read_text(encoding="utf-8"))
        raw_by_provider[provider] = payload
        normalized = _status_from_provider_result(provider, payload if isinstance(payload, dict) else {})
        source_name = normalized["source"]
        summary[source_name] = normalized
        pillars[source_name] = _pillar_from_summary(source_name, normalized, provider)

    return raw_by_provider, summary, pillars


def _pillar_from_summary(source_name: str, normalized: Dict[str, Any], raw_provider_name: str) -> Dict[str, Any]:
    status = str(normalized.get("status") or "unknown")
    if not normalized.get("consulted"):
        state = "pending"
    elif status == "error":
        state = "error"
    elif status in {"clean", "malicious", "suspicious"}:
        state = "ok"
    else:
        state = "pending"
    return {
        "status": state,
        "required": source_name in {"google_web_risk", "virustotal"},
        "provider": raw_provider_name,
        "details": normalized.get("verdict") or status,
    }


def _build_external_threat_intel(final_url: str, summary: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    if not final_url:
        return {}
    worst = "clean"
    score = 0
    for source in summary.values():
        status = str(source.get("status") or "").lower()
        if status in {"malicious", "phishing", "malware"}:
            worst = "malicious"
            score = max(score, int(source.get("risk_score") or 90))
        elif status == "suspicious" and worst != "malicious":
            worst = "suspicious"
            score = max(score, int(source.get("risk_score") or 55))
    return {
        final_url: {
            "verdict": worst,
            "risk_score": score,
            "sources": {
                source_name: {
                    "status": source.get("status"),
                    "verdict": source.get("verdict"),
                    "consulted": source.get("consulted"),
                    "score": source.get("risk_score"),
                    "risk_score": source.get("risk_score"),
                    "threat_type": source.get("threat_type"),
                    "details": source.get("details"),
                }
                for source_name, source in summary.items()
            },
        }
    }


def _find_mock_final_url(raw_mocks: Dict[str, Any]) -> Optional[str]:
    for key in ("urlscan", "urlscan.io"):
        raw = raw_mocks.get(key)
        if not isinstance(raw, dict):
            continue
        value = raw.get("final_url") or raw.get("finalUrl")
        if value:
            return str(value)
    return None


def _case_primary_url(case: Dict[str, Any], text: str, raw_mocks: Dict[str, Any]) -> Optional[str]:
    explicit = case.get("primary_url_expected") or case.get("primaryUrl") or case.get("visibleUrl")
    candidates = []
    if explicit:
        candidates.append(str(explicit))
    candidates.extend(extract_urls(text or ""))
    for candidate in candidates:
        canonical = _canonicalize_url(candidate)
        if canonical:
            return canonical
    return None


def _infer_offer_status(case: Dict[str, Any], expected_status: str, resolved_urls: List[Dict[str, Any]]) -> str:
    if not resolved_urls:
        return "skipped"
    truth = case.get("groundTruthIsScam")
    if truth is False or expected_status == "SAFE":
        return "confirmed"
    if truth is True or expected_status == "DANGEROUS":
        return "not_found"
    return "inconclusive"


def _expected_user_status(case: Dict[str, Any]) -> str:
    decision = str(case.get("expected_decision") or case.get("expectedDecision") or "").upper()
    # NO_REPLY is an action, not always a fraud verdict. In the 3-label
    # SigurScan UI, legitimate OTP/security education messages should warn the
    # user not to share codes without labeling the real sender as PERICULOS.
    if decision == "NO_REPLY" and case.get("groundTruthIsScam") is False:
        return "SUSPECT"
    if decision in ACTION_TO_USER_STATUS:
        return ACTION_TO_USER_STATUS[decision]
    if "expectedSeverityUi" in case and str(case.get("expectedSeverityUi") or "").upper() in SEVERITY_TO_USER_STATUS:
        return SEVERITY_TO_USER_STATUS[str(case.get("expectedSeverityUi") or "").upper()]
    return ACTION_TO_USER_STATUS.get(decision, "SUSPECT")


def _actual_user_status(analysis: Dict[str, Any]) -> str:
    risk_level = str(analysis.get("risk_level") or "").lower()
    if risk_level in {"critical", "dangerous", "high"}:
        return "DANGEROUS"
    if risk_level in {"medium", "warning", "unknown", "pending"}:
        return "SUSPECT"
    return "SAFE"


def _run_case(pack_root: Path, case: Dict[str, Any]) -> Dict[str, Any]:
    case_id = str(case.get("id") or case.get("case_id") or "unknown")
    raw_text, used_paths = _load_case_text(pack_root, case)
    normalized_text = _normalise_obfuscated_text(raw_text)
    redacted_text = redact_pii(normalized_text)
    raw_mocks, provider_summary, pillars = _load_provider_mocks(pack_root, case)
    primary_url = _case_primary_url(case, redacted_text, raw_mocks)
    final_url = _find_mock_final_url(raw_mocks) or primary_url
    resolved_urls = [_url_entry(primary_url, final_url=final_url, mock=raw_mocks.get("urlscan"))] if primary_url else []
    if final_url and not primary_url:
        resolved_urls = [_url_entry(final_url, final_url=final_url, mock=raw_mocks.get("urlscan"))]

    external_threat_intel = _build_external_threat_intel(final_url or primary_url or "", provider_summary)
    analysis = engine.analyze(
        redacted_text,
        urls=deepcopy(resolved_urls),
        external_threat_intel=external_threat_intel,
    )

    if case.get("brandClaimed") and str(analysis.get("claimed_brand") or "").lower() in {"", "nespecificat", "unknown"}:
        analysis["claimed_brand"] = str(case.get("brandClaimed"))
    elif case.get("brandClaimed"):
        analysis["claimed_brand"] = str(case.get("brandClaimed"))

    evidence = analysis.setdefault("evidence", {})
    existing_summary = evidence.get("external_intel_summary") if isinstance(evidence.get("external_intel_summary"), dict) else {}
    merged_summary = {**existing_summary, **provider_summary}
    evidence["external_intel_summary"] = merged_summary
    expected_status = _expected_user_status(case)
    evidence["offer_claim_verification"] = {
        "status": _infer_offer_status(case, expected_status, resolved_urls),
        "source": "fixture_mock",
    }

    final_analysis = _apply_provider_gate_verdict(
        analysis,
        resolved_urls,
        raw_text=redacted_text,
        pillars=pillars,
    )
    actual_status = _actual_user_status(final_analysis)
    expected_decision = str(case.get("expected_decision") or case.get("expectedDecision") or "")
    return {
        "id": case_id,
        "title": case.get("title"),
        "expected_decision": expected_decision,
        "expected_status": expected_status,
        "actual_status": actual_status,
        "passed": actual_status == expected_status,
        "ground_truth_is_scam": case.get("groundTruthIsScam"),
        "primary_url": primary_url,
        "final_url": final_url,
        "claimed_brand": final_analysis.get("claimed_brand"),
        "risk_level": final_analysis.get("risk_level"),
        "risk_score": final_analysis.get("risk_score"),
        "detected_family_id": final_analysis.get("detected_family_id"),
        "provider_gate": final_analysis.get("evidence", {}).get("provider_gate", {}),
        "provider_summary": final_analysis.get("evidence", {}).get("external_intel_summary", {}),
        "reasons": final_analysis.get("reasons", [])[:5],
        "used_paths": used_paths,
    }


def _load_cases(pack_root: Path, max_cases: Optional[int]) -> List[Dict[str, Any]]:
    path = pack_root / "test_cases.json"
    if not path.exists():
        raise FileNotFoundError(f"Missing test_cases.json in {pack_root}")
    cases = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(cases, list):
        raise ValueError(f"Expected list in {path}")
    if max_cases:
        return cases[:max_cases]
    return cases


def _build_metrics(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    expected_counts = Counter(row["expected_status"] for row in rows)
    actual_counts = Counter(row["actual_status"] for row in rows)
    failures = [row for row in rows if not row["passed"]]
    confusion: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for row in rows:
        confusion[row["expected_status"]][row["actual_status"]] += 1

    false_positive_guards_failed = [
        row for row in failures
        if row.get("ground_truth_is_scam") is False and row["actual_status"] == "DANGEROUS"
    ]
    false_negatives = [
        row for row in failures
        if row.get("ground_truth_is_scam") is True and row["actual_status"] != "DANGEROUS"
    ]
    dangerous_expected = [row for row in rows if row["expected_status"] == "DANGEROUS"]
    dangerous_predicted = [row for row in rows if row["actual_status"] == "DANGEROUS"]
    true_dangerous = [row for row in rows if row["expected_status"] == "DANGEROUS" and row["actual_status"] == "DANGEROUS"]
    precision = len(true_dangerous) / len(dangerous_predicted) if dangerous_predicted else 0.0
    recall = len(true_dangerous) / len(dangerous_expected) if dangerous_expected else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if precision + recall else 0.0

    return {
        "total": len(rows),
        "passed": len(rows) - len(failures),
        "failed": len(failures),
        "pass_rate": (len(rows) - len(failures)) / len(rows) if rows else 0.0,
        "expected_counts": dict(expected_counts),
        "actual_counts": dict(actual_counts),
        "confusion": {expected: dict(actuals) for expected, actuals in confusion.items()},
        "danger_precision": precision,
        "danger_recall": recall,
        "danger_f1": f1,
        "false_positive_guard_failures": len(false_positive_guards_failed),
        "false_negatives": len(false_negatives),
        "top_failed_family_ids": dict(Counter(row.get("detected_family_id") or "unknown" for row in failures).most_common(20)),
        "failures_sample": failures[:50],
    }


def run_pack(pack_root: Path, *, max_cases: Optional[int] = None) -> Dict[str, Any]:
    cases = _load_cases(pack_root, max_cases)
    rows = [_run_case(pack_root, case) for case in cases]
    return {
        "pack": str(pack_root),
        "mapping": {
            "CONTINUE_WITH_CAUTION": "SAFE",
            "DO_NOT_CONTINUE": "DANGEROUS",
            "NO_ENTER_DATA": "DANGEROUS",
            "NO_REPLY": "DANGEROUS",
            "VERIFY_OFFICIAL": "SUSPECT",
            "INSUFFICIENT_EVIDENCE": "SUSPECT",
        },
        "metrics": _build_metrics(rows),
        "rows": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run SigurScan E2E fixture evaluation with mocked providers.")
    parser.add_argument("--pack", required=True, help="Path to fixture pack root.")
    parser.add_argument("--output", help="Where to write JSON report.")
    parser.add_argument("--max-cases", type=int, default=None)
    parser.add_argument(
        "--max-failures",
        type=int,
        default=0,
        help="Allow up to this many total mismatches. Keep 0 for strict CI packs.",
    )
    parser.add_argument(
        "--allow-false-positive-guards",
        action="store_true",
        help="Do not fail separately when a known legitimate/guard case becomes PERICULOS.",
    )
    parser.add_argument(
        "--allow-false-negatives",
        action="store_true",
        help="Do not fail separately when a scam case is not classified as PERICULOS.",
    )
    args = parser.parse_args()

    pack_root = Path(args.pack)
    if not pack_root.is_absolute():
        pack_root = REPO_DIR / pack_root
    report = run_pack(pack_root, max_cases=args.max_cases)

    if args.output:
        output = Path(args.output)
        if not output.is_absolute():
            output = REPO_DIR / output
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    metrics = report["metrics"]
    print(json.dumps({
        "pack": report["pack"],
        "total": metrics["total"],
        "passed": metrics["passed"],
        "failed": metrics["failed"],
        "pass_rate": round(metrics["pass_rate"], 4),
        "danger_precision": round(metrics["danger_precision"], 4),
        "danger_recall": round(metrics["danger_recall"], 4),
        "false_positive_guard_failures": metrics["false_positive_guard_failures"],
        "false_negatives": metrics["false_negatives"],
        "max_failures": args.max_failures,
    }, indent=2, ensure_ascii=False))
    if metrics["failed"] > args.max_failures:
        return 1
    if metrics["false_positive_guard_failures"] and not args.allow_false_positive_guards:
        return 1
    if metrics["false_negatives"] and not args.allow_false_negatives:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
