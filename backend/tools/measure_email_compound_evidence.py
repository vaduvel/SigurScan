#!/usr/bin/env python3
"""Measure compound MIME extraction without labels, providers, or verdicts."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import io
import json
import os
import sys
import zipfile
from collections import Counter
from pathlib import Path
from typing import Iterable, Iterator, Tuple


os.environ["SIGURSCAN_SAFE_MODE"] = "true"
os.environ["EMAIL_COMPOUND_EVIDENCE_ACTIVE"] = "false"

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from fastapi import UploadFile  # noqa: E402
from services import extract_pipeline  # noqa: E402


def _iter_emails(inputs: Iterable[str]) -> Iterator[Tuple[str, bytes]]:
    for raw_input in inputs:
        path = Path(raw_input).expanduser().resolve()
        if path.is_dir():
            for email_path in sorted(path.rglob("*.eml")):
                yield path.name, email_path.read_bytes()
            continue
        if path.suffix.lower() == ".eml":
            yield path.parent.name, path.read_bytes()
            continue
        if path.suffix.lower() == ".zip":
            with zipfile.ZipFile(path) as archive:
                for member in sorted(archive.namelist()):
                    if member.lower().endswith(".eml") and not member.endswith("/"):
                        yield path.name, archive.read(member)


async def _measure_case(source_set: str, payload: bytes) -> dict:
    upload = UploadFile(filename="message.eml", file=io.BytesIO(payload))
    extraction = await extract_pipeline.extract_email_for_orchestration(
        email_file=upload,
        source_channel="offline_measurement",
    )
    ledger = extraction.get("email_evidence_ledger")
    ledger = ledger if isinstance(ledger, dict) else {}
    summary = ledger.get("summary") if isinstance(ledger.get("summary"), dict) else {}
    coverage = ledger.get("coverage") if isinstance(ledger.get("coverage"), dict) else {}
    body_urls = {
        str(url).strip()
        for url in extraction.get("extracted_urls") or []
        if str(url).strip()
    }
    candidate_urls = {
        str(url).strip()
        for url in extraction.get("email_compound_candidate_urls") or []
        if str(url).strip()
    }
    return {
        "source_set": source_set,
        "case_hash": hashlib.sha256(payload).hexdigest()[:16],
        "body_url_count": len(body_urls),
        "attachment_count": int(summary.get("attachment_count") or 0),
        "extracted_attachment_count": int(summary.get("extracted_attachment_count") or 0),
        "unsupported_attachment_count": int(summary.get("unsupported_attachment_count") or 0),
        "failed_attachment_count": int(summary.get("failed_attachment_count") or 0),
        "candidate_attachment_url_count": len(candidate_urls),
        "new_attachment_url_count": len(candidate_urls - body_urls),
        "candidate_qr_count": int(summary.get("candidate_qr_count") or 0),
        "coverage_status": str(coverage.get("status") or "unknown"),
        "email_auth_present": bool(extraction.get("email_auth")),
        "warning_present": bool(extraction.get("warning")),
    }


async def _run(inputs: Iterable[str], *, include_rows: bool = False) -> dict:
    extract_pipeline.EMAIL_COMPOUND_EVIDENCE_ACTIVE = False
    rows = []
    for source_set, payload in _iter_emails(inputs):
        try:
            rows.append(await _measure_case(source_set, payload))
        except Exception as exc:
            rows.append(
                {
                    "source_set": source_set,
                    "case_hash": hashlib.sha256(payload).hexdigest()[:16],
                    "measurement_error": type(exc).__name__,
                }
            )

    measured = [row for row in rows if "measurement_error" not in row]
    report = {
        "schema": "sigurscan_email_compound_measurement_v1",
        "mode": "privacy_safe_unlabeled_shadow",
        "active_flag": False,
        "source_set_case_counts": dict(
            sorted(Counter(str(row.get("source_set") or "unknown") for row in rows).items())
        ),
        "case_count": len(rows),
        "measured_case_count": len(measured),
        "error_count": len(rows) - len(measured),
        "cases_with_attachments": sum(bool(row.get("attachment_count")) for row in measured),
        "attachment_count": sum(int(row.get("attachment_count") or 0) for row in measured),
        "new_attachment_url_count": sum(
            int(row.get("new_attachment_url_count") or 0) for row in measured
        ),
        "candidate_qr_count": sum(int(row.get("candidate_qr_count") or 0) for row in measured),
        "coverage": {
            status: sum(row.get("coverage_status") == status for row in measured)
            for status in ("complete", "partial", "unknown")
        },
    }
    if include_rows:
        report["rows"] = rows
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("inputs", nargs="+", help=".eml file, directory, or zip archive")
    parser.add_argument("--output", required=True, help="Privacy-safe JSON report path")
    parser.add_argument(
        "--include-rows",
        action="store_true",
        help="Include privacy-safe per-message hashes and counters in the report.",
    )
    args = parser.parse_args()
    report = asyncio.run(_run(args.inputs, include_rows=args.include_rows))
    output = Path(args.output).expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({key: value for key, value in report.items() if key != "rows"}, indent=2))
    return 0 if report["error_count"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
