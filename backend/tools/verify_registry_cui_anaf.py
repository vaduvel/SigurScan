#!/usr/bin/env python3
"""Verify payment_destination_registry CUIs against the official ANAF web service.

Why: registry seeds declare their own freshness (generated_at / reverify_interval)
but that does NOT prove the CUI is correct. The Altex false-positive was caused by
a wrong CUI (13831166 in seed vs 2864518 real). This tool cross-checks every CUI
in the registry against ANAF (the source of truth for CUI + legal name + active
status) and reports discrepancies. Read-only by default.

Usage:
    python3 verify_registry_cui_anaf.py \
        --dir backend/data/payment_destination_registry \
        --out-json cui_verification_report.json \
        --out-csv cui_discrepancies.csv

Notes:
- Needs outbound network to https://webservicesp.anaf.ro (public, no auth).
- Stdlib only (urllib). No pip install required.
- ANAF v9: POST /api/PlatitorTvaRest/v9/tva, body [{"cui":<int>,"data":"YYYY-MM-DD"}],
  max 100 CUIs/request, ~1 request/second.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import time
import unicodedata
import urllib.request
import urllib.error
from datetime import date
from pathlib import Path
from typing import Any, Iterable

ANAF_URL = "https://webservicesp.anaf.ro/api/PlatitorTvaRest/v9/tva"
BATCH_SIZE = 100
SLEEP_BETWEEN_REQUESTS = 1.1  # respect ANAF ~1 req/s limit

_LEGAL_SUFFIXES = [
    "S.R.L.", "SRL", "S.A.", "SA", "S.C.", "SC", "PFA", "IFN", "EAD",
    "SUCURSALA BUCURESTI", "SUCURSALA", "ASIGURARE", "ASIGURARI",
    "FUNDATIA", "FUNDATIA CENTRUL DE FORMARE",
]


def strip_diacritics(text: str) -> str:
    nfkd = unicodedata.normalize("NFKD", text)
    return "".join(ch for ch in nfkd if not unicodedata.combining(ch))


def norm_name(text: str) -> str:
    text = strip_diacritics(str(text or "")).upper()
    text = text.replace("&", " ").replace(".", " ").replace(",", " ")
    text = re.sub(r"[^A-Z0-9 ]+", " ", text)
    for suf in sorted(_LEGAL_SUFFIXES, key=len, reverse=True):
        text = re.sub(rf"\b{re.escape(strip_diacritics(suf).upper())}\b", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def norm_cui(value: Any) -> str | None:
    digits = "".join(ch for ch in str(value or "") if ch.isdigit())
    return digits.lstrip("0") or (digits and "0") or None


def name_tokens(text: str) -> set[str]:
    return {t for t in norm_name(text).split(" ") if len(t) >= 3}


def names_match(registry_name: str, anaf_name: str) -> bool:
    a = norm_name(registry_name)
    b = norm_name(anaf_name)
    if not a or not b:
        return False
    if a == b or a in b or b in a:
        return True
    ta, tb = name_tokens(registry_name), name_tokens(anaf_name)
    if not ta or not tb:
        return False
    overlap = len(ta & tb) / min(len(ta), len(tb))
    return overlap >= 0.6


def iter_entries(payload: Any) -> Iterable[dict[str, Any]]:
    """Yield registry entry dicts across the known file shapes."""
    if isinstance(payload, dict):
        entries = payload.get("entries")
        if isinstance(entries, list):
            for e in entries:
                if isinstance(e, dict):
                    yield e


def collect_registry_cuis(directory: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            print(f"WARN: cannot parse {path.name}: {exc}", file=sys.stderr)
            continue
        for entry in iter_entries(payload):
            cui = norm_cui(entry.get("cui"))
            if not cui:
                continue
            src = ""
            refs = entry.get("source_refs") or []
            if isinstance(refs, list) and refs and isinstance(refs[0], dict):
                src = str(refs[0].get("url") or "")
            rows.append(
                {
                    "file": path.name,
                    "brand_id": entry.get("brand_id"),
                    "display_name": entry.get("display_name"),
                    "legal_name": entry.get("legal_name") or entry.get("display_name"),
                    "cui": cui,
                    "review_status": entry.get("review_status"),
                    "source_url": src,
                }
            )
    return rows


def query_anaf(cuis: list[str], as_of: str) -> dict[str, dict[str, Any]]:
    """Return {cui: anaf_record} for all queried CUIs (missing => not in result)."""
    out: dict[str, dict[str, Any]] = {}
    unique = sorted(set(cuis), key=int)
    for i in range(0, len(unique), BATCH_SIZE):
        chunk = unique[i : i + BATCH_SIZE]
        body = json.dumps([{"cui": int(c), "data": as_of} for c in chunk]).encode("utf-8")
        req = urllib.request.Request(
            ANAF_URL,
            data=body,
            headers={"Content-Type": "application/json", "User-Agent": "SigurScan-CUI-Verify/1.0"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            print(f"ERROR: ANAF HTTP {exc.code} on batch {i//BATCH_SIZE}", file=sys.stderr)
            time.sleep(SLEEP_BETWEEN_REQUESTS)
            continue
        except Exception as exc:
            print(f"ERROR: ANAF call failed on batch {i//BATCH_SIZE}: {exc}", file=sys.stderr)
            time.sleep(SLEEP_BETWEEN_REQUESTS)
            continue
        for rec in data.get("found", []) or []:
            dg = rec.get("date_generale", {}) if isinstance(rec, dict) else {}
            c = norm_cui(dg.get("cui"))
            if c:
                out[c] = rec
        print(f"  batch {i//BATCH_SIZE+1}: queried {len(chunk)}, cumulative found {len(out)}", file=sys.stderr)
        time.sleep(SLEEP_BETWEEN_REQUESTS)
    return out


def _is_inactive(rec: dict[str, Any]) -> bool:
    dg = rec.get("date_generale", {}) or {}
    inact = rec.get("stare_inactiv", {}) or {}
    if dg.get("statusInactivi") is True:
        return True
    if inact.get("statusInactivi") is True:
        return True
    stare = str(dg.get("stare_inregistrare") or dg.get("stareInregistrare") or "").upper()
    if "RADIAT" in stare or "INACTIV" in stare:
        return True
    return False


def _anaf_name(rec: dict[str, Any]) -> str:
    dg = rec.get("date_generale", {}) or {}
    return str(dg.get("denumire") or "")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--dir", type=Path, default=Path("backend/data/payment_destination_registry"))
    ap.add_argument("--as-of", default=date.today().isoformat())
    ap.add_argument("--out-json", type=Path, default=Path("cui_verification_report.json"))
    ap.add_argument("--out-csv", type=Path, default=Path("cui_discrepancies.csv"))
    ap.add_argument("--offline-extract-only", action="store_true",
                    help="Only extract CUIs from the registry; do not call ANAF.")
    args = ap.parse_args(argv)

    if not args.dir.is_dir():
        print(f"FATAL: directory not found: {args.dir}", file=sys.stderr)
        return 2

    rows = collect_registry_cuis(args.dir)
    unique_cuis = sorted({r["cui"] for r in rows}, key=int)
    print(f"Extracted {len(rows)} registry entries with CUI across {len({r['file'] for r in rows})} files; "
          f"{len(unique_cuis)} unique CUIs.", file=sys.stderr)

    if args.offline_extract_only:
        args.out_json.write_text(json.dumps({"as_of": args.as_of, "entries": rows,
                                             "unique_cuis": unique_cuis}, ensure_ascii=False, indent=2),
                                 encoding="utf-8")
        print(f"Wrote extraction to {args.out_json} (no ANAF call).")
        return 0

    anaf = query_anaf(unique_cuis, args.as_of)

    results = []
    discrepancies = []
    for r in rows:
        rec = anaf.get(r["cui"])
        status = "OK"
        detail = ""
        anaf_name = ""
        if rec is None:
            status = "CUI_NOT_FOUND_IN_ANAF"
            detail = "CUI not returned by ANAF (possibly invalid, radiat, or typo)."
        else:
            anaf_name = _anaf_name(rec)
            if _is_inactive(rec):
                status = "INACTIVE_OR_RADIATED"
                detail = f"ANAF marks entity inactive/radiat. ANAF name: {anaf_name}"
            elif not names_match(r["legal_name"] or r["display_name"] or "", anaf_name):
                status = "NAME_MISMATCH"
                detail = f"Registry '{r['legal_name']}' vs ANAF '{anaf_name}'"
        row = {**r, "anaf_name": anaf_name, "status": status, "detail": detail}
        results.append(row)
        if status != "OK":
            discrepancies.append(row)

    summary = {
        "as_of": args.as_of,
        "total_entries": len(rows),
        "unique_cuis": len(unique_cuis),
        "ok": sum(1 for x in results if x["status"] == "OK"),
        "discrepancies": len(discrepancies),
        "by_status": {},
    }
    for x in results:
        summary["by_status"][x["status"]] = summary["by_status"].get(x["status"], 0) + 1

    args.out_json.write_text(
        json.dumps({"summary": summary, "results": results}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    with args.out_csv.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["status", "file", "brand_id", "display_name",
                                           "legal_name", "cui", "anaf_name", "detail", "source_url"])
        w.writeheader()
        for x in sorted(discrepancies, key=lambda d: (d["status"], d["file"])):
            w.writerow({k: x.get(k, "") for k in w.fieldnames})

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
