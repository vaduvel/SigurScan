#!/usr/bin/env python3
"""Import an official URL patch report into SigurScan seed files.

The report is expected to contain one fenced ```json block with a list of
entries. Entries with preview_seed_include=true are added to preview seed files.
Registry-only/login/private portal entries are preserved in the patch artifact
but deliberately excluded from preview capture.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import date
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "backend" / "data" / "knowledge" / "official_url_patch_2026_06_14.json"
BACKEND_PREVIEW_SEED = ROOT / "backend" / "data" / "preview_seed_urls_ro.json"
WORKER_PREVIEW_SEED = ROOT / "workers" / "precapture" / "samples" / "official_preview_targets.ro.json"


def _load_report(path: Path) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    text = path.read_text(encoding="utf-8")
    match = re.search(r"```json\s*(.*?)\s*```", text, re.S)
    if not match:
        raise ValueError("No fenced json block found in report.")
    raw = json.loads(match.group(1))
    if not isinstance(raw, list):
        raise ValueError("Report json block must contain a list.")

    entries: list[dict[str, Any]] = []
    needs_review: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        if "needs_human_review" in item:
            review_items = item.get("needs_human_review")
            if isinstance(review_items, list):
                needs_review.extend(x for x in review_items if isinstance(x, dict))
            continue
        required = {"brand_id", "display_name", "url", "preview_seed_include", "registry_include"}
        missing = sorted(required - set(item))
        if missing:
            raise ValueError(f"Patch entry missing required fields {missing}: {item!r}")
        entries.append(item)

    return entries, needs_review


def _normalized_url(url: str) -> str | None:
    value = str(url or "").strip()
    if value in {"", "needs_exact_url"}:
        return None
    if not re.match(r"^https?://", value, flags=re.I):
        value = f"https://{value}"
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    host = parsed.hostname.lower()
    if host.endswith((".test", ".invalid", ".example", ".localhost")):
        return None
    path = re.sub(r"/+$", "", parsed.path or "/") or "/"
    return f"https://{host}{path}" + ("" if path != "/" else "")


def _seed_id(entry: dict[str, Any]) -> str:
    brand_id = re.sub(r"[^a-z0-9]+", "_", str(entry["brand_id"]).lower()).strip("_")
    url_hash = hashlib.sha256(str(entry["url"]).encode("utf-8")).hexdigest()[:8]
    return f"official_patch_{brand_id}_{url_hash}"


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _merge_backend_preview(entries: list[dict[str, Any]]) -> int:
    seed = _load_json(BACKEND_PREVIEW_SEED)
    urls = seed.setdefault("urls", [])
    seen = {_normalized_url(item.get("url")) for item in urls if isinstance(item, dict)}
    added = 0
    for entry in entries:
        if entry.get("preview_seed_include") is not True:
            continue
        normalized = _normalized_url(str(entry.get("url") or ""))
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        urls.append(
            {
                "label": entry["display_name"],
                "brand": entry["display_name"],
                "url": normalized,
                "source_channel": "official_url_patch_2026_06_14",
                "source_url": entry.get("official_evidence_url"),
            }
        )
        added += 1
    _write_json(BACKEND_PREVIEW_SEED, seed)
    return added


def _merge_worker_preview(entries: list[dict[str, Any]]) -> int:
    seed = _load_json(WORKER_PREVIEW_SEED)
    targets = seed.setdefault("targets", [])
    seen = {_normalized_url(item.get("url")) for item in targets if isinstance(item, dict)}
    added = 0
    for entry in entries:
        if entry.get("preview_seed_include") is not True:
            continue
        normalized = _normalized_url(str(entry.get("url") or ""))
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        targets.append(
            {
                "id": _seed_id(entry),
                "brand_id": entry["brand_id"],
                "display_name": entry["display_name"],
                "url": normalized,
                "source_url": entry.get("official_evidence_url") or normalized,
                "confidence": entry.get("confidence") or "unknown",
                "source": "official_url_patch_2026_06_14",
            }
        )
        added += 1
    _write_json(WORKER_PREVIEW_SEED, seed)
    return added


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    entries, needs_review = _load_report(args.report)
    patch = {
        "schema": "sigurscan_official_url_patch_v1",
        "generated_at": f"{date.today().isoformat()}T00:00:00Z",
        "source_report": args.report.name,
        "entry_count": len(entries),
        "preview_seed_count": sum(1 for entry in entries if entry.get("preview_seed_include") is True),
        "registry_only_count": sum(
            1 for entry in entries
            if entry.get("registry_include") is True and entry.get("preview_seed_include") is not True
        ),
        "entries": entries,
        "needs_human_review": needs_review,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    _write_json(args.output, patch)
    backend_added = _merge_backend_preview(entries)
    worker_added = _merge_worker_preview(entries)
    print(
        json.dumps(
            {
                "entries": len(entries),
                "needs_human_review": len(needs_review),
                "backend_preview_added": backend_added,
                "worker_preview_added": worker_added,
                "patch_output": str(args.output),
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
