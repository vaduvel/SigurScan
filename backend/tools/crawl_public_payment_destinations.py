#!/usr/bin/env python3
"""Crawl public/official pages for payment-destination IBAN candidates.

Outputs are backend-only. Raw IBANs are intentionally suitable for server-side
matching seeds, not Android/client distribution.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[2]
BACKEND_DIR = ROOT / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from services.public_payment_destination_crawler import (  # noqa: E402
    build_payment_destination_registry_delta,
    crawl_public_payment_sources,
)


DEFAULT_MANIFEST = (
    BACKEND_DIR
    / "data"
    / "payment_destination_registry"
    / "public_payment_crawl_sources_ro.json"
)


def _load_manifest(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or not isinstance(payload.get("sources"), list):
        raise ValueError(f"Manifest must be a JSON object with a sources list: {path}")
    return payload


def _write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def run_crawl(
    manifest_path: str | Path = DEFAULT_MANIFEST,
    *,
    fetcher: Callable[..., Any] | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    manifest_path = Path(manifest_path)
    manifest = _load_manifest(manifest_path)
    crawl = crawl_public_payment_sources(manifest.get("sources") or [], fetcher=fetcher, limit=limit)
    registry_delta = build_payment_destination_registry_delta(
        crawl["candidates"],
        version=manifest.get("output_version"),
    )
    return {
        "manifest": str(manifest_path),
        "summary": crawl["summary"],
        "candidates": crawl["candidates"],
        "errors": crawl["errors"],
        "registry_delta": registry_delta,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--jsonl-output", type=Path, default=None)
    parser.add_argument("--registry-output", type=Path, default=None)
    parser.add_argument("--summary-output", type=Path, default=None)
    args = parser.parse_args(argv)

    result = run_crawl(args.manifest, limit=args.limit)
    if args.jsonl_output:
        _write_jsonl(args.jsonl_output, result["candidates"])
    if args.registry_output:
        _write_json(args.registry_output, result["registry_delta"])
    if args.summary_output:
        _write_json(args.summary_output, {"summary": result["summary"], "errors": result["errors"]})
    print(json.dumps({"summary": result["summary"], "errors": result["errors"]}, ensure_ascii=False, indent=2))
    return 1 if result["errors"] and not result["candidates"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
