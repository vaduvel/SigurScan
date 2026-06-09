#!/usr/bin/env python3
"""Warm SigurScan urlscan preview cache for trusted, official URLs.

Default mode is dry-run so this tool cannot burn urlscan quota accidentally.
Use --execute explicitly when you want to submit/poll real orchestrated scans.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any, Callable, Iterable

import requests


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SEED_PATH = ROOT / "backend" / "data" / "preview_seed_urls_ro.json"
DEFAULT_BASE_URL = "https://nudaclick-backend.vercel.app"


def _normalize_seed_entry(entry: Any) -> dict[str, Any] | None:
    if not isinstance(entry, dict) or entry.get("enabled") is False:
        return None
    url = str(entry.get("url") or "").strip()
    if not url:
        return None
    return {
        "label": str(entry.get("label") or url).strip(),
        "url": url,
        "brand": str(entry.get("brand") or "").strip() or None,
        "source_channel": str(entry.get("source_channel") or "preview_seed").strip() or "preview_seed",
    }


def load_seed_urls(path: str | Path = DEFAULT_SEED_PATH) -> list[dict[str, Any]]:
    seed_path = Path(path)
    with seed_path.open("r", encoding="utf-8") as handle:
        raw = json.load(handle)
    entries = raw.get("urls") if isinstance(raw, dict) else raw
    if not isinstance(entries, list):
        raise ValueError("Preview seed file must contain a list or an object with a 'urls' list.")
    output: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry in entries:
        normalized = _normalize_seed_entry(entry)
        if not normalized:
            continue
        fingerprint = normalized["url"].lower()
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        output.append({key: value for key, value in normalized.items() if value is not None})
    return output


def _orchestrated_payload(seed: dict[str, Any]) -> dict[str, Any]:
    return {
        "input_type": "url",
        "url": seed["url"],
        "source_channel": seed.get("source_channel") or "preview_seed",
    }


def preseed_one(
    seed: dict[str, Any],
    *,
    base_url: str = DEFAULT_BASE_URL,
    client: requests.Session | None = None,
    timeout_seconds: int = 90,
    poll_interval_seconds: float = 2.0,
    request_timeout_seconds: float = 12.0,
    sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    session = client or requests.Session()
    base = base_url.rstrip("/")
    started_at = time.time()
    start_response = session.post(
        f"{base}/v1/scan/orchestrated",
        json=_orchestrated_payload(seed),
        timeout=request_timeout_seconds,
    )
    start_response.raise_for_status()
    scan_id = start_response.json().get("scan_id")
    if not scan_id:
        return {"label": seed.get("label"), "url": seed.get("url"), "status": "error", "details": "missing scan_id"}

    last_payload: dict[str, Any] = {}
    while time.time() - started_at <= timeout_seconds:
        response = session.get(f"{base}/v1/scan/orchestrated/{scan_id}", timeout=request_timeout_seconds)
        response.raise_for_status()
        payload = response.json()
        last_payload = payload if isinstance(payload, dict) else {}
        preview = last_payload.get("preview") if isinstance(last_payload.get("preview"), dict) else {}
        preview_is_cached = bool(preview.get("cache_hit"))
        preview_is_saved = bool(preview.get("cache_saved"))
        if preview.get("screenshot_url") and (preview_is_cached or preview_is_saved):
            return {
                "label": seed.get("label"),
                "url": seed.get("url"),
                "status": "preview_ready",
                "scan_id": scan_id,
                "cache_hit": preview_is_cached,
                "cache_saved": preview_is_saved,
                "final_url": preview.get("final_url"),
                "report_url": preview.get("report_url"),
                "screenshot_url": preview.get("screenshot_url"),
                "elapsed_seconds": round(time.time() - started_at, 2),
            }
        if last_payload.get("status") == "complete":
            return {
                "label": seed.get("label"),
                "url": seed.get("url"),
                "status": "complete_without_preview",
                "scan_id": scan_id,
                "elapsed_seconds": round(time.time() - started_at, 2),
            }
        sleep(poll_interval_seconds)

    return {
        "label": seed.get("label"),
        "url": seed.get("url"),
        "status": "timeout",
        "scan_id": scan_id,
        "last_status": last_payload.get("status"),
        "elapsed_seconds": round(time.time() - started_at, 2),
    }


def run_preseed(
    seeds: Iterable[dict[str, Any]],
    *,
    base_url: str = DEFAULT_BASE_URL,
    client: requests.Session | None = None,
    dry_run: bool = True,
    limit: int | None = None,
    offset: int = 0,
    timeout_seconds: int = 90,
    poll_interval_seconds: float = 2.0,
) -> list[dict[str, Any]]:
    selected = list(seeds)
    if isinstance(offset, int) and offset > 0:
        selected = selected[offset:]
    if isinstance(limit, int) and limit > 0:
        selected = selected[:limit]
    if dry_run:
        return [
            {"label": seed.get("label"), "url": seed.get("url"), "status": "dry_run"}
            for seed in selected
        ]
    session = client or requests.Session()
    return [
        preseed_one(
            seed,
            base_url=base_url,
            client=session,
            timeout_seconds=timeout_seconds,
            poll_interval_seconds=poll_interval_seconds,
        )
        for seed in selected
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description="Warm SigurScan urlscan preview cache for official URLs.")
    parser.add_argument("--seed-file", default=str(DEFAULT_SEED_PATH))
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--limit", type=int, default=5)
    parser.add_argument("--offset", type=int, default=0)
    parser.add_argument("--timeout", type=int, default=90)
    parser.add_argument("--poll-interval", type=float, default=2.0)
    parser.add_argument("--execute", action="store_true", help="Actually call the backend. Default is dry-run.")
    args = parser.parse_args()

    seeds = load_seed_urls(args.seed_file)
    results = run_preseed(
        seeds,
        base_url=args.base_url,
        dry_run=not args.execute,
        limit=args.limit,
        offset=args.offset,
        timeout_seconds=args.timeout,
        poll_interval_seconds=args.poll_interval,
    )
    print(json.dumps({"dry_run": not args.execute, "count": len(results), "results": results}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
