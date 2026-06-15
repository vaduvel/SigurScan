"""
Lightweight RSS feed worker for Urechea OSINT ingestion.

Polls configured RSS feeds, ingests raw entries via UrecheaIngester,
and logs results. Designed to run as a cron / scheduled job
(e.g., every 30 minutes via systemd timer or GitHub cron action).

Usage:
  python -m services.urechea_rss_worker
"""

import logging
import os
import sys
import time
import json
from typing import List

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from services.campaign_intel import CampaignStore
from services.urechea_ingester import UrecheaIngester, SEED_SOURCES
from services import supabase_store

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
)
logger = logging.getLogger("urechea_worker")


def _source_names(ingester: UrecheaIngester, raw_names: List[str] | None = None) -> List[str]:
    if not raw_names:
        return [s.name for s in SEED_SOURCES if s.feed_url is not None]
    names: List[str] = []
    for item in raw_names:
        for part in str(item or "").split(","):
            name = part.strip()
            if name:
                names.append(name)
    return names or [s.name for s in SEED_SOURCES if s.feed_url is not None]


def run(source_names: List[str] | None = None) -> int:
    """Fetch RSS feeds, ingest entries, return number ingested."""
    store = CampaignStore()
    ingester = UrecheaIngester(store)
    sources_to_fetch = _source_names(ingester, source_names)
    total = 0
    for name in sources_to_fetch:
        entries = ingester.fetch_source(name)
        if not entries:
            logger.info("Source %s: 0 entries", name)
            continue
        ingested = 0
        for entry in entries:
            try:
                intel = ingester.ingest_raw(
                    title=entry.get("title", ""),
                    body=entry.get("body", ""),
                    source_url=entry.get("link", ""),
                    source_kind=next((s.kind for s in SEED_SOURCES if s.name == name), "press_context"),
                )
                supabase_store.save_campaign_intel(intel.to_dict())
                ingested += 1
            except Exception as e:
                logger.warning("Failed to ingest entry from %s: %s", name, e)
        total += ingested
        logger.info("Source %s: ingested %d/%d entries", name, ingested, len(entries))
    return total


if __name__ == "__main__":
    logger.info("Urechea RSS worker starting")
    start = time.time()
    count = run(sys.argv[1:] or None)
    elapsed = time.time() - start
    print(json.dumps({"ingested": count, "elapsed_seconds": round(elapsed, 3)}, sort_keys=True))
    logger.info("Worker finished: %d entries ingested in %.2fs", count, elapsed)
