from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from services.campaign_intel import CampaignIntel, CampaignStore, FAMILY_TAXONOMY


logger = logging.getLogger("urechea")


@dataclass
class OsintSource:
    name: str
    kind: str
    feed_url: Optional[str] = None
    fetch_strategy: str = "rss"
    confidence: str = "medium"
    enabled: bool = True


SEED_SOURCES: List[OsintSource] = [
    OsintSource(name="DNSC", kind="official_alert", feed_url="https://www.dnsc.ro/feed", fetch_strategy="rss", confidence="high"),
    OsintSource(name="SigurantaOnline", kind="official_alert", feed_url="https://www.sigurantaonline.ro/feed", fetch_strategy="rss", confidence="high"),
    OsintSource(name="Mediafax", kind="press_context", feed_url="https://mediafax.ro/feed", fetch_strategy="rss", confidence="medium"),
    OsintSource(name="HotNews", kind="press_context", feed_url="https://www.hotnews.ro/feed", fetch_strategy="rss", confidence="medium"),
    OsintSource(name="Adevarul", kind="press_context", feed_url="https://adevarul.ro/feed", fetch_strategy="rss", confidence="medium"),
    OsintSource(name="StirileProTV", kind="press_context", feed_url="https://stirileprotv.ro/feed", fetch_strategy="rss", confidence="medium"),
    OsintSource(name="Economedia", kind="press_context", feed_url="https://economedia.ro/feed", fetch_strategy="rss", confidence="medium"),
    OsintSource(name="FactualRO", kind="press_context", feed_url="https://factual.ro/feed", fetch_strategy="rss", confidence="medium"),
    OsintSource(name="VendorOne", kind="vendor_advisory", feed_url=None, fetch_strategy="manual", confidence="high"),
    OsintSource(name="VendorTwo", kind="vendor_advisory", feed_url=None, fetch_strategy="manual", confidence="high"),
]


INTEL_ID_COUNTER: int = 0


def _next_intel_id() -> str:
    global INTEL_ID_COUNTER
    INTEL_ID_COUNTER += 1
    return f"ci_{int(time.time())}_{INTEL_ID_COUNTER}"


class UrecheaIngester:
    """Feeder engine: ingest OSINT sources → extract intel → moderate → store."""

    def __init__(self, store: CampaignStore):
        self._store = store
        self._sources = {s.name: s for s in SEED_SOURCES}
        self._moderation_queue: List[CampaignIntel] = []

    @property
    def sources(self) -> Dict[str, OsintSource]:
        return dict(self._sources)

    @property
    def moderation_queue(self) -> List[CampaignIntel]:
        return list(self._moderation_queue)

    @staticmethod
    def _normalize(text: str) -> str:
        replacements = {
            "ș": "s", "ș": "s", "ț": "t", "ț": "t", "ț": "t",
            "â": "a", "Â": "a", "î": "i", "Î": "i",
            "ă": "a", "Ă": "a",
        }
        for old, new in replacements.items():
            text = text.replace(old, new)
        return text

    def _classify_family(self, text: str, claimed_identity: Optional[str] = None) -> str:
        text_lower = self._normalize((text or "").lower())
        identity_lower = self._normalize((claimed_identity or "").lower())

        family_signals = {
            "IMP-01": ["cont sigur", "transfera fondurile", "banca"],
            "IMP-02": ["investitii", "investeste", "castig", "dividend", "profit", "platforma"],
            "IMP-03": ["curier", "taxa vamala", "colet", "awb", "fan courier", "sameday", "cargus"],
            "IMP-04": ["salveaza numarul", "noua mea", "schimbat numarul", "frate", "sora", "mama", "tata"],
            "IMP-05": ["whatsapp", "cod", "verificare", "2fa"],
            "IMP-06": ["anydesk", "teamviewer", "remote", "asistenta tehnica", "virus"],
            "IMP-07": ["olx", "card", "primi bani", "vanzare", "cumparator"],
            "IMP-08": ["job", "task", "top-up", "incarca", "comision"],
            "IMP-09": ["dating", "romance", "iubire", "relatie", "sentimental"],
            "OP-01": ["iban", "cont nou", "schimbat", "factura", "plata", "anaf"],
            "OP-02": ["avans", "plată în avans", "achizitie", "oferta"],
            "OP-03": ["parcare", "qr", "amenda", "plată parcare"],
        }

        family_identity_signals = {
            "IMP-01": ["bnr"],
        }

        for family, signals in family_signals.items():
            for signal in signals:
                if signal in text_lower:
                    return family

        for family, signals in family_identity_signals.items():
            for signal in signals:
                if identity_lower and signal in identity_lower:
                    return family

        return "UNKNOWN"

    def _compute_fingerprint_hash(self, intel: CampaignIntel) -> str:
        canonical = json.dumps(intel.skeleton, ensure_ascii=False, sort_keys=True)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]

    def ingest_raw(
        self,
        title: str,
        body: str,
        source_url: str,
        source_kind: str,
        *,
        claimed_identity: Optional[str] = None,
        evidence_quality: str = "medium",
        regions_hint: Optional[List[str]] = None,
    ) -> CampaignIntel:
        family = self._classify_family(body, claimed_identity)
        skeleton = {
            "claimed_identity": claimed_identity or "unknown",
            "ask": (body or "")[:200],
            "channel": "sms",
        }
        intel_id = _next_intel_id()
        now = time.time()
        intel = CampaignIntel(
            intel_id=intel_id,
            family=family,
            skeleton=skeleton,
            iocs={"domain_hashes": [], "display_redacted": []},
            source={"kind": source_kind, "url": source_url, "published_at": time.strftime("%Y-%m-%d", time.gmtime(now))},
            evidence_quality=evidence_quality,
            status="active",
            regions_hint=regions_hint or ["national"],
            moderation={},
            created_at=now,
            last_seen_at=now,
        )

        if intel.family == "UNKNOWN":
            intel.status = "draft"
            logger.info("Intel %s classified unknown -> draft", intel_id)

        if evidence_quality == "high" and source_kind in ("official_alert", "vendor_advisory"):
            intel.moderation = {"approved": True, "approved_by": "auto", "approved_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))}
            logger.info("Intel %s auto-approved (high quality, official source)", intel_id)
        else:
            self._moderation_queue.append(intel)
            intel.moderation = {"required_for": "dangerous", "approved": False}
            logger.info("Intel %s queued for moderation", intel_id)

        self._store.put(intel)
        return intel

    def approve_intel(self, intel_id: str, approved_by: str) -> bool:
        intel = self._store.get(intel_id)
        if not intel:
            return False
        intel.moderation["approved"] = True
        intel.moderation["approved_by"] = approved_by
        intel.moderation["approved_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time()))
        intel.status = "active"
        self._store.put(intel)
        self._moderation_queue = [i for i in self._moderation_queue if i.intel_id != intel_id]
        logger.info("Intel %s approved by %s", intel_id, approved_by)
        return True

    def reject_intel(self, intel_id: str) -> bool:
        intel = self._store.get(intel_id)
        if not intel:
            return False
        intel.status = "rejected"
        intel.moderation["approved"] = False
        self._store.put(intel)
        self._moderation_queue = [i for i in self._moderation_queue if i.intel_id != intel_id]
        logger.info("Intel %s rejected", intel_id)
        return True

    def fetch_source(self, source_name: str) -> List[Dict[str, str]]:
        source = self._sources.get(source_name)
        if not source or not source.enabled:
            return []
        if source.fetch_strategy in ("rss",):
            return self._fetch_rss(source)
        return []

    def _fetch_rss(self, source: OsintSource) -> List[Dict[str, str]]:
        if not source.feed_url:
            return []
        try:
            import feedparser
            feed = feedparser.parse(source.feed_url)
            entries = []
            for entry in feed.entries[:20]:
                entries.append({
                    "title": entry.get("title", ""),
                    "body": entry.get("summary", entry.get("description", "")),
                    "link": entry.get("link", ""),
                    "published": entry.get("published", ""),
                })
            return entries
        except Exception as e:
            logger.warning("RSS fetch failed for %s: %s", source.name, e)
            return []
