"""URL reputation aggregation service with multi-source support.

This module performs:
- multi-source lookups (Google Web Risk, Phishing.Database, URLhaus);
- per-source confidence scoring;
- cache-safe persistence with source metadata;
- aggregated verdict/reputation payload used by ScamAtlas.
"""

import hashlib
import json
import os
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urlunparse

import requests

from services import supabase_store
from services.google_web_risk import check_urls_against_web_risk, has_web_risk_key


WEB_RISK_SOURCE = "google_web_risk"
PHISHING_DATABASE_SOURCE = "phishing_database"
URLHAUS_SOURCE = "urlhaus"

WEB_RISK_WEIGHT = 60
PHISHING_DATABASE_WEIGHT = 80
URLHAUS_WEIGHT = 55
SOURCE_ORDER = [WEB_RISK_SOURCE, PHISHING_DATABASE_SOURCE, URLHAUS_SOURCE]

SOURCE_WEIGHTS = {
    WEB_RISK_SOURCE: WEB_RISK_WEIGHT,
    PHISHING_DATABASE_SOURCE: PHISHING_DATABASE_WEIGHT,
    URLHAUS_SOURCE: URLHAUS_WEIGHT,
}

SOURCE_STATUS_WEIGHTS = {
    "malicious": 1.0,
    "suspicious": 0.55,
    "clean": 0.0,
    "unknown": 0.0,
    "error": 0.0,
}

REPUTATION_CACHE_VERSION = 3
PHISHING_DATABASE_DOMAINS_URL = os.getenv(
    "PHISHING_DATABASE_DOMAINS_URL",
    "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt",
)
PHISHING_DATABASE_LINKS_URL = os.getenv(
    "PHISHING_DATABASE_LINKS_URL",
    "https://phish.co.za/latest/phishing-links-ACTIVE.txt",
)
URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1/url/"
PHISHING_DATABASE_TIMEOUT_SECONDS = float(os.getenv("PHISHING_DATABASE_TIMEOUT_SECONDS", "4.0"))
PHISHING_DATABASE_FEED_TTL_SECONDS = int(os.getenv("PHISHING_DATABASE_FEED_TTL_SECONDS", "3600"))
URLHAUS_TIMEOUT_SECONDS = float(os.getenv("URLHAUS_TIMEOUT_SECONDS", "3.0"))
URLHAUS_AUTH_KEY = (
    os.getenv("URLHAUS_AUTH_KEY", "").strip()
    or os.getenv("URLHAUS_API_KEY", "").strip()
    or os.getenv("ABUSECH_AUTH_KEY", "").strip()
)
ENABLE_PHISHING_DATABASE = os.getenv("ENABLE_PHISHING_DATABASE", "true").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}
PHISHING_DATABASE_MAX_FEED_BYTES = int(os.getenv("PHISHING_DATABASE_MAX_FEED_BYTES", "20000000"))

_PHISHING_DATABASE_CACHE: Dict[str, Any] = {
    "loaded_at": 0,
    "domains": set(),
    "links": set(),
    "error": None,
}

DEFAULT_CACHE_TTL_SECONDS = int(os.getenv("URL_REPUTATION_CACHE_TTL_SECONDS", "43200"))
MAX_REPUTATION_URLS = int(os.getenv("MAX_REPUTATION_URLS", "60"))
REPUTATION_CACHE_MAX_ITEMS = int(os.getenv("URL_REPUTATION_CACHE_MAX_ITEMS", "1000"))
DEFAULT_REPUTATION_CACHE_PATH = Path(__file__).resolve().parents[1] / "data" / "url_reputation_cache.json"
REPUTATION_CACHE_PATH = Path(
    os.getenv("URL_REPUTATION_CACHE_PATH", str(DEFAULT_REPUTATION_CACHE_PATH)),
)
REPUTATION_CACHE_TTL_SECONDS = int(
    os.getenv("URL_REPUTATION_CACHE_TTL_SECONDS", str(DEFAULT_CACHE_TTL_SECONDS)),
)
ENABLE_URL_REPUTATION = os.getenv("ENABLE_URL_REPUTATION", "true").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}


def _normalize_url_for_key(url: str) -> str:
    return (url or "").strip()


def _url_hash(url: str) -> str:
    normalized = _normalize_url_for_key(url).encode("utf-8")
    return hashlib.sha256(normalized).hexdigest()


def _coerce_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _clamp_int(value: Any, *, min_value: int, max_value: int, default: int = 0) -> int:
    try:
        numeric = int(value)
    except Exception:
        return default
    return max(min_value, min(max_value, numeric))


def _normalize_status(raw_status: Any) -> str:
    status = (str(raw_status).strip().lower() if raw_status is not None else "")
    if status in {"malicious", "suspicious", "clean", "error", "unknown"}:
        return status
    return "unknown"


def _normalize_source_entry(
    source_name: str,
    payload: Dict[str, Any] | None,
    *,
    consulted: bool,
    weight: int,
    fallback_status: str,
) -> Dict[str, Any]:
    payload = dict(payload or {})
    status = _normalize_status(payload.get("status", fallback_status))
    details = payload.get("details", {})

    entry: Dict[str, Any] = {
        "source": source_name,
        "status": status,
        "weight": int(weight),
        "consulted": bool(consulted),
        "risk_contribution": round(weight * SOURCE_STATUS_WEIGHTS.get(status, 0.0), 2),
        "score": _clamp_int(payload.get("score", 0), min_value=0, max_value=100),
        "threat_type": str(payload.get("threat_type", "unknown")).lower(),
    }
    if isinstance(details, dict) and details:
        entry["details"] = details
    if payload.get("error") is not None:
        entry["error"] = str(payload.get("error"))
    if payload.get("query_ms") is not None:
        entry["query_ms"] = _coerce_int(payload.get("query_ms", 0), 0)
    return entry


def _load_cache(path: Path) -> Dict[str, Any]:
    remote_cache = supabase_store.load_reputation_cache()
    if remote_cache:
        return remote_cache
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as f:
            payload = json.load(f)
    except Exception:
        return {}
    if isinstance(payload, dict):
        return payload
    return {}


def _prune_cache_for_save(data: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(data, dict):
        return {}
    max_items = max(0, REPUTATION_CACHE_MAX_ITEMS)
    if max_items <= 0 or len(data) <= max_items:
        return data
    now = int(time.time())
    valid_items = [
        (key, value)
        for key, value in data.items()
        if isinstance(value, dict) and _coerce_int(value.get("expires_at", 0), 0) > now
    ]
    if len(valid_items) < max_items:
        valid_items = [(key, value) for key, value in data.items() if isinstance(value, dict)]

    def sort_key(item: tuple[str, Dict[str, Any]]) -> int:
        value = item[1]
        return max(
            _coerce_int(value.get("cached_at", 0), 0),
            _coerce_int(value.get("created_at", 0), 0),
            _coerce_int(value.get("expires_at", 0), 0) - REPUTATION_CACHE_TTL_SECONDS,
        )

    kept = sorted(valid_items, key=sort_key, reverse=True)[:max_items]
    return {key: value for key, value in kept}


def _save_cache(path: Path, data: Dict[str, Any], remote_subset: Optional[Dict[str, Any]] = None) -> None:
    # Local file cache keeps the full snapshot, but Supabase must only receive
    # entries touched by this request. Upserting the entire cache for one URL
    # turns a single reputation lookup into hundreds of network writes.
    supabase_store.save_reputation_cache(remote_subset if remote_subset is not None else data)
    try:
        pruned_data = _prune_cache_for_save(data)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            json.dump(pruned_data, f, ensure_ascii=False, indent=2, sort_keys=True)
    except Exception:
        # Cache persistence is best-effort only.
        return


def _load_cache_entry(cache: Dict[str, Any], url: str) -> Optional[Dict[str, Any]]:
    key = _url_hash(url)
    raw = cache.get(key)
    if not isinstance(raw, dict):
        return None
    if raw.get("version", REPUTATION_CACHE_VERSION) < 2:
        # old schema migration path: keep only what can be safely reused
        return None
    return raw


def _is_cache_entry_valid(entry: Dict[str, Any], now: int) -> bool:
    if not isinstance(entry, dict):
        return False
    if not entry.get("verdict"):
        return False
    sources = entry.get("sources")
    if isinstance(sources, dict) and any(
        isinstance(source_payload, dict) and _normalize_status(source_payload.get("status")) == "error"
        for source_payload in sources.values()
    ):
        return False
    expires_at = _coerce_int(entry.get("expires_at", 0))
    return expires_at > now


def _cache_entry_covers_requested_sources(
    entry: Dict[str, Any],
    *,
    include_phishing_database: bool,
    include_urlhaus: bool,
    urlhaus_key: str,
    web_risk_enabled: bool,
) -> bool:
    sources = entry.get("sources")
    if not isinstance(sources, dict):
        return False

    required_sources: List[str] = []
    if web_risk_enabled:
        required_sources.append(WEB_RISK_SOURCE)
    if include_phishing_database and ENABLE_PHISHING_DATABASE:
        required_sources.append(PHISHING_DATABASE_SOURCE)
    if include_urlhaus and urlhaus_key:
        required_sources.append(URLHAUS_SOURCE)

    for source_name in required_sources:
        source_payload = sources.get(source_name)
        if not isinstance(source_payload, dict) or not source_payload.get("consulted"):
            return False
    return True


def _normalize_cached_entry(entry: Dict[str, Any], url: str, ttl: int) -> Dict[str, Any]:
    cached_at = _coerce_int(entry.get("cached_at", int(time.time())))
    created_at = _coerce_int(entry.get("created_at", cached_at))
    expires_at = _coerce_int(entry.get("expires_at", created_at + ttl))

    normalized: Dict[str, Any] = {
        "url": url,
        "url_hash": _url_hash(url),
        "cached": True,
        "created_at": created_at,
        "cached_at": cached_at,
        "expires_at": expires_at,
        "version": REPUTATION_CACHE_VERSION,
        "verdict": _normalize_status(entry.get("verdict", "unknown")),
        "risk_score": _clamp_int(entry.get("risk_score", 0), min_value=0, max_value=100),
        "confidence": float(entry.get("confidence", 0.0) or 0.0),
        "signals": list(entry.get("signals", [])),
        "active_sources": list(entry.get("active_sources", [])),
        "signal_count": int(entry.get("signal_count", 0)),
        "source_count": int(entry.get("source_count", 0)),
        "consulted_sources": list(entry.get("consulted_sources", [])),
        "consulted_source_count": int(entry.get("consulted_source_count", 0)),
    }

    raw_sources = entry.get("sources")
    if not isinstance(raw_sources, dict):
        raw_sources = {}
    normalized_sources: Dict[str, Any] = {}
    for source_name in SOURCE_ORDER:
        normalized_sources[source_name] = _normalize_source_entry(
            source_name=source_name,
            payload=raw_sources.get(source_name),
            consulted=bool(
                isinstance(raw_sources.get(source_name), dict)
                and raw_sources[source_name].get("consulted", False)
            ),
            weight=SOURCE_WEIGHTS.get(source_name, 0),
            fallback_status="unknown",
        )
        if not isinstance(raw_sources.get(source_name), dict):
            normalized_sources[source_name]["consulted"] = False
            normalized_sources[source_name]["status"] = "unknown"
            normalized_sources[source_name]["risk_contribution"] = 0.0

    normalized["sources"] = normalized_sources
    normalized["source_count"] = len(SOURCE_ORDER)
    normalized["consulted_sources"] = sorted(
        source for source, source_row in normalized_sources.items()
        if isinstance(source_row, dict) and source_row.get("consulted")
    )
    normalized["consulted_source_count"] = len(normalized["consulted_sources"])
    normalized["cache_metadata"] = {
        "version": int(entry.get("cache_metadata", {}).get("version", REPUTATION_CACHE_VERSION)),
        "last_saved_at": expires_at - ttl,
        "ttl_seconds": ttl,
        "source_count": len(normalized["sources"]),
        "consulted_source_count": normalized["consulted_source_count"],
        "from_cache": True,
    }

    return normalized


def get_reputation_cache_stats() -> Dict[str, Any]:
    """Return cache observability useful for production monitoring."""

    now = int(time.time())
    path = REPUTATION_CACHE_PATH
    stats = {
        "enabled": ENABLE_URL_REPUTATION,
        "cache_path": str(path),
        "ttl_seconds": REPUTATION_CACHE_TTL_SECONDS,
        "cache_version": REPUTATION_CACHE_VERSION,
        "now": now,
        "exists": path.exists(),
        "loaded": False,
        "load_error": None,
        "items": 0,
        "valid_items": 0,
        "expired_items": 0,
        "invalid_items": 0,
        "verdict_counts": {},
        "source_stats": {},
        "provider_errors": {},
        "metadata": {
            "source_entries_without_payload": 0,
            "source_entries_without_version": 0,
            "items_missing_verdict": 0,
            "items_missing_expiration": 0,
        },
        "ttl_remaining_seconds": {
            "min": None,
            "max": None,
            "avg": None,
        },
    }

    if not ENABLE_URL_REPUTATION:
        return stats

    cache = _load_cache(path)
    if not cache and not path.exists():
        return stats
    if not isinstance(cache, dict):
        stats["load_error"] = "invalid_cache_payload"
        return stats

    stats["loaded"] = True

    verdict_counts: Counter[str] = Counter()
    remaining_seconds: List[int] = []
    provider_errors: Counter[str] = Counter()

    for source in SOURCE_ORDER:
        stats["source_stats"][source] = {
            "entries": 0,
            "consulted": 0,
            "not_consulted": 0,
            "status_counts": {
                "malicious": 0,
                "suspicious": 0,
                "clean": 0,
                "unknown": 0,
                "error": 0,
            },
        }

    for raw_entry in cache.values():
        if not isinstance(raw_entry, dict):
            stats["invalid_items"] += 1
            continue

        version = _coerce_int(raw_entry.get("version", 0), 0)
        if version < REPUTATION_CACHE_VERSION:
            stats["metadata"]["source_entries_without_version"] += 1
            stats["invalid_items"] += 1
            continue

        stats["items"] += 1

        verdict = _normalize_status(raw_entry.get("verdict", "unknown"))
        verdict_counts[verdict] += 1
        if not raw_entry.get("verdict"):
            stats["metadata"]["items_missing_verdict"] += 1

        expires_at = _coerce_int(raw_entry.get("expires_at", 0), 0)
        if not expires_at:
            stats["metadata"]["items_missing_expiration"] += 1
            stats["invalid_items"] += 1
            continue

        if _is_cache_entry_valid(raw_entry, now):
            stats["valid_items"] += 1
            remaining_seconds.append(expires_at - now)
        else:
            stats["expired_items"] += 1

        sources = raw_entry.get("sources")
        if not isinstance(sources, dict):
            stats["metadata"]["source_entries_without_payload"] += 1
            continue

        for source in SOURCE_ORDER:
            source_stats = stats["source_stats"][source]
            source_stats["entries"] += 1

            source_payload = sources.get(source)
            if not isinstance(source_payload, dict):
                source_stats["not_consulted"] += 1
                source_stats["status_counts"]["unknown"] += 1
                continue

            consulted = bool(source_payload.get("consulted", False))
            if consulted:
                source_stats["consulted"] += 1
            else:
                source_stats["not_consulted"] += 1

            status = _normalize_status(source_payload.get("status", "unknown"))
            if status in source_stats["status_counts"]:
                source_stats["status_counts"][status] += 1
            else:
                source_stats["status_counts"]["unknown"] += 1

            if status == "error":
                provider_errors[source] += 1

    stats["verdict_counts"] = dict(verdict_counts)
    stats["provider_errors"] = dict(provider_errors)

    if remaining_seconds:
        stats["ttl_remaining_seconds"]["min"] = min(remaining_seconds)
        stats["ttl_remaining_seconds"]["max"] = max(remaining_seconds)
        stats["ttl_remaining_seconds"]["avg"] = int(sum(remaining_seconds) / len(remaining_seconds))

    return stats


def _build_cache_entry(url: str, reputation: Dict[str, Any], ttl: int, cache_metadata: Dict[str, Any]) -> Dict[str, Any]:
    now = int(time.time())
    verdict = _normalize_status(reputation.get("verdict", "unknown"))
    result = dict(reputation)
    result.update({
        "url": url,
        "url_hash": _url_hash(url),
        "created_at": now,
        "cached_at": now,
        "expires_at": now + ttl,
        "cached": False,
        "version": REPUTATION_CACHE_VERSION,
        "verdict": verdict,
    })
    cache_data = dict(result)
    cache_data["cache_metadata"] = dict(cache_metadata)
    return cache_data


def _parse_urlhaus_record(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return {}

    query_status = (payload.get("query_status") or "").lower()
    if query_status != "ok":
        return {}

    if payload.get("url_status", "").lower() in {"online", "offline"}:
        return {
            "status": "malicious" if payload.get("url_status", "").lower() == "online" else "suspicious",
            "threat_type": str(payload.get("threat", "unknown")),
            "details": str(payload.get("comment", "")),
            "last_seen": payload.get("date_added"),
        }

    if payload.get("payload", "").strip():
        return {
            "status": "malicious",
            "threat_type": str(payload.get("threat", "unknown")),
            "details": str(payload.get("comment", "")),
            "last_seen": payload.get("date_added"),
        }
    return {}


def _download_text_feed(url: str) -> str:
    response = requests.get(url, timeout=PHISHING_DATABASE_TIMEOUT_SECONDS)
    response.raise_for_status()
    content = response.content[:PHISHING_DATABASE_MAX_FEED_BYTES + 1]
    if len(content) > PHISHING_DATABASE_MAX_FEED_BYTES:
        raise ValueError(f"feed_too_large:{url}")
    return content.decode("utf-8", errors="ignore")


def _feed_lines(text: str) -> set[str]:
    values: set[str] = set()
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        values.add(line.lower())
    return values


def _load_phishing_database_feeds() -> Dict[str, Any]:
    now = int(time.time())
    cached_at = _coerce_int(_PHISHING_DATABASE_CACHE.get("loaded_at", 0), 0)
    if cached_at and now - cached_at < PHISHING_DATABASE_FEED_TTL_SECONDS:
        return _PHISHING_DATABASE_CACHE

    if not ENABLE_PHISHING_DATABASE:
        _PHISHING_DATABASE_CACHE.update({
            "loaded_at": now,
            "domains": set(),
            "links": set(),
            "error": "disabled",
        })
        return _PHISHING_DATABASE_CACHE

    try:
        domains_text = _download_text_feed(PHISHING_DATABASE_DOMAINS_URL)
        links_text = _download_text_feed(PHISHING_DATABASE_LINKS_URL)
        _PHISHING_DATABASE_CACHE.update({
            "loaded_at": now,
            "domains": _feed_lines(domains_text),
            "links": _feed_lines(links_text),
            "error": None,
            "domains_url": PHISHING_DATABASE_DOMAINS_URL,
            "links_url": PHISHING_DATABASE_LINKS_URL,
        })
    except Exception as exc:
        # If a warm cache exists, keep using it; otherwise expose a provider error.
        if not _PHISHING_DATABASE_CACHE.get("domains") and not _PHISHING_DATABASE_CACHE.get("links"):
            _PHISHING_DATABASE_CACHE.update({
                "loaded_at": now,
                "domains": set(),
                "links": set(),
            })
        _PHISHING_DATABASE_CACHE["error"] = str(exc)
    return _PHISHING_DATABASE_CACHE


def _canonical_url_variants(url: str) -> set[str]:
    parsed = urlparse(url.strip())
    if not parsed.scheme or not parsed.netloc:
        return {url.strip().lower()}
    hostname = (parsed.hostname or "").lower()
    netloc = hostname
    if parsed.port:
        netloc = f"{hostname}:{parsed.port}"
    path = parsed.path or "/"
    normalized = urlunparse((parsed.scheme.lower(), netloc, path, "", parsed.query, "")).lower()
    variants = {normalized}
    if normalized.endswith("/"):
        variants.add(normalized.rstrip("/"))
    else:
        variants.add(normalized + "/")
    return variants


def _host_from_url(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").strip(".").lower()
    except Exception:
        return ""


def _domain_matches_feed(hostname: str, feed_domains: set[str]) -> Optional[str]:
    if not hostname:
        return None
    hostname = hostname.strip(".").lower()
    if hostname in feed_domains:
        return hostname
    labels = hostname.split(".")
    for index in range(1, max(1, len(labels) - 1)):
        candidate = ".".join(labels[index:])
        # Avoid broad false positives from shared base domains. A listed
        # three-label domain may protect its subdomains; two-label domains
        # require exact match above.
        if candidate.count(".") >= 2 and candidate in feed_domains:
            return candidate
    return None


def _fetch_phishing_database(urls: List[str]) -> Dict[str, Dict[str, Any]]:
    output: Dict[str, Dict[str, Any]] = {}
    start = time.perf_counter()
    feed = _load_phishing_database_feeds()
    query_ms = int((time.perf_counter() - start) * 1000)
    domains = feed.get("domains") if isinstance(feed.get("domains"), set) else set()
    links = feed.get("links") if isinstance(feed.get("links"), set) else set()
    error = feed.get("error")

    for url in urls:
        key = _url_hash(url)
        if error and not domains and not links:
            output[key] = {
                "status": "error",
                "threat_type": "error",
                "score": 0,
                "details": {"error": str(error), "provider": "phishing_database"},
                "query_ms": query_ms,
            }
            continue

        matched_link = next((variant for variant in _canonical_url_variants(url) if variant in links), None)
        matched_domain = _domain_matches_feed(_host_from_url(url), domains)
        if matched_link or matched_domain:
            output[key] = {
                "status": "malicious",
                "threat_type": "phishing",
                "score": 92,
                "details": {
                    "provider": "phishing_database",
                    "status": "listed",
                    "match_type": "url" if matched_link else "domain",
                    "matched_value": matched_link or matched_domain,
                    "domains_loaded": len(domains),
                    "links_loaded": len(links),
                    "feed_version_loaded_at": _coerce_int(feed.get("loaded_at", 0), 0),
                },
                "query_ms": query_ms,
            }
            continue

        output[key] = {
            "status": "clean",
            "threat_type": "unknown",
            "score": 0,
            "details": {
                "status": "not_listed",
                "provider": "phishing_database",
                "domains_loaded": len(domains),
                "links_loaded": len(links),
            },
            "query_ms": query_ms,
        }
    return output


def _urlhaus_auth_key() -> str:
    return URLHAUS_AUTH_KEY


def _fetch_urlhaus(urls: List[str], auth_key: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
    output: Dict[str, Dict[str, Any]] = {}
    auth_key = (auth_key if auth_key is not None else _urlhaus_auth_key()).strip()
    for url in urls:
        key = _url_hash(url)
        if not auth_key:
            output[key] = {
                "status": "unknown",
                "threat_type": "unknown",
                "score": 0,
                "details": {"status": "not_configured", "provider": "urlhaus"},
                "query_ms": 0,
            }
            continue
        output[key] = {
            "status": "error",
            "threat_type": "error",
            "score": 0,
            "details": {"error": "not_scanned"},
            "query_ms": 0,
        }
        try:
            start = time.perf_counter()
            response = requests.post(
                URLHAUS_API_URL,
                data={"url": url},
                headers={"Auth-Key": auth_key},
                timeout=URLHAUS_TIMEOUT_SECONDS,
            )
            query_ms = int((time.perf_counter() - start) * 1000)
            if response.status_code != 200:
                output[key] = {
                    "status": "error",
                    "threat_type": "error",
                    "score": 0,
                    "details": {"error": f"HTTP {response.status_code}"},
                    "query_ms": query_ms,
                }
                continue

            payload = response.json()
            parsed = _parse_urlhaus_record(payload if isinstance(payload, dict) else {})
            if not parsed:
                output[key] = {
                    "status": "clean",
                    "threat_type": "unknown",
                    "score": 0,
                    "details": {"status": "not_listed"},
                    "query_ms": query_ms,
                }
                continue

            output[key] = {
                "status": parsed.get("status", "unknown"),
                "threat_type": parsed.get("threat_type", "unknown"),
                "score": 85 if parsed.get("status") == "malicious" else 45,
                "details": {
                    "status": parsed.get("status"),
                    "last_seen": parsed.get("last_seen"),
                    "comment": parsed.get("details", ""),
                },
                "query_ms": query_ms,
            }
        except Exception as exc:
            output[key] = {
                "status": "error",
                "threat_type": "error",
                "score": 0,
                "details": {"error": str(exc)},
                "query_ms": 0,
            }

    return output


def _aggregate_reputation(url: str, per_source: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    reasons: List[str] = []
    consulted_sources: List[str] = []
    source_summary: Dict[str, Dict[str, Any]] = {}

    total_weight = 0.0
    total_signal_weight = 0.0
    weighted_risk = 0.0

    for source_name in SOURCE_ORDER:
        raw_payload = per_source.get(source_name) if isinstance(per_source, dict) else None
        weight = SOURCE_WEIGHTS.get(source_name, 0)
        source_payload = _normalize_source_entry(
            source_name=source_name,
            payload=raw_payload,
            consulted=bool(raw_payload.get("consulted", True)) if isinstance(raw_payload, dict) else False,
            weight=weight,
            fallback_status="unknown",
        )
        source_summary[source_name] = source_payload

        consulted = bool(source_payload.get("consulted", False))
        if not consulted:
            continue

        consulted_sources.append(source_name)
        status = source_payload.get("status", "unknown")
        contribution = weight * SOURCE_STATUS_WEIGHTS.get(status, 0.0)
        weighted_risk += contribution
        total_weight += weight
        total_signal_weight += max(0.0, contribution)
        source_payload["risk_contribution"] = round(contribution, 2)

        if status in {"malicious", "suspicious"}:
            reasons.append(source_name)

    confidence = round(total_signal_weight / total_weight, 2) if total_weight else 0.0
    risk_score = int(min(100, round(weighted_risk)))

    consulted_count = len(consulted_sources)
    active_sources = sorted(set(reasons))

    if consulted_count == 0:
        verdict = "clean"
    elif risk_score >= 78 or confidence >= 0.75:
        verdict = "malicious"
    elif risk_score >= 38 or confidence >= 0.30 or (risk_score > 0 and consulted_count >= 2):
        verdict = "suspicious"
    else:
        verdict = "clean"

    return {
        "url": url,
        "verdict": verdict,
        "risk_score": risk_score,
        "confidence": confidence,
        "signals": active_sources,
        "signal_count": len(active_sources),
        "active_sources": active_sources,
        "sources": source_summary,
        "source_count": len(SOURCE_ORDER),
        "consulted_sources": sorted(consulted_sources),
        "consulted_source_count": consulted_count,
    }


def get_reputation_for_urls(
    urls: List[str],
    *,
    include_phishing_database: bool = True,
    include_urlhaus: bool = True,
    persist_partial: bool = False,
) -> Dict[str, Dict[str, Any]]:
    """
    Return reputation info for URLs.
    Keys are SHA-256(url), for compatibility with ScamAtlas consumers.

    Fast scans may skip slower fallback sources. Partial scans can read existing
    full cache entries, but they are not persisted by default so they do not
    poison later deep reputation lookups.
    """
    if not ENABLE_URL_REPUTATION:
        return {}

    normalized_urls: List[str] = []
    for url in urls:
        clean = _normalize_url_for_key(url)
        if clean:
            normalized_urls.append(clean)
    if not normalized_urls:
        return {}

    normalized_urls = list(dict.fromkeys(normalized_urls))[:MAX_REPUTATION_URLS]
    cache = _load_cache(REPUTATION_CACHE_PATH)
    now = int(time.time())
    results: Dict[str, Dict[str, Any]] = {}
    need_fetch: List[str] = []
    updated_cache_entries: Dict[str, Any] = {}
    web_risk_enabled = has_web_risk_key()
    urlhaus_key = _urlhaus_auth_key()

    for url in normalized_urls:
        key = _url_hash(url)
        cached_entry = _load_cache_entry(cache, url)
        if (
            cached_entry is not None
            and _is_cache_entry_valid(cached_entry, now)
            and _cache_entry_covers_requested_sources(
                cached_entry,
                include_phishing_database=bool(include_phishing_database),
                include_urlhaus=include_urlhaus,
                urlhaus_key=urlhaus_key,
                web_risk_enabled=web_risk_enabled,
            )
        ):
            results[key] = _normalize_cached_entry(cached_entry, url, REPUTATION_CACHE_TTL_SECONDS)
            continue
        need_fetch.append(url)

    if need_fetch:
        web_risk_matches = check_urls_against_web_risk(need_fetch) if web_risk_enabled else {}
        phishing_database_matches = _fetch_phishing_database(need_fetch) if include_phishing_database else {}
        urlhaus_matches = _fetch_urlhaus(need_fetch, urlhaus_key) if include_urlhaus else {}
        should_persist_results = persist_partial or (bool(include_phishing_database) and include_urlhaus)

        for url in need_fetch:
            key = _url_hash(url)
            per_source: Dict[str, Dict[str, Any]] = {}

            web_risk_entry_raw = web_risk_matches.get(key) if web_risk_enabled else None
            web_risk_entry = web_risk_entry_raw if isinstance(web_risk_entry_raw, dict) else {}
            per_source[WEB_RISK_SOURCE] = {
                "status": "malicious" if web_risk_entry else "clean",
                "consulted": web_risk_enabled,
                "threat_type": web_risk_entry.get("threat_type", "unknown"),
                "details": {
                    "cache_duration": web_risk_entry.get("cache_duration", ""),
                    "provider": "google_web_risk",
                    "status": "match" if web_risk_entry else "no_match",
                },
                "score": 100 if web_risk_entry else 0,
            }

            phishing_database_entry = phishing_database_matches.get(key, {
                "status": "unknown" if not include_phishing_database else "error",
                "threat_type": "unknown" if not include_phishing_database else "error",
                "score": 0,
                "details": {"status": "skipped_fast_scan" if not include_phishing_database else "not_scanned"},
                "query_ms": 0,
            })
            per_source[PHISHING_DATABASE_SOURCE] = {
                "status": phishing_database_entry.get("status", "unknown"),
                "consulted": bool(include_phishing_database and ENABLE_PHISHING_DATABASE),
                "threat_type": phishing_database_entry.get("threat_type", "unknown"),
                "details": phishing_database_entry.get("details", {}),
                "score": _coerce_int(phishing_database_entry.get("score", 0), 0),
                "query_ms": _coerce_int(phishing_database_entry.get("query_ms", 0), 0),
            }

            urlhaus_default_error = "skipped_fast_scan" if not include_urlhaus else "not_scanned"
            urlhaus_entry = urlhaus_matches.get(key, {
                "status": "unknown" if not include_urlhaus else "error",
                "threat_type": "unknown" if not include_urlhaus else "error",
                "score": 0,
                "details": {"status": "not_configured" if include_urlhaus and not urlhaus_key else urlhaus_default_error},
                "query_ms": 0,
            })
            per_source[URLHAUS_SOURCE] = {
                "status": urlhaus_entry.get("status", "unknown"),
                "consulted": bool(include_urlhaus and urlhaus_key),
                "threat_type": urlhaus_entry.get("threat_type", "unknown"),
                "details": urlhaus_entry.get("details", {}),
                "score": _coerce_int(urlhaus_entry.get("score", 0), 0),
                "query_ms": _coerce_int(urlhaus_entry.get("query_ms", 0), 0),
            }

            aggregated = _aggregate_reputation(url, per_source)
            cache_metadata = {
                "version": REPUTATION_CACHE_VERSION,
                "ttl_seconds": REPUTATION_CACHE_TTL_SECONDS,
                "requested_sources": SOURCE_ORDER,
                "consulted_sources": aggregated.get("consulted_sources", []),
                "source_count": len(SOURCE_ORDER),
                "consulted_source_count": aggregated.get("consulted_source_count", 0),
                "from_cache": False,
            }
            if should_persist_results:
                cache_entry = _build_cache_entry(url, aggregated, REPUTATION_CACHE_TTL_SECONDS, cache_metadata)
                cache_entry["sources"] = aggregated.get("sources", per_source)
                cache_entry["cache_metadata"]["provider_errors"] = [
                    source_name
                    for source_name, details in cache_entry["sources"].items()
                    if isinstance(details, dict) and details.get("status") == "error"
                ]
                cache[key] = cache_entry
                updated_cache_entries[key] = cache_entry
                results[key] = _normalize_cached_entry(cache_entry, url, REPUTATION_CACHE_TTL_SECONDS)
            else:
                results[key] = dict(aggregated, cached=False)

    if need_fetch and (persist_partial or (bool(include_phishing_database) and include_urlhaus)):
        _save_cache(REPUTATION_CACHE_PATH, cache, remote_subset=updated_cache_entries)
    return results
