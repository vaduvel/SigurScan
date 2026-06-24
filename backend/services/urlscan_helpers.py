"""URLscan utility helpers extracted from runtime.py."""

from __future__ import annotations

import hashlib
import re
import time
import urllib.parse
from datetime import datetime
from typing import Any, Dict, List, Optional

import requests
from fastapi import HTTPException, Request
from starlette.concurrency import run_in_threadpool

from config import (
    _LEGACY_SCREENSHOT_PROXY_HOSTS,
    _SCREENSHOT_PROXY_PATH_RE,
    PRIVACY_SAFE_MODE,
    SIGURSCAN_PUBLIC_API_BASE_URL,
    URLSCAN_PREVIEW_CACHE_MAX_ENTRIES,
    URLSCAN_API_KEY,
    URLSCAN_TIMEOUT_SECONDS,
    URLSCAN_VISIBILITY_DEFAULT,
)
from core.scan_context import _merge_url_privacy
from core.text_utils import _normalise_obfuscated_text
from core.url_intelligence import _canonicalize_url
from runtime_state import _URLSCAN_PREVIEW_CACHE
from services import supabase_store
from services.external_url_privacy import prepare_external_url
from services.redirect_resolver import _is_scan_target_blocked


def _require_urlscan_key() -> None:
    if PRIVACY_SAFE_MODE:
        raise HTTPException(
            status_code=503,
            detail="Sandbox dezactivat in SIGURSCAN_SAFE_MODE.",
        )
    if not URLSCAN_API_KEY:
        raise HTTPException(
            status_code=503,
            detail="urlscan.io nu este configurat pe backend.",
        )


def _validate_sandbox_url(raw_url: str) -> str:
    url = _canonicalize_url(_normalise_obfuscated_text(raw_url or ""))
    if not url:
        raise HTTPException(status_code=400, detail="URL invalid sau format neacceptat.")
    privacy = prepare_external_url(url)
    safe_url = privacy.get("external_url")
    if not isinstance(safe_url, str) or not safe_url:
        raise HTTPException(status_code=400, detail="URL invalid sau format neacceptat.")
    if privacy.get("preview_allowed") is False or privacy.get("action") in {"origin_only", "blocked"}:
        raise HTTPException(
            status_code=400,
            detail="URL blocat pentru sandbox din motive de privacy: contine date sensibile in path.",
        )
    url = safe_url
    blocked_reason = _is_scan_target_blocked(url)
    if blocked_reason:
        raise HTTPException(status_code=400, detail=f"URL blocat pentru sandbox: {blocked_reason}")
    return url


def _safe_urlscan_visibility(raw_visibility: str | None) -> str:
    visibility = (raw_visibility or URLSCAN_VISIBILITY_DEFAULT or "private").strip().lower()
    if visibility not in {"private", "unlisted", "public"}:
        return "private"
    # Public submissions can expose user URLs. Keep backend default privacy-first.
    return "unlisted" if visibility == "public" else visibility


def _urlscan_headers() -> Dict[str, str]:
    return {
        "api-key": URLSCAN_API_KEY,
        "accept": "application/json",
    }


def _safe_urlscan_tag(raw_tag: Any) -> Optional[str]:
    tag = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(raw_tag or "").strip().lower())
    tag = re.sub(r"-{2,}", "-", tag).strip("-._")
    if not tag:
        return None
    # urlscan.io rejects tags longer than 30 chars with HTTP 400. Keep tags observability-only.
    return tag[:30].strip("-._") or None


def _urlscan_tags(source_channel: Optional[str]) -> List[str]:
    tags: List[str] = []
    for raw_tag in ("sigurscan", "android", source_channel or "android_native"):
        tag = _safe_urlscan_tag(raw_tag)
        if tag and tag not in tags:
            tags.append(tag)
    return tags


def _urlscan_error_detail(response: requests.Response) -> str:
    detail = f"urlscan.io submission failed: HTTP {response.status_code}"
    try:
        body = response.json()
    except Exception:
        body = None
    message = None
    if isinstance(body, dict):
        message = body.get("message") or body.get("description") or body.get("detail")
    if not message:
        try:
            message = (response.text or "").strip()
        except Exception:
            message = ""
    if message:
        safe_message = re.sub(r"\s+", " ", str(message))[:240]
        detail = f"{detail}: {safe_message}"
    return detail


def _urlscan_report_url(uuid: str) -> str:
    return f"https://urlscan.io/result/{uuid}/"


def _urlscan_direct_screenshot_url(uuid: str) -> str:
    safe_uuid = re.sub(r"[^A-Za-z0-9._-]", "", uuid or "")
    return f"https://urlscan.io/screenshots/{safe_uuid}.png"


async def _urlscan_screenshot_is_ready(uuid: str) -> bool:
    safe_uuid = re.sub(r"[^A-Za-z0-9._-]", "", uuid or "")
    if not safe_uuid:
        return False

    def fetch_headline() -> bool:
        response = requests.get(
            _urlscan_direct_screenshot_url(safe_uuid),
            headers={"api-key": URLSCAN_API_KEY},
            timeout=min(URLSCAN_TIMEOUT_SECONDS, 4.0),
            stream=True,
        )
        try:
            content_type = (response.headers.get("content-type") or "").lower()
            return response.status_code < 400 and ("image/" in content_type or "png" in content_type)
        finally:
            close = getattr(response, "close", None)
            if callable(close):
                close()

    return bool(await run_in_threadpool(fetch_headline))


def _summarize_urlscan_payload(payload: Dict[str, Any], uuid: str, request: Request) -> Dict[str, Any]:
    page = payload.get("page") if isinstance(payload.get("page"), dict) else {}
    task = payload.get("task") if isinstance(payload.get("task"), dict) else {}
    verdicts = payload.get("verdicts") if isinstance(payload.get("verdicts"), dict) else {}
    overall = verdicts.get("overall") if isinstance(verdicts.get("overall"), dict) else {}
    urlscan = verdicts.get("urlscan") if isinstance(verdicts.get("urlscan"), dict) else {}
    brands = payload.get("brands") if isinstance(payload.get("brands"), list) else []
    lists = overall.get("categories") or urlscan.get("categories") or []
    if not isinstance(lists, list):
        lists = []

    malicious = bool(overall.get("malicious") or urlscan.get("malicious"))
    suspicious = bool(overall.get("suspicious") or urlscan.get("suspicious"))
    score = int(overall.get("score") or urlscan.get("score") or 0)
    categories = [str(item) for item in lists if item]

    if malicious:
        verdict = "Malicious phishing" if any("phish" in item.lower() for item in categories) else "Malicious"
        severity = "high"
    elif suspicious or score >= 50:
        verdict = "Suspicious"
        severity = "medium"
    else:
        verdict = "No malicious classification"
        severity = "low"

    final_url = page.get("url") or task.get("url")
    server = page.get("server")
    ip_address = page.get("ip")
    country = page.get("country")
    detail_parts = [
        f"urlscan verdict={verdict}",
        f"score={score}",
    ]
    if categories:
        detail_parts.append(f"categories={','.join(categories[:4])}")
    if brands:
        detail_parts.append(f"brands={','.join(str(item) for item in brands[:4])}")
    if ip_address:
        detail_parts.append(f"ip={ip_address}")
    if country:
        detail_parts.append(f"country={country}")
    if server:
        detail_parts.append(f"server={server}")

    return {
        "uuid": uuid,
        "status": "finished",
        "verdict": verdict,
        "severity": severity,
        "details": "; ".join(detail_parts),
        "final_url": final_url,
        "report_url": _urlscan_report_url(uuid),
        "screenshot_url": _public_route_url(request, "urlscan_screenshot", uuid=uuid),
        "score": score,
        "categories": categories,
        "brands": brands[:4],
    }


def _canonical_urlscan_preview_cache_url(raw_url: Any) -> Optional[str]:
    url = str(raw_url or "").strip()
    if not url:
        return None
    try:
        parsed = urllib.parse.urlsplit(url)
    except Exception:
        return None
    if not parsed.scheme or not parsed.netloc:
        return url
    return urllib.parse.urlunsplit(
        (
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path or "/",
            parsed.query,
            "",
        )
    )


def _urlscan_preview_cache_key(final_url: Any) -> Optional[str]:
    canonical_url = _canonical_urlscan_preview_cache_url(final_url)
    if not canonical_url:
        return None
    return hashlib.sha256(canonical_url.encode("utf-8")).hexdigest()


def _fast_preview_cache_lookup_keys(final_url: Any) -> List[str]:
    canonical_url = _canonical_urlscan_preview_cache_url(final_url)
    if not canonical_url:
        return []
    candidates = [canonical_url]
    try:
        parsed = urllib.parse.urlsplit(canonical_url)
    except Exception:
        parsed = None
    if parsed and parsed.query:
        queryless_url = urllib.parse.urlunsplit(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path or "/",
                "",
                "",
            )
        )
        if queryless_url and queryless_url not in candidates:
            candidates.append(queryless_url)
    keys: List[str] = []
    for candidate in candidates:
        cache_key = _urlscan_preview_cache_key(candidate)
        if cache_key and cache_key not in keys:
            keys.append(cache_key)
    return keys


def _urlscan_preview_cache_is_fresh(entry: Dict[str, Any]) -> bool:
    raw_expires_at = entry.get("expires_at")
    try:
        expires_at = int(raw_expires_at or 0)
    except Exception:
        try:
            expires_at = int(datetime.fromisoformat(str(raw_expires_at).replace("Z", "+00:00")).timestamp())
        except Exception:
            expires_at = 0
    return not expires_at or expires_at > int(time.time())


def _trim_preview_cache(cache: Dict[str, Dict[str, Any]], max_entries: int) -> None:
    try:
        limit = max(0, int(max_entries))
    except Exception:
        limit = 0

    for cache_key, entry in list(cache.items()):
        if not isinstance(entry, dict) or not _urlscan_preview_cache_is_fresh(entry):
            cache.pop(cache_key, None)

    if limit <= 0:
        cache.clear()
        return

    while len(cache) > limit:
        oldest_key = next(iter(cache), None)
        if oldest_key is None:
            break
        cache.pop(oldest_key, None)


def _remember_preview_cache_entry(
    cache: Dict[str, Dict[str, Any]],
    cache_key: str,
    entry: Dict[str, Any],
    max_entries: int,
) -> None:
    if not cache_key or not isinstance(entry, dict):
        return
    cache.pop(cache_key, None)
    cache[cache_key] = entry
    _trim_preview_cache(cache, max_entries)


def _normalize_screenshot_proxy_url(raw_url: Any) -> str:
    value = str(raw_url or "").strip()
    if not value:
        return ""
    parsed_public = urllib.parse.urlparse(SIGURSCAN_PUBLIC_API_BASE_URL)
    public_host = (parsed_public.hostname or "").lower()
    parsed = urllib.parse.urlparse(value)

    if parsed.scheme and parsed.netloc:
        host = (parsed.hostname or "").lower()
        if _SCREENSHOT_PROXY_PATH_RE.match(parsed.path) and (
            host in _LEGACY_SCREENSHOT_PROXY_HOSTS or host == public_host
        ):
            return f"{SIGURSCAN_PUBLIC_API_BASE_URL}{parsed.path}"
        return value

    if value.startswith("/") and _SCREENSHOT_PROXY_PATH_RE.match(value):
        return f"{SIGURSCAN_PUBLIC_API_BASE_URL}{value}"

    return value


def _supabase_signed_preview_object_path(raw_url: Any, *, bucket: str = "previews") -> Optional[str]:
    value = str(raw_url or "").strip()
    if not value:
        return None
    try:
        parsed = urllib.parse.urlparse(value)
    except Exception:
        return None
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    path = parsed.path or ""
    marker = f"/storage/v1/object/sign/{bucket}/"
    if marker not in path:
        return None
    object_path = path.split(marker, 1)[1].strip("/")
    if not object_path:
        return None
    return urllib.parse.unquote(object_path)


def _public_route_url(request: Request, route_name: str, **path_params: Any) -> str:
    generated = str(request.url_for(route_name, **path_params))
    parsed = urllib.parse.urlparse(generated)
    path = parsed.path or "/"
    query = f"?{parsed.query}" if parsed.query else ""
    return f"{SIGURSCAN_PUBLIC_API_BASE_URL}{path}{query}"


def _normalize_urlscan_preview_cache_entry(entry: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(entry, dict):
        return None
    final_url = str(entry.get("final_url") or entry.get("canonical_url") or "").strip()
    report_url = str(entry.get("report_url") or "").strip()
    screenshot_url = _normalize_screenshot_proxy_url(entry.get("screenshot_url"))
    if not final_url or not report_url:
        return None
    final_privacy = prepare_external_url(final_url)
    if (
        final_privacy.get("preview_allowed") is False
        or final_privacy.get("action") != "unchanged"
    ):
        return None
    safe_final_url = str(final_privacy.get("external_url") or "").strip()
    submitted_url = str(entry.get("submitted_url") or entry.get("canonical_url") or final_url).strip()
    submitted_privacy = prepare_external_url(submitted_url)
    if (
        submitted_privacy.get("preview_allowed") is False
        or submitted_privacy.get("action") != "unchanged"
    ):
        return None
    safe_submitted_url = str(submitted_privacy.get("external_url") or safe_final_url).strip()
    if not safe_final_url or not safe_submitted_url:
        return None
    normalized = dict(entry)
    normalized["status"] = "finished"
    normalized["final_url"] = safe_final_url
    normalized["submitted_url"] = safe_submitted_url
    if normalized.get("canonical_url"):
        normalized["canonical_url"] = safe_submitted_url
    normalized["url_privacy"] = _merge_url_privacy(
        final_privacy,
        submitted_privacy,
    )
    normalized["screenshot_url"] = screenshot_url
    normalized["report_url"] = report_url
    normalized["screenshot_ready"] = bool(normalized.get("screenshot_ready")) and bool(screenshot_url)
    normalized["cache_hit"] = True
    normalized.setdefault("verdict", "No malicious classification")
    normalized.setdefault("severity", "low")
    normalized.setdefault("details", "urlscan preview cache hit")
    normalized.setdefault("score", 0)
    normalized.setdefault("categories", [])
    normalized.setdefault("brands", [])
    if not _urlscan_preview_cache_is_fresh(normalized):
        return None
    return normalized


def _load_urlscan_preview_cache(final_url: Any) -> Optional[Dict[str, Any]]:
    cache_key = _urlscan_preview_cache_key(final_url)
    if not cache_key:
        return None
    cached = _normalize_urlscan_preview_cache_entry(_URLSCAN_PREVIEW_CACHE.get(cache_key))
    if cached:
        _remember_preview_cache_entry(
            _URLSCAN_PREVIEW_CACHE,
            cache_key,
            cached,
            URLSCAN_PREVIEW_CACHE_MAX_ENTRIES,
        )
        return cached
    persisted = _normalize_urlscan_preview_cache_entry(supabase_store.load_urlscan_preview_cache(cache_key))
    if persisted:
        _remember_preview_cache_entry(
            _URLSCAN_PREVIEW_CACHE,
            cache_key,
            persisted,
            URLSCAN_PREVIEW_CACHE_MAX_ENTRIES,
        )
    return persisted
