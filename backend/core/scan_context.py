from __future__ import annotations

from email import policy
from email.message import Message
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional
import re
import os
import logging
from core.url_intelligence import _canonicalize_url

import email
import html
from fastapi import HTTPException
import urllib.parse
from services.external_url_privacy import sanitize_resolved_url_entry
from services.redirect_resolver import is_known_shortener, resolve_redirects_safely
from core.email_auth import _extract_domain_root


_APP_SCHEME_BRAND_HINTS = {
    "uber": "Uber",
    "ubereats": "Uber",
    "revolut": "Revolut",
    "whatsapp": "WhatsApp",
}

_BACKEND_DIR = Path(__file__).resolve().parent.parent
EVAL_DATASET_DEFAULT_PATH = _BACKEND_DIR / "data" / "evaluation_dataset_v1.jsonl"
EVAL_DATASET_ALLOWED_ROOT = (_BACKEND_DIR / "data").resolve()
_SCAN_PRIVACY_SAFE_MODE_ENV_VARS = ("SIGURSCAN_SAFE_MODE", "NUDACLICK_SAFE_MODE")
logger = logging.getLogger("main")


def _is_privacy_safe_mode() -> bool:
    return (
        os.getenv(_SCAN_PRIVACY_SAFE_MODE_ENV_VARS[0])
        or os.getenv(_SCAN_PRIVACY_SAFE_MODE_ENV_VARS[1])
        or "false"
    ).strip().lower() in {"1", "true", "yes", "on"}


def _extract_email_mime_parts(raw_email: str) -> Dict[str, str]:
    raw = str(raw_email or "")
    if not raw.strip():
        return {}

    header_sample = raw.lstrip()[:4096]
    if not re.search(r"(?im)^(from|to|subject|mime-version|content-type|content-transfer-encoding):", header_sample):
        return {}

    try:
        parsed = email.message_from_string(raw.lstrip(), policy=policy.default)
    except Exception:
        return {}

    parts: Dict[str, List[str]] = {"plain": [], "html": []}

    def part_content(part: Message) -> str:
        try:
            content = part.get_content()
        except Exception:
            payload = part.get_payload(decode=True)
            if not payload:
                return ""
            charset = part.get_content_charset() or "utf-8"
            try:
                return payload.decode(charset, errors="replace")
            except Exception:
                return payload.decode("utf-8", errors="replace")
        if isinstance(content, bytes):
            charset = part.get_content_charset() or "utf-8"
            return content.decode(charset, errors="replace")
        return str(content or "")

    walkable = parsed.walk() if parsed.is_multipart() else [parsed]
    for part in walkable:
        if part.is_multipart():
            continue
        disposition = str(part.get_content_disposition() or "").lower()
        if disposition == "attachment":
            continue
        content_type = str(part.get_content_type() or "").lower()
        if content_type not in {"text/plain", "text/html"}:
            continue
        content = part_content(part).strip()
        if not content:
            continue
        if content_type == "text/html":
            parts["html"].append(content)
        else:
            parts["plain"].append(content)

    return {
        "plain": "\n".join(parts["plain"]).strip(),
        "html": "\n".join(parts["html"]).strip(),
        "subject": str(parsed.get("Subject") or "").strip(),
        "from": str(parsed.get("From") or "").strip(),
        "reply_to": str(parsed.get("Reply-To") or "").strip(),
    }


def _decode_repeated_url_value(value: str, max_rounds: int = 3) -> str:
    current = value or ""
    for _ in range(max_rounds):
        decoded = urllib.parse.unquote(html.unescape(current))
        if decoded == current:
            break
        current = decoded
    return current


def _brand_from_official_url(candidate: str, brand_registry: Mapping[str, List[str]]) -> Optional[str]:
    parsed = urllib.parse.urlparse(candidate if "://" in candidate else f"https://{candidate}")
    host = (parsed.hostname or "").lower().removeprefix("www.")
    if not host:
        return None
    for brand, domains in brand_registry.items():
        for domain in domains:
            normalized_domain = str(domain).lower().removeprefix("www.")
            if host == normalized_domain or host.endswith(f".{normalized_domain}"):
                return brand
    return None


def _infer_brand_hints_from_url(url: str, brand_registry: Mapping[str, List[str]]) -> List[str]:
    """
    Extracts brand context from app deep-links and official fallback URLs.

    This is not a whitelist: the inferred brand is used so downstream mismatch
    checks can compare the target against official/partner domains. A malicious
    domain with `fallback=https://brand.com` still becomes a brand-mismatch case.
    """
    hints: List[str] = []
    parsed = urllib.parse.urlparse(url)
    query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)

    def add_hint(value: Optional[str]) -> None:
        if value and value not in hints:
            hints.append(value)

    for key, raw_value in query_pairs:
        key_norm = key.lower().strip()
        value = _decode_repeated_url_value(raw_value)
        scheme = urllib.parse.urlparse(value).scheme.lower()

        if key_norm in {"_dl", "deep_link", "deeplink", "app_link", "applink"}:
            add_hint(_APP_SCHEME_BRAND_HINTS.get(scheme))

        if key_norm in {
            "_fallback_redirect",
            "fallback_redirect",
            "fallback",
            "redirect",
            "redirect_url",
            "url",
            "u",
            "target",
            "destination",
        }:
            add_hint(_brand_from_official_url(value, brand_registry))

    return hints


def _infer_brand_hints_from_click_targets(click_targets: List[Dict[str, Any]], brand_registry: Mapping[str, List[str]]) -> List[str]:
    hints: List[str] = []
    for target in click_targets:
        raw_url = str(target.get("original_url") or "")
        for hint in _infer_brand_hints_from_url(raw_url, brand_registry):
            if hint not in hints:
                hints.append(hint)
    return hints


def _feedback_sample_payload(row: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "scan_id": row.get("scan_id"),
        "feedback": row.get("feedback"),
        "actual_is_scam": row.get("actual_is_scam"),
        "predicted_is_scam": row.get("predicted_is_scam"),
        "predicted_risk_score": row.get("predicted_risk_score"),
        "risk_score": row.get("risk_score"),
        "risk_level": row.get("risk_level"),
        "signal_ids": row.get("signal_ids", []),
        "timestamp": row.get("timestamp"),
        "scan_context": row.get("scan_context", {}),
        "detected_family_id": row.get("detected_family_id"),
        "detected_family": row.get("detected_family"),
        "claimed_brand": row.get("claimed_brand"),
        "input_type": row.get("input_type"),
        "url_count": row.get("url_count", 0),
        "error_category": row.get("error_category"),
        "source_channel": row.get("source_channel"),
    }


def _merge_url_privacy(
    current: Optional[Dict[str, Any]],
    incoming: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    priority = {"unchanged": 0, "sanitized": 1, "origin_only": 2, "blocked": 3}
    candidates = [
        entry
        for entry in (current, incoming)
        if isinstance(entry, dict) and entry
    ]
    winner = max(
        candidates,
        key=lambda entry: priority.get(str(entry.get("action") or "unchanged"), 0),
        default={},
    )
    removed_query_params = sorted(
        {
            str(key)
            for entry in candidates
            for key in (entry.get("removed_query_params") or [])
            if str(key)
        }
    )
    return {
        "action": winner.get("action") or "unchanged",
        "reason": winner.get("reason"),
        "removed_query_params": removed_query_params,
        "preview_allowed": all(entry.get("preview_allowed") is not False for entry in candidates),
    }


def _attach_initial_url_privacy(
    resolved_urls: List[Dict[str, Any]],
    url_privacy: Optional[List[Dict[str, Any]]],
) -> List[Dict[str, Any]]:
    privacy_by_external_url: Dict[str, Dict[str, Any]] = {}
    for entry in url_privacy or []:
        if not isinstance(entry, dict) or not entry.get("external_url"):
            continue
        external_url = str(entry["external_url"])
        privacy_by_external_url[external_url] = _merge_url_privacy(
            privacy_by_external_url.get(external_url),
            entry,
        )

    attached: List[Dict[str, Any]] = []
    for resolved in resolved_urls:
        candidate = dict(resolved) if isinstance(resolved, dict) else {}
        initial_privacy = None
        for key in ("original_url", "url", "final_url"):
            value = candidate.get(key)
            if isinstance(value, str) and value in privacy_by_external_url:
                initial_privacy = privacy_by_external_url[value]
                break
        candidate["url_privacy"] = _merge_url_privacy(
            candidate.get("url_privacy"),
            initial_privacy,
        )
        attached.append(candidate)
    return attached


def _safe_mode_url_entry(url: str, *, privacy_safe_mode: Optional[bool] = None) -> Dict[str, Any]:
    raw_url = (url or "").strip()
    final_url = _canonicalize_url(raw_url) or raw_url
    parsed = urllib.parse.urlparse(final_url)
    hostname = (parsed.hostname or "").lower()
    is_shortener = False
    try:
        is_shortener = is_known_shortener(final_url)
    except Exception:
        is_shortener = False

    return {
        "original_url": raw_url,
        "final_url": final_url,
        "final_hostname": hostname,
        "final_registered_domain": _extract_domain_root(hostname),
        "domain_age_days": None,
        "domain_created_date": None,
        "has_mx_records": None,
        "redirect_chain": [],
        "redirect_count": 0,
        "shortener_count": 1 if is_shortener else 0,
        "uses_shortener": is_shortener,
        "detected_soft_redirects": [],
        "success": True,
        "error_message": (
            "SIGURSCAN_SAFE_MODE: nu se face verificare externă a URL-ului."
            if (_is_privacy_safe_mode() if privacy_safe_mode is None else privacy_safe_mode)
            else None
        ),
    }


def _safe_scan_url_list(
    urls: List[str],
    *,
    privacy_safe_mode: Optional[bool] = None,
    resolve_redirects_safely_fn: Optional[Callable[[str], Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    resolved_urls: List[Dict[str, Any]] = []
    safe_mode = _is_privacy_safe_mode() if privacy_safe_mode is None else privacy_safe_mode
    resolver_fn = resolve_redirects_safely_fn or resolve_redirects_safely
    if safe_mode:
        for url in urls:
            resolved_urls.append(sanitize_resolved_url_entry(_safe_mode_url_entry(url)))
        return resolved_urls
    for url in urls:
        try:
            resolved_urls.append(
                sanitize_resolved_url_entry(resolver_fn(url))
            )
        except Exception as exc:
            failed_entry = sanitize_resolved_url_entry(
                {
                    "original_url": url,
                    "final_url": url,
                    "final_hostname": urllib.parse.urlparse(url).hostname,
                    "final_registered_domain": urllib.parse.urlparse(url).hostname,
                    "domain_age_days": None,
                    "domain_created_date": None,
                    "has_mx_records": None,
                    "redirect_chain": [],
                    "redirect_count": 0,
                    "shortener_count": 0,
                    "uses_shortener": False,
                    "detected_soft_redirects": [],
                    "success": False,
                    "error_message": str(exc),
                }
            )
            logger.warning(
                "Redirect resolution failed for %s: %s",
                url,
                failed_entry.get("error_message") or "resolver_error",
            )
            resolved_urls.append(failed_entry)
    return resolved_urls


def _resolve_eval_dataset_path(dataset_path: Optional[str]) -> Path:
    if not dataset_path:
        candidate = EVAL_DATASET_DEFAULT_PATH
    else:
        cleaned = str(dataset_path).strip()
        if not cleaned:
            candidate = EVAL_DATASET_DEFAULT_PATH
        else:
            candidate = Path(cleaned)
            if not candidate.is_absolute():
                candidate = (_BACKEND_DIR / candidate)

    resolved = candidate.expanduser().resolve()
    if resolved != EVAL_DATASET_ALLOWED_ROOT and EVAL_DATASET_ALLOWED_ROOT not in resolved.parents:
        raise HTTPException(
            status_code=400,
            detail="Dataset file must be inside backend/data.",
        )
    if not resolved.exists() or not resolved.is_file():
        raise HTTPException(
            status_code=404,
            detail=(
                f"Dataset file not found: {resolved}"
                if os.path.isabs(str(resolved))
                else "Dataset file not found"
            ),
        )
    return resolved
