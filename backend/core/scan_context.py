from __future__ import annotations

from email import policy
from email.message import Message
from typing import Any, Dict, List, Mapping, Optional
import re

import email
import html
import urllib.parse


_APP_SCHEME_BRAND_HINTS = {
    "uber": "Uber",
    "ubereats": "Uber",
    "revolut": "Revolut",
    "whatsapp": "WhatsApp",
}


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
