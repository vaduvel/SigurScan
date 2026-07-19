import hashlib
import os
from typing import Any, Dict, List

import requests

WEB_RISK_API_URL = "https://webrisk.googleapis.com/v1/uris:search"
WEB_RISK_TIMEOUT_SECONDS = float(os.getenv("GOOGLE_WEB_RISK_TIMEOUT_SECONDS", "3.0"))
MAX_WEB_RISK_URLS = int(os.getenv("MAX_WEB_RISK_URLS", "20"))

DEFAULT_THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
    "UNWANTED_SOFTWARE",
]


def _web_risk_api_key() -> str:
    return os.getenv("GOOGLE_WEB_RISK_API_KEY", "").strip()


def has_web_risk_key() -> bool:
    return bool(_web_risk_api_key())


def _threat_types() -> List[str]:
    raw = os.getenv("GOOGLE_WEB_RISK_THREAT_TYPES", "").strip()
    if raw:
        return [item.strip() for item in raw.split(",") if item.strip()]

    threat_types = list(DEFAULT_THREAT_TYPES)
    include_extended = os.getenv("GOOGLE_WEB_RISK_INCLUDE_EXTENDED", "false").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    if include_extended:
        threat_types.append("SOCIAL_ENGINEERING_EXTENDED_COVERAGE")
    return threat_types


def _url_hash(url: str) -> str:
    return hashlib.sha256(url.encode("utf-8")).hexdigest()


def _google_error_details(response: requests.Response) -> Dict[str, Any]:
    details: Dict[str, Any] = {"http_status": response.status_code}
    try:
        payload = response.json()
    except ValueError:
        return details

    error = payload.get("error") if isinstance(payload, dict) else None
    if not isinstance(error, dict):
        return details

    api_status = str(error.get("status") or "").strip()
    api_message = str(error.get("message") or "").strip()
    if api_status:
        details["api_status"] = api_status
    if api_message:
        details["api_message"] = api_message

    for item in error.get("details") or []:
        if not isinstance(item, dict):
            continue
        reason = str(item.get("reason") or "").strip()
        if reason:
            details["api_reason"] = reason
            break
    return details


def _provider_error(
    url: str,
    reason: str,
    *,
    consulted: bool,
    extra_details: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    details = {
        "provider": "google_web_risk",
        "status": reason,
    }
    if extra_details:
        details.update(extra_details)
    return {
        "url": url,
        "provider": "google_web_risk",
        "status": "error",
        "consulted": bool(consulted),
        "threat_type": reason,
        "score": 0,
        "error": reason,
        "details": details,
    }


def check_urls_against_web_risk(urls: List[str]) -> Dict[str, Dict[str, Any]]:
    """
    Checks URLs against Google Web Risk Lookup API.

    The REST lookup endpoint accepts one URI per request, so this function keeps
    a strict per-call limit and returns results keyed by SHA-256(original_url).
    """
    api_key = _web_risk_api_key()
    if not api_key or not urls:
        return {}

    unique_urls = list(dict.fromkeys(url for url in urls if url))[:MAX_WEB_RISK_URLS]
    if not unique_urls:
        return {}

    results: Dict[str, Dict[str, Any]] = {}
    threat_types = _threat_types()
    # Cost guard (#82): each lookup is a paid API call. On budget exhaustion we
    # stop; missing provider data is treated conservatively by the verdict gate
    # (blocks SAFE), so this can never make a scam look safe.
    from services.paid_provider_budgets import consume_web_risk

    for index, url in enumerate(unique_urls):
        if not consume_web_risk():
            for remaining_url in unique_urls[index:]:
                results[_url_hash(remaining_url)] = _provider_error(
                    remaining_url,
                    "budget_exhausted",
                    consulted=False,
                )
            break
        params = [("uri", url), ("key", api_key)]
        params.extend(("threatTypes", threat_type) for threat_type in threat_types)
        try:
            response = requests.get(
                WEB_RISK_API_URL,
                params=params,
                timeout=WEB_RISK_TIMEOUT_SECONDS,
            )
            if response.status_code != 200:
                results[_url_hash(url)] = _provider_error(
                    url,
                    f"http_{response.status_code}",
                    consulted=True,
                    extra_details=_google_error_details(response),
                )
                continue
            data = response.json()
        except requests.RequestException:
            results[_url_hash(url)] = _provider_error(url, "request_error", consulted=True)
            continue
        except ValueError:
            results[_url_hash(url)] = _provider_error(url, "invalid_json", consulted=True)
            continue

        threat = data.get("threat") if isinstance(data, dict) else None
        if not isinstance(threat, dict):
            continue

        matched_types = threat.get("threatTypes", [])
        if not isinstance(matched_types, list) or not matched_types:
            continue

        key = _url_hash(url)
        results[key] = {
            "url": url,
            "threat_type": ",".join(str(item) for item in matched_types),
            "cache_duration": str(threat.get("expireTime", "")),
            "provider": "google_web_risk",
        }

    return results
