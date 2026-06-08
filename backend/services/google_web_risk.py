import hashlib
import os
from typing import Dict, List

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


def check_urls_against_web_risk(urls: List[str]) -> Dict[str, Dict[str, str]]:
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

    results: Dict[str, Dict[str, str]] = {}
    threat_types = _threat_types()
    for url in unique_urls:
        params = [("uri", url), ("key", api_key)]
        params.extend(("threatTypes", threat_type) for threat_type in threat_types)
        try:
            response = requests.get(
                WEB_RISK_API_URL,
                params=params,
                timeout=WEB_RISK_TIMEOUT_SECONDS,
            )
            if response.status_code != 200:
                continue
            data = response.json()
        except (requests.RequestException, ValueError):
            continue

        threat = data.get("threat") if isinstance(data, dict) else None
        if not isinstance(threat, dict):
            continue

        matched_types = threat.get("threatTypes", [])
        if not isinstance(matched_types, list) or not matched_types:
            continue

        key = hashlib.sha256(url.encode("utf-8")).hexdigest()
        results[key] = {
            "url": url,
            "threat_type": ",".join(str(item) for item in matched_types),
            "cache_duration": str(threat.get("expireTime", "")),
            "provider": "google_web_risk",
        }

    return results
