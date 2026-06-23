from __future__ import annotations

import hmac
import os
import re
from typing import Any, Dict

from fastapi import HTTPException, Request


def _env_present(*names: str) -> bool:
    return any(os.getenv(name, "").strip() for name in names)


def _provider_config_status() -> Dict[str, Any]:
    import main as _main

    web_risk_configured = _env_present("GOOGLE_WEB_RISK_API_KEY")
    phishing_database_enabled = os.getenv("ENABLE_PHISHING_DATABASE", "true").strip().lower() in {"1", "true", "yes", "on"}
    phishtank_enabled = os.getenv("ENABLE_PHISHTANK", "true").strip().lower() in {"1", "true", "yes", "on"}
    openphish_enabled = os.getenv("ENABLE_OPENPHISH", "true").strip().lower() in {"1", "true", "yes", "on"}
    asf_investor_alerts_enabled = os.getenv("ENABLE_ASF_INVESTOR_ALERTS", "true").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    scam_blocklist_nrd_enabled = os.getenv("ENABLE_SCAM_BLOCKLIST_NRD", "false").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    phishdestroy_enabled = os.getenv("ENABLE_PHISHDESTROY", "false").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    urlhaus_configured = _env_present("URLHAUS_AUTH_KEY", "URLHAUS_API_KEY", "ABUSECH_AUTH_KEY")
    openapi_ro_configured = _env_present("OPENAPI_RO_API_KEY")
    try:
        from services.anaf_cui import openapi_ro_monthly_budget

        openapi_ro_budget = openapi_ro_monthly_budget()
    except Exception:
        openapi_ro_budget = 100
    hunter_io_configured = _env_present("HUNTER_IO_API_KEY")
    try:
        from services.hunter_io import hunter_io_monthly_budget

        hunter_io_budget = hunter_io_monthly_budget()
    except Exception:
        hunter_io_budget = 50
    mistral_configured = _env_present("MISTRAL_API_KEY")
    gemini_configured = _env_present("GEMINI_API_KEY")
    offer_claim_configured = gemini_configured
    return {
        "privacy_safe_mode": _main.PRIVACY_SAFE_MODE,
        "rate_limit_enabled": _main.ENABLE_RATE_LIMIT,
        "rate_limit_backend": _main.rate_limiter.backend_mode(),
        "api_key_required": _main.REQUIRE_API_KEY,
        "admin_api_configured": bool(_main.ADMIN_API_KEYS),
        "play_integrity_mode": _main.play_integrity.mode(),
        "play_integrity_nonce_backend": _main.play_integrity_nonce.backend_mode(),
        "mock_ocr_allowed": _main.ALLOWED_MOCK_OCR,
        "providers": {
            "urlscan": {
                "configured": bool(_main.URLSCAN_API_KEY) and not _main.PRIVACY_SAFE_MODE,
                "visibility": _main.URLSCAN_VISIBILITY_DEFAULT,
            },
            "google_web_risk": {
                "configured": web_risk_configured and not _main.PRIVACY_SAFE_MODE,
                "extended_threat_types_env": bool(os.getenv("GOOGLE_WEB_RISK_THREAT_TYPES", "").strip()),
            },
            "phishing_database": {
                "configured": phishing_database_enabled and not _main.PRIVACY_SAFE_MODE,
                "policy": "open_feed_runtime_reputation",
            },
            "phishtank_online_valid": {
                "configured": phishtank_enabled and not _main.PRIVACY_SAFE_MODE,
                "policy": "open_feed_runtime_reputation",
                "source": "PhishTank online-valid feed",
            },
            "openphish": {
                "configured": openphish_enabled and not _main.PRIVACY_SAFE_MODE,
                "policy": "open_feed_runtime_reputation",
                "source": "OpenPhish public feed",
            },
            "asf_investor_alerts": {
                "configured": asf_investor_alerts_enabled and not _main.PRIVACY_SAFE_MODE,
                "policy": "official_authority_runtime_reputation",
                "source": "Autoritatea de Supraveghere Financiară",
                "source_url": os.getenv(
                    "ASF_INVESTOR_ALERTS_URL",
                    "https://asfromania.ro/ro/a/19/alerte-investitori---informari",
                ),
            },
            "urlhaus": {
                "configured": not _main.PRIVACY_SAFE_MODE,
                "policy": "abuse_ch_runtime_reputation",
                "source": "URLhaus public recent feed; Auth-Key optional for API lookup",
                "api_key_configured": urlhaus_configured and not _main.PRIVACY_SAFE_MODE,
            },
            "openapi_ro_company": {
                "configured": openapi_ro_configured and not _main.PRIVACY_SAFE_MODE,
                "policy": "paid_escalation_only",
                "monthly_budget": openapi_ro_budget,
            },
            "hunter_io_email_domain": {
                "configured": hunter_io_configured and not _main.PRIVACY_SAFE_MODE,
                "policy": "paid_escalation_only",
                "monthly_budget": hunter_io_budget,
            },
            "scam_blocklist_nrd": {
                "configured": scam_blocklist_nrd_enabled and not _main.PRIVACY_SAFE_MODE,
                "policy": "open_feed_runtime_reputation",
                "source": "jarelllama/Scam-Blocklist",
                "license": "GPL-3.0",
            },
            "phishdestroy_destroylist": {
                "configured": phishdestroy_enabled and not _main.PRIVACY_SAFE_MODE,
                "policy": "open_feed_runtime_reputation",
                "source": "phishdestroy/destroylist",
                "license": "MIT",
                "api": "https://api.destroy.tools/v1",
            },
            "ai_explanation": {
                "configured": (mistral_configured or gemini_configured) and _main.ENABLE_CLOUD_AI_EXPLANATION,
                "mistral_configured": mistral_configured,
                "gemini_configured": gemini_configured,
            },
            "offer_claim_verifier": {
                "configured": offer_claim_configured and not _main.PRIVACY_SAFE_MODE,
                "timeout_seconds": _main.AI_OFFER_CLAIM_TIMEOUT_SECONDS,
            },
        },
    }


def _extract_api_key(request: Request) -> str:
    api_key = request.headers.get("X-API-KEY") or ""
    if not api_key and request.headers.get("Authorization"):
        candidate = request.headers.get("Authorization", "").strip()
        if candidate.lower().startswith("bearer "):
            api_key = candidate.split(" ", 1)[1]
    return api_key.strip()


def _extract_client_instance_id(request: Request) -> str:
    import main as _main

    value = (request.headers.get(_main.CLIENT_INSTANCE_HEADER) or "").strip()
    if not value or len(value) > 128:
        return ""
    if not re.fullmatch(r"[A-Za-z0-9._:-]{8,128}", value):
        return ""
    return value


def _play_integrity_client_binding(request: Request, api_key: str = "") -> str:
    return _extract_client_instance_id(request) or api_key.strip()


def _internal_worker_token_matches(request: Request) -> bool:
    import main as _main

    if not _main.INTERNAL_WORKER_TOKEN:
        return False
    provided = (
        request.headers.get("X-Internal-Worker-Token")
        or request.headers.get("X-Cloud-Tasks-Token")
        or ""
    ).strip()
    return bool(provided) and hmac.compare_digest(provided, _main.INTERNAL_WORKER_TOKEN)


def _require_internal_worker_auth(request: Request) -> None:
    if _internal_worker_token_matches(request):
        return
    raise HTTPException(status_code=401, detail="Missing or invalid internal worker token.")


def _is_screenshot_proxy_path(path: str) -> bool:
    import main as _main

    return bool(_main._SCREENSHOT_PROXY_PATH_RE.match(path))


def _is_integrity_guarded_path(path: str) -> bool:
    import main as _main

    return path.startswith(_main._INTEGRITY_GUARDED_PREFIXES)


def _is_play_integrity_nonce_path(path: str) -> bool:
    import main as _main

    return path == _main.PLAY_INTEGRITY_NONCE_PATH
