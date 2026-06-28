from __future__ import annotations

import hmac
import asyncio
import os
import re
import sys
from typing import Any, Dict

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse

import config as _config_module
from config import (
    ADMIN_API_KEYS,
    AI_OFFER_CLAIM_TIMEOUT_SECONDS,
    ALLOWED_API_KEYS,
    ALLOWED_MOCK_OCR,
    CLIENT_INSTANCE_HEADER,
    PUBLIC_PATHS,
    ADMIN_ONLY_PATHS,
    ENABLE_CLOUD_AI_EXPLANATION,
    ENABLE_RATE_LIMIT,
    _INTEGRITY_GUARDED_PREFIXES,
    _SCREENSHOT_PROXY_PATH_RE,
    INTERNAL_WORKER_TOKEN,
    PRIVACY_SAFE_MODE,
    RATE_LIMIT_WINDOW_SECONDS,
    REQUIRE_API_KEY,
    RATE_LIMIT_PER_MINUTE,
    URLSCAN_API_KEY,
    URLSCAN_VISIBILITY_DEFAULT,
    PLAY_INTEGRITY_NONCE_PATH,
)
from services import play_integrity, play_integrity_nonce, rate_limiter

_RUNTIME_SETTING_BASELINE: dict[str, object] = {
    "ADMIN_API_KEYS": ADMIN_API_KEYS,
    "ALLOWED_API_KEYS": ALLOWED_API_KEYS,
    "ALLOWED_MOCK_OCR": ALLOWED_MOCK_OCR,
    "INTERNAL_WORKER_TOKEN": INTERNAL_WORKER_TOKEN,
    "PRIVACY_SAFE_MODE": PRIVACY_SAFE_MODE,
    "RATE_LIMIT_WINDOW_SECONDS": RATE_LIMIT_WINDOW_SECONDS,
    "REQUIRE_API_KEY": REQUIRE_API_KEY,
    "ENABLE_RATE_LIMIT": ENABLE_RATE_LIMIT,
    "RATE_LIMIT_PER_MINUTE": RATE_LIMIT_PER_MINUTE,
    "URLSCAN_API_KEY": URLSCAN_API_KEY,
    "URLSCAN_VISIBILITY_DEFAULT": URLSCAN_VISIBILITY_DEFAULT,
    "ENABLE_CLOUD_AI_EXPLANATION": ENABLE_CLOUD_AI_EXPLANATION,
}


def _runtime_setting(name: str, default):
    config_value = getattr(_config_module, name, default)
    baseline = _RUNTIME_SETTING_BASELINE.get(name, default)
    main_module = sys.modules.get("main")
    if main_module is not None and hasattr(main_module, name):
        main_candidate = getattr(main_module, name)
        if main_candidate != baseline:
            return main_candidate

    app_module = sys.modules.get("app")
    if app_module is not None and hasattr(app_module, name):
        app_candidate = getattr(app_module, name)
        if app_candidate != default:
            return app_candidate

    return config_value if config_value is not baseline else baseline


def _runtime_bool_setting(name: str, default: bool = False) -> bool:
    value = _runtime_setting(name, default)
    if isinstance(value, bool):
        return value
    if value is None:
        return bool(default)
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _runtime_internal_worker_token() -> str:
    candidate = _runtime_setting("INTERNAL_WORKER_TOKEN", INTERNAL_WORKER_TOKEN)
    return candidate.strip() if isinstance(candidate, str) else ""


def _env_present(*names: str) -> bool:
    return any(os.getenv(name, "").strip() for name in names)


def _provider_config_status() -> Dict[str, Any]:
    privacy_safe_mode = _runtime_bool_setting("PRIVACY_SAFE_MODE", PRIVACY_SAFE_MODE)
    api_key_required = _runtime_bool_setting("REQUIRE_API_KEY", REQUIRE_API_KEY)
    admin_api_keys = _runtime_setting("ADMIN_API_KEYS", ADMIN_API_KEYS)
    enabled_mock_ocr = _runtime_bool_setting("ALLOWED_MOCK_OCR", ALLOWED_MOCK_OCR)
    urlscan_api_key = _runtime_setting("URLSCAN_API_KEY", URLSCAN_API_KEY)
    urlscan_visibility = _runtime_setting("URLSCAN_VISIBILITY_DEFAULT", URLSCAN_VISIBILITY_DEFAULT)
    rate_limit_enabled = _runtime_bool_setting("ENABLE_RATE_LIMIT", ENABLE_RATE_LIMIT)

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
        "privacy_safe_mode": privacy_safe_mode,
        "rate_limit_enabled": rate_limit_enabled,
        "rate_limit_backend": rate_limiter.backend_mode(),
        "api_key_required": api_key_required,
        "admin_api_configured": bool(admin_api_keys),
        "play_integrity_mode": play_integrity.mode(),
        "play_integrity_nonce_backend": play_integrity_nonce.backend_mode(),
        "mock_ocr_allowed": enabled_mock_ocr,
        "providers": {
            "urlscan": {
                "configured": bool(urlscan_api_key) and not privacy_safe_mode,
                "visibility": urlscan_visibility,
            },
            "google_web_risk": {
                "configured": web_risk_configured and not PRIVACY_SAFE_MODE,
                "extended_threat_types_env": bool(os.getenv("GOOGLE_WEB_RISK_THREAT_TYPES", "").strip()),
            },
            "phishing_database": {
                "configured": phishing_database_enabled and not PRIVACY_SAFE_MODE,
                "policy": "open_feed_runtime_reputation",
            },
            "phishtank_online_valid": {
                "configured": phishtank_enabled and not PRIVACY_SAFE_MODE,
                "policy": "open_feed_runtime_reputation",
                "source": "PhishTank online-valid feed",
            },
            "openphish": {
                "configured": openphish_enabled and not PRIVACY_SAFE_MODE,
                "policy": "open_feed_runtime_reputation",
                "source": "OpenPhish public feed",
            },
            "asf_investor_alerts": {
                "configured": asf_investor_alerts_enabled and not PRIVACY_SAFE_MODE,
                "policy": "official_authority_runtime_reputation",
                "source": "Autoritatea de Supraveghere Financiară",
                "source_url": os.getenv(
                    "ASF_INVESTOR_ALERTS_URL",
                    "https://asfromania.ro/ro/a/19/alerte-investitori---informari",
                ),
            },
            "urlhaus": {
                "configured": not PRIVACY_SAFE_MODE,
                "policy": "abuse_ch_runtime_reputation",
                "source": "URLhaus public recent feed; Auth-Key optional for API lookup",
                "api_key_configured": urlhaus_configured and not PRIVACY_SAFE_MODE,
            },
            "openapi_ro_company": {
                "configured": openapi_ro_configured and not PRIVACY_SAFE_MODE,
                "policy": "paid_escalation_only",
                "monthly_budget": openapi_ro_budget,
            },
            "hunter_io_email_domain": {
                "configured": hunter_io_configured and not PRIVACY_SAFE_MODE,
                "policy": "paid_escalation_only",
                "monthly_budget": hunter_io_budget,
            },
            "scam_blocklist_nrd": {
                "configured": scam_blocklist_nrd_enabled and not PRIVACY_SAFE_MODE,
                "policy": "open_feed_runtime_reputation",
                "source": "jarelllama/Scam-Blocklist",
                "license": "GPL-3.0",
            },
            "phishdestroy_destroylist": {
                "configured": phishdestroy_enabled and not PRIVACY_SAFE_MODE,
                "policy": "open_feed_runtime_reputation",
                "source": "phishdestroy/destroylist",
                "license": "MIT",
                "api": "https://api.destroy.tools/v1",
            },
            "ai_explanation": {
                "configured": (mistral_configured or gemini_configured) and ENABLE_CLOUD_AI_EXPLANATION,
                "mistral_configured": mistral_configured,
                "gemini_configured": gemini_configured,
            },
            "offer_claim_verifier": {
                "configured": offer_claim_configured and not PRIVACY_SAFE_MODE,
                "timeout_seconds": AI_OFFER_CLAIM_TIMEOUT_SECONDS,
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
    value = (request.headers.get(CLIENT_INSTANCE_HEADER) or "").strip()
    if not value or len(value) > 128:
        return ""
    if not re.fullmatch(r"[A-Za-z0-9._:-]{8,128}", value):
        return ""
    return value


def _play_integrity_client_binding(request: Request, api_key: str = "") -> str:
    return _extract_client_instance_id(request) or api_key.strip()


def _internal_worker_token_matches(request: Request) -> bool:
    internal_token = _runtime_internal_worker_token()
    if not internal_token:
        return False
    provided = (
        request.headers.get("X-Internal-Worker-Token")
        or request.headers.get("X-Cloud-Tasks-Token")
        or ""
    ).strip()
    return bool(provided) and hmac.compare_digest(provided, internal_token)


def _require_internal_worker_auth(request: Request) -> None:
    if _internal_worker_token_matches(request):
        return
    raise HTTPException(status_code=401, detail="Missing or invalid internal worker token.")


def _is_screenshot_proxy_path(path: str) -> bool:
    return bool(_SCREENSHOT_PROXY_PATH_RE.match(path))


def _is_integrity_guarded_path(path: str) -> bool:
    return path.startswith(_INTEGRITY_GUARDED_PREFIXES)


def _is_play_integrity_nonce_path(path: str) -> bool:
    return path == PLAY_INTEGRITY_NONCE_PATH


async def security_guard(request: Request, call_next):
    """HTTP middleware preserving request security hardening."""

    path = request.url.path
    if path in PUBLIC_PATHS or request.method == "OPTIONS":
        return await call_next(request)

    api_key = _extract_api_key(request)
    internal_worker_authorized = path.startswith("/internal/") and _internal_worker_token_matches(request)
    integrity_verdict = None
    integrity_can_authorize_client = False
    should_check_integrity = (
        play_integrity.mode() != "off"
        and request.method == "POST"
        and _is_integrity_guarded_path(path)
    )
    if should_check_integrity:
        integrity_verdict = play_integrity.evaluate_request_token(
            request.headers.get(play_integrity.INTEGRITY_TOKEN_HEADER, ""),
            _play_integrity_client_binding(request, api_key),
        )
        integrity_can_authorize_client = (
            play_integrity.mode() == "enforce"
            and not integrity_verdict["block"]
            and (integrity_verdict.get("result") or {}).get("status") == "valid"
        )

    admin_api_keys = set(_runtime_setting("ADMIN_API_KEYS", ADMIN_API_KEYS) or [])
    allowed_api_keys = set(_runtime_setting("ALLOWED_API_KEYS", ALLOWED_API_KEYS) or [])

    if internal_worker_authorized:
        return await call_next(request)

    if path in ADMIN_ONLY_PATHS:
        if not admin_api_keys:
            return JSONResponse(
                status_code=403,
                content={"detail": "Admin access is not configured on this deployment."},
            )
        if not api_key or api_key not in admin_api_keys:
            return JSONResponse(status_code=401, content={"detail": "Missing or invalid admin API key."})

    elif _runtime_bool_setting("REQUIRE_API_KEY") and not (request.method == "GET" and _is_screenshot_proxy_path(path)):
        nonce_request_allowed = _is_play_integrity_nonce_path(path) and play_integrity.mode() != "off"
        # Public early-access waitlist intake from the marketing landing page.
        # The browser form carries no API key; allow this single POST past the
        # key check but keep it subject to the rate limiter below. It never
        # reaches scan/extract/audio pipelines and stores only a validated email.
        waitlist_request_allowed = request.method == "POST" and path == "/v1/waitlist"
        api_key_authorized = bool(api_key and api_key in allowed_api_keys)
        if (
            not api_key_authorized
            and not integrity_can_authorize_client
            and not nonce_request_allowed
            and not waitlist_request_allowed
        ):
            return JSONResponse(status_code=401, content={"detail": "Missing or invalid API key."})

    if integrity_verdict is not None and integrity_verdict["block"]:
        return JSONResponse(
            status_code=401,
            content={"detail": "Play Integrity verification failed.", "integrity": integrity_verdict["result"]},
        )

    if _runtime_bool_setting("ENABLE_RATE_LIMIT"):
        decision = await asyncio.to_thread(
            rate_limiter.check_sync,
            api_key or None,
            request.client.host if request.client else "anonymous",
            path,
            int(_runtime_setting("RATE_LIMIT_PER_MINUTE", RATE_LIMIT_PER_MINUTE)),
            path in ADMIN_ONLY_PATHS and api_key in admin_api_keys,
        )
        if not decision.allowed:
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many requests. Try again later."},
                headers={"Retry-After": str(decision.retry_after_seconds or RATE_LIMIT_WINDOW_SECONDS)},
            )

    return await call_next(request)
