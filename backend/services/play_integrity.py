"""Play Integrity token verification and rollout policy.

Why: the client API key ships inside the Android app (BuildConfig), so it can
be extracted from the APK. It raises the bar against casual abuse but is not
real authentication. Play Integrity binds requests to a genuine, Play-installed
app on a genuine device, which is the actual fix.

Rollout modes (PLAY_INTEGRITY_MODE):
- "off"     (default): nothing is checked.
- "monitor": tokens are decoded and logged when present; nothing is blocked.
             Use this first to measure pass rates before enforcing.
- "enforce": scan routes without a server-validated valid token are rejected with 401.

Rollout requirements:
1. Create a Google Cloud service account with the Play Integrity API enabled
   and grant it to the Play Console app (ro.sigurscan.app).
2. Deliver a Play-installed Android build with SIGURSCAN_ENABLE_PLAY_INTEGRITY.
3. Move from "monitor" to "enforce" only after the monitor pass rate is known.

Tokens use a backend-issued, Upstash-backed nonce with short TTL and atomic
single-use consumption. Android requests the nonce before asking Play Integrity.
"""

import json
import logging
import os
import time
from typing import Any, Dict

import requests
from google.auth.transport.requests import Request as GoogleAuthRequest
from google.oauth2 import service_account
from services import play_integrity_nonce

logger = logging.getLogger("sigurscan.play_integrity")

PLAY_INTEGRITY_MODE = os.getenv("PLAY_INTEGRITY_MODE", "off").strip().lower()
PLAY_INTEGRITY_PACKAGE_NAME = os.getenv("PLAY_INTEGRITY_PACKAGE_NAME", "ro.sigurscan.app").strip()
PLAY_INTEGRITY_CREDENTIALS_JSON = os.getenv("PLAY_INTEGRITY_CREDENTIALS_JSON", "").strip()
PLAY_INTEGRITY_TIMEOUT_SECONDS = float(os.getenv("PLAY_INTEGRITY_TIMEOUT_SECONDS", "3.0"))
PLAY_INTEGRITY_MAX_TOKEN_AGE_SECONDS = int(os.getenv("PLAY_INTEGRITY_MAX_TOKEN_AGE_SECONDS", "120"))
PLAY_INTEGRITY_MAX_FUTURE_SKEW_SECONDS = int(os.getenv("PLAY_INTEGRITY_MAX_FUTURE_SKEW_SECONDS", "30"))

INTEGRITY_TOKEN_HEADER = "X-Play-Integrity-Token"
PLAY_INTEGRITY_SCOPE = "https://www.googleapis.com/auth/playintegrity"

_VALID_MODES = {"off", "monitor", "enforce"}


def mode() -> str:
    candidate = (PLAY_INTEGRITY_MODE or "off").strip().lower()
    return candidate if candidate in _VALID_MODES else "off"


def is_configured() -> bool:
    return bool(PLAY_INTEGRITY_CREDENTIALS_JSON)


def verify_token(token: str, api_key: str = "") -> Dict[str, Any]:
    """Decodes and evaluates a Play Integrity token.

    Returns a dict with `status` in:
    - "missing":      no token supplied
    - "unconfigured": no server credentials yet; cannot validate
    - "valid":        token decoded and device/app verdicts acceptable
    - "invalid":      token decoded but verdicts unacceptable, or decode failed
    - "error":        transient failure talking to the Google API
    """
    if not token or not token.strip():
        return {"status": "missing"}
    if not is_configured():
        return {
            "status": "unconfigured",
            "detail": "PLAY_INTEGRITY_CREDENTIALS_JSON is not set; token cannot be validated yet.",
        }
    try:
        decoded = _decode_integrity_token(token.strip())
    except requests.RequestException as exc:
        logger.warning("play_integrity decode transport error: %s", exc)
        return {"status": "error", "detail": str(exc)}
    return _evaluate_verdict(decoded, api_key)


def _decode_integrity_token(token: str) -> Dict[str, Any]:
    """Calls playintegrity.googleapis.com decodeIntegrityToken."""
    access_token = _mint_access_token()
    response = requests.post(
        "https://playintegrity.googleapis.com/v1/"
        f"{PLAY_INTEGRITY_PACKAGE_NAME}:decodeIntegrityToken",
        json={"integrityToken": token},
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=PLAY_INTEGRITY_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    return response.json()


def _mint_access_token() -> str:
    try:
        service_account_info = json.loads(PLAY_INTEGRITY_CREDENTIALS_JSON)
        credentials = service_account.Credentials.from_service_account_info(service_account_info)
        credentials = credentials.with_scopes([PLAY_INTEGRITY_SCOPE])
        credentials.refresh(GoogleAuthRequest())
    except Exception as exc:
        raise requests.RequestException(f"Play Integrity access-token minting failed: {exc}") from exc
    token = getattr(credentials, "token", None)
    if not token:
        raise requests.RequestException("Play Integrity access-token minting returned an empty token.")
    return token


def _evaluate_verdict(decoded: Dict[str, Any], api_key: str = "") -> Dict[str, Any]:
    payload = decoded.get("tokenPayloadExternal") or {}
    request_details = payload.get("requestDetails") or {}
    app_integrity = (payload.get("appIntegrity") or {}).get("appRecognitionVerdict", "")
    device_integrity = (payload.get("deviceIntegrity") or {}).get("deviceRecognitionVerdict", [])
    package_ok = (payload.get("appIntegrity") or {}).get("packageName", "") == PLAY_INTEGRITY_PACKAGE_NAME
    nonce = str(request_details.get("nonce") or "").strip()
    nonce_result = play_integrity_nonce.consume_nonce(nonce, api_key)
    try:
        timestamp_ms = int(request_details.get("timestampMillis"))
    except (TypeError, ValueError):
        timestamp_ms = 0
    age_seconds = time.time() - (timestamp_ms / 1000)
    timestamp_fresh = (
        timestamp_ms > 0
        and age_seconds <= PLAY_INTEGRITY_MAX_TOKEN_AGE_SECONDS
        and age_seconds >= -PLAY_INTEGRITY_MAX_FUTURE_SKEW_SECONDS
    )

    acceptable = (
        package_ok
        and app_integrity == "PLAY_RECOGNIZED"
        and "MEETS_DEVICE_INTEGRITY" in device_integrity
        and nonce_result.get("status") == "consumed"
        and timestamp_fresh
    )
    return {
        "status": "valid" if acceptable else "invalid",
        "app_integrity": app_integrity,
        "device_integrity": device_integrity,
        "package_ok": package_ok,
        "nonce_status": nonce_result.get("status"),
        "timestamp_fresh": timestamp_fresh,
    }


def evaluate_request_token(token: str, api_key: str = "") -> Dict[str, Any]:
    """Middleware entry point: applies the configured mode to a request token.

    Returns {"block": bool, "result": <verify result>}; only enforce mode can
    set block=True. In monitor mode failures are logged for rollout metrics.
    """
    active_mode = mode()
    if active_mode == "off":
        return {"block": False, "result": {"status": "skipped"}}

    result = verify_token(token, api_key)
    if active_mode == "monitor":
        if result["status"] not in {"valid"}:
            logger.info("play_integrity monitor: %s", json.dumps(result, default=str))
        return {"block": False, "result": result}

    # enforce: reject every non-valid result. Missing server credentials or
    # Google/API errors mean the server cannot validate app integrity, so the
    # route must fail closed instead of silently disabling protection.
    status = result.get("status")
    if status in {"valid"}:
        return {"block": False, "result": result}
    logger.warning("play_integrity enforce blocked: %s", json.dumps(result, default=str))
    return {"block": True, "result": result}
