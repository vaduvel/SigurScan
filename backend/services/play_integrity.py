"""Play Integrity verification skeleton.

Why: the client API key ships inside the Android app (BuildConfig), so it can
be extracted from the APK. It raises the bar against casual abuse but is not
real authentication. Play Integrity binds requests to a genuine, Play-installed
app on a genuine device, which is the actual fix.

Rollout modes (PLAY_INTEGRITY_MODE):
- "off"     (default): nothing is checked.
- "monitor": tokens are decoded and logged when present; nothing is blocked.
             Use this first to measure pass rates before enforcing.
- "enforce": scan routes without a valid token are rejected with 401.

TODO(security, full implementation):
1. Create a Google Cloud service account with the Play Integrity API enabled
   and grant it to the Play Console app (ro.sigurscan.app).
2. Mint OAuth2 access tokens server-side (google-auth or manual JWT flow) and
   set PLAY_INTEGRITY_CREDENTIALS_JSON; _decode_integrity_token below already
   shapes the decodeIntegrityToken call.
3. Bind tokens to requests with a nonce: client requests a nonce from the
   backend, embeds it via IntegrityTokenRequest, backend checks it here
   (single use, short TTL) to stop replay.
4. Android side: add the Play Integrity client library and send the token in
   the X-Play-Integrity-Token header on scan requests.
5. Move from "monitor" to "enforce" only after the monitor pass rate is known.
"""

import json
import logging
import os
from typing import Any, Dict

import requests

logger = logging.getLogger("sigurscan.play_integrity")

PLAY_INTEGRITY_MODE = os.getenv("PLAY_INTEGRITY_MODE", "off").strip().lower()
PLAY_INTEGRITY_PACKAGE_NAME = os.getenv("PLAY_INTEGRITY_PACKAGE_NAME", "ro.sigurscan.app").strip()
PLAY_INTEGRITY_CREDENTIALS_JSON = os.getenv("PLAY_INTEGRITY_CREDENTIALS_JSON", "").strip()
PLAY_INTEGRITY_TIMEOUT_SECONDS = float(os.getenv("PLAY_INTEGRITY_TIMEOUT_SECONDS", "3.0"))

INTEGRITY_TOKEN_HEADER = "X-Play-Integrity-Token"

_VALID_MODES = {"off", "monitor", "enforce"}


def mode() -> str:
    candidate = (PLAY_INTEGRITY_MODE or "off").strip().lower()
    return candidate if candidate in _VALID_MODES else "off"


def is_configured() -> bool:
    return bool(PLAY_INTEGRITY_CREDENTIALS_JSON)


def verify_token(token: str) -> Dict[str, Any]:
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
    return _evaluate_verdict(decoded)


def _decode_integrity_token(token: str) -> Dict[str, Any]:
    """Calls playintegrity.googleapis.com decodeIntegrityToken.

    TODO(security): replace the placeholder bearer token with a real OAuth2
    access token minted from PLAY_INTEGRITY_CREDENTIALS_JSON (google-auth's
    service_account.Credentials, scope
    https://www.googleapis.com/auth/playintegrity).
    """
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
    # TODO(security): implement the service-account OAuth2 flow. Raising keeps
    # this path fail-closed if someone enables enforce mode without finishing
    # the credential wiring.
    raise requests.RequestException(
        "Play Integrity access-token minting is not implemented yet (see module TODOs)."
    )


def _evaluate_verdict(decoded: Dict[str, Any]) -> Dict[str, Any]:
    payload = decoded.get("tokenPayloadExternal") or {}
    app_integrity = (payload.get("appIntegrity") or {}).get("appRecognitionVerdict", "")
    device_integrity = (payload.get("deviceIntegrity") or {}).get("deviceRecognitionVerdict", [])
    package_ok = (payload.get("appIntegrity") or {}).get("packageName", "") == PLAY_INTEGRITY_PACKAGE_NAME

    # TODO(security): also check requestDetails.nonce against the issued nonce
    # store, and requestDetails.timestampMillis freshness.
    acceptable = (
        package_ok
        and app_integrity == "PLAY_RECOGNIZED"
        and "MEETS_DEVICE_INTEGRITY" in device_integrity
    )
    return {
        "status": "valid" if acceptable else "invalid",
        "app_integrity": app_integrity,
        "device_integrity": device_integrity,
        "package_ok": package_ok,
    }


def evaluate_request_token(token: str) -> Dict[str, Any]:
    """Middleware entry point: applies the configured mode to a request token.

    Returns {"block": bool, "result": <verify result>}; only enforce mode can
    set block=True. In monitor mode failures are logged for rollout metrics.
    """
    active_mode = mode()
    if active_mode == "off":
        return {"block": False, "result": {"status": "skipped"}}

    result = verify_token(token)
    if active_mode == "monitor":
        if result["status"] not in {"valid"}:
            logger.info("play_integrity monitor: %s", json.dumps(result, default=str))
        return {"block": False, "result": result}

    # enforce
    return {"block": result.get("status") != "valid", "result": result}
