"""Signed, expiring access tokens for the GET screenshot proxy (#80).

The screenshot proxy must stay header-less because the Android image loader
(Coil) fetches it directly, so instead of the API key it carries a short-lived
HMAC token in the query string (``?st=<expires_at>.<signature>``). Tokens are
minted server-side whenever the backend builds or returns a screenshot URL, so
clients never need to know the secret.

Key source: ``SCREENSHOT_PROXY_HMAC_KEY`` with fallback to
``INVOICE_CACHE_HMAC_KEY`` (already provisioned in deploy secrets and CI).
If neither is configured, enforcement is skipped so local/dev setups keep
working; production always has the invoice HMAC key set.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import time
from typing import Any, Optional

_TOKEN_VERSION = "v1"
_DEFAULT_TTL_SECONDS = 86400  # 24h: covers preview-cache reuse within a session


def _secret() -> bytes:
    raw = (
        os.getenv("SCREENSHOT_PROXY_HMAC_KEY")
        or os.getenv("INVOICE_CACHE_HMAC_KEY")
        or ""
    ).strip()
    return raw.encode("utf-8")


def secret_configured() -> bool:
    return bool(_secret())


def enforcement_enabled() -> bool:
    value = os.getenv("SCREENSHOT_PROXY_REQUIRE_TOKEN", "true").strip().lower()
    return value in {"1", "true", "yes", "on"}


def token_ttl_seconds() -> int:
    raw = os.getenv("SCREENSHOT_PROXY_TOKEN_TTL_SECONDS", "").strip()
    if not raw:
        return _DEFAULT_TTL_SECONDS
    try:
        return max(60, int(raw))
    except ValueError:
        return _DEFAULT_TTL_SECONDS


def _signature(uuid: str, expires_at: int) -> str:
    message = f"{_TOKEN_VERSION}:screenshot:{uuid}:{expires_at}".encode("utf-8")
    return hmac.new(_secret(), message, hashlib.sha256).hexdigest()[:32]


def mint_screenshot_token(uuid: str, *, now: Optional[int] = None) -> str:
    """Return ``<expires_at>.<signature>`` for the given urlscan UUID."""
    expires_at = int(now if now is not None else time.time()) + token_ttl_seconds()
    return f"{expires_at}.{_signature(str(uuid or ''), expires_at)}"


def verify_screenshot_token(uuid: str, token: Any, *, now: Optional[int] = None) -> bool:
    """Constant-time check that the token matches the UUID and is not expired."""
    if not secret_configured():
        return False
    raw = str(token or "").strip()
    if "." not in raw:
        return False
    expires_raw, _, provided = raw.partition(".")
    try:
        expires_at = int(expires_raw)
    except ValueError:
        return False
    if expires_at < int(now if now is not None else time.time()):
        return False
    return hmac.compare_digest(provided, _signature(str(uuid or ""), expires_at))
