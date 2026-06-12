import hashlib
import copy
import re
import urllib.parse
from typing import Any, Dict, Iterable, List

from services.pii_redactor import CARD_REGEX, EMAIL_REGEX, IBAN_REGEX, PHONE_REGEX, redact_pii


SENSITIVE_QUERY_KEY_RE = re.compile(
    r"(?:^|[_-])(?:"
    r"access|auth|authorization|card|client|cnp|code|customer|cvv|email|iban|"
    r"jwt|magic|otp|pass|password|phone|pin|refresh|secret|session|signature|"
    r"token|uid|user"
    r")(?:$|[_-])",
    re.IGNORECASE,
)
OPAQUE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{32,}$")
OPAQUE_HEX_TOKEN_RE = re.compile(r"^[A-Fa-f0-9]{24,}$")
UUID_TOKEN_RE = re.compile(
    r"^[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[1-5][A-Fa-f0-9]{3}-"
    r"[89ABab][A-Fa-f0-9]{3}-[A-Fa-f0-9]{12}$"
)
SHORT_SECRET_RE = re.compile(r"^\d{4,8}$")
URL_TEXT_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
ACTION_PRIORITY = {"unchanged": 0, "sanitized": 1, "origin_only": 2, "blocked": 3}
SENSITIVE_PATH_LABELS = {
    "auth",
    "authorization",
    "code",
    "confirm",
    "confirmation",
    "email",
    "magic",
    "otp",
    "password",
    "phone",
    "pin",
    "reset",
    "secret",
    "session",
    "token",
    "verify",
}


def _value_is_sensitive(value: str) -> bool:
    decoded = urllib.parse.unquote_plus(str(value or ""))
    if not decoded:
        return False
    if redact_pii(decoded) != decoded:
        return True
    return bool(OPAQUE_TOKEN_RE.fullmatch(decoded) or SHORT_SECRET_RE.fullmatch(decoded))


def _path_contains_opaque_token(path: str) -> bool:
    segments = [
        segment
        for segment in urllib.parse.unquote(path or "").split("/")
        if segment
    ]
    for index, segment in enumerate(segments):
        if OPAQUE_HEX_TOKEN_RE.fullmatch(segment) or UUID_TOKEN_RE.fullmatch(segment):
            return True
        if (
            OPAQUE_TOKEN_RE.fullmatch(segment)
            and sum(segment.count(separator) for separator in ("-", "_")) <= 2
            and any(character.isalpha() for character in segment)
            and any(character.isdigit() for character in segment)
        ):
            return True
        if (
            index > 0
            and segments[index - 1].lower() in SENSITIVE_PATH_LABELS
            and (len(segment) >= 12 or SHORT_SECRET_RE.fullmatch(segment))
        ):
            return True
    return False


def _path_contains_pii(path: str) -> bool:
    decoded_path = urllib.parse.unquote(path or "")
    if (
        EMAIL_REGEX.search(decoded_path)
        or IBAN_REGEX.search(decoded_path)
        or CARD_REGEX.search(decoded_path)
    ):
        return True
    return any(
        PHONE_REGEX.fullmatch(segment)
        for segment in decoded_path.split("/")
        if segment
    )


def _netloc_without_credentials(parsed: urllib.parse.ParseResult) -> str:
    hostname = str(parsed.hostname or "")
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    try:
        port = parsed.port
    except ValueError:
        port = None
    return f"{hostname}:{port}" if port else hostname


def prepare_external_url(raw_url: str) -> Dict[str, Any]:
    """Return a privacy-safe URL plus metadata that never contains raw secrets."""
    value = str(raw_url or "").strip()
    raw_hash = hashlib.sha256(value.encode("utf-8")).hexdigest()
    try:
        parsed = urllib.parse.urlparse(value)
    except Exception:
        parsed = urllib.parse.ParseResult("", "", "", "", "", "")

    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        return {
            "input_url_hash": raw_hash,
            "external_url": None,
            "action": "blocked",
            "reason": "invalid_external_url",
            "removed_query_params": [],
            "preview_allowed": False,
        }

    has_credentials = parsed.username is not None or parsed.password is not None
    if has_credentials:
        parsed = parsed._replace(netloc=_netloc_without_credentials(parsed))

    decoded_path = urllib.parse.unquote(parsed.path or "/")
    path_contains_pii = _path_contains_pii(decoded_path)
    path_contains_secret = _path_contains_opaque_token(decoded_path)
    if path_contains_pii or path_contains_secret:
        origin = urllib.parse.urlunparse(
            parsed._replace(path="/", params="", query="", fragment="")
        )
        return {
            "input_url_hash": raw_hash,
            "external_url": origin,
            "action": "origin_only",
            "reason": "pii_in_path" if path_contains_pii else "secret_in_path",
            "removed_query_params": sorted({key for key, _ in urllib.parse.parse_qsl(parsed.query)}),
            "preview_allowed": False,
        }

    kept_pairs = []
    removed_keys = []
    for key, query_value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True):
        if SENSITIVE_QUERY_KEY_RE.search(str(key or "")) or _value_is_sensitive(query_value):
            removed_keys.append(str(key or ""))
            continue
        kept_pairs.append((key, query_value))

    external_url = urllib.parse.urlunparse(
        parsed._replace(
            query=urllib.parse.urlencode(kept_pairs, doseq=True),
            fragment="",
        )
    )
    return {
        "input_url_hash": raw_hash,
        "external_url": external_url,
        "action": "sanitized" if removed_keys or has_credentials else "unchanged",
        "reason": (
            "url_credentials_removed"
            if has_credentials
            else "sensitive_query_removed"
            if removed_keys
            else None
        ),
        "removed_query_params": sorted(set(removed_keys)),
        "preview_allowed": not has_credentials,
    }


def prepare_external_urls(raw_urls: Iterable[str]) -> tuple[List[str], List[Dict[str, Any]]]:
    safe_urls: List[str] = []
    metadata: List[Dict[str, Any]] = []
    for raw_url in raw_urls:
        result = prepare_external_url(raw_url)
        metadata.append(result)
        safe_url = result.get("external_url")
        if isinstance(safe_url, str) and safe_url and safe_url not in safe_urls:
            safe_urls.append(safe_url)
    return safe_urls, metadata


def _safe_text_with_urls(value: Any) -> str:
    text = str(value or "")
    for raw_url in URL_TEXT_RE.findall(text):
        safe_url = prepare_external_url(raw_url.rstrip(".,;:!?)]}")).get("external_url") or "[protected-url]"
        text = text.replace(raw_url, str(safe_url))
    return text


def sanitize_external_text(value: Any) -> str:
    """Redact PII and replace embedded URLs with provider-safe variants."""
    return redact_pii(_safe_text_with_urls(value))


def sanitize_resolved_url_entries(entries: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Scrub a list of resolver entries before any external provider receives it."""
    return [
        sanitize_resolved_url_entry(
            entry,
            entry.get("url_privacy") if isinstance(entry.get("url_privacy"), dict) else None,
        )
        for entry in (entries or [])
        if isinstance(entry, dict)
    ]


def sanitize_resolved_url_entry(
    entry: Dict[str, Any],
    initial_privacy: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """Scrub resolver output before it is persisted or passed to providers."""
    sanitized = copy.deepcopy(entry if isinstance(entry, dict) else {})
    privacy_candidates = [dict(initial_privacy or {})]

    for key in ("url", "original_url", "final_url"):
        raw_url = sanitized.get(key)
        if not isinstance(raw_url, str) or not raw_url:
            continue
        result = prepare_external_url(raw_url)
        privacy_candidates.append(result)
        sanitized[key] = result.get("external_url")

    chain = sanitized.get("redirect_chain")
    if isinstance(chain, list):
        safe_chain = []
        for step in chain:
            if isinstance(step, dict):
                safe_step = dict(step)
                if isinstance(safe_step.get("url"), str):
                    result = prepare_external_url(safe_step["url"])
                    privacy_candidates.append(result)
                    safe_step["url"] = result.get("external_url")
                safe_chain.append(safe_step)
            elif isinstance(step, str):
                result = prepare_external_url(step)
                privacy_candidates.append(result)
                safe_chain.append(result.get("external_url"))
        sanitized["redirect_chain"] = safe_chain

    soft_redirects = sanitized.get("detected_soft_redirects")
    if isinstance(soft_redirects, list):
        safe_soft_redirects = []
        for raw_url in soft_redirects:
            result = prepare_external_url(str(raw_url or ""))
            privacy_candidates.append(result)
            if result.get("external_url"):
                safe_soft_redirects.append(result["external_url"])
        sanitized["detected_soft_redirects"] = safe_soft_redirects

    if sanitized.get("error_message"):
        sanitized["error_message"] = _safe_text_with_urls(sanitized["error_message"])

    privacy = max(
        (candidate for candidate in privacy_candidates if candidate),
        key=lambda candidate: ACTION_PRIORITY.get(str(candidate.get("action") or "unchanged"), 0),
        default={
            "action": "unchanged",
            "reason": None,
            "removed_query_params": [],
            "preview_allowed": True,
        },
    )
    sanitized["url_privacy"] = {
        "action": privacy.get("action") or "unchanged",
        "reason": privacy.get("reason"),
        "removed_query_params": list(privacy.get("removed_query_params") or []),
        "preview_allowed": privacy.get("preview_allowed") is not False,
    }
    return sanitized
