"""Canonicalize + hash identifiers for the reputation graph (D6).

The reputation graph stores only SHA-256 hex digests, never raw values. For a
backend-created edge to correlate with a client-reported observation, the
backend MUST hash an identifier byte-for-byte the same way the client does.

- Phone: mirrors the Android client exactly
  (app/.../RadarHotCache.kt :: PhoneNumberHasher). Normalize to Romanian E.164
  then SHA-256 the UTF-8 bytes.
- IBAN: the client does NOT hash IBANs anywhere (verified). This module DEFINES
  the canonical scheme — strip whitespace, uppercase, SHA-256 — matching the
  client's IBAN *display* normalization (OfferConfirmationCard.kt:
  `replace(" ","").uppercase()`). A future client-side IBAN hasher must adopt
  this exact scheme.

Pure and network-free.
"""
from __future__ import annotations

import hashlib
import re

_IBAN_CANON_RE = re.compile(r"[A-Z]{2}[A-Z0-9]{13,32}")


def _sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def normalize_phone(raw: str | None) -> str:
    """Romanian E.164 normalization — byte-for-byte mirror of the Android
    client's ``PhoneNumberHasher.normalizePhoneNumber``.

    Inputs are expected to be ASCII phone strings; digit detection follows the
    client's ``filter(Char::isDigit)``.
    """
    value = (raw or "").strip()
    if not value:
        return ""
    digits = "".join(ch for ch in value if ch.isdigit())
    if not digits:
        return ""
    if digits.startswith("0040") and len(digits) >= 6:
        return "+40" + digits[4:]
    if digits.startswith("40") and len(digits) >= 5:
        return "+" + digits
    if digits.startswith("0") and len(digits) >= 10:
        return "+40" + digits[1:]
    if value.startswith("+"):
        return "+" + digits
    return digits


def hash_phone(raw: str | None) -> str:
    """SHA-256 hex of the normalized phone, or "" when there is no phone.

    Matches the client's ``PhoneNumberHasher.hashPhone``.
    """
    normalized = normalize_phone(raw)
    if not normalized:
        return ""
    return _sha256_hex(normalized)


def canonical_iban(raw: str | None) -> str:
    """Canonical IBAN form: all whitespace removed, uppercased."""
    return "".join((raw or "").split()).upper()


def hash_iban(raw: str | None) -> str:
    """SHA-256 hex of the canonical IBAN, or "" when it is not a plausible IBAN.

    The guard keeps garbage out of the graph; it is intentionally lenient on the
    country (any 2 letters) but requires an IBAN-shaped length.
    """
    canon = canonical_iban(raw)
    if not (15 <= len(canon) <= 34) or not _IBAN_CANON_RE.fullmatch(canon):
        return ""
    return _sha256_hex(canon)
