"""Romanian text normalization helpers (P-MORPH).

Pure, dependency-free utilities that make keyword / brand / bank-name matching
robust against Romanian diacritics, casing and punctuation, with an optional
best-effort light stemmer for a few very common inflectional endings.

These helpers never change verdict behavior on their own; callers opt in by
normalizing both sides of a comparison. Everything here is deterministic and
side-effect free.
"""

from __future__ import annotations

import re
from typing import List, Set

_DIACRITIC_MAP = {
    "ă": "a", "â": "a", "î": "i",
    "ș": "s", "ş": "s", "ț": "t", "ţ": "t",
    "Ă": "A", "Â": "A", "Î": "I",
    "Ș": "S", "Ş": "S", "Ț": "T", "Ţ": "T",
}

# Conservative, "u"-safe inflectional endings, ordered longest-first. Endings
# that begin with a vowel commonly belonging to the stem (e.g. "urile") are left
# out to avoid over-stemming words like "facturile" -> "fact".
_LIGHT_SUFFIXES = ("ilor", "elor", "lor", "ile", "ele", "ii", "ei", "le", "ul")

# Never stem a token shorter than this, and never leave a stem shorter than this.
_MIN_TOKEN_LEN = 4
_MIN_STEM_LEN = 4

_TOKEN_RE = re.compile(r"[0-9A-Za-zĂÂÎȘŞȚŢăâîșşțţ]+")


def strip_diacritics(text: str) -> str:
    if not text:
        return ""
    return "".join(_DIACRITIC_MAP.get(ch, ch) for ch in text)


def normalize_token(token: str) -> str:
    folded = strip_diacritics(token or "").lower()
    return re.sub(r"[^0-9a-z]", "", folded)


def light_stem(token: str) -> str:
    """Best-effort removal of one common Romanian inflectional ending."""
    if len(token) < _MIN_TOKEN_LEN or not token.isalpha():
        return token
    for suffix in _LIGHT_SUFFIXES:
        if token.endswith(suffix) and len(token) - len(suffix) >= _MIN_STEM_LEN:
            return token[: -len(suffix)]
    return token


def tokens(text: str, *, stem: bool = False) -> List[str]:
    if not text:
        return []
    out: List[str] = []
    for raw in _TOKEN_RE.findall(text):
        norm = normalize_token(raw)
        if not norm:
            continue
        out.append(light_stem(norm) if stem else norm)
    return out


def normalize_text(text: str, *, stem: bool = False) -> str:
    return " ".join(tokens(text, stem=stem))


def token_set(text: str, *, stem: bool = False) -> Set[str]:
    return set(tokens(text, stem=stem))


def contains_all(haystack: str, needle: str, *, stem: bool = False) -> bool:
    """True when every normalized token of ``needle`` occurs in ``haystack``."""
    needle_tokens = tokens(needle, stem=stem)
    if not needle_tokens:
        return False
    hay = token_set(haystack, stem=stem)
    return all(tok in hay for tok in needle_tokens)
