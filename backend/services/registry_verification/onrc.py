"""Adapter ONRC — citește EXCLUSIV un snapshot CSV oficial (data.gov.ro).

Nu există API ONRC live și nu inventăm unul. Reguli oneste:
- snapshot absent          -> NOT_CONFIGURED (checked=False)
- snapshot corupt/incompat -> SOURCE_ERROR
- snapshot prea vechi      -> INCONCLUSIVE
- căutare după CUI și după denumire normalizată
- MATCH = entitatea apare în registru; NU înseamnă că oferta e sigură
- NO_MATCH solo NU înseamnă fraudă (snapshot-ul poate fi incomplet)
"""
from __future__ import annotations

import csv
import os
import re
import time
import unicodedata
from typing import Dict, Optional, Tuple

from services.registry_verification.metadata import (
    onrc_snapshot_max_age_days,
    onrc_snapshot_path,
    source_metadata,
)
from services.registry_verification.models import RegistryStatus, RegistryVerificationResult

SOURCE_ID = "onrc"

_LEGAL_FORMS = re.compile(
    r"\b(s\.?c\.?|s\.?r\.?l\.?(?:\-d)?|s\.?a\.?|p\.?f\.?a\.?|i\.?i\.?|i\.?f\.?|s\.?n\.?c\.?|"
    r"srl|sa|pfa|ii|snc|sca|ra)\b",
    re.IGNORECASE,
)

# Cache index pe (path, mtime_ns, size) — determinist, se invalidează la schimbarea fișierului.
_INDEX_CACHE: Dict[Tuple[str, int, int], Tuple[Dict[str, str], Dict[str, str], int]] = {}


def _strip_diacritics(value: str) -> str:
    return "".join(
        ch for ch in unicodedata.normalize("NFD", value) if unicodedata.category(ch) != "Mn"
    )


def normalize_company_name(name: str) -> str:
    n = _strip_diacritics(name).lower()
    n = _LEGAL_FORMS.sub(" ", n)
    n = re.sub(r"[^a-z0-9 ]", " ", n)
    return re.sub(r"\s+", " ", n).strip()


def _normalize_cui(raw: str) -> str:
    return "".join(ch for ch in (raw or "") if ch.isdigit())


def _header_key(header: str) -> str:
    return re.sub(r"[^a-z]", "", _strip_diacritics(header or "").lower())


def _find_columns(headers: list[str]) -> Tuple[Optional[int], Optional[int]]:
    cui_idx = name_idx = None
    for idx, raw in enumerate(headers):
        key = _header_key(raw)
        if cui_idx is None and ("cui" in key or ("cod" in key and ("fiscal" in key or "unic" in key))):
            cui_idx = idx
        if name_idx is None and ("denumire" in key or "nume" in key or "firma" in key):
            name_idx = idx
    return cui_idx, name_idx


def _load_index(path: str) -> Tuple[Dict[str, str], Dict[str, str], int]:
    """Întoarce (cui->denumire, nume_normalizat->denumire, nr_rânduri)."""
    stat = os.stat(path)
    cache_key = (path, stat.st_mtime_ns, stat.st_size)
    cached = _INDEX_CACHE.get(cache_key)
    if cached is not None:
        return cached

    with open(path, "r", encoding="utf-8", errors="strict", newline="") as handle:
        sample = handle.read(4096)
        if not sample.strip():
            raise ValueError("snapshot gol")
        delimiter = ";" if sample.count(";") > sample.count(",") else ","
        handle.seek(0)
        reader = csv.reader(handle, delimiter=delimiter)
        headers = next(reader, None)
        if not headers:
            raise ValueError("snapshot fără antet")
        cui_idx, name_idx = _find_columns(headers)
        if cui_idx is None and name_idx is None:
            raise ValueError("coloane CUI/denumire negăsite în snapshot")

        by_cui: Dict[str, str] = {}
        by_name: Dict[str, str] = {}
        rows = 0
        for row in reader:
            if not row:
                continue
            rows += 1
            denumire = (row[name_idx].strip() if name_idx is not None and name_idx < len(row) else "")
            if cui_idx is not None and cui_idx < len(row):
                cui = _normalize_cui(row[cui_idx])
                if cui:
                    by_cui[cui] = denumire or by_cui.get(cui, "")
            if denumire:
                normalized = normalize_company_name(denumire)
                if normalized:
                    by_name.setdefault(normalized, denumire)

    _INDEX_CACHE.clear()  # ținem un singur snapshot în memorie
    _INDEX_CACHE[cache_key] = (by_cui, by_name, rows)
    return by_cui, by_name, rows


def verify_onrc(cui: Optional[str], name: Optional[str]) -> RegistryVerificationResult:
    meta = source_metadata(SOURCE_ID)
    path = onrc_snapshot_path()

    if not os.path.isfile(path):
        return RegistryVerificationResult(
            source_id=SOURCE_ID, status=RegistryStatus.NOT_CONFIGURED, confidence=0.0,
            matched_entity_name=None, checked=False,
            details={"snapshot": meta, "reason": "Snapshot ONRC neconfigurat (fișier absent)."},
        )

    age_days = (time.time() - os.path.getmtime(path)) / 86400.0
    if age_days > onrc_snapshot_max_age_days():
        return RegistryVerificationResult(
            source_id=SOURCE_ID, status=RegistryStatus.INCONCLUSIVE, confidence=0.0,
            matched_entity_name=None, checked=True,
            details={"snapshot": meta, "reason": f"Snapshot prea vechi ({age_days:.0f} zile)."},
        )

    try:
        by_cui, by_name, rows = _load_index(path)
    except (ValueError, UnicodeDecodeError, csv.Error, OSError) as exc:
        return RegistryVerificationResult(
            source_id=SOURCE_ID, status=RegistryStatus.SOURCE_ERROR, confidence=0.0,
            matched_entity_name=None, checked=False,
            details={"snapshot": meta, "reason": f"Snapshot ilizibil/incompatibil: {exc}"},
        )

    cui_digits = _normalize_cui(cui or "")
    if cui_digits and cui_digits in by_cui:
        return RegistryVerificationResult(
            source_id=SOURCE_ID, status=RegistryStatus.MATCH, confidence=0.95,
            matched_entity_name=by_cui[cui_digits] or None, checked=True,
            details={"snapshot": meta, "matched_by": "cui", "rows": rows},
        )

    normalized_name = normalize_company_name(name or "")
    if normalized_name and normalized_name in by_name:
        return RegistryVerificationResult(
            source_id=SOURCE_ID, status=RegistryStatus.MATCH, confidence=0.75,
            matched_entity_name=by_name[normalized_name], checked=True,
            details={"snapshot": meta, "matched_by": "name", "rows": rows},
        )

    if not cui_digits and not normalized_name:
        return RegistryVerificationResult(
            source_id=SOURCE_ID, status=RegistryStatus.INCONCLUSIVE, confidence=0.0,
            matched_entity_name=None, checked=True,
            details={"snapshot": meta, "reason": "Niciun identificator (CUI/denumire) de căutat."},
        )

    return RegistryVerificationResult(
        source_id=SOURCE_ID, status=RegistryStatus.NO_MATCH, confidence=0.6,
        matched_entity_name=None, checked=True,
        details={"snapshot": meta, "rows": rows,
                 "note": "Lipsa din snapshot NU este dovadă de fraudă (dump-ul poate fi incomplet)."},
    )
