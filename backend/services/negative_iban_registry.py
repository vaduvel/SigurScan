from __future__ import annotations

import json
import os
from functools import lru_cache
from typing import Any, List, Optional, Set

from services.iban_validator import normalize_iban, validate_iban

_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DEFAULT_PATH = os.path.join(_BACKEND_DIR, "data", "negative_iban_registry_v1.json")
_ACTIVE_STATUSES = {"verified", "confirmed", "active"}
_ACTIVE_CONFIDENCE = {"high", "confirmed"}

_runtime_reported: Set[str] = set()


def _path() -> str:
    return os.getenv("NEGATIVE_IBAN_REGISTRY_PATH") or _DEFAULT_PATH


def _entry_iban(entry: Any) -> str | None:
    if isinstance(entry, str):
        return entry
    if isinstance(entry, dict):
        raw = entry.get("iban")
        if not raw:
            return None
        status = str(entry.get("status") or "").lower()
        confidence = str(entry.get("confidence") or "").lower()
        source = str(entry.get("source_kind") or entry.get("source") or "").strip()
        has_source_ref = bool(entry.get("source_url") or entry.get("source_ref") or entry.get("case_id"))
        if status not in _ACTIVE_STATUSES:
            return None
        if confidence not in _ACTIVE_CONFIDENCE:
            return None
        if not source or not has_source_ref:
            return None
        return str(raw)
    return None


@lru_cache(maxsize=1)
def _seed_registry() -> Set[str]:
    path = _path()
    if not os.path.isfile(path):
        return set()
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return set()

    output: Set[str] = set()
    for entry in data.get("reported_ibans") or []:
        raw = _entry_iban(entry)
        norm = normalize_iban(raw or "")
        if norm and validate_iban(norm).valid_structure:
            output.add(norm)
    return output


def reload_registry() -> None:
    _seed_registry.cache_clear()
    _runtime_reported.clear()


def is_reported_fraud(iban: str) -> bool:
    norm = normalize_iban(iban or "")
    return bool(norm) and (norm in _seed_registry() or norm in _runtime_reported)


def report_fraud_iban(iban: str, *, source: str = "manual", family: Optional[str] = None) -> bool:
    norm = normalize_iban(iban or "")
    if not norm or not validate_iban(norm).valid_structure:
        return False
    _runtime_reported.add(norm)
    try:
        from services import supabase_store

        supabase_store.save_negative_iban(norm, source=source, family=family)
    except Exception:
        pass
    return True


def load_supabase_reports() -> int:
    try:
        from services import supabase_store

        ibans = supabase_store.load_negative_ibans()
    except Exception:
        return 0
    added = 0
    for raw in ibans or []:
        norm = normalize_iban(str(raw or ""))
        if norm and validate_iban(norm).valid_structure and norm not in _runtime_reported:
            _runtime_reported.add(norm)
            added += 1
    return added


def reported_fraud_ibans(ibans: List[str]) -> List[str]:
    seen: Set[str] = set()
    output: List[str] = []
    for raw in ibans or []:
        norm = normalize_iban(raw or "")
        if norm and norm not in seen and is_reported_fraud(norm):
            seen.add(norm)
            output.append(norm)
    return output
