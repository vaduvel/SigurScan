from __future__ import annotations

import re
from typing import Dict, Optional, Set

from services.iban_validator import normalize_iban, validate_iban

_memory: Dict[str, Set[str]] = {}


def _norm_cui(cui: Optional[str]) -> str:
    return re.sub(r"\D", "", str(cui or ""))


def known_ibans_for_cui(cui: Optional[str]) -> Set[str]:
    return set(_memory.get(_norm_cui(cui), set()))


def iban_changed_for_cui(cui: Optional[str], iban: Optional[str]) -> bool:
    known = _memory.get(_norm_cui(cui))
    norm = normalize_iban(iban or "")
    return bool(known) and bool(norm) and norm not in known


def remember_invoice_iban(cui: Optional[str], iban: Optional[str]) -> bool:
    normalized_cui = _norm_cui(cui)
    norm = normalize_iban(iban or "")
    if not normalized_cui or not norm or not validate_iban(norm).valid_structure:
        return False
    _memory.setdefault(normalized_cui, set()).add(norm)
    try:
        from services import supabase_store

        supabase_store.save_vendor_iban(normalized_cui, norm)
    except Exception:
        pass
    return True


def reload() -> None:
    _memory.clear()
    try:
        from services import supabase_store

        rows = supabase_store.load_vendor_ibans()
    except Exception:
        return
    for row in rows or []:
        normalized_cui = _norm_cui(row.get("cui"))
        norm = normalize_iban(str(row.get("iban") or ""))
        if normalized_cui and norm and validate_iban(norm).valid_structure:
            _memory.setdefault(normalized_cui, set()).add(norm)
