"""Pilon — vendor memory (istoric IBAN per CUI).

Cel mai puternic semnal pe BEC/„cont schimbat" (research RO/internațional): dacă ai
mai plătit firma X în contul A și acum vine factură de la X cu contul B → red flag.

Anti-poisoning (failure mode #10): înregistrăm un IBAN ca „istoric curat" DOAR din
scanări fără semnale de fraudă. Un IBAN schimbat NU se memorează (nu otrăvește
baza). Semnalul DOAR ridică suspiciunea (out-of-band), nu coboară niciodată riscul.

In-memory per-proces + persistență Supabase write-through (no-op fără chei).
"""
from __future__ import annotations

import re
from typing import Dict, Optional, Set

from services.iban_validator import normalize_iban

# cui_normalizat -> set de IBAN-uri normalizate văzute pe scanări curate.
_memory: Dict[str, Set[str]] = {}


def _norm_cui(cui: Optional[str]) -> str:
    return re.sub(r"\D", "", str(cui or ""))


def known_ibans_for_cui(cui: Optional[str]) -> Set[str]:
    return set(_memory.get(_norm_cui(cui), set()))


def iban_changed_for_cui(cui: Optional[str], iban: Optional[str]) -> bool:
    """True dacă firma (CUI) are istoric de IBAN(uri) ȘI cel curent NU e printre ele."""
    known = _memory.get(_norm_cui(cui))
    norm = normalize_iban(iban or "")
    return bool(known) and bool(norm) and norm not in known


def remember_invoice_iban(cui: Optional[str], iban: Optional[str]) -> bool:
    """Memorează (CUI, IBAN) ca istoric curat. Best-effort persist în Supabase."""
    cn = _norm_cui(cui)
    norm = normalize_iban(iban or "")
    if not cn or not norm:
        return False
    _memory.setdefault(cn, set()).add(norm)
    try:
        from services import supabase_store
        supabase_store.save_vendor_iban(cn, norm)
    except Exception:
        pass
    return True


def reload() -> None:
    """Golește memoria + reîncarcă best-effort din Supabase (refresh/teste)."""
    _memory.clear()
    try:
        from services import supabase_store
        for row in supabase_store.load_vendor_ibans():
            cn = _norm_cui(row.get("cui"))
            norm = normalize_iban(str(row.get("iban") or ""))
            if cn and norm:
                _memory.setdefault(cn, set()).add(norm)
    except Exception:
        pass
