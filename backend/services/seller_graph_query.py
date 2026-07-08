"""D6 Felia 2 — query the seller-identity graph at verdict time (SOFT signal).

Given a payment IBAN, ask the reputation graph whether it is linked to a
community-flagged high-risk phone (the `pays_to` edges persisted by Felia 1).
If so, surface a SOFT advisory — never a hard conflict, never a DANGEROUS verdict.

Hard-gated by `D6_GRAPH_SIGNAL` (default OFF). When off, or when Supabase is not
configured, this is a pure no-op (returns None), so it can never change a verdict
in production before it is deliberately enabled and its FP rate measured (R7).

Conservative by construction:
- Emits ONLY on `GRAPH_LINKED_TO_HIGH_RISK_PHONE` (an IBAN paid-to by a phone the
  community reports as high-risk) — not the weaker infra linkage.
- Never emits for an allowlisted (official) IBAN.
- Best-effort: any failure yields None, never raises into the verdict path.
"""
from __future__ import annotations

import os
import time
from typing import Any, Dict, Optional

from services.reputation_identity import hash_iban

_HIGH_RISK_PHONE_LINK = "GRAPH_LINKED_TO_HIGH_RISK_PHONE"
_ALLOWLISTED_STATUSES = {"allowlisted", "allowlisted_watch"}

# Cache the loaded graph briefly so we don't hit Supabase on every verdict.
_CACHE_TTL_SECONDS = 300.0
_cache: Dict[str, Any] = {"graph": None, "loaded_at": 0.0}


def is_enabled() -> bool:
    """Default OFF. Enabled only for explicit truthy values."""
    return os.getenv("D6_GRAPH_SIGNAL", "0").strip().lower() in {"1", "true", "yes", "on"}


def reset_cache() -> None:
    _cache["graph"] = None
    _cache["loaded_at"] = 0.0


def _load_graph():
    from services import supabase_store

    if not supabase_store.is_supabase_enabled():
        return None
    now = time.time()
    if _cache["graph"] is not None and (now - _cache["loaded_at"]) < _CACHE_TTL_SECONDS:
        return _cache["graph"]
    from services.reputation_graph import ReputationGraph

    rows = supabase_store.load_reputation_graph_rows(limit=5000)
    graph = ReputationGraph.from_rows(
        observations=rows.get("observations", []),
        edges=rows.get("edges", []),
        allowlist=rows.get("allowlist", []),
    )
    _cache["graph"] = graph
    _cache["loaded_at"] = now
    return graph


def iban_graph_signal(iban: Optional[str]) -> Optional[Dict[str, str]]:
    """Return a soft advisory dict {code, message} or None. Never raises."""
    if not is_enabled() or not iban:
        return None
    try:
        iban_hash = hash_iban(iban)
        if not iban_hash:
            return None
        graph = _load_graph()
        if graph is None:
            return None
        verdict = graph.evaluate("iban", iban_hash)
        if verdict.get("status") in _ALLOWLISTED_STATUSES:
            return None  # official / allowlisted IBAN — never advise against it
        if _HIGH_RISK_PHONE_LINK in (verdict.get("reason_codes") or []):
            return {
                "code": _HIGH_RISK_PHONE_LINK,
                "message": (
                    "Contul de plată apare legat de un număr de telefon raportat ca "
                    "risc ridicat în alte cazuri; confirmă direct cu furnizorul înainte de plată."
                ),
            }
    except Exception:
        return None
    return None
