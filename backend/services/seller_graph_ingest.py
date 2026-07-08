"""D6 Felia 1 — persist cross-scan seller-identity edges (write-only, gated OFF).

When a single scan surfaces both a phone and an IBAN, they co-occur as one
seller's contact + payout account. Persisting a ``phone --pays_to--> iban`` edge
lets a later scan's verdict see that an IBAN is linked to a phone that the
community subsequently flags as high-risk (reputation_graph
``GRAPH_LINKED_TO_HIGH_RISK_PHONE``).

This module ONLY writes edges. It never reads the graph, never touches a verdict,
and is a hard no-op unless ``D6_PERSIST_EDGES`` is explicitly enabled. Felia 2
(query at verdict, soft signal only) is a separate slice.

Scope (Felia 1): IBAN <-> phone only. Beneficiary / legal-name nodes (diacritics,
legal_name vs brand) are a separate risk class, deliberately deferred.
"""
from __future__ import annotations

import os
from typing import Any, Dict, List

from services.pii_redactor import IBAN_REGEX, PHONE_REGEX
from services.reputation_identity import hash_iban, hash_phone

# Caps so a pathological text can't explode into a huge edge fan-out.
_MAX_PHONES = 8
_MAX_IBANS = 8
_MAX_EDGES = 25


def is_enabled() -> bool:
    """Default OFF. Enabled only for explicit truthy values."""
    return os.getenv("D6_PERSIST_EDGES", "0").strip().lower() in {"1", "true", "yes", "on"}


def _distinct(hashes: List[str], cap: int) -> List[str]:
    out: List[str] = []
    for h in hashes:
        if h and h not in out:
            out.append(h)
        if len(out) >= cap:
            break
    return out


def record_cooccurrence_edges(text: str | None, *, source: str = "scan_cooccurrence") -> Dict[str, Any]:
    """Best-effort. Returns a summary; never raises, never affects a verdict.

    No-op (persisted=0) unless D6_PERSIST_EDGES is on. When on, persists a
    deterministic, idempotent ``phone --pays_to--> iban`` edge for every distinct
    phone/IBAN pair co-occurring in ``text``.
    """
    if not is_enabled() or not text:
        return {"enabled": is_enabled(), "phones": 0, "ibans": 0, "persisted": 0}

    # finditer + group(0): IBAN_REGEX has a capturing group, so findall would
    # return the group instead of the full IBAN. group(0) is the full match.
    phone_hashes = _distinct([hash_phone(m.group(0)) for m in PHONE_REGEX.finditer(text)], _MAX_PHONES)
    iban_hashes = _distinct([hash_iban(m.group(0)) for m in IBAN_REGEX.finditer(text)], _MAX_IBANS)

    # Imported lazily so a missing/misconfigured Supabase never breaks a scan and
    # so tests can patch the persistence boundary cleanly.
    from services import supabase_store

    persisted = 0
    for phone_hash in phone_hashes:
        for iban_hash in iban_hashes:
            if persisted >= _MAX_EDGES:
                break
            try:
                supabase_store.upsert_reputation_edge({
                    "source_type": "phone",
                    "source_hash": phone_hash,
                    "target_type": "iban",
                    "target_hash": iban_hash,
                    "relation": "pays_to",
                    "source": source,
                    "evidence_quality": "low",
                })
                persisted += 1
            except Exception:
                # Write-only, best-effort: a persistence failure must never
                # surface to the caller / verdict path.
                continue
    return {"enabled": True, "phones": len(phone_hashes), "ibans": len(iban_hashes), "persisted": persisted}
