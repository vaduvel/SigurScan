"""Stratul „Ce spune legea" (PR5) — educație juridică deterministă.

Reguli (din planul de execuție):
- NU schimbă verdictul. Rulează DUPĂ verdict_gate și nu atinge bundle-ul/gate-ul.
- NU inventează articole: întoarce DOAR carduri din data/legal_kb.json, verbatim.
- Fără mapping → listă goală. Disclaimerul e mereu prezent.
- Label UI: „Ce spune legea" — NU „Jurist"/„Avocat".

Maparea semnale OFFER_* -> trigger-e KB e deterministă și documentată mai jos.
"""
from __future__ import annotations

import json
import os
from functools import lru_cache
from typing import Any, Dict, List, Optional

from services import offer_signals as S

UI_LABEL = "Ce spune legea"

_FALLBACK_DISCLAIMER = (
    "Informatiile sunt educatie juridica generala, nu sfat juridic personalizat "
    "si nu inlocuiesc consultarea unui avocat."
)

_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DEFAULT_KB_PATH = os.path.join(_BACKEND_DIR, "data", "legal_kb.json")

# Semnal ofertă -> trigger din KB. Conservator: doar mapări evidente; ce nu are
# mapping nu produce card (regula „fără mapping → empty").
_SIGNAL_TO_TRIGGERS: Dict[str, List[str]] = {
    S.OFFER_ID_DOCUMENT_REQUEST: ["cerere_copie_ci"],
    S.OFFER_CARD_CVV_OTP_REQUEST: ["cerere_card_cvv_otp"],
    S.OFFER_OFF_PLATFORM_PAYMENT: ["plata_off_platform"],
    S.OFFER_PRICE_URGENCY: ["presiune_termen_limita"],
    S.OFFER_TOTALS_INCOHERENT: ["document_alterat"],
    S.OFFER_VAT_INCOHERENT: ["document_alterat"],
    S.OFFER_DATES_INCOHERENT: ["document_alterat"],
    # Avans cerut înainte de vizionare/livrare / beneficiar PF pentru firmă —
    # tabloul clasic al înșelăciunii prin avans (art. 244).
    S.OFFER_PAYMENT_METHOD_HIGH_RISK: ["oferta_prea_buna_avans"],
}

# Familie OP -> trigger-e suplimentare.
_FAMILY_TO_TRIGGERS: Dict[str, List[str]] = {
    "OP-07": ["cerere_cnp"],
}

# Tip document -> trigger-e (educativ, indiferent de verdict).
_DOCUMENT_TO_TRIGGERS: Dict[str, List[str]] = {
    "invoice": ["factura_reala_dar_scam"],
    "proforma": ["factura_reala_dar_scam"],
}


def _kb_path() -> str:
    return os.getenv("LEGAL_KB_PATH") or _DEFAULT_KB_PATH


@lru_cache(maxsize=1)
def load_legal_kb() -> Dict[str, Any]:
    """Încarcă KB-ul determinist. Lipsă/corupt → KB gol (fără crash, fără invenții)."""
    path = _kb_path()
    if not os.path.isfile(path):
        return {"version": None, "disclaimer": _FALLBACK_DISCLAIMER, "cards": []}
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {"version": None, "disclaimer": _FALLBACK_DISCLAIMER, "cards": []}
    if not isinstance(data, dict) or not isinstance(data.get("cards"), list):
        return {"version": None, "disclaimer": _FALLBACK_DISCLAIMER, "cards": []}
    data.setdefault("disclaimer", _FALLBACK_DISCLAIMER)
    return data


def legal_cards_for(
    signals: List[str],
    *,
    family_code: Optional[str] = None,
    document_type: Optional[str] = None,
) -> Dict[str, Any]:
    """Selectează cardurile juridice pentru semnalele/contextul dat.

    Pur și determinist. Cardurile sunt copiate verbatim din KB (id, title,
    summary, actions, source_refs) — zero reformulare aici.
    """
    kb = load_legal_kb()

    active_triggers: List[str] = []

    def add_triggers(triggers: List[str]) -> None:
        for trigger in triggers:
            if trigger not in active_triggers:
                active_triggers.append(trigger)

    for signal in signals or []:
        add_triggers(_SIGNAL_TO_TRIGGERS.get(signal, []))
    add_triggers(_FAMILY_TO_TRIGGERS.get(family_code or "", []))
    add_triggers(_DOCUMENT_TO_TRIGGERS.get((document_type or "").lower(), []))

    cards: List[Dict[str, Any]] = []
    seen_ids: set[str] = set()
    if active_triggers:
        trigger_set = set(active_triggers)
        # Ordinea cardurilor = ordinea din KB (determinist).
        for card in kb["cards"]:
            card_triggers = set(card.get("triggers") or [])
            if card_triggers & trigger_set and card.get("id") not in seen_ids:
                seen_ids.add(card["id"])
                cards.append(
                    {
                        "id": card["id"],
                        "title": card.get("title"),
                        "summary": card.get("summary"),
                        "actions": list(card.get("actions") or []),
                        "source_refs": list(card.get("source_refs") or []),
                    }
                )

    return {
        "label": UI_LABEL,
        "cards": cards,
        "disclaimer": kb.get("disclaimer") or _FALLBACK_DISCLAIMER,
    }
