"""Offer family classifier (OP-00..OP-09) — WRAPPER peste ScamAtlasEngine.

NU un al doilea engine. Încarcă `data/scam_atlas_offer_seed.json`, adaptează
familiile OP în forma normalizată pe care o consumă
`ScamAtlasEngine.classify_scam_family`, și reutilizează exact acea logică de
matching (token overlap + claimed_brand). Familia e un HINT soft; verdictul
determinist vine din verdict_gate (PR2).

Schema seed-ului ofertă (`code` / `signals:[{text,...}]`) diferă de cea pe care o
așteaptă `_normalize_atlas_family` (`id` / `match_text`), de aceea facem aici un
adapter explicit: code→id, match_text construit din nume + textele semnalelor.
"""
from __future__ import annotations

import json
import os
from functools import lru_cache
from typing import Any, Dict, List, Optional, Tuple

from services.scam_atlas import ScamAtlasEngine

_DEFAULT_OFFER_SEED = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data",
    "scam_atlas_offer_seed.json",
)
OFFER_SEED_PATH = os.getenv("SCAM_ATLAS_OFFER_SEED_PATH", _DEFAULT_OFFER_SEED)

DEFAULT_FAMILY_CODE = "OP-00"
DEFAULT_FAMILY_NAME = "Necategorizat"
MIN_FAMILY_CONFIDENCE = 0.2


def _adapt_family(raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Mapează o familie din seed-ul ofertă în forma pe care o citește
    classify_scam_family (family/match_text/hook/signals)."""
    code = str(raw.get("code") or "").strip()
    name = str(raw.get("name") or "").strip()
    if not code or not name:
        return None

    signal_texts = [
        str(s.get("text")).strip()
        for s in (raw.get("signals") or [])
        if isinstance(s, dict) and s.get("text")
    ]
    match_parts = [name, *signal_texts]
    match_text = " | ".join(match_parts)

    return {
        "id": code,
        "code": code,
        "family": name,
        "title": name,
        "match_text": match_text,
        "hook": match_text,
        "asks_for": [],
        "signals": signal_texts,
        "examples": [],
        "claimed_brand_or_role": None,
        # metadata ofertă păstrată pentru PR2 (gate combos) / offer_signals
        "status": raw.get("status"),
        "verification_sources": list(raw.get("verification_sources") or []),
        "payment_risk": dict(raw.get("payment_risk") or {}),
    }


@lru_cache(maxsize=1)
def _load_offer_seed() -> Dict[str, Any]:
    if not os.path.exists(OFFER_SEED_PATH):
        return {"families": [], "cross_cutting_modifiers": []}
    try:
        with open(OFFER_SEED_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:  # pragma: no cover - corupt/illegible seed
        return {"families": [], "cross_cutting_modifiers": []}


@lru_cache(maxsize=1)
def _adapted_families() -> List[Dict[str, Any]]:
    seed = _load_offer_seed()
    out: List[Dict[str, Any]] = []
    for raw in seed.get("families", []):
        adapted = _adapt_family(raw)
        if adapted is not None:
            out.append(adapted)
    return out


@lru_cache(maxsize=1)
def _engine() -> ScamAtlasEngine:
    """O instanță ScamAtlasEngine alimentată cu familiile ofertă.

    Reutilizăm logica de matching a engine-ului (classify_scam_family) fără a o
    duplica; doar înlocuim setul de familii cu cele de tip ofertă (OP-xx).
    """
    engine = ScamAtlasEngine()
    engine.families = _adapted_families()
    return engine


def get_offer_family(code: str) -> Optional[Dict[str, Any]]:
    """Returnează metadata completă a unei familii OP (pentru PR2/offer_signals)."""
    for fam in _adapted_families():
        if fam.get("code") == code:
            return fam
    return None


def list_offer_family_codes() -> List[str]:
    return [fam["code"] for fam in _adapted_families()]


def classify_offer_family(
    text: str, claimed_brand: Optional[str] = None
) -> Tuple[str, str, float]:
    """Clasifică oferta într-o familie OP-xx.

    Returnează (code, name, confidence). Sub prag sau fără potrivire → OP-00.
    """
    if not text or not text.strip():
        return DEFAULT_FAMILY_CODE, DEFAULT_FAMILY_NAME, 0.0

    family, confidence = _engine().classify_scam_family(text, claimed_brand)
    code = str(family.get("id") or family.get("code") or "")
    name = str(family.get("family") or family.get("name") or "")

    if not code.startswith("OP-") or confidence < MIN_FAMILY_CONFIDENCE:
        return DEFAULT_FAMILY_CODE, DEFAULT_FAMILY_NAME, round(confidence, 4)

    return code, name, round(confidence, 4)
