"""Pilon — Registru NEGATIV de IBAN-uri (catâri/complici raportați).

Răspunsul determinist la „firmă reală + IBAN al unui complice": whitelist-ul nu
te ajută (firma nu pretinde un brand), dar dacă IBAN-ul a mai lovit pe altcineva,
îl prinzi la prima scanare a VICTIMEI #2. Alimentat din alerte DNSC + rapoarte
comunitare (Radar `/v1/report`). E un PILON de semnal — verdictul îl dă verdict_gate.

Privacy: în producție IBAN-urile pot fi stocate hash-uite (HMAC). Aici comparăm pe
forma normalizată; feed-ul decide formatul. Seed-ul pornește gol (zero fals-pozitive).
"""
from __future__ import annotations

import json
import os
from functools import lru_cache
from typing import List, Set

from services.iban_validator import normalize_iban

_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DEFAULT_PATH = os.path.join(_BACKEND_DIR, "data", "negative_iban_registry_v1.json")


def _path() -> str:
    return os.getenv("NEGATIVE_IBAN_REGISTRY_PATH") or _DEFAULT_PATH


@lru_cache(maxsize=1)
def _registry() -> Set[str]:
    """IBAN-uri raportate, normalizate (uppercase, fără spații). Lipsă/corupt → gol."""
    path = _path()
    if not os.path.isfile(path):
        return set()
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError):
        return set()
    out: Set[str] = set()
    for raw in (data.get("reported_ibans") or []):
        norm = normalize_iban(str(raw))
        if norm:
            out.add(norm)
    return out


def reload_registry() -> None:
    """Reîncarcă registrul (după update de feed sau în teste)."""
    _registry.cache_clear()


def is_reported_fraud(iban: str) -> bool:
    norm = normalize_iban(iban or "")
    return bool(norm) and norm in _registry()


def reported_fraud_ibans(ibans: List[str]) -> List[str]:
    """Subsetul de IBAN-uri din listă care apar în registrul negativ."""
    seen: Set[str] = set()
    out: List[str] = []
    for raw in ibans or []:
        norm = normalize_iban(raw or "")
        if norm and norm not in seen and norm in _registry():
            seen.add(norm)
            out.append(norm)
    return out
