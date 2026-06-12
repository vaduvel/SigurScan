"""Metadata onestă despre sursele de registru: ce sunt, cum sunt accesate, dacă
sunt configurate și cât de proaspete sunt datele. Fără API-uri inventate.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict

# Surse cunoscute. access="snapshot" = citim un fișier oficial descărcat local;
# access="not_configured" = nu există încă adapter real (stub onest).
SOURCES: Dict[str, Dict[str, Any]] = {
    "onrc": {
        "display_name": "ONRC — Registrul Comerțului",
        "official_source": "https://data.gov.ro/organization/onrc",
        "access": "snapshot",
        "recommended_runtime": "snapshot",
        "covers": ["firme/CUI", "stare firmă", "sediu", "activități autorizate"],
    },
    "situr": {
        "display_name": "SITUR / ANAT — agenții de turism licențiate",
        "official_source": "https://situr.gov.ro/portal/open-data",
        "access": "not_configured",
        "recommended_runtime": "snapshot",
        "covers": ["turism", "agenții licențiate", "agenții radiate", "licențe retrase"],
    },
    "bnr": {
        "display_name": "BNR — registre instituții financiare",
        "official_source": "https://www.bnr.ro/Registre-si-Liste-717.aspx",
        "access": "not_configured",
        "recommended_runtime": "live/hybrid",
        "covers": ["IFN", "instituții de plată", "entități supravegheate BNR"],
    },
    "asf": {
        "display_name": "ASF — registre piață financiară (SIIF)",
        "official_source": "https://www.asfromania.ro/ro/a/2818/registrul-a.s.f.",
        "access": "not_configured",
        "recommended_runtime": "live/hybrid",
        "covers": ["investiții", "piață de capital", "asigurări", "pensii"],
    },
    "anpc": {
        "display_name": "ANPC — protecția consumatorului",
        "official_source": "https://eservicii.anpc.ro/Depune-Cerere",
        "access": "not_configured",
        "recommended_runtime": "manual post-alert",
        "covers": ["reclamații și sesizări consumatori"],
        "notes": "Canal de raportare; nu validează singur existența sau legitimitatea entității.",
    },
    "ancpi": {
        "display_name": "ANCPI / Carte Funciară",
        "official_source": "https://epay.ancpi.ro/epay/SelectProd.action?prodId=1420",
        "access": "not_configured",
        "recommended_runtime": "manual/hybrid",
        "covers": ["proprietate imobiliară", "extras carte funciară"],
    },
    "rar_auto_pass": {
        "display_name": "RAR — Istoric Vehicul (VIN)",
        "official_source": "https://www.rarom.ro/?p=298531",
        "access": "not_configured",
        "recommended_runtime": "live/manual",
        "covers": ["istoric vehicul", "kilometraj", "daune"],
    },
    "itm": {
        "display_name": "ITM — inspecția muncii",
        "official_source": "https://www.inspectiamuncii.ro/",
        "access": "not_configured",
        "recommended_runtime": "manual",
        "covers": ["relații de muncă"],
    },
    "anofm": {
        "display_name": "ANOFM — agenția pentru ocuparea forței de muncă",
        "official_source": "https://www.anofm.ro/",
        "access": "not_configured",
        "recommended_runtime": "manual",
        "covers": ["oferte de muncă și servicii de ocupare"],
    },
}

ONRC_SNAPSHOT_PATH_ENV = "ONRC_SNAPSHOT_PATH"
ONRC_SNAPSHOT_MAX_AGE_ENV = "ONRC_SNAPSHOT_MAX_AGE_DAYS"
ONRC_SNAPSHOT_MAX_AGE_DEFAULT_DAYS = 400

_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# Cale implicită; fișierul NU e livrat în repo (zero date fake). Absent => NOT_CONFIGURED.
_ONRC_DEFAULT_PATH = os.path.join(_BACKEND_DIR, "data", "onrc_snapshot.csv")


def onrc_snapshot_path() -> str:
    return os.getenv(ONRC_SNAPSHOT_PATH_ENV) or _ONRC_DEFAULT_PATH


def onrc_snapshot_max_age_days() -> int:
    raw = os.getenv(ONRC_SNAPSHOT_MAX_AGE_ENV)
    try:
        value = int(raw) if raw else ONRC_SNAPSHOT_MAX_AGE_DEFAULT_DAYS
    except ValueError:
        value = ONRC_SNAPSHOT_MAX_AGE_DEFAULT_DAYS
    return max(1, value)


def source_metadata(source_id: str) -> Dict[str, Any]:
    """Metadata pentru o sursă: sursa oficială, data actualizării, configurare."""
    base = dict(SOURCES.get(source_id) or {"display_name": source_id, "access": "not_configured"})
    meta: Dict[str, Any] = {
        "source_id": source_id,
        "display_name": base.get("display_name"),
        "official_source": base.get("official_source"),
        "access": base.get("access"),
        "recommended_runtime": base.get("recommended_runtime"),
        "covers": list(base.get("covers") or []),
        "notes": base.get("notes"),
        "configured": False,
        "updated_at": None,
    }
    if source_id == "onrc":
        path = onrc_snapshot_path()
        meta["snapshot_path"] = path
        meta["max_age_days"] = onrc_snapshot_max_age_days()
        if os.path.isfile(path):
            meta["configured"] = True
            mtime = os.path.getmtime(path)
            meta["updated_at"] = datetime.fromtimestamp(mtime, tz=timezone.utc).date().isoformat()
    return meta
