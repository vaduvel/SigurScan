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
        "official_source": "https://data.gov.ro (dump ONRC firme)",
        "access": "snapshot",
    },
    "situr": {
        "display_name": "SITUR / ANAT — agenții de turism licențiate",
        "official_source": "situr.gov.ro / OpenData",
        "access": "not_configured",
    },
    "bnr": {
        "display_name": "BNR — registre instituții financiare",
        "official_source": "bnr.ro",
        "access": "not_configured",
    },
    "asf": {
        "display_name": "ASF — registre piață financiară (SIIF)",
        "official_source": "asfromania.ro",
        "access": "not_configured",
    },
    "anpc": {
        "display_name": "ANPC — protecția consumatorului",
        "official_source": "anpc.ro",
        "access": "not_configured",
    },
    "ancpi": {
        "display_name": "ANCPI / Carte Funciară",
        "official_source": "ancpi.ro (contra cost, fără API public)",
        "access": "not_configured",
    },
    "rar_auto_pass": {
        "display_name": "RAR — Istoric Vehicul (VIN)",
        "official_source": "prog.rarom.ro (taxă, fără API)",
        "access": "not_configured",
    },
    "itm": {
        "display_name": "ITM — inspecția muncii",
        "official_source": "inspectiamuncii.ro",
        "access": "not_configured",
    },
    "anofm": {
        "display_name": "ANOFM — agenția pentru ocuparea forței de muncă",
        "official_source": "anofm.ro",
        "access": "not_configured",
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
