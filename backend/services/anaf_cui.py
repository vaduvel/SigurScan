from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import date, datetime
from typing import Any, Dict

import requests

# ANAF PlatitorTVA v9 endpoint (public, zero auth).
ANAF_TVA_URL = "https://webservicesp.anaf.ro/api/PlatitorTvaRest/v9/tva"
ANAF_TIMEOUT_SECONDS = 4.0

# Fallback: lista-firme.info (public, rate-limited).
LISTA_FIRME_URL = "https://lista-firme.info/api/v1/info"
LISTA_FIRME_TIMEOUT_SECONDS = 3.0


@dataclass
class CuiResult:
    exists: bool
    denumire: str | None
    activ: bool
    data_inactivare: str | None
    platitor_tva: bool
    enrolled_efactura: bool
    raw: Dict[str, Any] | None


async def check_cui(cui: str, data: str | None = None) -> CuiResult:
    cui_digits = _normalize_cui(cui)
    if not cui_digits or not cui_digits.isdigit():
        return CuiResult(
            exists=False, denumire=None, activ=False, data_inactivare=None,
            platitor_tva=False, enrolled_efactura=False, raw=None,
        )
    ref_date = data or date.today().isoformat()
    try:
        result = await _call_anaf_api(int(cui_digits), ref_date)
        if result:
            return result
    except Exception:
        pass
    try:
        result = await _call_lista_firme_fallback(cui_digits)
        if result:
            return result
    except Exception:
        pass
    return CuiResult(
        exists=False, denumire=None, activ=False, data_inactivare=None,
        platitor_tva=False, enrolled_efactura=False, raw=None,
    )


def _normalize_cui(raw: str) -> str:
    return "".join(ch for ch in raw if ch.isdigit())


async def _call_anaf_api(cui_int: int, ref_date: str) -> CuiResult | None:
    payload = [{"cui": cui_int, "data": ref_date}]
    loop = asyncio.get_running_loop()

    def _request() -> requests.Response:
        return requests.post(
            ANAF_TVA_URL,
            json=payload,
            timeout=ANAF_TIMEOUT_SECONDS,
            headers={"Accept": "application/json", "Content-Type": "application/json"},
        )

    try:
        response = await loop.run_in_executor(None, _request)
        if response.status_code != 200:
            return None
        data = response.json()
        if not isinstance(data, list) or len(data) == 0:
            return None
        entry = data[0] if isinstance(data[0], dict) else None
        if not entry:
            return None
        return _parse_anaf_entry(entry)
    except requests.RequestException:
        return None


def _parse_anaf_entry(entry: Dict[str, Any]) -> CuiResult:
    dg = entry.get("date_generale")
    if not isinstance(dg, dict):
        return CuiResult(
            exists=False, denumire=None, activ=False, data_inactivare=None,
            platitor_tva=False, enrolled_efactura=False, raw=entry,
        )
    denumire = (dg.get("denumire") or "").strip() or None
    status_inactiv = (dg.get("statusInactivi") or "").strip().lower()
    data_inactivare = (dg.get("dataInactivare") or "").strip() or None
    scp_tva = (dg.get("scpTVA") or "").strip().lower() == "da"
    enrol_efactura = (dg.get("statusRO_e_Factura") or "").strip().lower() == "da"
    activ = status_inactiv not in {"inactiv", "true"}
    exists = bool(denumire)
    return CuiResult(
        exists=exists,
        denumire=denumire,
        activ=activ,
        data_inactivare=data_inactivare,
        platitor_tva=scp_tva,
        enrolled_efactura=enrol_efactura,
        raw=entry,
    )


async def _call_lista_firme_fallback(cui_digits: str) -> CuiResult | None:
    url = f"{LISTA_FIRME_URL}?cui={cui_digits}"
    loop = asyncio.get_running_loop()

    def _request() -> requests.Response:
        return requests.get(url, timeout=LISTA_FIRME_TIMEOUT_SECONDS, headers={"Accept": "application/json"})

    try:
        response = await loop.run_in_executor(None, _request)
        if response.status_code != 200:
            return None
        data = response.json()
        if not isinstance(data, dict) or not data.get("denumire"):
            return None
        denumire = (data.get("denumire") or "").strip() or None
        activ = str(data.get("stare") or "").strip().lower() != "inactiv"
        scp_tva = str(data.get("platitor_tva") or "").strip().lower() in {"da", "true", "1"}
        return CuiResult(
            exists=bool(denumire),
            denumire=denumire,
            activ=activ,
            data_inactivare=None,
            platitor_tva=scp_tva,
            enrolled_efactura=False,
            raw=data,
        )
    except requests.RequestException:
        return None
