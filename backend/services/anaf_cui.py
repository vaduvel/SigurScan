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

_INACTIVE_COMPANY_MARKERS = (
    "inactiv",
    "radiat",
    "radiata",
    "radiată",
    "dizolvat",
    "lichidare",
    "faliment",
    "insolven",
    "suspend",
    "desfiint",
    "desființ",
)
_ACTIVE_COMPANY_MARKERS = ("activ", "functiune", "funcțiune")


@dataclass
class CuiResult:
    exists: bool
    checked: bool
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
            exists=False, checked=True, denumire=None, activ=False, data_inactivare=None,
            platitor_tva=False, enrolled_efactura=False, raw=None,
        )
    ref_date = data or date.today().isoformat()
    anaf_ok = False
    try:
        result = await _call_anaf_api(int(cui_digits), ref_date)
        if result is not None:
            anaf_ok = True
            return result
    except Exception:
        pass
    try:
        result = await _call_lista_firme_fallback(cui_digits)
        if result is not None:
            return result
    except Exception:
        pass
    return CuiResult(
        exists=False, checked=anaf_ok, denumire=None, activ=False, data_inactivare=None,
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
            exists=False, checked=True, denumire=None, activ=False, data_inactivare=None,
            platitor_tva=False, enrolled_efactura=False, raw=entry,
        )
    denumire = (dg.get("denumire") or "").strip() or None
    raw_status = dg.get("statusInactivi")
    if isinstance(raw_status, bool):
        status_inactiv = "true" if raw_status else "false"
    else:
        status_inactiv = (raw_status or "").strip().lower()
    data_inactivare = (dg.get("dataInactivare") or "").strip() or None
    scp_tva_raw = dg.get("scpTVA")
    if isinstance(scp_tva_raw, bool):
        scp_tva = scp_tva_raw
    else:
        scp_tva = (scp_tva_raw or "").strip().lower() == "da"
    enrol_raw = dg.get("statusRO_e_Factura")
    if isinstance(enrol_raw, bool):
        enrol_efactura = enrol_raw
    else:
        enrol_efactura = (enrol_raw or "").strip().lower() == "da"
    activ = status_inactiv not in {"inactiv", "true"}
    exists = bool(denumire)
    return CuiResult(
        exists=exists,
        checked=True,
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
        if not isinstance(data, dict):
            return CuiResult(
                exists=False, checked=True, denumire=None, activ=False,
                data_inactivare=None, platitor_tva=False, enrolled_efactura=False, raw=data,
            )
        denumire = _first_non_empty_text(data, "denumire", "name", "company_name")
        returned_cui = _normalize_cui(str(data.get("cui") or data.get("fiscal_code") or ""))
        if returned_cui and returned_cui != cui_digits:
            return CuiResult(
                exists=False, checked=True, denumire=None, activ=False,
                data_inactivare=None, platitor_tva=False, enrolled_efactura=False, raw=data,
            )
        activ = _lista_firme_active_status(data, default=bool(denumire))
        scp_tva = _truthy_text(
            data.get("platitor_tva")
            or data.get("scp_tva")
            or data.get("vat_payer")
            or data.get("vatPayer")
        )
        return CuiResult(
            exists=bool(denumire),
            checked=True,
            denumire=denumire,
            activ=activ,
            data_inactivare=None,
            platitor_tva=scp_tva,
            enrolled_efactura=False,
            raw=data,
        )
    except requests.RequestException:
        return None


def _first_non_empty_text(data: Dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = data.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _truthy_text(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"da", "true", "1", "yes"}


def _collect_status_text(value: Any) -> str:
    if isinstance(value, dict):
        return " ".join(_collect_status_text(v) for v in value.values())
    if isinstance(value, list):
        return " ".join(_collect_status_text(v) for v in value)
    return str(value or "")


def _lista_firme_active_status(data: Dict[str, Any], *, default: bool) -> bool:
    status_text = " ".join(
        [
            _collect_status_text(data.get("stare")),
            _collect_status_text(data.get("status")),
            _collect_status_text(data.get("state")),
        ]
    ).strip().lower()
    if any(marker in status_text for marker in _INACTIVE_COMPANY_MARKERS):
        return False
    if any(marker in status_text for marker in _ACTIVE_COMPANY_MARKERS):
        return True
    return default
