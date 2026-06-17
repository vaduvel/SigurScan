from __future__ import annotations

import asyncio
import os
from concurrent.futures import ThreadPoolExecutor
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

# Paid/API-key fallback: openapi.ro company lookup.
OPENAPI_RO_COMPANY_URL = "https://api.openapi.ro/api/companies"
OPENAPI_RO_TIMEOUT_SECONDS = 3.0

# Bug#14: apelurile blocante către ANAF/lista-firme.info rulau pe executorul
# implicit al loop-ului (shared cu restul aplicației). Un ANAF lent/picat
# putea ocupa toate thread-urile executorului implicit și bloca alte operații
# async (ex. OCR) care depind de el. Folosim un executor dedicat, mărginit.
_ANAF_EXECUTOR = ThreadPoolExecutor(max_workers=4, thread_name_prefix="anaf-cui")

_INACTIVE_COMPANY_MARKERS = (
    "inactiv",
    "radiat",
    "radiata",
    "radiată",
    "dizolvat",
    "dizolvare",
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
    source: str | None = None


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
    try:
        result = await _call_openapi_ro_fallback(cui_digits)
        if result is not None:
            return result
    except Exception:
        pass
    return CuiResult(
        exists=False, checked=anaf_ok, denumire=None, activ=False, data_inactivare=None,
        platitor_tva=False, enrolled_efactura=False, raw=None, source=None,
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
        response = await loop.run_in_executor(_ANAF_EXECUTOR, _request)
        data = response.json()
        entry = _extract_anaf_entry(data)
        if response.status_code != 200 and entry is None:
            return None
        if entry is None:
            return None
        return _parse_anaf_entry(entry)
    except requests.RequestException:
        return None


def _extract_anaf_entry(data: Any) -> Dict[str, Any] | None:
    if isinstance(data, list):
        return data[0] if data and isinstance(data[0], dict) else None
    if not isinstance(data, dict):
        return None
    found = data.get("found")
    if isinstance(found, list) and found:
        return found[0] if isinstance(found[0], dict) else None
    not_found = data.get("notFound") or data.get("not_found")
    if isinstance(not_found, list) and not_found:
        raw = not_found[0] if isinstance(not_found[0], dict) else {"notFound": not_found[0]}
        return {"date_generale": None, "notFound": raw, "raw_response": data}
    return None


def _parse_anaf_entry(entry: Dict[str, Any]) -> CuiResult:
    dg = entry.get("date_generale")
    if not isinstance(dg, dict):
        return CuiResult(
            exists=False, checked=True, denumire=None, activ=False, data_inactivare=None,
            platitor_tva=False, enrolled_efactura=False, raw=entry, source="anaf",
        )
    denumire = (dg.get("denumire") or "").strip() or None
    stare_inactiv = entry.get("stare_inactiv") if isinstance(entry.get("stare_inactiv"), dict) else {}
    raw_status = dg.get("statusInactivi")
    if raw_status is None:
        raw_status = stare_inactiv.get("statusInactivi")
    if isinstance(raw_status, bool):
        status_inactiv = "true" if raw_status else "false"
    else:
        status_inactiv = (raw_status or "").strip().lower()
    data_inactivare = (dg.get("dataInactivare") or stare_inactiv.get("dataInactivare") or "").strip() or None
    scp_tva_raw = dg.get("scpTVA")
    scop_tva = entry.get("inregistrare_scop_Tva") if isinstance(entry.get("inregistrare_scop_Tva"), dict) else {}
    if scp_tva_raw is None:
        scp_tva_raw = scop_tva.get("scpTVA")
    if isinstance(scp_tva_raw, bool):
        scp_tva = scp_tva_raw
    else:
        scp_tva = (scp_tva_raw or "").strip().lower() == "da"
    enrol_raw = dg.get("statusRO_e_Factura")
    if isinstance(enrol_raw, bool):
        enrol_efactura = enrol_raw
    else:
        enrol_efactura = (enrol_raw or "").strip().lower() == "da"
    status_text = _collect_status_text(
        {
            "statusInactivi": status_inactiv,
            "stare_inregistrare": dg.get("stare_inregistrare"),
            "dataInactivare": data_inactivare,
            "dataRadiere": stare_inactiv.get("dataRadiere"),
        }
    ).lower()
    activ = status_inactiv not in {"inactiv", "true"} and not any(
        marker in status_text for marker in _INACTIVE_COMPANY_MARKERS
    )
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
        source="anaf",
    )


async def _call_lista_firme_fallback(cui_digits: str) -> CuiResult | None:
    url = f"{LISTA_FIRME_URL}?cui={cui_digits}"
    loop = asyncio.get_running_loop()

    def _request() -> requests.Response:
        return requests.get(url, timeout=LISTA_FIRME_TIMEOUT_SECONDS, headers={"Accept": "application/json"})

    try:
        response = await loop.run_in_executor(_ANAF_EXECUTOR, _request)
        if response.status_code != 200:
            return None
        data = response.json()
        if not isinstance(data, dict):
            return CuiResult(
                exists=False, checked=True, denumire=None, activ=False,
                data_inactivare=None, platitor_tva=False, enrolled_efactura=False, raw=data,
                source="lista_firme",
            )
        denumire = _first_non_empty_text(data, "denumire", "name", "company_name")
        returned_cui = _normalize_cui(str(data.get("cui") or data.get("fiscal_code") or ""))
        if returned_cui and returned_cui != cui_digits:
            return CuiResult(
                exists=False, checked=True, denumire=None, activ=False,
                data_inactivare=None, platitor_tva=False, enrolled_efactura=False, raw=data,
                source="lista_firme",
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
            source="lista_firme",
        )
    except requests.RequestException:
        return None


async def _call_openapi_ro_fallback(cui_digits: str) -> CuiResult | None:
    api_key = os.getenv("OPENAPI_RO_API_KEY", "").strip()
    if not api_key:
        return None

    url = f"{OPENAPI_RO_COMPANY_URL}/{cui_digits}"
    loop = asyncio.get_running_loop()

    def _request() -> requests.Response:
        return requests.get(
            url,
            timeout=OPENAPI_RO_TIMEOUT_SECONDS,
            headers={"Accept": "application/json", "x-api-key": api_key},
        )

    try:
        response = await loop.run_in_executor(_ANAF_EXECUTOR, _request)
        if response.status_code == 404:
            return CuiResult(
                exists=False,
                checked=True,
                denumire=None,
                activ=False,
                data_inactivare=None,
                platitor_tva=False,
                enrolled_efactura=False,
                raw=None,
                source="openapi_ro",
            )
        if response.status_code != 200:
            return None
        data = response.json()
        if not isinstance(data, dict):
            return CuiResult(
                exists=False,
                checked=True,
                denumire=None,
                activ=False,
                data_inactivare=None,
                platitor_tva=False,
                enrolled_efactura=False,
                raw={"payload": data},
                source="openapi_ro",
            )
        return _parse_openapi_ro_company(data, cui_digits)
    except requests.RequestException:
        return None


def _parse_openapi_ro_company(data: Dict[str, Any], cui_digits: str) -> CuiResult:
    company = _company_payload(data)
    returned_cui = _normalize_cui(
        str(
            company.get("cui")
            or company.get("cif")
            or company.get("fiscal_code")
            or company.get("fiscalCode")
            or company.get("tax_id")
            or company.get("taxId")
            or company.get("cod_fiscal")
            or ""
        )
    )
    if returned_cui and returned_cui != cui_digits:
        return CuiResult(
            exists=False,
            checked=True,
            denumire=None,
            activ=False,
            data_inactivare=None,
            platitor_tva=False,
            enrolled_efactura=False,
            raw=data,
            source="openapi_ro",
        )

    denumire = _first_non_empty_text(
        company,
        "denumire",
        "name",
        "company_name",
        "companyName",
        "nume",
        "legal_name",
        "legalName",
    )
    activ = _lista_firme_active_status(company, default=bool(denumire))
    scp_tva = _truthy_text(
        company.get("platitor_tva")
        or company.get("scp_tva")
        or company.get("vat_payer")
        or company.get("vatPayer")
        or company.get("tva")
    )
    enrolled_efactura = _truthy_text(
        company.get("statusRO_e_Factura")
        or company.get("efactura")
        or company.get("eFactura")
        or company.get("enrolled_efactura")
    )
    return CuiResult(
        exists=bool(denumire),
        checked=True,
        denumire=denumire,
        activ=activ,
        data_inactivare=None,
        platitor_tva=scp_tva,
        enrolled_efactura=enrolled_efactura,
        raw=data,
        source="openapi_ro",
    )


def _company_payload(data: Dict[str, Any]) -> Dict[str, Any]:
    for key in ("company", "data", "result", "item"):
        value = data.get(key)
        if isinstance(value, dict):
            return value
    return data


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
