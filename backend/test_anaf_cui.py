import pytest
from unittest.mock import patch, MagicMock

from services.anaf_cui import check_cui, _normalize_cui


ANAF_ACTIVE_RESPONSE = [
    {
        "cui": 14345906,
        "data": "2026-06-01",
        "date_generale": {
            "cui": "14345906",
            "denumire": "ENEL ENERGIE SA",
            "adresa": "Bucuresti, Sector 1",
            "statusInactivi": "False",
            "dataInactivare": None,
            "scpTVA": "Da",
            "statusRO_e_Factura": "Da",
        },
    }
]

ANAF_INACTIVE_RESPONSE = [
    {
        "cui": 99999999,
        "data": "2026-06-01",
        "date_generale": {
            "cui": "99999999",
            "denumire": "Firma Inactiva SRL",
            "statusInactivi": "True",
            "dataInactivare": "2025-01-15",
            "scpTVA": "Nu",
            "statusRO_e_Factura": "Nu",
        },
    }
]

ANAF_NONEXISTENT_RESPONSE = [
    {
        "cui": 11111111,
        "data": "2026-06-01",
        "date_generale": None,
    }
]

ANAF_V9_FOUND_RESPONSE = {
    "cod": 200,
    "message": "SUCCESS",
    "found": [
        {
            "date_generale": {
                "data": "2026-06-15",
                "cui": 5888716,
                "denumire": "DIGI ROMANIA S.A.",
                "stare_inregistrare": "INREGISTRAT din data 25.11.2003",
                "statusRO_e_Factura": False,
            },
            "inregistrare_scop_Tva": {"scpTVA": True},
            "stare_inactiv": {"statusInactivi": False, "dataInactivare": ""},
        }
    ],
    "notFound": [],
}

ANAF_V9_DISSOLVED_RESPONSE = {
    "cod": 200,
    "message": "SUCCESS",
    "found": [
        {
            "date_generale": {
                "data": "2026-06-15",
                "cui": 24387371,
                "denumire": "PPC ENERGIE MUNTENIA S.A.",
                "stare_inregistrare": "DIZOLVARE FARA LICHIDARE(FUZIUNE) din data 31.12.2024",
                "statusRO_e_Factura": False,
            },
            "inregistrare_scop_Tva": {"scpTVA": False},
            "stare_inactiv": {
                "statusInactivi": False,
                "dataInactivare": "",
                "dataRadiere": "",
            },
        }
    ],
    "notFound": [],
}


@pytest.mark.asyncio
async def test_cui_activ():
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = ANAF_ACTIVE_RESPONSE

    with patch("services.anaf_cui.requests.post", return_value=mock_response):
        result = await check_cui("14345906")

    assert result.exists is True
    assert result.checked is True
    assert result.denumire == "ENEL ENERGIE SA"
    assert result.activ is True
    assert result.platitor_tva is True
    assert result.enrolled_efactura is True
    assert result.data_inactivare is None


@pytest.mark.asyncio
async def test_cui_activ_from_anaf_v9_found_object_shape():
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = ANAF_V9_FOUND_RESPONSE

    with patch("services.anaf_cui.requests.post", return_value=mock_response):
        result = await check_cui("5888716")

    assert result.exists is True
    assert result.checked is True
    assert result.denumire == "DIGI ROMANIA S.A."
    assert result.activ is True
    assert result.platitor_tva is True


@pytest.mark.asyncio
async def test_cui_dissolved_from_anaf_v9_status_text_is_inactive():
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = ANAF_V9_DISSOLVED_RESPONSE

    with patch("services.anaf_cui.requests.post", return_value=mock_response):
        result = await check_cui("24387371")

    assert result.exists is True
    assert result.checked is True
    assert result.denumire == "PPC ENERGIE MUNTENIA S.A."
    assert result.activ is False


@pytest.mark.asyncio
async def test_cui_nonexistent_from_anaf_v9_not_found_object_shape():
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "cod": 200,
        "message": "SUCCESS",
        "found": [],
        "notFound": [{"cui": 11111111}],
    }

    with patch("services.anaf_cui.requests.post", return_value=mock_response):
        result = await check_cui("11111111")

    assert result.exists is False
    assert result.checked is True
    assert result.denumire is None


@pytest.mark.asyncio
async def test_cui_nonexistent_from_anaf_v9_http_404_json_not_found_is_checked():
    mock_response = MagicMock()
    mock_response.status_code = 404
    mock_response.json.return_value = {"found": [], "notFound": [11111111]}

    with patch("services.anaf_cui.requests.post", return_value=mock_response):
        result = await check_cui("11111111")

    assert result.exists is False
    assert result.checked is True
    assert result.denumire is None


@pytest.mark.asyncio
async def test_cui_inactiv():
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = ANAF_INACTIVE_RESPONSE

    with patch("services.anaf_cui.requests.post", return_value=mock_response):
        result = await check_cui("99999999")

    assert result.exists is True
    assert result.checked is True
    assert result.denumire == "Firma Inactiva SRL"
    assert result.activ is False
    assert result.data_inactivare == "2025-01-15"
    assert result.platitor_tva is False


@pytest.mark.asyncio
async def test_cui_nonexistent():
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = ANAF_NONEXISTENT_RESPONSE

    with patch("services.anaf_cui.requests.post", return_value=mock_response):
        result = await check_cui("11111111")

    assert result.exists is False
    assert result.checked is True
    assert result.denumire is None
    assert result.activ is False


@pytest.mark.asyncio
async def test_anaf_timeout_uses_fallback():
    def failing_post(*args, **kwargs):
        import requests
        raise requests.ConnectionError("timeout")

    mock_fallback = MagicMock()
    mock_fallback.status_code = 200
    mock_fallback.json.return_value = {"denumire": "ENEL ENERGIE SA", "stare": "activ", "platitor_tva": "Da"}

    with patch("services.anaf_cui.requests.post", side_effect=failing_post):
        with patch("services.anaf_cui.requests.get", return_value=mock_fallback):
            result = await check_cui("14345906")

    assert result.exists is True
    assert result.checked is True
    assert result.denumire == "ENEL ENERGIE SA"
    assert result.activ is True


@pytest.mark.asyncio
async def test_lista_firme_fallback_maps_live_shape_as_existing_company():
    def failing_post(*args, **kwargs):
        import requests
        raise requests.ConnectionError("timeout")

    mock_fallback = MagicMock()
    mock_fallback.status_code = 200
    mock_fallback.json.return_value = {
        "name": "DIGI ROMANIA S.A.",
        "cui": "5888716",
        "status": {
            "details": {
                "code": 1048,
                "description": "funcțiune",
            }
        },
    }

    with patch("services.anaf_cui.requests.post", side_effect=failing_post):
        with patch("services.anaf_cui.requests.get", return_value=mock_fallback):
            result = await check_cui("RO5888716")

    assert result.exists is True
    assert result.checked is True
    assert result.denumire == "DIGI ROMANIA S.A."
    assert result.activ is True
    assert result.platitor_tva is False


@pytest.mark.asyncio
async def test_lista_firme_fallback_marks_live_shape_radiated_company_inactive():
    def failing_post(*args, **kwargs):
        import requests
        raise requests.ConnectionError("timeout")

    mock_fallback = MagicMock()
    mock_fallback.status_code = 200
    mock_fallback.json.return_value = {
        "name": "PPC ENERGIE MUNTENIA S.A.",
        "cui": "24387371",
        "status": {
            "details": {
                "code": 1060,
                "description": "radiată",
            }
        },
    }

    with patch("services.anaf_cui.requests.post", side_effect=failing_post):
        with patch("services.anaf_cui.requests.get", return_value=mock_fallback):
            result = await check_cui("24387371")

    assert result.exists is True
    assert result.checked is True
    assert result.denumire == "PPC ENERGIE MUNTENIA S.A."
    assert result.activ is False


@pytest.mark.asyncio
async def test_lista_firme_fallback_rejects_mismatched_cui_payload():
    def failing_post(*args, **kwargs):
        import requests
        raise requests.ConnectionError("timeout")

    mock_fallback = MagicMock()
    mock_fallback.status_code = 200
    mock_fallback.json.return_value = {
        "name": "ALTĂ FIRMĂ S.R.L.",
        "cui": "99999999",
        "status": {"details": {"description": "funcțiune"}},
    }

    with patch("services.anaf_cui.requests.post", side_effect=failing_post):
        with patch("services.anaf_cui.requests.get", return_value=mock_fallback):
            result = await check_cui("5888716")

    assert result.exists is False
    assert result.checked is True
    assert result.denumire is None


@pytest.mark.asyncio
async def test_openapi_ro_fallback_maps_company_when_public_sources_fail(monkeypatch):
    def failing_post(*args, **kwargs):
        import requests
        raise requests.ConnectionError("anaf timeout")

    def get_side_effect(url, *args, **kwargs):
        import requests

        if "lista-firme.info" in url:
            raise requests.ConnectionError("lista-firme timeout")
        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {
            "cui": "5888716",
            "name": "DIGI ROMANIA S.A.",
            "status": {"details": {"description": "funcțiune"}},
            "vatPayer": True,
        }
        return response

    monkeypatch.setenv("OPENAPI_RO_API_KEY", "test-openapi-key")
    with patch("services.anaf_cui.requests.post", side_effect=failing_post):
        with patch("services.anaf_cui.requests.get", side_effect=get_side_effect) as mock_get:
            result = await check_cui("RO5888716")

    assert result.exists is True
    assert result.checked is True
    assert result.denumire == "DIGI ROMANIA S.A."
    assert result.activ is True
    assert result.platitor_tva is True
    assert result.source == "openapi_ro"
    assert any(
        call.kwargs.get("headers", {}).get("x-api-key") == "test-openapi-key"
        for call in mock_get.call_args_list
    )


@pytest.mark.asyncio
async def test_openapi_ro_fallback_rejects_mismatched_cui(monkeypatch):
    def failing_post(*args, **kwargs):
        import requests
        raise requests.ConnectionError("primary sources timeout")

    def get_side_effect(url, *args, **kwargs):
        import requests

        if "lista-firme.info" in url:
            raise requests.ConnectionError("lista-firme timeout")
        response = MagicMock()
        response.status_code = 200
        response.json.return_value = {
            "cui": "99999999",
            "name": "ALTĂ FIRMĂ S.R.L.",
            "status": {"details": {"description": "funcțiune"}},
        }
        return response

    monkeypatch.setenv("OPENAPI_RO_API_KEY", "test-openapi-key")
    with patch("services.anaf_cui.requests.post", side_effect=failing_post):
        with patch("services.anaf_cui.requests.get", side_effect=get_side_effect):
            result = await check_cui("5888716")

    assert result.exists is False
    assert result.checked is True
    assert result.denumire is None
    assert result.source == "openapi_ro"


@pytest.mark.asyncio
async def test_total_timeout_returns_low_confidence():
    def failing_request(*args, **kwargs):
        import requests
        raise requests.ConnectionError("timeout")

    with patch("services.anaf_cui.requests.post", side_effect=failing_request):
        with patch("services.anaf_cui.requests.get", side_effect=failing_request):
            result = await check_cui("14345906")

    assert result.exists is False
    assert result.checked is False
    assert result.denumire is None
    assert result.activ is False


@pytest.mark.asyncio
async def test_invalid_cui_empty():
    result = await check_cui("")
    assert result.exists is False
    assert result.checked is True


def test_normalize_cui():
    assert _normalize_cui("RO12345678") == "12345678"
    assert _normalize_cui("14345906") == "14345906"
    assert _normalize_cui("") == ""
