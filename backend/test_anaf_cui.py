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


@pytest.mark.asyncio
async def test_cui_activ():
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = ANAF_ACTIVE_RESPONSE

    with patch("services.anaf_cui.requests.post", return_value=mock_response):
        result = await check_cui("14345906")

    assert result.exists is True
    assert result.denumire == "ENEL ENERGIE SA"
    assert result.activ is True
    assert result.platitor_tva is True
    assert result.enrolled_efactura is True
    assert result.data_inactivare is None


@pytest.mark.asyncio
async def test_cui_inactiv():
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = ANAF_INACTIVE_RESPONSE

    with patch("services.anaf_cui.requests.post", return_value=mock_response):
        result = await check_cui("99999999")

    assert result.exists is True
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
    assert result.denumire == "ENEL ENERGIE SA"
    assert result.activ is True


@pytest.mark.asyncio
async def test_total_timeout_returns_low_confidence():
    def failing_request(*args, **kwargs):
        import requests
        raise requests.ConnectionError("timeout")

    with patch("services.anaf_cui.requests.post", side_effect=failing_request):
        with patch("services.anaf_cui.requests.get", side_effect=failing_request):
            result = await check_cui("14345906")

    assert result.exists is False
    assert result.denumire is None
    assert result.activ is False


@pytest.mark.asyncio
async def test_invalid_cui_empty():
    result = await check_cui("")
    assert result.exists is False


def test_normalize_cui():
    assert _normalize_cui("RO12345678") == "12345678"
    assert _normalize_cui("14345906") == "14345906"
    assert _normalize_cui("") == ""
