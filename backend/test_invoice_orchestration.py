import pytest
from unittest.mock import patch, AsyncMock

from services.invoice_orchestrator import _cache_key, _cui_cache_key, scan_invoice
from services.invoice_parser import InvoiceFields
from services.invoice_readiness_gate import ReadinessState


@pytest.mark.asyncio
async def test_scan_basic_enel_invoice():
    text = "Furnizor: ENEL ENERGIE SA\nCUI: RO24387371\nIBAN: RO33RNCB1234567890123456\n" \
           "Total: 245.50 RON\nData: 01.06.2026\nScadenta: 15.06.2026"
    with patch("services.invoice_orchestrator.check_cui", new_callable=AsyncMock) as mock_cui:
        mock_cui.return_value.exists = True
        mock_cui.return_value.denumire = "ENEL ENERGIE SA"
        mock_cui.return_value.activ = True
        mock_cui.return_value.platitor_tva = True
        mock_cui.return_value.data_inactivare = None

        result = await scan_invoice(text)

    assert result.fields.cui == "24387371"
    assert result.fields.iban == "RO33RNCB1234567890123456"
    assert result.fields.emitent == "ENEL ENERGIE SA"
    assert result.fields.total == 245.50
    assert result.readiness.state == ReadinessState.READY
    assert result.readiness.blocks_safe_verdict is False
    assert result.fraud_flags == []
    assert result.warnings == []


@pytest.mark.asyncio
async def test_scan_missing_cui_and_iban():
    text = "Factura cu TVA\nTotal: 100 RON"
    result = await scan_invoice(text)

    assert result.fields.cui is None
    assert result.fields.iban is None
    assert result.fields.total == 100.0
    assert result.readiness.state == ReadinessState.MISSING
    assert result.readiness.blocks_safe_verdict is True


@pytest.mark.asyncio
async def test_scan_brand_impersonation():
    text = "Furnizor: ANAF\nCUI: 12345678\nIBAN: RO33RNCB1234567890123456\nTotal: 1000 RON"
    with patch("services.invoice_orchestrator.check_cui", new_callable=AsyncMock) as mock_cui:
        mock_cui.return_value.exists = True
        mock_cui.return_value.denumire = "SC FANTASY SRL"
        mock_cui.return_value.activ = True
        mock_cui.return_value.platitor_tva = True
        mock_cui.return_value.data_inactivare = None

        result = await scan_invoice(text, links=["https://anaf.ro"])

    assert "Potential impersonation" in (result.warnings[0] if result.warnings else "")
    assert result.brand is not None
    assert result.brand_match is not None


@pytest.mark.asyncio
async def test_scan_cui_inactive_warning():
    text = "Furnizor: Firma Test SRL\nCUI: 99999999\nIBAN: RO33RNCB1234567890123456"
    with patch("services.invoice_orchestrator.check_cui", new_callable=AsyncMock) as mock_cui:
        mock_cui.return_value.exists = True
        mock_cui.return_value.denumire = "Firma Test SRL"
        mock_cui.return_value.activ = False
        mock_cui.return_value.platitor_tva = False
        mock_cui.return_value.data_inactivare = "2025-01-15"

        result = await scan_invoice(text)

    assert any("inactive" in w.lower() for w in result.warnings)


@pytest.mark.asyncio
async def test_scan_invalid_iban_warning():
    text = "Furnizor: Test SRL\nCUI: 12345678\nIBAN: RO33RNCB1234567890123456\nTotal: 100 RON\nData: 01.06.2026\nScadenta: 15.06.2026"

    with patch("services.invoice_orchestrator.check_cui", new_callable=AsyncMock) as mock_cui:
        mock_cui.return_value.exists = True
        mock_cui.return_value.denumire = "Test SRL"
        mock_cui.return_value.activ = True
        mock_cui.return_value.platitor_tva = True
        mock_cui.return_value.data_inactivare = None

        with patch("services.invoice_orchestrator.validate_iban") as mock_iban:
            mock_iban.return_value.valid_structure = False
            mock_iban.return_value.bank_code = None
            mock_iban.return_value.bank_name = None
            mock_iban.return_value.is_trezorerie = False

            result = await scan_invoice(text)

    assert result.iban_valid is not None
    assert result.iban_valid.valid_structure is False
    assert any("IBAN" in w for w in result.warnings)


@pytest.mark.asyncio
async def test_scan_empty_text():
    result = await scan_invoice("")
    assert result.error is not None
    assert result.readiness.state == ReadinessState.MISSING


@pytest.mark.asyncio
async def test_scan_coherence_warning():
    text = "Furnizor: Test SRL\nCUI: 12345678\nSubtotal: 100 RON\nTVA: 19 RON\nTotal: 100 RON"
    result = await scan_invoice(text)
    assert not result.coherence.totals_match


@pytest.mark.asyncio
async def test_scan_deterministic_repeatable():
    text = "Furnizor: ENEL ENERGIE SA\nCUI: RO24387371\nIBAN: RO33RNCB1234567890123456\n" \
           "Total: 245.50 RON\nData: 01.06.2026\nScadenta: 15.06.2026"
    mock_data = {
        "exists": True, "checked": True, "denumire": "ENEL ENERGIE SA",
        "activ": True, "platitor_tva": True, "data_inactivare": None, "enrolled_efactura": True,
    }
    with patch("services.invoice_orchestrator.check_cui", new_callable=AsyncMock) as mock_cui:
        mock_cui.return_value = type("CuiMock", (), mock_data)()
        result1 = await scan_invoice(text)
        result2 = await scan_invoice(text)

    assert result1.fields.cui == result2.fields.cui == "24387371"
    assert result1.fields.total == result2.fields.total == 245.50
    assert result1.readiness.state == result2.readiness.state
    assert result1.brand == result2.brand == "enel"
    assert result1.brand_match.impersonation_risk == result2.brand_match.impersonation_risk
    assert result1.warnings == result2.warnings


def test_invoice_cache_keys_are_hmac_and_do_not_leak_identifiers(monkeypatch):
    fields = InvoiceFields(
        cui="24387371",
        iban="RO33RNCB1234567890123456",
        total=245.50,
        data_emitere="2026-06-01",
        nr_factura="INV-123",
    )

    monkeypatch.setenv("INVOICE_CACHE_HMAC_KEY", "test-secret-a")
    key_a = _cache_key(fields)
    cui_key_a = _cui_cache_key("24387371")

    monkeypatch.setenv("INVOICE_CACHE_HMAC_KEY", "test-secret-b")
    key_b = _cache_key(fields)
    cui_key_b = _cui_cache_key("24387371")

    assert key_a != key_b
    assert cui_key_a != cui_key_b
    assert len(key_a) == 64
    assert cui_key_a.startswith("cui:")
    assert "24387371" not in key_a
    assert "24387371" not in cui_key_a
    assert "RO33RNCB1234567890123456" not in key_a


def test_invoice_cache_key_requires_env_secret(monkeypatch):
    fields = InvoiceFields(
        cui="24387371",
        iban="RO33RNCB1234567890123456",
        total=245.50,
        data_emitere="2026-06-01",
        nr_factura="INV-123",
    )

    monkeypatch.delenv("INVOICE_CACHE_HMAC_KEY", raising=False)

    with pytest.raises(RuntimeError, match="INVOICE_CACHE_HMAC_KEY"):
        _cache_key(fields)
