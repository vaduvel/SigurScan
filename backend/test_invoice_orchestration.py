import pytest
from unittest.mock import patch, AsyncMock

from services.invoice_orchestrator import scan_invoice
from services.invoice_readiness_gate import ReadinessState


@pytest.mark.asyncio
async def test_scan_basic_enel_invoice():
    text = "Furnizor: ENEL ENERGIE SA\nCUI: RO14345906\nIBAN: RO33RNCB1234567890123456\n" \
           "Total: 245.50 RON\nData: 01.06.2026\nScadenta: 15.06.2026"
    with patch("services.invoice_orchestrator.check_cui", new_callable=AsyncMock) as mock_cui:
        mock_cui.return_value.exists = True
        mock_cui.return_value.denumire = "ENEL ENERGIE SA"
        mock_cui.return_value.activ = True
        mock_cui.return_value.platitor_tva = True
        mock_cui.return_value.data_inactivare = None

        result = await scan_invoice(text)

    assert result.fields.cui == "14345906"
    assert result.fields.iban == "RO33RNCB1234567890123456"
    assert result.fields.emitent == "ENEL ENERGIE SA"
    assert result.fields.total == 245.50
    assert result.readiness.state == ReadinessState.READY
    assert result.readiness.blocks_safe_verdict is False
    assert len(result.warnings) == 0


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
