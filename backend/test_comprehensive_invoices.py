import pytest
from unittest.mock import patch, AsyncMock

from services.invoice_parser import parse_invoice
from services.iban_validator import validate_iban
from services.invoice_coherence import check_coherence
from services.brand_registry import detect_claimed_brand
from services.invoice_readiness_gate import evaluate_readiness, ReadinessState
from services.invoice_orchestrator import scan_invoice


@pytest.mark.asyncio
async def test_enel_energie():
    text = "ENEL Energie Muntenia SA\nCUI: 14345906\nFactura nr. 12345678\nData: 01.05.2026\nScadenta: 01.06.2026\nSubtotal: 200.00 RON\nTVA 19%: 38.00 RON\nTotal: 238.00 RON\nIBAN: RO33RNCB1234567890123456"
    with patch("services.invoice_orchestrator.check_cui", new_callable=AsyncMock) as mock_cui:
        mock_cui.return_value.exists = True
        mock_cui.return_value.activ = True
        result = await scan_invoice(text)
    assert result.fields.cui == "14345906"
    assert result.readiness.state == ReadinessState.READY
    assert result.brand == "enel"
    assert result.brand_match.impersonation_risk is False


@pytest.mark.asyncio
async def test_ppc_energie():
    text = "PPC Energie S.A.\nCUI: 22000460\nFactura: PPC-2026-06-001\nData emitere: 01.06.2026\nScadenta: 21.06.2026\nEnergie activa: 180 kWh\nTotal energie: 187.20 RON\nTVA 19%: 35.57 RON\nTotal de plata: 222.77 RON\nIBAN: RO33RNCB1234567890123456"
    with patch("services.invoice_orchestrator.check_cui", new_callable=AsyncMock) as mock_cui:
        mock_cui.return_value.exists = True
        mock_cui.return_value.activ = True
        result = await scan_invoice(text)
    assert result.fields.cui == "22000460"
    assert result.brand == "ppc"


@pytest.mark.asyncio
async def test_electrica_furnizare():
    text = "Electrica Furnizare S.A.\nCUI: 28909028\nFactura seria EF nr. 87654321\nData: 15.05.2026\nScadenta: 05.06.2026\nSubtotal: 145.50 RON\nTVA 19%: 27.65 RON\nTotal: 173.15 RON\nIBAN: RO33RNCB1234567890123456"
    with patch("services.invoice_orchestrator.check_cui", new_callable=AsyncMock) as mock_cui:
        mock_cui.return_value.exists = True
        mock_cui.return_value.activ = True
        result = await scan_invoice(text)
    assert result.fields.cui == "28909028"
    assert result.brand == "electrica"


@pytest.mark.asyncio
async def test_apa_nova():
    text = "Apa Nova Bucuresti S.A.\nCUI: RO12276949\nFactura nr. AN-2026-05-12345\nData: 10.05.2026\nScadenta: 31.05.2026\nConsum apa: 12 mc x 6.49 lei\nTotal apa: 77.88 RON\nTotal canal: 41.04 RON\nTVA 19%: 22.59 RON\nTotal de plata: 141.51 RON\nIBAN: RO33RNCB1234567890123456"
    with patch("services.invoice_orchestrator.check_cui", new_callable=AsyncMock) as mock_cui:
        mock_cui.return_value.exists = True
        mock_cui.return_value.activ = True
        result = await scan_invoice(text)
    assert result.fields.cui == "12276949"
    assert result.brand == "apa_nova"


@pytest.mark.asyncio
async def test_premier_energy():
    text = "Premier Energy Furnizare S.A.\nCUI: 21349608\nFactura seria PE nr. 555666777\nData: 20.05.2026\nScadenta: 10.06.2026\nSubtotal: 250.00 RON\nTVA 19%: 47.50 RON\nTotal: 297.50 RON\nIBAN: RO33RNCB1234567890123456"
    with patch("services.invoice_orchestrator.check_cui", new_callable=AsyncMock) as mock_cui:
        mock_cui.return_value.exists = True
        mock_cui.return_value.activ = True
        result = await scan_invoice(text)
    assert result.fields.cui == "21349608"
    assert result.brand == "premier_energy"


@pytest.mark.asyncio
async def test_engie():
    text = "Furnizor: Engie Romania S.A.\nCUI: 35194668\nFactura nr. EN-98765\nData: 05.05.2026\nScadenta: 25.05.2026\nSubtotal: 320.00 RON\nTVA 19%: 60.80 RON\nTotal: 380.80 RON\nIBAN: RO33RNCB1234567890123456"
    with patch("services.invoice_orchestrator.check_cui", new_callable=AsyncMock) as mock_cui:
        mock_cui.return_value.exists = True
        mock_cui.return_value.activ = True
        result = await scan_invoice(text)
    assert result.fields.cui == "35194668"
    assert result.brand == "engie"


@pytest.mark.asyncio
async def test_vodafone():
    text = "Vodafone Romania S.A.\nCUI: 15049623\nFactura nr. VF-2026-05-001\nData: 01.05.2026\nScadenta: 20.05.2026\nAbonament: 25.00 RON\nTVA 19%: 4.75 RON\nTotal: 29.75 RON\nIBAN: RO33RNCB1234567890123456"
    with patch("services.invoice_orchestrator.check_cui", new_callable=AsyncMock) as mock_cui:
        mock_cui.return_value.exists = True
        mock_cui.return_value.activ = True
        result = await scan_invoice(text)
    assert result.fields.cui == "15049623"
    assert result.brand == "vodafone"


@pytest.mark.asyncio
async def test_orange():
    text = "Orange Romania S.A.\nCUI: 16339980\nFactura seria OR nr. 123456\nData: 15.04.2026\nScadenta: 05.05.2026\nSubtotal: 59.66 RON\nTVA 19%: 11.34 RON\nTotal: 71.00 RON\nIBAN: RO33RNCB1234567890123456"
    with patch("services.invoice_orchestrator.check_cui", new_callable=AsyncMock) as mock_cui:
        mock_cui.return_value.exists = True
        mock_cui.return_value.activ = True
        result = await scan_invoice(text)
    assert result.fields.cui == "16339980"
    assert result.brand == "orange"


@pytest.mark.asyncio
async def test_digi_internet():
    text = "Digi Romania S.A.\nCIF: RO5888716\nFactura seria FDB25 / nr. 39486801\nData: 06.05.2025\nScadenta: 31.05.2025\nSubtotal: 348.59 RON\nTVA 19%: 66.23 RON\nTotal factura curenta: 414.82 RON\nIBAN: RO51INGB0001000000018827"
    with patch("services.invoice_orchestrator.check_cui", new_callable=AsyncMock) as mock_cui:
        mock_cui.return_value.exists = True
        mock_cui.return_value.activ = True
        result = await scan_invoice(text)
    assert result.fields.cui == "5888716"
    assert result.brand == "digi"
    assert result.brand_match.impersonation_risk is False


@pytest.mark.asyncio
async def test_energy_gas():
    text = "SC ENERGY GAS PROVIDER SRL\nCUI RO26741040\nNr. factura: EG-2025-12345\nData emitere: 15.05.2026\nScadenta: 05.06.2026\nSubtotal: 246.50 RON\nTVA 19%: 46.84 RON\nTotal factura curenta: 293.34 RON\nIBAN: RO25RNCB0300134768150001"
    with patch("services.invoice_orchestrator.check_cui", new_callable=AsyncMock) as mock_cui:
        mock_cui.return_value.exists = True
        mock_cui.return_value.activ = True
        result = await scan_invoice(text)
    assert result.fields.cui == "26741040"
    assert result.brand == "energy_gas"


@pytest.mark.asyncio
async def test_cnadnr_rovignieta():
    text = "CNADNR\nCUI: 16054316\nFactura seria RN nr. 999888777\nData: 15.06.2026\nScadenta: 15.07.2026\nRovignieta: 28.00 RON\nTVA 19%: 5.32 RON\nTotal: 33.32 RON\nIBAN: RO29TREZ7005069XXX010604"
    with patch("services.invoice_orchestrator.check_cui", new_callable=AsyncMock) as mock_cui:
        mock_cui.return_value.exists = True
        mock_cui.return_value.activ = True
        result = await scan_invoice(text)
    assert result.fields.cui == "16054316"
    assert result.brand == "cnadnr"
    assert result.brand_match.impersonation_risk is False


@pytest.mark.asyncio
async def test_anaf_phishing_commercial_iban():
    text = "Stimate contribuabil\nANAF\nCUI: 14345906\nAveti o rambursare fiscala disponibila!\nTotal: 2500.00 RON\nIBAN: RO33RNCB1234567890123456"
    with patch("services.invoice_orchestrator.check_cui", new_callable=AsyncMock) as mock_cui:
        mock_cui.return_value.exists = True
        mock_cui.return_value.activ = True
        result = await scan_invoice(text)
    assert result.brand == "anaf"
    assert result.brand_match.impersonation_risk is True


@pytest.mark.asyncio
async def test_eon_electrica_not_confused():
    text = "E.ON Energie Romania S.A.\nCUI: 15877338\nFactura seria EO nr. 111222333\nData: 01.04.2026\nScadenta: 21.04.2026\nEnergie electrica: 250 kWh\nGaze: 800 kWh\nTotal energie: 175.00 RON\nTotal gaze: 280.00 RON\nTVA 19%: 86.45 RON\nTotal de plata: 541.45 RON\nIBAN: RO33RNCB1234567890123456"
    with patch("services.invoice_orchestrator.check_cui", new_callable=AsyncMock) as mock_cui:
        mock_cui.return_value.exists = True
        mock_cui.return_value.activ = True
        result = await scan_invoice(text)
    assert result.brand == "eon"
    assert result.brand_match.impersonation_risk is False


@pytest.mark.asyncio
async def test_impozite_locale_trezorerie():
    text = "Directia de Venituri\nSector 3, Bucuresti\nCUI: 14345906\nFactura seria IV nr. 2026-05-001\nData: 01.05.2026\nScadenta: 31.05.2026\nImpozit cladire: 850.00 RON\nTotal: 850.00 RON\nIBAN: RO29TREZ7005069XXX010604"
    with patch("services.invoice_orchestrator.check_cui", new_callable=AsyncMock) as mock_cui:
        mock_cui.return_value.exists = True
        mock_cui.return_value.activ = True
        result = await scan_invoice(text)
    assert result.brand in ("impozite", "anaf")


@pytest.mark.asyncio
async def test_missing_cui_and_iban():
    text = "Total: 100 RON\nData: 01.01.2026"
    with patch("services.invoice_orchestrator.check_cui", new_callable=AsyncMock) as mock_cui:
        mock_cui.return_value.exists = False
        result = await scan_invoice(text)
    assert result.fields.cui is None
    assert result.fields.iban is None
    assert result.fields.total == 100.0
    assert result.readiness.state == ReadinessState.MISSING


def test_tva_9_percent():
    fields = parse_invoice("Furnizor: SC Test SRL\nCUI: 12345678\nFactura nr. INV-001\nData: 01.05.2026\nScadenta: 01.06.2026\nSubtotal: 1000.00 RON\nTVA 9%: 90.00 RON\nTotal: 1090.00 RON\nIBAN: RO33RNCB1234567890123456")
    assert fields.total == 1090.0
    assert fields.tva == 90.0
    assert fields.subtotal == 1000.0
    coh = check_coherence(fields.subtotal, fields.tva, fields.total, fields.data_emitere, fields.scadenta)
    assert coh.tva_rate_plausible is True


def test_tva_5_percent():
    fields = parse_invoice("Furnizor: SC Casa SRL\nCUI: 87654321\nFactura nr. INV-002\nData: 01.05.2026\nScadenta: 01.06.2026\nSubtotal: 5000.00 RON\nTVA 5%: 250.00 RON\nTotal: 5250.00 RON\nIBAN: RO33RNCB1234567890123456")
    coh = check_coherence(fields.subtotal, fields.tva, fields.total, fields.data_emitere, fields.scadenta)
    assert coh.tva_rate_plausible is True


def test_tva_19_monetary_amount():
    fields = parse_invoice("Furnizor: SC Test SRL\nCUI: 12345678\nFactura nr. 001\nData: 01.05.2026\nScadenta: 01.06.2026\nSubtotal: 189.10 RON\nTVA 19%: 35.93 RON\nTotal: 225.03 RON\nIBAN: RO33RNCB1234567890123456")
    assert fields.tva == 35.93
    assert fields.total == 225.03


def test_electrica_furnizare_cui_28909028_detected():
    brand = detect_claimed_brand(None, "Electrica Furnizare S.A.\nCUI: 28909028", [])
    assert brand == "electrica"


def test_ppc_cui_22000460_detected():
    brand = detect_claimed_brand(None, "PPC Energie S.A.\nCUI: 22000460", [])
    assert brand == "ppc"


def test_apa_nova_detected():
    brand = detect_claimed_brand(None, "Apa Nova Bucuresti S.A.\nCUI: RO12276949", [])
    assert brand == "apa_nova"


def test_premier_energy_detected():
    brand = detect_claimed_brand(None, "Premier Energy Furnizare S.A.\nCUI: 21349608", [])
    assert brand == "premier_energy"


def test_emitent_extracted_from_label():
    fields = parse_invoice("Furnizor: SC Test SRL\nCUI: 12345678\nTotal: 100 RON")
    assert fields.emitent == "SC Test SRL"


def test_emitent_fallback_first_company_line():
    fields = parse_invoice("ENEL Energie SA\nCUI: 14345906\nTotal: 225 RON")
    assert fields.emitent == "ENEL Energie SA"


def test_nr_factura_digi_format():
    fields = parse_invoice("Factura seria FDB25 / nr. 39486801\nTotal: 100 RON")
    assert fields.nr_factura == "39486801"


def test_nr_factura_seria_nr():
    fields = parse_invoice("Seria ABC Nr. 999\nTotal: 100 RON")
    assert fields.nr_factura == "999"


def test_nr_factura_classic():
    fields = parse_invoice("Factura nr. INV-001\nTotal: 100 RON")
    assert fields.nr_factura == "INV-001"


def test_nr_factura_numar():
    fields = parse_invoice("Număr factură: 12345\nTotal: 100 RON")
    assert fields.nr_factura == "12345"


def test_readiness_low_confidence_no_total():
    fields = parse_invoice("CUI: 12345678\nIBAN: RO33RNCB1234567890123456\nData: 01.05.2026")
    gate = evaluate_readiness(fields)
    assert gate.state.value == "analysis_allowed_but_low_confidence"
