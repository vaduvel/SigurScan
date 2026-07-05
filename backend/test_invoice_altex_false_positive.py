"""Regression guard for the Altex/Media Galaxy false-positive.

A real, legitimate retail invoice (Altex Romania SRL, phone purchase) was flagged
PERICULOS 90/100 by three compounding backend bugs:

  1. The orchestrator recomputed fields.all_ibans with require_valid=False, so an OCR
     artifact — the client code "CL006876853MARKETINGGROWTHHUBSRL" — was treated as a
     foreign (Chile) IBAN even though the parser's mod-97 check had rejected it.
  2. FRAGMENTED_IBAN_PAYMENT_TARGET fired on that garbage token.
  3. The Altex payment-destination seed carries a divergent CUI, and
     match_payment_destination collapsed a genuine brand match into brand_matches=False
     on any CUI mismatch -> PRIMARY_PAYMENT_DESTINATION_BELONGS_ELSEWHERE (hard conflict).

These tests pin the fixed behaviour.
"""

import pytest
from unittest.mock import AsyncMock, patch

from services.anaf_cui import CuiResult
from services.invoice_orchestrator import evaluate_invoice_verdict, scan_invoice
from services.payment_destination_registry import match_payment_destination


def _cui_ok(denumire: str = "ALTEX ROMANIA SRL") -> CuiResult:
    return CuiResult(
        exists=True, checked=True, denumire=denumire, activ=True,
        data_inactivare=None, platitor_tva=True, enrolled_efactura=True,
        raw=None, source="test",
    )


@pytest.fixture(autouse=True)
def _clean_invoice_state(monkeypatch):
    monkeypatch.setenv("INVOICE_CACHE_HMAC_KEY", "testkey")
    from services import invoice_orchestrator as io

    io._verdict_cache.clear()
    io._cui_cache.clear()
    try:
        from services import vendor_memory as vm

        vm._memory.clear()
    except Exception:
        pass
    yield
    io._verdict_cache.clear()
    io._cui_cache.clear()


# Altex's real BRD official destination (T1_PUBLIC_OFFICIAL, can_contribute_to_safe).
_ALTEX_BRD_IBAN = "RO53BRDE450SV01797384500"
# Real Altex CUI from the photographed invoice + brand_registry.
_ALTEX_REAL_CUI = "2864518"


def test_official_destination_brand_and_cui_match_can_contribute_to_safe():
    """The T1 official Altex BRD destination must match the photographed invoice's
    real CUI, so it can contribute to SAFE when the rest of the proof graph closes."""
    match = match_payment_destination(
        "RO53 BRDE 450S V017 9738 4500",
        claimed_brand="altex",
        cui=_ALTEX_REAL_CUI,
    )
    assert match["matched"] is True
    assert match["brand_matches"] is True
    assert match["cui_matches"] is True
    assert match["can_contribute_to_safe"] is True


@pytest.mark.asyncio
async def test_client_code_is_not_parsed_as_iban():
    """The client code line must not survive as an IBAN in fields.all_ibans."""
    text = (
        "ALTEX ROMANIA SRL\n"
        "Cod fiscal: RO2864518\n"
        "Cont IBAN: RO53BRDE450SV01797384500\n"
        "Client: CL006876853MARKETINGGROWTHHUBSRL\n"
        "Total: 520.65 RON\n"
    )
    with patch("services.invoice_orchestrator.check_cui", new_callable=AsyncMock) as mock_cui:
        mock_cui.return_value = _cui_ok()
        result = await scan_invoice(text)

    assert _ALTEX_BRD_IBAN in (result.fields.all_ibans or [])
    assert not any("MARKETINGGROWTHHUBSRL" in iban for iban in (result.fields.all_ibans or []))
    assert not any(iban.startswith("CL") for iban in (result.fields.all_ibans or []))
    assert "FRAGMENTED_IBAN_PAYMENT_TARGET" not in result.fraud_flags


@pytest.mark.asyncio
async def test_altex_real_invoice_not_dangerous():
    """End-to-end on the real photographed invoice: BRD + Trezorerie IBANs + client
    code. Two legitimate accounts make MULTIPLE_IBANS fire, but it must not escalate
    to DANGEROUS / belongs-elsewhere."""
    text = (
        "ALTEX ROMANIA SRL   MEDIA GALAXY\n"
        "Cod fiscal: RO2864518\n"
        "Cont IBAN: RO53BRDE450SV01797384500\n"
        "Banca: BRD Romania\n"
        "Cont IBAN 2: RO67TREZ7005069XXX008077\n"
        "Banca 2: Trezoreria Bucuresti\n"
        "Client: CL006876853 MARKETING GROWTH HUB SRL\n"
        "FACTURA F314027126-08562\n"
        "Data factura: 03/07/2026\n"
        "Telefon Galaxy A16, 4GB, 128GB\n"
        "Total: 630.00 RON\n"
        "TVA 21%: 109.34 RON\n"
    )
    with patch("services.invoice_orchestrator.check_cui", new_callable=AsyncMock) as mock_cui:
        mock_cui.return_value = _cui_ok()
        result = await scan_invoice(text)

    verdict = evaluate_invoice_verdict(result, result.raw_text, source_channel="android_native")

    # Both real IBANs survive validation; the client code does not.
    assert "RO53BRDE450SV01797384500" in (result.fields.all_ibans or [])
    assert "RO67TREZ7005069XXX008077" in (result.fields.all_ibans or [])
    assert not any("MARKETINGGROWTHHUBSRL" in iban for iban in (result.fields.all_ibans or []))
    # Two legitimate accounts -> MULTIPLE_IBANS fires, but on its own it must not escalate.
    assert "MULTIPLE_IBANS" in result.fraud_flags
    assert result.brand == "altex"
    assert "PAYMENT_DESTINATION_BRAND_MISMATCH" not in result.fraud_flags
    assert verdict["gate"]["label"] != "DANGEROUS"


@pytest.mark.asyncio
async def test_altex_retail_card_paid_invoice_is_safe_when_core_proofs_close():
    """A retail invoice already paid by card is not a pending bank transfer.

    If issuer identity, document coherence, and the printed official IBAN all
    verify, the user-facing verdict should be SAFE/Date confirmate, not a SANB
    prompt about an already-settled card payment.
    """
    text = (
        "ALTEX ROMANIA SRL\n"
        "Cod fiscal: RO2864518\n"
        "Cont IBAN: RO53BRDE450SV01797384500\n"
        "Cont IBAN 2: RO67TREZ7005069XXX008077\n"
        "FACTURA\n"
        "Serie şi nr.:\n"
        "F314027126-08562\n"
        "Dată factură: 03/07/2026\n"
        "TELEFON GALAXY A16, 4GB, 128GB, BLACK\n"
        "Tip plată: Cards Sibs ING Bank VISA\n"
        "Total:\n"
        "520.65\n"
    )
    with patch("services.invoice_orchestrator.check_cui", new_callable=AsyncMock) as mock_cui:
        mock_cui.return_value = _cui_ok()
        result = await scan_invoice(text)

    verdict = evaluate_invoice_verdict(result, result.raw_text, source_channel="android_native")

    assert result.fields.total == 520.65
    assert result.payment_destination["matched"] is True
    assert result.payment_destination["cui_matches"] is True
    assert result.payment_destination["can_contribute_to_safe"] is True
    assert verdict["invoice_truth"]["verdict"] == "DATE_CONFIRMATE"
    assert verdict["gate"]["label"] == "SAFE"


@pytest.mark.asyncio
async def test_card_paid_phrase_does_not_make_unknown_destination_safe():
    text = (
        "Furnizor: ALTEX ROMANIA SRL\n"
        "Cod fiscal: RO2864518\n"
        "IBAN: RO49AAAA1B31007593840000\n"
        "Factura nr. F-1\n"
        "Data factura: 03/07/2026\n"
        "Tip plata: card VISA\n"
        "Total: 520.65 RON\n"
    )
    with patch("services.invoice_orchestrator.check_cui", new_callable=AsyncMock) as mock_cui:
        mock_cui.return_value = _cui_ok()
        result = await scan_invoice(text)

    verdict = evaluate_invoice_verdict(result, result.raw_text, source_channel="android_native")

    assert result.payment_destination["matched"] is False
    assert verdict["invoice_truth"]["verdict"] != "DATE_CONFIRMATE"
    assert verdict["gate"]["label"] != "SAFE"
