"""Regression guard for the Altex/Media Galaxy false-positive.

A real, legitimate retail invoice (Altex Romania SRL, phone purchase) was flagged
PERICULOS 90/100 by three compounding backend bugs:

  1. The orchestrator recomputed fields.all_ibans with require_valid=False, so an OCR
     artifact — the client code "CL006876853MARKETINGGROWTHHUBSRL" — was treated as a
     foreign (Chile) IBAN even though the parser's mod-97 check had rejected it.
  2. FRAGMENTED_IBAN_PAYMENT_TARGET fired on that garbage token.
   3. The Altex payment-destination seed carried a divergent CUI (13831166 vs real 2864518),
     and match_payment_destination collapsed a genuine brand match into brand_matches=False
     on any CUI mismatch -> PRIMARY_PAYMENT_DESTINATION_BELONGS_ELSEWHERE (hard conflict).
     The seed CUI has since been corrected (PR #113), so cui_matches is now True.

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
# Real Altex CUI from the photographed invoice + brand_registry; the seed previously
# had a divergent value (13831166) which poisoned the match. Corrected in PR #113.
_ALTEX_REAL_CUI = "2864518"


def test_official_destination_brand_match_with_corrected_cui():
    """After the seed CUI fix (13831166 → 2864518), a T1 official destination whose
    brand_id matches the claim AND the CUI now matches. Exact match → auto-safe OK."""
    match = match_payment_destination(
        "RO53 BRDE 450S V017 9738 4500",
        claimed_brand="altex",
        cui=_ALTEX_REAL_CUI,
    )
    assert match["matched"] is True
    assert match["brand_matches"] is True
    assert match["cui_matches"] is True
    # Seed CUI corrected => exact match, auto-safe possible.
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


def test_official_destination_divergent_cui_blocks_auto_safe():
    """Safety guard, independent of seed data: when the destination brand_id matches
    the claim but the supplied CUI DIVERGES from the registry entry, the match must
    NOT auto-contribute to SAFE. Preserves the coverage previously provided (as a side
    effect) by the now-corrected Altex seed bug, using an explicit synthetic divergent
    CUI so it no longer depends on wrong data being present."""
    divergent_cui = "99999999"  # deliberately != Altex real CUI 2864518
    assert divergent_cui != _ALTEX_REAL_CUI
    match = match_payment_destination(
        "RO53 BRDE 450S V017 9738 4500",
        claimed_brand="altex",
        cui=divergent_cui,
    )
    assert match["matched"] is True
    assert match["brand_matches"] is True
    # Divergent CUI must be detected and must block auto-safe.
    assert match["cui_matches"] is False
    assert match["can_contribute_to_safe"] is False
