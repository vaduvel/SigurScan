"""Close the SANB user-assist loop.

Today the app PROMPTS the user to verify the beneficiary name in their bank app
(VERIFY_BENEFICIARY_IN_BANK), but the user's answer is never consumed. This wires
the answer back into the verdict — the free Verification-of-Payee substitute:

  - no_match            -> destination MISMATCH -> hard conflict -> DANGEROUS
  - match / close_match -> destination BANK_MATCH (SAFE-eligible)
  - not_shown / None    -> unchanged (stays SUSPECT/verify)

Anti-poisoning: a single user "match" cannot reach SAFE on its own — the Safe
Eligibility Gate still requires issuer + obligation confirmed.
"""

import pytest

from services.anaf_cui import CuiResult
from services.invoice_orchestrator import evaluate_invoice_verdict, scan_invoice
from services.invoice_truth_v4 import _payment_destination_state


INVOICE_TEXT = """
Factura MGH 0013
Furnizor: MARKETING GROWTH HUB S.R.L.
CIF: 45758405
IBAN (RON): RO42INGB0000999912242622
Total plata 200.00 RON
"""


def _cui(name: str) -> CuiResult:
    return CuiResult(exists=True, checked=True, denumire=name, activ=True,
                     data_inactivare=None, platitor_tva=False, enrolled_efactura=False, raw=None)


# ── unit: SANB attestation maps to destination state ─────────────────────────

def test_no_match_maps_to_mismatch():
    assert _payment_destination_state({}, {}, sanb_attestation="no_match") == "MISMATCH"


def test_match_maps_to_bank_match():
    assert _payment_destination_state({}, {}, sanb_attestation="match") == "BANK_MATCH"


def test_close_match_maps_to_bank_match():
    assert _payment_destination_state({}, {}, sanb_attestation="close_match") == "BANK_MATCH"


def test_not_shown_does_not_force_a_match():
    # falls through to the normal unconfirmed logic, never BANK_MATCH
    assert _payment_destination_state({}, {}, sanb_attestation="not_shown") != "BANK_MATCH"


def test_official_mismatch_still_wins_over_user_match():
    # a hard official-document contradiction cannot be overridden by a user "match"
    state = _payment_destination_state({}, {"status": "mismatch"}, sanb_attestation="match")
    assert state == "MISMATCH"


# ── integration: user's answer flips the verdict ─────────────────────────────

@pytest.mark.asyncio
async def test_sanb_no_match_flips_unconfirmed_invoice_to_dangerous(monkeypatch):
    async def fake_check_cui(cui):
        return _cui("MARKETING GROWTH HUB S.R.L.")
    monkeypatch.setattr("services.invoice_orchestrator.check_cui", fake_check_cui)

    result = await scan_invoice(INVOICE_TEXT)
    base = evaluate_invoice_verdict(result, result.raw_text, source_channel="android_native")
    assert base["invoice_truth"]["verdict"] == "VERIFY_BEFORE_PAYING"

    with_no_match = evaluate_invoice_verdict(
        result, result.raw_text, source_channel="android_native", sanb_attestation="no_match"
    )
    assert with_no_match["invoice_truth"]["verdict"] == "NU_PLATI"
    assert with_no_match["gate"]["label"] == "DANGEROUS"


@pytest.mark.asyncio
async def test_sanb_match_alone_without_issuer_obligation_stays_verify(monkeypatch):
    # offline: issuer/obligation not confirmed -> a single user "match" must NOT auto-SAFE
    async def fake_check_cui(cui):
        return CuiResult(exists=False, checked=False, denumire=None, activ=False,
                         data_inactivare=None, platitor_tva=False, enrolled_efactura=False, raw=None)
    monkeypatch.setattr("services.invoice_orchestrator.check_cui", fake_check_cui)

    result = await scan_invoice(INVOICE_TEXT)
    out = evaluate_invoice_verdict(
        result, result.raw_text, source_channel="android_native", sanb_attestation="match"
    )
    assert out["gate"]["label"] != "SAFE"
    assert out["invoice_truth"]["verdict"] != "DATE_CONFIRMATE"


@pytest.mark.asyncio
async def test_sanb_not_shown_keeps_verify(monkeypatch):
    async def fake_check_cui(cui):
        return _cui("MARKETING GROWTH HUB S.R.L.")
    monkeypatch.setattr("services.invoice_orchestrator.check_cui", fake_check_cui)

    result = await scan_invoice(INVOICE_TEXT)
    out = evaluate_invoice_verdict(
        result, result.raw_text, source_channel="android_native", sanb_attestation="not_shown"
    )
    assert out["invoice_truth"]["verdict"] == "VERIFY_BEFORE_PAYING"
