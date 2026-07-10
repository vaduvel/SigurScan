"""INVOICE_CARD_SETTLEMENT_PROOF flag (default OFF) — cherry-pick from #110.

A card-settled receipt ("Tip plata: card", "platit cu cardul") has no due date
and is not an outstanding obligation, so two proofs relax when the flag is ON:
- readiness: missing `scadenta` no longer counts against `has_dates`;
- truth v4: obligation_state promotes to CONFIRMED, but ONLY as the last lock —
  issuer AND payment destination must already be independently confirmed,
  because the settlement evidence is printed text and trivially forgeable.

Risk direction is toward SAFE, so the flag ships OFF until measured on the real
invoice corpus (same policy as INVOICE_ZONE_CUI).

Also pins the 2026-07-10 verification of the stale "bank mismatch doesn't block
SAFE" finding: it IS blocked on main (F2), and these tests keep it that way —
the refactor-lineage tree silently lacked the guard, so pin it against drift.
"""

from types import SimpleNamespace

import pytest

from services.invoice_parser import InvoiceFields
from services.invoice_readiness_gate import evaluate_readiness
from services.invoice_truth_v4 import _verify_truth_blocks_safe, evaluate_invoice_truth_v4


CARD_RECEIPT_TEXT = (
    "SC ALTEX ROMANIA SRL\nCUI RO6318970\nNumar factura:\nALX-2026-0099\n"
    "Data emiterii: 12.05.2026\nTotal:\n1.260,50\nTip plata: card\n"
)


def _fields(raw_text: str = CARD_RECEIPT_TEXT) -> InvoiceFields:
    return InvoiceFields(
        emitent="SC ALTEX ROMANIA SRL",
        cui="6318970",
        nr_factura="ALX-2026-0099",
        data_emitere="12.05.2026",
        scadenta=None,
        total=1260.50,
        iban="RO49AAAA1B31007593840000",
        raw_text=raw_text,
    )


def _result(fields: InvoiceFields, *, sanb: str | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        fields=fields,
        anaf_cui_check={"checked": True, "exists": True, "activ": True},
        iban_valid=SimpleNamespace(valid_structure=True),
        coherence=SimpleNamespace(all_ok=True),
        readiness=None,
        payment_destination={},
        official_document_check={},
        beneficiary_name_check=None,
        brand_match=None,
        fraud_flags=[],
        sanb_attestation=sanb,
    )


# ── flag OFF (default): behaviour identical to main ─────────────────────────

def test_flag_off_missing_scadenta_still_counts_against_dates(monkeypatch):
    monkeypatch.delenv("INVOICE_CARD_SETTLEMENT_PROOF", raising=False)
    readiness = evaluate_readiness(_fields())
    assert readiness.state.value == "analysis_allowed_but_low_confidence"
    assert readiness.blocks_safe_verdict is True


def test_flag_off_obligation_not_promoted(monkeypatch):
    monkeypatch.delenv("INVOICE_CARD_SETTLEMENT_PROOF", raising=False)
    truth = evaluate_invoice_truth_v4(_result(_fields(), sanb="match"))
    assert truth["proofs"]["invoice_obligation"]["state"] != "CONFIRMED"
    assert truth["verdict"] != "DATE_CONFIRMATE"


# ── flag ON: settlement relaxes exactly the two proofs, nothing else ────────

def test_flag_on_card_receipt_satisfies_dates(monkeypatch):
    monkeypatch.setenv("INVOICE_CARD_SETTLEMENT_PROOF", "1")
    readiness = evaluate_readiness(_fields())
    assert readiness.state.value == "ready_for_analysis"
    assert readiness.blocks_safe_verdict is False


def test_flag_on_obligation_promotes_only_with_issuer_and_destination(monkeypatch):
    monkeypatch.setenv("INVOICE_CARD_SETTLEMENT_PROOF", "1")
    # issuer CONFIRMED + destination BANK_MATCH (user SANB attestation) -> promote
    truth = evaluate_invoice_truth_v4(_result(_fields(), sanb="match"))
    assert truth["proofs"]["invoice_obligation"]["state"] == "CONFIRMED"


def test_flag_on_no_promotion_without_confirmed_destination(monkeypatch):
    monkeypatch.setenv("INVOICE_CARD_SETTLEMENT_PROOF", "1")
    # destination unconfirmed -> printed "platit cu card" must NOT confirm anything
    truth = evaluate_invoice_truth_v4(_result(_fields()))
    assert truth["proofs"]["invoice_obligation"]["state"] != "CONFIRMED"
    assert truth["verdict"] != "DATE_CONFIRMATE"


def test_flag_on_no_promotion_without_card_evidence(monkeypatch):
    monkeypatch.setenv("INVOICE_CARD_SETTLEMENT_PROOF", "1")
    fields = _fields(raw_text=CARD_RECEIPT_TEXT.replace("Tip plata: card\n", ""))
    truth = evaluate_invoice_truth_v4(_result(fields, sanb="match"))
    assert truth["proofs"]["invoice_obligation"]["state"] != "CONFIRMED"


# ── pinning the verified F2 contract (mismatch/VERIFY never leaks to SAFE) ──

def test_bank_match_with_unmet_safe_requirements_blocks_safe():
    # The exact scenario from the stale audit finding: truth said VERIFY
    # (safe_to_pay False) while the destination validated as BANK_MATCH.
    # _verify_truth_blocks_safe must suppress a SAFE fallback label.
    truth = {
        "safe_to_pay": False,
        "proofs": {
            "issuer_identity": {"state": "CONFIRMED", "source": "anaf"},
            "payment_destination": {"state": "BANK_MATCH"},
        },
    }
    assert _verify_truth_blocks_safe(truth) is True


def test_bank_name_mismatch_keeps_verdict_out_of_confirmed(monkeypatch):
    # End-to-end: printed bank name (BT) contradicting the IBAN bank (BRD=BRDE)
    # must land in VERIFY_BEFORE_PAYING with the mismatch as a recorded reason,
    # never DATE_CONFIRMATE -- even with the card-settlement flag ON and every
    # other proof green (worst case for a SAFE leak). Guards the F2 wiring
    # against refactor-lineage drift.
    monkeypatch.setenv("SIGURSCAN_ENABLE_BANK_NAME_CROSSCHECK", "1")
    monkeypatch.setenv("INVOICE_CARD_SETTLEMENT_PROOF", "1")
    fields = _fields()
    fields.printed_bank_name = "Banca Transilvania"
    fields.iban = "RO28BRDE4500000000045000"  # structurally valid, bank=BRD
    truth = evaluate_invoice_truth_v4(_result(fields, sanb="match"))
    assert truth["verdict"] == "VERIFY_BEFORE_PAYING"
    codes = {item["code"] for item in truth.get("unconfirmed_items", [])}
    assert "IBAN_BANK_NAME_MISMATCH" in codes
    assert "IBAN_BANK_NAME_MISMATCH" in set(truth.get("fraud_flags") or [])
