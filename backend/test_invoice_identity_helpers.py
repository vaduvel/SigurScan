"""R6 — the extracted invoice identity helpers, and the re-export contract that
keeps the extraction behavior-preserving."""

from services import invoice_identity_helpers as H

_REEXPORTED = [
    "_txt_norm",
    "_name_tokens",
    "_beneficiary_is_person",
    "_beneficiary_is_company",
    "_beneficiary_mismatch",
    "_beneficiary_company_mismatch",
    "_payment_destination_confirms_current_invoice",
    "_anaf_identity_matches_invoice",
]


def test_invoice_orchestrator_reexports_every_moved_helper():
    # External `from services.invoice_orchestrator import <name>` must keep working.
    from services import invoice_orchestrator as io

    for name in _REEXPORTED:
        assert getattr(io, name) is getattr(H, name), name


def test_beneficiary_predicates():
    assert H._beneficiary_is_person("Ion Popescu")
    assert not H._beneficiary_is_person("ALFA SRL")
    assert H._beneficiary_is_company("ALFA SRL")
    assert not H._beneficiary_is_company("Ion Popescu")


def test_beneficiary_company_mismatch():
    assert H._beneficiary_company_mismatch("ALFA SRL", "BETA SRL")
    assert not H._beneficiary_company_mismatch("ALFA SRL", "ALFA SRL")
    assert not H._beneficiary_company_mismatch("Ion Popescu", "BETA SRL")  # not a company


def test_anaf_identity_and_payment_destination():
    assert H._anaf_identity_matches_invoice(
        {"checked": True, "exists": True, "activ": True, "denumire": "ALFA SRL"}, "ALFA SRL"
    )
    assert not H._anaf_identity_matches_invoice(
        {"checked": True, "exists": True, "activ": False, "denumire": "ALFA SRL"}, "ALFA SRL"
    )
    assert H._payment_destination_confirms_current_invoice(
        {"matched": True, "can_contribute_to_safe": True, "cui_matches": True}
    )
    assert not H._payment_destination_confirms_current_invoice({"matched": False})
