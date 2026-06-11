import pytest

from services.invoice_parser import InvoiceFields, parse_invoice
from services.invoice_readiness_gate import evaluate_readiness, ReadinessState


def test_ready_when_all_fields_present():
    fields = parse_invoice("""
        Furnizor: SC TEST SRL
        CUI: RO12345678
        Factura nr: INV-001
        Data: 01.05.2026
        Scadenta: 01.06.2026
        Total: 119,00 RON
        TVA: 19,00 RON
        Subtotal: 100,00 RON
        IBAN: RO66RNCB1234567890123456
    """)
    gate = evaluate_readiness(fields)
    assert gate.state == ReadinessState.READY
    assert gate.blocks_safe_verdict is False
    assert gate.can_be_safe() is True


def test_missing_when_no_cui_and_no_iban():
    fields = parse_invoice("Total plata: 100 RON")
    gate = evaluate_readiness(fields)
    assert gate.state == ReadinessState.MISSING
    assert gate.blocks_safe_verdict is True
    assert gate.can_be_safe() is False


def test_low_confidence_when_only_iban():
    fields = InvoiceFields(iban="RO33RNCB1234567890123456")
    gate = evaluate_readiness(fields)
    assert gate.state == ReadinessState.LOW_CONFIDENCE
    assert gate.blocks_safe_verdict is True


def test_low_confidence_when_ocr_confidence_low():
    fields = parse_invoice("CUI: 12345678 IBAN: RO66RNCB1234567890123456")
    gate = evaluate_readiness(fields, ocr_confidence=0.3)
    assert gate.state == ReadinessState.LOW_CONFIDENCE
    assert gate.blocks_safe_verdict is True
    assert gate.verdict_minimum() == "suspect"


def test_low_confidence_when_no_total():
    fields = parse_invoice("""
        CUI: RO12345678
        IBAN: RO66RNCB1234567890123456
        Data: 01.05.2026
    """)
    gate = evaluate_readiness(fields)
    assert gate.state == ReadinessState.LOW_CONFIDENCE
    assert gate.blocks_safe_verdict is True


def test_low_confidence_when_no_dates():
    fields = InvoiceFields(cui="12345678", iban="RO66RNCB1234567890123456", total=100.0)
    gate = evaluate_readiness(fields)
    assert gate.state == ReadinessState.LOW_CONFIDENCE
    assert gate.blocks_safe_verdict is True


def test_ready_with_cui_and_iban_minimal():
    fields = InvoiceFields(
        cui="12345678",
        iban="RO66RNCB1234567890123456",
        total=100.0,
        data_emitere="2026-05-01",
        scadenta="2026-06-01",
    )
    gate = evaluate_readiness(fields)
    assert gate.state == ReadinessState.READY
    assert gate.can_be_safe() is True


def test_ready_verdict_minimum():
    fields = InvoiceFields(cui="12345678", iban="RO66RNCB1234567890123456", total=100.0, data_emitere="2026-05-01", scadenta="2026-06-01")
    gate = evaluate_readiness(fields)
    assert gate.verdict_minimum() == "any"


def test_ready_for_international_saas_invoice_without_cui_or_iban():
    fields = parse_invoice("""
        Invoice
        Invoice number Q4HWLGHJ-0001
        Date of issue March 1, 2026
        Date due March 1, 2026
        Anthropic, PBC
        support@anthropic.com
        Subtotal €18.00
        Tax (21% on €18.00) €3.78
        Total €21.78
        Amount due €21.78
    """)
    gate = evaluate_readiness(fields)
    assert gate.state == ReadinessState.READY
    assert gate.blocks_safe_verdict is False
    assert gate.can_be_safe() is True


def test_low_confidence_for_international_invoice_missing_invoice_number():
    fields = parse_invoice("""
        Invoice
        Date of issue March 1, 2026
        Date due March 1, 2026
        Anthropic, PBC
        Total €21.78
    """)
    gate = evaluate_readiness(fields)
    assert gate.state == ReadinessState.LOW_CONFIDENCE
    assert gate.blocks_safe_verdict is True
    assert any(item.id == "missing-international-fields" for item in gate.items)
