"""OCR layout hardening for the invoice parser (surgical cherry-pick from #110).

#110 ("mark real Altex card-paid invoice safe") is a stale branch that cannot be
re-merged wholesale (its base predates F2/R1/R3 on main). These are the two
parser-level fixes worth carrying, plus one bug found during verification:

1. Bare-amount lookahead: OCR often emits "Total:" with the value on the NEXT
   line and WITHOUT a currency suffix (the Altex receipt layout). Main's
   lookahead only accepted currency-suffixed values, so the total came back
   None -> LOW_CONFIDENCE -> INSUFFICIENT_DATA for a perfectly readable doc.
2. Invoice-number label-alone-on-a-line: value on one of the following lines.
3. NEW (found by execution, worse than the #110 finding): on COLUMN layouts
   ("Numar factura    Data emiterii" / values on the next row) the same-line
   regex crossed the newline via `\\s` and captured the next LABEL word --
   nr_factura='Data', silent corrupt data. The digit-guard rejects it: a missing
   field triggers LOW_CONFIDENCE honestly; a garbage field poisons coherence.
"""

from services.invoice_parser import (
    _extract_bare_amount_values,
    _extract_invoice_number,
    parse_invoice,
)


# ── 1. bare-amount next-line (Altex total) ──────────────────────────────────

def test_total_label_with_bare_value_on_next_line():
    text = "SC ALTEX ROMANIA SRL\nCUI RO6318970\nTotal:\n1.260,50\nTip plata: card"
    fields = parse_invoice(text)
    assert fields.total == 1260.50


def test_bare_amount_helper_accepts_standalone_number_only():
    assert _extract_bare_amount_values("1.260,50") == [1260.50]
    assert _extract_bare_amount_values("  119.99  ") == [119.99]
    # A table row with trailing words is NOT a bare amount (quantities must not
    # become money outside label-lookahead mode).
    assert _extract_bare_amount_values("2 buc x 500") == []
    assert _extract_bare_amount_values("") == []


def test_total_with_currency_next_line_still_works():
    # Control: the pre-existing currency-suffixed lookahead is untouched.
    text = "Total de plata:\n1.500,00 RON"
    fields = parse_invoice(text)
    assert fields.total == 1500.00


# ── 2. invoice number: label alone on its line, value below ─────────────────

def test_invoice_number_label_alone_value_on_next_line():
    text = "Furnizor: Test SRL\nNumar factura:\nFCT-2024-0154\nData emiterii: 12.05.2026"
    assert _extract_invoice_number(text) == "FCT-2024-0154"


def test_invoice_number_same_line_still_works():
    assert _extract_invoice_number("Factura nr: FCT-2024-0154 din 12.05.2026") == "FCT-2024-0154"


# ── 3. digit-guard: column layouts must not capture label words ─────────────

def test_column_layout_does_not_capture_next_label_as_number():
    # Before the guard this returned 'Data' (the neighbouring column header):
    # `\s` in the same-line patterns crosses newlines. None is the honest
    # answer -- readiness flags the missing field instead of trusting garbage.
    text = "Numar factura    Data emiterii\nFCT-2024-0154    12.05.2026"
    result = _extract_invoice_number(text)
    assert result != "Data"
    assert result is None


def test_digit_guard_keeps_numeric_only_invoice_numbers():
    assert _extract_invoice_number("Factura nr: 2026") == "2026"


# ── 4. invoice number: label variants and heading-style identifiers ────────

def test_invoice_number_serie_slash_numar_same_line():
    text = "FACTURA\nSerie / numar TEST-0001\nData emiterii: 12.05.2026"
    assert _extract_invoice_number(text) == "TEST-0001"


def test_invoice_number_heading_with_series_and_number():
    text = "FACTURA MGH 0013\nData facturii: 12.05.2026\nTotal: 119,00 RON"
    assert _extract_invoice_number(text) == "MGH 0013"


def test_invoice_number_after_plain_factura_label():
    assert _extract_invoice_number("Factura: EF-2026-05-001\nTotal: 119 RON") == "EF-2026-05-001"


def test_invoice_number_after_inflected_number_label():
    assert _extract_invoice_number("Nr. facturii: ABC/2026/42\nTotal: 119 RON") == "ABC/2026/42"


def test_invoice_heading_description_is_not_an_invoice_number():
    assert _extract_invoice_number("Factura fiscala\nData 12.05.2026") is None
    assert _extract_invoice_number("Factura restanta 30 zile\nTotal 100 RON") is None


# ── 5. amount labels: table headers must not become subtotals ──────────────

def test_bare_valoare_table_header_does_not_capture_quantity_as_subtotal():
    text = (
        "Denumire articol\n"
        "Valoare\n"
        "Cant.\n"
        "1\n"
        "Total de plata:\n"
        "119,00 RON"
    )
    fields = parse_invoice(text)
    assert fields.subtotal is None
    assert fields.total == 119.0


def test_qualified_net_value_label_remains_a_subtotal():
    fields = parse_invoice(
        "Valoare fara TVA: 100,00 RON\n"
        "TVA: 19,00 RON\n"
        "Total de plata: 119,00 RON"
    )
    assert fields.subtotal == 100.0
    assert fields.tva == 19.0
    assert fields.total == 119.0


def test_vat_value_label_is_tax_not_subtotal():
    fields = parse_invoice("Valoare TVA: 19,00 RON\nTotal de plata: 119,00 RON")
    assert fields.subtotal is None
    assert fields.tva == 19.0
    assert fields.total == 119.0
