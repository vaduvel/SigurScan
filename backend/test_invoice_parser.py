import pytest

from services.invoice_parser import parse_invoice, _normalize_cui, _parse_ro_amount


class TestNormalizeCui:
    def test_strips_ro_prefix(self):
        assert _normalize_cui("RO12345678") == "12345678"

    def test_strips_ro_with_space(self):
        assert _normalize_cui("RO 12345678") == "12345678"

    def test_already_digits(self):
        assert _normalize_cui("12345678") == "12345678"

    def test_removes_letters(self):
        assert _normalize_cui("RO12A345") == "12345"


class TestParseRoAmount:
    def test_comma_decimal(self):
        assert _parse_ro_amount("119,99") == 119.99

    def test_dot_thousands_comma_decimal(self):
        assert _parse_ro_amount("1.234,56") == 1234.56

    def test_dot_decimal(self):
        assert _parse_ro_amount("119.99") == 119.99

    def test_no_decimals(self):
        assert _parse_ro_amount("119") == 119.0

    def test_with_currency(self):
        assert _parse_ro_amount("119,99 RON") == 119.99

    def test_empty(self):
        assert _parse_ro_amount("") is None

    def test_invalid(self):
        assert _parse_ro_amount("abc") is None


class TestParseInvoice:
    def test_basic_invoice(self):
        text = """
        Furnizor: SC TEST SRL
        CUI: RO12345678
        Factura nr: INV-001
        Data: 01.05.2026
        Scadenta: 01.06.2026
        Total: 119,00 RON
        TVA: 19,00 RON
        Subtotal: 100,00 RON
        IBAN: RO33RNCB1234567890123456
        """
        result = parse_invoice(text)
        assert result.emitent == "SC TEST SRL"
        assert result.cui == "12345678"
        assert result.nr_factura == "INV-001"
        assert result.data_emitere == "2026-05-01"
        assert result.scadenta == "2026-06-01"
        assert result.total == 119.0
        assert result.tva == 19.0
        assert result.subtotal == 100.0
        assert result.iban == "RO33RNCB1234567890123456"

    def test_enel_invoice(self):
        text = """
        Furnizor: ENEL ENERGIE SA
        CUI: 24387371
        Factura: EF-2026-05-001
        Data factura: 15.05.2026
        Scadenta: 15.06.2026
        Total plata: 245,80 lei
        TVA: 39,25 lei
        Valoare: 206,55 lei
        IBAN: RO57BTRL1234567890123456
        """
        result = parse_invoice(text)
        assert result.cui == "24387371"
        assert result.total == 245.80
        assert result.tva == 39.25
        assert result.subtotal == 206.55
        assert result.scadenta == "2026-06-15"

    def test_no_cui(self):
        text = "Total: 100 RON"
        result = parse_invoice(text)
        assert result.cui is None
        assert result.total == 100.0

    def test_no_iban(self):
        text = "CUI: 12345678 Total: 100 RON"
        result = parse_invoice(text)
        assert result.cui == "12345678"
        assert result.iban is None

    def test_empty_text(self):
        result = parse_invoice("")
        assert result.cui is None
        assert result.iban is None
        assert result.raw_text == ""

    def test_with_links(self):
        text = "CUI: 12345678 Total: 100 RON"
        result = parse_invoice(text, pdf_links=["https://enel.ro/factura"], qr_payloads=["https://platibancar.ro"])
        assert result.links == ["https://enel.ro/factura"]
        assert result.qr_payloads == ["https://platibancar.ro"]

    def test_anaf_impersonation_text(self):
        text = """
        Ministerul Finantelor - ANAF
        Amenzi si penalitati
        CUI: 12345678
        Total: 500 RON
        IBAN: RO33RNCB1234567890123456
        """
        result = parse_invoice(text)
        assert result.cui == "12345678"
        assert result.iban == "RO33RNCB1234567890123456"

    def test_google_vision_split_cif_and_ocr_ro_iban(self):
        text = """
        Furnizor:
        MARKETING GROWTH HUB S.R.L.
        Reg. com.:
        CIF:
        45758405
        IBAN (RON):
        R042INGB0000999912242622
        Banca:
        ING BANK NV
        Total plata
        200.00 RON
        CNP: -
        """
        result = parse_invoice(text)
        assert result.emitent == "MARKETING GROWTH HUB S.R.L."
        assert result.cui == "45758405"
        assert result.iban == "RO42INGB0000999912242622"
        assert result.all_ibans == ["RO42INGB0000999912242622"]

    def test_emitent_fallback_first_line(self):
        result = parse_invoice("ENEL Energie SA\nCUI: 14345906\nTotal: 100 RON")
        assert result.emitent == "ENEL Energie SA"

    def test_emitent_fallback_skips_date(self):
        result = parse_invoice("15.05.2026\nENEL Energie\nCUI: 14345906\nTotal: 100 RON")
        assert result.emitent == "ENEL Energie"

    def test_nr_factura_seria_slash_nr(self):
        result = parse_invoice("Factura seria FDB25 / nr. 39486801\nTotal: 100 RON")
        assert result.nr_factura == "39486801"

    def test_nr_factura_seria_nr(self):
        result = parse_invoice("Seria ABC Nr. 999\nTotal: 100 RON")
        assert result.nr_factura == "999"

    def test_anthropic_saas_invoice_without_ro_cui_or_iban(self):
        text = """
        Invoice
        Invoice number Q4HWLGHJ-0001
        Date of issue March 1, 2026
        Date due March 1, 2026

        Anthropic, PBC
        548 Market Street
        San Francisco, California 94104
        support@anthropic.com

        €21.78 due March 1, 2026
        Pay online

        Description Qty Unit price Tax Amount
        Claude Pro 1 €18.00 21% €18.00
        Subtotal €18.00
        Tax (21% on €18.00) €3.78
        Total €21.78
        Amount due €21.78
        """
        result = parse_invoice(text)
        assert result.emitent == "Anthropic, PBC"
        assert result.nr_factura == "Q4HWLGHJ-0001"
        assert result.data_emitere == "2026-03-01"
        assert result.scadenta == "2026-03-01"
        assert result.subtotal == 18.0
        assert result.tva == 3.78
        assert result.total == 21.78
        assert result.currency == "EUR"
        assert result.invoice_profile == "international"
        assert result.cui is None
        assert result.iban is None

    def test_anthropic_pdf_text_layout_with_labels_and_values_on_separate_lines(self):
        text = """
        Invoice
        Invoice number Q4HWLGHJ-0001
        Date of issue
        March 1, 2026
        Date due
        March 1, 2026
        Anthropic, PBC
        548 Market Street
        PMB 90375
        United States
        support@anthropic.com

        €21.78 due March 1, 2026
        Pay online

        Description
        Claude Pro
        Qty
        Unit price
        Tax
        Amount
        1
        €18.00
        21%
        €18.00
        Subtotal
        €18.00
        Total excluding tax
        €18.00
        Tax (21% on €18.00)
        €3.78
        Total
        €21.78
        Amount due
        €21.78
        """
        result = parse_invoice(text)
        assert result.emitent == "Anthropic, PBC"
        assert result.nr_factura == "Q4HWLGHJ-0001"
        assert result.data_emitere == "2026-03-01"
        assert result.scadenta == "2026-03-01"
        assert result.subtotal == 18.0
        assert result.tva == 3.78
        assert result.total == 21.78
        assert result.currency == "EUR"
        assert result.invoice_profile == "international"

    def test_anthropic_ocr_layout_with_summary_labels_separated_from_values(self):
        text = """
        Invoice
        Invoice number Q4HWLGHJ-0001
        Date of issue
        March 1, 2026
        Date due
        March 1, 2026
        Anthropic, PBC
        548 Market Street
        PMB 90375
        San Francisco, California 94104
        United States
        support@anthropic.com
        €21.78 due March 1, 2026
        Pay online
        Bill to
        Customer Organization
        Description
        Claude Pro
        Mar 1-Apr 1, 2026
        Subtotal
        Total excluding tax
        Tax (21% on €18.00)
        Total
        Amount due
        Al
        Qty
        Unit price
        Tax
        Amount
        1
        €18.00
        21%
        €18.00
        €18.00
        €18.00
        €3.78
        €21.78
        €21.78
        Page 1 of 1
        """
        result = parse_invoice(text)
        assert result.emitent == "Anthropic, PBC"
        assert result.nr_factura == "Q4HWLGHJ-0001"
        assert result.data_emitere == "2026-03-01"
        assert result.scadenta == "2026-03-01"
        assert result.subtotal == 18.0
        assert result.tva == 3.78
        assert result.total == 21.78
        assert result.currency == "EUR"
        assert result.invoice_profile == "international"

    def test_openai_saas_invoice_with_usd_dates_and_payment_link(self):
        text = """
        Invoice
        Invoice no. INV-OPENAI-2026-0042
        Issued on April 6, 2026
        Due date May 6, 2026
        OpenAI, L.L.C.
        support@openai.com
        Pay online: https://pay.openai.com/invoice/INV-OPENAI-2026-0042
        Subtotal $20.00
        Tax $0.00
        Total due $20.00
        """
        result = parse_invoice(text, pdf_links=["https://pay.openai.com/invoice/INV-OPENAI-2026-0042"])
        assert result.emitent == "OpenAI, L.L.C."
        assert result.nr_factura == "INV-OPENAI-2026-0042"
        assert result.data_emitere == "2026-04-06"
        assert result.scadenta == "2026-05-06"
        assert result.subtotal == 20.0
        assert result.tva == 0.0
        assert result.total == 20.0
        assert result.currency == "USD"
        assert result.invoice_profile == "international"
