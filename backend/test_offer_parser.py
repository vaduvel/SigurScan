from services.invoice_parser import InvoiceFields
from services.offer_parser import OfferFields, parse_offer


class TestOfferFieldsExtendsInvoiceFields:
    def test_is_subclass(self):
        assert issubclass(OfferFields, InvoiceFields)

    def test_has_invoice_fields(self):
        o = OfferFields()
        assert hasattr(o, "emitent")
        assert hasattr(o, "cui")
        assert hasattr(o, "iban")
        assert hasattr(o, "qr_payloads")

    def test_issuer_cui_aliases_cui(self):
        o = OfferFields(cui="12345678")
        assert o.issuer_cui == "12345678"

    def test_issuer_cui_none_when_no_cui(self):
        assert OfferFields().issuer_cui is None


class TestParseOfferReusesInvoiceParser:
    def test_basic_invoice_fields_populated(self):
        text = """
        Furnizor: SC TEST SRL
        CUI: RO12345678
        Total: 119,00 RON
        IBAN: RO33RNCB1234567890123456
        """
        o = parse_offer(text)
        assert isinstance(o, OfferFields)
        assert o.cui == "12345678"
        assert o.total == 119.0
        assert o.iban == "RO33RNCB1234567890123456"
        assert o.issuer_name == "SC TEST SRL"
        assert o.issuer_cui == "12345678"

    def test_default_input_type_is_offer(self):
        assert parse_offer("CUI: 12345678").input_type == "offer"

    def test_input_type_invoice(self):
        assert parse_offer("CUI: 12345678", input_type="invoice").input_type == "invoice"

    def test_threads_links_and_qr(self):
        o = parse_offer(
            "CUI: 12345678",
            links=["https://example.ro/x"],
            qr_payloads=["RO49AAAA1B31007593840000"],
        )
        assert "https://example.ro/x" in o.urls
        assert o.qr_payloads == ["RO49AAAA1B31007593840000"]


class TestOfferEnrichment:
    def test_currency_eur(self):
        assert parse_offer("Pret: 399 euro all inclusive").currency == "EUR"

    def test_currency_defaults_ron(self):
        assert parse_offer("Total: 100 lei").currency == "RON"

    def test_document_type_proforma(self):
        assert parse_offer("Proforma rezervare").document_type == "proforma"

    def test_document_type_contract(self):
        assert parse_offer("Contract de inchiriere").document_type == "contract"

    def test_document_type_ticket(self):
        assert parse_offer("Bilet e-ticket Untold").document_type == "ticket"

    def test_email_domains_extracted(self):
        o = parse_offer("Scrie la rezervari@booking-fake.test pentru confirmare")
        assert "booking-fake.test" in o.email_domains

    def test_beneficiary_extracted(self):
        o = parse_offer("Beneficiar: POPESCU ION\nIBAN: RO33RNCB1234567890123456")
        assert o.payment_beneficiary == "POPESCU ION"

    def test_platform_detected_olx(self):
        assert parse_offer("Anunt pe OLX, pret bun").platform_name == "OLX"

    def test_platform_detected_from_url(self):
        o = parse_offer("Vezi aici", links=["https://booking-secure-verify.test/pay"])
        assert o.platform_name == "Booking"

    def test_vin_extracted(self):
        o = parse_offer("Vand BMW VIN WVWZZZ1KZAW123456 stare buna")
        assert o.vin == "WVWZZZ1KZAW123456"

    def test_license_extracted(self):
        o = parse_offer("Agentie cu licenta de turism nr. 1234/2025")
        assert o.license_number == "1234/2025"


class TestExtractionConfidenceAndMissing:
    def test_confidence_in_range(self):
        o = parse_offer("Furnizor: SC X SRL\nCUI: 12345678\nTotal: 100 RON\nIBAN: RO33RNCB1234567890123456")
        assert 0.0 <= o.extraction_confidence <= 1.0
        assert o.extraction_confidence >= 0.6

    def test_empty_offer_low_confidence(self):
        o = parse_offer("")
        assert o.extraction_confidence == 0.0
        assert "issuer_cui" in o.missing_fields

    def test_missing_total(self):
        o = parse_offer("CUI: 12345678\nIBAN: RO33RNCB1234567890123456")
        assert "total_amount" in o.missing_fields
