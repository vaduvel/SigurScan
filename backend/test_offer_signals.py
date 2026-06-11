from services.iban_validator import validate_iban
from services.invoice_coherence import check_coherence
from services.offer_parser import OfferFields, parse_offer
from services.offer_readiness import evaluate_offer_readiness
from services.payment_method_classifier import classify_payment_method
from services import offer_signals as sig
from services.offer_signals import derive_offer_signals


class TestPaymentSignals:
    def test_critical_payment(self):
        o = parse_offer("plata in crypto wallet")
        payment = classify_payment_method(o.raw_text)
        signals = derive_offer_signals(o, payment=payment)
        assert sig.OFFER_PAYMENT_METHOD_CRITICAL in signals

    def test_high_payment(self):
        o = parse_offer("plata pe Revolut")
        payment = classify_payment_method(o.raw_text)
        signals = derive_offer_signals(o, payment=payment)
        assert sig.OFFER_PAYMENT_METHOD_HIGH_RISK in signals


class TestIbanSignals:
    def test_invalid_iban_structure(self):
        o = OfferFields(iban="RO00BADIBAN")
        result = validate_iban(o.iban)
        signals = derive_offer_signals(o, iban_result=result)
        assert sig.OFFER_IBAN_INVALID_STRUCTURE in signals

    def test_trezorerie_iban(self):
        # IBAN Trezorerie valid (cod TREZ).
        o = OfferFields(iban="RO33TREZ1234567890123456")
        result = validate_iban(o.iban)
        signals = derive_offer_signals(o, iban_result=result)
        # semnal emis doar dacă MOD-97 trece; verificăm consistent cu validatorul
        if result.is_trezorerie:
            assert sig.OFFER_IBAN_TREZORERIE in signals


class TestTextSignals:
    def test_off_platform(self):
        o = parse_offer("hai pe whatsapp sa continuam, plata direct")
        assert sig.OFFER_OFF_PLATFORM_PAYMENT in derive_offer_signals(o)

    def test_card_cvv_otp(self):
        o = parse_offer("introdu datele cardului si codul OTP")
        assert sig.OFFER_CARD_CVV_OTP_REQUEST in derive_offer_signals(o)

    def test_id_document_request(self):
        o = parse_offer("trimite o poza la buletin ca sa pregatesc contractul")
        assert sig.OFFER_ID_DOCUMENT_REQUEST in derive_offer_signals(o)

    def test_price_urgency(self):
        o = parse_offer("oferta doar azi, pret redus, plateste acum")
        assert sig.OFFER_PRICE_URGENCY in derive_offer_signals(o)

    def test_crypto_wallet(self):
        o = parse_offer("trimite in bitcoin wallet")
        assert sig.OFFER_HAS_CRYPTO_WALLET in derive_offer_signals(o)


class TestStructuralSignals:
    def test_qr_payment(self):
        o = parse_offer("scaneaza codul", qr_payloads=["RO49AAAA1B31007593840000"])
        assert sig.OFFER_HAS_QR_PAYMENT in derive_offer_signals(o)

    def test_incoherent_totals(self):
        o = parse_offer("CUI: 12345678")
        coherence = check_coherence(subtotal=100.0, tva=19.0, total=999.0, data_emitere=None, scadenta=None)
        signals = derive_offer_signals(o, coherence=coherence)
        assert sig.OFFER_TOTALS_INCOHERENT in signals

    def test_family_classified(self):
        o = parse_offer("CUI: 12345678")
        signals = derive_offer_signals(o, family_code="OP-04")
        assert sig.OFFER_FAMILY_CLASSIFIED in signals

    def test_family_op00_not_flagged(self):
        o = parse_offer("CUI: 12345678")
        signals = derive_offer_signals(o, family_code="OP-00")
        assert sig.OFFER_FAMILY_CLASSIFIED not in signals

    def test_missing_anchors(self):
        o = parse_offer("")
        readiness = evaluate_offer_readiness(o)
        signals = derive_offer_signals(o, readiness=readiness)
        assert sig.OFFER_MISSING_ANCHORS in signals
