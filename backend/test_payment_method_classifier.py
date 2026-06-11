from services.payment_method_classifier import (
    PaymentRisk,
    classify_payment_method,
)


class TestCritical:
    def test_western_union(self):
        assert classify_payment_method("Plateste prin Western Union").risk == PaymentRisk.CRITICAL

    def test_moneygram(self):
        assert classify_payment_method("trimite banii pe MoneyGram").risk == PaymentRisk.CRITICAL

    def test_gift_card(self):
        assert classify_payment_method("plata cu gift card iTunes").risk == PaymentRisk.CRITICAL

    def test_crypto(self):
        assert classify_payment_method("transfer in crypto wallet USDT").risk == PaymentRisk.CRITICAL

    def test_cvv_otp_to_receive_money(self):
        c = classify_payment_method("introdu CVV ca sa primesti banii")
        assert c.risk == PaymentRisk.CRITICAL


class TestHigh:
    def test_revolut(self):
        assert classify_payment_method("plata pe Revolut @maria").risk == PaymentRisk.HIGH

    def test_avans_inainte_de_vizionare(self):
        c = classify_payment_method("plateste avans inainte de vizionare")
        assert c.risk == PaymentRisk.HIGH

    def test_person_beneficiary_for_company(self):
        c = classify_payment_method(
            "transfer bancar",
            beneficiary_is_person=True,
            issuer_claims_company=True,
        )
        assert c.risk == PaymentRisk.HIGH


class TestMedium:
    def test_bank_transfer(self):
        assert classify_payment_method("plata prin transfer bancar in cont").risk == PaymentRisk.MEDIUM

    def test_cash_on_delivery(self):
        assert classify_payment_method("plata la livrare, ramburs").risk == PaymentRisk.MEDIUM


class TestLow:
    def test_official_card(self):
        assert classify_payment_method("plata cu cardul pe platforma cu 3D Secure").risk == PaymentRisk.LOW

    def test_empty_defaults_low(self):
        assert classify_payment_method("").risk == PaymentRisk.LOW

    def test_trezorerie_stays_low(self):
        c = classify_payment_method("plata taxa", iban_is_trezorerie=True)
        assert c.risk == PaymentRisk.LOW
        assert c.method == "trezorerie"


class TestHighestRiskWins:
    def test_transfer_and_crypto_is_critical(self):
        c = classify_payment_method("transfer bancar sau in crypto wallet")
        assert c.risk == PaymentRisk.CRITICAL

    def test_reasons_collected(self):
        c = classify_payment_method("Western Union sau gift card")
        assert len(c.reasons) >= 2
