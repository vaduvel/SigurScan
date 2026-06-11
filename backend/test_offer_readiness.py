from services.invoice_readiness_gate import ReadinessState
from services.offer_parser import OfferFields, parse_offer
from services.offer_readiness import evaluate_offer_readiness


class TestReadyStates:
    def test_full_offer_ready(self):
        o = parse_offer(
            "Furnizor: SC X SRL\nCUI: 12345678\nTotal: 100 RON\nIBAN: RO33RNCB1234567890123456"
        )
        result = evaluate_offer_readiness(o)
        assert result.state == ReadinessState.READY
        assert result.blocks_safe_verdict is False

    def test_pf_rent_without_cui_or_total_can_be_ready(self):
        # Chirie de la persoană fizică: fără CUI/total, dar cu emitent + IBAN + beneficiar.
        o = OfferFields(
            emitent="Maria Ionescu",
            issuer_name="Maria Ionescu",
            iban="RO33RNCB1234567890123456",
            payment_beneficiary="Maria Ionescu",
            total=1500.0,
        )
        o.extraction_confidence = 0.8
        result = evaluate_offer_readiness(o)
        assert result.state == ReadinessState.READY


class TestMissing:
    def test_empty_offer_missing(self):
        o = parse_offer("")
        result = evaluate_offer_readiness(o)
        assert result.state == ReadinessState.MISSING
        assert result.blocks_safe_verdict is True


class TestLowConfidence:
    def test_low_confidence_blocks(self):
        o = OfferFields(iban="RO33RNCB1234567890123456")
        result = evaluate_offer_readiness(o, ocr_confidence=0.3)
        assert result.state == ReadinessState.LOW_CONFIDENCE
        assert result.blocks_safe_verdict is True

    def test_threshold_is_0_6(self):
        o = OfferFields(emitent="SC X", iban="RO33RNCB1234567890123456")
        assert evaluate_offer_readiness(o, ocr_confidence=0.59).state == ReadinessState.LOW_CONFIDENCE
        assert evaluate_offer_readiness(o, ocr_confidence=0.6).state == ReadinessState.READY

    def test_reuses_readiness_state_enum(self):
        o = parse_offer("CUI: 12345678\nIBAN: RO33RNCB1234567890123456")
        result = evaluate_offer_readiness(o, ocr_confidence=0.9)
        assert isinstance(result.state, ReadinessState)
        assert result.verdict_minimum() in ("any", "suspect")
