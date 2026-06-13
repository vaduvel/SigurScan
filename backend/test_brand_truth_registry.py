import pytest

from services.brand_truth_registry import BrandTruthRegistry, DATA_DIR
import os


BTR_PATH = os.path.join(DATA_DIR, "brand_truth_registry_v1.json")


@pytest.fixture
def btr():
    return BrandTruthRegistry(BTR_PATH)


class TestLoadAndVersion:
    def test_loads_all_manifests(self, btr):
        assert len(btr.all()) == 16

    def test_version_format(self, btr):
        assert btr.version.startswith("btr-ro-")
        assert len(btr.version) > 10

    def test_generated_at_not_empty(self, btr):
        assert btr.generated_at

    def test_all_brands_have_source_kind(self, btr):
        for m in btr.all():
            assert m.source_kind, f"{m.manifest_id} missing source_kind"

    def test_all_brands_have_confidence(self, btr):
        for m in btr.all():
            assert m.confidence, f"{m.manifest_id} missing confidence"

    def test_confidence_values_valid(self, btr):
        valid = {"high", "medium", "needs_confirmation"}
        for m in btr.all():
            assert m.confidence in valid, f"{m.manifest_id} confidence={m.confidence}"

    def test_source_kind_values_valid(self, btr):
        valid = {"partner_signed", "public_self_asserted", "official_registry", "press_context", "community_noisy"}
        for m in btr.all():
            assert m.source_kind in valid, f"{m.manifest_id} source_kind={m.source_kind}"

    def test_all_have_review_status(self, btr):
        for m in btr.all():
            assert m.review_status == "active"


class TestBrandCount:
    def test_15_brands_plus_1_person(self, btr):
        assert len(btr.brands()) == 15
        assert len(btr.persons()) == 1

    def test_person_is_isarescu(self, btr):
        isarescu = btr.get("isarescu")
        assert isarescu is not None
        assert isarescu.type == "person"
        assert "Isărescu" in isarescu.display_name

    def test_key_brands_present(self, btr):
        expected = {"bnr", "anaf", "dnsc", "politia_mai", "olx", "emag",
                    "fan_courier", "sameday", "cargus", "posta_romana",
                    "bt", "bcr", "ing", "electrica_ppc", "orange_vodafone_digi"}
        found = {m.manifest_id for m in btr.brands()}
        assert found == expected


class TestMatchByDomain:
    def test_match_fan_courier(self, btr):
        m = btr.match_brand_by_domain("fancourier.ro")
        assert m is not None
        assert m.manifest_id == "fan_courier"

    def test_match_fan_courier_subdomain(self, btr):
        m = btr.match_brand_by_domain("tracking.fancourier.ro")
        assert m is not None
        assert m.manifest_id == "fan_courier"

    def test_match_sameday_whitelist(self, btr):
        m = btr.match_brand_by_domain("sameday.ro")
        assert m is not None
        assert m.manifest_id == "sameday"

    def test_match_sdy_ro(self, btr):
        m = btr.match_brand_by_domain("sdy.ro")
        assert m is not None
        assert m.manifest_id == "sameday"

    def test_match_bnr(self, btr):
        m = btr.match_brand_by_domain("bnr.ro")
        assert m is not None
        assert m.manifest_id == "bnr"

    def test_match_olx(self, btr):
        m = btr.match_brand_by_domain("olx.ro")
        assert m is not None
        assert m.manifest_id == "olx"

    def test_no_match_for_unknown_domain(self, btr):
        m = btr.match_brand_by_domain("scam-site-123.xyz")
        assert m is None


class TestMatchByName:
    def test_match_bnr_by_name(self, btr):
        m = btr.match_brand_by_name("Banca Națională a României")
        assert m is not None
        assert m.manifest_id == "bnr"

    def test_match_fan_courier_by_name(self, btr):
        m = btr.match_brand_by_name("FAN Courier")
        assert m is not None
        assert m.manifest_id == "fan_courier"

    def test_match_olx_by_short_name(self, btr):
        m = btr.match_brand_by_name("OLX")
        assert m is not None
        assert m.manifest_id == "olx"

    def test_no_match_for_random_name(self, btr):
        m = btr.match_brand_by_name("Companie Inventata SRL")
        assert m is None


class TestProvenanceCheck:
    def test_fan_courier_official_domain_no_sensitive(self, btr):
        result = btr.provenance_check(
            claimed_brand="FAN Courier",
            observed_channel="sms",
            observed_domain="fancourier.ro",
            observed_phone_e164=None,
            sensitive_asks=[],
            payment_method=None,
            final_url="https://fancourier.ro/tracking",
        )
        assert result.provenance == "partial"
        assert result.official_match is False
        assert result.max_effect == "can_raise_suspect"
        assert result.manifest_id == "fan_courier"

    def test_fan_courier_official_domain_official_channel(self, btr):
        result = btr.provenance_check(
            claimed_brand="FAN Courier",
            observed_channel="official_website",
            observed_domain="fancourier.ro",
            observed_phone_e164=None,
            sensitive_asks=[],
            payment_method=None,
            final_url="https://fancourier.ro/tracking",
        )
        assert result.provenance == "match"
        assert result.official_match is True
        assert result.max_effect == "can_raise_safe"

    def test_fan_courier_fake_domain_with_card(self, btr):
        result = btr.provenance_check(
            claimed_brand="FAN Courier",
            observed_channel="sms",
            observed_domain="fan-livrare-fake.xyz",
            observed_phone_e164=None,
            sensitive_asks=["card_number", "cvv"],
            payment_method="card_form",
            final_url="https://fan-livrare-fake.xyz/pay",
        )
        assert result.provenance == "mismatch"
        assert result.official_match is False
        assert "card_number" in result.violated_never_asks
        assert "cvv" in result.violated_never_asks
        assert result.evidence_power == "decisive"
        assert result.max_effect == "can_raise_dangerous_with_combo"
        assert "BTR_DOMAIN_MISMATCH" in result.reason_codes
        assert "BTR_NEVER_ASK_CARD_NUMBER_VIOLATED" in result.reason_codes
        assert "BTR_NEVER_ASK_CVV_VIOLATED" in result.reason_codes

    def test_olx_card_for_receive_money(self, btr):
        result = btr.provenance_check(
            claimed_brand="OLX",
            observed_channel="whatsapp",
            observed_domain=None,
            observed_phone_e164=None,
            sensitive_asks=["card_number", "advance_payment_for_receive_money"],
            payment_method="card_form",
            final_url="https://bit.ly/olx-pay",
        )
        assert result.provenance == "mismatch"
        assert "card_number" in result.violated_never_asks
        assert result.max_effect == "can_raise_dangerous_with_combo"

    def test_isarescu_deepfake_investment(self, btr):
        result = btr.provenance_check(
            claimed_brand=None,
            observed_channel="meta_ads",
            observed_domain="romania-investition.info",
            observed_phone_e164=None,
            sensitive_asks=[],
            payment_method=None,
            final_url="https://romania-investition.info/depozit",
        )
        assert result.provenance == "unknown"
        assert result.identity_status == "no_manifest_match"
        assert result.max_effect == "none"

    def test_isarescu_violated_never_does(self, btr):
        isarescu = btr.get("isarescu")
        assert "investment_endorsement" in isarescu.never_does
        assert "investment_recommendation" in isarescu.never_does
        assert "crypto_promotion" in isarescu.never_does

    def test_no_claimed_brand_returns_unknown(self, btr):
        result = btr.provenance_check(
            claimed_brand=None,
            observed_channel="sms",
            observed_domain=None,
            observed_phone_e164=None,
            sensitive_asks=[],
            payment_method=None,
            final_url=None,
        )
        assert result.provenance == "unknown"
        assert result.manifest_id is None

    def test_bnr_never_asks_includes_transfer_safe_account(self, btr):
        bnr = btr.get("bnr")
        assert bnr is not None
        assert "transfer_safe_account" in bnr.never_asks

    def test_politia_mai_never_does_request_money_transfer(self, btr):
        p = btr.get("politia_mai")
        assert p is not None
        assert "request_money_transfer" in p.never_does

    def test_get_returns_none_for_missing(self, btr):
        assert btr.get("nonexistent_brand") is None

    def test_all_brands_have_never_asks(self, btr):
        for m in btr.brands():
            assert m.never_asks, f"{m.manifest_id} has empty never_asks"

    def test_all_banks_have_never_does(self, btr):
        bank_ids = {"bt", "bcr", "ing"}
        for bid in bank_ids:
            m = btr.get(bid)
            assert m is not None
            assert m.never_does, f"{bid} missing never_does"
