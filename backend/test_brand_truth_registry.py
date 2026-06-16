import pytest

from services.brand_truth_registry import BrandTruthRegistry, DATA_DIR
import os


BTR_PATH = os.path.join(DATA_DIR, "brand_truth_registry_v1.json")


@pytest.fixture
def btr():
    return BrandTruthRegistry(BTR_PATH)


class TestLoadAndVersion:
    def test_loads_all_manifests(self, btr):
        assert len(btr.all()) >= 29

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
    def test_active_romania_research_expands_brands_without_quarantine_people(self, btr):
        assert len(btr.brands()) >= 29
        assert len(btr.persons()) == 1

    def test_person_is_isarescu(self, btr):
        isarescu = btr.get("isarescu")
        assert isarescu is not None
        assert isarescu.type == "person"
        assert "Isărescu" in isarescu.display_name

    def test_key_brands_present(self, btr):
        expected = {"bnr", "anaf", "dnsc", "politia_mai", "olx", "emag",
                    "fan_courier", "sameday", "cargus", "posta_romana",
                    "bt", "bcr", "brd", "ing", "raiffeisen", "unicredit",
                    "revolut_ro", "garanti", "dpd_romania", "gls_romania",
                    "electrica_ppc", "orange_vodafone_digi", "orange",
                    "vodafone", "digi", "yoxo", "wipo"}
        found = {m.manifest_id for m in btr.brands()}
        assert expected.issubset(found)
        assert "alpha_bank_legacy" not in found
        assert "otp_bank_legacy" not in found
        assert "ion_tiriac" not in found


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

    def test_match_yoxo_domains(self, btr):
        assert btr.match_brand_by_domain("www.yoxo.ro").manifest_id == "yoxo"
        assert btr.match_brand_by_domain("reconditionate.yoxo.ro").manifest_id == "yoxo"

    def test_match_wipo_official_domain(self, btr):
        assert btr.match_brand_by_domain("www.wipo.int").manifest_id == "wipo"

    def test_match_new_bank_and_courier_domains_from_official_research(self, btr):
        assert btr.match_brand_by_domain("www.brd.ro").manifest_id == "brd"
        assert btr.match_brand_by_domain("www.unicredit.ro").manifest_id == "unicredit"
        assert btr.match_brand_by_domain("www.dpd.com").manifest_id == "dpd_romania"
        assert btr.match_brand_by_domain("gls-group.eu").manifest_id == "gls_romania"


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

    def test_match_yoxo_by_name(self, btr):
        m = btr.match_brand_by_name("YOXO")
        assert m is not None
        assert m.manifest_id == "yoxo"


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

    def test_yoxo_official_website_match(self, btr):
        result = btr.provenance_check(
            claimed_brand="YOXO",
            observed_channel="official_website",
            observed_domain="yoxo.ro",
            observed_phone_e164=None,
            sensitive_asks=[],
            payment_method=None,
            final_url="https://www.yoxo.ro/",
        )
        assert result.manifest_id == "yoxo"
        assert result.provenance == "match"
        assert result.official_match is True
        assert result.max_effect == "can_raise_safe"

    def test_yoxo_web_channel_alias_matches_official_website(self, btr):
        result = btr.provenance_check(
            claimed_brand="YOXO",
            observed_channel="web",
            observed_domain="yoxo.ro",
            observed_phone_e164=None,
            sensitive_asks=[],
            payment_method=None,
            final_url="https://www.yoxo.ro/",
        )
        assert result.manifest_id == "yoxo"
        assert result.provenance == "match"
        assert result.official_match is True
        assert result.max_effect == "can_raise_safe"

    def test_phone_channel_can_match_official_phone(self, tmp_path):
        path = tmp_path / "btr_phone.json"
        path.write_text(
            """
            {
              "btr_version": "btr-test",
              "generated_at": "2026-06-16T00:00:00Z",
              "manifests": [
                {
                  "manifest_id": "test_bank",
                  "type": "brand",
                  "display_name": "Test Bank",
                  "category": "bank",
                  "country": "RO",
                  "official_domains": ["testbank.ro"],
                  "official_phones_e164": ["+40211234567"],
                  "official_channels": ["phone"],
                  "never_asks": ["otp"],
                  "source_kind": "public_self_asserted",
                  "source_refs": [],
                  "confidence": "high",
                  "review_status": "active"
                }
              ]
            }
            """,
            encoding="utf-8",
        )
        reg = BrandTruthRegistry(str(path))

        result = reg.provenance_check(
            claimed_brand="Test Bank",
            observed_channel="phone",
            observed_domain=None,
            observed_phone_e164="021 123 4567",
            sensitive_asks=[],
            payment_method=None,
            final_url=None,
        )

        assert result.provenance == "partial"
        assert result.official_match is False
        assert "BTR_PHONE_MATCH" in result.reason_codes
        assert "BTR_PHONE_MATCH_SPOOFABLE" in result.reason_codes

    def test_sms_channel_can_match_official_shortcode(self, tmp_path):
        path = tmp_path / "btr_shortcode.json"
        path.write_text(
            """
            {
              "btr_version": "btr-test",
              "generated_at": "2026-06-16T00:00:00Z",
              "manifests": [
                {
                  "manifest_id": "test_telco",
                  "type": "brand",
                  "display_name": "Test Telco",
                  "category": "telecom",
                  "country": "RO",
                  "official_domains": ["telco.test"],
                  "official_shortcodes": ["1872"],
                  "official_channels": ["sms"],
                  "never_asks": ["card_number"],
                  "source_kind": "public_self_asserted",
                  "source_refs": [],
                  "confidence": "high",
                  "review_status": "active"
                }
              ]
            }
            """,
            encoding="utf-8",
        )
        reg = BrandTruthRegistry(str(path))

        result = reg.provenance_check(
            claimed_brand="Test Telco",
            observed_channel="sms",
            observed_domain=None,
            observed_phone_e164=None,
            observed_shortcode="1872",
            sensitive_asks=[],
            payment_method=None,
            final_url=None,
        )

        assert result.provenance == "match"
        assert result.official_match is True
        assert "BTR_SHORTCODE_MATCH" in result.reason_codes

    def test_scoped_sms_shortcode_does_not_raise_safe_generically(self, btr):
        result = btr.provenance_check(
            claimed_brand="BCR",
            observed_channel="sms",
            observed_domain=None,
            observed_phone_e164=None,
            observed_shortcode="3761",
            sensitive_asks=[],
            payment_method=None,
            final_url=None,
        )

        assert result.manifest_id == "bcr"
        assert result.provenance == "partial"
        assert result.official_match is False
        assert "BTR_SHORTCODE_MATCH" in result.reason_codes
        assert "BTR_SHORTCODE_MATCH_SCOPED" in result.reason_codes

    def test_brd_fake_domain_with_card_data_is_decisive(self, btr):
        result = btr.provenance_check(
            claimed_brand="BRD",
            observed_channel="sms",
            observed_domain="brd-secure-card.example",
            observed_phone_e164=None,
            sensitive_asks=["card_number", "cvv"],
            payment_method="card_form",
            final_url="https://brd-secure-card.example/confirmare",
        )

        assert result.manifest_id == "brd"
        assert result.provenance == "mismatch"
        assert result.evidence_power == "decisive"
        assert "card_number" in result.violated_never_asks
        assert "cvv" in result.violated_never_asks

    def test_wipo_lookalike_domain_is_not_official(self, btr):
        result = btr.provenance_check(
            claimed_brand="WIPO",
            observed_channel="web",
            observed_domain="wipo-office.com",
            observed_phone_e164=None,
            sensitive_asks=[],
            payment_method=None,
            final_url="https://wipo-office.com/payment",
        )

        assert result.manifest_id == "wipo"
        assert result.official_match is False
        assert result.identity_status == "claimed_brand_official_mismatch"
        assert "BTR_DOMAIN_MISMATCH" in result.reason_codes

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
