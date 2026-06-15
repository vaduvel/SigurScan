import pytest

from services.brand_registry import detect_claimed_brand, match_brand, BRAND_REGISTRY
from services.iban_validator import validate_iban


class TestDetectClaimedBrand:
    def test_detect_enel_from_emitent(self):
        assert detect_claimed_brand("ENEL Energie SA", "factura curent", []) == "enel"

    def test_detect_anaf_from_text(self):
        assert detect_claimed_brand("Ministerul Finantelor", "ANAF notificare", []) == "anaf"

    def test_detect_from_link(self):
        assert detect_claimed_brand(None, "", ["https://www.enel.ro/factura"]) == "enel"

    def test_no_brand_match(self):
        assert detect_claimed_brand("SC Test SRL", "factura servicii", []) is None

    def test_detect_digi(self):
        assert detect_claimed_brand("RCS RDS", "factura internet", []) == "digi"

    def test_eon_not_detected_as_electrica(self):
        assert detect_claimed_brand(None, "E.ON Energie Romania S.A.\nCUI: 22043010\nFactura seria EO nr. 111222333\nEnergie electrica: 250 kWh\nTotal: 541.45 RON", []) == "eon"

    def test_energy_gas_detected(self):
        assert detect_claimed_brand(None, "SC ENERGY GAS PROVIDER SRL\nCUI RO26741040", []) == "energy_gas"

    def test_electrica_detected_from_emitent(self):
        assert detect_claimed_brand("Electrica Furnizare SA", "factura energie", []) == "electrica"

    def test_detect_emag(self):
        assert detect_claimed_brand("Dante International SA", "eMAG factura", []) == "emag"

    def test_detect_altex(self):
        assert detect_claimed_brand("Altex Romania", "factura", []) == "altex"

    def test_detect_dedeman(self):
        assert detect_claimed_brand("Dedeman SRL", "factura materiale", []) == "dedeman"

    def test_detect_fan_courier(self):
        assert detect_claimed_brand("FAN Courier Express", "factura curierat", []) == "fan_courier"

    def test_detect_dpd_romania(self):
        assert detect_claimed_brand("Dynamic Parcel Distribution SA", "DPD Romania factura", []) == "dpd_romania"

    def test_detect_raja(self):
        assert detect_claimed_brand("RAJA SA", "servicii apa canal CUI 1890420", []) == "raja"

    def test_detect_petrom(self):
        assert detect_claimed_brand("OMV Petrom SA", "factura carburanti", []) == "petrom"

    def test_detect_carrefour(self):
        assert detect_claimed_brand(None, "Carrefour Romania\nCUI 11588780\nFactura seria CR", []) == "carrefour"

    def test_detect_kaufland(self):
        assert detect_claimed_brand("Kaufland Romania", "factura cumparaturi", []) == "kaufland"


class TestMatchBrand:
    def test_no_claimed_brand(self):
        result = match_brand("SC Test SRL", "factura", [], "12345678", validate_iban("RO33RNCB1234567890123456"), "RO33RNCB1234567890123456")
        assert result.claimed_brand is None
        assert result.impersonation_risk is False

    def test_enel_matching_domain(self):
        result = match_brand("ENEL Energie", "factura", ["https://www.enel.ro/factura"], "24387371", validate_iban("RO33RNCB1234567890123456"), "RO33RNCB1234567890123456")
        assert result.claimed_brand == "enel"
        assert result.domain_matches is True
        assert result.cui_matches is True
        assert result.impersonation_risk is False

    def test_enel_wrong_domain_impersonation(self):
        result = match_brand("ENEL Energie", "factura", ["https://enel-facturi-usoare.ro/pay"], "14345906", validate_iban("RO33RNCB1234567890123456"), "RO33RNCB1234567890123456")
        assert result.claimed_brand == "enel"
        assert result.domain_matches is False
        assert result.impersonation_risk is True

    def test_anaf_with_commercial_iban(self):
        iban_result = validate_iban("RO33RNCB1234567890123456")
        result = match_brand("ANAF", "amenda", [], "12345678", iban_result, "RO33RNCB1234567890123456")
        assert result.claimed_brand == "anaf"
        assert result.iban_matches is False
        assert result.impersonation_risk is True

    def test_anaf_with_trezorerie_iban(self):
        iban_result = validate_iban("RO40TREZ1234567890123456")
        result = match_brand("ANAF", "amenda", [], "12345678", iban_result, "RO40TREZ1234567890123456")
        assert result.claimed_brand == "anaf"
        assert result.iban_matches is True
        assert result.impersonation_risk is False

    def test_wrong_cui_for_brand(self):
        result = match_brand("ENEL Energie", "factura", ["https://www.enel.ro"], "99999999", validate_iban("RO33RNCB1234567890123456"), "RO33RNCB1234567890123456")
        assert result.claimed_brand == "enel"
        assert result.cui_matches is False
        assert result.impersonation_risk is True

    def test_digi_cui_old_format(self):
        result = match_brand("Digi Romania", "Digi Romania S.A.", [], "5888716", validate_iban("RO51INGB0001000000018827"), "RO51INGB0001000000018827")
        assert result.claimed_brand == "digi"
        assert result.cui_matches is True

    def test_digi_cui_new_format(self):
        result = match_brand("Digi Romania", "Digi Romania S.A.", [], "5888716", validate_iban("RO51INGB0001000000018827"), "RO51INGB0001000000018827")
        assert result.claimed_brand == "digi"
        assert result.cui_matches is True

    def test_energy_gas_official_iban_match(self):
        iban_result = validate_iban("RO25RNCB0300134768150001")
        result = match_brand(None, "SC ENERGY GAS PROVIDER SRL\nCUI RO26741040", [], "26741040", iban_result, "RO25RNCB0300134768150001")
        assert result.claimed_brand == "energy_gas"
        assert result.iban_matches is True

    def test_energy_gas_official_iban_mismatch(self):
        iban_result = validate_iban("RO33RNCB1234567890123456")
        result = match_brand(None, "SC ENERGY GAS PROVIDER SRL\nCUI RO26741040", [], "26741040", iban_result, "RO33RNCB1234567890123456")
        assert result.claimed_brand == "energy_gas"
        assert result.iban_matches is False
        assert result.impersonation_risk is True

    def test_emag_cui_match(self):
        result = match_brand("eMAG", "factura", [], "14399840", validate_iban("RO33RNCB1234567890123456"), "RO33RNCB1234567890123456")
        assert result.claimed_brand == "emag"
        assert result.cui_matches is True

    def test_petrom_cui_match(self):
        result = match_brand("OMV Petrom", "factura", [], "1590082", validate_iban("RO33RNCB1234567890123456"), "RO33RNCB1234567890123456")
        assert result.claimed_brand == "petrom"
        assert result.cui_matches is True

    def test_fan_courier_detected_from_domain(self):
        result = match_brand(None, "colet", ["https://www.fancourier.ro/tracking"], None, validate_iban("RO33RNCB1234567890123456"), "RO33RNCB1234567890123456")
        assert result.claimed_brand == "fan_courier"
        assert result.domain_matches is True

    def test_carrefour_cui_match(self):
        result = match_brand("Carrefour Romania", "factura", [], "11588780", validate_iban("RO33RNCB1234567890123456"), "RO33RNCB1234567890123456")
        assert result.claimed_brand == "carrefour"
        assert result.cui_matches is True
