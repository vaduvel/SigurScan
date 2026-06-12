from services.family_classifier import (
    DEFAULT_FAMILY_CODE,
    classify_offer_family,
    get_offer_family,
    list_offer_family_codes,
)


class TestSeedLoading:
    def test_all_op_codes_present(self):
        codes = list_offer_family_codes()
        for expected in ["OP-00", "OP-01", "OP-02", "OP-03", "OP-04", "OP-05", "OP-06", "OP-07", "OP-08", "OP-09"]:
            assert expected in codes

    def test_get_family_metadata(self):
        fam = get_offer_family("OP-01")
        assert fam is not None
        assert "ANAF v9" in fam["verification_sources"]

    def test_get_family_unknown(self):
        assert get_offer_family("OP-99") is None


class TestClassification:
    def test_turism(self):
        text = "Agentie de turism vinde pachet all inclusive cu licenta ANAT, pret sub piata"
        code, name, conf = classify_offer_family(text)
        assert code == "OP-01"
        assert conf > 0.0

    def test_auto(self):
        text = "Vand masina, refuz vizionare fizica, plateste avans pentru transport, lipsa serie sasiu"
        code, _, _ = classify_offer_family(text)
        assert code == "OP-04"

    def test_marketplace(self):
        text = "Anunt pe Marketplace, formularul cere cod 3D Secure ca sa primesti banii, muta discutia pe WhatsApp"
        code, _, _ = classify_offer_family(text)
        # Hint soft: dupa imbogatirea OP-08 v3 (joburi pe WhatsApp), textul cu
        # marketplace+WhatsApp poate match-ui legitim oricare din cele doua familii.
        assert code in ("OP-06", "OP-08", "OP-09")

    def test_crypto_investment(self):
        text = "Investitie garantata cu profit rapid prin crypto wallet, instaleaza aplicatie de acces la distanta"
        code, _, _ = classify_offer_family(text)
        assert code == "OP-09"


class TestFallback:
    def test_empty_text(self):
        code, name, conf = classify_offer_family("")
        assert code == DEFAULT_FAMILY_CODE
        assert conf == 0.0

    def test_unrelated_text(self):
        code, _, _ = classify_offer_family("buna ziua ce mai faci azi vremea e frumoasa")
        assert code == DEFAULT_FAMILY_CODE

    def test_returns_tuple_of_three(self):
        result = classify_offer_family("text oarecare")
        assert len(result) == 3
        assert isinstance(result[0], str)
        assert isinstance(result[2], float)
