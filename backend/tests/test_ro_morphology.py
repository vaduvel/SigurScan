from services.ro_morphology import (
    contains_all,
    light_stem,
    normalize_text,
    normalize_token,
    strip_diacritics,
    token_set,
    tokens,
)


def test_strip_diacritics_both_variants():
    assert strip_diacritics("Președinție") == "Presedintie"
    # cedilla variants (ş/ţ) fold the same as comma-below (ș/ț)
    assert strip_diacritics("Peştişani") == "Pestisani"
    assert strip_diacritics("Târgu Mureș") == "Targu Mures"


def test_normalize_token_folds_case_and_punctuation():
    assert normalize_token("Factură,") == "factura"
    assert normalize_token("  BRD-ul ") == "brdul"
    assert normalize_token("") == ""


def test_tokens_and_normalize_text():
    assert tokens("Banca Transilvania S.A.") == ["banca", "transilvania", "s", "a"]
    assert normalize_text("Plată către ING") == "plata catre ing"


def test_token_set_and_contains_all():
    assert contains_all("Banca Transilvania SA", "transilvania") is True
    assert contains_all("Banca Transilvania SA", "banca transilvania") is True
    assert contains_all("Banca Transilvania SA", "brd") is False
    assert contains_all("anything", "") is False
    assert "ing" in token_set("Plata catre ING")


def test_light_stem_removes_common_endings():
    assert light_stem("clientul") == "client"
    assert light_stem("clientii") == "client"
    assert light_stem("facturii") == "factur"
    assert light_stem("facturile") == "factur"
    assert light_stem("facturilor") == "factur"
    # short tokens are left intact
    assert light_stem("bt") == "bt"
    assert light_stem("cec") == "cec"
