from services.bank_name_crosscheck import crosscheck, detect_bank_key


def _mod97(value: str) -> int:
    remainder = 0
    for ch in value:
        remainder = (remainder * 10 + (ord(ch) - ord("0"))) % 97
    return remainder


def _make_ro_iban(bank_code: str, account: str) -> str:
    """Build a structurally valid RO IBAN (mod-97) for use as a test fixture."""
    bban = f"{bank_code}{account}"  # 4 + 16 = 20 chars
    rearranged = bban + "RO00"
    numeric = "".join(str(ord(c) - 55) if c.isalpha() else c for c in rearranged)
    check = 98 - _mod97(numeric)
    return f"RO{check:02d}{bban}"


BRD_IBAN = _make_ro_iban("BRDE", "4500000000000000")
TREZ_IBAN = _make_ro_iban("TREZ", "7005069000008077")


def test_detect_bank_key_basic():
    assert detect_bank_key("Banca Transilvania S.A.") == "BANCA_TRANSILVANIA"
    assert detect_bank_key("Plata catre ING") == "ING"
    assert detect_bank_key("BRD - Groupe Societe Generale") == "BRD"
    assert detect_bank_key("Trezoreria Statului Sector 1") == "TREZORERIE"


def test_detect_bank_key_avoids_substring_false_positive():
    # "ing" must not match inside "marketing"
    assert detect_bank_key("Marketing Growth Hub SRL") is None
    assert detect_bank_key("Total de plata") is None


def test_crosscheck_match():
    result = crosscheck("BRD Groupe Societe Generale", BRD_IBAN)
    assert result.status == "MATCH"
    assert result.iban_bank_code == "BRDE"


def test_crosscheck_mismatch():
    result = crosscheck("Banca Transilvania", BRD_IBAN)
    assert result.status == "MISMATCH"
    assert result.is_mismatch is True
    assert result.printed_bank_key == "BANCA_TRANSILVANIA"
    assert result.iban_bank_key == "BRD"


def test_crosscheck_trezorerie_match():
    assert crosscheck("Trezoreria Statului", TREZ_IBAN).status == "MATCH"


def test_crosscheck_unknown_printed_bank():
    assert crosscheck("Total de plata", BRD_IBAN).status == "UNKNOWN"


def test_crosscheck_no_data_without_iban():
    assert crosscheck("BRD", None).status == "NO_DATA"


def test_crosscheck_no_data_foreign_iban():
    assert crosscheck("BRD", "GB29NWBK60161331926819").status == "NO_DATA"
