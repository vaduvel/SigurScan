from services.sanb_registry import lookup_sanb_participant


def test_lookup_known_sanb_participant_by_iban_bank_code():
    participant = lookup_sanb_participant("RNCB")

    assert participant is not None
    assert participant.bic == "RNCBROBU"
    assert "BANCA COMERCIALA ROMANA" in participant.institution


def test_lookup_known_sanb_alias_for_banca_transilvania():
    participant = lookup_sanb_participant("BTRL")

    assert participant is not None
    assert participant.bic == "BTRLRO22"


def test_trezorerie_is_not_sanb_participant():
    assert lookup_sanb_participant("TREZ") is None
