from services.iban_lifecycle import (
    detection_candidate_ibans,
    normalize_iban_candidates,
    payment_target_ibans,
)

_VALID_RO = "RO53BRDE450SV01797384500"              # Altex BRD, valid mod-97
_CLIENT_CODE = "CL006876853MARKETINGGROWTHHUBSRL"   # OCR artifact, not an IBAN


def test_payment_targets_keep_only_valid():
    assert payment_target_ibans([_VALID_RO, _CLIENT_CODE]) == [_VALID_RO]


def test_detection_keeps_all_tokens_but_never_pays_artifact():
    d = detection_candidate_ibans([_VALID_RO, _CLIENT_CODE])
    assert _VALID_RO in d
    assert any("MARKETINGGROWTHHUBSRL" in tok for tok in d)
    assert _CLIENT_CODE not in payment_target_ibans([_CLIENT_CODE])


def test_normalization_and_dedup_first_seen_order():
    assert payment_target_ibans(["  " + _VALID_RO + " ", _VALID_RO.lower(), _VALID_RO]) == [_VALID_RO]


def test_candidates_resolve_validity_once():
    by_norm = {c.normalized: c.valid_structure for c in normalize_iban_candidates([_VALID_RO, _CLIENT_CODE])}
    assert by_norm[_VALID_RO] is True
    assert all(v is False for k, v in by_norm.items() if k != _VALID_RO)
