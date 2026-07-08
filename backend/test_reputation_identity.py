"""Hash-parity gate for D6 identifier hashing (Felia 1, hard gate).

Golden vectors are frozen, independently-computed SHA-256 digests. They lock the
algorithm so a future change to normalization/hashing fails CI instead of
silently breaking cross-surface correlation.

Phone hashes MUST equal what the Android client produces
(RadarHotCache.kt :: PhoneNumberHasher). The normalized intermediate is asserted
explicitly so a human can eyeball it against the Kotlin. IBAN hashing is a
backend-defined convention (the client does not hash IBANs); the future client
IBAN hasher must adopt this same scheme.
"""

from services.reputation_identity import (
    canonical_iban,
    hash_iban,
    hash_phone,
    normalize_phone,
)

# (raw, expected_normalized_e164, expected_sha256_hex)
PHONE_GOLDEN = [
    ("0722123456", "+40722123456", "93841fe8558bfa0dbc484f476f27af1de186cd33dfb09c4d1215d42f1abbe0f5"),
    ("0040722123456", "+40722123456", "93841fe8558bfa0dbc484f476f27af1de186cd33dfb09c4d1215d42f1abbe0f5"),
    ("40722123456", "+40722123456", "93841fe8558bfa0dbc484f476f27af1de186cd33dfb09c4d1215d42f1abbe0f5"),
    ("+40 722 123 456", "+40722123456", "93841fe8558bfa0dbc484f476f27af1de186cd33dfb09c4d1215d42f1abbe0f5"),
    ("0722.123.456", "+40722123456", "93841fe8558bfa0dbc484f476f27af1de186cd33dfb09c4d1215d42f1abbe0f5"),
]

# (raw, expected_canonical, expected_sha256_hex)
IBAN_GOLDEN = [
    ("RO49 AAAA 1B31 0075 9384 0000", "RO49AAAA1B31007593840000",
     "92c09c16747a943f3f36638dbb910fa9b398ed623aa1f00ec765bc4d4a420677"),
    ("ro49aaaa1b3100759384 0000", "RO49AAAA1B31007593840000",
     "92c09c16747a943f3f36638dbb910fa9b398ed623aa1f00ec765bc4d4a420677"),
    ("RO27CECEB00030RON0509820", "RO27CECEB00030RON0509820",
     "2ef9e526286fed2a282ccd1ad59121441015bf8bae0a6476415fe24fa3282881"),
]


def test_phone_normalization_and_hash_parity():
    for raw, expected_norm, expected_hash in PHONE_GOLDEN:
        assert normalize_phone(raw) == expected_norm, raw
        assert hash_phone(raw) == expected_hash, raw


def test_all_phone_formats_of_same_number_collapse_to_one_hash():
    # The whole point of E.164 normalization: any input format of one number
    # links to a single graph node.
    hashes = {hash_phone(raw) for raw, _, _ in PHONE_GOLDEN}
    assert len(hashes) == 1


def test_iban_canonicalization_and_hash_parity():
    for raw, expected_canon, expected_hash in IBAN_GOLDEN:
        assert canonical_iban(raw) == expected_canon, raw
        assert hash_iban(raw) == expected_hash, raw


def test_iban_spacing_and_case_insensitive():
    assert hash_iban("RO49 AAAA 1B31 0075 9384 0000") == hash_iban("ro49aaaa1b3100759384  0000")


def test_blank_and_garbage_yield_empty_hash():
    for bad in (None, "", "   ", "not a phone", "abc"):
        assert hash_phone(bad) == ""
    for bad in (None, "", "RO12", "1234567890", "hello world"):
        assert hash_iban(bad) == ""
