"""Non-regression: the P-MORPH fuzzy brand-alias fallback must not drive a
false PERICOL verdict.

Background: P-MORPH added a token-based (`contains_all`) fallback to
`detect_claimed_brand`, so a multi-word brand alias can now match even when its
tokens are non-adjacent. That broadened brand attribution, and a mis-attributed
brand with a contradicted CUI would otherwise escalate to the
`BRAND_IMPERSONATION_PAYMENT_DESTINATION_MISMATCH` hard conflict (= DANGEROUS)
on an ordinary legit invoice that merely shares brand tokens.

The two inputs below were confirmed to regress (main -> None, #111 -> brand):
  "Media Solutii Galaxy Design SRL" -> altex   (Media Galaxy is an Altex brand)
  "Mega distributie image studio"   -> mega_image

Fix: strict (word-boundary / exact-domain) matches keep escalating; a fuzzy
match still adds recall but is flagged non-strict and can never produce the
impersonation hard conflict.
"""

import pytest

from services.brand_registry import BrandMatchResult, detect_claimed_brand, match_brand
from services.invoice_truth_v4 import (
    _brand_impersonation_payment_destination_mismatch as _impersonation_hard_conflict,
)


FUZZY_REGRESSION_CASES = [
    ("Media Solutii Galaxy Design SRL", "altex"),
    ("Mega distributie image studio", "mega_image"),
]


@pytest.mark.parametrize("emitent,expected_brand", FUZZY_REGRESSION_CASES)
def test_fuzzy_multiword_alias_still_recalls_brand(emitent, expected_brand):
    # Recall is intentionally preserved: the brand is still detected...
    assert detect_claimed_brand(emitent, emitent, []) == expected_brand


@pytest.mark.parametrize("emitent,expected_brand", FUZZY_REGRESSION_CASES)
def test_fuzzy_multiword_alias_is_flagged_non_strict(emitent, expected_brand):
    # ...but flagged non-strict so it cannot escalate to a hard PERICOL conflict.
    result = match_brand(
        emitent, "", [], cui="12345678", validated_iban=None, iban_raw=None
    )
    assert result.claimed_brand == expected_brand
    assert result.claimed_brand_match_strict is False


@pytest.mark.parametrize(
    "emitent,expected_brand",
    [
        ("Altex Romania", "altex"),
        ("ELECTRICA FURNIZARE S.A.", "electrica"),
        ("ENEL Energie SA", "enel"),
    ],
)
def test_strict_alias_match_stays_strict(emitent, expected_brand):
    result = match_brand(
        emitent, "", [], cui=None, validated_iban=None, iban_raw=None
    )
    assert result.claimed_brand == expected_brand
    assert result.claimed_brand_match_strict is True


def _brand_match(*, strict: bool) -> BrandMatchResult:
    # A contradicted-CUI impersonation-risk brand match (the escalation trigger).
    return BrandMatchResult(
        claimed_brand="altex",
        domain_matches=None,
        iban_matches=None,
        cui_matches=False,
        impersonation_risk=True,
        claimed_brand_match_strict=strict,
    )


_UNREGISTERED_DEST = {"matched": False, "registry_has_brand_destinations": True}


@pytest.mark.parametrize("destination_state", ["UNCONFIRMED_VALID", "BANK_MATCH"])
def test_fuzzy_brand_match_does_not_escalate_to_pericol(destination_state):
    assert (
        _impersonation_hard_conflict(
            brand_match=_brand_match(strict=False),
            destination_state=destination_state,
            payment_destination=_UNREGISTERED_DEST,
        )
        is False
    )


@pytest.mark.parametrize("destination_state", ["UNCONFIRMED_VALID", "BANK_MATCH"])
def test_strict_brand_match_still_escalates_to_pericol(destination_state):
    # The genuine impersonation signal (incl. the #6 BANK_MATCH path) is intact.
    assert (
        _impersonation_hard_conflict(
            brand_match=_brand_match(strict=True),
            destination_state=destination_state,
            payment_destination=_UNREGISTERED_DEST,
        )
        is True
    )
