"""Guard for the protected-cluster IBAN-format / institution-fee fix.

SYNTHETIC TEST VECTORS ONLY. The IBANs below are obvious test values
(RO49AAAA..., RO12BTRL...0123456) and the texts are constructed stress vectors,
NOT real reported cases -> kept OUT of the provenance corpus
(eval/ro_recall_corpus*.json) on purpose.

Covers two protected-cluster holes found by the recall eval:
1. BEC where the new account is given as an IBAN *format* (RO49...) without the
   literal word "iban" + a verb-form change pretext ("ne-am schimbat banca") ->
   previously UNVERIFIED (the bank-change families keyed on the "iban" keyword).
2. OSIM/EUIPO/IP & judicial bodies requesting a fee paid to an indicated/private
   account -> previously UNVERIFIED.

Both must escalate; legit invoices that merely contain an IBAN (no change pretext,
no such institution) must NOT escalate to DANGEROUS (assert via the deterministic floor).
"""

import os

import eval.large_offline_fixture_runner as runner


def _verdict(text, channel="email"):
    for k, v in {
        "PRIVACY_SAFE_MODE": "false", "ENABLE_CLOUD_AI_EXPLANATION": "false",
        "ENABLE_MISTRAL_SHADOW_ADJUDICATION": "false", "ENABLE_DNS_REPUTATION": "false",
        "INVOICE_CACHE_HMAC_KEY": "ci-test-hmac-key",
    }.items():
        os.environ.setdefault(k, v)
    return runner._run_case({"id": "x", "text": text, "expected": "DANGEROUS",
                             "source": "synthetic", "meta": {"input_type": channel}}).get("actual")


def test_bec_iban_format_without_keyword_escalates():
    # P0 hole: change pretext + IBAN format, no literal "iban" word.
    text = ("Buna ziua, va informam ca ne-am schimbat banca in urma unui audit. "
            "Va rugam achitati factura in noul nostru cont: RO49AAAA1B31007593840000. "
            "Restul detaliilor raman neschimbate.")
    assert _verdict(text) == "DANGEROUS"


def test_bec_iban_keyword_still_escalates():
    # Regression: the pre-existing keyword path must keep firing.
    text = ("Buna ziua, va informam ca ne-am schimbat banca. Va rugam achitati "
            "factura atasata in noul cont IBAN. Restul detaliilor raman neschimbate.")
    assert _verdict(text) == "DANGEROUS"


def test_institution_fee_to_account_escalates():
    # OSIM/EUIPO fee to an indicated account.
    text = ("Pentru cererea dumneavoastra de marca depusa la OSIM, este necesara "
            "achitarea unei taxe de inregistrare/publicare. Efectuati plata in contul "
            "indicat in termen de 5 zile pentru a evita respingerea cererii.")
    assert _verdict(text) == "DANGEROUS"


def test_legit_invoice_with_iban_does_not_escalate():
    # FP boundary: a legit invoice that simply contains an IBAN, with no change
    # pretext and no fee-charging institution, must NOT become DANGEROUS.
    text = ("Buna ziua, va rugam achitati factura 2026-0042 in contul nostru "
            "RO12BTRL1234567890123456 pana pe 30 mai. Multumim.")
    assert _verdict(text) != "DANGEROUS"
