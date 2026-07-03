"""Guard for the soft-ask recall families: account-inventory harvesting and
advance-fee / pay-to-unlock.

SYNTHETIC TEST VECTORS ONLY -> kept OUT of the provenance corpus.

The "soft-ask" class is what a rigid classifier hesitates on: the first ask is not
"give me money" but "tell me where you bank" / "pay a small fee to unlock". FP guard
is critical: legit messages that mention an account statement, a processing
commission, an insurance offer, or a withdrawal must NOT escalate.
"""

import os

import eval.large_offline_fixture_runner as runner


def _verdict(text, channel="phone_call"):
    for k, v in {
        "PRIVACY_SAFE_MODE": "false", "ENABLE_CLOUD_AI_EXPLANATION": "false",
        "ENABLE_MISTRAL_SHADOW_ADJUDICATION": "false", "ENABLE_DNS_REPUTATION": "false",
        "INVOICE_CACHE_HMAC_KEY": "ci-test-hmac-key",
    }.items():
        os.environ.setdefault(k, v)
    return runner._run_case({"id": "x", "text": text, "expected": "DANGEROUS",
                             "source": "synthetic", "meta": {"input_type": channel}}).get("actual")


def test_account_inventory_harvest_escalates():
    assert _verdict("Pentru verificare, spuneti-mi unde aveti conturi deschise, la ce banci si "
                    "ce sume aveti in ele.") == "DANGEROUS"


def test_advance_fee_to_recover_escalates():
    assert _verdict("Am identificat fondurile pierdute. Putem recupera banii, insa trebuie "
                    "achitata in avans o taxa de procesare pentru a debloca transferul.",
                    channel="email") == "DANGEROUS"


def test_advance_fee_insurance_to_withdraw_escalates():
    assert _verdict("Pentru a putea retrage profitul din platforma, trebuie sa incheiati o "
                    "asigurare care costa alti 10.000 de euro.", channel="app") == "DANGEROUS"


def test_legit_loan_statement_and_id_does_not_escalate():
    # FP boundary: a legit credit application asking for a statement + ID copy.
    assert _verdict("Pentru aprobarea creditului, va rugam atasati extrasul de cont pe ultimele "
                    "3 luni si o copie a buletinului. Multumim.", channel="email") == "UNVERIFIED"


def test_legit_processing_commission_does_not_escalate():
    assert _verdict("Tranzactie procesata. S-a aplicat un comision de procesare de 5 lei conform "
                    "contractului.", channel="email") == "UNVERIFIED"


def test_legit_withdrawal_notice_does_not_escalate():
    assert _verdict("Retragerea de 500 lei a fost initiata. Fondurile vor ajunge in 1-2 zile "
                    "lucratoare.", channel="email") == "UNVERIFIED"


def test_legit_atm_withdrawal_alert_does_not_escalate():
    # FP boundary (advance_fee sibling): a legit ATM withdrawal alert that self-directs
    # the user to the number on the back of the card must stay UNVERIFIED, never escalate.
    assert _verdict("Ati efectuat o retragere de 700 lei de la bancomat (ATM) astazi, ora 14:32. "
                    "Daca nu recunoasteti operatiunea, contactati banca la numarul de pe spatele "
                    "cardului.", channel="sms") == "UNVERIFIED"


def test_legit_broker_kyc_onboarding_does_not_escalate():
    # FP boundary (account_inventory sibling): a legit brokerage KYC onboarding that asks,
    # via the official portal, which bank will fund the account must stay UNVERIFIED.
    assert _verdict("Pentru deschiderea contului de brokeraj, conform cerintelor legale KYC, va "
                    "rugam completati formularul oficial cu banca din care veti alimenta contul. "
                    "Documentele se incarca doar in portalul nostru securizat.", channel="email") == "UNVERIFIED"


def test_legit_broker_kyc_id_statement_in_official_portal_does_not_escalate():
    # FP boundary for RO-SCAM-2026-018: ID + bank statement alone are normal KYC
    # when the message explicitly stays inside an official secured portal and does
    # not guide the user through trades or ask for a first deposit.
    assert _verdict("Pentru deschiderea contului de brokeraj, conform cerintelor legale KYC, "
                    "incarcati actul de identitate si extrasul de cont in portalul oficial "
                    "securizat. Nu efectuati nicio plata in afara platformei oficiale.",
                    channel="email") == "UNVERIFIED"
