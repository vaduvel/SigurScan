"""Recall guard for the "green" RO-2025/2026 families promoted in the closeout round
(#76/T5): courier-fee payment link carried as a bare URL, and money-mule transit.

SYNTHETIC TEST VECTORS ONLY (constructed from cited public typologies — DNSC courier
campaigns, FAN/DHL phishing, Revolut money-mule reporting) -> kept OUT of the
provenance corpus.

Green = clear FP boundary: the official channel never asks for card/transit via a
link, and a legit reimbursement/salary/affiliate payout is receive-only (no
forward-onward + commission).
"""

import os

import eval.large_offline_fixture_runner as runner


def _verdict(text, channel="sms"):
    for k, v in {
        "PRIVACY_SAFE_MODE": "false", "ENABLE_CLOUD_AI_EXPLANATION": "false",
        "ENABLE_MISTRAL_SHADOW_ADJUDICATION": "false", "ENABLE_DNS_REPUTATION": "false",
        "INVOICE_CACHE_HMAC_KEY": "ci-test-hmac-key",
    }.items():
        os.environ.setdefault(k, v)
    return runner._run_case({"id": "x", "text": text, "expected": "DANGEROUS",
                             "source": "synthetic", "meta": {"input_type": channel}}).get("actual")


# ── Courier-fee payment link carried as a bare URL (recall #76/T5) ───────────
def test_courier_fee_url_fan_escalates():
    text = ("FAN Courier: coletul asteapta livrarea. Confirmati adresa si plata taxei de "
            "livrare cu cardul: https://fan-curier-livrare.info")
    assert _verdict(text) == "DANGEROUS"


def test_courier_fee_url_dhl_escalates():
    text = ("DHL: coletul nu poate fi livrat pana nu achitati taxa vamala. "
            "Plata: https://dhl-customs-pay.com")
    assert _verdict(text) == "DANGEROUS"


def test_courier_fee_literal_link_still_escalates():
    # Regression: the original literal-"link" shape must keep firing.
    text = "Posta: achitati taxa de livrare accesand link-ul de mai jos."
    assert _verdict(text) == "DANGEROUS"


def test_legit_courier_tracking_url_does_not_escalate():
    # FP boundary: a legit tracking SMS with a URL but NO card/payment ask.
    text = ("Coletul tau AWB 12345 este in livrare azi, interval 14-18. Detalii si "
            "tracking: https://www.fancourier.ro/track")
    assert _verdict(text) == "UNVERIFIED"


# ── Money-mule transit (recall #76/T5) ──────────────────────────────────────
def test_money_mule_recruit_escalates():
    text = ("Oferta: primesti bani in contul tau si ii retrimiti mai departe, pastrezi "
            "10% comision. Trimite-mi IBAN-ul tau ca sa incepem azi.")
    assert _verdict(text, channel="telegram") == "DANGEROUS"


def test_money_mule_job_framing_escalates():
    text = ("Job usor de acasa: vei primi sume in cont, le transferi mai departe catre "
            "partenerii nostri si opresti un procent.")
    assert _verdict(text, channel="whatsapp") == "DANGEROUS"


def test_money_mule_third_person_intra_escalates():
    # "intra bani in cont" (3rd person) + redirect onward + keep commission.
    text = ("Cautam colaboratori: intra bani in contul tau, ii redirectionezi catre alt "
            "cont si pastrezi comisionul tau.")
    assert _verdict(text, channel="telegram") == "DANGEROUS"


def test_legit_affiliate_commission_does_not_escalate():
    # FP boundary: receive + commission, but NO forward-onward.
    text = "Castigi 10% comision din vanzarile aduse. Banii intra lunar in contul tau."
    assert _verdict(text, channel="email") == "UNVERIFIED"


def test_legit_reimbursement_does_not_escalate():
    # FP boundary: a legit reimbursement between acquaintances (receive-only).
    text = "Salut, iti returnez cei 200 lei pe care mi i-ai imprumutat saptamana trecuta. Multumesc!"
    assert _verdict(text) == "UNVERIFIED"


def test_legit_salary_notice_does_not_escalate():
    # FP boundary: a legit salary credit notice (receive-only).
    text = "Vei primi salariul in cont pe data de 5 ale lunii, conform contractului de munca."
    assert _verdict(text, channel="email") == "UNVERIFIED"
