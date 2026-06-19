"""EDGE-04: educational anti-scam content that DESCRIBES scams and tells the
reader "nu da codul nimanui" must not be flagged DANGEROUS.

The protective-negation requirement is also the discriminator against adversarial
"educational" framing that hides a real request ("exerseaza introducand datele
cardului") — that has no negation, so it must NOT be treated as safety education.
"""

from main import (
    _apply_provider_gate_verdict,
    _build_decision_evidence_bundle,
    _looks_like_official_safety_education,
    _normalize_mistral_semantic_review,
    _normalize_model_intent_analysis,
    _normalise_obfuscated_text,
    engine,
)
from services.pii_redactor import redact_pii


EDU = (
    "Newsletter educatie financiara: cum recunosti un scam cu OTP, IBAN fals si "
    "transfer in cont sigur. Nu da niciodata codul nimanui."
)
PROTECTIVE_CONTROLS = [
    (
        "ING Bank: Nu accesa linkuri din emailuri sau SMS-uri care pretind ca sunt de la banca. "
        "ING nu iti va cere niciodata sa introduci codul de activare sau parola pe un link primit prin mesaj."
    ),
    (
        "FAN Courier: Coletul cu AWB 9876543210 a fost predat. Livrare cu plata ramburs 45 RON. "
        "Nu accesati linkuri false care solicita date bancare in numele FAN Courier. "
        "Verificati statusul doar pe fancourier.ro sau in aplicatia oficiala."
    ),
    (
        "Te rog sa nu schimbi IBAN-ul pentru furnizorul Y. Am verificat si datele raman cele din contractul initial. "
        "Orice solicitare de modificare a contului trebuie confirmata telefonic cu persoana de contact cunoscuta."
    ),
    (
        "Furnizorul W ne-a trimis o factura. Va rog sa o verificati in sistem. "
        "IBAN-ul este identic cu cel din luna trecuta. Nu deschideti linkuri sau atasamente suspecte."
    ),
    (
        "Confirmam ca factura cu numarul 3344/16.06.2026 a fost incarcata in SPV si are starea Acceptata. "
        "Puteti descarca XML-ul de pe portalul ANAF. Nu deschideti fisiere primite pe email decat daca ati solicitat explicit."
    ),
    (
        "Revolut: Nu iti vom cere niciodata sa ne trimiti ecranul cu cardul tau, codul CVC sau parola. "
        "Daca cineva pretinde ca este din echipa Revolut si cere aceste date, raporteaza imediat."
    ),
    (
        "Raiffeisen Bank: Atentie la mesajele care te indruma sa instalezi aplicatii de la distanta (AnyDesk, TeamViewer). "
        "Nu permite niciodata accesul la dispozitivul tau unei persoane necunoscute."
    ),
]
NON_ACTION_CONTROLS = [
    (
        "ING: tranzactie autorizata 89.00 lei la Kaufland. "
        "Sold disponibil in Home'Bank"
    ),
    (
        "Furnizor cunoscut, domeniu email cunoscut, DKIM pass, "
        "IBAN HMAC match cu vendor profile, total coerent."
    ),
    (
        "Factura din e-Factura XML furnizat de user corespunde PDF-ului "
        "si IBAN-ul match vendor local."
    ),
    (
        "Articol Microsoft despre sextortion/tech support scams, "
        "fara wallet sau plata."
    ),
]
ADVERSARIAL_EDU_WITH_REQUEST = (
    "Ghid educativ de securitate: ca sa intelegi cum arata o verificare reala, "
    "exerseaza acum introducand datele cardului in formularul-demo de mai jos."
)
OTP_PHONE_REQUEST = (
    "Sunt de la banca. Am detectat o tranzactie suspecta. "
    "Dati-mi codul OTP pentru a o bloca."
)


def _label(text, channel="email"):
    red = redact_pii(_normalise_obfuscated_text(text))
    a = engine.analyze(red, urls=[], external_threat_intel={})
    a.setdefault("evidence", {})["source_channel"] = channel
    fa = _apply_provider_gate_verdict(a, [], raw_text=red, pillars={})
    return fa["evidence"]["verdict_gate"]["label"]


def test_education_with_protective_negation_is_detected():
    assert _looks_like_official_safety_education(EDU) is True


def test_education_content_is_not_dangerous():
    assert _label(EDU) != "DANGEROUS"


def test_protective_negation_controls_are_not_dangerous():
    for text in PROTECTIVE_CONTROLS:
        assert _looks_like_official_safety_education(text) is True
        assert _label(text, channel="android_native") != "DANGEROUS"


def test_non_action_status_and_descriptive_controls_are_not_dangerous():
    for text in NON_ACTION_CONTROLS:
        assert _label(text, channel="sms") != "DANGEROUS"


def test_explicit_otp_request_on_wrong_channel_stays_dangerous():
    assert _label(OTP_PHONE_REQUEST, channel="phone") == "DANGEROUS"


def test_mistral_intent_analysis_can_suppress_non_action_keyword_noise():
    local = {
        "status": "done",
        "positive_action_request": True,
        "protective_warning": False,
        "descriptive_context": False,
        "source": "local_request_intent_v1",
    }
    model = {
        "positive_action_request": False,
        "is_protective_warning": True,
        "is_descriptive_or_status": True,
        "negation_scope_resolved": True,
        "describes_fraud_without_request": True,
        "confidence": 0.91,
    }

    merged = _normalize_model_intent_analysis(model, local)

    assert merged["positive_action_request"] is False
    assert merged["protective_warning"] is True
    assert merged["descriptive_context"] is True


def test_mistral_intent_analysis_can_raise_real_payment_request():
    local = {
        "status": "done",
        "positive_action_request": False,
        "protective_warning": False,
        "descriptive_context": False,
        "source": "local_request_intent_v1",
    }
    model = {
        "positive_action_request": True,
        "invoice_or_payment_document": True,
        "payment_instruction_present": True,
        "payment_instruction_is_requested": True,
        "payment_instruction_is_descriptive": False,
        "confidence": 0.74,
    }

    merged = _normalize_model_intent_analysis(model, local)

    assert merged["positive_action_request"] is True
    assert merged["payment_instruction_is_requested"] is True


def test_mistral_semantic_review_preserves_intent_analysis_contract():
    raw = {
        "risk_class": "benign",
        "claim_matches_known_scam_family": False,
        "claim_matches_legit_template": True,
        "reason_codes": ["semantic:status_notification"],
        "intent_analysis": {
            "positive_action_request": False,
            "is_descriptive_or_status": True,
            "negation_scope_resolved": True,
            "confidence": 0.88,
        },
    }

    normalized = _normalize_mistral_semantic_review(raw, {"risk_class": "unknown"})

    assert normalized["intent_analysis"]["positive_action_request"] is False
    assert normalized["intent_analysis"]["descriptive_context"] is True


def test_mistral_intent_analysis_is_used_by_decision_bundle():
    analysis = {
        "claimed_brand": "Nespecificat",
        "evidence": {
            "source_channel": "sms",
            "semantic_review": {
                "status": "done",
                "risk_class": "high",
                "claim_matches_known_scam_family": True,
                "claim_matches_legit_template": False,
                "reason_codes": ["semantic:example"],
                "intent_analysis": {
                    "positive_action_request": False,
                    "is_descriptive_or_status": True,
                    "negation_scope_resolved": True,
                    "confidence": 0.9,
                },
            },
        },
    }

    bundle = _build_decision_evidence_bundle(
        analysis,
        [],
        raw_text="Audit intern: exemplu de mesaj cu OTP, fara solicitare reala catre client.",
        pillars={},
    )

    assert bundle["request"]["positive_action_request"] is False
    assert bundle["request"]["descriptive_context"] is True


def test_adversarial_education_with_real_request_is_not_safety_education():
    # has a positive request and no protective negation -> stays detectable
    assert _looks_like_official_safety_education(ADVERSARIAL_EDU_WITH_REQUEST) is False
