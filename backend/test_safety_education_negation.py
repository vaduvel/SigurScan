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
    _canonicalize_url,
    engine,
    extract_urls,
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
        "Furnizor hosting cunoscut trimite factură de renewal din domeniul obișnuit; "
        "IBAN HMAC match; DKIM pass."
    ),
    (
        "Reminder plată de la vendor cunoscut, fără schimbare IBAN, fără link extern, "
        "factură număr deja văzut."
    ),
    (
        "Plată urgentă are ticket intern, two-person approval și vendor/IBAN cunoscut; "
        "email DKIM pass."
    ),
    (
        "e-Factura XML furnizat de user se potrivește cu PDF-ul primit: CUI emitent, "
        "număr factură, total și IBAN identice cu vendor registry local."
    ),
    (
        "OSIM: userul intră manual pe portalul oficial și generează taxă oficială; "
        "documentul vine din portalul oficial, fără link din email și fără cont terț."
    ),
    (
        "Factura nr. 8849 Emitent: Furnizor Confirmat SRL CUI: 00000000 "
        "Total: 1.200,00 RON IBAN: RO49AAAA1B31007593840000 "
        "Beneficiar: Furnizor Confirmat SRL"
    ),
    (
        "Factura nr. 8849\n"
        "Emitent: Furnizor Confirmat SRL\n"
        "CUI: 00000000\n"
        "Total: 1.200,00 RON\n"
        "IBAN: RO49AAAA1B31007593840000\n"
        "Beneficiar: Furnizor Confirmat SRL"
    ),
    "Revolut Pay OTP: 123-456. Nu îl divulga nimănui.",
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


def _label(text, channel="email", with_urls=False):
    red = redact_pii(_normalise_obfuscated_text(text))
    resolved_urls = []
    if with_urls:
        for url in extract_urls(red):
            canonical = _canonicalize_url(url) or url
            resolved_urls.append({"url": canonical, "input_url": canonical, "final_url": canonical, "success": True, "status_code": 200})
    a = engine.analyze(red, urls=resolved_urls, external_threat_intel={})
    a.setdefault("evidence", {})["source_channel"] = channel
    fa = _apply_provider_gate_verdict(a, resolved_urls, raw_text=red, pillars={})
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


def test_red_flag_explainer_with_negation_is_not_dangerous():
    text = (
        "Acest ghid explică red flag-ul «IBAN nou»; "
        "nu înseamnă că factura ta cere IBAN nou."
    )

    assert _label(text, channel="android_native") != "DANGEROUS"


def test_bec_account_change_worded_as_vendor_context_stays_dangerous():
    text = (
        "Furnizor cunoscut trimite cont bancar nou cu Reply-To diferit "
        "si cere plata azi in IBAN RO49AAAA1B31007593840000."
    )

    assert _label(text, channel="email") == "DANGEROUS"


def test_invoice_qr_payment_instruction_is_not_calmed_as_static_invoice():
    text = (
        "Factura nr. 8842\n"
        "Total: 980,00 RON\n"
        "IBAN tipărit: RO49AAAA1B31007593840000\n"
        "Scanați QR pentru plată rapidă"
    )

    assert _label(text, channel="invoice") == "DANGEROUS"


def test_invoice_payment_beneficiary_mismatch_is_not_calmed_as_static_invoice():
    text = (
        "Factura nr. 8844\n"
        "Emitent: Service Expert SRL\n"
        "CUI: 00000000\n"
        "Total: 6.200,00 RON\n"
        "IBAN: RO06MIDL0000000000000005\n"
        "Beneficiar plată: Procesator Rapid SRL\n"
        "Nu este necesar act adițional."
    )

    assert _label(text, channel="invoice") == "DANGEROUS"


def test_non_http_deeplink_without_sensitive_request_is_not_dangerous():
    text = (
        "<a href='whatsapp://send?text=cod'>Trimite pe WhatsApp</a>"
        "<a href='https://sigurantaonline.ro/uniti-impotriva-escrocheriilor/'>Info</a>"
    )

    assert _label(text, channel="html_email", with_urls=True) != "DANGEROUS"


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


def test_mistral_protective_education_can_override_local_keyword_high():
    fallback = {
        "risk_class": "high",
        "claim_matches_known_scam_family": True,
        "matched_family": "IMP-02",
        "reason_codes": ["semantic:high", "family:imp-02"],
        "source": "scam_atlas_structured",
    }
    raw = {
        "risk_class": "benign",
        "claim_matches_known_scam_family": False,
        "claim_matches_legit_template": True,
        "matched_template": "safety_education",
        "reason_codes": ["semantic:benign", "template:educational_warning"],
        "intent_analysis": {
            "positive_action_request": False,
            "is_descriptive_or_status": True,
            "negation_scope_resolved": True,
            "confidence": 0.9,
        },
    }

    normalized = _normalize_mistral_semantic_review(raw, fallback)

    assert normalized["risk_class"] == "benign"
    assert normalized["claim_matches_known_scam_family"] is False
    assert normalized["claim_matches_legit_template"] is True
    assert "semantic:atlas_high_preserved" not in normalized["reason_codes"]


def test_mistral_semantic_review_accepts_nested_contract_shape():
    raw = {
        "semantic_review": {
            "risk_class": "high",
            "claim_matches_known_scam_family": False,
            "claim_matches_legit_template": False,
            "reason_codes": ["semantic:request_for_otp"],
            "social_engineering": {
                "intent": "credential_theft",
                "ask_present": True,
                "ask_type": ["otp"],
                "levers": ["authority"],
                "confidence": 0.95,
            },
            "intent_analysis": {
                "positive_action_request": True,
                "negation_scope_resolved": True,
                "confidence": 0.95,
            },
        }
    }

    normalized = _normalize_mistral_semantic_review(raw, {"risk_class": "unknown"})

    assert normalized["risk_class"] == "high"
    assert normalized["intent_analysis"]["positive_action_request"] is True


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
