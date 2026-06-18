import main as app_main
from services.verdict_gate import verdict


AUTHORITY_CALLBACK = (
    "Buna ziua, sunt procuror de caz. Pe numele dumneavoastra exista un dosar penal. "
    "Nu spuneti nimanui din familie, ancheta este confidentiala. Ramaneti pe linie si "
    "urmati instructiunile operatorului."
)

PIG_BUTCHERING_BUILDUP = (
    "Am lucrat ani in trading si iti arat gratuit cum functioneaza grupul nostru privat. "
    "Membrii posteaza profituri zilnice si vei vedea singur rezultatele in cateva zile."
)

MARKETING = "eMAG: oferta limitata weekendul acesta, pana la -50%. Vezi produsele in aplicatie."


def _base_bundle() -> dict:
    return {
        "schema": "sigurscan_evidence_bundle_v2",
        "input": {"type": "sms", "redacted_text": ""},
        "resolution": {"status": "not_required", "completeness": True, "final_url": None},
        "providers": {"verdict": "clean", "hits": ["local"], "completeness": True},
        "identity": {
            "claimed_brand": None,
            "status": "unknown",
            "tld_suspicious": False,
            "completeness": True,
        },
        "request": {"sensitive": "none", "channel": "sms", "completeness": True},
        "context": {"urgency": False, "passive_payment": False, "apk_or_remote_mention": False},
        "semantic_review": {
            "status": "done",
            "claim_matches_known_scam_family": False,
            "matched_family": None,
            "claim_matches_legit_template": False,
            "matched_template": None,
            "reason_codes": ["semantic:unknown"],
            "risk_class": "unknown",
            "completeness": True,
        },
    }


def test_local_social_engineering_signal_extracts_authority_callback_scam():
    signal = app_main._social_engineering_signal_for_decision_bundle(
        AUTHORITY_CALLBACK,
        request_sensitive="none",
        source_channel="phone",
        semantic_review={"risk_class": "high", "source": "mistral_semantic_pillar"},
    )

    assert signal["status"] == "done"
    assert signal["provenance"] == "pipeline_only"
    assert signal["intent"] == "credential_theft"
    assert signal["ask_present"] is True
    assert "callback" in signal["ask_type"]
    assert {"authority", "secrecy", "fear"}.issubset(set(signal["levers"]))
    assert signal["confidence"] >= 0.78


def test_gate_turns_high_confidence_social_engineering_ask_dangerous_without_keywords():
    bundle = _base_bundle()
    bundle["input"]["redacted_text"] = AUTHORITY_CALLBACK
    bundle["social_engineering"] = {
        "status": "done",
        "intent": "credential_theft",
        "ask_present": True,
        "ask_type": ["callback"],
        "levers": ["authority", "secrecy", "fear"],
        "persona_targeting": "generic",
        "channel_coherence": "mismatch",
        "urgency_score": 0.65,
        "confidence": 0.86,
        "model": "local_social_engineering_v1",
        "provenance": "pipeline_only",
    }

    result = verdict(bundle)

    assert result["label"] == "DANGEROUS"
    assert result["reason_codes"] == ["social_engineering_high_confidence_intent"]


def test_gate_marks_social_engineering_build_up_suspect_without_action_request():
    bundle = _base_bundle()
    bundle["input"]["redacted_text"] = PIG_BUTCHERING_BUILDUP
    bundle["social_engineering"] = {
        "status": "done",
        "intent": "investment_fraud",
        "ask_present": False,
        "ask_type": ["none"],
        "levers": ["greed", "social_proof", "liking"],
        "persona_targeting": "investor",
        "channel_coherence": "unknown",
        "urgency_score": 0.1,
        "confidence": 0.74,
        "model": "local_social_engineering_v1",
        "provenance": "pipeline_only",
    }

    result = verdict(bundle)

    assert result["label"] == "SUSPECT"
    assert result["reason_codes"] == ["social_engineering_build_up"]


def test_social_engineering_signal_does_not_escalate_plain_marketing():
    signal = app_main._social_engineering_signal_for_decision_bundle(
        MARKETING,
        request_sensitive="none",
        source_channel="sms",
        semantic_review={"risk_class": "benign", "matched_template": "legit_marketing"},
    )

    assert signal["intent"] in {"benign", "unknown"}
    assert signal["ask_present"] is False
    assert signal["confidence"] < 0.65


def test_model_social_engineering_normalizer_treats_string_false_as_false():
    fallback = app_main._social_engineering_signal_for_decision_bundle(
        MARKETING,
        request_sensitive="none",
        source_channel="sms",
        semantic_review={"risk_class": "benign", "matched_template": "legit_marketing"},
    )

    signal = app_main._normalize_model_social_engineering_signal(
        {
            "intent": "benign",
            "ask_present": "false",
            "ask_type": ["none"],
            "levers": [],
            "confidence": 0.2,
        },
        fallback,
    )

    assert signal["ask_present"] is False


def test_gate_keeps_safety_education_unverified_even_with_scary_words():
    bundle = _base_bundle()
    bundle["input"]["redacted_text"] = "Banca nu iti cere niciodata sa muti banii in cont de protectie."
    bundle["semantic_review"] = {
        "status": "done",
        "claim_matches_known_scam_family": False,
        "matched_family": None,
        "claim_matches_legit_template": True,
        "matched_template": "safety_education",
        "reason_codes": ["semantic:benign", "semantic:safety_education_scope"],
        "risk_class": "benign",
        "completeness": True,
    }
    bundle["social_engineering"] = {
        "status": "done",
        "intent": "benign",
        "ask_present": False,
        "ask_type": ["none"],
        "levers": [],
        "persona_targeting": "generic",
        "channel_coherence": "coherent",
        "urgency_score": 0.0,
        "confidence": 0.1,
        "model": "local_social_engineering_v1",
        "provenance": "pipeline_only",
    }

    result = verdict(bundle)

    assert result["label"] == "UNVERIFIED"
    assert result["reason_codes"] == ["safety_education_not_action_request"]
