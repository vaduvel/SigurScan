import json
from pathlib import Path

from fastapi.testclient import TestClient

import main as app_main
from services import audio_semantic_review
from services.audio_scam_context import build_audio_scam_context


def test_audio_scam_atlas_v2_has_unique_ids_and_provenance():
    atlas_path = Path(__file__).parent / "data" / "audio_scam_atlas_v2.json"
    payload = json.loads(atlas_path.read_text(encoding="utf-8"))
    families = payload["families"]
    family_ids = [family["id"] for family in families]

    assert len(family_ids) == len(set(family_ids))
    missing_sources = [
        family["id"]
        for family in families
        if not family.get("sources") or not all(source.get("url") and source.get("source_type") for source in family["sources"])
    ]
    assert missing_sources == []


def test_audio_semantic_review_uses_mistral_without_echoing_redacted_transcript(monkeypatch):
    captured_payloads = []

    def fake_mistral(payload):
        captured_payloads.append(payload)
        return {
            "risk_class": "high",
            "claim_matches_known_scam_family": True,
            "matched_family": "CONV_BANK_SAFE_ACCOUNT",
            "reason_codes": ["semantic:false_authority", "semantic:safe_account"],
            "social_engineering": {
                "intent": "payment_redirection",
                "ask_present": True,
                "ask_type": ["transfer"],
                "levers": ["authority", "urgency", "secrecy"],
                "urgency_score": 0.9,
                "confidence": 0.93,
            },
        }

    monkeypatch.setattr(audio_semantic_review, "PRIVACY_SAFE_MODE", False, raising=False)
    monkeypatch.setattr(audio_semantic_review, "ENABLE_MISTRAL_SEMANTIC_PILLAR", True, raising=False)
    monkeypatch.setattr(audio_semantic_review, "MISTRAL_SEMANTIC_API_KEY", "test-key", raising=False)
    monkeypatch.setattr(audio_semantic_review, "_call_mistral_semantic_review", fake_mistral)

    client = TestClient(app_main.app)
    response = client.post(
        "/v1/audio/semantic-review",
        json={
            "transcript_redacted": "Sunt de la bancă. Mută banii în [iban] și nu spune nimănui. Codul este [cod].",
            "channel": "call_live",
            "local_verdict": "UNVERIFIED",
            "local_reason_codes": ["residual"],
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "done"
    assert body["semantic_review"]["source"] == "mistral_semantic_pillar"
    assert body["semantic_review"]["risk_class"] == "high"
    assert body["escalates"] is True
    assert captured_payloads[0]["channel"] == "call_live"
    assert captured_payloads[0]["redacted_text"].startswith("Sunt de la bancă")
    assert "transcript_redacted" not in body
    assert "[iban]" not in json.dumps(body, ensure_ascii=False)


def test_audio_semantic_review_sends_relevant_scam_context_to_mistral(monkeypatch):
    captured_payloads = []

    def fake_mistral(payload):
        captured_payloads.append(payload)
        return {
            "risk_class": "high",
            "claim_matches_known_scam_family": True,
            "matched_family": "CONV_TRUSTED_CONTACT_MONEY_URGENCY",
            "reason_codes": ["semantic:trusted_contact_money_urgency"],
            "social_engineering": {
                "intent": "urgent_money_transfer",
                "ask_present": True,
                "ask_type": ["transfer"],
                "levers": ["trusted_contact", "urgency", "secrecy"],
                "confidence": 0.92,
            },
        }

    monkeypatch.setattr(audio_semantic_review, "PRIVACY_SAFE_MODE", False, raising=False)
    monkeypatch.setattr(audio_semantic_review, "ENABLE_MISTRAL_SEMANTIC_PILLAR", True, raising=False)
    monkeypatch.setattr(audio_semantic_review, "MISTRAL_SEMANTIC_API_KEY", "test-key", raising=False)
    monkeypatch.setattr(audio_semantic_review, "_call_mistral_semantic_review", fake_mistral)

    client = TestClient(app_main.app)
    response = client.post(
        "/v1/audio/semantic-review",
        json={
            "transcript_redacted": "Sunt Mihai colegul tau. Am nevoie urgent de bani si nu spune nimanui.",
            "channel": "call_live",
            "local_verdict": "UNVERIFIED",
            "local_reason_codes": ["residual"],
        },
    )

    assert response.status_code == 200
    payload = captured_payloads[0]
    context = payload["audio_scam_context"]
    family_ids = {item["id"] for item in context["candidate_families"]}

    assert "CONV_TRUSTED_CONTACT_MONEY_URGENCY" in family_ids
    assert "CONV_BANK_SAFE_ACCOUNT" not in family_ids
    assert context["recall_first"] is True
    assert context["anti_downgrade"] == "mistral_may_escalate_only"
    assert "Sunt Mihai" not in json.dumps(context, ensure_ascii=False)


def test_audio_semantic_review_sends_bank_antifraud_context_for_tiny_asr(monkeypatch):
    captured_payloads = []

    def fake_mistral(payload):
        captured_payloads.append(payload)
        return {
            "risk_class": "medium",
            "claim_matches_known_scam_family": True,
            "matched_family": "CONV_BANK_ANTI_FRAUD_CALL",
            "reason_codes": ["semantic:bank_antifraud_call"],
            "social_engineering": {
                "intent": "bank_security_call",
                "ask_present": False,
                "ask_type": [],
                "levers": ["financial_authority", "partial_transcript"],
                "confidence": 0.83,
            },
        }

    monkeypatch.setattr(audio_semantic_review, "PRIVACY_SAFE_MODE", False, raising=False)
    monkeypatch.setattr(audio_semantic_review, "ENABLE_MISTRAL_SEMANTIC_PILLAR", True, raising=False)
    monkeypatch.setattr(audio_semantic_review, "MISTRAL_SEMANTIC_API_KEY", "test-key", raising=False)
    monkeypatch.setattr(audio_semantic_review, "_call_mistral_semantic_review", fake_mistral)

    client = TestClient(app_main.app)
    response = client.post(
        "/v1/audio/semantic-review",
        json={
            "transcript_redacted": "Bu nezioa, văsun din partea bănsin, departamentul anti-fraude.",
            "channel": "call_live",
            "local_verdict": "SUSPECT",
            "local_reason_codes": ["campaign_match_only"],
            "arc_family": "CONV_BANK_ANTI_FRAUD_CALL",
        },
    )

    assert response.status_code == 200
    payload = captured_payloads[0]
    context = payload["audio_scam_context"]
    family_ids = {item["id"] for item in context["candidate_families"]}

    assert "CONV_BANK_ANTI_FRAUD_CALL" in family_ids
    assert context["local_family_hint"] == "CONV_BANK_ANTI_FRAUD_CALL"
    assert "campaign_match_only" in context["local_reason_codes"]
    assert "Bu nezioa" not in json.dumps(context, ensure_ascii=False)


def test_audio_semantic_review_sends_creditline_context_for_tiny_asr(monkeypatch):
    captured_payloads = []

    def fake_mistral(payload):
        captured_payloads.append(payload)
        return {
            "risk_class": "medium",
            "claim_matches_known_scam_family": True,
            "matched_family": "CONV_BANK_FRAUDULENT_CREDIT",
            "reason_codes": ["semantic:credit_offer_call"],
        }

    monkeypatch.setattr(audio_semantic_review, "PRIVACY_SAFE_MODE", False, raising=False)
    monkeypatch.setattr(audio_semantic_review, "ENABLE_MISTRAL_SEMANTIC_PILLAR", True, raising=False)
    monkeypatch.setattr(audio_semantic_review, "MISTRAL_SEMANTIC_API_KEY", "test-key", raising=False)
    monkeypatch.setattr(audio_semantic_review, "_call_mistral_semantic_review", fake_mistral)

    client = TestClient(app_main.app)
    response = client.post(
        "/v1/audio/semantic-review",
        json={
            "transcript_redacted": "Bu nezioa, văsun din parte acreditline Romania. Avem o veste buna.",
            "channel": "audio_share",
            "local_verdict": "SUSPECT",
            "local_reason_codes": ["campaign_match_only"],
            "arc_family": "CONV_BANK_FRAUDULENT_CREDIT",
        },
    )

    assert response.status_code == 200
    context = captured_payloads[0]["audio_scam_context"]
    family_ids = {item["id"] for item in context["candidate_families"]}

    assert "CONV_BANK_FRAUDULENT_CREDIT" in family_ids
    assert context["local_family_hint"] == "CONV_BANK_FRAUDULENT_CREDIT"
    assert "acreditline" not in json.dumps(context, ensure_ascii=False)


def test_audio_semantic_review_sends_marketplace_context_to_mistral(monkeypatch):
    captured_payloads = []

    def fake_mistral(payload):
        captured_payloads.append(payload)
        return {
            "risk_class": "high",
            "claim_matches_known_scam_family": True,
            "matched_family": "CONV_MARKETPLACE_RECEIVE_MONEY",
            "reason_codes": ["semantic:marketplace_receive_money_card"],
        }

    monkeypatch.setattr(audio_semantic_review, "PRIVACY_SAFE_MODE", False, raising=False)
    monkeypatch.setattr(audio_semantic_review, "ENABLE_MISTRAL_SEMANTIC_PILLAR", True, raising=False)
    monkeypatch.setattr(audio_semantic_review, "MISTRAL_SEMANTIC_API_KEY", "test-key", raising=False)
    monkeypatch.setattr(audio_semantic_review, "_call_mistral_semantic_review", fake_mistral)

    client = TestClient(app_main.app)
    response = client.post(
        "/v1/audio/semantic-review",
        json={
            "transcript_redacted": (
                "Sunt cumparatorul de pe OLX. Ca sa primesti banii, intra pe linkul de livrare "
                "si introdu datele cardului."
            ),
            "channel": "audio_share",
            "local_verdict": "SUSPECT",
            "local_reason_codes": ["campaign_match_only"],
            "arc_family": "CONV_MARKETPLACE_RECEIVE_MONEY",
        },
    )

    assert response.status_code == 200
    context = captured_payloads[0]["audio_scam_context"]
    family_ids = {item["id"] for item in context["candidate_families"]}

    assert "CONV_MARKETPLACE_RECEIVE_MONEY" in family_ids
    assert context["local_family_hint"] == "CONV_MARKETPLACE_RECEIVE_MONEY"
    assert "OLX" not in json.dumps(context, ensure_ascii=False)


def test_audio_semantic_review_context_covers_research_v2_families(monkeypatch):
    expected = {
        "CONV_BANK_SAFE_ACCOUNT",
        "CONV_AUTHORITY_IMPERSONATION_LEGAL_THREAT",
        "CONV_TECH_SUPPORT_REMOTE_ACCESS",
        "CONV_REFUND_OVERPAYMENT_REVERSAL",
        "CONV_VOICE_CLONE_EMERGENCY_IMPERSONATION",
        "CONV_DELIVERY_CUSTOMS_RELEASE_FEE",
        "CONV_TELECOM_OPERATOR_ACCOUNT_TAKEOVER",
        "CONV_UTILITIES_DISCONNECTION_PAYMENT",
        "CONV_PRIZE_RELEASE_FEE",
        "CONV_RECOVERY_SCAM",
        "CONV_JOB_TASK_ADVANCE_PAYMENT",
        "CONV_MARKETPLACE_RECEIVE_MONEY",
    }

    seen = set()
    for family_id in expected:
        context = build_audio_scam_context(
            "generic redacted text",
            local_family=family_id,
            local_reason_codes=["campaign_match_only"],
            max_families=1,
        )
        seen.update(item["id"] for item in context["candidate_families"])

    assert expected <= seen


def test_audio_semantic_review_falls_back_without_green_claim(monkeypatch):
    def failing_mistral(_payload):
        raise RuntimeError("mistral down")

    monkeypatch.setattr(audio_semantic_review, "PRIVACY_SAFE_MODE", False, raising=False)
    monkeypatch.setattr(audio_semantic_review, "ENABLE_MISTRAL_SEMANTIC_PILLAR", True, raising=False)
    monkeypatch.setattr(audio_semantic_review, "MISTRAL_SEMANTIC_API_KEY", "test-key", raising=False)
    monkeypatch.setattr(audio_semantic_review, "_call_mistral_semantic_review", failing_mistral)

    client = TestClient(app_main.app)
    response = client.post(
        "/v1/audio/semantic-review",
        json={
            "transcript_redacted": "[redactat]",
            "channel": "audio_share",
            "local_verdict": "SUSPECT",
            "local_reason_codes": ["value_request_needs_verification"],
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "fallback"
    assert body["semantic_review"]["risk_class"] == "medium"
    assert body["semantic_review"]["source"] == "audio_local_fallback"
    assert body["escalates"] is False
    assert "semantic:mistral_fallback" in body["semantic_review"]["reason_codes"]
    assert "Sigur" not in json.dumps(body, ensure_ascii=False)


def test_audio_semantic_review_uses_full_scam_atlas_when_mistral_unavailable(monkeypatch):
    monkeypatch.setattr(audio_semantic_review, "PRIVACY_SAFE_MODE", False, raising=False)
    monkeypatch.setattr(audio_semantic_review, "ENABLE_MISTRAL_SEMANTIC_PILLAR", False, raising=False)
    monkeypatch.setattr(audio_semantic_review, "MISTRAL_SEMANTIC_API_KEY", "", raising=False)

    client = TestClient(app_main.app)
    response = client.post(
        "/v1/audio/semantic-review",
        json={
            "transcript_redacted": (
                "Sunt de la banca. Mutati banii intr-un cont sigur si nu spuneti nimanui. "
                "Codul primit prin SMS trebuie comunicat acum."
            ),
            "channel": "call_live",
            "local_verdict": "SUSPECT",
            "local_reason_codes": ["campaign_match_only"],
            "arc_family": "CONV_BANK_ANTI_FRAUD_CALL",
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "fallback"
    assert body["semantic_review"]["source"] == "scam_atlas_structured"
    assert body["semantic_review"]["risk_class"] == "high"
    assert body["escalates"] is True
    assert "raw_audio_received" in json.dumps(body, ensure_ascii=False)
    assert "Mutati banii" not in json.dumps(body, ensure_ascii=False)


def test_audio_semantic_review_never_lets_mistral_medium_downgrade_atlas_high(monkeypatch):
    captured_payloads = []

    def fake_mistral(payload):
        captured_payloads.append(payload)
        return {
            "risk_class": "medium",
            "claim_matches_known_scam_family": True,
            "matched_family": "CONV_BANK_ANTI_FRAUD_CALL",
            "reason_codes": ["semantic:bank_antifraud_intro_only"],
        }

    monkeypatch.setattr(audio_semantic_review, "PRIVACY_SAFE_MODE", False, raising=False)
    monkeypatch.setattr(audio_semantic_review, "ENABLE_MISTRAL_SEMANTIC_PILLAR", True, raising=False)
    monkeypatch.setattr(audio_semantic_review, "MISTRAL_SEMANTIC_API_KEY", "test-key", raising=False)
    monkeypatch.setattr(audio_semantic_review, "_call_mistral_semantic_review", fake_mistral)

    client = TestClient(app_main.app)
    response = client.post(
        "/v1/audio/semantic-review",
        json={
            "transcript_redacted": (
                "Sunt de la suport tehnic bancar. Instalati aplicatia de suport pentru "
                "diagnoza la distanta in mobile banking."
            ),
            "channel": "audio_share",
            "local_verdict": "SUSPECT",
            "local_reason_codes": ["campaign_match_only"],
            "arc_family": "CONV_TECH_SUPPORT_REMOTE_ACCESS",
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert captured_payloads
    assert captured_payloads[0]["atlas_semantic_review"]["risk_class"] == "high"
    assert body["semantic_review"]["risk_class"] == "high"
    assert body["semantic_review"]["source"] == "scam_atlas_structured"
    assert body["escalates"] is True
