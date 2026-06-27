import json

from fastapi.testclient import TestClient

import main as app_main
from services import audio_semantic_review


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
