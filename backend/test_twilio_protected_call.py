import json

from fastapi.testclient import TestClient

import main as app_main
from routers import twilio_voice


def test_twilio_incoming_returns_realtime_transcription_twiml(monkeypatch):
    monkeypatch.setenv("TWILIO_ALLOW_UNSIGNED_WEBHOOKS", "true")
    monkeypatch.setenv("TWILIO_PUBLIC_BASE_URL", "https://sigurscan.example")
    client = TestClient(app_main.app)

    response = client.post(
        "/v1/voice/twilio/incoming",
        data={"CallSid": "CA111", "From": "+40755111222"},
    )

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/xml")
    body = response.text
    assert "<Start>" in body
    assert "<Transcription" in body
    assert 'statusCallbackUrl="https://sigurscan.example/v1/voice/twilio/transcription"' in body
    assert 'languageCode="ro-RO"' in body
    assert 'partialResults="true"' in body
    assert "Apel protejat SigurScan" in body


def test_twilio_transcription_updates_session_without_exposing_transcript(monkeypatch):
    monkeypatch.setenv("TWILIO_ALLOW_UNSIGNED_WEBHOOKS", "true")

    async def fake_review(request):
        assert request.transcript_redacted
        assert "123456" not in request.transcript_redacted
        assert request.channel == "twilio_protected_call"
        return {
            "status": "done",
            "semantic_review": {
                "risk_class": "high",
                "matched_family": "CONV_BANK_SAFE_ACCOUNT",
                "reason_codes": ["semantic:safe_account", "semantic:otp_request"],
                "source": "mistral_semantic_pillar",
            },
            "reason_codes": ["semantic:safe_account", "semantic:otp_request"],
            "escalates": True,
            "privacy": {"raw_audio_received": False, "transcript_echoed": False},
        }

    monkeypatch.setattr(twilio_voice, "review_redacted_audio_transcript", fake_review)
    client = TestClient(app_main.app)

    response = client.post(
        "/v1/voice/twilio/transcription",
        data={
            "CallSid": "CA222",
            "TranscriptionEvent": "transcription-content",
            "TranscriptionData": json.dumps(
                {
                    "transcript": "Sunt de la banca, muta banii in cont sigur si spune codul 123456.",
                    "is_final": True,
                    "confidence": 0.94,
                }
            ),
        },
    )

    assert response.status_code == 200
    assert response.json()["accepted"] is True
    assert response.json()["latest_verdict"] == "DANGEROUS"

    status = client.get("/v1/voice/twilio/sessions/CA222")
    assert status.status_code == 200
    body = status.json()
    assert body["latest_verdict"] == "DANGEROUS"
    assert body["latest_risk_class"] == "high"
    assert body["chunks_received"] == 1
    assert body["privacy"]["raw_audio_stored"] is False
    assert body["privacy"]["transcript_echoed"] is False
    serialized = json.dumps(body, ensure_ascii=False).lower()
    assert "muta banii" not in serialized
    assert "123456" not in serialized


def test_twilio_webhook_rejects_missing_signature_when_auth_token_configured(monkeypatch):
    monkeypatch.setenv("TWILIO_AUTH_TOKEN", "test-auth-token")
    client = TestClient(app_main.app)

    response = client.post(
        "/v1/voice/twilio/transcription",
        data={"CallSid": "CA333", "TranscriptionEvent": "transcription-started"},
    )

    assert response.status_code == 403
    assert "twilio signature" in response.json()["detail"].lower()


def test_twilio_webhook_rejects_unsigned_requests_when_auth_token_missing(monkeypatch):
    monkeypatch.delenv("TWILIO_AUTH_TOKEN", raising=False)
    monkeypatch.delenv("TWILIO_ALLOW_UNSIGNED_WEBHOOKS", raising=False)
    client = TestClient(app_main.app)

    response = client.post(
        "/v1/voice/twilio/transcription",
        data={"CallSid": "CA444", "TranscriptionEvent": "transcription-started"},
    )

    assert response.status_code == 403
    assert "not configured" in response.json()["detail"].lower()
