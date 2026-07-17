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


def test_audio_semantic_review_samples_long_context_instead_of_prefix_only(monkeypatch):
    captured_payloads = []

    def fake_mistral(payload):
        captured_payloads.append(payload)
        return {
            "risk_class": "high",
            "claim_matches_known_scam_family": True,
            "matched_family": "CONV_BANK_SAFE_ACCOUNT",
            "reason_codes": ["semantic:safe_account"],
        }

    monkeypatch.setattr(audio_semantic_review, "PRIVACY_SAFE_MODE", False, raising=False)
    monkeypatch.setattr(audio_semantic_review, "ENABLE_MISTRAL_SEMANTIC_PILLAR", True, raising=False)
    monkeypatch.setattr(audio_semantic_review, "MISTRAL_SEMANTIC_API_KEY", "test-key", raising=False)
    monkeypatch.setattr(audio_semantic_review, "_call_mistral_semantic_review", fake_mistral)

    transcript = "\n\n".join(
        [
            "START_MARKER " + ("a" * 2_000),
            "MIDDLE_MARKER pretinde ca este de la banca " + ("b" * 2_000),
            "END_MARKER muta banii in contul sigur " + ("c" * 2_000),
        ]
    )
    client = TestClient(app_main.app)
    response = client.post(
        "/v1/audio/semantic-review",
        json={
            "transcript_redacted": transcript,
            "channel": "audio_share",
            "local_verdict": "SUSPECT",
            "local_reason_codes": ["campaign_match_only"],
            "coverage": {
                "status": "partial",
                "source_duration_ms": 600_000,
                "planned_duration_ms": 180_000,
                "transcribed_duration_ms": 90_000,
                "source_coverage_ratio": 0.3,
                "windows_planned": 6,
                "windows_transcribed": 3,
                "transcript_chars_total": len(transcript),
                "transcript_chars_sent": 2_500,
                "transcript_truncated": True,
            },
        },
    )

    assert response.status_code == 200
    sent = captured_payloads[0]["redacted_text"]
    assert len(sent) <= 2_500
    assert "START_MARKER" in sent
    assert "MIDDLE_MARKER" in sent
    assert "END_MARKER" in sent
    body = response.json()
    assert body["coverage"]["status"] == "partial"
    assert "semantic:audio_partial_coverage" in body["reason_codes"]
    assert body["semantic_review"]["risk_class"] == "high"


def test_audio_semantic_review_preserves_end_signal_with_many_windows(monkeypatch):
    captured_payloads = []

    def fake_mistral(payload):
        captured_payloads.append(payload)
        return {
            "risk_class": "high",
            "claim_matches_known_scam_family": True,
            "matched_family": "CONV_BANK_SAFE_ACCOUNT",
            "reason_codes": ["semantic:safe_account"],
        }

    monkeypatch.setattr(audio_semantic_review, "PRIVACY_SAFE_MODE", False, raising=False)
    monkeypatch.setattr(audio_semantic_review, "ENABLE_MISTRAL_SEMANTIC_PILLAR", True, raising=False)
    monkeypatch.setattr(audio_semantic_review, "MISTRAL_SEMANTIC_API_KEY", "test-key", raising=False)
    monkeypatch.setattr(audio_semantic_review, "_call_mistral_semantic_review", fake_mistral)

    transcript = "\n\n".join(
        ["START_MARKER " + ("a" * 500)]
        + [f"WINDOW_{index} " + ("x" * 500) for index in range(1, 99)]
        + ["END_MARKER spune codul si muta banii in contul sigur " + ("z" * 500)]
    )
    client = TestClient(app_main.app)
    response = client.post(
        "/v1/audio/semantic-review",
        json={
            "transcript_redacted": transcript,
            "channel": "audio_share",
            "local_verdict": "SUSPECT",
            "local_reason_codes": ["campaign_match_only"],
            "coverage": {"status": "partial", "windows_planned": 100},
        },
    )

    assert response.status_code == 200
    sent = captured_payloads[0]["redacted_text"]
    assert len(sent) <= 2_500
    assert "START_MARKER" in sent
    assert "WINDOW_50" in sent
    assert "END_MARKER" in sent


def test_audio_partial_coverage_never_downgrades_local_dangerous(monkeypatch):
    monkeypatch.setattr(audio_semantic_review, "PRIVACY_SAFE_MODE", True, raising=False)

    client = TestClient(app_main.app)
    response = client.post(
        "/v1/audio/semantic-review",
        json={
            "transcript_redacted": "Mută banii în [iban].",
            "channel": "audio_share",
            "local_verdict": "DANGEROUS",
            "local_reason_codes": ["sensitive_wrong_channel"],
            "coverage": {
                "status": "partial",
                "source_duration_ms": 600_000,
                "planned_duration_ms": 180_000,
                "source_coverage_ratio": 0.3,
                "windows_planned": 6,
                "windows_transcribed": 1,
            },
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["semantic_review"]["risk_class"] == "high"
    assert body["escalates"] is False
    assert "sensitive_wrong_channel" in body["reason_codes"]
    assert "semantic:audio_partial_coverage" in body["reason_codes"]
