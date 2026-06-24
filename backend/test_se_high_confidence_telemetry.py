"""Observable-only telemetry on the social_engineering_high_confidence_intent
branch. Guards: (1) the side-channel never changes a verdict, (2) the single emit
helper produces the full event schema, separating Mistral vs local sub-signals.
"""

import services.telemetry as telemetry
from services.verdict_gate import verdict


def _se_bundle(sensitive="otp", channel="unknown"):
    return {
        "social_engineering": {
            "status": "done", "intent": "credential_theft", "ask_present": True,
            "confidence": 0.9, "levers": ["authority"], "ask_type": ["account_login"],
        },
        "request": {"sensitive": sensitive, "channel": channel, "positive_action_request": True},
        "semantic_review": {"status": "done", "completeness": True},
        "resolution": {"status": "resolved", "completeness": True},
        "providers": {"verdict": "clean", "completeness": True},
        "identity": {"status": "unknown"},
    }


def test_se_signals_raw_does_not_change_verdict():
    # verdict_gate must ignore the observable-only side-channel: same input with
    # and without `_se_signals_raw` => bit-identical result.
    base = _se_bundle()
    without = verdict(dict(base))
    with_raw = dict(base)
    with_raw["_se_signals_raw"] = {
        "local": {"intent": "credential_theft", "confidence": 0.9},
        "model": {"intent": "credential_theft", "confidence": 0.95},
        "source_channel": "push",
    }
    assert verdict(with_raw) == without


def _decision_bundle(local, model, *, sensitive="none", channel="reply", source_channel="push"):
    return {
        "request": {"sensitive": sensitive, "channel": channel, "positive_action_request": True},
        "identity": {"status": "unknown"},
        "provenance": {},
        "providers": {"verdict": "clean"},
        "_se_signals_raw": {"local": local, "model": model, "source_channel": source_channel},
    }


def _capture(monkeypatch):
    events = []
    monkeypatch.setattr(telemetry, "log_scan_event", lambda payload: events.append(payload))
    return events


REQUIRED_FIELDS = {
    "event", "mistral_label", "mistral_confidence", "local_label", "local_confidence",
    "classifiers_agree", "hard_sensitive", "hard_sensitive_token", "value_sensitive",
    "positive_action_request", "channel_raw", "channel_mapped", "wrong_channel",
    "has_provenance", "provenance_clean", "final_verdict", "scan_id", "revision",
}


def test_helper_emits_full_schema_with_agreement(monkeypatch):
    events = _capture(monkeypatch)
    bundle = _decision_bundle(
        local={"intent": "credential_theft", "confidence": 0.85},
        model={"intent": "credential_theft", "confidence": 0.95},
    )
    telemetry.log_se_high_confidence_fire(bundle, {"label": "DANGEROUS"}, scan_id="scan-1")
    assert len(events) == 1
    e = events[0]
    assert REQUIRED_FIELDS.issubset(e.keys()), REQUIRED_FIELDS - set(e.keys())
    assert e["event"] == "se_high_confidence_fire"
    assert e["mistral_label"] == "credential_theft"
    assert e["local_label"] == "credential_theft"
    assert e["classifiers_agree"] is True
    assert e["final_verdict"] == "DANGEROUS"
    assert e["scan_id"] == "scan-1"


def test_helper_mistral_null_when_offline(monkeypatch):
    events = _capture(monkeypatch)
    # Offline: no Mistral sub-signal -> mistral fields null, agreement False.
    bundle = _decision_bundle(local={"intent": "credential_theft", "confidence": 0.85}, model={})
    telemetry.log_se_high_confidence_fire(bundle, {"label": "DANGEROUS"})
    e = events[0]
    assert e["mistral_label"] is None
    assert e["mistral_confidence"] is None
    assert e["classifiers_agree"] is False


def test_helper_flags_classifier_disagreement_fp_shape(monkeypatch):
    events = _capture(monkeypatch)
    # FP candidate: Mistral fires SE-high, local does not agree.
    bundle = _decision_bundle(
        local={"intent": "benign", "confidence": 0.2},
        model={"intent": "credential_theft", "confidence": 0.95},
    )
    telemetry.log_se_high_confidence_fire(bundle, {"label": "DANGEROUS"})
    e = events[0]
    assert e["classifiers_agree"] is False
    assert e["mistral_label"] == "credential_theft"
    assert e["local_label"] == "benign"
