"""Deterministic replay guard for the 2026-07-09 SE hallucination incident.

A benign Romanian text ("Ti-am trimis codul de la interfon pe WhatsApp, e 4821,
ne vedem sus." -- someone sending a friend the intercom code) was escalated to
DANGEROUS on live prod (revision sigurscan-api-00181-c57, scan
orch_WkcpqELTsvxlXm-dshuMLCHhKnjHcBdW). Root cause chain:

1. Mistral's semantic pillar hallucinated the SE signal (intent=impersonation,
   ask_type=[otp], ask_present=true, levers=[authority,urgency], confidence 0.8)
   on ~1 in 5 identical calls (temperature=0 -- provider-side nondeterminism).
   The local extractor correctly said unknown/0.15 every time.
2. _normalize_model_social_engineering_signal merges local+model with
   max()/OR/union ("most alarming wins"), so the solo hallucination survived.
3. verdict_gate's impersonation_with_authority_ask promotion (Rule 4b) turned it
   into DANGEROUS 88 with zero local corroboration.

The guard (SE_GATE_IMPERSONATION_REQUIRES_LOCAL_CORROBORATION, default ON)
requires the RAW local signal (bundle["_se_signals_raw"]["local"], attached in
provider_gate) to independently corroborate before that promotion may fire.

DETERMINISTIC BY CONSTRUCTION: these tests replay the actual captured
decision_bundle from the dangerous prod run -- Mistral is not in the loop, so
the 1-in-5 stochasticity cannot flake the suite. This also sidesteps the
structural blindness of the offline-runner FP corpus, which runs with the
Mistral pillar disabled and can never exercise a model-only fabrication.
"""

import copy

import services.verdict_gate as verdict_gate
from services.verdict_gate import verdict


# Verbatim decision_bundle captured from the DANGEROUS prod response
# (orch_WkcpqELTsvxlXm-dshuMLCHhKnjHcBdW, 2026-07-09). Only the payload of a
# single scan -- no secrets, no PII (synthetic-ish benign text typed by us).
HALLUCINATED_PROD_BUNDLE = {
    "input": {
        "type": "android_native",
        "redacted_text": "Ti-am trimis codul de la interfon pe WhatsApp, e 4821, ne vedem sus.",
    },
    "schema": "sigurscan_evidence_bundle_v2",
    "context": {
        "urgency": False,
        "intent_analysis": {
            "source": "mistral_intent_analysis",
            "status": "done",
            "confidence": 0.9,
            "fallback_source": "local_request_intent_v1",
            "protective_warning": False,
            "descriptive_context": False,
            "negation_scope_resolved": True,
            "positive_action_request": True,
            "invoice_or_payment_document": False,
            "payment_instruction_present": False,
            "describes_fraud_without_request": False,
            "payment_instruction_is_requested": False,
            "payment_instruction_is_descriptive": False,
        },
        "passive_payment": False,
        "non_http_deeplink": {
            "count": 0,
            "present": False,
            "schemes": [],
            "preview_supported": False,
        },
        "cross_scan_knowledge": {
            "fraud_flags": [],
            "brand_never_asks": {
                "brand_ids": [],
                "source_refs": [],
                "source_channel": "android_native",
                "violated_never_asks": [],
            },
            "b2b_invoice_signals": {"flags": [], "metadata": {}, "warnings": []},
            "payment_destinations": [],
        },
        "apk_or_remote_mention": False,
    },
    "request": {
        "channel": "reply",
        "sensitive": "none",
        "completeness": True,
        "protective_warning": False,
        "descriptive_context": False,
        "positive_action_request": True,
    },
    "identity": {
        "status": "unknown",
        "completeness": True,
        "claimed_brand": "WhatsApp",
        "tld_suspicious": False,
        "brand_token_mismatch": None,
    },
    "providers": {"hits": [], "verdict": "unknown", "completeness": True},
    "provenance": {
        "provenance": "unknown",
        "manifest_id": None,
        "evidence_power": "none",
        "manifest_version": "btr-ro-2026.06.16",
        "official_domain_match": False,
    },
    "resolution": {"status": "not_required", "final_url": None, "completeness": True},
    "evidence_hash": "sha256:64d2f124a81beda70f9c063b0acdeb61424ed68f376805a6b7a93942cae69f25",
    "_se_signals_raw": {
        "local": {
            "model": "local_social_engineering_v1",
            "intent": "unknown",
            "levers": [],
            "status": "done",
            "ask_type": ["none"],
            "confidence": 0.15,
            "provenance": "pipeline_only",
            "ask_present": False,
            "urgency_score": 0.0,
            "channel_coherence": "unknown",
            "persona_targeting": "generic",
        },
        "model": {
            "model": "mistral_semantic_pillar",
            "intent": "impersonation",
            "levers": ["authority", "urgency"],
            "status": "done",
            "ask_type": ["otp", "none"],
            "confidence": 0.8,
            "provenance": "pipeline_only",
            "ask_present": True,
            "urgency_score": 0.7,
            "channel_coherence": "coherent",
            "persona_targeting": "generic",
        },
        "source_channel": "android_native",
    },
    "semantic_review": {
        "source": "mistral_semantic_pillar",
        "status": "done",
        "confidence": None,
        "risk_class": "medium",
        "completeness": True,
        "reason_codes": ["semantic:medium", "family:imp-08", "semantic:mistral_pillar"],
        "matched_family": "IMP-08",
        "fallback_source": "scam_atlas_structured",
        "intent_analysis": {
            "source": "mistral_intent_analysis",
            "status": "done",
            "confidence": 0.9,
            "fallback_source": None,
            "protective_warning": False,
            "descriptive_context": False,
            "negation_scope_resolved": True,
            "positive_action_request": True,
            "invoice_or_payment_document": False,
            "payment_instruction_present": False,
            "describes_fraud_without_request": False,
            "payment_instruction_is_requested": False,
            "payment_instruction_is_descriptive": False,
        },
        "matched_template": None,
        "claim_matches_legit_template": False,
        "claim_matches_known_scam_family": True,
    },
    # The MERGED signal the gate reads: Mistral's hallucination survived the
    # max()/OR/union merge verbatim (local contributed nothing to it).
    "social_engineering": {
        "model": "mistral_semantic_pillar",
        "intent": "impersonation",
        "levers": ["authority", "urgency"],
        "status": "done",
        "ask_type": ["otp", "none"],
        "confidence": 0.8,
        "provenance": "pipeline_only",
        "ask_present": True,
        "urgency_score": 0.7,
        "channel_coherence": "coherent",
        "persona_targeting": "generic",
    },
}


def _bundle():
    return copy.deepcopy(HALLUCINATED_PROD_BUNDLE)


def test_hallucinated_prod_bundle_does_not_reach_dangerous():
    """Condition 1: replaying the exact prod bundle must not produce DANGEROUS."""
    result = verdict(_bundle())
    assert result["label"] != "DANGEROUS", result
    assert "social_engineering_high_confidence_intent" not in (result.get("reason_codes") or []), result
    # Not a silent miss either: benign-but-unproven must stay in the warn band.
    assert result["label"] in {"SUSPECT", "UNVERIFIED"}, result


def test_corroborated_impersonation_still_escalates():
    """Condition 2 (non-regression): a real fake-Police/ANAF shape -- same merged
    signal but the LOCAL extractor independently agrees -- must stay DANGEROUS.
    The guard must not weaken the class the promotion was built for."""
    bundle = _bundle()
    bundle["_se_signals_raw"]["local"] = {
        "model": "local_social_engineering_v1",
        "intent": "impersonation",
        "levers": ["authority"],
        "status": "done",
        "ask_type": ["personal_data"],
        "confidence": 0.8,
        "provenance": "pipeline_only",
        "ask_present": True,
        "urgency_score": 0.6,
        "channel_coherence": "unknown",
        "persona_targeting": "generic",
    }
    result = verdict(bundle)
    assert result["label"] == "DANGEROUS", result
    assert "social_engineering_high_confidence_intent" in (result.get("reason_codes") or []), result


def test_kill_switch_restores_pre_guard_behavior(monkeypatch):
    """Flag OFF reproduces the incident (DANGEROUS on the hallucinated bundle):
    proves the guard is the only thing standing between the hallucination and a
    false-PERICOL, and that the kill switch actually works."""
    monkeypatch.setattr(
        verdict_gate, "SE_GATE_IMPERSONATION_REQUIRES_LOCAL_CORROBORATION", False
    )
    result = verdict(_bundle())
    assert result["label"] == "DANGEROUS", result
    assert "social_engineering_high_confidence_intent" in (result.get("reason_codes") or []), result


def test_core_dangerous_intents_unaffected_by_missing_corroboration():
    """Scoping: the guard applies ONLY to the impersonation promotion. A core
    dangerous intent (credential_theft) with no local corroboration escalates
    exactly as before."""
    bundle = _bundle()
    bundle["social_engineering"]["intent"] = "credential_theft"
    result = verdict(bundle)
    assert result["label"] == "DANGEROUS", result
    assert "social_engineering_high_confidence_intent" in (result.get("reason_codes") or []), result


def test_missing_raw_signals_sidechannel_fails_closed_to_no_promotion():
    """Robustness: if _se_signals_raw is absent (older bundle shape / projection),
    the promotion is withheld (no corroboration evidence) rather than granted."""
    bundle = _bundle()
    del bundle["_se_signals_raw"]
    result = verdict(bundle)
    assert result["label"] != "DANGEROUS", result
