"""Red->green guard for the social-engineering impersonation dead zone.

`impersonation` is only a build-up intent (-> SUSPECT) and the build-up branch
requires ask_present=False. So an authority/fear impersonation that makes a
concrete ask (fake Police/ANAF demanding identity data) lands in a dead zone:
not actionable (impersonation not in DANGEROUS_SOCIAL_ENGINEERING_INTENTS) and
not build-up (ask is present) -> no escalation. This file pins the fix:
impersonation + ask_present + authority/fear lever + confidence>=0.78 escalates,
while leaving the existing build-up branch untouched.

2026-07-09 amendment (live SE hallucination incident): the promotion additionally
requires LOCAL corroboration (SE_GATE_IMPERSONATION_REQUIRES_LOCAL_CORROBORATION,
default ON), because the merged signal it reads can be fabricated by Mistral alone
via the max()/OR/union merge. TP cases below now pass a corroborating local signal
-- on the real pipeline a genuine fake-Police/ANAF text fires the local extractor
too. test_se_impersonation_local_corroboration.py replays the actual hallucinated
prod bundle end-to-end.
"""

from services.verdict_gate import (
    _is_actionable_social_engineering,
    _is_social_engineering_build_up,
)


def _se(intent, ask_present, *, confidence=0.92, levers=("authority", "fear"), ask_type=("personal_data",)):
    return {
        "status": "done",
        "intent": intent,
        "ask_present": ask_present,
        "confidence": confidence,
        "ask_type": list(ask_type),
        "levers": list(levers),
    }


def _local_corroborating(confidence=0.8):
    return {"status": "done", "intent": "impersonation", "confidence": confidence}


def test_impersonation_with_authority_ask_is_actionable():
    # The fix: fake-authority impersonation that MAKES a concrete ask escalates --
    # when the local extractor independently corroborates (real fake-ANAF shape).
    assert _is_actionable_social_engineering(_se("impersonation", True), _local_corroborating()) is True


def test_impersonation_promotion_requires_local_corroboration():
    # 2026-07-09 incident guard: the same merged shape WITHOUT local corroboration
    # (local said unknown/0.15 -- Mistral-only hallucination) must NOT escalate.
    hallucinated_local = {"status": "done", "intent": "unknown", "confidence": 0.15}
    assert _is_actionable_social_engineering(_se("impersonation", True), hallucinated_local) is False
    assert _is_actionable_social_engineering(_se("impersonation", True), None) is False
    assert _is_actionable_social_engineering(_se("impersonation", True)) is False


def test_local_corroboration_needs_meaningful_confidence():
    # A local signal with a named intent but sub-threshold confidence is not
    # corroboration (0.68 bar, same as the build-up branch).
    weak_local = {"status": "done", "intent": "impersonation", "confidence": 0.4}
    assert _is_actionable_social_engineering(_se("impersonation", True), weak_local) is False
    assert _is_actionable_social_engineering(_se("impersonation", True), _local_corroborating(0.68)) is True


def test_impersonation_buildup_branch_unchanged():
    # Build-up (no ask) must stay SUSPECT-level: actionable False, build_up True.
    no_ask = _se("impersonation", False)
    assert _is_actionable_social_engineering(no_ask) is False
    assert _is_social_engineering_build_up(no_ask) is True


def test_impersonation_ask_without_authority_lever_not_actionable():
    # Only authority/fear impersonations escalate; a bare impersonation ask with
    # no authority/fear lever must NOT become actionable (keeps the gate tight).
    weak = _se("impersonation", True, levers=("liking",), ask_type=("none",))
    assert _is_actionable_social_engineering(weak) is False


def test_impersonation_ask_below_confidence_not_actionable():
    low = _se("impersonation", True, confidence=0.5)
    assert _is_actionable_social_engineering(low) is False


def test_existing_dangerous_intents_still_actionable():
    # Regression: the pre-existing dangerous intents must keep escalating.
    # Scoping proof: the local-corroboration guard applies ONLY to the widened
    # impersonation promotion -- core dangerous intents escalate with NO local
    # corroboration, exactly as before the 2026-07-09 guard.
    assert _is_actionable_social_engineering(_se("credential_theft", True)) is True
    assert _is_actionable_social_engineering(_se("payment_redirection", True)) is True
