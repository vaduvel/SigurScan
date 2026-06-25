"""RO recall regression — real RO scam corpus (2025-2026) with provenance.

Hard senior guardrails (see PR discussion):
- Assertions run ONLY on the DETERMINISTIC floor (offline _run_case, providers +
  Mistral OFF). Live-Mistral behaviour is non-deterministic and is tracked via
  telemetry/shadow, never as a hard pass/fail here.
- HARD_FLOOR cases: the deterministic path already catches them (flagged =
  SUSPECT or DANGEROUS) and must keep doing so (recall regression guard).
- KNOWN_GAP cases: real text-evident misses the engine does NOT yet catch
  deterministically -> xfail(strict). When a fix lands, the xfail flips to a pass
  and the marker is removed (clean before/after evidence, TDD-style).
- INDICATOR_ONLY cases: the danger lives in a <LINK>/QR/IBAN that is
  <NEEDS_LIVE_CAPTURE>; text-only cannot assert detection -> not in the hard floor.
- NON_MESSAGE cases: press descriptions / quoted fragments, not real messages ->
  kept in the corpus for provenance but excluded from any assertion.

Provenance: backend/eval/ro_recall_corpus.json + ro_recall_corpus_v2.json are the
REAL, sourced corpus. No synthetic indicators are injected here.
"""

import json
import os
from pathlib import Path

import pytest

import eval.large_offline_fixture_runner as runner

_EVAL = Path(__file__).resolve().parent / "eval"
_CH = {"voce": "phone_call", "sms": "sms", "email": "email", "qr": "qr_scan", "app": "app",
       "whatsapp": "whatsapp", "telegram": "telegram", "chat": "chat"}

# case_id -> mode. Default for v1 corpus is HARD_FLOOR unless overridden here.
MODE = {
    # ---- v1 corpus ----
    "OSIM_INVOICE-001": "KNOWN_GAP",       # P0 protected, missed offline+live (fix incoming)
    "BANK_PHISH-001": "KNOWN_GAP",
    "FAKE_APP-001": "KNOWN_GAP",
    "RECOVERY_SCAM-001": "KNOWN_GAP",      # offline UNVERIFIED / live DANGEROUS (Mistral, non-det)
    "PIG_BUTCHERING-001": "KNOWN_GAP",     # grooming, no ask yet
    "DELIVERY_SMISH-002": "INDICATOR_ONLY",
    "QUISH_PARKING-001": "INDICATOR_ONLY",
    # ---- v2 corpus ----
    "RO-SCAM-2025-002": "HARD_FLOOR",
    "RO-SCAM-2026-014": "HARD_FLOOR",
    "RO-SCAM-2026-008": "HARD_FLOOR",      # caught as SUSPECT (flagged)
    "RO-SCAM-2026-016": "HARD_FLOOR",
    "RO-SCAM-2025-020": "HARD_FLOOR",
    "RO-SCAM-2025-006": "KNOWN_GAP",
    "RO-SCAM-2025-010": "KNOWN_GAP",       # "where do you bank / balances" identity harvest
    "RO-SCAM-2026-017": "KNOWN_GAP",
    "RO-SCAM-2026-018": "KNOWN_GAP",
    "RO-SCAM-2026-019": "KNOWN_GAP",
    "RO-SCAM-2026-003": "INDICATOR_ONLY",
    "RO-SCAM-2026-004": "INDICATOR_ONLY",
    "RO-SCAM-2025-005": "INDICATOR_ONLY",
    "RO-SCAM-2025-001": "INDICATOR_ONLY",  # social vote: danger is the link
    "RO-SCAM-2025-007": "NON_MESSAGE",     # subject-line fragment
    "RO-SCAM-2025-009": "NON_MESSAGE",     # scenario description
    "RO-SCAM-2025-011": "NON_MESSAGE",     # police narrative
    "RO-SCAM-2025-012": "NON_MESSAGE",     # description
    "RO-SCAM-2026-013": "NON_MESSAGE",     # news warning text, not the SMS
    "RO-SCAM-2025-015": "NON_MESSAGE",     # phrase fragment
}


def _load():
    cases = []
    for fn in ("ro_recall_corpus.json", "ro_recall_corpus_v2.json"):
        path = _EVAL / fn
        if path.exists():
            cases.extend(json.loads(path.read_text(encoding="utf-8")))
    return cases


def _verdict(case):
    sc = _CH.get(case["channel"], case["channel"])
    env = {
        "PRIVACY_SAFE_MODE": "false", "ENABLE_CLOUD_AI_EXPLANATION": "false",
        "ENABLE_MISTRAL_SHADOW_ADJUDICATION": "false", "ENABLE_DNS_REPUTATION": "false",
        "INVOICE_CACHE_HMAC_KEY": "ci-test-hmac-key",
    }
    for k, v in env.items():
        os.environ.setdefault(k, v)
    r = runner._run_case({"id": case["case_id"], "text": case["text"], "expected": case["expected"],
                          "source": "ro_recall", "meta": {"input_type": sc}})
    return r.get("actual")


_CASES = _load()
_HARD = [c for c in _CASES if MODE.get(c["case_id"], "HARD_FLOOR") == "HARD_FLOOR"]
_GAP = [c for c in _CASES if MODE.get(c["case_id"]) == "KNOWN_GAP"]


def test_corpus_loaded():
    assert len(_CASES) >= 40, f"expected both corpora, got {len(_CASES)}"


@pytest.mark.parametrize("case", _HARD, ids=lambda c: c["case_id"])
def test_hard_floor_recall_holds(case):
    # Deterministic floor must keep flagging these real scams (SUSPECT or DANGEROUS).
    actual = _verdict(case)
    assert actual in {"DANGEROUS", "SUSPECT"}, f"{case['case_id']} recall regressed -> {actual}"


@pytest.mark.parametrize("case", _GAP, ids=lambda c: c["case_id"])
@pytest.mark.xfail(strict=True, reason="known deterministic recall gap; fix flips this to pass")
def test_known_gap_recall(case):
    # These are real text-evident misses today. When the gap is fixed, the case
    # starts flagging deterministically and this xfail becomes an XPASS -> remove
    # the case from KNOWN_GAP. Strict xfail keeps us honest (no silent pass).
    actual = _verdict(case)
    assert actual in {"DANGEROUS", "SUSPECT"}, f"{case['case_id']} still a gap -> {actual}"
