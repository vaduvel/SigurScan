"""P-MORPH measured-recall gate for RO semantic scam-intent detection.

Why this exists
---------------
P-MORPH (services/ro_morphology.py) shipped the morphology *mechanism* but the
execution plan (§4) also required a **measured-recall gate before release** for
the semantic scam keywords (OTP, upfront fee, "cont sigur", eSIM, ...). Without
it, "the detector handles inflections" was an untested claim and any future
change to the keyword patterns / normalization could silently drop recall.

What it measures
----------------
A versioned corpus of realistic Romanian scam paraphrases (with morphological
variation: diacritics on/off, inflection, word order) is run through the
production semantic keyword detector
``ScamAtlasEngine.check_sensitive_requests`` + ``check_language_manipulation``.
A row is "recalled" when the detector emits a signal matching the row's
category.

The corpus freezes a ``currently_detected`` flag per row (the baseline at commit
time). This test then enforces two things:

1. **No regression** — every row detected at baseline must still be detected.
   If a pattern change drops one, CI fails.
2. **Overall recall floor** — aggregate recall must stay above a floor.

Rows with ``currently_detected == false`` are the in-repo morphology backlog:
paraphrases a human reads as obvious scams that the current (non-P-MORPH)
keyword layer misses — the concrete justification for wiring ro_morphology into
the semantic path later. Improvements are always allowed (they only raise
recall); regressions are not.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from services.scam_atlas import ScamAtlasEngine

CORPUS_PATH = (
    Path(__file__).resolve().parent
    / "data"
    / "eval"
    / "pmorph_recall_corpus_ro_v2026_07_08.jsonl"
)

# Minimum aggregate recall. Baseline at commit time is 0.766; the floor sits
# just under it so genuine regressions fail while morphology improvements pass.
MIN_OVERALL_RECALL = 0.75

# category -> signal substrings; a row is recalled when the union of detector
# signals contains any of these (case-insensitive substring match). Kept here,
# not in the corpus, so the corpus stays pure data.
CATEGORY_SIGNALS = {
    "OTP_CODE_REQUEST": ["Solicitare cod SMS/OTP", "Solicitare date sensibile"],
    "CARD_CREDENTIAL_REQUEST": ["Solicitare date sensibile"],
    "SAFE_ACCOUNT_TRANSFER": ["Solicitare de transfer de bani"],
    "REMOTE_ACCESS_APP": ["acces la distan"],
    "UPFRONT_FEE_PAYMENT": ["Solicitare de plat", "Solicitare de transfer de bani"],
    "REWARD_PROFIT_LURE": ["Promisiune de c"],
    "URGENCY_PRESSURE": ["sentiment artificial de urgen"],
    "DELIVERY_CUSTOMS_FEE": ["Pretext de livrare", "Solicitare de plat"],
    "SIM_SWAP_ESIM": ["impostur"],
    "WHATSAPP_CODE": ["cod de confirmare WhatsApp"],
}

_ENGINE = ScamAtlasEngine()


def _load_corpus():
    rows = []
    for line in CORPUS_PATH.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        obj = json.loads(line)
        if "_meta" in obj:
            continue
        rows.append(obj)
    return rows


def _is_recalled(category: str, text: str) -> bool:
    signals = _ENGINE.check_sensitive_requests(text) + _ENGINE.check_language_manipulation(text)
    joined = " || ".join(signals).lower()
    return any(sub.lower() in joined for sub in CATEGORY_SIGNALS[category])


CORPUS = _load_corpus()


def test_corpus_loads_and_categories_are_known():
    assert CORPUS, "recall corpus is empty"
    unknown = {row["category"] for row in CORPUS} - set(CATEGORY_SIGNALS)
    assert not unknown, f"corpus references unknown categories: {unknown}"


def test_no_recall_regression_on_baseline_detected_rows():
    """Every row detected at baseline must still be detected."""
    regressions = [
        row["text"]
        for row in CORPUS
        if row.get("currently_detected") and not _is_recalled(row["category"], row["text"])
    ]
    assert not regressions, (
        "P-MORPH recall REGRESSION: rows detected at baseline are no longer "
        f"flagged by the semantic detector:\n  - " + "\n  - ".join(regressions)
    )


def test_overall_recall_meets_floor():
    hits = sum(1 for row in CORPUS if _is_recalled(row["category"], row["text"]))
    recall = hits / len(CORPUS)
    assert recall >= MIN_OVERALL_RECALL, (
        f"overall semantic recall {recall:.3f} < floor {MIN_OVERALL_RECALL:.3f} "
        f"({hits}/{len(CORPUS)} paraphrases detected)"
    )
