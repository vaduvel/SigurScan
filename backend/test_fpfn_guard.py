"""R7-rest FP/FN guard — the anti-false-PERICOL safety net, in normal CI.

Runs the committed generic-path corpus through the offline provider gate and
enforces the two hard invariants (no benign->DANGEROUS, no scam->SAFE) plus a
soft scam-recall floor. This is the net that every later verdict-touching sprint
(D6 Felia 2, P-MORPH-WIRE, D3) is measured against.
"""

from eval.fpfn_guard import (
    MIN_SCAM_CAUGHT_RATE,
    compute_metrics,
    evaluate_corpus,
    load_corpus,
)

_ROWS = evaluate_corpus()
_METRICS = compute_metrics(_ROWS)


def test_corpus_has_both_classes():
    labels = {r["label"] for r in load_corpus()}
    assert labels == {"BENIGN", "SCAM"}
    assert _METRICS["benign_total"] >= 20
    assert _METRICS["scam_total"] >= 12


def test_zero_false_pericol_on_benign():
    """Cardinal sin: no benign message may be flagged DANGEROUS."""
    assert _METRICS["false_pericol_count"] == 0, (
        "FALSE-PERICOL regression on benign messages: "
        f"{_METRICS['false_pericol_examples']}"
    )


def test_zero_missed_scam():
    """No scam may pass as SAFE."""
    assert _METRICS["missed_scam_count"] == 0, (
        f"missed scam (FN) regression: {_METRICS['missed_scam_examples']}"
    )


def test_scam_recall_above_floor():
    assert _METRICS["scam_caught_rate"] >= MIN_SCAM_CAUGHT_RATE, (
        f"scam recall {_METRICS['scam_caught_rate']} < floor {MIN_SCAM_CAUGHT_RATE}"
    )
