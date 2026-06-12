import json
from pathlib import Path

from services.scam_atlas import ScamAtlasEngine


ROOT = Path(__file__).resolve().parent.parent
OP_IMP_FIXTURES = (
    ROOT
    / "docs"
    / "fable_handoff"
    / "2026-06-12_scam_atlas_legal"
    / "op_imp_impersonation_atlas_cleaned.json"
)


def _op_imp_examples() -> list[dict]:
    payload = json.loads(OP_IMP_FIXTURES.read_text(encoding="utf-8"))
    return payload["examples"]


def test_impersonation_atlas_examples_are_runtime_covered():
    engine = ScamAtlasEngine()

    misses = []
    for example in _op_imp_examples():
        result = engine.analyze(example["text"], [])
        semantic_review = result.get("evidence", {}).get("semantic_review", {})
        detected_family = str(result.get("detected_family_id") or "")
        risk_class = str(semantic_review.get("risk_class") or "")

        if detected_family == "unknown-scam" or risk_class not in {"medium", "high"}:
            misses.append(
                {
                    "expected_family": example["family"],
                    "detected_family": detected_family,
                    "risk_class": risk_class,
                    "confidence": result.get("confidence"),
                    "text": example["text"],
                }
            )

    assert misses == []


def test_impersonation_runtime_seed_has_canonical_imp_block():
    ids = {family["id"] for family in ScamAtlasEngine().families}

    for family_id in [f"IMP-{index:02d}" for index in range(1, 13)]:
        assert family_id in ids


def test_impersonation_gap_cases_prefer_canonical_runtime_family():
    engine = ScamAtlasEngine()
    exact_family_cases = {
        "IMP-04",
        "IMP-07",
        "IMP-10",
        "IMP-11",
        "IMP-12",
    }

    for example in _op_imp_examples():
        if example["family"] not in exact_family_cases:
            continue

        result = engine.analyze(example["text"], [])

        assert result["detected_family_id"] == example["family"]
