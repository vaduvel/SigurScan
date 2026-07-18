import json
from pathlib import Path

import pytest

from services.action_asset import build_action_asset_contract
from services.protected_action_shadow import evaluate_protected_action_shadow


HOLDOUT_PATH = (
    Path(__file__).resolve().parent
    / "data"
    / "eval"
    / "action_asset_novel_holdout_v2026_07_18.jsonl"
)


def _cases():
    return [
        json.loads(line)
        for line in HOLDOUT_PATH.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


@pytest.mark.parametrize("case", _cases(), ids=lambda case: case["id"])
def test_novel_action_asset_holdout(case):
    assert case["provenance"] == "synthetic_adversarial_holdout"
    contract = build_action_asset_contract(case["text"], source_channel=case["channel"])
    shadow = evaluate_protected_action_shadow(
        contract,
        identity_status="unknown",
        actual_label="SAFE",
    )

    expected_action = case["expected_action"]
    if expected_action is None:
        assert contract["positive_request"] is False
        assert contract["requested_actions"] == []
    else:
        assert expected_action in contract["requested_actions"]
    assert shadow["candidate_min_label"] == case["expected_candidate"]
