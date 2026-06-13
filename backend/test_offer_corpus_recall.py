"""Recall pe corpusul de fixtures din cercetari (fable_handoff 2026-06-12).

BLOCANT per fixture: >=1 semnal asteptat detectat SI verdict != SIGUR.
NE-BLOCANT: >=80% din semnalele asteptate detectate per total.
REGRESIE: niciun fixture nu produce SIGUR. Fixtures dependente de lookup live = xfail.
"""
import json, os
from unittest.mock import AsyncMock, patch

import pytest

from services.anaf_cui import CuiResult
from services.invoice_orchestrator import scan_offer

CORPUS = json.load(open(os.path.join(os.path.dirname(__file__), "data", "offer_corpus_fixtures.json")))
FIXTURES = CORPUS["fixtures"]


def _cui_down():
    return CuiResult(exists=False, checked=False, denumire=None, activ=False,
                     data_inactivare=None, platitor_tva=False, enrolled_efactura=False, raw=None)


async def _scan(text):
    with patch("services.offer_entity_verifier.check_cui", new_callable=AsyncMock) as mock:
        mock.return_value = _cui_down()
        return await scan_offer(text)


@pytest.mark.asyncio
@pytest.mark.parametrize("idx", range(len(FIXTURES)), ids=[f"{f['family']}-{i}" for i, f in enumerate(FIXTURES)])
async def test_fixture_blocking_recall(idx):
    fx = FIXTURES[idx]
    if fx.get("xfail_live"):
        pytest.xfail("depinde de lookup live (registru)")
    result = await _scan(fx["text"])
    assert result.gate["label"] != "SAFE", f"fixture de frauda nu poate fi SAFE: {fx['text'][:60]}"
    expected = fx["expected_offer_signals"]
    if expected:
        detected = set(result.signals)
        assert detected & set(expected), (
            f"niciun semnal asteptat detectat. expected={expected} detected={sorted(detected)}"
        )


@pytest.mark.asyncio
async def test_overall_signal_recall_objective():
    """Obiectiv ne-blocant >=80%: raportat, nu impus (asserta doar podeaua de 50%)."""
    total = hit = 0
    for fx in FIXTURES:
        if fx.get("xfail_live") or not fx["expected_offer_signals"]:
            continue
        result = await _scan(fx["text"])
        detected = set(result.signals)
        for e in fx["expected_offer_signals"]:
            total += 1
            if e in detected:
                hit += 1
    ratio = hit / total if total else 1.0
    print(f"\nRECALL semnale: {hit}/{total} = {ratio:.0%} (obiectiv ne-blocant: 80%)")
    assert ratio >= 0.5, "recall sub podeaua minima"
