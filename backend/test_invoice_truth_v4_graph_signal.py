"""D6 Felia 2 — end-to-end: the seller-graph advisory is soft and gated.

Structural guarantee: the signal only ever enters unconfirmed_items, never
hard_conflicts, so it can never turn an invoice DANGEROUS. These tests lock
(a) flag OFF = no change, (b) flag ON + a linked high-risk IBAN surfaces a soft
item WITHOUT escalating the verdict or becoming the primary reason.
"""

import pytest

from services.anaf_cui import CuiResult
from services.invoice_orchestrator import evaluate_invoice_verdict, scan_invoice
from services import seller_graph_query as q
from services.reputation_graph import ReputationGraph
from services.reputation_identity import hash_iban, hash_phone

MGH_TEXT = """
Factura MGH 0013
Data emiterii: 06.04.2022
Termen plata: 07.04.2022
Furnizor:
MARKETING GROWTH HUB S.R.L.
CIF:
45758405
IBAN (RON):
RO42INGB0000999912242622
Total plata 200.00 RON
"""
MGH_IBAN = "RO42INGB0000999912242622"
GRAPH_CODE = "GRAPH_LINKED_TO_HIGH_RISK_PHONE"


def _cui_result(name: str) -> CuiResult:
    return CuiResult(exists=True, checked=True, denumire=name, activ=True,
                     data_inactivare=None, platitor_tva=False, enrolled_efactura=False,
                     raw=None, source="anaf")


@pytest.fixture(autouse=True)
def _reset_cache():
    q.reset_cache()
    yield
    q.reset_cache()


async def _run_mgh(monkeypatch):
    async def fake_check_cui(cui: str):
        return _cui_result("MARKETING GROWTH HUB S.R.L.")

    monkeypatch.setattr("services.invoice_orchestrator.check_cui", fake_check_cui)
    result = await scan_invoice(MGH_TEXT)
    evaluated = evaluate_invoice_verdict(result, result.raw_text, source_channel="android_native")
    return evaluated["invoice_truth"]


def _link_mgh_iban_to_high_risk_phone():
    g = ReputationGraph()
    ph = hash_phone("0722000001")
    g.add_observation(target_type="phone", target_hash=ph, source="community",
                      risk_level="high", report_count=30)
    g.add_edge(source_type="phone", source_hash=ph, target_type="iban",
               target_hash=hash_iban(MGH_IBAN), relation="pays_to")
    return g


@pytest.mark.asyncio
async def test_graph_signal_off_is_a_no_op(monkeypatch):
    monkeypatch.delenv("D6_GRAPH_SIGNAL", raising=False)
    monkeypatch.setattr(q, "_load_graph", _link_mgh_iban_to_high_risk_phone)
    truth = await _run_mgh(monkeypatch)
    assert not any(i["code"] == GRAPH_CODE for i in truth["unconfirmed_items"])
    assert truth["verdict"] == "VERIFY_BEFORE_PAYING"  # unchanged baseline


@pytest.mark.asyncio
async def test_graph_signal_on_surfaces_soft_without_escalating(monkeypatch):
    monkeypatch.setenv("D6_GRAPH_SIGNAL", "1")
    monkeypatch.setattr(q, "_load_graph", _link_mgh_iban_to_high_risk_phone)
    truth = await _run_mgh(monkeypatch)
    # soft advisory surfaces...
    assert any(i["code"] == GRAPH_CODE for i in truth["unconfirmed_items"])
    # ...but the verdict is NOT escalated and there is no hard conflict.
    assert truth["verdict"] != "NU_PLATI"
    assert truth["hard_conflicts"] == []
    # and it does not hijack the primary reason (no severity influence in Felia 2).
    assert truth["primary_reason_code"] != GRAPH_CODE


@pytest.mark.asyncio
async def test_graph_signal_on_but_iban_unlinked_no_item(monkeypatch):
    monkeypatch.setenv("D6_GRAPH_SIGNAL", "1")
    monkeypatch.setattr(q, "_load_graph", lambda: ReputationGraph())  # empty graph
    truth = await _run_mgh(monkeypatch)
    assert not any(i["code"] == GRAPH_CODE for i in truth["unconfirmed_items"])
