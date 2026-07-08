"""D6 Felia 2 — seller-graph verdict signal (FP-focused, verdict path).

The critical property: the advisory fires ONLY for an IBAN linked to a
genuinely high-risk phone, never for a benign IBAN, never for an allowlisted
(official) one, and never at all unless D6_GRAPH_SIGNAL is enabled.
"""

import pytest

from services import seller_graph_query as q
from services.reputation_graph import ReputationGraph
from services.reputation_identity import hash_iban, hash_phone

HIGH_PHONE = hash_phone("0722000001")
NORMAL_PHONE = hash_phone("0722000002")
LINKED_IBAN_RAW = "RO49 AAAA 1B31 0075 9384 0000"
LINKED_IBAN = hash_iban(LINKED_IBAN_RAW)
CLEAN_IBAN_RAW = "RO27CECEB00030RON0509820"


def _graph_high_risk_linked():
    g = ReputationGraph()
    g.add_observation(target_type="phone", target_hash=HIGH_PHONE, source="community",
                      risk_level="high", report_count=30)
    g.add_edge(source_type="phone", source_hash=HIGH_PHONE, target_type="iban",
               target_hash=LINKED_IBAN, relation="pays_to")
    return g


def _graph_normal_linked():
    g = ReputationGraph()
    g.add_observation(target_type="phone", target_hash=NORMAL_PHONE, source="community",
                      risk_level="low", report_count=2)
    g.add_edge(source_type="phone", source_hash=NORMAL_PHONE, target_type="iban",
               target_hash=LINKED_IBAN, relation="pays_to")
    return g


@pytest.fixture(autouse=True)
def _reset_cache():
    q.reset_cache()
    yield
    q.reset_cache()


def test_disabled_by_default_never_signals(monkeypatch):
    monkeypatch.delenv("D6_GRAPH_SIGNAL", raising=False)
    monkeypatch.setattr(q, "_load_graph", _graph_high_risk_linked)  # linked graph present
    assert q.iban_graph_signal(LINKED_IBAN_RAW) is None


@pytest.mark.parametrize("flag", ["0", "false", "off", ""])
def test_falsey_flags_stay_off(monkeypatch, flag):
    monkeypatch.setenv("D6_GRAPH_SIGNAL", flag)
    monkeypatch.setattr(q, "_load_graph", _graph_high_risk_linked)
    assert q.iban_graph_signal(LINKED_IBAN_RAW) is None


def test_enabled_linked_high_risk_phone_emits_soft_signal(monkeypatch):
    monkeypatch.setenv("D6_GRAPH_SIGNAL", "1")
    monkeypatch.setattr(q, "_load_graph", _graph_high_risk_linked)
    sig = q.iban_graph_signal(LINKED_IBAN_RAW)
    assert sig is not None
    assert sig["code"] == "GRAPH_LINKED_TO_HIGH_RISK_PHONE"


def test_enabled_but_phone_not_high_risk_no_signal(monkeypatch):
    # FP guard: a benign co-occurrence (IBAN shares a phone that is NOT flagged)
    # must not raise a signal.
    monkeypatch.setenv("D6_GRAPH_SIGNAL", "1")
    monkeypatch.setattr(q, "_load_graph", _graph_normal_linked)
    assert q.iban_graph_signal(LINKED_IBAN_RAW) is None


def test_enabled_unknown_iban_no_signal(monkeypatch):
    monkeypatch.setenv("D6_GRAPH_SIGNAL", "1")
    monkeypatch.setattr(q, "_load_graph", _graph_high_risk_linked)
    assert q.iban_graph_signal(CLEAN_IBAN_RAW) is None


def test_allowlisted_official_iban_never_signals(monkeypatch):
    # FP guard: an official/allowlisted IBAN is protected even if linked.
    monkeypatch.setenv("D6_GRAPH_SIGNAL", "1")

    def _graph():
        g = _graph_high_risk_linked()
        g.mark_allowlisted(target_type="iban", target_hash=LINKED_IBAN,
                           source="dnsc", reason="official")
        return g

    monkeypatch.setattr(q, "_load_graph", _graph)
    assert q.iban_graph_signal(LINKED_IBAN_RAW) is None


def test_supabase_disabled_is_a_no_op(monkeypatch):
    monkeypatch.setenv("D6_GRAPH_SIGNAL", "1")
    from services import supabase_store
    monkeypatch.setattr(supabase_store, "is_supabase_enabled", lambda: False)
    q.reset_cache()
    assert q.iban_graph_signal(LINKED_IBAN_RAW) is None


def test_no_iban_no_signal(monkeypatch):
    monkeypatch.setenv("D6_GRAPH_SIGNAL", "1")
    monkeypatch.setattr(q, "_load_graph", _graph_high_risk_linked)
    assert q.iban_graph_signal(None) is None
    assert q.iban_graph_signal("") is None
