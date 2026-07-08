"""D6 Felia 1 — gated seller-edge persistence (write-only, verdict untouched)."""

import pytest

from services import seller_graph_ingest as ingest
from services import supabase_store

TEXT = "Sunati la 0722 123 456 si platiti in contul RO49 AAAA 1B31 0075 9384 0000 azi."
PHONE_HASH = "93841fe8558bfa0dbc484f476f27af1de186cd33dfb09c4d1215d42f1abbe0f5"
IBAN_HASH = "92c09c16747a943f3f36638dbb910fa9b398ed623aa1f00ec765bc4d4a420677"


@pytest.fixture
def captured_edges(monkeypatch):
    edges = []
    monkeypatch.setattr(supabase_store, "upsert_reputation_edge", lambda e: edges.append(e))
    return edges


def test_disabled_by_default_is_a_no_op(monkeypatch, captured_edges):
    monkeypatch.delenv("D6_PERSIST_EDGES", raising=False)
    result = ingest.record_cooccurrence_edges(TEXT)
    assert result["enabled"] is False
    assert result["persisted"] == 0
    assert captured_edges == []  # nothing written when the flag is off


@pytest.mark.parametrize("flag", ["0", "false", "off", "no", ""])
def test_falsey_flag_values_stay_off(monkeypatch, captured_edges, flag):
    monkeypatch.setenv("D6_PERSIST_EDGES", flag)
    ingest.record_cooccurrence_edges(TEXT)
    assert captured_edges == []


def test_enabled_persists_phone_to_iban_pays_to_edge(monkeypatch, captured_edges):
    monkeypatch.setenv("D6_PERSIST_EDGES", "1")
    result = ingest.record_cooccurrence_edges(TEXT, source="unit_test")
    assert result == {"enabled": True, "phones": 1, "ibans": 1, "persisted": 1}
    assert captured_edges == [{
        "source_type": "phone",
        "source_hash": PHONE_HASH,
        "target_type": "iban",
        "target_hash": IBAN_HASH,
        "relation": "pays_to",
        "source": "unit_test",
        "evidence_quality": "low",
    }]


def test_edge_direction_matches_linked_evidence_consumer(monkeypatch, captured_edges):
    # reputation_graph._linked_evidence keys on iban <- phone via pays_to.
    monkeypatch.setenv("D6_PERSIST_EDGES", "1")
    ingest.record_cooccurrence_edges(TEXT)
    edge = captured_edges[0]
    assert edge["source_type"] == "phone" and edge["target_type"] == "iban"
    assert edge["relation"] == "pays_to"


def test_persistence_failure_is_swallowed(monkeypatch):
    monkeypatch.setenv("D6_PERSIST_EDGES", "1")

    def _boom(_entry):
        raise RuntimeError("supabase down")

    monkeypatch.setattr(supabase_store, "upsert_reputation_edge", _boom)
    # Must never raise into the caller / verdict path.
    result = ingest.record_cooccurrence_edges(TEXT)
    assert result["persisted"] == 0


def test_no_identifiers_persists_nothing(monkeypatch, captured_edges):
    monkeypatch.setenv("D6_PERSIST_EDGES", "1")
    assert ingest.record_cooccurrence_edges("no phone or iban here")["persisted"] == 0
    assert ingest.record_cooccurrence_edges(None)["persisted"] == 0
    assert captured_edges == []


def test_edge_id_is_deterministic_and_distinct():
    row = {"source_type": "phone", "source_hash": PHONE_HASH,
           "target_type": "iban", "target_hash": IBAN_HASH, "relation": "pays_to"}
    id1 = supabase_store._reputation_edge_id(row)
    id2 = supabase_store._reputation_edge_id(dict(row))
    assert id1 == id2  # idempotent: same edge -> same row id
    other = supabase_store._reputation_edge_id({**row, "relation": "claimed_by"})
    assert other != id1


def test_upsert_uses_merge_duplicates(monkeypatch):
    captured = {}

    def fake_post(table, payload, prefer="return=minimal", params=None):
        captured["table"] = table
        captured["prefer"] = prefer
        captured["payload"] = payload

    monkeypatch.setattr(supabase_store, "_post_json", fake_post)
    monkeypatch.setattr(supabase_store, "is_supabase_enabled", lambda: True)
    supabase_store.upsert_reputation_edge({
        "source_type": "phone", "source_hash": PHONE_HASH,
        "target_type": "iban", "target_hash": IBAN_HASH, "relation": "pays_to",
    })
    assert captured["table"] == "reputation_edges"
    assert "resolution=merge-duplicates" in captured["prefer"]
    assert captured["payload"]["id"]  # deterministic id attached for the upsert
