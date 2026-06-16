"""Reputation Graph v1 — privacy-first cross-surface intel.

Graph-ul este combustibil pentru Radar, facturi si scanari URL. Reguli:
- foloseste doar identificatori hash-uiti/canonici, nu PII brut;
- un singur raport comunitar nu blocheaza;
- volum mare + risc ridicat poate bloca telefonul in hot-cache;
- legaturile phone/domain/url -> IBAN ridica riscul unei facturi fara sa inventeze
  o potrivire oficiala;
- allowlist-ul oficial nu poate fi otravit de un cluster comunitar slab.
"""


def test_single_community_phone_report_warns_but_never_blocks():
    from services.reputation_graph import ReputationGraph

    graph = ReputationGraph()
    phone_hash = "a" * 64
    graph.add_observation(
        target_type="phone",
        target_hash=phone_hash,
        source="community",
        risk_level="high",
        family="CONV_BANK_SAFE_ACCOUNT",
        report_count=1,
    )

    verdict = graph.evaluate("phone", phone_hash)

    assert verdict["status"] == "reported"
    assert verdict["action"] == "warn"
    assert verdict["can_block"] is False
    assert verdict["bucket_count"] == "1-4"
    assert "GRAPH_SINGLE_REPORT_NON_BLOCKING" in verdict["reason_codes"]


def test_high_volume_high_risk_phone_reports_can_block_offline_radar():
    from services.reputation_graph import ReputationGraph

    graph = ReputationGraph()
    phone_hash = "b" * 64
    graph.add_observation(
        target_type="phone",
        target_hash=phone_hash,
        source="community",
        risk_level="high",
        family="CONV_BANK_SAFE_ACCOUNT",
        report_count=25,
    )

    verdict = graph.evaluate("phone", phone_hash)

    assert verdict["status"] == "blocked"
    assert verdict["action"] == "block"
    assert verdict["can_block"] is True
    assert verdict["bucket_count"] == "25-99"
    assert "GRAPH_HIGH_VOLUME_PHONE_REPORTS" in verdict["reason_codes"]


def test_iban_linked_to_known_scam_infrastructure_raises_invoice_risk():
    from services.reputation_graph import ReputationGraph

    graph = ReputationGraph()
    phone_hash = "c" * 64
    iban_hash = "d" * 64
    graph.add_observation(
        target_type="phone",
        target_hash=phone_hash,
        source="community",
        risk_level="high",
        family="DOC_BEC_IBAN_CHANGE",
        report_count=40,
    )
    graph.add_edge(
        source_type="phone",
        source_hash=phone_hash,
        target_type="iban",
        target_hash=iban_hash,
        relation="pays_to",
        evidence_quality="high",
        source="case_correlation",
    )

    verdict = graph.evaluate("iban", iban_hash)

    assert verdict["status"] == "suspicious"
    assert verdict["action"] == "raise_risk"
    assert verdict["can_block"] is False
    assert verdict["family"] == "DOC_BEC_IBAN_CHANGE"
    assert "GRAPH_LINKED_TO_HIGH_RISK_PHONE" in verdict["reason_codes"]


def test_official_allowlist_cannot_be_poisoned_by_weak_community_cluster():
    from services.reputation_graph import ReputationGraph

    graph = ReputationGraph()
    domain_hash = "e" * 64
    graph.mark_allowlisted(
        target_type="domain",
        target_hash=domain_hash,
        source="brand_truth_registry",
        reason="official_domain",
    )
    graph.add_observation(
        target_type="domain",
        target_hash=domain_hash,
        source="community",
        risk_level="high",
        family="CONV_FAKE_SHOP",
        report_count=3,
    )

    verdict = graph.evaluate("domain", domain_hash)

    assert verdict["status"] == "allowlisted_watch"
    assert verdict["action"] == "allow_with_watch"
    assert verdict["can_block"] is False
    assert "GRAPH_ALLOWLIST_PROTECTED" in verdict["reason_codes"]


def test_rejects_raw_phone_or_iban_values():
    from services.reputation_graph import ReputationGraph

    graph = ReputationGraph()

    try:
        graph.add_observation(
            target_type="phone",
            target_hash="+40722123456",
            source="community",
            risk_level="high",
        )
    except ValueError as exc:
        assert "sha256" in str(exc).lower()
    else:
        raise AssertionError("raw phone values must not enter the reputation graph")


def test_graph_loads_supabase_rows_and_emits_radar_reputation_items():
    from services.reputation_graph import ReputationGraph

    graph = ReputationGraph.from_rows(
        observations=[
            {
                "target_type": "phone",
                "target_hash": "f" * 64,
                "source": "community",
                "risk_level": "high",
                "family": "CONV_BANK_SAFE_ACCOUNT",
                "report_count": 25,
            }
        ],
        edges=[],
        allowlist=[],
    )

    items = graph.radar_number_reputation()

    assert items == [
        {
            "phone_hash": "f" * 64,
            "status": "blocked",
            "family": "CONV_BANK_SAFE_ACCOUNT",
            "bucket_count": "25-99",
        }
    ]


def test_supabase_reputation_helpers_write_only_hashed_payloads(monkeypatch):
    from services import supabase_store

    calls = []
    monkeypatch.setattr(supabase_store, "is_supabase_enabled", lambda: True)
    monkeypatch.setattr(
        supabase_store,
        "_post_json",
        lambda table, payload, prefer="return=minimal": calls.append((table, payload, prefer)),
    )

    supabase_store.save_reputation_observation(
        {
            "target_type": "phone",
            "target_hash": "1" * 64,
            "source": "community",
            "risk_level": "high",
            "family": "CONV_BANK_SAFE_ACCOUNT",
            "report_count": 30,
        }
    )
    supabase_store.save_reputation_edge(
        {
            "source_type": "phone",
            "source_hash": "1" * 64,
            "target_type": "iban",
            "target_hash": "2" * 64,
            "relation": "pays_to",
            "source": "case_correlation",
        }
    )
    supabase_store.save_reputation_allowlist(
        {
            "target_type": "domain",
            "target_hash": "3" * 64,
            "source": "brand_truth_registry",
            "reason": "official_domain",
        }
    )

    tables = [table for table, _, _ in calls]
    blob = repr(calls)

    assert tables == ["reputation_observations", "reputation_edges", "reputation_allowlist"]
    assert "+407" not in blob
    assert "RO49" not in blob
    assert "1" * 64 in blob and "2" * 64 in blob and "3" * 64 in blob
