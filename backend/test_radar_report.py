"""PR-5 — Radarul: hot-cache pentru CallScreening + raport 1-tap (1911/PNRISC).

Reguli pinuite (din MoatOS §7):
- hot-cache: campanii active + reputație numere pe buckets; ZERO număr brut
  server-side (doar hash-uri primite + prefixe HMAC).
- since-filter pe campanii.
- report builder: pachet precompletat DNSC(1911)/PNRISC; fără PII raw; determinist.
- Verdictul rămâne la verdict_gate — radar/report produc DOAR date, nu verdicte.
"""
import time

from services.campaign_intel import CampaignIntel, CampaignStore
from services.radar_hot_cache import (
    build_hot_cache,
    reputation_bucket,
    hot_warning_for_family,
)
from services.report_builder import REPORT_DISCLAIMER, build_report_package


def _store_with(*intels) -> CampaignStore:
    store = CampaignStore.__new__(CampaignStore)
    store._intels = {}
    for it in intels:
        store._intels[it.intel_id] = it
    return store


def _intel(intel_id, family, ask="depozit", channel="meta_ads", status="active", last_seen=None, regions=None):
    return CampaignIntel(
        intel_id=intel_id, family=family,
        skeleton={"claimed_identity": "BNR", "ask": ask, "channel": channel},
        iocs={"phone_hash_prefixes": ["hmacpfx0001"]},
        source={"kind": "official_alert", "url": "https://dnsc.ro/x"},
        evidence_quality="high", status=status,
        regions_hint=regions or ["national"],
        last_seen_at=last_seen if last_seen is not None else time.time(),
    )


class TestReputationBuckets:
    def test_zero(self):
        assert reputation_bucket(0) == "0"

    def test_low(self):
        assert reputation_bucket(1) == "1-4"
        assert reputation_bucket(4) == "1-4"

    def test_mid(self):
        assert reputation_bucket(5) == "5-24"
        assert reputation_bucket(24) == "5-24"

    def test_high(self):
        assert reputation_bucket(25) == "25-99"
        assert reputation_bucket(99) == "25-99"

    def test_viral(self):
        assert reputation_bucket(100) == "100+"
        assert reputation_bucket(5000) == "100+"


class TestHotCacheShape:
    def test_payload_keys(self):
        store = _store_with(_intel("ci_1", "CONV_BANK_SAFE_ACCOUNT"))
        out = build_hot_cache(store, reports=[])
        assert set(out) >= {"generated_at", "ttl_minutes", "hot_campaigns", "number_reputation"}
        assert out["ttl_minutes"] > 0

    def test_campaign_mapped_with_warning(self):
        store = _store_with(_intel("ci_1", "CONV_BANK_SAFE_ACCOUNT"))
        out = build_hot_cache(store, reports=[])
        assert len(out["hot_campaigns"]) == 1
        c = out["hot_campaigns"][0]
        assert c["family"] == "CONV_BANK_SAFE_ACCOUNT"
        assert c["warning_title"] and c["warning_body"]
        assert "phone_hash_prefixes" in c

    def test_since_filters_old_campaigns(self):
        old = _intel("ci_old", "CONV_COURIER_TAX_CARD", last_seen=time.time() - 30 * 86400)
        fresh = _intel("ci_new", "CONV_BANK_SAFE_ACCOUNT", last_seen=time.time())
        store = _store_with(old, fresh)
        out = build_hot_cache(store, reports=[], since=time.time() - 7 * 86400)
        ids = {c["campaign_id"] for c in out["hot_campaigns"]}
        assert "ci_new" in ids and "ci_old" not in ids

    def test_inactive_campaign_excluded(self):
        store = _store_with(_intel("ci_dead", "CONV_BANK_SAFE_ACCOUNT", status="dead"))
        out = build_hot_cache(store, reports=[], since=0)
        assert out["hot_campaigns"] == []


class TestNumberReputationPrivacy:
    def test_buckets_and_no_raw_phone(self):
        store = _store_with()
        reports = [
            {"hash": "hmac_aaa", "report_count": 7, "family": "IMP-02"},
            {"hash": "hmac_bbb", "report_count": 1, "family": "IMP-02"},
        ]
        out = build_hot_cache(store, reports=reports)
        rep = {r["phone_hash"]: r for r in out["number_reputation"]}
        assert rep["hmac_aaa"]["bucket_count"] == "5-24"
        assert rep["hmac_bbb"]["bucket_count"] == "1-4"
        # zero număr brut: payload-ul nu conține cifre de telefon RO (07...)
        import json
        blob = json.dumps(out)
        assert "+407" not in blob and "07" not in rep  # doar hash-uri

    def test_status_reported(self):
        out = build_hot_cache(_store_with(), reports=[{"hash": "h1", "report_count": 3}])
        assert out["number_reputation"][0]["status"] == "reported"


class TestReportBuilder:
    def test_phishing_routes_dnsc_1911(self):
        pkg = build_report_package(
            target={"type": "url", "value_redacted": "fan-livrare[.]test"},
            family="CONV_COURIER_TAX_CARD", verdict="DANGEROUS",
        )
        channels = {c["name"] for c in pkg["channels"]}
        assert "DNSC" in channels
        dnsc = next(c for c in pkg["channels"] if c["name"] == "DNSC")
        assert "1911" in (dnsc.get("contact") or "")
        assert dnsc["prefilled_subject"] and dnsc["prefilled_body"]

    def test_includes_pnrisc(self):
        pkg = build_report_package(
            target={"type": "phone", "value_redacted": "07xx...xx"},
            family="CONV_BANK_SAFE_ACCOUNT", verdict="DANGEROUS",
        )
        assert any("PNRISC" in c["name"] or "Poli" in c["name"] for c in pkg["channels"])

    def test_no_raw_pii_only_redacted_target(self):
        pkg = build_report_package(
            target={"type": "iban", "value_redacted": "RO** **** 3456"},
            family="DOC_BEC_IBAN_CHANGE", verdict="SUSPECT",
        )
        import json
        blob = json.dumps(pkg)
        # nu apar CNP-uri / IBAN complet / numere lungi în pachet
        import re
        assert not re.search(r"\bRO\d{22}\b", blob)
        assert not re.search(r"\b\d{13}\b", blob)  # CNP

    def test_disclaimer_present(self):
        pkg = build_report_package(target={"type": "url", "value_redacted": "x[.]test"},
                                   family="CONV_BANK_SAFE_ACCOUNT", verdict="DANGEROUS")
        assert pkg["disclaimer"] == REPORT_DISCLAIMER

    def test_unknown_family_still_has_dnsc(self):
        pkg = build_report_package(target={"type": "url", "value_redacted": "x[.]test"},
                                   family="UNKNOWN_XYZ", verdict="SUSPECT")
        assert any(c["name"] == "DNSC" for c in pkg["channels"])

    def test_deterministic(self):
        args = dict(target={"type": "url", "value_redacted": "x[.]test"},
                    family="CONV_BANK_SAFE_ACCOUNT", verdict="DANGEROUS")
        assert build_report_package(**args) == build_report_package(**args)


class TestEndpoints:
    def test_hot_iocs_endpoint(self):
        from fastapi.testclient import TestClient
        import main as app_main

        client = TestClient(app_main.app)
        r = client.get("/v1/radar/hot-iocs")
        assert r.status_code == 200
        body = r.json()
        assert "hot_campaigns" in body and "number_reputation" in body
        assert body["ttl_minutes"] > 0

    def test_report_endpoint(self):
        from fastapi.testclient import TestClient
        import main as app_main

        client = TestClient(app_main.app)
        r = client.post(
            "/v1/report",
            json={"target_type": "url", "target_redacted": "fan-livrare[.]test",
                  "family": "CONV_COURIER_TAX_CARD", "verdict": "DANGEROUS"},
        )
        assert r.status_code == 200
        body = r.json()
        names = {c["name"] for c in body["channels"]}
        assert "DNSC" in names
        assert body["disclaimer"]
