from services.campaign_intel import CampaignStore, CampaignIntel, FAMILY_TAXONOMY
from services.urechea_ingester import UrecheaIngester


class TestCampaignIntel:
    def test_family_taxonomy_has_12_families(self):
        assert len(FAMILY_TAXONOMY) == 12

    def test_known_family_keys(self):
        expected = {"IMP-01", "IMP-02", "IMP-03", "IMP-04", "IMP-05", "IMP-06",
                    "IMP-07", "IMP-08", "IMP-09", "OP-01", "OP-02", "OP-03"}
        assert set(FAMILY_TAXONOMY.keys()) == expected


class TestCampaignStore:
    def test_empty_store(self):
        store = CampaignStore(seed_path="")
        assert len(store.all()) == 0

    def test_put_and_get(self):
        store = CampaignStore(seed_path="")
        intel = CampaignIntel(
            intel_id="test_001", family="IMP-01",
            skeleton={}, iocs={}, source={}, evidence_quality="high",
        )
        store.put(intel)
        assert store.get("test_001") is not None
        assert store.get("test_001").intel_id == "test_001"

    def test_active_filters_by_status(self):
        store = CampaignStore(seed_path="")
        a = CampaignIntel(intel_id="a", family="IMP-01", skeleton={}, iocs={}, source={},
                          evidence_quality="high", status="active", moderation={"approved": True})
        b = CampaignIntel(intel_id="b", family="IMP-02", skeleton={}, iocs={}, source={},
                          evidence_quality="medium", status="inactive", moderation={})
        store.put(a)
        store.put(b)
        active = store.active()
        assert len(active) == 1
        assert active[0].intel_id == "a"

    def test_active_filters_unapproved(self):
        store = CampaignStore(seed_path="")
        a = CampaignIntel(intel_id="a", family="IMP-01", skeleton={}, iocs={}, source={},
                          evidence_quality="high", status="active", moderation={"approved": False})
        b = CampaignIntel(intel_id="b", family="IMP-02", skeleton={}, iocs={}, source={},
                          evidence_quality="medium", status="active", moderation={})
        store.put(a)
        store.put(b)
        active = store.active()
        assert len(active) == 1
        assert active[0].intel_id == "b"


class TestUrecheaIngester:
    def test_sources_loaded(self, store: CampaignStore | None = None):
        _store = store or CampaignStore(seed_path="")
        ingester = UrecheaIngester(_store)
        assert len(ingester.sources) >= 9
        assert "WIPOScamWarnings" in ingester.sources

    def test_ingest_raw_high_quality_auto_approved(self):
        store = CampaignStore(seed_path="")
        ingester = UrecheaIngester(store)
        intel = ingester.ingest_raw(
            title="Alertă DNSC: Campanie de smishing FAN Courier",
            body="DNSC avertizează asupra unei campanii de smishing care folosește numele FAN Courier. "
                 "Mesajele cer plata unei taxe vamale și introducerea datelor cardului.",
            source_url="https://www.dnsc.ro/alerta",
            source_kind="official_alert",
            claimed_identity="FAN Courier",
            evidence_quality="high",
        )
        assert intel.family == "IMP-03"
        assert intel.moderation.get("approved") is True
        assert intel.status == "active"
        assert intel.source["kind"] == "official_alert"

    def test_ingest_raw_medium_quality_queues_moderation(self):
        store = CampaignStore(seed_path="")
        ingester = UrecheaIngester(store)
        intel = ingester.ingest_raw(
            title="Posibilă campanie nouă",
            body="Am primit un mesaj suspect despre o oportunitate de investiții cu randament garantat.",
            source_url="",
            source_kind="press_context",
            claimed_identity="BNR",
            evidence_quality="medium",
        )
        assert intel.family == "IMP-02"
        assert intel.moderation.get("approved") is False
        assert intel.moderation.get("required_for") == "dangerous"
        assert len(ingester.moderation_queue) == 1

    def test_ingest_unknown_family_goes_to_draft(self):
        store = CampaignStore(seed_path="")
        ingester = UrecheaIngester(store)
        intel = ingester.ingest_raw(
            title="Știre generală",
            body="Astăzi a avut loc un eveniment important în oraș.",
            source_url="https://stiri.ro/eveniment",
            source_kind="press_context",
            evidence_quality="low",
        )
        assert intel.family == "UNKNOWN"
        assert intel.status == "draft"

    def test_approve_intel(self):
        store = CampaignStore(seed_path="")
        ingester = UrecheaIngester(store)
        intel = ingester.ingest_raw(
            title="Test", body="Test", source_url="", source_kind="press_context",
            claimed_identity="BNR", evidence_quality="medium",
        )
        assert ingester.approve_intel(intel.intel_id, "moderator") is True
        stored = store.get(intel.intel_id)
        assert stored is not None
        assert stored.moderation["approved"] is True
        assert stored.moderation["approved_by"] == "moderator"
        assert len(ingester.moderation_queue) == 0

    def test_reject_intel(self):
        store = CampaignStore(seed_path="")
        ingester = UrecheaIngester(store)
        intel = ingester.ingest_raw(
            title="Test", body="Test", source_url="", source_kind="press_context",
            claimed_identity="OLX", evidence_quality="medium",
        )
        assert ingester.reject_intel(intel.intel_id) is True
        stored = store.get(intel.intel_id)
        assert stored is not None
        assert stored.status == "rejected"

    def test_classify_imp01_bank_safe_account(self):
        store = CampaignStore(seed_path="")
        ingester = UrecheaIngester(store)
        intel = ingester.ingest_raw(
            title="SMS cont sigur", body="Transferă fondurile în contul nostru sigur. Sună la banca.",
            source_url="", source_kind="press_context", claimed_identity="Banca Transilvania",
            evidence_quality="low",
        )
        assert intel.family == "IMP-01"

    def test_classify_imp03_courier_tax(self):
        store = CampaignStore(seed_path="")
        ingester = UrecheaIngester(store)
        intel = ingester.ingest_raw(
            title="SMS curier", body="Ai o taxă vamală de plată pentru coletul tău FAN Courier.",
            source_url="", source_kind="press_context", claimed_identity="FAN Courier",
            evidence_quality="low",
        )
        assert intel.family == "IMP-03"

    def test_classify_op01_bec_iban_change(self):
        store = CampaignStore(seed_path="")
        ingester = UrecheaIngester(store)
        intel = ingester.ingest_raw(
            title="Email IBAN schimbat",
            body="Factura ANAF: IBAN-ul nostru s-a schimbat. Vă rugăm să faceți plata în noul cont.",
            source_url="", source_kind="vendor_advisory", claimed_identity="ANAF",
            evidence_quality="medium",
        )
        assert intel.family == "OP-01"

    def test_by_family(self):
        store = CampaignStore(seed_path="")
        ingester = UrecheaIngester(store)
        ingester.ingest_raw("A", "cont sigur", "", "press_context", claimed_identity="BT", evidence_quality="high")
        ingester.ingest_raw("B", "cont sigur", "", "press_context", claimed_identity="BCR", evidence_quality="high")
        results = store.by_family("IMP-01")
        assert len(results) == 2

    def test_html_source_fetch_is_bounded_and_extracts_visible_text(self, monkeypatch):
        class FakeResponse:
            text = """
            <html><head><title>Spoofed Calls and Fraudulent Payment Requests</title></head>
            <meta name="keywords" content="admin@wipo-office.com EPO EUIPO">
            <body><h1>Latest active scams</h1>
            <p>Scammers impersonate WIPO, EPO and EUIPO.</p>
            <script>ignored()</script></body></html>
            """

            @staticmethod
            def raise_for_status():
                return None

        captured = {}

        def fake_get(url, *, timeout):
            captured["url"] = url
            captured["timeout"] = timeout
            return FakeResponse()

        monkeypatch.setattr("services.urechea_ingester.requests.get", fake_get)
        ingester = UrecheaIngester(CampaignStore(seed_path=""))

        entries = ingester.fetch_source("WIPOScamWarnings")

        assert captured["url"] == "https://www.wipo.int/en/web/paying-for-ip-services/scam-warning"
        assert captured["timeout"] <= 8
        assert len(entries) == 1
        assert entries[0]["title"] == "Spoofed Calls and Fraudulent Payment Requests"
        assert "admin@wipo-office.com" in entries[0]["body"]


class TestUrecheaApiRunner:
    def test_admin_run_endpoint_fetches_sources_and_updates_status(self, monkeypatch):
        from fastapi.testclient import TestClient
        import main as app_main

        monkeypatch.setattr(app_main, "ADMIN_API_KEYS", {"admin-test"})
        monkeypatch.setattr(app_main.supabase_store, "save_campaign_intel", lambda entry: None)
        monkeypatch.setattr(
            app_main.urechea_ingester,
            "fetch_source",
            lambda name: [
                {
                    "title": "DNSC alerta FAN Courier",
                    "body": "Campanie smishing FAN Courier cere taxa vamala si date card.",
                    "link": "https://dnsc.ro/alerta-test",
                }
            ],
        )

        client = TestClient(app_main.app)
        r = client.post(
            "/v1/urechea/run",
            headers={"X-API-KEY": "admin-test"},
            json={"sources": ["DNSC"], "max_entries_per_source": 1},
        )
        status = client.get("/v1/urechea/status", headers={"X-API-KEY": "admin-test"}).json()

        assert r.status_code == 200
        body = r.json()
        assert body["entries_ingested"] == 1
        assert body["sources_attempted"] == 1
        assert body["source_results"][0]["source"] == "DNSC"
        assert status["last_run_at"] is not None
        assert status["entries_ingested"] >= 1
