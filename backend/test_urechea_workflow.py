from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_urechea_rss_workflow_exists_and_runs_worker():
    workflow = ROOT / ".github" / "workflows" / "urechea-rss-ingest.yml"
    assert workflow.exists()
    text = workflow.read_text()
    assert "services.urechea_rss_worker" in text
    assert "workflow_dispatch" in text
    assert "schedule:" in text
    assert "SUPABASE_URL" in text
    assert "SUPABASE_SERVICE_ROLE_KEY" in text


def test_feedparser_dependency_is_declared_for_rss_sources():
    requirements = (ROOT / "backend" / "requirements.txt").read_text()
    assert "feedparser==" in requirements


def test_worker_accepts_comma_separated_workflow_sources():
    from services.campaign_intel import CampaignStore
    from services.urechea_ingester import UrecheaIngester
    from services.urechea_rss_worker import _source_names

    ingester = UrecheaIngester(CampaignStore())

    assert _source_names(ingester, ["DNSC,SigurantaOnline"]) == ["DNSC", "SigurantaOnline"]


def test_worker_persists_ingested_intel_to_supabase(monkeypatch):
    from services import urechea_rss_worker as worker

    saved = []

    def fake_fetch_source(self, source_name):
        return [
            {
                "title": "Alertă facturi false",
                "body": "Factură falsă cu IBAN nou și presiune la plată.",
                "link": "https://dnsc.ro/alerte/facturi-false",
            }
        ]

    monkeypatch.setattr(worker.UrecheaIngester, "fetch_source", fake_fetch_source)
    monkeypatch.setattr(worker.supabase_store, "save_campaign_intel", lambda entry: saved.append(entry))

    assert worker.run(["DNSC"]) == 1
    assert len(saved) == 1
    assert saved[0]["source"]["url"] == "https://dnsc.ro/alerte/facturi-false"
