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
    assert "SUPABASE_SERVICE_KEY" in text


def test_feedparser_dependency_is_declared_for_rss_sources():
    requirements = (ROOT / "backend" / "requirements.txt").read_text()
    assert "feedparser==" in requirements


def test_worker_accepts_comma_separated_workflow_sources():
    from services.campaign_intel import CampaignStore
    from services.urechea_ingester import UrecheaIngester
    from services.urechea_rss_worker import _source_names

    ingester = UrecheaIngester(CampaignStore())

    assert _source_names(ingester, ["DNSC,SigurantaOnline"]) == ["DNSC", "SigurantaOnline"]
