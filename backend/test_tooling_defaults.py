import importlib.util
import sys
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parent
ROOT_DIR = BACKEND_DIR.parent
PRODUCTION_API_BASE_URL = "https://api.sigurscan.com"


def _load_module(path: Path, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def test_live_smoke_runner_defaults_to_sigurscan_api_domain(monkeypatch):
    monkeypatch.delenv("SIGURSCAN_LIVE_SMOKE_BASE_URL", raising=False)

    module = _load_module(
        BACKEND_DIR / "eval" / "live_provider_smoke_runner.py",
        "live_provider_smoke_runner_defaults_test",
    )

    assert module.DEFAULT_BASE_URL == PRODUCTION_API_BASE_URL


def test_preview_preseed_tool_defaults_to_sigurscan_api_domain():
    module = _load_module(
        BACKEND_DIR / "tools" / "preseed_urlscan_previews.py",
        "preseed_urlscan_previews_defaults_test",
    )

    assert module.DEFAULT_BASE_URL == PRODUCTION_API_BASE_URL


def test_cloud_run_deploy_preserves_safe_concurrency_default():
    script = (ROOT_DIR / "tools" / "deploy_cloud_run_backend.sh").read_text(encoding="utf-8")

    assert 'CONCURRENCY="${CONCURRENCY:-2}"' in script
    assert '--concurrency "$CONCURRENCY"' in script
    assert "--concurrency 40" not in script


def test_cloud_run_deploy_routes_traffic_to_latest_revision():
    script = (ROOT_DIR / "tools" / "deploy_cloud_run_backend.sh").read_text(encoding="utf-8")

    assert "gcloud run services update-traffic" in script
    assert '--to-latest' in script
