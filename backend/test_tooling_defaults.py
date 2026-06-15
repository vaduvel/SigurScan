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


def test_e2e_fixture_runner_treats_unverified_info_as_suspect():
    module = _load_module(
        BACKEND_DIR / "eval" / "e2e_fixture_runner.py",
        "e2e_fixture_runner_unverified_mapping_test",
    )

    assert module._actual_user_status({"risk_level": "info"}) == "SUSPECT"
    assert module._actual_user_status({"risk_level": "unverified"}) == "SUSPECT"


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


def test_supabase_logical_backup_workflow_is_scheduled_and_private_artifact():
    workflow = (ROOT_DIR / ".github" / "workflows" / "supabase-logical-backup.yml").read_text(
        encoding="utf-8"
    )

    assert "workflow_dispatch:" in workflow
    assert "cron:" in workflow
    assert "postgresql-client-17" in workflow
    assert "/usr/lib/postgresql/17/bin" in workflow
    assert "SUPABASE_DB_URL: ${{ secrets.SUPABASE_DB_URL }}" in workflow
    assert "tools/supabase_logical_backup.sh" in workflow
    assert "actions/upload-artifact@v4" in workflow
    assert "retention-days: 30" in workflow
    assert "if-no-files-found: error" in workflow


def test_supabase_logical_backup_script_is_secret_safe_and_restore_verified():
    script = (ROOT_DIR / "tools" / "supabase_logical_backup.sh").read_text(encoding="utf-8")

    assert "set -euo pipefail" in script
    assert "set -x" not in script
    assert "pg_dump" in script
    assert "--format=custom" in script
    assert "--no-owner" in script
    assert "--no-privileges" in script
    assert "pg_restore --list" in script
    assert "SUPABASE_DB_URL: SET length=" in script
    assert 'echo "$SUPABASE_DB_URL"' not in script
    assert "sha256sum" in script
    assert "shasum -a 256" in script


def test_android_ci_workflow_builds_with_jdk_and_recursive_submodules():
    workflow_path = ROOT_DIR / ".github" / "workflows" / "android-ci.yml"
    assert workflow_path.exists()
    workflow = workflow_path.read_text(encoding="utf-8")

    assert "workflow_dispatch:" in workflow
    assert "pull_request:" in workflow
    assert "push:" in workflow
    assert "submodules: recursive" in workflow
    assert "actions/setup-java" in workflow
    assert "distribution: temurin" in workflow
    assert 'java-version: "21"' in workflow
    assert "actions/setup-android" in workflow
    assert "./gradlew testDebugUnitTest" in workflow
    assert "./gradlew assembleRelease" in workflow
