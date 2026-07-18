import importlib.util
import json
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


def test_live_smoke_runner_waits_for_preview_after_final_verdict(monkeypatch):
    module = _load_module(
        BACKEND_DIR / "eval" / "live_provider_smoke_runner.py",
        "live_provider_smoke_runner_preview_wait_test",
    )

    responses = [
        {
            "status": "complete",
            "result": {"is_final": True, "user_risk_label": "SAFE"},
            "preview": {
                "status": "pending",
                "reason": "urlscan_screenshot_pending",
                "report_url": "https://urlscan.io/result/shot-1/",
            },
        },
        {
            "status": "complete",
            "result": {"is_final": True, "user_risk_label": "SAFE"},
            "preview": {
                "status": "ready",
                "report_url": "https://urlscan.io/result/shot-1/",
                "screenshot_url": "https://api.sigurscan.com/v1/sandbox/urlscan/shot-1/screenshot",
            },
        },
    ]

    class FakeResponse:
        def __init__(self, payload):
            self._payload = payload

        def raise_for_status(self):
            return None

        def json(self):
            return self._payload

    def fake_get(*args, **kwargs):
        return FakeResponse(responses.pop(0))

    monkeypatch.setattr(module.requests, "get", fake_get)
    monkeypatch.setattr(module.time, "sleep", lambda _: None)

    result = module._poll_scan(
        "https://api.sigurscan.com",
        "orch_preview_wait",
        max_seconds=10,
        poll_interval=0,
        timeout=1,
    )

    assert result["result_payload"]["preview"]["status"] == "ready"
    assert result["timings"]["time_to_verdict_sec"] is not None
    assert result["timings"]["time_to_preview_screenshot_sec"] is not None


def test_live_smoke_runner_accepts_romanian_expected_label_aliases():
    module = _load_module(
        BACKEND_DIR / "eval" / "live_provider_smoke_runner.py",
        "live_provider_smoke_runner_label_aliases_test",
    )

    assert module._label_matches_expected("SAFE", ["SIGUR"])
    assert module._label_matches_expected("DANGEROUS", ["PERICULOS"])
    assert module._label_matches_expected("UNVERIFIED", ["NEVERIFICAT"])
    assert not module._label_matches_expected("SAFE", ["PERICULOS"])


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


def test_cloud_run_deploy_enables_play_integrity_monitor_rollout():
    script = (ROOT_DIR / "tools" / "deploy_cloud_run_backend.sh").read_text(encoding="utf-8")

    assert "PLAY_INTEGRITY_MODE=monitor" in script
    assert "PLAY_INTEGRITY_MODE=enforce" not in script
    assert "PLAY_INTEGRITY_CREDENTIALS_JSON_SECRET=" in script
    assert "PLAY_INTEGRITY_CREDENTIALS_JSON=$PLAY_INTEGRITY_CREDENTIALS_JSON_SECRET" in script
    assert "PLAY_INTEGRITY_CREDENTIALS_JSON=play-integrity-credentials-json:latest" not in script
    assert "UPSTASH_REDIS_REST_URL=upstash-redis-rest-url:latest" in script
    assert "UPSTASH_REDIS_REST_TOKEN=upstash-redis-rest-token:latest" in script


def test_cloud_run_deploy_fails_closed_on_rate_limit_backend_errors():
    script = (ROOT_DIR / "tools" / "deploy_cloud_run_backend.sh").read_text(encoding="utf-8")

    assert "ENABLE_RATE_LIMIT=true" in script
    assert "RATE_LIMIT_FAIL_CLOSED=true" in script


def test_env_example_documents_paid_intel_budget_guards():
    env_example = (ROOT_DIR / "backend" / ".env.example").read_text(encoding="utf-8")

    assert "OPENAPI_RO_MONTHLY_BUDGET=100" in env_example
    assert "HUNTER_IO_MONTHLY_BUDGET=50" in env_example


def test_cloud_run_deploy_enables_asf_investor_alerts_provider():
    script = (ROOT_DIR / "tools" / "deploy_cloud_run_backend.sh").read_text(encoding="utf-8")

    assert "ENABLE_ASF_INVESTOR_ALERTS=true" in script


def test_cloud_run_deploy_preserves_paid_intel_budget_guards():
    script = (ROOT_DIR / "tools" / "deploy_cloud_run_backend.sh").read_text(encoding="utf-8")

    assert "OPENAPI_RO_MONTHLY_BUDGET=100" in script
    assert "HUNTER_IO_MONTHLY_BUDGET=50" in script
    assert "OPENAPI_RO_API_KEY_SECRET-openapi-ro-api-key:latest" in script
    assert "HUNTER_IO_API_KEY_SECRET-hunter-io-api-key:latest" in script
    assert "OPENAPI_RO_API_KEY=$OPENAPI_RO_API_KEY_SECRET" in script
    assert "HUNTER_IO_API_KEY=$HUNTER_IO_API_KEY_SECRET" in script


def test_cloud_run_deploy_routes_traffic_to_latest_revision():
    script = (ROOT_DIR / "tools" / "deploy_cloud_run_backend.sh").read_text(encoding="utf-8")

    assert "gcloud run services update-traffic" in script
    assert '--to-latest' in script


def test_cloud_run_deploy_wires_orchestrated_cloud_tasks_worker():
    script = (ROOT_DIR / "tools" / "deploy_cloud_run_backend.sh").read_text(encoding="utf-8")

    assert "ORCHESTRATED_CLOUD_TASKS_ENABLED=" in script
    assert "CLOUD_TASKS_PROJECT=" in script
    assert "CLOUD_TASKS_LOCATION=" in script
    assert "CLOUD_TASKS_QUEUE=" in script
    assert "SIGURSCAN_INTERNAL_WORKER_TOKEN=sigurscan-internal-worker-token:latest" in script
    assert ",INTERNAL_WORKER_TOKEN=" not in script
    assert " INTERNAL_WORKER_TOKEN=" not in script
    assert "OPENAPI_RO_API_KEY_SECRET-openapi-ro-api-key:latest" in script
    assert "OPENAPI_RO_API_KEY=$OPENAPI_RO_API_KEY_SECRET" in script
    assert "OPENAPI_RO_MONTHLY_BUDGET=100" in script
    assert "HUNTER_IO_API_KEY_SECRET-hunter-io-api-key:latest" in script
    assert "HUNTER_IO_API_KEY=$HUNTER_IO_API_KEY_SECRET" in script
    assert "HUNTER_IO_MONTHLY_BUDGET=50" in script


def test_backend_ci_installs_pytest_before_running_backend_tests():
    workflow = (ROOT_DIR / ".github" / "workflows" / "backend-ci.yml").read_text(
        encoding="utf-8"
    )
    install_block = workflow.split("- name: Install backend dependencies", 1)[1].split(
        "- name: Run backend tests",
        1,
    )[0]

    assert "python -m pip install -r requirements.lock" in install_block
    assert "python -m pip install pytest pytest-asyncio" in install_block
    assert "python -m pytest -q" in workflow


def test_email_compound_evidence_stays_off_in_ci_and_cloud_run_defaults():
    workflow = (ROOT_DIR / ".github" / "workflows" / "backend-ci.yml").read_text(
        encoding="utf-8"
    )
    deploy = (ROOT_DIR / "tools" / "deploy_cloud_run_backend.sh").read_text(
        encoding="utf-8"
    )

    assert workflow.count('EMAIL_COMPOUND_EVIDENCE_ACTIVE: "false"') == 2
    assert "EMAIL_COMPOUND_EVIDENCE_ACTIVE=false" in deploy


def test_email_compound_measurement_is_shadow_only_and_aggregate_by_default():
    report = json.loads(
        (ROOT_DIR / "backend" / "data" / "eval" / "email_compound_measurement_v2026_07_17.json")
        .read_text(encoding="utf-8")
    )

    assert report["active_flag"] is False
    assert report["case_count"] == 160
    assert report["measured_case_count"] == 160
    assert report["error_count"] == 0
    assert report["cases_with_attachments"] == 0
    assert "rows" not in report
    assert sum(report["source_set_case_counts"].values()) == report["case_count"]


def test_action_asset_measurement_is_shadow_only_private_and_meets_stage_two_gates():
    report = json.loads(
        (
            ROOT_DIR
            / "backend"
            / "data"
            / "eval"
            / "action_asset_shadow_measurement_v2026_07_18.json"
        ).read_text(encoding="utf-8")
    )
    serialized = json.dumps(report, ensure_ascii=False)

    assert report["schema"] == "sigurscan_action_asset_shadow_measurement_v1"
    assert len(report["implementation_sha256"]) == 64
    assert report["corpus"]["deduplicated_case_count"] == 2294
    assert report["corpus"]["evaluated_cases"] == 2294
    assert report["corpus"]["errors"] == {}
    assert report["results"]["protected_floor_coverage"] == 1.0
    assert report["results"]["protected_expected_risk_false_safe_after_shadow"] == 0
    assert report["results"]["expected_safe_candidate_dangerous"] == 0
    assert report["acceptance"]["protected_expected_risk_false_safe_pass"] is True
    assert report["acceptance"]["expected_safe_candidate_dangerous_rate_pass"] is True
    assert report["decision"]["shadow_only"] is True
    assert report["decision"]["active_flag_default"] is False
    assert report["decision"]["activation_authorized"] is False
    assert "rows" not in report
    assert "text_preview" not in serialized
    assert "raw_text" not in serialized
    assert "case_id" not in serialized


def test_backend_ci_guards_tracked_local_secrets_before_tests():
    workflow = (ROOT_DIR / ".github" / "workflows" / "backend-ci.yml").read_text(
        encoding="utf-8"
    )
    guard_index = workflow.index("python tools/guard_no_tracked_secrets.py")
    install_index = workflow.index("- name: Install backend dependencies")

    assert guard_index < install_index


def test_runtime_knowledge_builder_preserves_imported_official_registry_updates():
    module = _load_module(
        BACKEND_DIR / "tools" / "build_runtime_knowledge.py",
        "build_runtime_knowledge_preserve_registry_test",
    )

    payload = module.build_brand_pack_payload(
        {
            "official_registry_updates": [
                {
                    "brand_id": "anaf",
                    "display_name": "ANAF",
                    "official_domains": ["anaf.ro"],
                }
            ],
            "brand_warnings": [],
            "claim_verifier_targets": [],
            "false_positive_guards": [],
            "signal_mapping": [],
            "sources": {},
        },
        {
            "metadata": {
                "official_domain_registry_sources": ["pack3.zip"],
                "official_domain_registry_import_summary": {"updates_added": 126},
            },
            "brand_registry": {
                "Instituția Prefectului – Județul Alba": ["ab.prefectura.mai.gov.ro"]
            },
            "official_registry_updates": [
                {
                    "brand_id": "prefectura_alba",
                    "display_name": "Instituția Prefectului – Județul Alba",
                    "exact_hosts": ["ab.prefectura.mai.gov.ro"],
                    "match_policy": "exact_host",
                    "source_pack": "official-domain-registry-ro-pack3-prefectures-labour-health",
                }
            ],
        },
    )

    updates = {entry["brand_id"]: entry for entry in payload["official_registry_updates"]}
    assert "anaf" in updates
    assert updates["prefectura_alba"]["match_policy"] == "exact_host"
    assert payload["metadata"]["official_domain_registry_sources"] == ["pack3.zip"]
    assert payload["metadata"]["official_domain_registry_import_summary"]["updates_added"] == 126


def test_tracked_secret_guard_blocks_local_secret_filenames():
    module = _load_module(
        ROOT_DIR / "tools" / "guard_no_tracked_secrets.py",
        "guard_no_tracked_secrets_test",
    )

    assert module._is_denied_tracked_path("backend/.env.vercel")
    assert module._is_denied_tracked_path("local.properties")
    assert module._is_denied_tracked_path("keystore.properties")
    assert module._is_denied_tracked_path("release/upload.jks")
    assert module._is_denied_tracked_path("google-service-account.json")
    assert not module._is_denied_tracked_path("backend/.env.example")
    assert not module._is_denied_tracked_path("workers/precapture/.env.example")
    assert not module._is_denied_tracked_path("tools/audit_android_release_secrets.py")


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


def test_supabase_migration_workflow_uses_db_url_secret_and_dry_run_guard():
    workflow = (ROOT_DIR / ".github" / "workflows" / "supabase-migrations.yml").read_text(
        encoding="utf-8"
    )

    assert "workflow_dispatch:" in workflow
    assert "push:" in workflow
    assert "supabase/setup-cli@v2" in workflow
    assert "SUPABASE_DB_URL: ${{ secrets.SUPABASE_DB_URL }}" in workflow
    assert "supabase db push --db-url \"$SUPABASE_DB_URL\" --dry-run" in workflow
    assert "github.event_name == 'push' || github.event.inputs.apply == 'true'" in workflow
    assert 'echo "$SUPABASE_DB_URL"' not in workflow


def test_new_service_role_supabase_tables_are_rls_private():
    migration_paths = [
        ROOT_DIR / "supabase" / "migrations" / "20260616090000_create_reputation_graph_v1.sql",
        ROOT_DIR / "supabase" / "migrations" / "20260616093000_create_circle_delivery_outbox.sql",
    ]

    for path in migration_paths:
        sql = path.read_text(encoding="utf-8").lower()
        assert "enable row level security" in sql
        assert "revoke all on table" in sql
        assert "from anon" in sql
        assert "from authenticated" in sql
        assert "to service_role" in sql


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


def test_android_release_enables_r8_with_safe_keep_rules():
    gradle = (ROOT_DIR / "app" / "build.gradle.kts").read_text(encoding="utf-8")
    proguard = (ROOT_DIR / "app" / "proguard-rules.pro").read_text(encoding="utf-8")

    assert "isMinifyEnabled = true" in gradle
    assert "isShrinkResources = true" in gradle
    assert "-keep class ro.sigurscan.app.** { *; }" in proguard
