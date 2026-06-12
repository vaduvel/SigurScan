# SigurScan Freeze Proof - 2026-06-12

Status: in progress. This document is proof-led: an item is not green unless the evidence below can be rerun.

## Source Of Truth

- Repository: `vaduvel/SigurScan`
- Local repo: `/Users/vaduvageorge/AndroidStudioProjects/SigurScan`
- Current branch: `main`
- Verified code commit: `4918162`
- Deployed code commit: `4918162`
- Documentation may advance past the deployed code commit with proof-only updates.
- Cloud Run project: `project-20f225c0-d756-4cba-864`
- Cloud Run service: `sigurscan-api`
- Cloud Run region: `europe-west1`
- Official API domain: `https://api.sigurscan.com`

## Zone 1 - Google Cloud Run

### Verified

- Cloud Run service exists in `europe-west1`.
  Evidence: `gcloud run services describe sigurscan-api --project project-20f225c0-d756-4cba-864 --region europe-west1`.
- Latest ready revision is `sigurscan-api-00025-vg5`.
- Traffic is `100%` to `sigurscan-api-00025-vg5`.
- Deployed image is `europe-west1-docker.pkg.dev/project-20f225c0-d756-4cba-864/sigurscan/sigurscan-api:4918162`.
- Deployed image digest is `sha256:1951be05e620f71b74923f4d6460ab36f322767f98f14987e38ff20eea11d1c7`.
- Latest Cloud Build deployment proof:
  - build id: `c87c4cb2-c160-4abc-95a5-624a611eeb16`
  - status: `SUCCESS`
  - deployed revision: `sigurscan-api-00025-vg5`
- Cloud Build deployment proof:
  - build id: `8088b6e7-7662-43fb-936a-494baffbd5a2`
  - status: `SUCCESS`
  - service URL: `https://sigurscan-api-357849228072.europe-west1.run.app`
- Container build is reproducible:
  - base image is pinned by digest to Python `3.12.13-slim-trixie`.
  - Python dependencies are installed from `backend/requirements.lock` with `--require-hashes`.
  - dynamic `pip install --upgrade pip` and unnecessary apt/curl installation were removed.
  - zero-cache local Docker build completed successfully.
  - local container `/health` returned `HTTP 200`, `pip check` found no broken requirements, and importing `main` exposed `39` routes.
  - Cloud Build log for `8088b6e7-7662-43fb-936a-494baffbd5a2` contained no warning/error/failed tokens.
  - contract test: `backend/test_container_contract.py` passes.
- Request timeout is `300s`.
- Container concurrency is `2`.
  - It was reduced during Zone 8 hardening from the earlier high-concurrency posture after live scan probes showed better request stability for the current monolith on Cloud Run.
  - No code redeploy was required for this tuning; the deployed image remains `4918162`.
- CPU/memory are `1 CPU` / `1Gi`.
- Min instances is `1`; max instances is `5`.
- CPU throttling is `true`, preserving request-based CPU billing rather than always-allocated CPU.
- Startup CPU boost is enabled.
- Provider secrets are injected through Secret Manager references, including Supabase, Gemini, Vision, Web Risk, Mistral, urlscan, URLhaus, Upstash, app API keys, admin API keys, and `invoice-cache-hmac-key`.
- Invoice cache HMAC uses only `INVOICE_CACHE_HMAC_KEY` from Secret Manager/env.
  - Legacy fallback string `sigurscan-cache-key-v1` has been removed from runtime code.
  - `gcloud secrets list` confirms `invoice-cache-hmac-key` exists in Secret Manager.
  - `gcloud secrets list` does not show a separate `sigurscan-cache-key-v1` secret.
  - Cloud Run injects `INVOICE_CACHE_HMAC_KEY=invoice-cache-hmac-key:latest`.
  - Test proof: `test_invoice_cache_key_requires_env_secret` fails without env and passes with the test fixture env.
- Health check returns `HTTP 200` through Cloudflare on `https://api.sigurscan.com/health`.
  - Post-deploy health after `4918162`: `HTTP 200`, `0.442909s`.
  - Post-deploy health after `45b5663`: `HTTP 200`, `1.168s`; runtime reports `rate_limit_backend=upstash`, `api_key_required=true`.
  - Post-deploy health after `21a6943`: `HTTP 200`, `0.361590s`.
  - Post-deploy health after `17dcfc7`: `HTTP 200`, `0.336330s`.
  - Post-deploy health after `e55bc7b`: `HTTP 200`, `0.288110s`.
  - Post-deploy health after `d9d452c`: official domain `HTTP 200`, `0.369934s`; raw Run URL `HTTP 200`, `0.164767s`.
- API protection is active:
  - unauthenticated `POST /v1/scan/orchestrated` returns `401`.
  - authenticated `POST /v1/scan/orchestrated` returns `200` and creates a scan.
- Cloud Billing budget guard exists for this project:
  - billing account: `018B56-5DF133-D4A772`
  - budget id: `95a50d26-6008-4a9b-84f7-22d36d786ff5`
  - display name: `SigurScan Cloud Run Guard`
  - amount: `20 USD` monthly
  - project filter: `projects/357849228072`
  - thresholds: `50% current`, `100% current`, `100% forecasted`
- Cloud Logging latency outlier metric exists:
  - metric id: `sigurscan_poll_latency_over_8s`
  - filter: Cloud Run `GET /v1/scan/orchestrated/{id}` with `httpRequest.latency > 8s`
  - validation read returned `[]` before creation, proving the filter parses and no current outlier was present.
- Cloud Monitoring alert policy exists:
  - policy id: `9868521767490194527`
  - display name: `SigurScan orchestrated poll latency > 8s`
  - condition: any logged poll-latency metric count greater than `0` over a `300s` alignment window.
- Cloud Monitoring error-rate alert policy exists:
  - display name: `SigurScan Cloud Run 5xx errors > 0`
  - condition: any `5xx` response from Cloud Run service `sigurscan-api`.
  - status: enabled.
- Alert caveat:
  - both alert policies are enabled, but no notification channel is attached yet.
  - this is acceptable as proof of monitoring rules, but not sufficient as production paging/email alerting until a notification channel is added.
- Cloud Logging structured-error/request proof captured:
  - controlled request: authenticated `GET /v1/scan/orchestrated/freeze-proof-missing-scan-1781272609`.
  - client response: `HTTP 404`, `2.968071s`, JSON body `{"detail":"Scanarea nu a fost gasita sau a expirat."}`.
  - Cloud Logging entry:
    - timestamp: `2026-06-12T13:56:49.348815Z`
    - revision: `sigurscan-api-00020-xvd`
    - severity: `WARNING`
    - method/status: `GET` / `404`
    - server latency: `0.682251566s`
    - user-agent: `SigurScan/1.0 Android OkHttp`
- Authenticated smoke scan through official domain completed:
  - scan id: `orch_1781267052_627619ad`
  - poll 1: `SUSPECT`, `is_final=false`, `1.532s`
  - poll 2: `SUSPECT`, `is_final=true`, `4.262s`
- Live provider smoke after commit `cf842d2` passed:
  - report: `build/reports/live_provider_smoke_after_upfront_fee_fix_2026-06-12.json`
  - result: `5/5 passed`.
- Offer latency re-check through `https://api.sigurscan.com` with Android UA:
  - 4 consecutive OP-08 scans.
  - POST range: `0.487s` - `1.320s`.
  - Polls to provisional verdict: under `0.91s`.
  - Final poll range: `3.341s` - `3.546s`.
  - No `29s` poll reproduced in this run.
  - Captured scan ids: `orch_1781268026_47cf2e9a`, `orch_1781268035_bd224992`, `orch_1781268043_411c19b7`, `orch_1781268051_94f80036`.
- Warm Cloud Run smoke after `17dcfc7` through `https://api.sigurscan.com` with Android UA:
  - input: benign DNSC official URL smoke.
  - POST: `HTTP 200`, `1.434s`, scan created.
  - poll 1: `HTTP 200`, `4.382s`, total `5.815s`, `SIGUR`, `risk=low`, `is_final=false`, preview `ready`.
  - poll 2: `HTTP 200`, `4.307s`, total `11.131s`, `SIGUR`, `risk=low`, `is_final=true`, preview `ready`.
- Quota-safe live URL-provider smoke through `https://api.sigurscan.com` with Android UA after proof commit `e49ace6`:
  - input: benign DNSC official URL smoke.
  - POST: `HTTP 200`, `1.103s`, scan created.
  - poll 1: `HTTP 200`, `3.159s`, total `4.772s`, `SIGUR`, `risk=low`, `is_final=false`, preview `ready`.
  - poll 2: `HTTP 200`, `4.281s`, total `11.057s`, `SIGUR`, `risk=low`, `is_final=true`, preview `ready`.
- Cloud Build log audit for build `8d7baef8-3a79-482c-be3c-c7d4e0823ef8` found no build failures/errors; only two standard Docker `pip as root` warnings.
- Authenticated lightweight concurrency probe through `https://api.sigurscan.com/health` with Android UA:
  - 20 requests, 10 workers.
  - result: `20/20 HTTP 200`, `0` errors.
  - total wall time: `5.577s`.
  - latency: min `0.150s`, p50 `0.224s`, p95 `0.300s`, max `5.343s`.
- Controlled scan concurrency probe through `https://api.sigurscan.com` with Android UA:
  - 3 concurrent `input_type=offer` text-only scans.
  - No URL was included, avoiding urlscan/Web Risk/URLhaus calls.
  - result: `3/3` POST `HTTP 200`, `3/3` final polls `HTTP 200`.
  - wall time: `9.872s`.
  - final labels: `SUSPECT`, `PERICULOS`, `SUSPECT`.
  - final per-scan totals: `9.862s`, `9.629s`, `9.869s`.
- Controlled five-scan concurrency probe after deploy `d9d452c`:
  - 5 concurrent `input_type=offer` text-only scans, without URLs, so external URL-provider quota was not consumed.
  - official domain: `5/5` finalized, `0` failures, wall time `12.276s`, max per-scan total `12.269s`, max poll `4.944s`.
  - direct Cloud Run URL: `5/5` finalized, `0` failures, wall time `11.677s`, max per-scan total `11.673s`, max poll `5.158s`.
  - an earlier probe had one client-side `15s` read timeout, but Cloud Run request logs showed every received request below `4.751s`; the immediate controlled rerun above did not reproduce it through either path.
- Android emulator E2E through the installed debug app:
  - Device: `emulator-5554`.
  - App package: `ro.sigurscan.app`.
  - Installed with `./gradlew :app:installDebug`.
  - Input entered in the UI: `https://dnsc.ro/`.
  - Result after polling: `SIGUR`, `Verdict final`, `Verificari complete`.
  - Preview card rendered inside the app with final destination `https://dnsc.ro/`.
  - App crash log check: no SigurScan `AndroidRuntime` crash or fatal app exception found in the filtered logcat window; the only earlier crash was Android `uiautomator` itself while dumping UI hierarchy.
  - Screenshot evidence: `docs/freeze/evidence/android_e2e_dnsc_sigur_preview_2026-06-12.png`.
- Android emulator offer/text-only E2E through the installed debug app:
  - Device: `emulator-5554`.
  - App package: `ro.sigurscan.app`.
  - Input entered in the UI: `job pe telegram profit garantat 500 USD pe zi contact Frank`.
  - Result after polling: `SUSPECT`, `Verdict final`, `Verificari complete`.
  - This is acceptable as a non-safe verdict for a text-only OP-08 style job/profit claim; it is not marked as a `PERICULOS` recall proof because the shortened test input intentionally avoided long paste/share text and did not include a complete URL.
  - App crash log check: no SigurScan `AndroidRuntime` crash or fatal app exception found in the filtered logcat window.
  - UX/copy gap found: for this no-link text-only case the result explanation still says it checked a final link and secure preview. That text must be split by input type before release.
  - Screenshot evidence: `docs/freeze/evidence/android_e2e_offer_text_only_suspect_2026-06-12.png`.
- Android emulator invoice image E2E through the installed debug app:
  - Device: `emulator-5554`.
  - App package: `ro.sigurscan.app`.
  - Input: generated Romanian invoice PNG pushed to emulator Downloads and selected from Android DocumentsUI.
  - Result screen rendered `Scanare Factură` with extracted issuer `DIGI ROMANIA S.A.`, CUI `5888716`, IBAN `RO49AAAA1B31007593840000`, invoice number `TEST-2026-0612`, issue date `2026-06-12`, due date `2026-06-27`, subtotal `84.03 RON`, VAT `15.97 RON`, and total `100.00 RON`.
  - App crash log check: no SigurScan `AndroidRuntime` crash, fatal exception, or ANR found in the filtered logcat window.
  - Defect found before backend fix: live CUI fallback found `DIGI ROMANIA S.A.` in provider raw data but mapped it as `exists=false`, so the UI showed `CUI 5888716 not found in ANAF registry`.
  - Backend fix proof: `check_cui("5888716")` and `check_cui("RO5888716")` now return `exists=true`, `checked=true`, `denumire="DIGI ROMANIA S.A."`, `activ=true`.
  - Test proof: backend full suite after the fix: `662 passed, 1 warning`.
  - Before-fix screenshot evidence: `docs/freeze/evidence/android_e2e_invoice_digi_attention_before_cui_fallback_fix_2026-06-12.png`.
- Invoice finalize fix after deploy `e55bc7b`:
  - Root cause: invoice fast-lane produced an internal `SIGUR` bundle, but generic finalization recomputed it as text/payment risk and exposed public `SUSPECT`.
  - Fix: invoice and offer specialized decision bundles are now preserved during orchestrated finalization.
  - Backend full suite after the fix: `663 passed, 1 warning`.
  - Live API smoke through `https://api.sigurscan.com` with Android UA:
    - POST: `HTTP 200`, `1.358s`, scan id `orch_1781279790_48bef996`.
    - poll 1: `HTTP 200`, `1.376s`, no public label yet.
    - poll 2: `HTTP 200`, `0.893s`, `SIGUR`, `is_final=false`.
    - poll 3: `HTTP 200`, `3.516s`, `SIGUR`, `is_final=true`, status `complete`.
    - top-level gate: `SIGUR`, reason `official_clean`.
    - invoice gate: `SIGUR`, reason `official_clean`.
    - invoice warnings: `[]`.
  - Android emulator after-fix proof:
    - Installed with `./gradlew :app:installDebug`.
    - Input: generated Romanian invoice PNG selected through Android DocumentsUI.
    - Result: `Scanare Factură` screen shows status `Verificat`, issuer `DIGI ROMANIA S.A.`, CUI `5888716`, IBAN valid `Da`, invoice number `TEST-2026-0612`, dates and totals.
    - App-only logcat check: no SigurScan `AndroidRuntime` crash, fatal exception, or ANR found.
    - Screenshot evidence: `docs/freeze/evidence/android_e2e_invoice_digi_verified_after_invoice_finalize_fix_2026-06-12.png`.
- Rollback is proven end-to-end:
  - traffic was moved temporarily from current revision `sigurscan-api-00023-58k` to previous revision `sigurscan-api-00022-wj8`.
  - while rolled back, `https://api.sigurscan.com/health` returned `HTTP 200` in `0.252051s`.
  - traffic was restored immediately to `sigurscan-api-00023-58k`.
  - after restore, `https://api.sigurscan.com/health` returned `HTTP 200` in `0.264415s`.
  - final state: `100%` traffic on `sigurscan-api-00023-58k`.
- Post-deploy latency re-check after `21a6943`:
  - Existing scan `orch_1781268789_c6e92ca2` returned `HTTP 200` in `4.008s` and was already `complete`, `SUSPECT`, `is_final=true`.
  - New offer scan `orch_1781269113_5074e703`:
    - POST: `HTTP 200`, `0.548s`
    - poll 1: `HTTP 200`, `0.807s`, still scanning
    - poll 2: `HTTP 200`, `0.755s`, `SUSPECT`, `is_final=false`
    - poll 3: `HTTP 200`, `3.407s`, `SUSPECT`, `is_final=true`
  - Cloud Run request logs for `orch_1781269113_5074e703` show server-side GET latencies of `0.501767931s`, `0.517308680s`, and `3.180505344s`.
  - A previous local `urllib` poll timeout was not reproduced with `requests`; Cloud Run logs for that scan showed quick server responses. Treat remaining risk as edge/client-path observability, not a confirmed backend handler latency defect.
- Zone 8 runtime hardening after container-concurrency tuning:
  - Domain health after tuning:
    - `https://api.sigurscan.com/health`: `HTTP 200`, `0.276s`.
    - direct Cloud Run health: `HTTP 200`, `0.146s`.
    - runtime config reports `api_key_required=true`, `admin_api_configured=true`, `rate_limit_backend=upstash`.
    - report: `build/reports/freeze/zone8_domain_health_after_tuning_2026-06-12.json`.
  - Single warm text-only scan:
    - POST `1.188s`.
    - provisional public verdict after first poll in roughly `2.5s` total.
    - final `SUSPECT` in `7.131s` total.
    - report: `build/reports/freeze/zone8_live_single_warm_2026-06-12.json`.
  - 8 simultaneous text-only scans before final tuning:
    - `8/8` finalized.
    - no `5xx`.
    - poll p50 `4.847s`, poll max `9.367s`.
    - total p50 `15.725s`, total max `16.244s`.
    - report: `build/reports/freeze/zone8_live_concurrency_admin_2026-06-12.json`.
  - 8 simultaneous text-only scans after `containerConcurrency=2`:
    - `8/8` finalized.
    - no `5xx`.
    - poll p50 `5.041s`, poll max `8.328s`.
    - total p50 `14.849s`, total max `15.565s`.
    - report: `build/reports/freeze/zone8_live_concurrency_after_concurrency2_2026-06-12.json`.
  - 4 simultaneous text-only scans after `containerConcurrency=2`:
    - `4/4` finalized.
    - no `5xx`.
    - poll p50 `3.283s`, poll max `6.049s`.
    - total p50 `8.992s`, total max `9.147s`.
    - report: `build/reports/freeze/zone8_live_concurrency4_after_concurrency2_2026-06-12.json`.
  - Interpretation:
    - normal single-user and 4-concurrent paths are within the current target posture.
    - 8 simultaneous text-only scans are stable and complete, but remain a capacity watch item because max poll latency is near/above the `8s` alert threshold.
- Zone 8 admin telemetry proof:
  - `/v1/orchestration/telemetry`: `HTTP 200`, JSON response, keys include `alerts`, `by_event_type`, `by_stage`, `conflicts`, `polls_to_final`, `stage_latency_ms`, `time_to_final_ms`, and `urlscan`.
  - `/v1/orchestration/dashboard`: `HTTP 200`, HTML dashboard response.
  - `/v1/feedback/summary`: `HTTP 200`, JSON response with accuracy/precision/recall/f1 summary fields.
  - `/v1/reputation/cache/stats`: `HTTP 200`, JSON response.
  - telemetry summary: `alerts_count=0`, `urlscan.pending_timeout_events=0`, `urlscan.pending_timeout_rate=0.0`.
  - reports:
    - `build/reports/freeze/zone8_admin_endpoints_live_2026-06-12.json`
    - `build/reports/freeze/zone8_admin_telemetry_summary_2026-06-12.json`
- Zone 8 log hygiene proof:
  - controlled live scan included a unique marker plus fake OTP, CNP, IBAN, and card-number values.
  - `300` Cloud Run log entries were checked.
  - exact sensitive matches found: `0` for marker, OTP, CNP, IBAN, and card number.
  - request report: `build/reports/freeze/zone8_log_hygiene_probe_request_2026-06-12.json`.
  - log report: `build/reports/freeze/zone8_cloud_run_log_hygiene_2026-06-12.json`.
- Zone 8 regression/provider-degrade proof:
  - targeted atlas/knowledge/gate/invoice/security/latency regression:
    - command: `python3 -m pytest backend/test_offer_corpus_recall.py backend/test_family_classifier.py backend/test_scam_atlas_contract.py backend/test_scam_atlas_impersonation.py backend/test_impersonation_knowledge_builder.py backend/test_verdict_gate.py backend/test_offer_gate_combos.py backend/test_legal_layer.py backend/test_registry_verification.py backend/test_invoice_orchestration.py backend/test_invoice_endpoint.py backend/test_invoice_parser.py backend/test_invoice_readiness_gate.py backend/test_invoice_coherence.py backend/test_security_hardening.py backend/test_orchestrated_latency.py -q`
    - result: `231 passed, 1 warning`.
    - report: `build/reports/freeze/zone8_regression_junit_2026-06-12.xml`.
  - provider degrade/error handling regression:
    - command: `python3 -m pytest backend/test_anaf_cui.py backend/test_anaf_cui_offer.py backend/test_offer_web_confirm.py backend/test_registry_verification.py backend/test_backend.py::test_gemini_explainer_handles_timeout_gracefully backend/test_backend.py::test_offer_claim_gemini_grounding_is_bounded_for_25_flash backend/test_backend.py::test_reputation_cache_refetches_when_configured_source_was_not_consulted -q`
    - result: `54 passed, 1 warning`.
    - report: `build/reports/freeze/zone8_provider_degrade_junit_2026-06-12.xml`.

### Not Yet Green

- Cold-start test after 15 minutes idle has not been run.
- Full URL-provider scan concurrency/load test has not been run; only single URL-provider smoke and text-only scan concurrency are proven, deliberately avoiding quota burn.
- Latency outlier root-cause is not fully closed: a prior live run had one `29s` poll. Latest single-user, 4-concurrent, and 8-concurrent probes did not produce `5xx`, but 8-concurrent text-only scans can still approach the `8s` poll alert threshold. This remains a capacity/observability watch item rather than a confirmed handler crash.
- Cloud Monitoring policies exist and are enabled, but no notification channel is attached yet.

### Immediate Fixes

1. Run cold-start proof after an idle window if we ever reduce `min-instances` back to `0`.
2. Run a tiny URL-provider scan concurrency probe only when rate-limit budget allows.
3. Attach an email notification channel to the Cloud Monitoring policies before public launch.
4. Keep the latency alert active and investigate any future poll over `8s` with its Cloud Run request log and edge path.

## Zone 2 - Cloudflare Official Domain

### Verified

- `https://api.sigurscan.com/health` responds with `HTTP/2 200`.
- HTTP requests are redirected before hitting the origin:
  - `http://api.sigurscan.com/health` returns `HTTP 308`.
  - `Location: https://api.sigurscan.com/health`.
  - `cache-control: no-store`.
  - `x-sigurscan-edge: cloudflare`.
- TLS certificate proof:
  - certificate subject: `CN=sigurscan.com`.
  - issuer: `Google Trust Services WE1`.
  - validity: `2026-06-11` through `2026-09-09`.
  - SAN contains `sigurscan.com`, `api.sigurscan.com`, and `*.api.sigurscan.com`.
- Cloudflare Worker proxy version deployed:
  - worker: `sigurscan-api-proxy`.
  - version id: `d5e812eb-baca-4b88-95af-595966e1613c`.
  - route: `api.sigurscan.com`.
  - `workers/api-proxy` test suite: `5/5 passed`.
- Response headers show Cloudflare in the path:
  - `server: cloudflare`
  - `cf-cache-status: DYNAMIC`
  - `x-sigurscan-edge: cloudflare`
  - `cache-control: no-store`
- Official domain health body reports:
  - `rate_limit_enabled=true`
  - `rate_limit_backend=upstash`
  - `api_key_required=true`
  - configured providers: urlscan, Google Web Risk, Phishing.Database, URLhaus, Mistral/Gemini explanation, offer claim verifier.
- Cloudflare user-agent behavior is explicit:
  - Default `curl` UA: `HTTP 200` on `/health`.
  - `Python-urllib/3.14`: `HTTP 403` at the Cloudflare edge.
  - Android-style UA `okhttp/4.12.0 SigurScan/1.0 Android`: `HTTP 200`.
  - Android app now sends a stable `User-Agent: SigurScan/1.0 Android OkHttp` through `ApiKeyInterceptor`.
  - Post-`21a6943` proof:
    - `Python-urllib/3.14`: `HTTP 403`, `0.103618s`
    - `SigurScan/1.0 Android OkHttp`: `HTTP 200`, `0.184060s`
    - authenticated Android UA health: `HTTP 200`, `0.164287s`
  - This is a Cloudflare/WAF user-agent rule, not CORS. QA scripts and legitimate non-Android clients must send an app-like UA or be allowlisted intentionally.
- `/v1/*` edge behavior after Worker deploy `d5e812eb-baca-4b88-95af-595966e1613c`:
  - unauthenticated `POST https://api.sigurscan.com/v1/scan/orchestrated` returns `HTTP 401` in `0.281984s`.
  - response includes `cache-control: no-store`.
  - response includes `x-sigurscan-edge: cloudflare`.
  - backend body is preserved: `{"detail":"Missing or invalid API key."}`.

### Not Yet Green

- Cloudflare timeout behavior for long scans not tested.
- Android mobile-network test on 4G/5G not recorded.

## Zone 3 - Supabase

### Verified

- Supabase CLI version used for this proof: `2.101.0`.
- Remote migration list matches local migrations:
  - `20260525091000`
  - `20260525092000`
  - `20260528001000`
  - `20260528002000`
  - `20260603031448`
  - `20260603093000`
  - `20260609120852`
  - `20260609175707`
  - `20260609181828`
  - `20260609185251`
  - `20260609212500`
  - `20260609214000`
- Required runtime tables exist in `public`:
  - `scan_jobs`
  - `urlscan_preview_cache`
  - `fast_preview_cache`
  - `fast_preview_alias_cache`
  - `fast_preview_capture_runs`
- RLS is enabled on all five runtime tables above.
- `anon` and `authenticated` have no direct table privileges on those five runtime tables.
- Storage bucket proof:
  - bucket `previews` exists.
  - bucket is private: `public=false`.
  - file size limit: `5242880`.
  - allowed MIME type: `image/png`.
- Fast preview structural constraints exist:
  - `fast_preview_cache_visual_only_chk`
  - `fast_preview_cache_status_chk`
  - `fast_preview_alias_cache_final_url_hash_fkey`
- Live Cloud Run -> Supabase write proof through `https://api.sigurscan.com`:
  - scan id: `orch_1781289050_c007425e`.
  - request: authenticated `POST /v1/scan/orchestrated` with Android UA.
  - POST latency: `1.439s`.
  - poll latencies: `1.361s`, `4.732s`.
  - final API status: `complete`.
  - final label: `SUSPECT`.
  - Supabase `scan_jobs` row exists with:
    - `status=complete`.
    - `input_type=text`.
    - `source_channel=android_native`.
    - `created_at` present.
    - `updated_at` present.
    - `expires_at > now()`.
    - `payload.result` present.
    - `payload.pipeline_stage=analysis_ready`.

### Not Yet Green

- Backup / point-in-time recovery was not confirmed from the CLI. Needs dashboard or management API proof before the whole Zone 3 can be signed as fully green.
- Dedicated Supabase connection-pool pressure test was not run. Existing five-scan Cloud Run concurrency did not expose a DB failure, but it is not a standalone pool exhaustion proof.

## Zone 4 - Cache And Providers

### Verified

- Local provider/cache/orchestration regression suite passed:
  - Command: `python3 -m pytest backend/test_anaf_cui.py backend/test_anaf_cui_offer.py backend/test_backend.py backend/test_invoice_orchestration.py backend/test_orchestrated_latency.py backend/test_preview_preseed_tool.py backend/test_tooling_defaults.py -q`
  - Result: `266 passed, 1 warning`.
- Security hardening suite passed:
  - Command: `python3 -m pytest backend/test_security_hardening.py -q`
  - Result: `18 passed, 1 warning`.
- Remote reputation-cache stats bug was fixed in `45b5663`:
  - Runtime now reads Supabase-backed cache stats even when the local cache file does not exist.
  - Targeted proof: `python3 -m pytest backend/test_backend.py -q -k "reputation_cache_stats_reads_remote_cache_without_local_file or supabase_reputation_cache_uses_single_batch_upsert or local_reputation_cache_is_lru_capped"` -> `3 passed`.
  - Combined hardening/default proof after patch: `python3 -m pytest backend/test_security_hardening.py backend/test_tooling_defaults.py -q` -> `20 passed, 1 warning`.
  - Full backend suite after patch: `665 passed, 1 warning`.
- Provider behavior is verified through live smoke on the official API domain:
  - urlscan returned report/screenshot for benign YOXO and eMAG flows.
  - Google Web Risk was consulted and returned clean in the recorded live flows.
  - Phishing.Database produced a malicious hard-provider verdict for the `live_google_webrisk_phishing_test` fixture.
  - URLhaus was consulted and returned clean in the recorded live flows.
  - offer claim verifier ran in skipped/disabled mode where configured; it did not block the provider-gate result.
- Live reputation-cache stats through `https://api.sigurscan.com/v1/reputation/cache/stats`:
  - HTTP `200`, `1.188s`.
  - `loaded=true`, `items=66`, `valid_items=6`, `expired_items=60`, `invalid_items=436`.
  - verdict counts: `clean=64`, `malicious=1`, `suspicious=1`.
  - source stats: Google Web Risk `66/66` consulted clean; Phishing.Database `66/66` consulted with `1` malicious; URLhaus `66/66` consulted with `1` malicious.
- Supabase cache snapshot:
  - `url_reputation_cache`: `502` rows, `6` valid.
  - version `3`: `66` rows, `6` valid.
  - version `2` legacy cache rows are all invalid/expired for current runtime and ignored by version/TTL checks.
- Quota-safe live URL-provider smoke through official domain:
  - case: `live_emag_tracking_official`.
  - status: passed.
  - final label: `SIGUR`, status `complete`, `is_final=true`, risk `low`.
  - provider gate reason: `official_clean`.
  - timings: scan id `1.33s`, verdict `7.69s`, preview report `2.36s`, screenshot `2.36s`, completion `9.03s`.
  - provider summary keys included `ai_offer_web_check`, `google_web_risk`, `infra_domain_age`, `phishing_database`, `urlhaus`, and `urlscan`.

### Not Yet Green

- Full live URL-provider concurrency was intentionally not run to avoid burning provider quota.
- Legacy reputation-cache rows remain in Supabase but are ignored by current version/TTL logic. Cleanup can be done later as cache hygiene, not as a verdict blocker.

## Zone 5 - Android Direct Infrastructure

### Verified

- Android local configuration targets the official Cloudflare API domain:
  - `SIGURSCAN_BACKEND_BASE_URL=https://api.sigurscan.com/`
  - `SIGURSCAN_RELEASE_BACKEND_BASE_URL=https://api.sigurscan.com/`
  - `SIGURSCAN_PRIVACY_URL=https://api.sigurscan.com/privacy`
  - `SIGURSCAN_RELEASE_PRIVACY_URL=https://api.sigurscan.com/privacy`
- Android app API keys are configured for debug and release builds, but the proof intentionally records only `SET` and key length, never the secret value.
- Direct provider keys are disabled in Android build config:
  - `SIGURSCAN_ENABLE_DIRECT_PROVIDER_KEYS=false`
  - generated debug/release `URLSCAN_API_KEY=EMPTY`
  - generated debug/release `GOOGLE_WEB_RISK_API_KEY=EMPTY`
- `ApiKeyInterceptor` attaches:
  - `X-API-KEY` when a build key is present.
  - stable `User-Agent: SigurScan/1.0 Android OkHttp`.
- Android network timeouts match the current orchestration posture:
  - Retrofit/OkHttp `callTimeout=75s`
  - `readTimeout=75s`
  - `writeTimeout=30s`
  - `connectTimeout=20s`
  - Backend Cloud Run request timeout remains `300s`, so the app is the stricter client-side bound.
- Android build proof:
  - Command: `JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home" ./gradlew :app:testDebugUnitTest :app:assembleDebug :app:assembleRelease`
  - Result: `BUILD SUCCESSFUL`.
  - Release APK: `app/build/outputs/apk/release/app-release.apk`, size `16M`.
  - Debug APK: `app/build/outputs/apk/debug/app-debug.apk`, size `25M`.
  - Release lint vital completed as part of `assembleRelease`.
- Release signing proof:
  - Command: `apksigner verify --print-certs app/build/outputs/apk/release/app-release.apk` with Android Studio JBR.
  - Certificate DN: `CN=SigurScan, OU=Mobile Security, O=SigurScan, L=Bucharest, ST=Bucharest, C=RO`.
  - SHA-256 digest: `bfd7991c4a7d0c349ae41235f2c0b52d77962c5a9a6729aa3410c54840168b67`.

### Not Yet Green

- Physical-device release test has not been run yet.
- Mobile-network 4G/5G test has not been recorded yet.
- AVD `Medium_Phone_API_36.1` exists, but the emulator did not appear in ADB during this freeze continuation:
  - `adb devices` showed no attached devices.
  - `emulator -avd Medium_Phone_API_36.1 -no-snapshot-load` did not produce a booted ADB device within the wait window.
  - This is an environment availability gap, not an app build failure.
- Upload near `MAX_UPLOAD_BYTES=25MB` has not been run yet.
- Poor-network retry/timeout behavior has not been run yet.

## Zone 6 - Live Feature Flows

### Verified

- Backend Zone 6 regression suite passed after the PDF annotation fix:
  - Command: `python3 -m pytest backend/test_email_link_extraction.py backend/test_invoice_endpoint.py backend/test_invoice_parser.py backend/test_invoice_orchestration.py backend/test_invoice_readiness_gate.py backend/test_comprehensive_invoices.py backend/test_offer_parser.py backend/test_offer_signals.py backend/test_offer_orchestration.py backend/test_offer_corpus_recall.py backend/test_offer_gate_combos.py backend/test_offer_web_confirm.py backend/test_legal_layer.py backend/test_registry_verification.py backend/test_verdict_gate.py backend/test_orchestrated_latency.py backend/test_backend.py -q`
  - Result: `515 passed, 1 warning`.
- Full backend suite passed after the PDF annotation fix:
  - Command: `python3 -m pytest backend -q`
  - Result: `666 passed, 1 warning`.
- Quota-bounded live provider smoke through `https://api.sigurscan.com` passed:
  - report: `build/reports/freeze_zone6_live_provider_smoke_2026-06-12.json`
  - command: `backend/eval/live_provider_smoke_runner.py --base-url https://api.sigurscan.com --case live_yoxo_buyback --case live_emag_tracking_official --case live_google_webrisk_phishing_test`
  - result: `3/3 passed`.
  - `live_yoxo_buyback`: `SIGUR`, final URL `https://buyback.yoxo.ro/?r=1`, provider gate reason `official_clean`, completion `11.41s`, urlscan report and screenshot present.
  - `live_emag_tracking_official`: `SIGUR`, final URL `https://auth.emag.ro/user/login`, provider gate reason `official_clean`, completion `8.66s`, urlscan report and screenshot present.
  - `live_google_webrisk_phishing_test`: `PERICULOS`, final URL `https://00000000000000000000000000000000000000000.xyz/`, provider gate reason `provider_malicious`, completion `10.87s`.
  - Honesty note: this hard-provider proof was from Phishing.Database; Google Web Risk returned clean in this run, so this is not recorded as Web Risk-specific proof.
- Additional hard-provider phishing control through `https://api.sigurscan.com`:
  - report: `build/reports/freeze_zone6_webrisk_control_2026-06-12.json`
  - input: `http://testsafebrowsing.appspot.com/s/phishing.html`
  - result: `PERICULOS`, `risk=high`, `provider_gate_reason=provider_malicious`, completion `11.17s`.
  - provider statuses: `urlscan=malicious`, `google_web_risk=clean`, `phishing_database=clean`, `urlhaus=clean`.
  - Honesty note: despite the test URL name, this run proves the urlscan malicious path, not Google Web Risk.
- Email HTML hidden-link extraction is live:
  - extract report: `build/reports/freeze_zone6_email_html_extract_live_2026-06-12.json`
  - extracted URL: `https://www.emag.ro/order/tracking`
  - extracted button count: `1`
  - extracted button: text `Urmareste coletul`, `source_tag=a`, `source_attr=href`, `is_sensitive_cta=true`.
- Email HTML hidden-link scan is live:
  - scan report: `build/reports/freeze_zone6_email_html_hidden_link_live_2026-06-12.json`
  - result: `SIGUR`, `risk=low`, `status=complete`, `is_final=true`.
  - final URL: `https://auth.emag.ro/user/login`.
  - provider statuses: Google Web Risk clean, Phishing.Database clean, URLhaus clean, urlscan clean, domain age clean.
  - urlscan report and screenshot are present.
- PDF annotation links are extracted even when OCR has no useful text:
  - defect found before fix: `/v1/extract/pdf` returned `503` when OCR was empty before annotation URLs were processed.
  - fix commit: `4918162 fix: keep PDF annotation links when OCR is empty`.
  - targeted proof: `python3 -m pytest backend/test_backend.py -q -k "extract_pdf_returns_annotation_urls_when_ocr_is_empty or extract_pdf_annotation_links or scan_pdf_legacy_endpoint"` -> `5 passed`.
  - live report after deploy: `build/reports/freeze_zone6_pdf_extract_live_after_fix_2026-06-12.json`.
  - live result: `HTTP 200`, `0.81s`, `input_type=pdf_ocr`, extracted URL `https://dnsc.ro/`, `hidden_url_visibility=true`.
- Cloud Run deployment proof for the PDF fix:
  - commit: `4918162`.
  - build id: `c87c4cb2-c160-4abc-95a5-624a611eeb16`.
  - revision: `sigurscan-api-00025-vg5`.
  - image digest: `sha256:1951be05e620f71b74923f4d6460ab36f322767f98f14987e38ff20eea11d1c7`.
  - `sigurscan-api-00025-vg5` receives `100%` traffic.

### Not Yet Green

- QR import and camera-driven QR scan were not rerun in this continuation.
- Physical-device release proof and mobile-network proof remain open.
- Full provider concurrency remains intentionally deferred to avoid burning live provider quota.

## Zone 7 - Main Consolidation Snapshot

### Verified

- `main` contains the freeze integration, invoice HMAC config, upfront-fee offer fix, secret fallback removal, and Android UA hardening:
  - `4bbbc88 feat: integrate freeze offer knowledge and invoice pipeline`
  - `789d497 chore: wire invoice HMAC secret into Cloud Run deploy`
  - `cf842d2 fix: flag upfront fee offer scams`
  - `21a6943 fix: close freeze secret and edge UA gaps`
- `fa6a22c fix: map live CUI fallback company data`
- `e55bc7b fix: preserve invoice fast-lane verdict`
- `d9d452c build: make Cloud Run container reproducible`
- `45b5663 fix: include remote reputation cache in stats`
- `4918162 fix: keep PDF annotation links when OCR is empty`
- `origin/main` includes deployed code commit `4918162`.
- Cloud Run intentionally runs code image `4918162`.
- Branch audit was run from isolated worktree `/Users/vaduvageorge/.config/superpowers/worktrees/SigurScan/freeze-main-2026-06-12` at `7cb7651`.
- Integrated/ancestor branches:
  - `origin/feature/deepseek-invoice-freeze-handoff-2026-06-12`
  - `origin/feature/freeze-ready-main-2026-06-12`
  - `origin/fix/text-pipeline-privacy-hardening`
- Branches not safe for raw merge:
  - `origin/feature/fable-freeze-handoff-2026-06-12`
  - `origin/feature/freeze-integration-2026-06-12`
  - `origin/feature/offer-core-parser-readiness`
  - `origin/feature/offer-anaf-iban-gate`
  - `origin/feature/offer-android-field-confirmation`
  - `origin/feature/offer-registry-snapshots`
  - `origin/feature/offer-legal-layer`
  - `origin/feature/offer-web-confirm-async`
  - `origin/feature/offer-knowledge-v3`
  - `origin/feature/offer-knowledge-v3-complete`
- Reason: tree diffs from current `main` show these branch trees are older than the freeze base and would delete or revert current freeze docs/evidence, Cloud Run deploy hardening, data assets, and/or tests if merged as whole branches.
- Current `main` content check:
  - offer atlas: `10` families.
  - OP-08 job scams: `16` signals.
  - OP-09 investment/crypto scams: `15` signals.
  - offer corpus: `51` fixtures.
  - legal KB: `9` cards.
  - impersonation atlas: `13` scam families.
- Fresh backend verification from the clean worktree:
  - Command: `python3 -m pytest backend -q`
  - Result: `666 passed, 1 warning in 4.29s`.
- Fresh Android verification from the clean worktree:
  - Command: `JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home" ./gradlew :app:testDebugUnitTest :app:assembleDebug :app:assembleRelease`
  - Result: `BUILD SUCCESSFUL in 1m 2s`, `96 actionable tasks`.
- Physical checkout guard:
  - `/Users/vaduvageorge/AndroidStudioProjects/SigurScan` is on local branch `gate/unverified-verdict` with uncommitted external work.
  - Freeze work did not mutate that branch; all checks and doc edits were done in the isolated `main` worktree.

### Not Yet Green

- Do not delete old feature branches until Sonet UI and active `gate/unverified-verdict` work are explicitly resolved.
- Remaining unproven device flows are outside Zone 7: QR import/camera, physical-device release, mobile-network, and fuller offer-with-URL/payment proof if required.

## Current Verdict

Freeze is not complete yet.

The backend is live and healthy on Cloud Run behind `api.sigurscan.com`, with provider smoke green, API auth active, invoice HMAC secret fallback removed, Android UA hardening deployed, a reproducible hash-locked container, min instances enabled, request-based CPU billing preserved, a Cloud Billing budget guard created, build log audited, latency alerting configured, structured-error proof captured, rollback executed and restored successfully, lightweight concurrency proven, controlled five-scan text-only concurrency proven, remote reputation-cache stats fixed, Android emulator URL E2E proven, Android emulator invoice E2E verified after the CUI/finalization fixes, email HTML hidden-link extraction/scan proven live, and PDF annotation-link extraction fixed and proven live on deployed commit `4918162`. The remaining Cloud Run freeze items are optional cold-start proof if scale-to-zero returns and a deliberately quota-bounded URL-provider concurrency probe.
