# SigurScan Freeze Status Matrix - 2026-06-12

Status: proof-led, not marketing-led. Nothing is green unless there is a rerunnable proof in this repo or in Cloud/Supabase output.

## Current Source Of Truth

- Repo: `/Users/vaduvageorge/AndroidStudioProjects/SigurScan`
- Branch: `main`
- GitHub: `origin/main`
- Current deployed code baseline after 2026-06-13 deploy-tooling hardening: `fa1e75c`
- Deployed Cloud Run code image: `fa1e75c`
- Documentation-only commits may advance `origin/main` past the deployed code baseline when they only record proof.
- API domain: `https://api.sigurscan.com`
- Cloud project id: `project-20f225c0-d756-4cba-864`
- Cloud Run service: `sigurscan-api`, region `europe-west1`
- Supabase project ref: `hslqboubacrdhatmqcky`

## Branch Handoff Decision

| Source | Status | Decision |
| --- | --- | --- |
| DeepSeek invoice handoff | Integrated | `main` already contains `90b551c` and `a38c7af`; no merge needed. |
| Freeze-ready main handoff | Integrated | `origin/feature/freeze-ready-main-2026-06-12` is an ancestor of `main`; no merge needed. |
| Text pipeline privacy hardening | Integrated | `origin/fix/text-pipeline-privacy-hardening` is an ancestor of `main`; no merge needed. |
| Fable freeze handoff | Do not merge directly | Branch is older than `main` in several operational areas and would remove Cloud Run freeze proof, deploy-script fixes, and newer impersonation assets if merged raw. |
| Fable/freeze integration branch | Do not merge directly | Functional delta vs `main` is mostly older/reverting material; use `main` as source of truth. |
| Offer PR stage branches | Archive / no raw merge | `offer-core-parser-readiness`, `offer-anaf-iban-gate`, `offer-android-field-confirmation`, `offer-registry-snapshots`, `offer-legal-layer`, `offer-web-confirm-async`, `offer-knowledge-v3`, and `offer-knowledge-v3-complete` are older stage branches. Current `main` contains the release-ready combined implementation; raw merge would delete current freeze docs/tests/assets. |
| Sonet new UI | Not part of this freeze audit | No `origin/feature/new-ui-design` branch was visible during this fetch. Keep any UI branch separate until explicitly reviewed/merged; no branch deletion yet. |
| Local `gate/unverified-verdict` | Active external work | Physical checkout `/Users/vaduvageorge/AndroidStudioProjects/SigurScan` is on this branch with uncommitted changes. Freeze work is isolated in `/Users/vaduvageorge/.config/superpowers/worktrees/SigurScan/freeze-main-2026-06-12`; do not touch or overwrite the active branch. |

Evidence:

- `git cherry -v main origin/feature/deepseek-invoice-freeze-handoff-2026-06-12` produced no pending commits.
- `git merge-base --is-ancestor origin/feature/deepseek-invoice-freeze-handoff-2026-06-12 main`, `origin/feature/freeze-ready-main-2026-06-12 main`, and `origin/fix/text-pipeline-privacy-hardening main` returned true.
- `git diff --stat main..origin/feature/fable-freeze-handoff-2026-06-12` shows large deletions/reverts from current `main`, including freeze docs and impersonation knowledge.
- `git diff --stat main..origin/feature/freeze-integration-2026-06-12` shows the branch would delete `docs/freeze/FREEZE_PROOF_2026-06-12.md` and revert recent Cloud Run/deploy fixes.
- `git diff --name-status main..origin/feature/offer-knowledge-v3-complete`, `main..origin/feature/offer-web-confirm-async`, and the other offer stage branches shows each branch is missing current freeze docs, current Cloud Run/deploy hardening, and/or current data assets.
- Content check on `main`: `scam_atlas_offer_seed.json` has `10` offer families; OP-08 has `16` signals; OP-09 has `15` signals; `offer_corpus_fixtures.json` has `51` fixtures; `legal_kb.json` has `9` cards; `scam_atlas_impersonation_seed.json` has `13` impersonation families.

## Zone Matrix

| Zone | Area | Status | Proof / Gap |
| --- | --- | --- | --- |
| 1 | Cloud Run runtime | Green for current release posture, watch on URL-provider load | Live service is healthy behind `api.sigurscan.com`, min instances is `1`, request-based CPU is preserved, budget + latency + 5xx alert policies exist and now have an email notification channel. Reproducible hash-locked container is deployed as revision `sigurscan-api-00029-gjg` on code image `fa1e75c`, digest `sha256:a6f9b7be332223e02e925ac4f0b3bafc3e4ca8d0b4534d667d92b3b2c1904b50`, traffic `100%` to latest. Runtime truth from `gcloud run services describe`: `containerConcurrency=2`, `maxScale=5`. Exact-N reconciliation on 2026-06-13 used `N=2` text-only scans with no URL-provider quota: official domain `2/2` finalized, `0` `5xx`, max poll `4.344s`; raw Run `2/2` finalized, `0` `5xx`, max poll `4.36s`. Post-deploy text-only smoke on `fa1e75c`: POST `0.679s`, final status `complete` on poll 2, max poll `4.087s`, wall `7.705s`. Older 4/8-scan probes remain historical stress probes, not the current concurrency threshold. Deploy script hardening preserves `CONCURRENCY="${CONCURRENCY:-2}"`, uses `--concurrency "$CONCURRENCY"`, and now runs `update-traffic --to-latest` after deploy so live traffic cannot remain pinned to an older revision. Optional: quota-bounded URL-provider concurrency. |
| 2 | Cloudflare/domain | Green for API edge posture | `https://api.sigurscan.com/health` is live through Cloudflare and Android UA is accepted. HTTP redirects to HTTPS with `308`, TLS SAN covers `api.sigurscan.com`, `/v1/*` returns `no-store`, and unauthenticated API calls preserve backend `401`. HSTS is now present at the edge: `strict-transport-security: max-age=31536000; includeSubDomains`. Route parity official vs raw Run is proven for `/health`, `/v1/scan/orchestrated` unauthenticated, `/v1/reputation/cache/stats` unauthenticated, and `/v1/extract/pdf` unauthenticated. Open: long-scan timeout proof and physical mobile-network proof. |
| 3 | Supabase | Green for runtime DB path and accepted no-PITR backup posture | Remote migration list matches local migrations. Required tables exist, RLS is enabled, `anon`/`authenticated` have no direct grants on runtime tables, preview bucket `previews` is private PNG-only with 5MB limit, visual-only constraints exist, and a live scan wrote `orch_1781289050_c007425e` to `scan_jobs`. Runtime access is Data API/PostgREST, not long-lived direct DB connections; a 20-concurrent admin telemetry pressure check returned `20/20 HTTP 200` on both official and raw Run paths. Supabase CLI proof shows `pitr_enabled=false`, `walg_enabled=true`, `backups=[]`; database size is currently `26 MB`. Automated daily logical backup is now active through GitHub Actions private artifact retention: run `27462542127` succeeded on `main` commit `cdad5f9`, produced dump/schema/restore-list/manifest, and `pg_restore --list` passed. Local schema/data emergency dumps also exist outside the repo. Limitation remains explicit: this is daily logical backup, not PITR, and does not include Supabase Storage objects. |
| 4 | Cache/providers | Green for deterministic/provider contract, Partial for quota-heavy load | Provider smoke, single live URL-provider smoke, cache stats, and preview cache paths have proof. Live flows prove urlscan, Google Web Risk consultation, Phishing.Database, URLhaus, and offer-claim verifier behavior; `/v1/reputation/cache/stats` reads the Supabase-backed cache on Cloud Run after `45b5663`; deployed runtime is now `fa1e75c`. 2026-06-13 reconciliation adds redirect resolver contract proof, benign live redirect proof, RDAP/ROTLD/MX/domain-risk proof, `52/52` brand registry sweep, provider fault-injection tests proving provider errors do not become `SIGUR`, and a provider timeout/error behavior table. Open: full provider load/concurrency intentionally not run to avoid quota burn; legacy expired cache rows remain as non-blocking cache hygiene. |
| 5 | Android direct infra | Green for build/config, Partial for device proof | Debug and release local config point to `https://api.sigurscan.com/`; app API keys are configured without logging their values; direct provider keys are empty in generated BuildConfig; API key interceptor sends `X-API-KEY` and stable Android UA; `testDebugUnitTest`, `assembleDebug`, and `assembleRelease` pass; release APK is signed with SigurScan cert. Open: physical-device proof, mobile-network proof, upload-size proof, poor-network behavior, and post-UI-merge regression. AVD exists but did not boot into ADB during this continuation. |
| 6 | Live feature flows | Green for backend/API live flows, Partial for full device/import coverage | Backend tests cover text/url/email/offer/invoice/security/registry/legal paths. Live provider smoke is `3/3`; live YOXO and eMAG tracking are `SIGUR`, and hard-provider controls are `PERICULOS` through Phishing.Database/urlscan. Email HTML hidden-link extraction and scan are proven live. PDF annotation-link extraction was fixed in `4918162` and proven live on Cloud Run. Android emulator URL scan reaches final `SIGUR` with preview. Android emulator text-only offer/job scan reaches final non-safe `SUSPECT`. Android invoice image scan reaches verified invoice state with issuer/CUI/IBAN/dates/totals and live API top-level `SIGUR` after CUI + finalization fixes. Open: QR import/camera, physical-device release, mobile-network proof, and fuller offer-with-URL/payment proof if required. |
| 7 | Code consolidation | Green for current release consolidation, Partial for branch cleanup/UI | `main` is clean in the freeze worktree and has current invoice + offer + Cloud Run fixes. Backend full suite passes from the clean freeze worktree. Android unit/debug/release build passes from the clean freeze worktree. Branch audit is complete: DeepSeek/freeze-ready/privacy hardening are integrated; Fable/offer stage branches must not be merged raw because they would revert current `main`. Open: do not delete old branches until Sonet UI and any active `gate/unverified-verdict` work are explicitly resolved. |
| 8 | Hardening/regression | Green for automated/runtime hardening, Partial for physical/store launch | Zone 8 targeted regression passed `231` tests. Provider-degrade regression passed `54` tests. Offer corpus recall now covers OP-01..09 with `52 passed` and fixture distribution `OP-01..07=5 each`, `OP-08=8`, `OP-09=8`; signal recall is `26/29 = 90%`. Local freeze hardening tests add telemetry sink redaction for email, phone, CNP, IBAN, card, OTP, and URL-query email; `backend/test_freeze_hardening.py` passes `4/4` before deployment. Live log hygiene checked `300` Cloud Run log entries and found zero exact matches for the controlled marker, OTP, CNP, IBAN, or card value. Admin telemetry endpoints return live `200`; dashboard HTML returns `200`; telemetry summary reports `alerts_count=0` and urlscan pending-timeout rate `0.0`. Cloud Monitoring has enabled latency and 5xx policies with email channel `6336647364895454298` attached. Controlled 5xx stack-trace proof is deferred because no safe admin-only diagnostic crash route exists. Open: full URL-provider load pack, Play-ready privacy/legal store checklist, and physical-device/mobile-network proof. |

## Tests Run In This Audit

- Backend full suite:
  - Command: `python3 -m pytest backend -q`
  - Location: `/Users/vaduvageorge/.config/superpowers/worktrees/SigurScan/freeze-main-2026-06-12`
  - Result after Zone 7 branch audit: `666 passed, 1 warning`
- Zone 8 hardening regression:
  - Command: `python3 -m pytest backend/test_offer_corpus_recall.py backend/test_family_classifier.py backend/test_scam_atlas_contract.py backend/test_scam_atlas_impersonation.py backend/test_impersonation_knowledge_builder.py backend/test_verdict_gate.py backend/test_offer_gate_combos.py backend/test_legal_layer.py backend/test_registry_verification.py backend/test_invoice_orchestration.py backend/test_invoice_endpoint.py backend/test_invoice_parser.py backend/test_invoice_readiness_gate.py backend/test_invoice_coherence.py backend/test_security_hardening.py backend/test_orchestrated_latency.py -q`
  - Result: `231 passed, 1 warning`
  - JUnit: `build/reports/freeze/zone8_regression_junit_2026-06-12.xml`
- Zone 8 provider-degrade regression:
  - Command: `python3 -m pytest backend/test_anaf_cui.py backend/test_anaf_cui_offer.py backend/test_offer_web_confirm.py backend/test_registry_verification.py backend/test_backend.py::test_gemini_explainer_handles_timeout_gracefully backend/test_backend.py::test_offer_claim_gemini_grounding_is_bounded_for_25_flash backend/test_backend.py::test_reputation_cache_refetches_when_configured_source_was_not_consulted -q`
  - Result: `54 passed, 1 warning`
  - JUnit: `build/reports/freeze/zone8_provider_degrade_junit_2026-06-12.xml`
- Reproducible container contract:
  - Command: `python3 -m pytest backend/test_container_contract.py -q`
  - Result: `1 passed`
  - Zero-cache Docker build: success.
  - Cloud Build: `8088b6e7-7662-43fb-936a-494baffbd5a2`, success, clean log.
  - Deployed digest: `sha256:0424d26d5eb06f0a73566c0d55964cb0f36fc8ec6180b060cfadc7a0cd735406`.
- Cache/provider hardening after `45b5663`:
  - Command: `python3 -m pytest backend/test_backend.py -q -k "reputation_cache_stats_reads_remote_cache_without_local_file or supabase_reputation_cache_uses_single_batch_upsert or local_reputation_cache_is_lru_capped"`
  - Result: `3 passed`
  - Full backend after patch: `665 passed, 1 warning`
  - Cloud Build: `00da774a-512f-41d8-b345-1bd6ee1c9736`, success.
  - Deployed revision: `sigurscan-api-00024-46n`, traffic `100%`.
  - Deployed digest: `sha256:fb1dc18409350b592e3c946928b500dd90832b61b4201e8d6ff7b4e765dd6506`.
- PDF annotation-link hardening after `4918162`:
  - Targeted command: `python3 -m pytest backend/test_backend.py -q -k "extract_pdf_returns_annotation_urls_when_ocr_is_empty or extract_pdf_annotation_links or scan_pdf_legacy_endpoint"`
  - Targeted result: `5 passed`.
  - Zone 6 regression command: `python3 -m pytest backend/test_email_link_extraction.py backend/test_invoice_endpoint.py backend/test_invoice_parser.py backend/test_invoice_orchestration.py backend/test_invoice_readiness_gate.py backend/test_comprehensive_invoices.py backend/test_offer_parser.py backend/test_offer_signals.py backend/test_offer_orchestration.py backend/test_offer_corpus_recall.py backend/test_offer_gate_combos.py backend/test_offer_web_confirm.py backend/test_legal_layer.py backend/test_registry_verification.py backend/test_verdict_gate.py backend/test_orchestrated_latency.py backend/test_backend.py -q`
  - Zone 6 regression result: `515 passed, 1 warning`.
  - Cloud Build: `c87c4cb2-c160-4abc-95a5-624a611eeb16`, success.
  - Deployed revision: `sigurscan-api-00025-vg5`, traffic `100%`.
  - Deployed digest: `sha256:1951be05e620f71b74923f4d6460ab36f322767f98f14987e38ff20eea11d1c7`.
- Android unit + debug build:
  - Command: `JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home" ./gradlew :app:testDebugUnitTest :app:assembleDebug :app:assembleRelease`
  - Location: `/Users/vaduvageorge/.config/superpowers/worktrees/SigurScan/freeze-main-2026-06-12`
  - Result after Zone 7 branch audit: `BUILD SUCCESSFUL` in `1m 2s`, `96 actionable tasks`.
  - Release APK: `app/build/outputs/apk/release/app-release.apk`, signed as `CN=SigurScan, OU=Mobile Security, O=SigurScan, L=Bucharest, ST=Bucharest, C=RO`.
  - Generated debug/release BuildConfig uses `https://api.sigurscan.com/`, app key `SET`, `URLSCAN_API_KEY=EMPTY`, and `GOOGLE_WEB_RISK_API_KEY=EMPTY`.
- Zone 7 branch audit:
  - Worktree: `/Users/vaduvageorge/.config/superpowers/worktrees/SigurScan/freeze-main-2026-06-12`, branch `main`, head `7cb7651`.
  - `origin/feature/deepseek-invoice-freeze-handoff-2026-06-12`, `origin/feature/freeze-ready-main-2026-06-12`, and `origin/fix/text-pipeline-privacy-hardening` are ancestors of `main`.
  - Offer/Fable stage branches are not merge candidates as whole branches; tree diffs from `main` show deletion/revert risk against current freeze docs, current data files, deploy scripts, and tests.
  - The physical checkout is on `gate/unverified-verdict` with uncommitted external work; freeze checks intentionally avoided mutating it.
- Supabase remote migrations:
  - Command: `supabase migration list --linked`
  - Result: all local migrations from `20260525091000` through `20260609214000` are present remotely.
- Supabase remote structural checks:
  - Tables present: `fast_preview_alias_cache`, `fast_preview_cache`, `fast_preview_capture_runs`, `scan_jobs`, `urlscan_preview_cache`
  - Constraints present: `fast_preview_cache_status_chk`, `fast_preview_cache_visual_only_chk`, `fast_preview_capture_runs_skipped_sensitive_nonnegative_chk`
  - Bucket: `previews`, `public=false`
  - `skipped_or_blocked_rows=0`
- Quota-safe live URL-provider smoke:
  - Target: `https://api.sigurscan.com/v1/scan/orchestrated`
  - Input: benign DNSC official URL smoke with Android UA.
  - Result: POST `HTTP 200` in `1.103s`; provisional `SIGUR` in `4.772s`; final `SIGUR` in `11.057s`; preview `ready`.
- Quota-safe live provider/cache smoke after `45b5663`:
  - Target: `https://api.sigurscan.com`.
  - Case: `live_emag_tracking_official`.
  - Result: `SIGUR`, `status=complete`, `is_final=true`, provider gate reason `official_clean`.
  - Timings: scan id `1.33s`, verdict `7.69s`, completion `9.03s`, preview report/screenshot `2.36s`.
  - Cache stats: `loaded=true`, `items=66`, `valid_items=6`, `expired_items=60`, `invalid_items=436`; provider sources include Google Web Risk, Phishing.Database, and URLhaus.
- Zone 6 live API flow proof after `4918162`:
  - Live provider smoke report: `build/reports/freeze_zone6_live_provider_smoke_2026-06-12.json`, result `3/3 passed`.
  - Additional hard-provider control report: `build/reports/freeze_zone6_webrisk_control_2026-06-12.json`, result `PERICULOS` through urlscan malicious; Google Web Risk returned clean in that run.
  - Email HTML extract report: `build/reports/freeze_zone6_email_html_extract_live_2026-06-12.json`, extracted one hidden/button CTA URL.
  - Email HTML scan report: `build/reports/freeze_zone6_email_html_hidden_link_live_2026-06-12.json`, result `SIGUR`, final URL `https://auth.emag.ro/user/login`, preview report/screenshot present.
  - PDF extraction report: `build/reports/freeze_zone6_pdf_extract_live_after_fix_2026-06-12.json`, result `HTTP 200`, extracted `https://dnsc.ro/`, `hidden_url_visibility=true`.
- Zone 8 runtime/load hardening after final `containerConcurrency=2` tuning:
  - Domain health: official API `HTTP 200` in `0.276s`; direct Run URL `HTTP 200` in `0.146s`; runtime reports `api_key_required=true`, `admin_api_configured=true`, `rate_limit_backend=upstash`.
  - Single warm text-only scan: POST `1.188s`; provisional public verdict after first poll in roughly `2.5s` total; final `SUSPECT` in `7.131s`.
  - 8 simultaneous text-only scans before final tuning: `8/8` finalized, no `5xx`, poll max `9.367s`, total max `16.244s`.
  - 8 simultaneous text-only scans after `containerConcurrency=2`: `8/8` finalized, no `5xx`, poll max `8.328s`, total max `15.565s`.
  - 4 simultaneous text-only scans after `containerConcurrency=2`: `4/4` finalized, no `5xx`, poll max `6.049s`, total max `9.147s`.
  - Reports:
    - `build/reports/freeze/zone8_domain_health_after_tuning_2026-06-12.json`
    - `build/reports/freeze/zone8_live_single_warm_2026-06-12.json`
    - `build/reports/freeze/zone8_live_concurrency_admin_2026-06-12.json`
    - `build/reports/freeze/zone8_live_concurrency_after_concurrency2_2026-06-12.json`
    - `build/reports/freeze/zone8_live_concurrency4_after_concurrency2_2026-06-12.json`
- Zone 8 admin/log hygiene proof:
  - Admin endpoints:
    - `/v1/orchestration/telemetry`: `HTTP 200`, JSON.
    - `/v1/orchestration/dashboard`: `HTTP 200`, HTML.
    - `/v1/feedback/summary`: `HTTP 200`, JSON.
    - `/v1/reputation/cache/stats`: `HTTP 200`, JSON.
  - Telemetry summary: `alerts_count=0`, `urlscan.pending_timeout_events=0`, `urlscan.pending_timeout_rate=0.0`.
  - Log hygiene: `300` Cloud Run log entries checked; controlled marker, OTP, CNP, IBAN, and card exact matches all `0`.
  - Reports:
    - `build/reports/freeze/zone8_admin_endpoints_live_2026-06-12.json`
    - `build/reports/freeze/zone8_admin_telemetry_summary_2026-06-12.json`
    - `build/reports/freeze/zone8_log_hygiene_probe_request_2026-06-12.json`
    - `build/reports/freeze/zone8_cloud_run_log_hygiene_2026-06-12.json`
- Zone 8 Cloud Monitoring alert proof:
  - Policies enabled:
    - `SigurScan orchestrated poll latency > 8s`
    - `SigurScan Cloud Run 5xx errors > 0`
  - Report: `build/reports/freeze/zone8_gcp_alert_policies_after_create_2026-06-12.json`
  - 2026-06-13 reconciliation attached notification channel `6336647364895454298` to both policies; the email address is recorded only as `SET`.
- Freeze QA reconciliation hardening:
  - Cloud Run concurrency truth:
    - command: `gcloud run services describe sigurscan-api --project project-20f225c0-d756-4cba-864 --region europe-west1 --format='value(spec.template.spec.containerConcurrency)'`
    - result: `2`
  - Exact-N text-only scan proof:
    - official domain: `2/2` finalized, `0` `5xx`, wall time `8.37s`, max poll `4.344s`
    - raw Run: `2/2` finalized, `0` `5xx`, wall time `7.398s`, max poll `4.36s`
  - HSTS edge proof:
    - `curl -sD - -o /dev/null https://api.sigurscan.com/health` includes `strict-transport-security: max-age=31536000; includeSubDomains`
    - Cloudflare Worker version: `c2523aae-9215-4527-93aa-9a36b82cc491`
  - Route parity official vs raw Run:
    - `/health`: `200` / `200`, same body hash
    - `/v1/scan/orchestrated` unauthenticated: `401` / `401`, same body hash
    - `/v1/reputation/cache/stats` unauthenticated: `401` / `401`, same body hash
    - `/v1/extract/pdf` unauthenticated: `401` / `401`, same body hash
  - Supabase pressure/PITR proof:
    - 20 concurrent admin telemetry requests: official `20/20 HTTP 200`, raw Run `20/20 HTTP 200`
    - `supabase backups list --project-ref hslqboubacrdhatmqcky --output json`: `pitr_enabled=false`, `walg_enabled=true`, `backups=[]`
    - database size: `26 MB`
    - local emergency dumps exist under `/Users/vaduvageorge/SigurScan_backups/supabase/`
  - Provider/registry proof:
    - redirect resolver freeze contract covered by `backend/test_freeze_hardening.py`
    - live benign redirect resolved `httpbin.org` redirect to `https://example.com`
    - RDAP/ROTLD/MX/domain-risk smoke passed for `google.com` and `digi.ro`
    - brand registry sweep: `52/52` aliases matched
    - provider error/degrade tests prove errors/pending states do not become `SIGUR`
- Android emulator URL E2E:
  - Device: `emulator-5554`.
  - App package: `ro.sigurscan.app`.
  - Input: `https://dnsc.ro/` typed into the app UI.
  - Result: final `SIGUR`, `Verdict final`, `Verificari complete`, preview rendered.
  - Screenshot: `docs/freeze/evidence/android_e2e_dnsc_sigur_preview_2026-06-12.png`
- Android emulator offer/text-only E2E:
  - Device: `emulator-5554`.
  - App package: `ro.sigurscan.app`.
  - Input: `job pe telegram profit garantat 500 USD pe zi contact Frank` typed into the app UI.
  - Result: final `SUSPECT`, `Verdict final`, `Verificari complete`.
  - Screenshot: `docs/freeze/evidence/android_e2e_offer_text_only_suspect_2026-06-12.png`
  - Follow-up: text-only result copy must not claim that a final URL/preview was checked when no complete URL exists.
- Android emulator invoice image E2E:
  - Device: `emulator-5554`.
  - App package: `ro.sigurscan.app`.
  - Input: generated Romanian invoice PNG selected through Android DocumentsUI.
  - Result: stable `Scanare Factură` screen with issuer `DIGI ROMANIA S.A.`, CUI `5888716`, IBAN, invoice number, issue/due dates, subtotal, VAT, and total extracted.
  - Defect found: live CUI fallback returned provider raw data for Digi but mapped it as `exists=false`.
  - Local fix proof: `backend/test_anaf_cui.py` now covers the live fallback shape; full backend suite after the fix: `662 passed, 1 warning`.
  - Before-fix screenshot: `docs/freeze/evidence/android_e2e_invoice_digi_attention_before_cui_fallback_fix_2026-06-12.png`
- Android emulator invoice image E2E after CUI + finalization fixes:
  - Device: `emulator-5554`.
  - App package: `ro.sigurscan.app`.
  - Input: generated Romanian invoice PNG selected through Android DocumentsUI.
  - Live API result before Android proof: top-level `SIGUR`, invoice gate `SIGUR`, reason `official_clean`, warnings `[]`.
  - Android result: stable `Scanare Factură` screen with status `Verificat`, issuer `DIGI ROMANIA S.A.`, CUI `5888716`, IBAN valid `Da`, invoice number, issue/due dates, subtotal, VAT, and total extracted.
  - Screenshot: `docs/freeze/evidence/android_e2e_invoice_digi_verified_after_invoice_finalize_fix_2026-06-12.png`

## Next Actions

1. Do not merge Fable/offer stage branches raw. If a specific missing feature is found later, cherry-pick or reimplement the minimal diff onto `main`.
2. Keep `main` as the freeze base and treat the current physical `gate/unverified-verdict` checkout as separate active work.
3. Keep daily Supabase logical backups monitored and run a restore drill before Play launch. PITR remains optional paid resilience later.
4. Run the remaining Android E2E flows: QR import/camera, physical-device release, mobile-network, and fuller offer-with-URL/payment if needed.
5. Run full URL-provider concurrency only during a deliberate quota window, not during normal freeze checks.
6. Add a temporary admin-only diagnostic route only if stack-trace proof is required; keep it disabled by default and remove/disable after proof.
7. Keep old feature branches until the UI branch and active gate branch are fully accounted for; delete only after a named cleanup pass.
