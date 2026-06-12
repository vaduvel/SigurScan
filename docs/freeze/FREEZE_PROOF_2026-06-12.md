# SigurScan Freeze Proof - 2026-06-12

Status: in progress. This document is proof-led: an item is not green unless the evidence below can be rerun.

## Source Of Truth

- Repository: `vaduvel/SigurScan`
- Local repo: `/Users/vaduvageorge/AndroidStudioProjects/SigurScan`
- Current branch: `main`
- Current commit: `cf842d2`
- Cloud Run project: `project-20f225c0-d756-4cba-864`
- Cloud Run service: `sigurscan-api`
- Cloud Run region: `europe-west1`
- Official API domain: `https://api.sigurscan.com`

## Zone 1 - Google Cloud Run

### Verified

- Cloud Run service exists in `europe-west1`.
  Evidence: `gcloud run services describe sigurscan-api --project project-20f225c0-d756-4cba-864 --region europe-west1`.
- Latest ready revision is `sigurscan-api-00018-p8s`.
- Traffic is `100%` to `sigurscan-api-00018-p8s`.
- Deployed image is `europe-west1-docker.pkg.dev/project-20f225c0-d756-4cba-864/sigurscan/sigurscan-api:cf842d2`.
- Request timeout is `300s`.
- Container concurrency is `40`.
- CPU/memory are `1 CPU` / `1Gi`.
- Max instances is `5`.
- Provider secrets are injected through Secret Manager references, including Supabase, Gemini, Vision, Web Risk, Mistral, urlscan, URLhaus, Upstash, app API keys, admin API keys, and `invoice-cache-hmac-key`.
- Invoice cache HMAC uses only `INVOICE_CACHE_HMAC_KEY` from Secret Manager/env.
  - Legacy fallback string `sigurscan-cache-key-v1` has been removed from runtime code.
  - `gcloud secrets list` confirms `invoice-cache-hmac-key` exists in Secret Manager.
  - Cloud Run injects `INVOICE_CACHE_HMAC_KEY=invoice-cache-hmac-key:latest`.
  - Test proof: `test_invoice_cache_key_requires_env_secret` fails without env and passes with the test fixture env.
- Health check returns `HTTP 200` through Cloudflare on `https://api.sigurscan.com/health`.
- API protection is active:
  - unauthenticated `POST /v1/scan/orchestrated` returns `401`.
  - authenticated `POST /v1/scan/orchestrated` returns `200` and creates a scan.
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

### Not Yet Green

- Container build warnings have not been audited from Cloud Build logs yet.
- `min-instances` is not set. Cold-start protection is therefore not proven.
- Cold-start test after 15 minutes idle has not been run.
- Concurrency/load test has not been run.
- Cloud Logging structured-error proof has not been captured.
- Latency outlier root-cause is not fully closed: a prior live run had one `29s` poll. The latest 4-run probe did not reproduce it, so this remains a watch item rather than a confirmed code defect.
- Rollback has not been tested end-to-end.

### Immediate Fixes

1. Decide and apply `min-instances=1` if we accept the small always-on Cloud Run cost.
2. Add `MIN_INSTANCES` support to `tools/deploy_cloud_run_backend.sh` so deploys are reproducible.
3. Run Cloud Build log audit for the `cf842d2` image.
4. Run a small authenticated concurrency test through `https://api.sigurscan.com`.
5. Add/confirm Cloud Logging alerting for poll latency outliers, for example any `GET /v1/scan/orchestrated/{id}` over `8s` or any component duration over provider timeout.
6. Document rollback command and test it against the previous ready revision, or run a non-destructive dry-run proof if we do not want to move production traffic.

## Zone 2 - Cloudflare Official Domain

### Verified

- `https://api.sigurscan.com/health` responds with `HTTP/2 200`.
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
  - This is a Cloudflare/WAF user-agent rule, not CORS. QA scripts and legitimate non-Android clients must send an app-like UA or be allowlisted intentionally.

### Not Yet Green

- TLS chain screenshot/proof not captured.
- HTTP to HTTPS redirect not tested.
- Cloudflare cache bypass/rate-limit rules for `/v1/*` not fully audited.
- Cloudflare timeout behavior for long scans not tested.
- Android mobile-network test on 4G/5G not recorded.

## Zone 7 - Main Consolidation Snapshot

### Verified

- `main` contains the freeze integration, invoice HMAC config, and upfront-fee offer fix:
  - `4bbbc88 feat: integrate freeze offer knowledge and invoice pipeline`
  - `789d497 chore: wire invoice HMAC secret into Cloud Run deploy`
  - `cf842d2 fix: flag upfront fee offer scams`
- `origin/main` points to `cf842d2`.

### Not Yet Green

- Need a final branch audit for unmerged feature branches before deleting anything.
- Need one full backend + Android test run after any remaining Cloud Run config fixes.

## Current Verdict

Freeze is not complete yet.

The backend is live and healthy on Cloud Run behind `api.sigurscan.com`, with provider smoke green and API auth active. The next blocking item is Cloud Run hardening: reproducible min instances, build log audit, concurrency proof, and rollback proof.
