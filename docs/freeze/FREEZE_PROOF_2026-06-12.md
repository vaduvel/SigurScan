# SigurScan Freeze Proof - 2026-06-12

Status: in progress. This document is proof-led: an item is not green unless the evidence below can be rerun.

## Source Of Truth

- Repository: `vaduvel/SigurScan`
- Local repo: `/Users/vaduvageorge/AndroidStudioProjects/SigurScan`
- Current branch: `main`
- Current repo commit: `9bae857`
- Deployed code commit: `21a6943`
- Cloud Run project: `project-20f225c0-d756-4cba-864`
- Cloud Run service: `sigurscan-api`
- Cloud Run region: `europe-west1`
- Official API domain: `https://api.sigurscan.com`

## Zone 1 - Google Cloud Run

### Verified

- Cloud Run service exists in `europe-west1`.
  Evidence: `gcloud run services describe sigurscan-api --project project-20f225c0-d756-4cba-864 --region europe-west1`.
- Latest ready revision is `sigurscan-api-00019-lxl`.
- Traffic is `100%` to `sigurscan-api-00019-lxl`.
- Deployed image is `europe-west1-docker.pkg.dev/project-20f225c0-d756-4cba-864/sigurscan/sigurscan-api:21a6943`.
- Cloud Build deployment proof:
  - build id: `23a660e7-6983-4785-85a9-a435eed15fad`
  - status: `SUCCESS`
  - service URL: `https://sigurscan-api-357849228072.europe-west1.run.app`
- Request timeout is `300s`.
- Container concurrency is `40`.
- CPU/memory are `1 CPU` / `1Gi`.
- Max instances is `5`.
- Provider secrets are injected through Secret Manager references, including Supabase, Gemini, Vision, Web Risk, Mistral, urlscan, URLhaus, Upstash, app API keys, admin API keys, and `invoice-cache-hmac-key`.
- Invoice cache HMAC uses only `INVOICE_CACHE_HMAC_KEY` from Secret Manager/env.
  - Legacy fallback string `sigurscan-cache-key-v1` has been removed from runtime code.
  - `gcloud secrets list` confirms `invoice-cache-hmac-key` exists in Secret Manager.
  - `gcloud secrets list` does not show a separate `sigurscan-cache-key-v1` secret.
  - Cloud Run injects `INVOICE_CACHE_HMAC_KEY=invoice-cache-hmac-key:latest`.
  - Test proof: `test_invoice_cache_key_requires_env_secret` fails without env and passes with the test fixture env.
- Health check returns `HTTP 200` through Cloudflare on `https://api.sigurscan.com/health`.
  - Post-deploy health after `21a6943`: `HTTP 200`, `0.361590s`.
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
- Post-deploy latency re-check after `21a6943`:
  - Existing scan `orch_1781268789_c6e92ca2` returned `HTTP 200` in `4.008s` and was already `complete`, `SUSPECT`, `is_final=true`.
  - New offer scan `orch_1781269113_5074e703`:
    - POST: `HTTP 200`, `0.548s`
    - poll 1: `HTTP 200`, `0.807s`, still scanning
    - poll 2: `HTTP 200`, `0.755s`, `SUSPECT`, `is_final=false`
    - poll 3: `HTTP 200`, `3.407s`, `SUSPECT`, `is_final=true`
  - Cloud Run request logs for `orch_1781269113_5074e703` show server-side GET latencies of `0.501767931s`, `0.517308680s`, and `3.180505344s`.
  - A previous local `urllib` poll timeout was not reproduced with `requests`; Cloud Run logs for that scan showed quick server responses. Treat remaining risk as edge/client-path observability, not a confirmed backend handler latency defect.

### Not Yet Green

- Container build warnings have not been audited from Cloud Build logs yet.
- `min-instances` is not set. Cold-start protection is therefore not proven.
- Cold-start test after 15 minutes idle has not been run.
- Concurrency/load test has not been run.
- Cloud Logging structured-error proof has not been captured.
- Latency outlier root-cause is not fully closed: a prior live run had one `29s` poll. The latest 4-run probe and the post-`21a6943` probe did not reproduce it, and Cloud Run logs show sub-4s server-side poll latency for the latest scan, so this remains a watch item rather than a confirmed code defect.
- Rollback has not been tested end-to-end.

### Immediate Fixes

1. Decide and apply `min-instances=1` if we accept the small always-on Cloud Run cost.
2. Add `MIN_INSTANCES` support to `tools/deploy_cloud_run_backend.sh` so deploys are reproducible.
3. Run Cloud Build log audit for the `21a6943` image.
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
  - Post-`21a6943` proof:
    - `Python-urllib/3.14`: `HTTP 403`, `0.103618s`
    - `SigurScan/1.0 Android OkHttp`: `HTTP 200`, `0.184060s`
    - authenticated Android UA health: `HTTP 200`, `0.164287s`
  - This is a Cloudflare/WAF user-agent rule, not CORS. QA scripts and legitimate non-Android clients must send an app-like UA or be allowlisted intentionally.

### Not Yet Green

- TLS chain screenshot/proof not captured.
- HTTP to HTTPS redirect not tested.
- Cloudflare cache bypass/rate-limit rules for `/v1/*` not fully audited.
- Cloudflare timeout behavior for long scans not tested.
- Android mobile-network test on 4G/5G not recorded.

## Zone 7 - Main Consolidation Snapshot

### Verified

- `main` contains the freeze integration, invoice HMAC config, upfront-fee offer fix, secret fallback removal, and Android UA hardening:
  - `4bbbc88 feat: integrate freeze offer knowledge and invoice pipeline`
  - `789d497 chore: wire invoice HMAC secret into Cloud Run deploy`
  - `cf842d2 fix: flag upfront fee offer scams`
  - `21a6943 fix: close freeze secret and edge UA gaps`
- `origin/main` points to `9bae857`.
- Cloud Run intentionally remains on code image `21a6943`; `9bae857` is documentation-only.

### Not Yet Green

- Need a final branch audit for unmerged feature branches before deleting anything.
- Need one full backend + Android test run after any remaining Cloud Run config fixes.

## Current Verdict

Freeze is not complete yet.

The backend is live and healthy on Cloud Run behind `api.sigurscan.com`, with provider smoke green, API auth active, invoice HMAC secret fallback removed, and Android UA hardening deployed. The next blocking item is Cloud Run hardening: reproducible min instances, build log audit, concurrency proof, latency alerting, and rollback proof.
