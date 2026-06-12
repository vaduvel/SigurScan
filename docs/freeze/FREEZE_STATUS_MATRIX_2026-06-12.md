# SigurScan Freeze Status Matrix - 2026-06-12

Status: proof-led, not marketing-led. Nothing is green unless there is a rerunnable proof in this repo or in Cloud/Supabase output.

## Current Source Of Truth

- Repo: `/Users/vaduvageorge/AndroidStudioProjects/SigurScan`
- Branch: `main`
- GitHub: `origin/main`
- Current repo head at audit time: `bebd86b`
- Deployed Cloud Run code image: `17dcfc7`
- API domain: `https://api.sigurscan.com`
- Cloud project id: `project-20f225c0-d756-4cba-864`
- Cloud Run service: `sigurscan-api`, region `europe-west1`
- Supabase project ref: `hslqboubacrdhatmqcky`

## Branch Handoff Decision

| Source | Status | Decision |
| --- | --- | --- |
| DeepSeek invoice handoff | Integrated | `main` already contains `90b551c` and `a38c7af`; no merge needed. |
| Fable freeze handoff | Do not merge directly | Branch is older than `main` in several operational areas and would remove Cloud Run freeze proof, deploy-script fixes, and newer impersonation assets if merged raw. |
| Fable/freeze integration branch | Do not merge directly | Functional delta vs `main` is mostly older/reverting material; use `main` as source of truth. |
| Sonet new UI | Not part of this freeze audit | Keep separate until explicitly merged/reviewed; no branch deletion yet. |

Evidence:

- `git cherry -v main origin/feature/deepseek-invoice-freeze-handoff-2026-06-12` produced no pending commits.
- `git diff --stat main..origin/feature/fable-freeze-handoff-2026-06-12` shows large deletions/reverts from current `main`, including freeze docs and impersonation knowledge.
- `git diff --stat main..origin/feature/freeze-integration-2026-06-12` shows the branch would delete `docs/freeze/FREEZE_PROOF_2026-06-12.md` and revert recent Cloud Run/deploy fixes.

## Zone Matrix

| Zone | Area | Status | Proof / Gap |
| --- | --- | --- | --- |
| 1 | Cloud Run runtime | Partial Green | Live service is healthy behind `api.sigurscan.com`, min instances is `1`, request-based CPU is preserved, budget + latency alert exist. Open: optional URL-provider concurrency, optional full rollback drill, prior 29s outlier remains watch item. |
| 2 | Cloudflare/domain | Partial Green | `https://api.sigurscan.com/health` is live through Cloudflare and Android UA is accepted. Open: TLS screenshot/proof, HTTP->HTTPS redirect proof, full Cloudflare `/v1/*` rule audit. |
| 3 | Supabase | Green for current schema | Remote migration list matches local migrations. Required tables exist: `scan_jobs`, `urlscan_preview_cache`, `fast_preview_cache`, `fast_preview_alias_cache`, `fast_preview_capture_runs`. Preview bucket `previews` is private. Visual-only constraints exist. Open: one non-critical Supabase CLI temp-role query failed after parallel auth attempts; avoid repeated parallel DB auth probes. |
| 4 | Cache/providers | Partial Green | Provider smoke, single live URL-provider smoke, and preview cache paths have proof. URLhaus/Web Risk/urlscan/Mistral/Upstash secrets are wired in deploy script. Open: full provider load/concurrency intentionally not run to avoid quota burn. |
| 5 | Android direct infra | Partial Green | Android unit tests + debug build pass with Android Studio JBR. Local config points to `https://api.sigurscan.com/`. API key interceptor sends `X-API-KEY` and stable Android UA. Emulator URL E2E is proven. Open: physical-device proof and post-UI-merge regression. |
| 6 | Live feature flows | Partial Green | Backend tests cover text/url/email/offer/invoice/security/registry/legal paths. Live URL/domain smoke exists. Android emulator URL scan reaches final `SIGUR` with preview. Open: live cap-to-cap on Android for offer scan, invoice scan, email HTML hidden-link scan, PDF/image/QR import. |
| 7 | Code consolidation | Partial Green | `main` is clean and has current invoice + offer + Cloud Run fixes. Backend full suite passes. Android build/tests pass. Open: do not delete old branches until Sonet UI and any wanted handoff deltas are explicitly resolved. |
| 8 | Hardening/regression | Partial Green | Latency alert, budget, structured error proof, API key requirement, Android UA hardening, and freeze docs exist. Open: full live regression pack, Play-ready privacy/legal store checklist, and physical-device proof. |

## Tests Run In This Audit

- Backend full suite:
  - Command: `/opt/homebrew/bin/python3 -m pytest -q`
  - Location: `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/backend`
  - Result: `659 passed, 1 warning`
- Android unit + debug build:
  - Command: `JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home" ./gradlew :app:testDebugUnitTest :app:assembleDebug`
  - Location: `/Users/vaduvageorge/AndroidStudioProjects/SigurScan`
  - Result: `BUILD SUCCESSFUL`
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
- Android emulator URL E2E:
  - Device: `emulator-5554`.
  - App package: `ro.sigurscan.app`.
  - Input: `https://dnsc.ro/` typed into the app UI.
  - Result: final `SIGUR`, `Verdict final`, `Verificari complete`, preview rendered.
  - Screenshot: `docs/freeze/evidence/android_e2e_dnsc_sigur_preview_2026-06-12.png`

## Next Actions

1. Do not merge Fable handoff branches raw. If a specific missing feature is found later, cherry-pick or reimplement the minimal diff onto `main`.
2. Keep `main` as the freeze base.
3. Run the remaining Android E2E flows: offer, invoice, email HTML hidden-link, PDF/image, and QR.
4. Run full URL-provider concurrency only during a deliberate quota window, not during normal freeze checks.
5. Keep old feature branches until the UI branch and invoice/offer freeze deltas are fully accounted for; delete only after a named cleanup pass.
