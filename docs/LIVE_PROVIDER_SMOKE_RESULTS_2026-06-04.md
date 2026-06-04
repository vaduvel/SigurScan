# Live Provider Smoke Results - 2026-06-04

Scope: production backend `https://nudaclick-backend.vercel.app`, real provider calls, no mocks.

## Production Deploys

- Deployed urlscan hard-provider finalize fix.
- Deployed urlscan tag sanitization fix.
- Deployed urlscan pending screenshot timeout fix.
- Deployed Sprint S+1 dashboard/evaluation follow-up to production alias `https://nudaclick-backend.vercel.app`.

## Post-Deploy S+1 Smoke

Command:

```bash
SIGURSCAN_RUN_LIVE_PROVIDER_SMOKE=1 python3 backend/eval/live_provider_smoke_runner.py --base-url https://nudaclick-backend.vercel.app --output build/reports/live_provider_smoke_2026-06-04_post_deploy.json --poll-interval 3 --timeout 35
```

Result:

- Full capped batch: 4/5 passed.
- YOXO buyback: `SIGUR`, complete, preview available.
- SMYK catalog: `SIGUR`, complete, preview available.
- eMAG tracking: `SIGUR`, complete, preview available.
- Google Web Risk phishing test URL: `PERICULOS`, complete.
- iDroid status: runner client timed out while polling at 35s.

Follow-up iDroid-only command:

```bash
SIGURSCAN_RUN_LIVE_PROVIDER_SMOKE=1 python3 backend/eval/live_provider_smoke_runner.py --base-url https://nudaclick-backend.vercel.app --case live_idroid_status --output build/reports/live_provider_smoke_idroid_2026-06-04_post_deploy.json --poll-interval 5 --timeout 90
```

Result:

- iDroid status: 1/1 passed.
- Verdict: `SUSPECT`.
- Final URL: `https://idroid.ro/verifica-status/`.
- Preview/report available.

Interpretation: the product pipeline passed the capped smoke set. The first iDroid batch failure was runner timeout sensitivity, not a wrong provider/gate result.

## Cases

### YOXO Buyback SMS

Input:

`Ai un telefon sau o tableta pe care nu le mai folosesti? ... buyback.yoxo.ro`

Result:

- Scan ID: `orch_1780545443_b6a354cc`
- Verdict: `SIGUR`
- Risk: `low`, score `10`
- Final URL: `https://buyback.yoxo.ro/?r=1`
- Web Risk: `clean`
- VirusTotal: `clean`
- urlscan: `ok`, `No malicious classification`
- Claim verifier: `confirmed`
- Preview screenshot: `https://nudaclick-backend.vercel.app/v1/sandbox/urlscan/019e90c7-5878-762a-9d04-3babb2165ba4/screenshot`
- urlscan report: `https://urlscan.io/result/019e90c7-5878-762a-9d04-3babb2165ba4/`

Conclusion: full pipeline works for benign commercial SMS with real providers and preview.

### Google Safe Browsing / Web Risk Phishing Test URL

Input:

`https://testsafebrowsing.appspot.com/s/phishing.html`

Result:

- Scan ID: `orch_1780545146_3899c7c3`
- Verdict: `PERICULOS`
- Risk: `high`, score `90`
- Web Risk: `malicious`
- VirusTotal: `malicious`
- urlscan: rejected with HTTP 400
- Claim verifier: not required

Conclusion: hard malicious providers can finalize `PERICULOS` even when urlscan cannot scan the URL.

### Flanco / Postis Feedback SMS

Input:

`Ai primit produsul Flanco. Dorim sa fim mai buni pentru tine, acorda-ne un calificativ pentru livrare cu un clic aici: https://t.postis.io/9kj8p`

Result:

- Scan ID: `orch_1780545551_fd1d905b`
- Verdict: `SUSPECT`
- Risk: `medium`, score `50`
- Final URL: `https://postis.io/api/v1/clients/redirect/shorten/9kj8p`
- Web Risk: `clean`
- VirusTotal: `clean`
- urlscan: accepted scan, but screenshot did not complete before timeout
- Claim verifier: `inconclusive`, not required
- urlscan report: `https://urlscan.io/result/019e90c9-00e9-7761-bbf6-e94987c43c4d/`

Conclusion: backend no longer blocks forever. It does not call the message safe without preview; it returns `SUSPECT` with a partial-verification reason.

## Fixes Validated

- Long `source_channel` no longer breaks urlscan tags.
- urlscan HTTP 400 details are retained in backend pillar details.
- `PERICULOS` can finalize from hard provider evidence even when urlscan fails.
- `SIGUR` requires urlscan preview to be ready.
- urlscan screenshot timeout produces `SUSPECT`, not `SIGUR` and not infinite `scanning`.

## Capped Opt-In Runner

Live smoke is now scriptable, but intentionally opt-in:

```bash
python3 backend/eval/live_provider_smoke_runner.py --dry-run
SIGURSCAN_RUN_LIVE_PROVIDER_SMOKE=1 python3 backend/eval/live_provider_smoke_runner.py --output build/reports/live_provider_smoke.json
```

Rules:

- Do not run fixture packs through live providers.
- Do not run `.test`, `.invalid`, or `.example` live targets.
- Keep the set capped and user-approved.
- Use `SIGURSCAN_LIVE_SMOKE_API_KEY` if production requires `X-API-KEY`.
- Use `SIGURSCAN_LIVE_SMOKE_BASE_URL` to switch between Vercel environments.
