# Live Provider Smoke Results - 2026-06-04

Scope: production backend `https://nudaclick-backend.vercel.app`, real provider calls, no mocks.

## Production Deploys

- Deployed urlscan hard-provider finalize fix.
- Deployed urlscan tag sanitization fix.
- Deployed urlscan pending screenshot timeout fix.

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
