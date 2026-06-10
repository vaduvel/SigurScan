# SigurScan Preview Pre-Capture Worker v1

Worker Node.js + Playwright pentru capturi cache de URL-uri din emailuri sau liste de URL-uri. Scopul este să servești instant preview-uri din cache în aplicația SigurScan, fără să aștepți urlscan/screenshot live de fiecare dată.

## Ce face

1. Parsează `.eml`, `.html`, `.txt`, `.md`, `.csv`, `.json`.
2. Extrage URL-uri din:
   - HTML `href`, `src`, `action`, `data-href`, `data-url`;
   - plaintext URLs;
   - butoane/linkuri ascunse;
   - seed JSON oficial.
3. Normalizează URL-ul: host lowercase, fragment strip, query păstrat.
4. Dedup pe URL normalizat la input.
5. Navighează izolat cu Playwright.
6. Blochează cereri către IP-uri private/interne/metadata.
7. Urmărește redirecturile și calculează `url_hash = sha256(final_url_normalized)`.
8. Respectă TTL: skip dacă există cache fresh.
9. Captureaza PNG cu inaltime limitata, pentru a evita paginile infinite/ostile.
10. Scrie în Supabase sau local fallback: `manifest.json` + `/screenshots`.
11. Nu persistă deloc URL-urile marcate `skipped`/`blocked`; rapoartele conțin doar hash + host.
12. Reîncearcă o singură dată erorile tranzitorii (`timeout`, HTTP/2, 5xx/429), dar nu încearcă să ocolească răspunsurile anti-bot `401/403`.
13. Aplică backoff pe rândurile `dead`/`error` încă proaspete, ca seed-ul zilnic să nu lovească repetat aceleași pagini blocate.

## Ce NU face

- Nu introduce date în formulare.
- Nu apasă butoane de download.
- Nu descarcă fișiere.
- Nu dă click în pagini.
- Nu presupune că o pagină clean este sigură absolut.
- Nu scanează automat mailbox-uri live; primește exporturi sau foldere.

## Instalare

```bash
cd sigurscan_precapture_worker_v1
npm install
npm run install-browsers
cp .env.example .env
```

## Fără Supabase: manifest local

```bash
node src/index.js \
  --email-source ./samples/official_preview_targets.ro.json \
  --out-dir ./output/official \
  --concurrency 2 \
  --nav-timeout-seconds 20
```

Output:

```text
output/official/manifest.json
output/official/screenshots/{url_hash}.png
output/official/final_report.json
```

## Cu Supabase

1. Rulează `supabase/schema.sql`.
2. Creează bucket privat `previews`.
3. Completează `.env`:

```bash
SUPABASE_URL=https://xxxx.supabase.co
SUPABASE_SERVICE_KEY=service_role_key_here
STORAGE_BUCKET=previews
CACHE_TABLE=fast_preview_cache
RUNS_TABLE=fast_preview_capture_runs
CLEANUP_EXPIRED=true
CLEANUP_LIMIT=200
```

Apoi:

```bash
node src/index.js --email-source ./emails --out-dir ./output/run1
```

Workerul va încărca screenshot-ul în bucket și va face upsert în tabel.
La începutul fiecărui run non-dry-run, șterge controlat maximum
`CLEANUP_LIMIT` rânduri expirate și imaginile lor din bucket.
Fiecare run non-dry-run este înregistrat în `fast_preview_capture_runs`
cu metrici agregate; nu se stochează conținut brut de email.

Workflow-ul GitHub Actions rulează exclusiv seed-ul public oficial
`samples/official_preview_targets.ro.json`. Input-uri din scanări reale trebuie
rulate doar într-un worker de producție izolat, nu pe runner-ul GitHub.

## Input acceptat

### Folder cu `.eml`

```bash
node src/index.js --email-source ./mailbox_export
```

### Fișier JSON cu URL-uri

```json
{
  "targets": [
    { "id": "official_anaf_home", "url": "https://www.anaf.ro/" },
    { "id": "official_fan_home", "url": "https://www.fancourier.ro/" }
  ]
}
```

### TXT/CSV/MD

Orice URL detectabil în text este extras.

## Skip pentru domenii rezervate

Workerul marchează `.test`, `.example`, `.invalid`, `.localhost` ca `reserved_domain_skipped`, ca să nu trimită/ping-uiască domenii de CI. Excepție: `example.com`, `example.org`, `example.net` sunt domenii documentare reale și pot fi folosite pentru smoke tests.

## Coloane cache

Conform contractului tău:

```text
url_hash
original_url
final_url
redirect_chain
http_status
page_title
screenshot_path
captured_at
source_email_id
reachable
error
visual_only=true
verdict_role=none
```

## Recomandări de rulare

- Pentru domenii oficiale: `concurrency=1-2`.
- Pentru emailuri suspecte: rulează în container izolat, fără acces la rețea internă.
- Pentru producție: rulează workerul în job queue, nu direct din request user-facing.
- TTL default: 7 zile.
- Nu rula pe providerii live în buclă infinită; marchează `timeout`/`dead` și gata.
- `401/403` înseamnă `blocked_by_origin`, nu URL mort; captura rămâne indisponibilă fără a influența verdictul.

## Contract pentru UI

Dacă `reachable=false` sau `screenshot_path=null`, UI-ul trebuie să arate:

```text
Preview indisponibil.
Am verificat linkul, dar pagina nu a putut fi capturată în siguranță.
```

Dacă `reachable=true` și screenshot există:

```text
Preview capturat în mediu izolat.
Nu ai accesat direct acest site.
```
