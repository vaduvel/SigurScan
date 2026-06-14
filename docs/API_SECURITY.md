# API Security

Data: 2026-06-10

Cum este protejat backend-ul public (Vercel) împotriva abuzului de quota
(urlscan, Google Web Risk, Gemini, Mistral) și a expunerii telemetriei.

## Straturi

| Strat | Mecanism | Stare |
| --- | --- | --- |
| Cheie de client | `X-API-KEY` (sau `Authorization: Bearer`) pe toate rutele non-publice | activabil prin env |
| Cheie de admin | chei separate pentru telemetrie/dashboards, fail-closed | activabil prin env |
| Rate limiting | sliding window 60s per cheie + per IP, Upstash Redis partajat între instanțe | activ; fallback documentat mai jos |
| Play Integrity | leagă request-urile de aplicația reală din Play | schelet, mod `off` |

## Variabile de mediu

| Variabilă | Rol |
| --- | --- |
| `REQUIRE_API_KEY` | `true` ⇒ rutele non-publice cer cheie de client |
| `SIGURSCAN_API_KEYS` | chei de client, separate prin virgulă (rotație: adaugă cheia nouă, livrează build-ul, șterge cheia veche) |
| `SIGURSCAN_ADMIN_API_KEYS` | chei de operator, separate prin virgulă; NU se livrează în aplicație |
| `ENABLE_RATE_LIMIT` / `RATE_LIMIT_PER_MINUTE` | activare / prag pe minut (default 60) |
| `UPSTASH_REDIS_REST_URL` + `UPSTASH_REDIS_REST_TOKEN` | backend-ul real de rate limiting (REST, partajat) |
| `PLAY_INTEGRITY_MODE` | `off` (default) / `monitor` / `enforce` |

`/health` raportează postura curentă fără să expună secrete:
`api_key_required`, `admin_api_configured`, `rate_limit_backend`
(`upstash` sau `memory_best_effort`), `play_integrity_mode`.

## Reguli de rutare

- **Publice** (fără cheie): `/`, `/health`, `/healthz`, `/privacy`,
  `/privacy-policy`, `/docs`, `/openapi.json`, `/redoc`.
- **Admin-only** (fail-closed, 403 dacă `SIGURSCAN_ADMIN_API_KEYS` lipsește,
  401 fără cheia corectă; cheia de client NU e acceptată):
  `/v1/orchestration/dashboard`, `/v1/orchestration/telemetry`,
  `/v1/feedback/summary`, `/v1/adjudication/shadow`, `/v1/adjudication/dashboard`.
- **Excepție vizuală**: `GET /v1/sandbox/urlscan/{uuid}/screenshot` rămâne fără
  cheie pentru că e încărcat de Coil (image loader fără headere custom).
  UUID-ul urlscan e neghicibil și rate limiting-ul se aplică în continuare.
- Restul rutelor `/v1/*` cer cheia de client când `REQUIRE_API_KEY=true`.
  Cheia de admin e acceptată și pe rutele de client.

## Rate limiting: Upstash și fallback-ul

Cu Upstash configurat, limita e un sliding window de 60s ținut într-un sorted
set Redis per `(identitate, path)`, partajat între toate instanțele serverless.
Identități: `key:<sha256-prefix>` (cheia brută nu ajunge în Redis) și
`ip:<adresă>`.

**Fallback (important):** fără `UPSTASH_REDIS_REST_URL`/`TOKEN`, limita cade pe
bucket-uri in-memory **per instanță lambda**. Pe serverless asta înseamnă
best-effort: un atacator care nimerește instanțe diferite nu e limitat global.
Starea e vizibilă în `/health` ca `rate_limit_backend: memory_best_effort`.
Erorile de rețea spre Upstash fac fail-open pe fallback-ul de memorie ca să nu
blocheze scanări legitime. Concluzie: în producție, configurează Upstash.

## Cheia de client în Android

- Build: `SIGURSCAN_API_KEY` (debug) / `SIGURSCAN_RELEASE_API_KEY` (release) din
  `local.properties` sau env, expuse prin `BuildConfig`.
- Runtime: `ApiKeyInterceptor` adaugă `X-API-KEY` pe clientul Retrofit.
- **Limitare asumată:** cheia din APK e extractabilă. E doar o barieră
  anti-abuz. Autentificarea reală vine din Play Integrity (mai jos).
- Audit repetabil: `python3 tools/audit_android_release_secrets.py app/build/outputs/apk/release/app-release.apk`
  trebuie să eșueze dacă găsește provider/admin/service secrets în artifact.
  `SIGURSCAN_API_KEY` / `SIGURSCAN_RELEASE_API_KEY` sunt raportate ca warning
  până când sunt înlocuite de Play Integrity sau token scurt emis de backend.

## Play Integrity (schelet)

`services/play_integrity.py` conține fluxul `decodeIntegrityToken` cu TODO-uri
explicite: service account + OAuth2, nonce anti-replay, client Android.
Rollout recomandat: `off` → `monitor` (măsoară pass rate) → `enforce`.
În `enforce`, rutele de scan (`/v1/scan/*`, `/v1/extract/*`,
`/v1/sandbox/urlscan`) cer un token valid în `X-Play-Integrity-Token`.
