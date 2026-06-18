# API Security

Data: 2026-06-10

Cum este protejat backend-ul public (Cloud Run) împotriva abuzului de quota
(urlscan, Google Web Risk, Gemini, Mistral) și a expunerii telemetriei.

## Straturi

| Strat | Mecanism | Stare |
| --- | --- | --- |
| Cheie de client | `X-API-KEY` (sau `Authorization: Bearer`) pe toate rutele non-publice | activabil prin env |
| Cheie de admin | chei separate pentru telemetrie/dashboards, fail-closed | activabil prin env |
| Rate limiting | sliding window 60s per cheie + per IP, Upstash Redis partajat între instanțe | activ; fallback documentat mai jos |
| Play Integrity | leagă request-urile de aplicația reală din Play | OAuth/decode + nonce distribuit single-use + Android SDK; poate autoriza scan routes în `enforce` fără cheie statică în APK |

## Variabile de mediu

| Variabilă | Rol |
| --- | --- |
| `REQUIRE_API_KEY` | `true` ⇒ rutele non-publice cer cheie de client |
| `SIGURSCAN_API_KEYS` | chei de client, separate prin virgulă (rotație: adaugă cheia nouă, livrează build-ul, șterge cheia veche) |
| `SIGURSCAN_ADMIN_API_KEYS` | chei de operator, separate prin virgulă; NU se livrează în aplicație |
| `ENABLE_RATE_LIMIT` / `RATE_LIMIT_PER_MINUTE` | activare / prag pe minut (default 60) |
| `UPSTASH_REDIS_REST_URL` + `UPSTASH_REDIS_REST_TOKEN` | backend-ul real de rate limiting (REST, partajat) |
| `PLAY_INTEGRITY_MODE` | `off` (default) / `monitor` / `enforce` |
| `PLAY_INTEGRITY_CREDENTIALS_JSON` | service account autorizat în Play Console pentru `decodeIntegrityToken` |
| `PLAY_INTEGRITY_NONCE_TTL_SECONDS` | TTL pentru provocarea single-use distribuită (default 120s) |
| `SIGURSCAN_ALLOW_RELEASE_STATIC_API_KEY` | Android build flag de fallback; default `false`, deci release nu include `SIGURSCAN_RELEASE_API_KEY` implicit |
| `OPENAPI_RO_API_KEY` / `OPENAPI_RO_MONTHLY_BUDGET` | fallback plătit pentru verificare CUI/firme, consumat doar după ANAF/lista-firme; default buget 100/lună |
| `HUNTER_IO_API_KEY` / `HUNTER_IO_MONTHLY_BUDGET` | rezervat pentru provider email/domain cu buget 50/lună; nu există call-site activ până la integrare explicită |

`/health` raportează postura curentă fără să expună secrete:
`api_key_required`, `admin_api_configured`, `rate_limit_backend`
(`upstash` sau `memory_best_effort`), `play_integrity_mode`,
`play_integrity_nonce_backend`.

## Reguli de rutare

- **Publice** (fără cheie): `/`, `/health`, `/healthz`, `/privacy`,
  `/privacy-policy`, `/terms`, `/terms-of-service`.
- **API docs:** `/docs`, `/openapi.json`, `/redoc` sunt dezactivate implicit.
  Se activează doar cu `EXPOSE_API_DOCS=true` pentru dev/debug controlat.
- **Admin-only** (fail-closed, 403 dacă `SIGURSCAN_ADMIN_API_KEYS` lipsește,
  401 fără cheia corectă; cheia de client NU e acceptată):
  `/v1/orchestration/dashboard`, `/v1/orchestration/telemetry`,
  `/v1/feedback/summary`, `/v1/adjudication/shadow`, `/v1/adjudication/dashboard`.
- **Excepție vizuală**: `GET /v1/sandbox/urlscan/{uuid}/screenshot` rămâne fără
  cheie pentru că e încărcat de Coil (image loader fără headere custom).
  UUID-ul urlscan e neghicibil și rate limiting-ul se aplică în continuare.
- Restul rutelor `/v1/*` cer cheia de client când `REQUIRE_API_KEY=true`.
  Cheia de admin nu este acceptată pe rutele de client.
- Excepție Play Integrity: în `PLAY_INTEGRITY_MODE=enforce`, rutele POST de
  scanare (`/v1/scan/*`, `/v1/extract/*`, `/v1/sandbox/urlscan`) pot fi
  autorizate de un token Play Integrity valid chiar fără `X-API-KEY`.
- `POST /v1/security/play-integrity/nonce` poate emite nonce fără cheia statică
  atunci când Play Integrity nu este `off`; nonce-ul se leagă de
  `X-SigurScan-Client-Instance` și rate limiting-ul rămâne activ.

## Rate limiting: Upstash și fallback-ul

Cu Upstash configurat, limita e un sliding window de 60s ținut într-un sorted
set Redis per `(identitate, path)`, partajat între toate instanțele serverless.
Identități: `key:<sha256-prefix>` (cheia brută nu ajunge în Redis) și
`ip:<adresă>`.

**Fallback (important):** fără `UPSTASH_REDIS_REST_URL`/`TOKEN`, limita cade pe
bucket-uri in-memory **per instanță lambda**. Pe serverless asta înseamnă
best-effort: un atacator care nimerește instanțe diferite nu e limitat global.
Starea e vizibilă în `/health` ca `rate_limit_backend: memory_best_effort`.
În producție Cloud Run, `RATE_LIMIT_FAIL_CLOSED=true` face ca erorile Upstash să
returneze 429 în loc să cadă pe fallback local. Concluzie: în producție,
configurează Upstash și fail-closed.

## Bugete provider plătit / rar

Providerii cu quota mică sau cost direct nu sunt controlați doar prin rate limit
de client. Backend-ul folosește `services.provider_budget` pentru un buget lunar
per provider. În producție, dacă Supabase este configurat, consumul trece prin
RPC atomic `try_consume_provider_budget`, partajat între toate instanțele Cloud
Run. Dacă RPC-ul nu este disponibil într-un mediu cu Supabase configurat,
providerul este blocat fail-closed, ca să nu ardă quota per instanță.

Local/dev fără Supabase folosește fallback in-memory, doar pentru testare. În
producție trebuie aplicată migrarea Supabase pentru
`provider_monthly_budget_usage` înainte de activarea cheilor rare. În prezent,
`openapi.ro` consumă bugetul `OPENAPI_RO_MONTHLY_BUDGET` doar ca fallback după
ANAF și lista-firme. Hunter.io este doar secret/env pregătit; nu este apelat de
pipeline până la o integrare explicită.

## CORS

Origini permise: `sigurscan.ro`, `www.sigurscan.ro` și backend-ul web configurat
prin `ALLOWED_ORIGINS`. Metodele sunt limitate la `GET`, `POST`, `OPTIONS`, iar
headerele custom permise sunt explicite: `Authorization`, `Content-Type`,
`X-API-KEY`, `X-Play-Integrity-Token`, `X-SigurScan-Client-Instance`.

## Cheia de client în Android

- Build debug/private: `SIGURSCAN_API_KEY` din `local.properties` sau env poate
  fi expus prin `BuildConfig`.
- Build release public: `SIGURSCAN_RELEASE_API_KEY` este gol implicit. Este inclus
  doar dacă `SIGURSCAN_ALLOW_RELEASE_STATIC_API_KEY=true`, ca fallback conștient.
- Runtime: `ApiKeyInterceptor` adaugă `X-API-KEY` doar când există și trimite un
  `X-SigurScan-Client-Instance` anonim stabil pentru binding-ul nonce-ului.
- **Limitare asumată:** cheia din APK e extractabilă. E doar o barieră
  anti-abuz. Autentificarea reală vine din Play Integrity (mai jos).
- Audit repetabil: `python3 tools/audit_android_release_secrets.py app/build/outputs/apk/release/app-release.apk`
  trebuie să eșueze dacă găsește provider/admin/service secrets în artifact.
  `SIGURSCAN_API_KEY` în debug/private poate apărea ca warning. Release public
  trebuie verificat fără provider/admin/service secrets și fără static client key,
  cu excepția unui fallback explicit documentat.

## Play Integrity

`services/play_integrity.py` conține fluxul `decodeIntegrityToken` și mapează
`PLAY_INTEGRITY_CREDENTIALS_JSON` prin service-account OAuth2 către Google Play
Integrity API. Android include Play Integrity SDK (`com.google.android.play:integrity`)
și `ApiKeyInterceptor` poate atașa tokenul în `X-Play-Integrity-Token` când
`SIGURSCAN_ENABLE_PLAY_INTEGRITY=true`.

`POST /v1/security/play-integrity/nonce` emite o provocare legată de
`X-SigurScan-Client-Instance` (sau de cheia client pentru build-uri legacy).
Backend-ul stochează doar hash-ul nonce-ului și binding-ul hash-uit
în Upstash, cu TTL scurt și `NX`. După `decodeIntegrityToken`,
backend-ul verifică timestamp-ul Google și consumă provocarea atomic cu
`GETDEL`; replay-ul, expirarea, client mismatch și indisponibilitatea store-ului
nu pot produce status `valid`.

Ce NU este gata încă pentru enforce public: secretul de service account trebuie
configurat în Cloud Run/Secret Manager, build-ul Play semnat trebuie să activeze
flagul Android, release-ul trebuie livrat prin Play ca să primească verdict
`PLAY_RECOGNIZED`, iar pass rate-ul trebuie măsurat întâi în `monitor`.
Rollout recomandat: `off` → `monitor` (măsoară pass rate) → `enforce`.
În `enforce`, rutele de scan (`/v1/scan/*`, `/v1/extract/*`,
`/v1/sandbox/urlscan`) cer un token valid în `X-Play-Integrity-Token` sau o
cheie client validă plus token valid, în funcție de etapa de rollout.
