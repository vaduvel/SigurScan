# SigurScan — Audit final de maturitate production‑grade / real‑world readiness

**Branch analizat:** `codex/romania-research-2026-06-16`  
**Data auditului:** 17 iunie 2026  
**Teste backend la momentul auditului:** 1148 passed / 0 failed  
**Surse:** analiză manuală a codului + cercetare web (OWASP, NIST, Stripe Radar, Cloudflare, Google Play Integrity, GDPR, NIS2, DORA, best practices FastAPI/Celery/Redis)

---

## 1. Executive summary

SigurScan este un **MVP tehnic solid** cu arhitectură bună la nivel conceptual: pipeline asincron cu stări, privacy‑first design, multiple layere de analiză (reputație, semantică, invoice, community), test coverage consistent și documentație bogată.

**Cu toate acestea, codebase‑ul NU este pregătit pentru producție reală, comercială, la scară.** Cele mai grave probleme sunt de securitate și arhitectură operațională:

1. **Secrete de producție pe disc** (`backend/.env.vercel`, `local.properties`).
2. **Chei API înglobate în APK** și acceptate pe endpointuri interne.
3. **Scan IDs predictibile** + rezultate accesibile doar cu cheia client → risc de leak cross‑user.
4. **Backend monolitic de 11.000+ linii** cu stare globală în memorie.
5. **Apeluri sincrone `requests` în cod async** + zeci de `except Exception` care înghit erori.
6. **Rate limiter cu fallback per instanță**, deci nu scalează orizontal.
7. **Lipsă circuit breaker, retry științific, queue real și observabilitate de producție.**

### Scoruri de maturitate

| Dimensiune | Scor /10 | Justificare |
|---|---|---|
| Corectitudine funcțională | 7.5 | Rule‑based solid, teste multe, dar fragil la inputuri noi |
| Securitate | 4.5 | Controale de bază există, dar găuri critice la auth, secrets, client |
| Scalabilitate / performanță | 4.0 | Stare în memorie, requests sincrone, cache local |
| Operare / observabilitate | 4.5 | Health checks, telemetry local, dar fără alerte/paginație/retention |
| Compliance / privacy | 6.0 | Privacy policy, RLS, PII redaction, dar fără DPIA/Terms până recent |
| Arhitectură / maintainability | 4.0 | Monolit greu, 61 fișiere de test dar unul singur de 10k linii |
| Mobile security | 4.5 | Play Integrity există dar off, chei în BuildConfig, ProGuard permisiv |
| Cost control | 5.0 | Feature flags, dar fără global quota guard |

**Scor general production‑readiness: ~5.0/10.**  
**Recomandare:** nu lansa în producție publică/comercială până nu rezolvi itemii P0 de mai jos.

---

## 2. Probleme critice (P0) — blochează producția

### CRIT-1. Secrete de producție pe discul de lucru

**Fișiere:**
- `backend/.env.vercel` — conține `SUPABASE_SERVICE_ROLE_KEY`, `UPSTASH_REDIS_REST_TOKEN`, `URLHAUS_AUTH_KEY`, chei Gemini/Vision, `SIGURSCAN_ADMIN_API_KEYS`, `SIGURSCAN_API_KEYS`, `SIGURSCAN_URLSCAN_API_KEY`.
- `local.properties` — conține `SIGURSCAN_URLSCAN_API_KEY`, `SIGURSCAN_VIRUS_TOTAL_API_KEY`, Google Web Risk/Safe Browsing keys, client/admin/release API keys.

**Impact:** Un singur leak dă acces total la DB, Redis, provideri plătiți, admin dashboards.  
**Recomandare:**
- Șterge ambele fișiere imediat.
- Rotează TOATE secretele din ele.
- Mută secretele în Secret Manager / Vercel env / GitHub Secrets.
- Adaugă `backend/.env*.vercel` și `local.properties` în `.gitignore` cu verificare pre‑commit.

**Status 2026-06-18:** fișierele locale sunt ignorate și nu apar în `git ls-files`; CI rulează `tools/guard_no_tracked_secrets.py` ca să blocheze tracking-ul accidental de `.env*`, `local.properties`, `keystore.properties`, keystore-uri și credentials JSON. Rămâne acțiune externă obligatorie: rotația secretelor deja prezente pe discul local și confirmarea în Secret Manager/GitHub Secrets.

### CRIT-2. Chei API înglobate în APK Android

**Locații:** `app/build.gradle.kts:86-87, 91, 96, 119-121`
- `SIGURSCAN_API_KEY` / `SIGURSCAN_RELEASE_API_KEY`
- `URLSCAN_API_KEY`
- `GOOGLE_WEB_RISK_API_KEY`

**Impact:** Decompilarea APK‑ului dezvăluie cheile. URLscan și Web Risk pot fi abuzate financiar. Cheia SigurScan poate fi folosită pentru scraping.  
**Recomandare:**
- Elimină TOATE cheile din `BuildConfig`.

**Status 2026-06-18:** provider keys (`URLSCAN_API_KEY`, `GOOGLE_WEB_RISK_API_KEY`) sunt goale în Android BuildConfig; release nu mai include `SIGURSCAN_RELEASE_API_KEY` implicit și acceptă cheia statică doar cu fallback explicit `SIGURSCAN_ALLOW_RELEASE_STATIC_API_KEY=true`. Rămâne de configurat Play Integrity live (`monitor` → `enforce`) înainte de release public fără static key.
- Androidul trebuie să se autentifice doar prin **Play Integrity** + token JWT pe viață scurtă emis de backend.
- Mută apelurile URLscan/Web Risk în backend exclusiv.

### CRIT-3. Endpointul intern acceptă și cheia client

**Locație:** `backend/main.py:445-451`

```python
def _require_internal_worker_auth(request: Request) -> None:
    if _internal_worker_token_matches(request):
        return
    api_key = _extract_api_key(request)
    if api_key and api_key in (ALLOWED_API_KEYS | ADMIN_API_KEYS):
        return
```

**Impact:** Orice client care extrage cheia din APK poate apela `/internal/orchestrated/{scan_id}/advance`, consumând provider quota și perturbând pipeline‑ul.  
**Recomandare:**
- Elimină fallback‑ul pe API key.
- `INTERNAL_WORKER_TOKEN` trebuie să fie singura cale de auth pentru `/internal/*`.
- Token lung random (≥128 biți) în Secret Manager, niciodată în client.

**Status 2026-06-18:** fallback-ul pe client/admin API key a fost eliminat; `/internal/*` acceptă doar `X-Internal-Worker-Token` / `X-Cloud-Tasks-Token`, testat în `test_internal_worker_routes_reject_client_and_admin_api_keys`.

### CRIT-4. Scan IDs predictibile

**Locație:** `backend/main.py:4609-4610`

```python
def _new_scan_id(prefix: str) -> str:
    return f"{prefix}_{int(time.time())}_{os.urandom(4).hex()}"
```

**Impact:** Doar 4 bytes de entropie + timestamp. Cu cheia client partajată, un atacator poate brute‑force ID‑urile recente și citi conținutul scanărilor altor utilizatori.  
**Recomandare:**
- Folosește `secrets.token_urlsafe(24)` sau UUID4 criptografic.
- Leagă scanarea de sesiune/device token; returnează doar câmpurile autorizate.

**Status 2026-06-18:** `_new_scan_id()` folosește `secrets.token_urlsafe(24)` și testul `test_scan_ids_do_not_expose_timestamp_or_low_entropy_suffix` blochează regresia. Legarea completă scan-result de token/sesiune rămâne de făcut separat.

### CRIT-5. Backend monolitic cu stare globală în memorie

**Locații:** `backend/main.py` (11.292 linii), `_ORCHESTRATED_SCAN_JOBS`, `_ORCHESTRATED_SCAN_LOCKS`, `_URLSCAN_PREVIEW_CACHE`, `_FAST_PREVIEW_CACHE`.

**Impact:**
- Nu scalează orizontal: 2 instanțe Cloud Run nu împărțesc starea.
- Pierdere de joburi la restart.
- Merge conflicts severe, testare izolată dificilă.

**Recomandare:**
- Refactor în FastAPI routers: `api/scan/`, `api/extract/`, `api/invoice/`, `api/intel/`, `api/admin/`, `api/community/`.
- Mută starea în Redis (joburi, locks, cache preview).

### CRIT-6. `requests` sincron în cod async

**Locații:** `services/url_reputation.py`, `services/redirect_resolver.py`, `services/anaf_cui.py`, `services/gemini_explainer.py`, apeluri directe în `main.py`.

**Impact:** Blochează event loop‑ul FastAPI; sub load, instanțele se sufocă și dau timeout.  
**Recomandare:**
- Înlocuiește `requests` cu `httpx.AsyncClient` pentru toate provider calls.
- Sau folosește `asyncio.to_thread` cu `ThreadPoolExecutor` bounded pentru cod sincron legacy.

### CRIT-7. `except Exception` înghite erori

**Locații:** 58 în `main.py`, multe și în `services/*.py`.

**Impact:** Incidente de securitate, erori de provider și pierderi de date sunt invizibile. Fail‑open prevalent.  
**Recomandare:**
- Prinde excepții specifice.
- Folosește `logger.exception(...)` pentru structured logging.
- Pe căi critice (auth, integrity, quota) — **fail closed**.

### CRIT-8. Rate limiter cu fallback per instanță

**Locație:** `services/rate_limiter.py:123-143`

**Impact:** Dacă Upstash e indisponibil, limitarea devine locală per instanță. Un atacator distribuit poate evada rate limit‑ul global.  
**Recomandare:**
- În producție: cere Upstash și **fail closed** (returnează 429) la eroare Redis.
- Alertă imediată când `rate_limit_backend != upstash`.

**Status 2026-06-18:** `RATE_LIMIT_FAIL_CLOSED=true` este implementat și activ în `tools/deploy_cloud_run_backend.sh`; pe erori Upstash, producția poate returna 429 în loc să cadă pe fallback local. Dev/local păstrează fallback-ul de memorie când flagul nu e activ.

---

## 3. Probleme High (P1) — rezolvă în 1‑2 săptămâni

### HIGH-1. Admin keys accepted on non-admin routes
**Locație:** `main.py:485` — `api_key not in (ALLOWED_API_KEYS | ADMIN_API_KEYS)`  
**Recomandare:** Rutelor client doar client keys; admin routes doar admin keys.

**Status 2026-06-18:** rezolvat; admin key nu mai autorizează rute client și bypass-ul de rate limit pentru admin se aplică doar pe admin endpoints.

### HIGH-2. Play Integrity default `off` + nonce binding slab
**Locații:** `services/play_integrity.py:37`, `services/play_integrity_nonce.py:28-29`  
**Recomandare:**
- `monitor` → `enforce` după măsurare.
- Leagă nonce de device/install ID, nu de cheia client partajată.

**Status 2026-06-18:** Android trimite `X-SigurScan-Client-Instance` anonim stabil, nonce-ul se leagă de acest id, iar backend-ul poate autoriza scan routes în `PLAY_INTEGRITY_MODE=enforce` fără static API key. Rămâne operațional: service account Play Integrity + build Play semnat + monitor pass rate înainte de enforce.

### HIGH-3. `READ_PHONE_STATE` și `RECORD_AUDIO` în manifestul principal
**Locație:** `app/src/main/AndroidManifest.xml:7-8`  
**Recomandare:** Elimină din manifestul principal până la QA completă și consimțământ explicit.

### HIGH-4. Lipsă network security config / certificate pinning
**Recomandare:** Adaugă `res/xml/network_security_config.xml` cu pinning pentru `api.sigurscan.com`.

**Status 2026-06-18:** network security config adăugat și legat în manifest; cleartext este dezactivat explicit, iar `api.sigurscan.com` este declarat cu trust anchors de sistem. Certificate pinning strict rămâne neactivat intenționat până există pin + backup pin gestionat operațional, ca să nu blocăm aplicația la rotații Cloudflare.

### HIGH-5. `/docs`, `/openapi.json`, `/redoc` publice
**Locație:** `main.py:192-193` (acum și `/terms`, `/terms-of-service`)  
**Recomandare:** Dezactivează în producție sau gatează‑le cu admin auth.

**Status 2026-06-18:** rezolvat implicit; FastAPI docs/openapi/redoc sunt dezactivate by default și se activează doar cu `EXPOSE_API_DOCS=true`.

### HIGH-6. CORS permisiv
**Locație:** `main.py:417-421` — `allow_methods=["*"]`, `allow_headers=["*"]`  
**Recomandare:** Whitelist explicit metode și headere.

**Status 2026-06-18:** rezolvat; CORS folosește metode explicite `GET/POST/OPTIONS` și headere explicite, inclusiv Play Integrity și client-instance.

### HIGH-7. Validare upload doar pe extensie/MIME
**Locație:** `main.py:4965-4973`  
**Recomandare:** Verifică magic bytes cu `python-magic`.

**Status 2026-06-18:** rezolvat pentru imagini fără dependență nativă: validatorul verifică magic bytes JPEG/PNG/WebP pentru upload-urile image; PDF-ul avea deja verificare `%PDF-`.

### HIGH-8. XML parsing cu `xml.etree.ElementTree`
**Locație:** `services/efactura_xml.py:119-127`  
**Recomandare:** Folosește `defusedxml.ElementTree`.

**Status 2026-06-18:** rezolvat; parserul e-Factura folosește `defusedxml.ElementTree`, cu test dedicat în `test_efactura_xml.py`.

### HIGH-9. Supabase service role bypass RLS
**Locație:** `services/supabase_store.py:11-15`  
**Recomandare:** Rol dedicat Postgres cu least privilege; rotează service key; monitorizează query‑urile.

### HIGH-10. Cloud Run allow-unauthenticated + URL în worker config
**Locații:** `tools/deploy_cloud_run_backend.sh:84`, `workers/api-proxy/wrangler.jsonc:16`  
**Recomandare:** Restricționează Cloud Run ingress la Cloudflare IPs; nu comite origin URL.

### HIGH-11. Cache `_URLSCAN_PREVIEW_CACHE` fără limită
**Locație:** `main.py:5650, 6085`  
**Recomandare:** LRU/TTL bounded.

### HIGH-12. Telemetry JSONL local, ne‑rotit, încărcat în memorie
**Locație:** `services/telemetry.py`  
**Recomandare:** Log rotation, retention policy, paginație DB.

### HIGH-13. Admin endpoints fără paginație
**Recomandare:** Cursor‑based pagination pentru toate listele.

### HIGH-14. Fără global provider cost guard
**Recomandare:** Token bucket global per provider în Redis + alerte de cost.
**Status 2026-06-18:** parțial rezolvat pentru providerii plătiți/rar folosiți:
`openapi.ro` este protejat de `OPENAPI_RO_MONTHLY_BUDGET` și consumă buget prin
RPC Supabase atomic `try_consume_provider_budget`, fail-closed când Supabase este
configurat dar RPC-ul lipsește. Hunter.io are secret/env și buget documentat, dar
nu are încă un call-site activ. Rămân de adăugat alerte de cost și guards similare
pentru alți provideri unde quota/costul o cere.

### HIGH-15. MainActivity exported cu intent filters nerestricționate
**Locație:** `app/src/main/AndroidManifest.xml:30-89`  
**Recomandare:** Android App Links verificate sau verificare package signature.

### HIGH-16. ProGuard păstrează tot pachetul
**Locație:** `app/proguard-rules.pro:27`  
**Recomandare:** Tighten keep rules; eventual string encryption pentru constante sensibile.

### HIGH-17. `ApiKeyInterceptor` cu cheie statică
**Locație:** `app/.../ApiKeyInterceptor.kt`  
**Recomandare:** Elimină calea statică; folosește token backend pe viață scurtă.

### HIGH-18. `api-proxy` fără rate limit / timeout / origin validation
**Locație:** `workers/api-proxy/src/index.js:67-98`  
**Recomandare:** Rate limiting Cloudflare, timeout worker, validare semnătură/origin.

### HIGH-19. Precapture worker fără sandbox Chromium
**Locații:** `workers/precapture/src/index.js:661-665`, workflow `CHROMIUM_SANDBOX=false`  
**Recomandare:** Sandbox enabled + context nou per URL.

### HIGH-20. Precapture worker poate citi fișiere arbitrare
**Locație:** `workers/precapture/src/index.js:428-458`  
**Recomandare:** Restricționează input la director cunoscut, validează extensii, permisiuni minime.

### HIGH-21. Shadow adjudication / telemetry sincron în finalizare
**Locații:** `main.py:4864, 7594`, `services/mistral_shadow_adjudicator.py:69-98`  
**Recomandare:** Mută în coadă de background.

---

## 4. Probleme Medium (P2)

1. **Dockerfile include date dev/test și cache** — adaugă `.dockerignore`.
2. **Backup workflow pune pg_dump ca artifact GitHub** — criptează, trimite în bucket locked.
3. **Migrațiile auto‑apply pe push în main** — gate de aprobare manuală.
4. **Backup script hardcodează Supabase project ref** — mută în secret/env.
5. **Health endpoints expun config** — returnează doar `status`, `version`, `timestamp`.
6. **Community report acceptă stringuri arbitrare** — restricționează enum‑uri.
7. **Play Integrity acceptă doar `MEETS_DEVICE_INTEGRITY`** — evaluează strong/virtual.
8. **Lipsă SAST/DAST în CI** — adaugă Dependabot, bandit, semgrep, OWASP dependency-check.
9. **Prompt injection în LLM** — system/user messages structurate, schema output.
10. **`_ORCHESTRATED_SCAN_LOCKS` nu e curățat** — prune cu joburile.
11. **Lipsă limită explicită request body size** — configurează Starlette.
12. **RSS workflow shell injection** — validează/sanitizează input.
13. **`ScannerViewModel` păstrează căi directe către provideri** — elimină din release.
14. **`community_campaigns` nu e în `PUBLIC_PATHS`** — adaugă sau proxy cu key.

---

## 5. Probleme Low (P3)

1. `test_backend.py` are ~10.000 linii — împarte pe module.
2. API key comparison nu e constant‑time — folosește `hmac.compare_digest`.
3. Health checks nu verifică downstream dependencies.
4. Screenshots GET fără auth — acceptă trade‑off sau signed URLs.
5. ProGuard line numbers policy nedefinită.

---

## 6. Ce face bine — păstrează

- **RLS hardening** (`supabase/migrations/20260603031448_harden_public_rls_for_client_release.sql`).
- **PII redaction** (`services/pii_redactor.py`) și **URL privacy sanitization** (`services/external_url_privacy.py`).
- **Optimistic locking** pe scan jobs (`add_scan_jobs_cas_lock.sql`).
- **Dockerfile cu `--require-hashes`**.
- **Play Integrity nonce single‑use cu TTL**.
- **Invoice HMAC cache key** din secret.
- **Feature flags** pentru majoritatea providerilor.
- **Privacy policy și Terms of Service** endpointuri (adăugate recent).

---

## 7. Recomandări din cercetarea web — cum fac companiile mari

### 7.1 Arhitectură
Companii ca Stripe Radar, Cloudflare și Wise folosesc **pipelines event‑driven asincrone**:

```
ingest → enrich → score → decide → act → learn
```

- **Layered detection:** reguli rapide → ML scoring → inteligență externă → human review.
- **Async processing:** Celery/RabbitMQ pentru feature extraction, deep URL analysis, model inference.
- **Synchronous API path scurt:** acceptă request, cache/rule check rapid, returnează verdict preliminar, restul merge în coadă.
- **Privacy‑preserving lookups:** Google Safe Browsing Update API cu hash prefix local; Lookup API doar pentru back‑office.

### 7.2 Securitate
- HTTPS only, TLS 1.2+, mTLS service‑to‑service.
- WAF, DDoS/bot protection la edge.
- JWT semnat, validat `iss`, `aud`, `exp`, `nbf`; object‑level authorization.
- API keys scoped per tenant; revocare la abuz.
- Security headers: HSTS, `X-Content-Type-Options: nosniff`, CSP `frame-ancestors 'none'`, `Cache-Control: no-store`.
- Loguri structurate, PII redactat, mesaje de eroare generice pentru client.

### 7.3 Scalabilitate
- FastAPI pe Uvicorn, un proces per container, scalează poduri.
- Celery cu cozi separate pentru taskuri scurte/lungi, autoscaling workers.
- Circuit breakers pentru toate apelurile externe.
- Redis pentru hot cache, feature store, counters.
- BentoML pentru model serving cu adaptive batching.
- Graceful degradation: dacă ML/feed cade, fallback la rule‑based cu verdict „limited”.

### 7.4 Observabilitate
- Metrici: latency, throughput, error rate, queue depth, circuit breaker state, model drift, FP/FN rate.
- Structured logs cu correlation IDs, PII redactat.
- Distributed tracing (OpenTelemetry).
- Runbooks, incident response, post‑mortems.

### 7.5 Mobile
- Play Integrity: `PLAY_RECOGNIZED`, `LICENSED`, `requestHash`/`nonce` validate.
- Nu cache verdicts integrity; request fresh la acțiunea sensibilă.
- CallScreeningService sub 5 secunde deadline.
- OWASP MASVS Level 1 pentru launch, roadmap la Level 2/3.

### 7.6 Compliance
- GDPR: lawful basis, minimizare, retention, DPA, erasure requests.
- DORA / NIS2 dacă servești entități financiare: incident reporting, third‑party risk, resilience testing.
- SOC 2 / ISO 27001 ca roadmap.

---

## 8. Roadmap final: de la 5/10 la 9/10

### Sprint 0 — Security lockdown (zilele 1‑7)
1. Șterge și rotează toate secretele din `.env.vercel` și `local.properties`.
2. Elimină cheile din `BuildConfig`; autentificare doar Play Integrity + JWT scurt.
3. Harden `/internal/*` să accepte doar `X-Internal-Worker-Token`.
4. Scan IDs cu `secrets.token_urlsafe(24)`.
5. Dezactivează `/docs`, `/openapi.json`, `/redoc` în producție.
6. Tighten CORS.

### Sprint 1 — Arhitectură async și scalabilitate (zilele 8‑21)
7. Refactor `main.py` în routers/module.
8. Mută job state în Redis (nu doar rate limiter).
9. Înlocuiește `requests` cu `httpx.AsyncClient`.
10. Adaugă circuit breaker + retry cu backoff per provider.
11. Cache distribuit pentru reputație.
12. Deduplicare scan pe hash input.

### Sprint 2 — Mobile și workers (zilele 22‑35)
13. Network security config + certificate pinning.
14. Elimină `READ_PHONE_STATE` / `RECORD_AUDIO` din manifest principal.
15. ProGuard strict.
16. Harden `api-proxy` cu rate limit, timeout, origin validation.
17. Precapture worker cu sandbox + context per URL.

### Sprint 3 — Operare și compliance (zilele 36‑60)
18. JSON structured logging + trace_id.
19. Prometheus/Grafana metrics.
20. Paginație în toate admin endpoints.
21. Retention policy pentru telemetry și date personale.
22. DPIA formală.
23. Terms of Service / Privacy Policy în app (acceptare la primul start).

### Sprint 4 — Cost și calitate (zilele 61‑90)
24. Global provider quota guards pentru toți providerii cu cost/quota mică.
25. SAST/DAST în CI (bandit, semgrep, npm audit, OWASP dependency-check).
26. Load test 1000 scanări/min.
27. Penetration test extern.
28. A/B testing framework pentru gate changes.
29. ML model lightweight pentru scoring (reduce cost LLM).

---

## 9. Decizii imediate propuse

Vreau să începem? Aș propune să demarăm cu cele mai mari impact/securitate:

1. **Rotire secrete + ștergere fișiere locale**
2. **Eliminare chei din BuildConfig + refactor auth intern**
3. **Scan IDs criptografici + binding la sesiune/device**
4. **Refactor `main.py` și mutare stare în Redis**

Aceste 4 itemi schimbă codebase‑ul semnificativ, așa că e nevoie de confirmare înainte de a începe.

---

## 10. Anexe

### A. Inventar fișiere analizate
- `backend/main.py`
- `backend/services/*.py` (toate)
- `backend/test_*.py` (toate)
- `app/build.gradle.kts`
- `app/src/main/AndroidManifest.xml`
- `app/src/main/java/ro/sigurscan/app/*.kt`
- `app/proguard-rules.pro`
- `workers/api-proxy/src/index.js`
- `workers/precapture/src/index.js`
- `.github/workflows/*.yml`
- `supabase/migrations/*.sql`
- `backend/Dockerfile`
- `tools/deploy_cloud_run_backend.sh`

### B. Referințe web
- OWASP API Security Top 10 2023
- OWASP REST Security Cheat Sheet
- OWASP MASVS
- NIST SP 800-53 Rev. 5
- DORA (EIOPA), NIS2 (European Commission)
- Google Play Integrity API overview
- Android CallScreeningService
- Martin Fowler — Circuit Breaker
- Stripe Radar engineering blog
- Cloudflare phishing automation blog
- BentoML docs
- Celery docs
- Upstash Ratelimit
- Supabase Security
