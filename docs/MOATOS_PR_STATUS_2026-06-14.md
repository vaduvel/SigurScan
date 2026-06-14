# MoatOS PR Status - 2026-06-14

Repo: `vaduvel/SigurScan`
Branch verificat: `feature/osint-intel-pipeline`
Production Cloud Run: `sigurscan-api-00043-qq7`
Production image: `europe-west1-docker.pkg.dev/project-20f225c0-d756-4cba-864/sigurscan/sigurscan-api:3231eeb`

## Rezumat Brutal

- Backend PR-5..PR-8 este deployat live si verificat pe endpoint-uri reale.
- Supabase PR-6 tables sunt aplicate live si citibile prin REST.
- DNS reputation este activ live (`ENABLE_DNS_REPUTATION=true`) si apare in scanari reale ca `infra_dns`.
- PR-6 Cercul are acum write-through plus read-fallback din Supabase; testat live cu link creat inainte de deploy.
- Android PR-5/PR-7/PR-9/PR-10 nu este feature-complete. Build-ul trece, dar lipsesc integrari reale on-device.
- Android PR-8 afiseaza acum `action_plan` cand vine in scan response, dar nu are inca flow separat prin care userul completeaza impacts reale post-incident.
- `origin/main` nu este sursa exacta a productiei; productia ruleaza branch-ul `feature/osint-intel-pipeline`.

## Verificari Rulate

- Backend full test: `INVOICE_CACHE_HMAC_KEY=testkey PRIVACY_SAFE_MODE=false pytest -q`
  - rezultat: `898 passed, 1 warning`
- Android JVM + build: `JAVA_HOME='/Applications/Android Studio.app/Contents/jbr/Contents/Home' ./gradlew testDebugUnitTest assembleDebug`
  - rezultat: `BUILD SUCCESSFUL`
- Cloud Run live:
  - revision: `sigurscan-api-00043-qq7`
  - traffic: `100%`
  - image: `:3231eeb`
- Domeniu oficial `https://api.sigurscan.com`:
  - `/health`: OK
  - `/v1/radar/hot-iocs`: OK
  - POST `/v1/scan/orchestrated` cu YOXO: `SAFE`, score `10`, preview `ready`
- Live scan YOXO:
  - verdict: `SAFE`
  - score: `10`
  - `infra_dns`: `clean / resolves`
  - preview: `ready`
- Live scan mesaj bancar periculos:
  - verdict: `DANGEROUS`
  - score: `90`
  - `action_plan`: prezent, 2 pasi
  - `infra_dns`: `suspicious / nxdomain`
- Live scan `https://urlz.fr/rZrw` dupa activare DNS:
  - status: `complete`
  - preview reason: `final_url_unresolved`
  - `infra_dns`: `suspicious / registrar_suspended`
  - observatie: user label ramas `UNVERIFIED/info`, nu `SUSPECT`

## PR / Moat Matrix

| PR | Moat / functie | Backend live | Android live | Evidence |
| --- | --- | --- | --- | --- |
| PR-0..PR-4 | verdict gate, BTR, provenance, Urechea, CFX | Da | Partial, prin flow-ul existent de scanare | `/v1/verify/provenance` live OK; backend tests passing |
| PR-5 | Radar hot-cache | Da | Nu pentru CallScreening | `/v1/radar/hot-iocs` live OK; Android nu are `CallScreeningService` / `ROLE_CALL_SCREENING` |
| PR-5 | Raport 1-tap | Da | Nu este conectat ca flow dedicat | `/v1/report` live OK, canale DNSC/PNRISC/Banca |
| PR-6 | Cercul out-of-band | Da | Nu are UI Android dedicat | `/v1/circle/pair`, `/ping`, `/respond`, `/revoke` live OK |
| PR-6 persist | Supabase durable state | Da | N/A | `circle_links`, `verification_pings`, `guardian_second_opinion` live OK; read-fallback adaugat in `4ba2b9b` |
| PR-6 | Guardian second opinion | Da | Nu are UI Android dedicat | `/v1/guardian/second-opinion` live OK; full fara consimtamant downgrade la metadata_only |
| PR-7 | Inbox provenance contract / BTR sync | Da ca endpoint | Nu ca procesare SMS on-device | `/v1/btr/sync` live OK; Android nu consuma endpointul si nu are service SMS/inbox dedicat |
| PR-8 | Plan de actiune post-incident | Da | Partial | `/v1/legal/action-plan` live OK; Android parseaza/randeaza `action_plan` din scan response |
| PR-8/9 integ | `action_plan` in orchestrator + audio reference | Partial backend | Partial pentru action_plan, nu audio | Orchestratorul trimite `action_plan`; Android il afiseaza. Nu exista audio reference/on-device audio |
| Extra | DNS reputation | Da | Da indirect prin scan response | `infra_dns` live OK; flag Cloud Run activ |
| PR-9/PR-10 | Android on-device: ASR/Vosk, banda inline, captura difuzor | Nu ca feature complet | Nu | Nu exista `Vosk`, `AudioRecord`, `SpeechRecognizer`, call/audio service in `app/src/main` |

## Gap-uri Care Nu Trebuie Numite Complete

1. Android CallScreening pentru PR-5 lipseste.
   - Nu exista service in manifest.
   - Nu exista cerere `ROLE_CALL_SCREENING`.
   - Radar tab-ul existent foloseste campanii UI, nu hot-cache offline pentru apel.

2. Android BTR sync / Inbox PR-7 lipseste.
   - Backend-ul ofera `/v1/btr/sync`.
   - App-ul nu are client Retrofit pentru acest endpoint si nu are pipeline SMS/inbox on-device.

3. Android PR-8 Action Plan este doar partial.
   - Backend-ul ofera `/v1/legal/action-plan`.
   - App-ul afiseaza `action_plan` primit in scan response.
   - Lipseste flow-ul dedicat in care userul declara impacts reale (`shared_card`, `paid_transfer` etc.) si app-ul cere planul personalizat.

4. PR-9/PR-10 Android audio nu este implementat.
   - Nu exista Vosk/ASR/captura difuzor in codul Android.

5. Gate/UX pentru `urlz.fr/rZrw` merita decis explicit.
   - Tehnic scanarea se inchide corect, preview explica `final_url_unresolved`, DNS detecteaza `registrar_suspended`.
   - User-facing label este `UNVERIFIED/info`; daca produsul vrea fail-safe mai vizibil, regula trebuie ajustata la `SUSPECT` pentru shortener + final unresolved + DNS suspended.

## Ce E Production-Grade Acum

- Backend scan pipeline nu mai ramane blocat la provider errors cunoscute.
- Malformed URL port nu mai crapa scanarea.
- Preview fallback queryless functioneaza pentru YOXO.
- DNS reputation este activ si verificat live.
- Supabase PR-6 tables exista live.
- Cercul PR-6 nu mai depinde strict de memoria unei singure instante Cloud Run.
- Android afiseaza planul de actiune preventiv PR-8 cand backend-ul il include in scan response.
