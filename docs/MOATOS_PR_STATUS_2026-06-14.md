# MoatOS PR Status - 2026-06-14

Repo: `vaduvel/SigurScan`
Branch verificat: `feature/osint-intel-pipeline`
Main remote: `origin/main` este aliniat cu branch-ul verificat; commit-urile ulterioare deployului pot fi doar documentatie/status.
Production Cloud Run: `sigurscan-api-00047-q5m`
Production image: `europe-west1-docker.pkg.dev/project-20f225c0-d756-4cba-864/sigurscan/sigurscan-api:3183000`

## Rezumat Brutal

- Backend PR-5..PR-8 este deployat live si verificat pe endpoint-uri reale.
- Supabase PR-6 tables sunt aplicate live si citibile prin REST.
- DNS reputation este activ live (`ENABLE_DNS_REPUTATION=true`) si apare in scanari reale ca `infra_dns`.
- PR-6 Cercul are acum write-through plus read-fallback din Supabase; testat live cu link creat inainte de deploy.
- Android PR-5 are acum hot-cache client, cache offline, CallScreeningService, UI pentru sync/rol OS, audit local fara numar brut si flow de raport oficial 1-tap (`/v1/report`). Flow-ul scan + raport oficial a fost validat pe emulator API 36; CallScreening a fost validat pe emulator cu rol OS activ si apel GSM simulat.
- Android PR-7 are acum BTR sync local, motor on-device de provenienta pe semnale locale si actiune UI pentru verificarea locala a ultimului scan impotriva BTR. Nu citeste automat SMS-uri.
- Android PR-8 afiseaza `action_plan` si are flow post-incident pentru impacts reale (`shared_card`, `paid_transfer` etc.).
- Android PR-9/PR-10 audio este blocat explicit prin policy pana exista model ASR on-device, consimtamant, disclosure si QA real-device.
- Productia ruleaza imaginea backend taguita `3183000`. Commit-urile de documentatie/status de dupa deploy nu schimba codul backend din container.

## Verificari Rulate

- PR-0..PR-4 targeted backend: `INVOICE_CACHE_HMAC_KEY=testkey PRIVACY_SAFE_MODE=false /opt/homebrew/bin/python3 -m pytest test_evidence_gate_golden.py test_verdict_gate.py test_brand_truth_registry.py test_provenance_gate.py test_urechea_ingester.py test_cfx_engine.py -q`
  - rezultat: `114 passed, 1 warning`
- PR-0..PR-4 targeted Android JVM: `./gradlew testDebugUnitTest --tests ...EvidenceGateTest --tests ...EvidenceSignalNormalizerTest --tests ...BackendVerdictMapperTest --tests ...GateResultPresentationTest --tests ...BrandKnowledgeRegistryTest --tests ...KnowledgePackIntegrationTest --tests ...ScamKnowledgeLayerTest --tests ...ThreatIntelOrchestratorTest --tests ...E2EFixturePackTest --tests ...SigurScanFixturePackE2ETest --tests ...InboxProvenanceEngineTest --tests ...BtrSyncStoreTest`
  - rezultat: `BUILD SUCCESSFUL`
- PR-0..PR-4 Cloud Run direct live smoke:
  - `/v1/verify/provenance` BTR: `eMAG`, `FAN Courier`, `Orange` cu `observed_channel=official_website` returneaza `provenance=match`, `official_match=true`, `max_effect=can_raise_safe`.
  - `/v1/verify/provenance` BTR fake FAN + card/CVV returneaza `provenance=mismatch`, `violated_never_asks=["card_number","cvv"]`, `max_effect=can_raise_dangerous_with_combo`.
  - `/v1/urechea/status`: `sources_configured=10`, `sources_with_rss=8`, `sources_enabled=10`, `campaign_count=6`.
  - `/v1/campaign/match`: seed FAN Courier tax/card returneaza `matched=true`, top match `CONV_COURIER_TAX_CARD`, `best_similarity=0.8375`.
  - `/v1/scan/orchestrated` cu `input_type=text` pentru `https://www.emag.ro/`: `SAFE`, score `10`, preview prezent, gate `positive_provenance_clean`.
  - `/v1/scan/orchestrated` cu `input_type=text` pentru `https://www.yoxo.ro/`: `SAFE`, score `10`, preview prezent.
  - `/v1/scan/orchestrated` cu `input_type=text` pentru FAN fake `fan-livrare.xyz`: `DANGEROUS`, score `90`, final URL nerezolvabil explicat.
- Backend full test: `INVOICE_CACHE_HMAC_KEY=testkey PRIVACY_SAFE_MODE=false pytest -q`
  - rezultat final dupa merge cu `origin/main`: `914 passed, 1 warning`
- Android JVM + build: `JAVA_HOME='/Applications/Android Studio.app/Contents/jbr/Contents/Home' ./gradlew testDebugUnitTest assembleDebug`
  - rezultat: `BUILD SUCCESSFUL`
- Android feature tests adaugate:
  - `RadarHotCacheTest`
  - `BtrSyncStoreTest`
  - `InboxProvenanceEngineTest`
  - `CircleGuardianContractTest`
  - `ActionPlanRequestTest`
  - `AudioSafetyPolicyTest`
- Android CallScreening targeted dupa audit local:
  - `JAVA_HOME='/Applications/Android Studio.app/Contents/jbr/Contents/Home' ./gradlew testDebugUnitTest --tests 'ro.sigurscan.app.RadarHotCacheTest'`
  - rezultat: `BUILD SUCCESSFUL`
  - `JAVA_HOME='/Applications/Android Studio.app/Contents/jbr/Contents/Home' ./gradlew assembleDebug`
  - rezultat: `BUILD SUCCESSFUL`
- Android full final dupa audit CallScreening si policy docs:
  - `git diff --check`: OK
  - `JAVA_HOME='/Applications/Android Studio.app/Contents/jbr/Contents/Home' ./gradlew testDebugUnitTest assembleDebug`
  - rezultat: `BUILD SUCCESSFUL`
  - observatii: doar warning-uri Kotlin existente/deprecated Compose icons/clipboard/lifecycle; fara test sau build failure
- Android PR-7 local inbox/BTR dupa conectare UI:
  - `JAVA_HOME='/Applications/Android Studio.app/Contents/jbr/Contents/Home' ./gradlew testDebugUnitTest --tests 'ro.sigurscan.app.InboxProvenanceEngineTest'`
  - rezultat: `BUILD SUCCESSFUL`
  - `JAVA_HOME='/Applications/Android Studio.app/Contents/jbr/Contents/Home' ./gradlew testDebugUnitTest assembleDebug`
  - rezultat: `BUILD SUCCESSFUL`
  - live BTR smoke cu `User-Agent: SigurScan/1.0 Android OkHttp` si cheia locala: `/v1/btr/sync` `200`, `count=17`, `version=btr-ro-2026.06.13`, `yoxo=true`
  - observatie: acelasi endpoint poate intoarce Cloudflare `1010` pentru clienti de terminal fara User-Agent-ul app-ului; nu este un 403 backend de API key.
- Verificari locale dupa conectarea raportului oficial si BTR YOXO:
  - Backend full final dupa merge cu `origin/main`: `914 passed, 1 warning`
  - Android full JVM: `BUILD SUCCESSFUL`
  - Android `assembleDebug`: `BUILD SUCCESSFUL`
  - Backend targeted BTR/Radar/PR-8: `73 passed, 1 warning`
  - Backend targeted BTR channel fix: `48 passed, 1 warning`
- Cloud Run live:
  - revision: `sigurscan-api-00047-q5m`
  - traffic: `100%`
  - image: `:3183000`
  - concurrency: `2`
- Domeniu oficial `https://api.sigurscan.com`:
  - `/health`: OK
  - `/v1/radar/hot-iocs`: OK
  - `/v1/btr/sync`: OK, `17` manifeste; `yoxo` prezent
  - `/v1/verify/provenance` YOXO: OK, `provenance=match`, `official_match=true`
  - `/v1/report`: OK, `2` canale (`DNSC`, `PNRISC / Poliția Română`)
  - `/v1/legal/action-plan`: OK, plan cu `4` pasi si `3` canale raportare pentru impacts reale
  - POST `/v1/scan/orchestrated` cu YOXO: `SAFE`, score `10`, preview `ready`
- Android emulator QA API 36 (`Medium_Phone_API_36.1`):
  - APK debug instalat cu succes pe `emulator-5554`.
  - Launch `ro.sigurscan.app/.MainActivity`: OK, fara crash `AndroidRuntime` pentru app.
  - Scan Android `https://www.yoxo.ro/`: UI `SIGUR`, verdict final, verificari complete, preview securizat cu imagine izolata, destinatie `yoxo.ro`.
  - Scan Android `https://fan-livrare.xyz/`: UI `PERICULOS`, verdict final, mesaj `Nu apasa linkul`, preview indisponibil cu motiv clar `Destinatia finala nu poate fi incarcata/verificata`.
  - Android PR-8: plan de actiune vizibil in rezultat, inclusiv `Raportare: DNSC, PNRISC / Poliția Română` si impacts reale selectabile.
  - Android PR-5 raport 1-tap: buton `Pregătește raport oficial` a populat cardul `Raport oficial pregătit` cu `DNSC`, `PNRISC / Poliția Română`, subiecte si mesaje precompletate.
  - Android PR-5 CallScreening:
    - `cmd role get-role-holders android.app.role.CALL_SCREENING`: `ro.sigurscan.app`
    - Telecom: `SCREENING_BOUND` si `SCREENING_COMPLETED` pentru `ro.sigurscan.app/.SigurScanCallScreeningService`
    - apel GSM simulat catre numar din hot-cache: decizie `WARN`, `SKIP_RINGING (Silent ringing requested)`
    - audit local salvat: `action=WARN`, `reason=reported_number_bucket_test`, `family=qa_call_screening`, fara numar brut
    - UI Radar afiseaza `Ultimul apel verificat local: warn · reported_number_bucket_test`
- Live scan YOXO:
  - verdict: `SAFE`
  - score: `10`
  - BTR: `manifest_id=yoxo`, `provenance=match`, `official_domain_match=true`
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
| PR-0..PR-4 | verdict gate, BTR, provenance, Urechea, CFX | Da, verificat targetat | Da pentru flow-ul principal de scanare | `114 passed` backend targetat; Android targetat `BUILD SUCCESSFUL`; `/v1/verify/provenance`, `/v1/urechea/status`, `/v1/campaign/match` live OK; scan live eMAG/YOXO SAFE si FAN fake DANGEROUS; emulator YOXO `SIGUR` si FAN fake `PERICULOS` |
| PR-5 | Radar hot-cache | Da | Da pe emulator API 36; necesita inca telefon real pentru carrier QA | `/v1/radar/hot-iocs` live OK; Android are cache offline, CallScreeningService, UI sync/rol si audit local fara numar brut; rol `CALL_SCREENING` activat pe emulator; apel GSM simulat a produs `WARN` si `SKIP_RINGING` |
| PR-5 | Raport 1-tap | Da | Da pe emulator | `/v1/report` live OK; Android are endpoint typed, buton in rezultat de risc si card cu canale DNSC/PNRISC; validat pe emulator prin FAN fake |
| PR-6 | Cercul out-of-band | Da | Da, UI Android dedicat in Radar | `/v1/circle/pair`, `/ping`, `/respond`, `/revoke` live OK; Android are pair/ping/respond/revoke fara continut brut |
| PR-6 persist | Supabase durable state | Da | N/A | `circle_links`, `verification_pings`, `guardian_second_opinion` live OK; read-fallback adaugat in `4ba2b9b` |
| PR-6 | Guardian second opinion | Da | Da, UI Android dedicat in Radar | `/v1/guardian/second-opinion` live OK; Android trimite rezumat redactat, full fara consimtamant downgrade la metadata_only |
| PR-7 | Inbox provenance contract / BTR sync | Da ca endpoint | Da ca foundation + UI local check | `/v1/btr/sync` live OK cu User-Agent Android; Android consuma endpointul, stocheaza local si are engine on-device pe semnale locale. UI Radar poate rula verificarea locala a ultimului scan. Nu citeste automat SMS-uri |
| PR-8 | Plan de actiune post-incident | Da | Da pentru flow de rezultat | `/v1/legal/action-plan` live OK; Android trimite impacts reale selectate si randeaza planul; planul apare in smoke emulator FAN fake |
| PR-8/9 integ | `action_plan` in orchestrator + audio reference | Partial backend | Partial pentru action_plan, nu audio | Orchestratorul trimite `action_plan`; Android il afiseaza. Nu exista audio reference/on-device audio |
| Extra | DNS reputation | Da | Da indirect prin scan response | `infra_dns` live OK; flag Cloud Run activ |
| PR-9/PR-10 | Android on-device: ASR/Vosk, banda inline, captura difuzor | Nu ca ASR complet | UI readiness + gated sigur | `AudioSafetyPolicy` + UI readiness blocheaza capture by default. Nu exista inca model ASR local si QA real-device |

## Gap-uri Care Nu Trebuie Numite Complete

1. Android CallScreening pentru PR-5 este validat pe emulator cu rol OS si apel GSM simulat, dar nu este inca validat pe telefon fizic cu apel de carrier.
   - Exista service in manifest.
   - Exista cerere `ROLE_CALL_SCREENING`.
   - Serviciul foloseste hot-cache offline, fara network in `onScreenCall`.
   - Serviciul salveaza audit local minim (`action`, `reason`, `family`, timestamp), fara numar brut.
   - Pe emulator API 36: `SCREENING_BOUND`, `SCREENING_COMPLETED`, `SKIP_RINGING` pentru numar raportat.
   - Lipseste test pe telefon real cu apel real/carrier.

2. Android BTR sync / Inbox PR-7 este foundation, nu citire automata SMS.
   - Backend-ul ofera `/v1/btr/sync`.
   - App-ul are client Retrofit, store local, engine on-device si buton UI pentru verificarea locala a ultimului scan pe semnale redactate/local extrase.
   - Manifestul Android nu cere `READ_SMS`; nu exista citire automata inbox/SMS.
   - Lipseste integrarea cu un flux real de inbox/SMS dupa decizia de produs si permisiuni.

3. Android PR-8 Action Plan este functional in ecranul de rezultat.
   - Backend-ul ofera `/v1/legal/action-plan`.
   - App-ul afiseaza `action_plan` primit in scan response.
   - App-ul permite declararea impacts reale si cere plan personalizat.

4. PR-9/PR-10 Android audio nu este implementat ca ASR, dar este blocat matur si vizibil in UI.
   - Nu exista Vosk/ASR/captura difuzor in productie.
   - `AudioSafetyPolicy` blocheaza capture fara feature flag, consimtamant, disclosure si model.
   - Manifestul Android nu cere `RECORD_AUDIO`; nu exista captura audio ascunsa.
   - Android are card readiness pentru consimtamant/disclosure/model/feature flag; nu cere permisiune microfon si nu porneste captura falsa.

5. Gate/UX pentru `urlz.fr/rZrw` merita decis explicit.
   - Tehnic scanarea se inchide corect, preview explica `final_url_unresolved`, DNS detecteaza `registrar_suspended`.
   - User-facing label este `UNVERIFIED/info`; daca produsul vrea fail-safe mai vizibil, regula trebuie ajustata la `SUSPECT` pentru shortener + final unresolved + DNS suspended.

6. BTR backend production are manifest YOXO dupa deploy `e4a0f82`.
   - Manifest `yoxo`: `yoxo.ro`, `buyback.yoxo.ro`, `reconditionate.yoxo.ro`, `newsroom.orange.ro`.
   - Flow-ul live YOXO cu `input_type=text` da `SAFE`, preview prezent, `provenance=match`, `official_domain_match=true`.

## Ce E Production-Grade Acum

- Backend scan pipeline nu mai ramane blocat la provider errors cunoscute.
- Malformed URL port nu mai crapa scanarea.
- Preview fallback queryless functioneaza pentru YOXO.
- DNS reputation este activ si verificat live.
- Supabase PR-6 tables exista live.
- Cercul PR-6 nu mai depinde strict de memoria unei singure instante Cloud Run.
- Android afiseaza planul de actiune preventiv PR-8 cand backend-ul il include in scan response.
- Android poate sincroniza Radar hot-cache si BTR de pe domeniul oficial.
- Android poate rula PR-7 BTR local check din UI pe ultimul scan, fara endpoint care primeste SMS sau text brut.
- Android poate cere pachet de raportare oficiala 1-tap pentru verdicturi de risc, fara continut brut.
- Android are CallScreeningService offline-first; nu face network in timpul apelului, este validat pe emulator cu rol OS activ si apel GSM simulat.
- Android are UI Cercul/Guardian in Radar: pair, ping, raspuns, revocare si second opinion metadata/redacted.
- Android poate cere plan post-incident personalizat pe impacts reale.
- Android audio capture este blocat by default prin policy testat si readiness UI.
