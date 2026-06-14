# MoatOS PR Status - 2026-06-14

Repo: `vaduvel/SigurScan`
Branch verificat: `feature/osint-intel-pipeline`
Main remote: `origin/main` este aliniat cu branch-ul verificat; commit-urile ulterioare deployului pot fi doar documentatie/status.
Production Cloud Run: `sigurscan-api-00050-lkc`
Production image: `europe-west1-docker.pkg.dev/project-20f225c0-d756-4cba-864/sigurscan/sigurscan-api:92c65de`

## Rezumat Brutal

- Backend PR-5..PR-8 este deployat live si verificat pe endpoint-uri reale.
- Supabase PR-6 tables sunt aplicate live si citibile prin REST.
- DNS reputation este activ live (`ENABLE_DNS_REPUTATION=true`) si apare in scanari reale ca `infra_dns`.
- PR-6 Cercul are acum write-through plus read-fallback din Supabase; testat live cu link creat inainte de deploy.
- Android PR-5 are acum hot-cache client, cache offline, CallScreeningService, UI pentru sync/rol OS, audit local fara numar brut si flow de raport oficial 1-tap (`/v1/report`). Flow-ul scan + raport oficial a fost validat pe emulator API 36; CallScreening a fost validat pe emulator cu rol OS activ si apel GSM simulat.
- Android PR-7 are acum BTR sync local, motor on-device de provenienta pe semnale locale si actiune UI pentru verificarea locala a ultimului scan impotriva BTR. Nu citeste automat SMS-uri.
- Android PR-8 afiseaza `action_plan` si are flow post-incident pentru impacts reale (`shared_card`, `paid_transfer` etc.).
- Android PR-9/PR-10 audio are acum engine local de verdict din semnale audio/vishing redactate, dar captura/ASR ramane blocata explicit prin policy pana exista model ASR on-device, consimtamant, disclosure si QA real-device.
- Play Integrity are wiring testat cap-coada pana la limita credențialelor: backend poate minta access token din service account JSON, emite nonce distribuit Upstash si il consuma atomic single-use, iar Android cere nonce-ul, foloseste Play Integrity SDK si ataseaza `X-Play-Integrity-Token` numai pe POST-urile protejate. Live ramane `off` pana la secret + build Play semnat + monitor pass rate.
- Productia ruleaza imaginea backend taguita `92c65de`.

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
- Backend full test dupa fail-safe `urlz.fr`: `INVOICE_CACHE_HMAC_KEY=testkey PRIVACY_SAFE_MODE=false /opt/homebrew/bin/python3 -m pytest backend -q`
  - rezultat: `915 passed, 1 warning`
- Backend full test dupa Play Integrity OAuth wiring: `INVOICE_CACHE_HMAC_KEY=testkey PRIVACY_SAFE_MODE=false /opt/homebrew/bin/python3 -m pytest backend -q`
  - rezultat: `916 passed, 1 warning`
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
- Android manifest/privacy guard dupa alinierea Data Safety:
  - `JAVA_HOME='/Applications/Android Studio.app/Contents/jbr/Contents/Home' ./gradlew testDebugUnitTest --tests 'ro.sigurscan.app.ShareIntentManifestTest'`
  - rezultat: `BUILD SUCCESSFUL`
  - testul blocheaza `READ_SMS`, `RECEIVE_SMS`, `SEND_SMS`, `READ_CALL_LOG`, `READ_CONTACTS`, `RECORD_AUDIO`, `POST_NOTIFICATIONS`
  - testul confirma `READ_PHONE_STATE` si `BIND_SCREENING_SERVICE` pentru CallScreening/Radar
- Android BuildConfig privacy/provider guard:
  - `JAVA_HOME='/Applications/Android Studio.app/Contents/jbr/Contents/Home' ./gradlew testDebugUnitTest --tests 'ro.sigurscan.app.AndroidBuildConfigPolicyTest'`
  - rezultat: `BUILD SUCCESSFUL`
  - testul confirma `SIGURSCAN_ENABLE_DIRECT_PROVIDER_KEYS=false` default, `URLSCAN_API_KEY=""`, `GOOGLE_WEB_RISK_API_KEY=""` in debug si release
  - testul confirma `SIGURSCAN_ENABLE_AUDIO_ASR=false` default si acelasi gate pentru debug/release
  - Android unit suite dupa guard: `JAVA_HOME='/Applications/Android Studio.app/Contents/jbr/Contents/Home' ./gradlew testDebugUnitTest` -> `BUILD SUCCESSFUL`
- PR-9/PR-10 audio/vishing contract:
  - Android TDD red: `AudioEvidenceEngineTest` a picat initial la compilare pentru `AudioEvidenceEngine` lipsa.
  - Android green: `JAVA_HOME='/Applications/Android Studio.app/Contents/jbr/Contents/Home' ./gradlew testDebugUnitTest --tests 'ro.sigurscan.app.AudioEvidenceEngineTest'`
  - rezultat: `BUILD SUCCESSFUL`
  - Android targeted audio/privacy gate: `./gradlew testDebugUnitTest --tests 'ro.sigurscan.app.AudioEvidenceEngineTest' --tests 'ro.sigurscan.app.AudioSafetyPolicyTest' --tests 'ro.sigurscan.app.ShareIntentManifestTest' --tests 'ro.sigurscan.app.AndroidBuildConfigPolicyTest'`
  - rezultat: `BUILD SUCCESSFUL`
  - Backend reference: `INVOICE_CACHE_HMAC_KEY=testkey PRIVACY_SAFE_MODE=false /opt/homebrew/bin/python3 -m pytest backend/test_audio_evidence.py -q`
  - rezultat: `9 passed, 1 warning`
  - Android full dupa engine audio: `JAVA_HOME='/Applications/Android Studio.app/Contents/jbr/Contents/Home' ./gradlew testDebugUnitTest assembleDebug`
  - rezultat: `BUILD SUCCESSFUL`
  - Android release dupa engine audio: `JAVA_HOME='/Applications/Android Studio.app/Contents/jbr/Contents/Home' ./gradlew assembleRelease bundleRelease`
  - rezultat: `BUILD SUCCESSFUL`
- Play Integrity / public auth hardening:
  - TDD red backend: `test_play_integrity_mints_access_token_from_service_account_json` a picat initial pentru `_mint_access_token` TODO.
  - Backend green: `INVOICE_CACHE_HMAC_KEY=testkey PRIVACY_SAFE_MODE=false /opt/homebrew/bin/python3 -m pytest backend/test_security_hardening.py -q`
  - rezultat: `19 passed, 1 warning`
  - TDD red Android: `ApiKeyInterceptorTest` a picat initial pentru lipsa parametrului `integrityTokenProvider` si a headerului `SIGURSCAN_PLAY_INTEGRITY_HEADER`.
  - Android green: `JAVA_HOME='/Applications/Android Studio.app/Contents/jbr/Contents/Home' ./gradlew testDebugUnitTest --tests 'ro.sigurscan.app.ApiKeyInterceptorTest' --tests 'ro.sigurscan.app.AndroidBuildConfigPolicyTest' --tests 'ro.sigurscan.app.ShareIntentManifestTest'`
  - rezultat: `BUILD SUCCESSFUL`
  - Android Play Integrity SDK readiness: `JAVA_HOME='/Applications/Android Studio.app/Contents/jbr/Contents/Home' ./gradlew testDebugUnitTest --tests 'ro.sigurscan.app.PlayIntegrityTokenProviderTest' --tests 'ro.sigurscan.app.AndroidBuildConfigPolicyTest.playIntegrityFeatureFlagDefaultsOff' --tests 'ro.sigurscan.app.ApiKeyInterceptorTest'`
  - rezultat: `BUILD SUCCESSFUL`
  - Android full dupa Play Integrity header plumbing: `JAVA_HOME='/Applications/Android Studio.app/Contents/jbr/Contents/Home' ./gradlew testDebugUnitTest assembleDebug`
  - rezultat: `BUILD SUCCESSFUL`
  - Android release dupa Play Integrity header plumbing: `JAVA_HOME='/Applications/Android Studio.app/Contents/jbr/Contents/Home' ./gradlew assembleRelease bundleRelease`
  - rezultat: `BUILD SUCCESSFUL`
  - Secret audit dupa Play Integrity SDK: `tools/audit_android_release_secrets.py` pe APK si AAB -> provider/admin/service secrets `embedded=false`; client API key warning neschimbat
- Android release artifacts:
  - `JAVA_HOME='/Applications/Android Studio.app/Contents/jbr/Contents/Home' ./gradlew testDebugUnitTest assembleDebug assembleRelease bundleRelease`
  - rezultat: `BUILD SUCCESSFUL`
  - `JAVA_HOME='/Applications/Android Studio.app/Contents/jbr/Contents/Home' ./gradlew lintDebug`
  - rezultat: `BUILD SUCCESSFUL`, report: `app/build/reports/lint-results-debug.html`
  - APK: `app/build/outputs/apk/release/app-release.apk` (`17,067,679` bytes)
  - AAB: `app/build/outputs/bundle/release/app-release.aab` (`16,399,395` bytes)
  - `apksigner verify --verbose --print-certs`: `Verifies`, v2 signing `true`, signer `CN=SigurScan`
  - `strings app-release.apk | rg "SUPABASE|URLSCAN_API_KEY|VIRUSTOTAL_API_KEY|GOOGLE_SAFE|GOOGLE_WEB_RISK_API_KEY|ro.nudaclick|com.example.myapplication|BEGIN PRIVATE KEY|AIza|eyJhbGci"`: no matches
  - `python3 tools/audit_android_release_secrets.py app/build/outputs/apk/release/app-release.apk`: provider/admin/service secrets `embedded=false`; client API key warning prezent
  - `python3 tools/audit_android_release_secrets.py app/build/outputs/bundle/release/app-release.aab`: provider/admin/service secrets `embedded=false`; client API key warning prezent
- Android emulator QA PR-7 local check (`Medium_Phone_API_36.1`):
  - APK debug curent instalat cu `./gradlew installDebug`
  - scan Android `YOXO Shop oferte pe https://www.yoxo.ro/`: UI `SIGUR`, `Verificări complete`, preview securizat, final domain `yoxo.ro`
  - tab Radar dupa sync: `17 manifeste oficiale • btr-ro-2026.06.13`, chip `local`
  - buton `Verifică local`: `Ultima verificare locală: safe · official_domain_match`
  - mesaj UI: `Verificare locală: canal oficial și fără cerere sensibilă.`
  - crash buffer: gol pentru sesiune
  - evidence screenshot: `docs/evidence/android_pr7_btr_local_check_2026-06-14.png`
- Verificari locale dupa conectarea raportului oficial si BTR YOXO:
  - Backend full final dupa merge cu `origin/main`: `914 passed, 1 warning`
  - Android full JVM: `BUILD SUCCESSFUL`
  - Android `assembleDebug`: `BUILD SUCCESSFUL`
  - Backend targeted BTR/Radar/PR-8: `73 passed, 1 warning`
  - Backend targeted BTR channel fix: `48 passed, 1 warning`
- Cloud Run live:
  - revision: `sigurscan-api-00050-lkc`
  - traffic: `100%`
  - image: `:92c65de`
  - concurrency: `2`
  - env check: `ENABLE_DNS_REPUTATION` prezent pe revizia live
  - health dupa Play Integrity wiring deploy: `HTTP 200`, `api_key_required=true`, `rate_limit_backend=upstash`, `admin_api_configured=true`, `play_integrity_mode=off`
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
  - PR-7 Radar/BTR dupa commit `4d0850e`: sync BTR OK in UI (`17` manifeste), local check pe ultimul scan YOXO OK (`safe / official_domain_match`).
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
  - verdict live dupa `b7a0f68`: `SUSPECT`, risk `medium`, score `55`
  - gate reason: `final_url_unresolved_dns_suspicious_shortener`

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
| PR-8/9 integ | `action_plan` in orchestrator + audio reference | Partial backend | Partial pentru action_plan; audio engine local fara captura | Orchestratorul trimite `action_plan`; Android il afiseaza. Backend are `audio_evidence` referinta; Android are `AudioEvidenceEngine` pentru semnale redactate. Nu exista captura/ASR audio |
| Extra | DNS reputation | Da | Da indirect prin scan response | `infra_dns` live OK; flag Cloud Run activ si pastrat in scriptul de deploy |
| PR-9/PR-10 | Android on-device: ASR/Vosk, banda inline, captura difuzor | Nu ca ASR complet | Engine local de verdict + UI readiness + gated sigur | `AudioEvidenceEngineTest`, `AudioSafetyPolicyTest`, `ShareIntentManifestTest`, `AndroidBuildConfigPolicyTest`; nu exista inca model ASR local, captura audio sau QA real-device |

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
   - Manifestul este acoperit de `ShareIntentManifestTest`, inclusiv interdictia `READ_SMS`/`RECEIVE_SMS`/`SEND_SMS`.
   - Lipseste integrarea cu un flux real de inbox/SMS dupa decizia de produs si permisiuni.

3. Android PR-8 Action Plan este functional in ecranul de rezultat.
   - Backend-ul ofera `/v1/legal/action-plan`.
   - App-ul afiseaza `action_plan` primit in scan response.
   - App-ul permite declararea impacts reale si cere plan personalizat.

4. PR-9/PR-10 Android audio nu este implementat ca ASR, dar este blocat matur si vizibil in UI.
   - Nu exista Vosk/ASR/captura difuzor in productie.
   - Exista `AudioEvidenceEngine` Android pentru reducerea locala a semnalelor audio/vishing deja redactate; nu stocheaza transcript brut si nu foloseste server audio.
   - `AudioSafetyPolicy` blocheaza capture fara feature flag, consimtamant, disclosure si model.
   - `AndroidBuildConfigPolicyTest` confirma ca `SIGURSCAN_ENABLE_AUDIO_ASR` ramane false-by-default pentru debug/release.
   - Manifestul Android nu cere `RECORD_AUDIO`; nu exista captura audio ascunsa.
   - Manifestul este acoperit de `ShareIntentManifestTest`, inclusiv interdictia `RECORD_AUDIO`.
   - Android are card readiness pentru consimtamant/disclosure/model/feature flag; nu cere permisiune microfon si nu porneste captura falsa.

5. Gate/UX pentru `urlz.fr/rZrw` este rezolvat live pentru cazul shortener + final URL nerezolvabil + DNS suspendat.
   - Scanarea se inchide corect, preview explica `final_url_unresolved`, DNS detecteaza `registrar_suspended`.
   - User-facing label live este `SUSPECT/medium`, cu gate reason `final_url_unresolved_dns_suspicious_shortener`.
   - Regula nu este generala pentru orice NXDOMAIN: testul `test_orchestrated_plain_unresolved_final_url_remains_final_unverified` pastreaza un domeniu simplu nerezolvabil ca `UNVERIFIED/info`.

6. Release public auth ramane limitat pana la Play Integrity/backend-issued token.
   - APK/AAB nu contin provider/admin/service secrets dupa auditul `tools/audit_android_release_secrets.py`.
   - APK/AAB contin cheia de client `SIGURSCAN_API_KEY`/`SIGURSCAN_RELEASE_API_KEY`, tratata doar ca bariera anti-abuz extractabila.
   - Backend-ul poate valida Play Integrity cand `PLAY_INTEGRITY_CREDENTIALS_JSON` si `PLAY_INTEGRITY_MODE=monitor/enforce` sunt configurate.
   - Android include `com.google.android.play:integrity`, cere nonce backend single-use si poate trimite `X-Play-Integrity-Token` prin `ApiKeyInterceptor`, dar token request ramane off-by-default prin `SIGURSCAN_ENABLE_PLAY_INTEGRITY=false`.
   - Backend-ul stocheaza doar hash nonce + hash binding client in Upstash, foloseste TTL/NX si consuma atomic cu `GETDEL`; verifica si timestamp-ul Google.
   - `/health` live arata in continuare `play_integrity_mode=off`; pentru release public larg nu trebuie numita autentificare reala pana la secret + build Play semnat + monitor pass rate.

7. BTR backend production are manifest YOXO dupa deploy `e4a0f82`.
   - Manifest `yoxo`: `yoxo.ro`, `buyback.yoxo.ro`, `reconditionate.yoxo.ro`, `newsroom.orange.ro`.
   - Flow-ul live YOXO cu `input_type=text` da `SAFE`, preview prezent, `provenance=match`, `official_domain_match=true`.

## Play Integrity Nonce Anti-Replay Live Proof

- Commit cod: `ebbebe7`; Cloud Run revision: `sigurscan-api-00051-q7d`; imagine: `sigurscan-api:ebbebe7`; trafic: 100%.
- Backend full: `923 passed, 1 warning`.
- Android: `testDebugUnitTest lintDebug assembleDebug assembleRelease bundleRelease` -> `BUILD SUCCESSFUL`.
- `/health` oficial: `play_integrity_mode=off`, `play_integrity_nonce_backend=upstash`, `rate_limit_backend=upstash`, `api_key_required=true`.
- Endpoint live nonce: doua raspunsuri HTTP 200, nonce-uri distincte de 43 caractere.
- Upstash live atomic proof: `issued` -> primul `GETDEL=consumed` -> al doilea `GETDEL=missing_or_replayed`.
- Regresie live YOXO pe contractul corect `input_type=text`: `SAFE/low`, scor 10, preview `ready`, screenshot prezent, rezultat final.
- Regresie live `urlz.fr/rZrw`: `SUSPECT/medium`, scor 55, preview `unavailable`, reason `final_url_unresolved`, rezultat final.
- Nu exista inca dovada token Google real: lipsesc service-account-ul autorizat Play Console, build-ul instalat din Google Play cu flag activ si perioada de monitorizare. Din acest motiv live ramane corect `off`.

## Fresh Live Matrix After Revision 00051

- Provider smoke report: `backend/eval/live_provider_smoke_2026_06_14_post_nonce.json` -> 5/5 passed.
- YOXO buyback, SMYK catalog, eMAG tracking si iDroid status: `SAFE`, finale, toate cu screenshot preview.
- Google Web Risk phishing test: `DANGEROUS`, final.
- Endpoint contract matrix PR-0..PR-8: 9/9 passed pe domeniul oficial.
- PR-0..PR-4: provenance YOXO cu canal contractual `official_website` -> `match`; Urechea are surse active; CFX produce fingerprint si match-uri.
- PR-5: Radar hot-cache are schema valida; raportul 1-tap produce canale DNSC + PNRISC precompletate.
- PR-6: pair -> ping -> respond -> revoke functioneaza; Guardian downgradeaza `full_with_consent` la `metadata_only` fara consimtamant.
- PR-7: BTR sync are versiune si 17/17 manifeste.
- PR-8: action plan produce pasi urgenti si raport cu minimum doua canale.

## Radar Community Report Contract Hardening

- QA MobAI pe emulator Android 16 a descoperit ca Radar live exporta `test123` si `abc123` drept hash-uri de numere; acestea erau date de test Supabase si nu puteau corespunde unui SHA-256 real.
- Auditul a gasit si nealinierea de contract: Android raporta hash-ul textului scanat, iar Radar il interpreta drept hash de telefon.
- Contractul nou pastreaza `target_type` pentru fiecare raport comunitar; numai `target_type=phone` poate intra in `number_reputation`.
- Android normalizeaza si hash-uieste exact numarul pentru rapoarte phone-only; URL/text raman rapoarte comunitare, dar nu pot influenta CallScreening.
- Backend respinge hash-uri non-SHA-256 si tipuri necunoscute.
- Supabase migration `20260614194000_harden_community_report_targets.sql` este aplicata live: datele invalide au fost sterse, `target_type` exista, iar constrangerile hash/target sunt active.

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
- Android are engine local PR-9/PR-10 pentru verdict din semnale audio/vishing redactate, iar audio capture este blocat by default prin policy testat si readiness UI.
