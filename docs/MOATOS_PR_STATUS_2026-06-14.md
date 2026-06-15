# MoatOS PR Status - 2026-06-14

Repo: `vaduvel/SigurScan`
Branch verificat: `feature/osint-intel-pipeline`
Main remote: `origin/main` este aliniat cu branch-ul verificat; commit-urile ulterioare deployului pot fi doar documentatie/status.
Production Cloud Run: `sigurscan-api-00053-d9d`
Production image: `europe-west1-docker.pkg.dev/project-20f225c0-d756-4cba-864/sigurscan/sigurscan-api:893832e`

## Addendum 2026-06-15 — post provider expansion + YOXO parser fix

- Branch verificat: `feature/osint-intel-pipeline`, commit live `e5a5e16`.
- Cloud Run live: `sigurscan-api-00057-mfc`, 100% trafic, image `europe-west1-docker.pkg.dev/project-20f225c0-d756-4cba-864/sigurscan/sigurscan-api:e5a5e16`.
- Env live confirma `ENABLE_DNS_REPUTATION=true`, `ENABLE_SCAM_BLOCKLIST_NRD=true`, `ENABLE_PHISHDESTROY=true`.
- Fix live: `input_type=url` cu mesaj complet extrage URL-urile reale din text in loc sa trateze tot mesajul ca un URL.
- Backend full: `INVOICE_CACHE_HMAC_KEY=testkey PRIVACY_SAFE_MODE=false /opt/homebrew/bin/python3 -m pytest backend -q` -> `942 passed, 1 warning`.
- Android JVM/debug: `JAVA_HOME='/Applications/Android Studio.app/Contents/jbr/Contents/Home' ./gradlew testDebugUnitTest assembleDebug` -> `BUILD SUCCESSFUL`.
- Android release: `JAVA_HOME='/Applications/Android Studio.app/Contents/jbr/Contents/Home' ./gradlew assembleRelease bundleRelease` -> `BUILD SUCCESSFUL`.
- Release APK: `app/build/outputs/apk/release/app-release.apk`, `63M`, SHA-256 `cb4da87feac38d404c1fd1401b4d084c4b20de9ca34335ea97a282731834d41d`.
- Release AAB: `app/build/outputs/bundle/release/app-release.aab`, `61M`, SHA-256 `99deae719f22b522ac03185e3cd360082ce1f25591fdd851ef728cc1a1834d2d`.
- Secret audit release APK/AAB: provider/admin/service secrets `embedded=false`; client API key warning ramane explicit pentru cheia client publica a aplicatiei.
- Live YOXO exact (`www.yoxo.ro` + `reconditionate.yoxo.ro` in acelasi mesaj): `SAFE`, score `10`, `provider-gate-official-clean`, preview `ready`, URL-uri rezolvate corect la domenii `yoxo.ro`.
- Live provider smoke post-deploy: `build/reports/live_provider_smoke_2026-06-15_after_e5a5e16.json` -> `5/5 passed`, `0 failed`.
- Live contract smoke post-deploy: `build/reports/live_contract_smoke_2026-06-15_after_e5a5e16.json` -> `10/10 passed`, `0 failed`.
- Edge/security post-deploy: `https://api.sigurscan.com/health` -> HTTP 200 cu `strict-transport-security`, `cache-control: no-store`, `x-sigurscan-edge: cloudflare`; `http://api.sigurscan.com/health` -> HTTP 308 spre HTTPS; scan fara API key -> HTTP 401.
- Cloud Run logs pe revizia `sigurscan-api-00057-mfc`, `severity>=ERROR`, `freshness=2h`: `[]`.
- Nokia C22 Android 13 vazut prin ADB (`3Z01Z3268Y392400836`). Instrumented tests reale pe device:
  `JAVA_HOME='/Applications/Android Studio.app/Contents/jbr/Contents/Home' ./gradlew connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=ro.sigurscan.app.AndroidUrlExtractorCompatibilityTest,ro.sigurscan.app.SharedIntentStreamExtractorInstrumentedTest,ro.sigurscan.app.SigurScanFixturePackDeviceE2ETest,ro.sigurscan.app.WhisperNativeRuntimeInstrumentedTest` -> `26/26`, `BUILD SUCCESSFUL`.
- Dupa instrumented tests, release APK a fost reinstalat pe Nokia C22: `versionCode=1`, `versionName=1.0`, `targetSdk=36`, `lastUpdateTime=2026-06-15 08:12:13`.
- Brutal de sincer: PR-0..PR-8 + provider expansion sunt live/testate pe backend, domeniu oficial si Android build/device. PR-9/PR-10 ramane corect numit Speaker Guard best-effort pentru apel pe difuzor, nu interceptare audio de apel si nu ASR real-time strict. CallScreening are in continuare nevoie de proba cu apel carrier real pentru semnatura finala “100% telefon fizic in conditii de retea”.

## Rezumat Brutal

- Backend PR-5..PR-8 este deployat live si verificat pe endpoint-uri reale.
- Supabase PR-6 tables sunt aplicate live si citibile prin REST.
- DNS reputation este activ live (`ENABLE_DNS_REPUTATION=true`) si apare in scanari reale ca `infra_dns`.
- PR-6 Cercul are acum write-through plus read-fallback din Supabase; testat live cu link creat inainte de deploy.
- Android PR-5 are acum hot-cache client, cache offline, CallScreeningService, UI pentru sync/rol OS, audit local fara numar brut si flow de raport oficial 1-tap (`/v1/report`). Flow-ul scan + raport oficial a fost validat pe emulator API 36; CallScreening a fost validat pe emulator cu rol OS activ si apel GSM simulat.
- Android PR-7 are acum BTR sync local, motor on-device de provenienta pe semnale locale si actiune UI pentru verificarea locala a ultimului scan impotriva BTR. Nu citeste automat SMS-uri.
- Android PR-8 afiseaza `action_plan` si are flow post-incident pentru impacts reale (`shared_card`, `paid_transfer` etc.).
- Android PR-9/PR-10 audio are engine local de verdict, Whisper.cpp on-device si Speaker Guard cu captura microfon user-started testata pe release APK pe Nokia C22. Transcriptul este redus local la semnale, rezultatul nu retine text brut, iar flow-ul ramane best-effort pentru apel pe difuzor, nu interceptare audio de apel si nu real-time strict.
- Play Integrity are wiring testat cap-coada pana la limita credențialelor: backend poate minta access token din service account JSON, emite nonce distribuit Upstash si il consuma atomic single-use, iar Android cere nonce-ul, foloseste Play Integrity SDK si ataseaza `X-Play-Integrity-Token` numai pe POST-urile protejate. Live ramane `off` pana la secret + build Play semnat + monitor pass rate.
- Productia ruleaza imaginea backend taguita `893832e`.

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
- Backend full test dupa hardening Radar/community reports: `INVOICE_CACHE_HMAC_KEY=testkey PRIVACY_SAFE_MODE=false /opt/homebrew/bin/python3 -m pytest backend -q`
  - rezultat: `926 passed, 1 warning`
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
  - Android transcript bridge: `AudioTranscriptEvidenceTest` valideaza cont sigur, AnyDesk, metoda accidentul, apel legitim si toate cele `34` fixture-uri realiste de call transcript.
  - Android full dupa transcript bridge: `./gradlew testDebugUnitTest lintDebug assembleDebug assembleRelease bundleRelease`
  - rezultat: `BUILD SUCCESSFUL`
  - MobAI/emulator: transcrierea `Politie + BNR + cont sigur` a produs `PERICULOS` in analiza locala audio; screenshot `docs/evidence/android_pr9_local_transcript_evidence_2026-06-14.png`.
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
  - APK: `app/build/outputs/apk/release/app-release.apk` (`63 MB`, include Whisper.cpp model/runtime)
  - AAB: `app/build/outputs/bundle/release/app-release.aab` (`61 MB`, include Whisper.cpp model/runtime)
  - APK SHA-256: `ccc15aeb3c6577a99259ded33cbb86f86668a8472aa16c8a6af9e92613b42e55`
  - AAB SHA-256: `e5b771bdea3a909d5640f63ccfcca6e1ba887f1f745a3ffe6aa7dfb37a8db7b2`
  - `aapt dump badging`: package `ro.sigurscan.app`, `versionCode=1`, `versionName=1.0`, `sdkVersion=24`, `targetSdkVersion=36`, label `SigurScan`
  - permisiuni release observate: `INTERNET`, `CAMERA`, `READ_PHONE_STATE`, `RECORD_AUDIO`, `ACCESS_NETWORK_STATE`; fara `READ_SMS`, `RECEIVE_SMS`, `SEND_SMS`, `READ_CALL_LOG`, `READ_CONTACTS`
  - `apksigner verify --verbose --print-certs`: `Verifies`, v2 signing `true`, signer `CN=SigurScan`
  - signer certificate SHA-256: `bfd7991c4a7d0c349ae41235f2c0b52d77962c5a9a6729aa3410c54840168b67`
  - `strings app-release.apk | rg "SUPABASE|URLSCAN_API_KEY|VIRUSTOTAL_API_KEY|GOOGLE_SAFE|GOOGLE_WEB_RISK_API_KEY|ro.nudaclick|com.example.myapplication|BEGIN PRIVATE KEY|AIza|eyJhbGci"`: no matches
  - `python3 tools/audit_android_release_secrets.py app/build/outputs/apk/release/app-release.apk`: provider/admin/service secrets `embedded=false`; client API key warning prezent
  - `python3 tools/audit_android_release_secrets.py app/build/outputs/bundle/release/app-release.aab`: provider/admin/service secrets `embedded=false`; client API key warning prezent
  - APK contine `libsigurscan_whisper.so` pentru `arm64-v8a`, `armeabi-v7a`, `x86`, `x86_64` si `assets/asr/whispercpp/ggml-model.bin`; model manifest: `engine=whisper.cpp`, `model_id=ggml-tiny-q8_0`, `language=ro`, `sample_rate_hz=16000`
- Android Speaker Guard release QA pe Nokia C22:
  - evidence doc: `docs/SPEAKER_GUARD_RELEASE_QA_2026-06-14.md`
  - release APK instalat curat; `versionName=1.0`, `versionCode=1`, target SDK 36, fara debug flag
  - deep link `sigurscan://speaker-guard` deschide Radar/Speaker Guard fara sa incarce Whisper/native la startup
  - dupa consimtamant explicit si Start: UI `ascultă`, `AudioFlinger` confirma microfon activ `AUDIO_DEVICE_IN_BUILTIN_MIC`, sample rate `16000`, client `ro.sigurscan.app`
  - sesiunea a procesat chunk-uri reale: observat `Fragmente analizate: 6`, `pierdute: 0`, `audio brut salvat: nu`
  - dupa Stop: UI `oprit`, `AudioFlinger` revine la standby si input device `AUDIO_DEVICE_NONE`; logcat arata `AudioRecord stop/destructor/Release`
  - logul `CALL_AUDIO_INTERCEPTION denied` este asteptat: Speaker Guard nu intercepteaza audio de apel, ci asculta microfonul numai dupa ce userul pune apelul pe difuzor si apasa Start
- Android full dupa hardening Radar/community reports:
  - `./gradlew testDebugUnitTest lintDebug assembleDebug assembleRelease bundleRelease`
  - rezultat: `BUILD SUCCESSFUL`
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
- Verificari post-deploy `893832e`:
  - Backend full: `INVOICE_CACHE_HMAC_KEY=testkey PRIVACY_SAFE_MODE=false /opt/homebrew/bin/python3 -m pytest -q` -> `930 passed, 1 warning`
  - Android JVM: `JAVA_HOME='/Applications/Android Studio.app/Contents/jbr/Contents/Home' ./gradlew testDebugUnitTest` -> `BUILD SUCCESSFUL`
- Cloud Run live:
  - revision: `sigurscan-api-00053-d9d`
  - traffic: `100%`
  - image: `:893832e`
  - concurrency: `2`
  - env check: `ENABLE_DNS_REPUTATION` prezent pe revizia live
  - health dupa Play Integrity wiring deploy: `HTTP 200`, `api_key_required=true`, `rate_limit_backend=upstash`, `admin_api_configured=true`, `play_integrity_mode=off`
- Domeniu oficial `https://api.sigurscan.com`:
  - `/health`: OK
  - `/v1/radar/hot-iocs`: OK
  - `/v1/btr/sync`: OK, `17` manifeste; `yoxo` prezent
  - `/v1/verify/provenance` YOXO: OK, `provenance=match`, `official_match=true`; canalul alias `web` este normalizat la `official_website` dupa deploy `893832e`
  - `/v1/report`: OK, `2` canale (`DNSC`, `PNRISC / Poliția Română`)
  - `/v1/legal/action-plan`: OK, plan cu `4` pasi si `3` canale raportare pentru impacts reale
  - POST `/v1/scan/orchestrated` cu YOXO: `SAFE`, score `10`, preview `ready`
- Post-deploy live contract smoke dupa `893832e`:
  - report: `build/reports/live_contract_smoke_2026-06-14_after_provenance_alias_deploy.json`
  - rezultat: `12/12 passed`, `0 failed`
  - acopera: `/health`, `/v1/radar/hot-iocs`, `/v1/btr/sync` full/no-op, `/v1/verify/provenance`, `/v1/circle/pair`, `/v1/circle/ping`, `/v1/circle/respond`, `/v1/circle/revoke`, `/v1/guardian/second-opinion`, `/v1/legal/action-plan`, `/v1/report`
- Post-deploy live provider smoke dupa `893832e`:
  - report: `build/reports/live_provider_smoke_2026-06-14_full_after_provenance_alias_deploy.json`
  - rezultat: `5/5 passed`, `0 failed`
  - YOXO buyback: `SAFE`, final `https://buyback.yoxo.ro/?r=1`, preview screenshot/report prezente, provideri: `google_web_risk`, `urlhaus`, `phishing_database`, `urlscan`, `infra_dns`, `infra_domain_age`, `infra_ssl`, `ai_offer_web_check`
  - SMYK catalog: `SAFE`, final `https://smyk.ro/catalogul-ziua-copilului`, preview screenshot/report prezente, provideri: `google_web_risk`, `urlhaus`, `phishing_database`, `urlscan`, `infra_dns`, `infra_domain_age`, `ai_offer_web_check`
  - eMAG tracking official: `SAFE`, final `https://auth.emag.ro/user/login`, preview screenshot/report prezente, provideri: `google_web_risk`, `urlhaus`, `phishing_database`, `urlscan`, `infra_dns`, `infra_domain_age`, `ai_offer_web_check`
  - Google Web Risk phishing test: `DANGEROUS`, final, provideri: `google_web_risk`, `urlhaus`, `phishing_database`, `infra_dns`, `ai_offer_web_check`
  - iDroid status: `SAFE`, final `https://idroid.ro/verifica-status/`, preview screenshot/report prezente, provideri: `google_web_risk`, `urlhaus`, `phishing_database`, `urlscan`, `infra_dns`, `infra_domain_age`, `ai_offer_web_check`
- Post-deploy edge/security smoke dupa `893832e`:
  - report: `build/reports/live_edge_security_smoke_2026-06-14_after_893832e.json`
  - rezultat: `4/4 passed`, `0 failed`
  - `/health`: `HTTP 200`, `status=ok`, `strict-transport-security=max-age=31536000; includeSubDomains`, `x-sigurscan-edge=cloudflare`, `cache-control=no-store`
  - `http://api.sigurscan.com/health`: `HTTP 308` catre HTTPS
  - POST `/v1/scan/orchestrated` fara API key: `HTTP 401`, `Missing or invalid API key.`, `cache-control=no-store`
  - GET `/v1/btr/sync` fara API key: `HTTP 401`, `Missing or invalid API key.`, `cache-control=no-store`
- Cloud Run post-deploy observability:
  - `gcloud logging read` pe `sigurscan-api-00053-d9d`, `severity>=ERROR`, `freshness=2h`: `[]`
  - Cloud Build `fa67cbf2-7c61-460b-a706-28b36080cb10`: `SUCCESS`
  - Artifact digest: `sha256:b52ac50e70760daad92271709a422e3b8f8851f6470ed12b0e1d211ffa957f4f`
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
| PR-8/9 integ | `action_plan` in orchestrator + audio reference | Partial backend | Action plan functional; analiza locala a transcrierii functionala | Orchestratorul trimite `action_plan`; Android il afiseaza. Android reduce local transcrierea curenta la semnale si verdict, fara text brut in rezultat. Nu exista captura/ASR audio |
| Extra | DNS reputation | Da | Da indirect prin scan response | `infra_dns` live OK; flag Cloud Run activ si pastrat in scriptul de deploy |
| PR-9/PR-10 | Android on-device: Whisper.cpp ASR, banda inline, captura difuzor | Partial: engine local + release Speaker Guard best-effort | Analiza transcript local + engine verdict + UI readiness + Start/Stop Speaker Guard + Whisper native/model gated sigur | `AudioTranscriptEvidenceTest` acopera 34/34 fixture-uri realiste + zgomot ASR real; `WhisperCppAsrEngineTest` acopera contractul adapterului fara audio raw retinut; `AudioSafetyPolicyTest` acopera manifestul Whisper si permisiunea microfon; instrumented test pe Nokia C22 confirma runtime native, model checksum/load si transcriere fixture RO. Release APK pe Nokia C22 confirma deep link, Start/Stop, microfon activ 16 kHz, chunk-uri analizate si eliberare microfon dupa Stop. Ramane best-effort pentru apel pe difuzor, nu interceptare call audio si nu real-time strict |

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

4. PR-9/PR-10 Android audio are native/model functional pentru batch benchmark si Speaker Guard best-effort, dar nu este inca ASR production real-time strict.
   - Exista Whisper.cpp `v1.8.6` ca submodule, build NDK/CMake si `libsigurscan_whisper.so` ambalat in APK.
   - Exista model multilingual `ggml-tiny-q8_0` in `assets/asr/whispercpp/`, cu manifest SHA-256.
   - Pe Nokia C22, testul instrumentat confirma load runtime, load model si transcriere fixture romana, dar timpul optimizat este ~12.9s pentru un WAV scurt. Asta este acceptabil pentru batch scurt, dar prea lent pentru banda live/call real-time.
   - `tiny-q5_1` a fost mai lent (~16.4s), iar `tiny` full a fost mai mare/lent si nu este selectat.
   - Exista `SpeakerGuardSession` pentru user-started microphone capture cand apelul este pus pe difuzor: PCM mono 16 kHz, chunk-uri de 6s, queue de 1 chunk, drop la backpressure, Whisper local, evidence local, fara audio brut retinut in state.
   - Release APK pe Nokia C22 confirma ca Start porneste microfonul, chunk-urile sunt analizate, Stop elibereaza imediat `AudioRecord`, iar input device revine la `AUDIO_DEVICE_NONE`.
   - Vosk nu mai este calea aleasa pentru Android; inlocuitorul selectat este Whisper.cpp.
   - Exista `AudioEvidenceEngine` + `AudioTranscriptEvidence` pentru reducerea locala a transcrierii la semnale audio/vishing; rezultatul nu stocheaza transcript brut si nu foloseste server audio.
   - Exista `WhisperCppAsrEngine` cu runtime native injectabil, contract PCM mono 16 kHz romana si fallback explicit `whisper_native_unavailable` cand JNI-ul lipseste.
   - UI poate analiza local transcrierea curenta si afisa verdictul audio chiar daca ASR/captura ramane blocata.
   - Readiness-ul modelului necesita pachetul `assets/asr/whispercpp/` cu `model-manifest.json` si `ggml-model.bin`; manifestul trebuie sa declare `engine=whisper.cpp`, `language=ro`, `sample_rate_hz=16000` si checksum SHA-256 valid.
   - Readiness-ul de captura necesita si runtime-ul native `sigurscan_whisper`; un model valid fara JNI ramane blocat cu `asr_native_runtime_missing`.
   - Lista oficiala Vosk verificata pe 2026-06-14 nu ofera model romanesc.
   - `AudioSafetyPolicy` blocheaza capture fara feature flag, consimtamant, disclosure, model, runtime native si permisiune microfon.
   - `AndroidBuildConfigPolicyTest` confirma ca `SIGURSCAN_ENABLE_AUDIO_ASR` ramane false-by-default pentru debug/release.
   - Manifestul Android cere `RECORD_AUDIO` pentru Speaker Guard explicit pornit de user; nu cere SMS/call log/contacts si nu exista captura audio ascunsa.
   - Manifestul este acoperit de `ShareIntentManifestTest`, inclusiv permisiunea microfon revizuita pentru Speaker Guard.
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

7. BTR backend production are manifest YOXO dupa deploy `e4a0f82`, iar aliasul API `web` este acceptat dupa deploy `893832e`.
   - Manifest `yoxo`: `yoxo.ro`, `buyback.yoxo.ro`, `reconditionate.yoxo.ro`, `newsroom.orange.ro`.
   - Flow-ul live YOXO cu `input_type=text` da `SAFE`, preview prezent, `provenance=match`, `official_domain_match=true`.
   - `/v1/verify/provenance` cu `observed_channel=web`, `claimed_brand=YOXO`, `observed_domain=yoxo.ro` intoarce live `provenance=match`, `official_match=true`.

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

## Fresh Live Matrix After Revision 00053

- Provider smoke report: `build/reports/live_provider_smoke_2026-06-14_full_after_provenance_alias_deploy.json` -> 5/5 passed.
- YOXO buyback, SMYK catalog, eMAG tracking si iDroid status: `SAFE`, finale, toate cu screenshot preview si urlscan report.
- Google Web Risk phishing test: `DANGEROUS`, final.
- Endpoint contract matrix PR-0..PR-8: `build/reports/live_contract_smoke_2026-06-14_after_provenance_alias_deploy.json` -> 12/12 passed pe domeniul oficial.
- Edge/security smoke: `build/reports/live_edge_security_smoke_2026-06-14_after_893832e.json` -> 4/4 passed; fara erori Cloud Run `severity>=ERROR` pe revizia `00053-d9d` in fereastra verificata.
- PR-0..PR-4: provenance YOXO cu canal contractual `official_website` -> `match`; Urechea are surse active; CFX produce fingerprint si match-uri.
- PR-0..PR-4: provenance YOXO cu alias live `web` -> `match` dupa normalizarea din `893832e`.
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
- Live pe `api.sigurscan.com`: hash invalid respins cu HTTP 400; raport URL acceptat dar absent din Radar; raport phone sintetic prezent temporar in Radar.
- MobAI/emulator: dupa sync, apelul GSM sintetic a produs `WARN`, `SCREENING_COMPLETED` si `SKIP_RINGING`; UI a afisat auditul local. Datele QA au fost apoi sterse, iar live + Android au revenit la `0 numere raportate`.
- Live provider smoke dupa deploy `893832e`: `5/5 passed`, `0 failed`.
- Evidence: `docs/evidence/android_radar_phone_contract_warn_2026-06-14.png`.

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
- Android Speaker Guard release APK este testat pe Nokia C22 pentru deep link, consimtamant, Start/Stop, chunk-uri analizate si eliberare microfon dupa Stop; ramane explicit best-effort pentru apel pe difuzor, nu interceptare call audio.
- Backend BTR/provenance accepta aliasul `web` pentru website oficial, iar live `/v1/verify/provenance` YOXO intoarce `match/official_match=true` pe `api.sigurscan.com`.
