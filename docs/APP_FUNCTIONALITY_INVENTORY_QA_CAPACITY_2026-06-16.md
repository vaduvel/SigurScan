# SigurScan - inventar functionalitati, QA si capacitate

Data: 2026-06-16  
Repo: `/Users/vaduvageorge/AndroidStudioProjects/SigurScan`  
Branch observat: `codex/romania-research-2026-06-16`

## Update live QA - 2026-06-16 15:29:39 EEST

- `A4 Scanare cod QR live`: verificat pe Nokia C22 release build. Bug real identificat si reparat. Cauza a fost R8 care taia constructorii registrarilor ML Kit folositi prin reflection (`CommonComponentRegistrar`, `BarcodeRegistrar`, `TextRegistrar`, `VisionCommonRegistrar`). Dupa fixul din `app/proguard-rules.pro`, ecranul live QR se deschide corect, fara fallback si fara crash.
- `A11 Share text/html catre SigurScan` plus `A1 Scanare text/link`: verificat pe Nokia C22 release build cu `https://www.yoxo.ro/` trimis prin `ACTION_SEND`. Bug real identificat si reparat. Cauza a fost R8 full mode pe Retrofit suspend interfaces, care producea `ClassCastException: Class cannot be cast to ParameterizedType` la `startOrchestratedScan`. Dupa adaugarea regulilor oficiale Retrofit in `app/proguard-rules.pro`, flow-ul revine la verdictul corect `SIGUR`, `Verdict final`, `Verificari complete` si preview securizat cu captura.
- `A6/A7 Scanare factura`: verificata intrarea de produs pe Nokia C22 release build. Tile unic `Scanează Factură` deschide chooser-ul corect cu `Fă poză` si `Încarcă imagine/PDF`. `Fă poză` intra in camera nativa Nokia (`com.hmdglobal.app.cameralite/.CaptureActivity`), iar `Încarcă imagine/PDF` deschide picker-ul de documente (`com.google.android.go.documentsui/...PickActivity`).
- Ambele fixuri sunt reparatii de release real-device, nu doar de test local.

## Update live QA - 2026-06-16 16:12:00 EEST

- `A7 + A8 Scanare factura din fisier + XML optional`: verificat cap-coada pe Nokia C22 release build cu `mgh_invoice.png` + `efactura_match.xml`. Rezultat: `Sigur`, emitent `MARKETING GROWTH HUB S.R.L.`, CUI `45758405`, IBAN detectat `RO42INGB0000999912242622`, banca `ING`, plus mesajul SANB/guidance pentru confirmarea numelui beneficiarului in aplicatia bancii. Scannerul nu a mai ratat CUI-ul in acest flow.
- `A1 Scanare text/link manual`: verificat din nou pe Nokia C22 release build cu `https://www.yoxo.ro/`. Rezultat final `SIGUR`, `Verdict final`, `Verificări complete`, preview securizat prezent. Timp observat pe device-ul real, scan cold: aproximativ 19s pana la starea intermediara cu preview pending si aproximativ 34s pana la verdict final complet. Functional corect, dar inca lent.
- `A26 Istoric scanari`: verificat pe Nokia C22 release build. Dupa scanarea manuala YOXO, intrarea apare in `Mai mult > Istoric Scanări` cu timestamp si clasificare `Sigur`. Concluzie: istoricul functioneaza pentru scanarile text/link finale; faptul ca factura nu aparea singura in istoric nu este dovada de bug pentru acest modul.
- `A27/A29 Radar hot cache apeluri`: verificat pe Nokia C22 release build. `Sincronizează` muta cardul din `Cache apeluri indisponibil` in `0 campanii, 0 numere raportate` si status `offline ready`.
- `A31 BTR on-device`: verificat pe Nokia C22 release build. `Sincronizează` coboara `30 manifeste oficiale • btr-ro-2026.06.16` si marcheaza status `local`. `Verifică local` fara un mesaj/link activ raspunde corect cu `Scanează sau partajează întâi un mesaj/link.`
- `A39 Contrast/accessibility control`: verificat pe Nokia C22 release build. `Contrast Checker` nu mai este expus in `Mai mult`, conform intentiei de a-l lasa doar pentru debug.
- `A3 Scanare email/PDF - EML`: bug real identificat si reparat in release. Fluxul `Email / PDF -> emag_legit_newsletter.eml` ramanea blocat pe `Analizăm fișierul email...` deoarece ramura HTML/EML tinea `loading=true` si apoi chema `onScanClick()`, iar `onScanClick()` refuza sa porneasca atunci cand `loading` era deja activ. Dupa fix, acelasi `.eml` intra corect in pipeline, extrage destinatia `https://auth.emag.ro/user/login`, apoi finalizeaza cu verdict `SIGUR` si preview securizat.
- `A4 modalitate de navigare`: din ecranul fullscreen `Scanează codul QR`, schimbarea de tab prin bottom-nav nu este un flow util; trebuie mai intai `Închide`, apoi navigare. Este comportament de modal fullscreen, nu crash.

## Update live QA - 2026-06-16 16:29:46 EEST

- `A3 Scanare email/PDF - PDF`: verificat pe Nokia C22 release build cu `bt_ghid_legitim.pdf`. Importul documentului porneste corect din `Email / PDF`, extrage destinatia `https://www.bancatransilvania.ro/siguranta-online`, inchide scanarea cu `SIGUR` si ajunge la `Verificări complete`. Preview-ul securizat se genereaza corect, dar mai lent decat verdictul final pe acest device.
- `Bottom navigation / safe area`: bug real identificat si reparat pe Nokia C22. Bara de jos nu rezerva inset-ul pentru `navigationBar`, iar slotul central `Scanează` era clickabil doar pe cercul albastru, nu si pe eticheta. Pe telefonul cu gesture navigation, asta putea arunca userul in launcher cand atingea jos in zona tabului. Fix aplicat: bara de jos rezerva explicit `WindowInsets.navigationBars`, iar tot slotul central `Scanează` este acum tappable. Re-verificat live: `Radar -> Scanează` revine in app, nu mai iese in launcher.
- `A30 Call Screening / role`: verificat la nivel OS pe Nokia C22. `adb shell cmd role get-role-holders android.app.role.CALL_SCREENING` intoarce `ro.sigurscan.app`, iar manifestul expune corect `.SigurScanCallScreeningService` cu `android.permission.BIND_SCREENING_SERVICE`. Concluzie: rolul este deja acordat; ce ramane neprobat in acest run este doar un apel real cap-coada prin serviciul de screening.
- `A2 Scanare screenshot OCR`: testat din nou prin Photos Picker -> Albume -> `Descărcări`. Picker-ul ramane greu de facut determinist deoarece afiseaza thumbnail-uri si timestamp-uri, nu numele reale ale fixture-urilor. Selectarea imaginii vizibile din albumul `Descărcări` a pornit fluxul de scanare, dar cu status partial `Nu am găsit un link complet pentru scanare`; concluzia ramane ca inputul ales nu poate fi atribuit sigur fixture-ului `ocr_emag_oficial.png` fara un selector mai stabil.

## Open issues / gaps ramase dupa QA live

- `A5 Scanare QR din imagine`: functionalitatea exista in cod (`onQrPicked`), dar in release UI este expusa doar cand camera live nu este disponibila sau nu exista permisiune. Pe Nokia C22, unde scanarea live functioneaza, fallback-ul `Scanează din poză` nu este vizibil. Inventarul trebuie tratat ca `conditional UI`, nu `always exposed`.
- `A2 Scanare screenshot OCR`: testarea prin Photos Picker pe Nokia este inca neconcludenta pentru fixture-uri nominale, deoarece albumul `Descărcări` afiseaza doar thumbnail-uri/timestamps, nu nume de fișier. Selectarea imaginii vizibile din `Descărcări` a dus la un flow de scanare partial cu `Nu am găsit un link complet pentru scanare`, dar nu pot afirma inca daca a fost fixture-ul corect sau un bug OCR real fara o selectie mai determinista.
- `A30 Call Screening / Activează`: rolul Android de screening este deja acordat pe Nokia, dar nu am executat inca un apel necunoscut de test ca sa verific raspunsul serviciului cap-coada.

## Verdict onest, inainte de testarea finala

Aplicatia are mult mai multe functionalitati decat se vad in primul ecran. Inventarul de mai jos este facut din cod, nu din UI. UI-ul este tratat ca dovada de expunere, nu ca sursa unica de adevar.

Nu pot spune inca "1000 useri production ready" doar din citirea codului. Exista fundatie serioasa: backend async cu `scan_jobs`, cache-uri Supabase, rate limiting, API key, Play Integrity optional, fast preview cache, provider gating, worker de pre-capture si multe teste. Dar capacitatea reala pentru 1000 useri depinde de Cloud Run, Supabase, quota providerilor externi, preview/urlscan/OCR si mixul de trafic. Asta trebuie dovedit prin load test staged, nu presupus.

## Metodologie

- Am inspectat cod Android: Manifest, MainActivity, ViewModel, API client, share-intents, call screening, audio, invoice, knowledge, radar.
- Am inspectat backend: rute FastAPI, middleware, provider config, Supabase store, servicii de reputatie, facturi, radar, Cercul/Guardian, legal/reporting.
- Am inspectat date/knowledge: assets Android, backend data packs, payment registry, scam atlas, e2e fixtures.
- Am inspectat infra: Supabase migrations, Cloudflare proxy worker, pre-capture worker.
- Testarea cap-coada trebuie facuta dupa acest inventar, pe trei niveluri: unit/integration, live backend, telefon real.

## Inventar Android - functionalitati expuse sau prezente

| ID | Functionalitate | Suprafata utilizator | Cod principal | Backend/API | Status produs |
|---|---|---|---|---|---|
| A1 | Scanare text/link manual | Tab Scan, input + buton "Scaneaza acum" | `MainActivity.kt`, `ScannerViewModel.onScanClick` | `/v1/scan/orchestrated` | Expus in UI, flow principal |
| A2 | Scanare screenshot/imagine OCR | Tile "Incarca Screenshot" | `onImagePicked`, ML Kit OCR | `/v1/extract/image`, apoi orchestrated scan | Expus in UI |
| A3 | Scanare email/PDF/fisier | Tile "Email / PDF" | `onFilePicked`, `EmailMessageParser`, `PdfLinkExtractor`, `FileImportClassifier` | `/v1/extract/email`, `/v1/extract/pdf`, orchestrated scan | Expus in UI; EML verificat live pe Nokia |
| A4 | Scanare cod QR live | Tile "Scaneaza Cod QR" | `QrScannerScreen`, CameraX, ML Kit barcode | Orchestrated scan dupa URL extras | Expus in UI |
| A5 | Scanare QR din imagine | fallback conditionat din ecranul QR | `onQrPicked` | Orchestrated scan | Prezent in cod; expus doar cand live QR indisponibil / fara permisiune |
| A6 | Scanare factura din poza | Tile unic "Scaneaza Factura" -> "Fa poza" | `createInvoiceCaptureUri`, camera permission, `scanInvoiceFromDocument` | `/v1/scan/invoice` | Expus in UI |
| A7 | Scanare factura din fisier/PDF | Tile unic "Scaneaza Factura" -> "Incarca imagine/PDF" | `scanInvoiceFromDocument` | `/v1/scan/invoice` | Expus in UI; verificat live pe Nokia |
| A8 | XML e-Factura optional | Dialog dupa alegerea facturii | `OfficialInvoiceXmlChooserDialog` | `/v1/scan/invoice` cu `official_xml` | Expus in UI; verificat live pe Nokia |
| A9 | Scanare oferta/document oferta | Card "Verifica o oferta" | `scanOfferFromDocument`, `confirmOfferAndScan` | Extractie + orchestrated scan | Expus in UI |
| A10 | Confirmare campuri oferta | Card confirmare in app | `OfferConfirmationCard` | Orchestrated scan cu context oferta | Expus in UI |
| A11 | Share text/html catre SigurScan | Android share sheet | `SharedIntentIntakePlanner`, `SharedTextPayloadResolver` | Orchestrated scan | Expus prin intent filters |
| A12 | ACTION_PROCESS_TEXT | Select text -> process/share | `buildSharedIntentIntakePlan` | Orchestrated scan | Expus prin intent filter |
| A13 | Share fisiere catre SigurScan | Android share sheet | `collectSharedStreamUris`, `stageSharedFile` | Extractie/scan in functie de tip | Expus prin intent filters |
| A14 | Share audio catre SigurScan | Android share sheet audio/* | `FileImportClassifier.AUDIO`, `publishAudioShareRequiresTranscript` | Doar transcript/text daca ASR indisponibil | Prezent, dar ASR nu e garantat live |
| A15 | Multiple share files | ACTION_SEND_MULTIPLE | planner stage multiple | Partial, necesita alegere/scan pe rand | Prezent, partial user-flow |
| A16 | Deep link scan | `sigurscan://scan` | `resolveDeepLinkScanText` | Orchestrated scan | Prezent |
| A17 | Deep link Radar | `sigurscan://radar` | `resolveDeepLinkDestination` | UI Radar | Prezent |
| A18 | Deep link Speaker Guard | `sigurscan://speaker-guard` | `resolveDeepLinkDestination` | Audio UI daca flag activ | Prezent, flag-gated |
| A19 | Rezultat/verdict | Card rezultat cu SIGUR/SUSPECT/PERICULOS | `ResultCard`, `GateResultPresentation` | Orchestrated result | Expus in UI |
| A20 | Preview securizat | Card preview final URL/screenshot | `EvidenceSection`, `orchestratedPreviewStillPending` | urlscan/fast preview/screenshot proxy | Expus, dependent de backend/worker/provider |
| A21 | Detalii tehnice provider | Toggle in rezultat | `ThreatIntelSection`, `RedirectChainSection`, pillars | External intel summary | Expus in UI |
| A22 | Feedback corect/fals pozitiv | Butoane rezultat | `sendFeedback` | `/v1/feedback` | Expus in UI |
| A23 | Raport comunitar | Buton pentru periculos | `sendCommunityReport` | `/v1/community/report` | Expus conditionat |
| A24 | Raport oficial 1-tap | Buton rezultat | `requestOfficialReportPackage` | `/v1/report` | Expus in UI |
| A25 | Plan actiune post-incident | Selectie impact + actiune | `requestPostIncidentActionPlan` | `/v1/legal/action-plan` | Expus in UI |
| A26 | Istoric scanari | In More + component dedicat | `HistoryTab`, local SharedPreferences | local | Prezent; verificat live dupa scan text/link; nu are tab separat in bottom nav |
| A27 | Radar campanii active | Tab Radar | `loadCampaigns` | `/v1/community/campaigns` | Expus in UI; sync live verificat pe Nokia |
| A28 | Harta Radar RO | Tab Radar, WebView/static fallback | `RadarMapCard` | Campanii cu lat/lon | Expus daca exista date geo |
| A29 | Hot-cache Radar pe device | Tab Radar sync | `syncRadarHotCache`, `RadarHotCacheStore` | `/v1/radar/hot-iocs` | Expus in UI; sync live verificat pe Nokia |
| A30 | Call Screening / caller reputation | Android role + service | `SigurScanCallScreeningService`, `RadarCallDecider` | Hot-cache local | Prezent; nu asculta apeluri, nu popup custom |
| A31 | BTR on-device | Card Radar | `syncBtrManifests`, `InboxProvenanceEngine` | `/v1/btr/sync` | Expus in UI; sync live verificat pe Nokia |
| A32 | Cercul de siguranta | Card Radar | `createCirclePair`, `createCirclePing`, `resolveCirclePing`, `revokeCirclePair` | `/v1/circle/*` | Expus in UI |
| A33 | Guardian second opinion | Card Radar | `requestGuardianSecondOpinion` | `/v1/guardian/second-opinion` | Expus in UI |
| A34 | Speaker Guard / local ASR | Card Radar | `AudioAsrReadinessCard`, `SpeakerGuardSession`, `WhisperCppAsrEngine` | local + orchestrated text | Prezent, dar ascuns daca `SIGURSCAN_ENABLE_AUDIO_ASR=false` |
| A35 | Analiza transcript audio | Card Audio | `analyzeCurrentTextAsAudioTranscript`, `AudioEvidenceEngine` | Orchestrated scan pe transcript | Prezent, flag-gated |
| A36 | Educatie anti-scam | Tab Educatie | `EducationTab`, lesson state | local | Expus in UI |
| A37 | Triage urgenta | Tab Urgenta | `TriageTab`, DNSC 1911 dial | local + dial intent | Expus in UI |
| A38 | Familie / alerte | More | `SecurityFamilySection`, local family alerts | local | Expus in UI |
| A39 | Contrast/accessibility control | More | `ContrastSection` | local | Doar debug; ascuns corect in release UI |
| A40 | Rapoarte readiness/quality/cache | More, doar debug | `ReportsTab`, `BuildConfig.DEBUG` | `/v1/evaluation/*`, `/v1/reputation/cache/stats` | Debug-only, nu release UI |

## Inventar backend - rute si functionalitati

| Grup | Endpoint-uri | Rol | Status |
|---|---|---|---|
| Health/privacy/security | `/`, `/privacy`, `/privacy-policy`, `/health`, `/healthz`, `/health/security`, `/v1/security/play-integrity/nonce` | operare, privacy, nonce Play Integrity | Prezent |
| Orchestrated scan | `POST /v1/scan/orchestrated`, `GET /v1/scan/orchestrated/{scan_id}` | pipeline principal async/polling | Prezent |
| Sandbox/preview | `/v1/sandbox/urlscan`, `/v1/sandbox/urlscan/{uuid}`, `/screenshot` | urlscan + screenshot proxy | Prezent |
| Extractie | `/v1/extract/image`, `/v1/extract/pdf`, `/v1/extract/email` | OCR/link extraction | Prezent |
| Compat scan | `/v1/scan/text`, `/url`, `/email`, `/image`, `/pdf`, `/invoice` | endpoint-uri directe/legacy | Prezent |
| Facturi | `/v1/scan/invoice` | OCR, CUI, IBAN, registry, SANB guidance, gate | Prezent |
| Provenienta/intel | `/v1/verify/provenance`, `/v1/intel/ingest`, `/v1/intel/moderate` | ingestion/moderare intel | Prezent; operator/admin pentru unele |
| Radar | `/v1/community/campaigns`, `/v1/campaign/active`, `/v1/radar/hot-iocs` | campanii si cache telefon | Prezent |
| Reporting | `/v1/report`, `/v1/community/report`, `/v1/push/register` | raport oficial, raport comunitar, push devices | Prezent |
| Cercul/Guardian | `/v1/circle/pair`, `/ping`, `/respond`, `/revoke`, `/v1/guardian/second-opinion` | verificare out-of-band | Prezent |
| BTR | `/v1/btr/sync` | manifest Brand Truth Registry | Prezent |
| Legal/Jurist L2 | `/v1/legal/action-plan` | plan de actiune post-incident | Prezent |
| Urechea/campaign ops | `/v1/urechea/status`, `/run`, `/v1/campaign/match`, `/families` | ingester/campaign family matching | Prezent; mai mult operator/admin |
| Evaluare/admin | `/v1/feedback/*`, `/v1/evaluation/*`, `/v1/orchestration/*`, `/v1/adjudication/*`, `/v1/reputation/cache/stats` | QA, telemetry, dashboard, shadow adjudication | Prezent; nu toate sunt UI release |

## Provideri si piloni de risc

- Web Risk: suport backend, configurabil prin `GOOGLE_WEB_RISK_API_KEY`.
- urlscan: suport backend, configurabil prin `SIGURSCAN_URLSCAN_API_KEY`/`URLSCAN_API_KEY`, cu timeout si privacy-safe mode.
- URLhaus: suport in reputatie, dar ruleaza doar daca exista cheie/flag relevant.
- Phishing.Database: suport ca provider free, flag `ENABLE_PHISHING_DATABASE`.
- Scam Blocklist NRD si phishdestroy: suport env-gated.
- DNS reputation: pilon gratuit, `ENABLE_DNS_REPUTATION`; consens NXDOMAIN/suspendare ca evidenta, nu judecator unic.
- RDAP/whois/SSL/MX: servicii dedicate in backend.
- Mistral/Gemini semantic/cloud explanation: env-gated, cu fallback local.
- Tier1/local classifier + knowledge corpus: local, fara cheie.
- Invoice providers: ANAF CUI, IBAN validator, payment destination registry, negative IBAN registry, SANB guidance, vendor IBAN memory.

## Knowledge/data folosite

| Zona | Fisiere/locatie | Observatie |
|---|---|---|
| Android knowledge compact | `app/src/main/assets/knowledge/romania_knowledge_layer_compact.json` | 18 brand warnings, 23 registry updates, 16 claim targets, 63 scenarii, 8 false-positive guards |
| Android knowledge split | `app/src/main/assets/knowledge/*.json` | registry, brand warnings, claim targets, mapping, sources |
| Backend brand/official | `backend/data/brand_knowledge_pack.json`, `brand_truth_registry_v1.json`, `brand_never_asks_v1.json` | folosit in verificari brand/claim |
| Scam atlas | `backend/data/scam_atlas_*.json` | familii scam, impersonare, oferte |
| Payment destination registry | `backend/data/payment_destination_registry/*.json` | 10 fisiere, aproximativ 66 intrari oficiale/contextuale |
| Negative IBAN | `backend/data/negative_iban_registry_v1.json` + Supabase `negative_iban_registry` | semnal negativ, nu acoperire universala IMM |
| Invoice golden corpus | `backend/data/eval/invoice_golden_corpus_v2026_06_15.json` | teste facturi |
| E2E fixtures | `e2e_fixtures/*` | scenarii realiste pentru testare |
| Legal KB | `backend/data/legal_kb.json` | Jurist L2/action plan |

## Persistenta si infrastructura

| Componenta | Ce exista in cod | Status |
|---|---|---|
| Supabase scan jobs | `scan_jobs` cu CAS lock migration | baza pentru orchestrated async/polling |
| Supabase preview | `urlscan_preview_cache`, `fast_preview_cache`, alias cache, capture runs, storage bucket | baza pentru preview rapid/cache |
| Supabase community | `community_reports`, `scam_campaigns`, `push_devices` | baza pentru Radar/comunitate |
| Supabase PR0-PR4/PR6+ | BTR, campaign intel/fingerprint, circle, guardian, call radar hot cache | prezent in migrations |
| Supabase invoice | `negative_iban_registry`, `vendor_iban_memory` | prezent |
| Supabase reputation graph | observations, edges, allowlist | prezent, service-role only |
| Cloudflare API proxy | `workers/api-proxy` | proxy domeniu/API |
| Pre-capture worker | `workers/precapture` | capture preview, privacy guard, cache Supabase |
| Android release guard | API key, Play Integrity optional, provider keys not shipped direct | prezent |
| Backend guard | API key, admin keys, rate limiter, Play Integrity guarded paths | prezent |

## Functionalitati prezente, dar care trebuie marcate realist

- Speaker Guard/local ASR nu este automat productie doar fiindca exista cod. Implicit build flag-ul este `SIGURSCAN_ENABLE_AUDIO_ASR=false`; are nevoie de model, runtime nativ si QA pe device. Flow-ul audio share exista, dar poate cadea pe "transcriere necesara" daca ASR nu e activ.
- Call Screening verifica numarul prin cache local si poate avertiza/bloca/silentiona prin API oficial Android. Nu asculta convorbirea si nu face popup custom peste apel. Asta este corect Play-safe.
- Istoricul exista, dar este in More; componenta `HistoryTab` nu este tab bottom-nav separat.
- `ReportsTab` este debug-only; in release utilizatorul nu vede readiness/quality/cache dashboards.
- Endpoint-urile Urechea/admin/evaluation exista, dar nu sunt toate produs user-facing.
- Preview-ul depinde de URL final, worker/cache/urlscan si privacy guard. Pentru URL-uri moarte/sensibile, lipsa preview-ului poate fi comportament corect, dar UI trebuie sa explice clar.
- Facturile pot verifica CUI/IBAN/registry/memorie, dar nu exista sursa publica universala care sa confirme orice IMM + orice IBAN in timp real. Scannerul trebuie sa evite "suspect" doar pentru necunoscut si sa foloseasca "verifica in banca/SANB" cand dovada e insuficienta.

## Test matrix necesar pentru "100% cap-coada"

### Automat local

- Backend: `pytest` pe toata suita `backend/test_*.py`.
- Android: `./gradlew testDebugUnitTest`.
- Android instrumented/device: share intents, camera QR, invoice photo/upload, fixture pack, Whisper runtime daca ASR activ.
- Workers: `npm test` in `workers/api-proxy` si `workers/precapture`.
- Web red-team RO: `backend/test_web_redteam_scam_fixtures.py` ruleaza replici sigure, sursate public, prin `/v1/scan/orchestrated`.

### Web red-team RO 2026-06-16

Pack nou: `backend/testdata/web_redteam_scam_fixtures_2026_06_16.json`.

Surse folosite: Posta Romana, FAN Courier, DNSC/HotNews, Politia Romana, Siguranta Online si raportare publica DNSC despre amenzi false/Ghiseul.ro.

Rezultat local cu providerii mock-uiti deterministic:

- WEBRT-POSTA-001: DANGEROUS.
- WEBRT-FAN-001: DANGEROUS.
- WEBRT-GHISEUL-001: DANGEROUS.
- WEBRT-ANAF-001: DANGEROUS.
- WEBRT-ANAF-CALL-001: DANGEROUS.
- WEBRT-TRADING-001: DANGEROUS.
- WEBRT-INVOICE-IBAN-001: SUSPECT.
- WEBRT-CEO-001: DANGEROUS.

Fix aferent: cererile de transfer cu suma/moneda (`RON`, `EUR`, `USD`) sau catre `cont nou` sunt marcate ca `transfer`, astfel CEO fraud text-only nu mai cade in `UNVERIFIED`.

### Live backend

- Health/security: `/health`, `/health/security`.
- Orchestrated safe URL oficial: exemplu YOXO/SMYK/eMAG, trebuie SIGUR cand providerii/claim/domain sunt curate.
- Orchestrated scam: shortener -> domeniu mort/dubios, trebuie SUSPECT/PERICULOS cu mesaj clar, fara polling infinit.
- Preview: URL oficial cu cache/worker, masurat timp pana la verdict si timp pana la preview.
- Factura reala safe: CUI + IBAN valid + semnale curate, fara penalizare pentru IMM necunoscut.
- Factura atac: CUI real + IBAN personal/negativ/mismatch, trebuie ridicat risc.
- Oferta scam: marketplace/casier/crypto/curier ramburs/anunt fals.
- Radar hot cache: sync + local decision pe numar hash/prefix.
- Cercul/Guardian: pair -> ping -> respond -> revoke, plus second opinion.
- BTR: sync + local provenance check.
- Legal/report: action plan + one-tap report.
- Community report: insert raport si verificare aparitie in radar/hot cache conform regulilor.

### Telefon real

- Pornire app + permisiuni de baza.
- Scanare text/link manual.
- Incarcare screenshot.
- Email/PDF.
- QR live si QR image fallback.
- Factura: poza si upload.
- Oferta: upload si confirmare.
- Share text/html/pdf/image/audio din alta aplicatie.
- Radar: sync hot cache, BTR, campanii, Cercul/Guardian.
- Call Screening role: activare si audit ultim apel, fara a pretinde ascultare audio.
- Triage, Educatie, Familie, History.

## Capacitate 1000 useri - ce stim si ce trebuie dovedit

Ce ajuta deja:

- `scan_jobs` persistente cu CAS lock reduc blocajele intre instante.
- Cache-uri pentru reputatie, urlscan si preview reduc costul providerilor.
- Rate limiter si API key reduc abuzul.
- Play Integrity exista ca optiune pentru release.
- Workerul de pre-capture poate muta preview-ul in afara requestului critic.
- Radar/BTR/call cache functioneaza local pe device dupa sync.

Riscuri reale:

- 1000 useri inregistrati nu inseamna 1000 scanari simultane. Pentru 1000 scanari concurente, bottleneck-urile sunt providerii externi, OCR, urlscan/preview, Supabase, Cloud Run max instances/concurrency si polling-ul.
- Orchestrated scan depinde de multe servicii cu rate-limit: Web Risk, urlscan, URLhaus, Gemini/Mistral, ANAF/RDAP/DNS, preview worker.
- Preview poate fi mai lent decat verdictul; trebuie tratat ca rezultat secundar, nu blocant.
- Scanarea factura/OCR este mai grea decat text scan si trebuie load-test separat.

Plan minim de load test matur:

1. 100 VU text/link safe, 10 minute, tinta p95 verdict sub 8-12s fara preview.
2. 250 VU mix text/link + cached preview, 15 minute, masurat p95/p99 si provider error rate.
3. 500 VU mix realist: 70% text/link, 15% image OCR, 10% invoice, 5% report/feedback.
4. 1000 VU burst controlat, cu providerii costisitori fie cache-warmed, fie quota confirmata.
5. Test separat invoice/OCR 50-100 VU, fiindca nu are acelasi profil ca text scan.
6. Test separat preview worker, cu concurrency si privacy guard.

Concluzie capacitate: arhitectura are mecanisme pentru scalare, dar "duce 1000 useri" trebuie validat pe Cloud Run live cu quota reale si metrici. Nu trebuie declarat production-grade la 1000 fara aceste rezultate.
