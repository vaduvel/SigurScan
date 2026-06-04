# SigurScan Master Sprint Roadmap

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans` for inline execution or `superpowers:subagent-driven-development` for parallel execution. This document is the source-of-truth roadmap for turning SigurScan into a production-ready, evidence-based scam detection app.

**Goal:** Build SigurScan as a real, mature, customer-ready scam detector that parses user-provided inputs, scans the extracted targets through live evidence pillars, verifies claims against official knowledge, and returns one simple verdict: `SIGUR`, `SUSPECT`, or `PERICULOS`.

**Architecture:** SigurScan has one final pipeline and one final decision gate. Parser, providers, knowledge corpus, RAG/AI, and UI are supporting layers; they do not independently decide the final user verdict. The product must never classify a message as dangerous only because it contains marketing language, urgency, or a link hidden under a normal CTA button.

**Tech Stack:** Native Android/Kotlin/Compose, Python backend on Vercel, Supabase, urlscan, Google Web Risk, VirusTotal as controlled fallback, Mistral for claim/summary support, official Romania scam knowledge corpus, Android JVM/unit tests, emulator/manual E2E, live provider smoke tests.

---

## 0. Non-Negotiable Product Rules

These rules override older documents when there is conflict.

1. No final verdict without scan evidence when a URL is present.
2. The app is not offline-first. Offline/local-only can extract and prepare evidence, but cannot give a final `SIGUR` or `PERICULOS` verdict for URL-bearing content.
3. Text-only marketing signals are context, not proof. Words like "oferta", "nu rata", "ultima sansa", "voucher", "catalog", "click aici" cannot produce `PERICULOS` alone.
4. Link under button is normal email marketing. It becomes risk only after extraction plus final URL/provider/brand/form evidence.
5. Final URL matters more than first URL. Redirect chains must be resolved, and preview must correspond to the final analyzed destination.
6. RAG/AI is not the judge. It explains, compares, verifies claims, and maps knowledge, but the final verdict is produced by the deterministic gate reading evidence.
7. Corpus is not a panic engine. It is Romania scam memory, false-positive guard, acceptance-test source, and knowledge context for the gate.
8. User UI is non-technical. The user sees a simple verdict, preview, final domain, one or two reasons, and one recommended action.
9. Provider raw details are hidden by default. They remain available for debug/internal QA, not as user-facing jargon.
10. Bulk CI/E2E uses mocks. Provider live tests are limited, controlled smoke tests to avoid rate-limit abuse and noisy external submissions.

## 1. Source Documents And Decisions

This section records what we take from the files provided and what we explicitly do not take.

### 1.1 EvidenceGate And Final Pipeline Specs

Relevant attachments and docs:

- `/Users/vaduvageorge/.codex/attachments/0d741b1d-2a65-410b-a2d7-9d35d8a42ac8/pasted-text.txt`
- `/Users/vaduvageorge/.codex/attachments/1c0920cd-cf80-4447-b4a4-5d5a3ddf7ae6/pasted-text.txt`
- `/Users/vaduvageorge/.codex/attachments/c472802d-0eda-4a4c-b812-2c57c6bf31b2/pasted-text.txt`
- `/Users/vaduvageorge/.codex/attachments/bf665528-6428-401a-b502-124c1b8a2e6d/pasted-text.txt`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/docs/LAUNCH_ARCHITECTURE_FINAL.md`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/docs/MASTER_PIPELINE_SPEC.md`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/docs/EVIDENCE_GATE_FINAL_CANDIDATE.md`

What we take:

- One deterministic EvidenceGate.
- EvidenceSignal/EvidenceSnapshot model.
- Final URL as primary decision target.
- Web Risk, urlscan, VT fallback, claim verifier, official registry, corpus, and RAG as evidence providers.
- Conflict handling: provider conflict prevents `SIGUR`.
- Provider incompleteness: no final confident verdict until required pillars have returned, timed out, or failed with explicit status.
- TTL/cache policy for reputation and provider results.
- Async enrichment can update a result, but user-facing state must clearly say still scanning until evidence is enough.

What we do not take:

- Any architecture where RAG/LLM changes the verdict directly.
- Any architecture where keyword score alone becomes final verdict.
- Any UI with percentages like "70% scam" for normal users.
- Any offline fallback that pretends to know whether a URL is safe.
- Any "scan only when suspicious" shortcut. URL-bearing inputs are scanned.

### 1.2 Backend Infra Intelligence Specs

Relevant attachments:

- `/Users/vaduvageorge/.codex/attachments/455c935c-4449-492e-8792-2423ea4c62b3/pasted-text.txt`
- `/Users/vaduvageorge/.codex/attachments/c42a9870-a77a-49dc-aa7e-271d942d05c5/pasted-text.txt`
- `/Users/vaduvageorge/.codex/attachments/94fe85db-407d-449a-8e3c-f68072a88c7e/pasted-text.txt`

What we take:

- Backend `scam_atlas.py` / infrastructure intelligence must feed decision-grade EvidenceCodes.
- Typosquat, homoglyph, punycode, high entropy, suspicious domain age, suspicious redirects, non-HTTPS, and risky forms must map into the Kotlin gate.
- VT contract must be explicit: VT skipped by policy is not provider failure; VT required but unavailable is provider incompleteness/conflict.
- Homoglyph/confusable detection must run both on extracted URLs and claimed brand/domain comparisons.

What we do not take:

- Treating infra intelligence as mere `CORPUS_SIMILARITY`.
- Blocking legitimate domains only because they use tracking or redirects.
- Forcing VT on every clean low-risk URL if Web Risk/urlscan/official registry are coherent, unless product policy changes and quotas allow it.

### 1.3 Romania Knowledge Layer Research

Relevant attachments and generated packs:

- `/Users/vaduvageorge/.codex/attachments/79341906-5f3b-47d3-bf50-5a4d34c948a5/pasted-text.txt`
- `/Users/vaduvageorge/.codex/attachments/db3bace5-449d-4d5f-ad82-f1e911f0d525/pasted-text.txt`
- `/Users/vaduvageorge/.codex/attachments/58bd306f-52f6-40de-b78f-3f8576a083b2/pasted-text.txt`
- `/Users/vaduvageorge/.codex/attachments/6d5623d5-179b-44fb-b21b-19b5a9438a53/pasted-text.txt`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/backend/data/brand_knowledge_pack.json`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/backend/data/scam_atlas_seed.json`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/app/src/main/java/ro/sigurscan/app/SigurScanKnowledgePack.kt`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/app/src/main/java/ro/sigurscan/app/ScamKnowledgeLayer.kt`

What we take:

- Official registry updates for Romanian brands/institutions.
- Brand warnings and explicit `never_ask_for` rules from official sources.
- Scenario corpus from DNSC, SigurantaOnline, Police, ARB, official brand warnings, and carefully marked community signals.
- False-positive guards for real marketing: Uber, YOXO/Orange, eMAG, FAN, Posta Romana, Sameday, telecom, utilities, bank notifications.
- Claim verifier targets: "is this offer/campaign real and active?", "does the official brand mention this domain?", "does this brand ever ask for card/OTP/password by this channel?"
- Source confidence: official source beats community, community cannot create hard verdict alone.

What we do not take:

- Unverified claims as hard rules.
- Reddit/community posts as final truth.
- Corpus-only dangerous verdict for real marketing language.
- Any "ANAF refund" or "iDroid status" hard rule unless supported by provider/brand/domain/sensitive action evidence.

### 1.4 Android Architecture Refactor Docs

Relevant attachments:

- `/Users/vaduvageorge/.codex/attachments/3ac2153b-9ec2-4b42-8e3d-e577fc0c95c3/pasted-text.txt`
- `/Users/vaduvageorge/.codex/attachments/ed7e19b8-a6b2-4c95-bb83-6cbf80b44ed0/pasted-text.txt`

What we take:

- Incremental refactor, not big-bang rewrite.
- `MainActivity` becomes thin over time.
- Feature-based UI packages: scan, result, radar, triage, education, more.
- Pure domain layer for EvidenceGate and models.
- MVI-style state/event/effect where it reduces confusion.
- Tests around domain and ViewModel before moving code.

What we do not take immediately:

- Hilt first.
- Room/DataStore first.
- Large package migration before scan pipeline is fully stable.
- Blindly copying endpoint examples from the doc.

### 1.5 UI Redesign Kit

Relevant attachment:

- `/Users/vaduvageorge/.codex/attachments/7bca648e-f63d-4265-baa5-f5c3af465b9e/pasted-text.txt`

What we take:

- Premium theme direction.
- Better typography, spacing, cards, pills, and verdict hero.
- Dark mode support.
- Result card centered around `SIGUR`, `SUSPECT`, `PERICULOS`.
- Preview-first UX: secure screenshot of final URL, final domain, simple reason, simple action.
- Reusable components after we split the monolith enough to apply safely.

What we adjust:

- Prefer bundled local Manrope fonts in `res/font` instead of downloadable Google Fonts if release reliability matters.
- Apply screen-by-screen with build after each change.
- No percentage risk score in final user UI.

What we do not take:

- Blind full paste into the current monolithic `MainActivity`.
- Any visual element that makes provider internals look like user-facing requirements.
- Any "cyber hero" copy that distracts from the practical user decision.

### 1.6 E2E, Live Provider, And Emulator Packs

Relevant docs and fixtures:

- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/e2e_fixtures/`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/docs/E2E_FIXTURE_PACK_INTEGRATION.md`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/docs/E2E_FIXTURE_PACK_V2_PREP.md`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/docs/E2E_EMULATOR_RESULTS_2026-06-03.md`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/docs/LIVE_SMOKE_RESULTS_2026-06-03.md`

What we take:

- Fixture v1/v2 as deterministic mocked regression.
- Live provider smoke pack capped at 15-20 cases.
- Real user cases like YOXO, SMYK, eMAG tracking, FAN fake tax, iDroid status, Postis/Flanco as special acceptance cases.
- Emulator testing for star flows: share text, share HTML/email, URL scan with preview, final verdict rendering.

What we do not take:

- Running hundreds of fixtures against live urlscan/Web Risk/VT.
- Treating provider no-match as "safe absolute".
- Treating urlscan 404/pending as proof of safety or danger.

### 1.7 Compliance, Release, And Store Readiness

Relevant docs:

- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/docs/PLAY_PRIVACY_DATA_SAFETY.md`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/docs/RELEASE_PROCESS.md`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/docs/RELEASE_SIGNING.md`

What we take:

- Privacy Policy must disclose URL/content snippets sent to third-party scanning providers.
- Data Safety must match real behavior.
- Clipboard only through user action.
- API keys remain backend-side where possible.
- Backend must enforce auth/rate limit/origin controls before production launch.
- Supabase RLS must be audited before public release.

What we do not take:

- Automatic monitoring of all notifications/messages.
- Background scraping of user data.
- Any feature requiring sensitive permissions before strong store justification.

---

## 2. Final Target Pipeline

Every scan goes through this pipeline.

```text
User input
  -> Intake assembler
  -> Parser/extractor
  -> Primary target picker
  -> URL sanitization and PII redaction
  -> Provider scan pillars
       -> urlscan final URL + screenshot preview + redirect chain
       -> Google Web Risk
       -> VirusTotal fallback/controlled reputation
       -> backend infra intelligence
       -> claim verifier / official web check
  -> Knowledge layer
       -> official domain registry
       -> brand warnings / never_ask_for
       -> Romania scam scenario corpus
       -> false-positive guards
       -> RAG explanation context
  -> EvidenceGate
  -> GateResultPresentation
  -> UI: SIGUR / SUSPECT / PERICULOS
```

Required user-facing output:

- Verdict: `SIGUR`, `SUSPECT`, or `PERICULOS`.
- Final domain.
- Secure preview screenshot when URL exists and provider returned one.
- One or two plain-language reasons.
- One recommended action.

Internal-only output:

- Provider raw payloads.
- Threat intelligence details.
- Redirect chain.
- Rule IDs.
- RAG/corpus match IDs.
- Debug timing and cache metadata.

---

## 3. Sprint Sequence

### Sprint 0: Roadmap Lock And Current-State Audit

**Goal:** Freeze this roadmap as the execution source and record current code reality before more changes.

**Files to inspect:**

- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/app/src/main/java/ro/sigurscan/app/ScannerViewModel.kt`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/app/src/main/java/ro/sigurscan/app/EvidenceGate.kt`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/app/src/main/java/ro/sigurscan/app/EvidenceSignalNormalizer.kt`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/backend/main.py`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/backend/scam_atlas.py`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/backend/offer_claim_verifier.py`

**Implementation checklist:**

- [ ] Confirm app name/package/repo are SigurScan only.
- [ ] Confirm React Native `/Users/vaduvageorge/Desktop/NuDaClick/mobile` is not part of release.
- [ ] Confirm Vercel backend env vars are present for Web Risk/urlscan/VT/Mistral/Supabase.
- [ ] Confirm provider calls go through backend or controlled Android config, not hardcoded public secrets in APK.
- [ ] Write `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/docs/CURRENT_STATE_AUDIT.md`.

**Verification commands:**

```bash
cd /Users/vaduvageorge/AndroidStudioProjects/SigurScan
git status --short --branch
JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home" ./gradlew :app:testDebugUnitTest
cd backend && pytest -q
```

**Acceptance criteria:**

- Tests pass.
- Current pipeline gaps are written down.
- No work continues in the wrong project.

### Sprint 1: Provider Pillar Contract And No-Early-Verdict Rule

**Goal:** Ensure URL-bearing input always waits for required provider pillar states before final verdict.

**Primary files:**

- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/app/src/main/java/ro/sigurscan/app/ThreatIntelOrchestrator.kt`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/app/src/main/java/ro/sigurscan/app/ScannerViewModel.kt`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/app/src/main/java/ro/sigurscan/app/EvidenceGate.kt`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/app/src/main/java/ro/sigurscan/app/EvidenceSignalNormalizer.kt`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/backend/main.py`

**What to implement:**

- [ ] A provider-state model: `NOT_STARTED`, `RUNNING`, `OK`, `NO_MATCH`, `MALICIOUS`, `SKIPPED_BY_POLICY`, `TIMEOUT`, `ERROR`.
- [ ] Required URL-bearing pillars: urlscan final URL/preview, Web Risk, claim verifier when text claim exists.
- [ ] VT as fallback or extended pillar, not a required blocker when policy says skip.
- [ ] UI scan state says "Se scaneaza..." until evidence is enough.
- [ ] Gate cannot return `SIGUR` when required URL pillars are missing.
- [ ] Gate cannot return `PERICULOS` from text-only/corpus-only if URL pillars are missing.

**Tests to add/update:**

- URL exists + providers running -> scanning/incomplete, not final.
- URL exists + Web Risk clean + urlscan final official + no sensitive request -> `SIGUR`.
- URL exists + Web Risk no-match + urlscan pending -> `SUSPECT` only after timeout with reason "nu putem verifica suficient", not `PERICULOS`.
- Text-only "voucher/oferta" without URL -> max `SUSPECT`, never `PERICULOS`.
- VT skipped by policy -> not provider failure.

**Verification commands:**

```bash
cd /Users/vaduvageorge/AndroidStudioProjects/SigurScan
JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home" ./gradlew :app:testDebugUnitTest
cd backend && pytest -q
```

**Commit message:**

```bash
git commit -m "fix: enforce provider pillar contract before final verdict"
```

### Sprint 2: Parser And Intake Hardening

**Goal:** Extract the real scan target from SMS, share text, HTML email, buttons, ClipData, PDF, image/OCR and QR as reliably as possible.

**Primary files:**

- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/app/src/main/java/ro/sigurscan/app/SharedTextPayloadResolver.kt`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/app/src/main/java/ro/sigurscan/app/MailShareInputAssembler.kt`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/app/src/main/java/ro/sigurscan/app/EmailMessageParser.kt`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/app/src/main/java/ro/sigurscan/app/HtmlLinkExtractor.kt`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/app/src/main/java/ro/sigurscan/app/UrlTextExtractor.kt`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/app/src/main/java/ro/sigurscan/app/PdfLinkExtractor.kt`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/app/src/main/java/ro/sigurscan/app/PrimaryUrlPicker.kt`

**What to implement:**

- [ ] Read `Intent.EXTRA_TEXT`, `Intent.EXTRA_HTML_TEXT`, `intent.clipData`, URI streams, and MIME metadata.
- [ ] Show internal parse source: full HTML received vs visible text only, but keep it simple in UI.
- [ ] Extract links from `href`, buttons, `data-url`, `onclick`, JS `window.location`, `atob`, `decodeURIComponent`, CSS `url(...)`, SVG `xlink:href`, `srcset`, and meta refresh.
- [ ] Decode recursively with depth limit: HTML entities, percent encoding, base64, JS unicode escapes.
- [ ] Normalize zero-width spaces, soft hyphens, comments inside brand names, BIDI overrides, mixed-script and confusables.
- [ ] Extract form actions and sensitive fields.
- [ ] PrimaryUrlPicker selects maximum user-action/suspicion target, not first URL.
- [ ] Ignore ordinary unsubscribe/social/footer links unless they are the only actionable URL.

**Tests to add/update:**

- Gmail/Outlook-like HTML button with visible "Comanda o cursa" and hidden tracking URL.
- Uber/YOOX/YOXO/marketing tracking link under CTA -> parse link, do not mark dangerous before scan.
- Phishing email with 10 official footer links and one fake payment CTA -> pick fake CTA as primary.
- CSS/SVG/JS/base64 hidden URL extraction.
- PDF with visible URL and embedded URL.
- OCR blurry input with partial URL -> insufficient until user gives more data.

**Verification commands:**

```bash
cd /Users/vaduvageorge/AndroidStudioProjects/SigurScan
JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home" ./gradlew :app:testDebugUnitTest
```

**Commit message:**

```bash
git commit -m "feat: harden intake and hidden link extraction"
```

### Sprint 3: Knowledge Layer Runtime Integration

**Goal:** Make the Romania knowledge layer actively shape evidence and explanations without becoming a false-positive judge.

**Primary files:**

- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/app/src/main/java/ro/sigurscan/app/SigurScanKnowledgePack.kt`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/app/src/main/java/ro/sigurscan/app/ScamKnowledgeLayer.kt`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/app/src/main/java/ro/sigurscan/app/BrandKnowledgeRegistry.kt`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/backend/data/brand_knowledge_pack.json`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/backend/data/scam_atlas_seed.json`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/backend/tools/build_runtime_knowledge.py`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/backend/offer_claim_verifier.py`

**What to implement:**

- [ ] Ensure all current research pack brands and warnings are loaded by backend and Android.
- [ ] Add source confidence: official, brand official, public authority, community, synthetic test.
- [ ] Map `never_ask_for` to decision-grade structural evidence only when matched with a real request/action.
- [ ] Add false-positive guards for marketing/tracking links from known legitimate brands.
- [ ] Corpus scenario similarity can explain and raise suspicion but cannot alone produce `PERICULOS`.
- [ ] Claim verifier checks official brand domains and campaign/offer pages when claim exists.
- [ ] Add "source missing" output for unverified scenarios so gate does not hallucinate authority.

**Tests to add/update:**

- YOXO buyback message -> official domain and claim coherent -> `SIGUR` if providers clean.
- SMYK catalog message -> official domain and normal marketing -> `SIGUR` if providers clean.
- FAN fake tax domain -> `PERICULOS` or `SUSPECT` based on provider/form evidence.
- ANAF refund on unofficial domain asking card/login -> `PERICULOS`.
- Real eMAG/FAN/Posta/Sameday tracking -> not false positive.

**Verification commands:**

```bash
cd /Users/vaduvageorge/AndroidStudioProjects/SigurScan/backend
python3 tools/build_runtime_knowledge.py
pytest -q
cd ..
JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home" ./gradlew :app:testDebugUnitTest
```

**Commit message:**

```bash
git commit -m "feat: wire Romania knowledge layer into evidence pipeline"
```

### Sprint 4: Final EvidenceGate v2 And Three Verdict Contract

**Goal:** Make the final gate match the actual product: `SIGUR`, `SUSPECT`, `PERICULOS`, based on evidence pillars plus knowledge layer.

**Primary files:**

- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/app/src/main/java/ro/sigurscan/app/EvidenceGate.kt`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/app/src/main/java/ro/sigurscan/app/GateResultPresentation.kt`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/app/src/main/java/ro/sigurscan/app/EvidenceSignalNormalizer.kt`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/app/src/test/java/ro/sigurscan/app/EvidenceGateTest.kt`

**What to implement:**

- [ ] Map internal actions to only three user verdicts.
- [ ] `SIGUR`: final URL official/delegated or claim coherent, Web Risk no-match/clean, urlscan non-malicious, no unofficial sensitive form, no hard conflict.
- [ ] `SUSPECT`: provider incomplete, conflict, unknown domain with sensitive context, text/corpus suspicion without hard provider evidence, or final URL cannot be verified.
- [ ] `PERICULOS`: Web Risk match, urlscan malicious, confirmed blacklist, final URL mismatch plus sensitive request, form action to unofficial domain, malware/APK/remote access, or provider/corpus official hard confirmation.
- [ ] Corpus/RAG cannot override clean coherent provider evidence to dangerous.
- [ ] Provider hard malicious can override corpus false-positive guard.
- [ ] Add explanation priority: hard provider reason first, then final domain mismatch, then sensitive request, then corpus scenario.

**Tests to add/update:**

- YOXO official clean -> `SIGUR`.
- Postis/Flanco survey link with download prompt -> provider/preview/claim evidence decides, not text.
- iDroid status SMS -> final URL official and non-sensitive -> `SIGUR` or `SUSPECT` based on provider/preview, not corpus panic.
- Marketing CTA with hidden link official -> `SIGUR`.
- Marketing CTA with hidden fake login -> `PERICULOS`.
- Provider clean + "send OTP by reply" -> `SUSPECT`/`PERICULOS` based on reply/code evidence, never `SIGUR`.

**Verification commands:**

```bash
cd /Users/vaduvageorge/AndroidStudioProjects/SigurScan
JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home" ./gradlew :app:testDebugUnitTest
```

**Commit message:**

```bash
git commit -m "feat: finalize three-verdict evidence gate"
```

### Sprint 5: Preview And Result UX

**Goal:** Make the app's strongest feature visible: final URL preview screenshot plus simple decision.

**Primary files:**

- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/app/src/main/java/ro/sigurscan/app/MainActivity.kt`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/app/src/main/java/ro/sigurscan/app/ScannerViewModel.kt`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/app/src/main/java/ro/sigurscan/app/ui/theme/Color.kt`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/app/src/main/java/ro/sigurscan/app/ui/theme/Theme.kt`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/app/src/main/java/ro/sigurscan/app/ui/theme/Type.kt`

**What to implement:**

- [ ] Result screen shows verdict first: `SIGUR`, `SUSPECT`, `PERICULOS`.
- [ ] Show "Am analizat linkul final" and final domain.
- [ ] Show preview image from urlscan/final URL if available.
- [ ] Show "Preview indisponibil" only when provider lacks screenshot; do not replace with first-hop screenshot.
- [ ] Hide provider jargon by default.
- [ ] Add collapsible "Detalii tehnice" only for debug/developer mode if needed.
- [ ] Apply UI kit selectively: colors, spacing, verdict hero, result card, scan input card.
- [ ] Prefer local font files if adding Manrope.

**Tests/checks:**

- Manual emulator: scan YOXO/SMYK/eMAG/FAN fake and verify preview slot.
- Screenshot compare manually for light/dark mode.
- Confirm no percentages are user-facing.

**Verification commands:**

```bash
cd /Users/vaduvageorge/AndroidStudioProjects/SigurScan
JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home" ./gradlew :app:assembleDebug
JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home" ./gradlew :app:lintDebug
```

**Commit message:**

```bash
git commit -m "feat: simplify result UI around verdict and final URL preview"
```

### Sprint 6: Backend Provider Reliability And Live Smoke

**Goal:** Make live provider integrations reliable without burning quotas or leaking data unnecessarily.

**Primary files:**

- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/backend/main.py`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/backend/urlscan_client.py`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/backend/webrisk_client.py`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/backend/virustotal_client.py`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/backend/offer_claim_verifier.py`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/backend/scam_atlas.py`

**What to implement:**

- [ ] Provider response contract with timing, cache hit, status, raw confidence, and normalized evidence.
- [ ] PII redaction before urlscan/VT: emails, phone numbers, OTPs, long tokens, session IDs.
- [ ] urlscan visibility policy: use private/unlisted according to account capability and product policy.
- [ ] Web Risk checks include malware/social engineering/unwanted software and extended coverage where configured.
- [ ] VT runs only under policy: conflict, unknown, suspicious, user requested extended scan, or fallback.
- [ ] Rate limits per device/user/API key.
- [ ] Health endpoint reports provider config presence without exposing secrets.

**Live smoke set:**

- YOXO buyback: `buyback.yoxo.ro`.
- SMYK catalog: `https://smyk.ro/catalogul-ziua-copilului`.
- eMAG tracking official path.
- FAN official path.
- FAN fake reserved/safe test domain with mocks only.
- iDroid status real URL if user approves live scan.
- Postis/Flanco survey link if user approves live scan.
- `example.com` clean baseline.

**Verification commands:**

```bash
cd /Users/vaduvageorge/AndroidStudioProjects/SigurScan/backend
pytest -q
curl -s https://nudaclick-backend.vercel.app/health
```

**Commit message:**

```bash
git commit -m "feat: harden backend provider contract and live smoke policy"
```

### Sprint 7: E2E Regression Harness

**Goal:** Turn v1/v2 fixture packs and Romania acceptance tests into the safety net that prevents future regressions.

**Primary files:**

- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/e2e_fixtures/`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/app/src/test/java/ro/sigurscan/app/`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/backend/tests/`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/docs/E2E_FIXTURE_PACK_INTEGRATION.md`

**What to implement:**

- [ ] JVM runner for all text/HTML/email/PDF-extractable fixtures.
- [ ] Mock provider adapter for Web Risk/urlscan/VT/claim verifier.
- [ ] Unsupported OCR/QR image tests are marked as emulator/manual unless MLKit/image decode is available.
- [ ] Expected verdict assertion uses three final verdicts.
- [ ] False-positive guard suite must be separate and mandatory.
- [ ] Provider live smoke suite must remain capped and opt-in.

**Verification commands:**

```bash
cd /Users/vaduvageorge/AndroidStudioProjects/SigurScan
JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home" ./gradlew :app:testDebugUnitTest
cd backend && pytest -q
```

**Acceptance criteria:**

- Fixture v1 mocked runner passes supported cases.
- Fixture v2 mocked runner passes supported cases or produces categorized known gaps.
- No known legitimate marketing case returns `PERICULOS`.

**Commit message:**

```bash
git commit -m "test: add mocked e2e regression harness"
```

### Sprint 8: Emulator And Real Star-Flow QA

**Goal:** Prove the app works from the user's perspective, not just unit tests.

**Flows to test:**

- [ ] Direct SMS text paste/share with URL.
- [ ] Gmail/Outlook-style HTML share with CTA button and hidden URL.
- [ ] PDF/document upload with link.
- [ ] Screenshot/photo OCR with URL.
- [ ] QR scan.
- [ ] Final preview display.
- [ ] Provider pending/timeout UI.
- [ ] Dark mode result screen.

**Manual test messages:**

```text
Ai un telefon sau o tableta pe care nu le mai folosesti? Acum le poti transforma rapid in bani cu serviciul de buy-back YOXO. Beneficiezi de evaluare online in doar cateva minute, transport gratuit si plata in cont in maximum 48 de ore de la confirmarea dispozitivului. Simplu, sigur si fara batai de cap. Afla cat valoreaza dispozitivul tau si incepe procesul chiar acum: buyback.yoxo.ro
```

```text
Rasfoieste catalogul de 1 iunie: https://smyk.ro/catalogul-ziua-copilului si vino in magazine sa alegi: jucarii, jocuri, haine si incaltaminte la super preturi.
```

```text
Comanda ta eMAG #4471122 a fost expediata. Urmareste coletul: https://www.emag.ro/order/tracking
```

```text
FanCourier: Coletul dvs. nr. 8842231 nu a putut fi livrat - taxa vamala neachitata 3,50 RON. Reprogramati livrarea: https://fancurier-relivrare.com/plata
```

```text
Dispozitivul dvs. (cod 8HXDX) nu a putut fi reparat. Informatii la 0371237475. https://idroid.ro/verificare-status Se percepe taxa de magazinaj la depasirea a 10 zile.
```

**Deliverable:**

- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/docs/STAR_FLOW_QA_REPORT.md`

**Commit message:**

```bash
git commit -m "docs: add star flow QA report"
```

### Sprint 9: Store, Privacy, Security, And Backend Production Readiness

**Goal:** Make SigurScan safe to put in front of real users.

**Primary files/docs:**

- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/docs/PLAY_PRIVACY_DATA_SAFETY.md`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/docs/RELEASE_PROCESS.md`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/docs/RELEASE_SIGNING.md`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/supabase/`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/backend/`

**What to implement:**

- [ ] Privacy Policy page published and linked.
- [ ] Data Safety answers match real provider sharing.
- [ ] Backend API auth/rate limiting enabled in production.
- [ ] Supabase RLS audited: anon cannot read/poison sensitive/community data.
- [ ] No automatic device registration without clear consent or legitimate minimal purpose.
- [ ] No secrets in APK except acceptable public config protected by backend/RLS.
- [ ] Android permissions reviewed: CAMERA only if QR/OCR feature exists and is user initiated.
- [ ] Crash/error telemetry reviewed for PII leakage.

**Verification commands:**

```bash
cd /Users/vaduvageorge/AndroidStudioProjects/SigurScan
JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home" ./gradlew :app:lintRelease
JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home" ./gradlew :app:assembleRelease
cd backend && pytest -q
```

**Commit message:**

```bash
git commit -m "chore: harden release privacy and production security"
```

### Sprint 10: Android Architecture Cleanup

**Goal:** Make the codebase maintainable without changing detection behavior.

**Primary files:**

- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/app/src/main/java/ro/sigurscan/app/MainActivity.kt`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/app/src/main/java/ro/sigurscan/app/ScannerViewModel.kt`
- New feature packages under `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/app/src/main/java/ro/sigurscan/app/feature/`
- New core UI package under `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/app/src/main/java/ro/sigurscan/app/core/ui/`

**What to implement:**

- [ ] Extract theme/tokens/components first.
- [ ] Extract result card and scan input card.
- [ ] Extract tabs one by one: scan, radar, triage, education, more.
- [ ] Move pure gate/domain models to a domain package only after tests pin behavior.
- [ ] Add MVI state/event/effect for scan feature.
- [ ] Defer Hilt/Room/DataStore until the monolith split is stable.

**Verification commands after each extracted feature:**

```bash
cd /Users/vaduvageorge/AndroidStudioProjects/SigurScan
JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home" ./gradlew :app:testDebugUnitTest
JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home" ./gradlew :app:assembleDebug
```

**Commit messages:**

```bash
git commit -m "refactor: extract scan UI components"
git commit -m "refactor: extract result UI components"
git commit -m "refactor: split app tabs into feature packages"
git commit -m "refactor: introduce scan MVI state"
```

### Sprint 11: Final Release Candidate

**Goal:** Produce a version that can be tested by real people without apologizing for demo behavior.

**Checklist:**

- [ ] All unit tests pass.
- [ ] Backend tests pass.
- [ ] Mocked E2E v1/v2 supported cases pass.
- [ ] Live provider smoke report exists.
- [ ] Emulator star-flow report exists.
- [ ] Privacy/security docs are complete.
- [ ] Release build succeeds.
- [ ] App name, icon, package, and store copy say SigurScan.
- [ ] User-facing verdicts are only `SIGUR`, `SUSPECT`, `PERICULOS`.
- [ ] No user-facing risk percentages.
- [ ] No offline final verdict for URL-bearing input.
- [ ] Git is clean and pushed.

**Final verification commands:**

```bash
cd /Users/vaduvageorge/AndroidStudioProjects/SigurScan
git status --short --branch
JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home" ./gradlew :app:testDebugUnitTest :app:lintRelease :app:assembleRelease
cd backend && pytest -q
curl -s https://nudaclick-backend.vercel.app/health
```

**Commit message:**

```bash
git commit -m "release: prepare SigurScan production candidate"
```

---

## 4. Implementation Priority

If only one thing can be done next, do Sprint 1.

Priority order:

1. Provider pillar contract and no-early-verdict.
2. Parser/intake hardening.
3. Knowledge layer runtime integration.
4. EvidenceGate v2 with three verdicts.
5. Preview/result UX.
6. Backend provider reliability and live smoke.
7. E2E regression harness.
8. Emulator star-flow QA.
9. Store/privacy/security.
10. Architecture cleanup.
11. Release candidate.

Reason: UI and refactor are important, but they are lipstick if the app still decides before scanning. The first four sprints protect the product from the exact failure mode we care about: false positives on normal marketing and false confidence without provider evidence.

---

## 5. Definition Of "Ready For Clients"

SigurScan is client-ready only when all statements below are true:

- A normal user can share/paste a suspicious SMS/email/link/photo/PDF/QR into the app.
- The app extracts the actual actionable URL, including hidden CTA/button links where the source provides HTML.
- The app scans the final destination with configured providers.
- The app shows a preview of the final URL when available.
- The app verifies the claim/brand context when the message makes a concrete claim.
- The app uses Romania official knowledge and false-positive guards.
- The app returns exactly one simple verdict: `SIGUR`, `SUSPECT`, or `PERICULOS`.
- The app explains the verdict in plain Romanian.
- Real marketing messages from official domains are not called dangerous because of wording or CTA buttons.
- Known scam patterns are caught when provider/brand/domain/sensitive-action evidence supports them.
- Provider failures produce honest uncertainty, not fake confidence.
- Backend, Supabase, privacy policy, and rate limits are production safe.
- Tests cover the cases that hurt: Uber/eMAG/FAN/Posta/YOOX/YOXO/SMYK/ANAF/Revolut/marketplace/OTP/remote access.

---

## 6. What To Ask Future Research Agents For

Ask for evidence artifacts, not opinions.

### 6.1 Romania Knowledge Refresh

Request:

```text
Creeaza un update pentru SigurScan Romania Knowledge Layer. Foloseste doar surse oficiale sau branduri oficiale pentru reguli hard. Include: brand, domenii oficiale, parteneri/tracking legitimi, ce spune oficial ca nu cere niciodata, link sursa, data verificarii, confidence, scenarii de scam confirmate, false-positive guards. Marcheaza separat sursele community ca semnale slabe. Nu inventa reguli.
```

### 6.2 Parser Torture Pack

Request:

```text
Creeaza un test pack sigur pentru parser email/HTML/SMS/PDF/QR pentru SigurScan. Include linkuri sub butoane, href, data-url, onclick, atob, decodeURIComponent, CSS url(), SVG xlink:href, meta refresh, zero-width chars, BIDI override, homoglyph, redirect wrappers Microsoft/Proofpoint/Google/Facebook, footer links legitime si un primary phishing CTA. Toate domeniile scam trebuie sa fie .test/.invalid/.example.
```

### 6.3 Live Provider Smoke Pack

Request:

```text
Creeaza maxim 20 de cazuri pentru live provider smoke testing SigurScan. Include doar URL-uri sigure, oficiale sau rezervate. Nu include sute de cazuri. Pentru fiecare caz spune ce provider trebuie apelat, ce se accepta ca rezultat flexibil, daca urlscan trebuie folosit unlisted/private, si ce nu trebuie assertat rigid.
```

### 6.4 False-Positive Guard Pack

Request:

```text
Creeaza un false-positive guard pack pentru Romania: newslettere reale mimetic construite, marketing CTA, tracking links, livrari legitime, OTP legitim, facturi utilitati, telecom buyback, catalog retail, survey post-livrare. Pentru fiecare: expected verdict, de ce nu e scam, ce provider/brand evidence trebuie sa confirme.
```

---

## 7. Open Risks To Keep Visible

- urlscan can be fooled by cloaking; treat clean as one signal, not absolute truth.
- Web Risk no-match means no known match at lookup time, not "safe forever".
- VT Public API has commercial/product limitations; verify licensing before relying on it in production.
- Claim verifier with web search can hallucinate if not constrained to official domains and source URLs.
- HTML share from Gmail/Outlook may provide visible text only depending on app/platform; UI must indicate when full HTML was not received.
- Supabase anon key is acceptable only if RLS is strict and tested.
- Provider screenshots may expose sensitive URLs if PII redaction is incomplete.
- Too much technical detail in UI will confuse the user and reduce trust.

---

## 8. Execution Rule

Every sprint must end with:

```bash
cd /Users/vaduvageorge/AndroidStudioProjects/SigurScan
git status --short --branch
JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home" ./gradlew :app:testDebugUnitTest
cd backend && pytest -q
```

If UI changed, also run:

```bash
cd /Users/vaduvageorge/AndroidStudioProjects/SigurScan
JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home" ./gradlew :app:assembleDebug
```

If release/security changed, also run:

```bash
cd /Users/vaduvageorge/AndroidStudioProjects/SigurScan
JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home" ./gradlew :app:lintRelease :app:assembleRelease
```

Every sprint report must say:

- What changed.
- What source document it came from.
- What tests passed.
- What remains risky.
- Whether the app is closer to client-ready.
