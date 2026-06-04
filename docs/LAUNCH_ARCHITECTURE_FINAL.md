# SigurScan Launch Architecture Final

Data: 2026-06-02

Status: source of truth pentru Android Launch Candidate v1. Daca exista conflict intre acest document si review-urile GPT/Sonnet/Gemini, acest document castiga.

## Scop

SigurScan pentru lansarea light Romania este un produs user-initiated care raspunde la o intrebare simpla:

```text
Linkul duce unde pretinde mesajul ca duce?
```

Produsul nu este un AI care decide daca un mesaj "suna a scam". Produsul construieste dovezi verificabile, le trece printr-un gate determinist si arata userului o actiune clara.

## Documente Sursa

Acest document reconciliaza:

- `PRODUCT_CORE_LINK_TRUTH.md`: principiul de produs si regula de aur.
- `EVIDENCE_GATE_FINAL_CANDIDATE.md`: baza tehnica pentru EvidenceGate.
- `ROMANIA_SCAM_SCENARIO_CORPUS.md`: taxonomie determinista pentru scamuri romanesti.
- `docs/gpt55-review/*.md`: audit si input, nu implementare copy-paste.
- `MASTER_PIPELINE_SPEC.md`: context istoric pentru pipeline unificat.

## Clarificari 3/3 Incorporate

Aceste reguli sunt parte din source of truth:

- `finalUrl` este tinta principala a deciziei cand exista; `primaryUrl` este doar primul hop.
- Orice verdict provizoriu calculat pe `primaryUrl` se reevalueaza cand apare `finalUrl` sau un `formActionHost`.
- Google Web Risk include `MALWARE`, `SOCIAL_ENGINEERING`, `UNWANTED_SOFTWARE` si, daca este disponibil/permis, `SOCIAL_ENGINEERING_EXTENDED_COVERAGE`.
- urlscan este `private` by default; `public` este interzis pentru URL-uri user-submitted.
- `unlisted` se foloseste doar daca `private` nu este disponibil, URL-ul este redacted si privacy policy acopera explicit acest fallback.
- VirusTotal Public API nu intra in produs comercial Play; pentru productie folosim Premium/Private Scanning/contract compatibil sau dezactivam VT in v1.
- Preferam scanners/pickers fara permisiuni grele: Google Code Scanner / Document Scanner / Android Photo Picker / SAF, cand sunt fezabile.
- Update-urile async pot creste riscul, dar nu coboara silent `DO_NOT_CONTINUE` sau `NO_ENTER_DATA` in aceeasi sesiune.

## Regula De Aur

```text
claimed brand != final official/partner domain
+ user is asked to act
= Nu continua sau Verifica pe canalul oficial, in functie de actiune si dovezi
```

Regula stricta:

```text
claimed brand != final official/partner domain
+ asks card / CVV / OTP / password / login / payment / CNP / IBAN / APK / remote access
= Nu introduce date sau Nu continua
```

## Verdicturi User-Facing

UI foloseste doar aceste actiuni principale:

| Internal decision | User label | Cand apare |
| --- | --- | --- |
| `DO_NOT_CONTINUE` | `Nu continua` | reputatie hard, sandbox phishing/malware, domeniu rau confirmat, APK/remote access compound |
| `NO_ENTER_DATA` | `Nu introduce date` | card/login/OTP/parola/CNP/IBAN/plata pe domeniu neoficial sau nevalidat |
| `NO_REPLY` | `Nu raspunde` | text-only/social scam care cere coduri, bani, date sau continuarea conversatiei |
| `VERIFY_OFFICIAL` | `Verifica pe canalul oficial` | domeniu necunoscut, shortener, tracking nerezolvat, semnale slabe, brand mentionat fara confirmare |
| `CONTINUE_WITH_CAUTION` | `Poti continua cu prudenta` | final URL oficial/partener valid, fara semnale riscante si cu analiza suficienta |
| `INSUFFICIENT_EVIDENCE` | `Nu pot verifica suficient` | input incomplet, OCR slab, provider indisponibil, redaction prea puternic, webmail shell |

Nu folosim in UI:

- procente ca mesaj principal;
- `safe`, `100% sigur`, `garantat legitim`, `site sigur`;
- `detectam toate scamurile`;
- `suspect` ca verdict final vag.

## Pipeline Final

```text
User input
-> Extractor local
-> Primary URL Picker
-> PII Redaction
-> Official Registry lookup
-> Provider adapters
-> EvidenceSnapshot
-> EvidenceGate deterministic
-> RAG Explainer read-only
-> UserResult action-first UI
```

Toate sursele produc `EvidenceSignal`. Nicio sursa nu intoarce verdict final. Numai `EvidenceGate` produce actiunea principala.

Target resolution rule:

```text
primaryUrl -> redirectChain -> finalUrl -> formActionHost
```

Gate-ul decide pe cea mai relevanta tinta disponibila:

- `primaryUrl` pentru fast checks;
- `finalUrl` pentru official registry, reputation si preview;
- `formActionHost` pentru decizii despre card/login/OTP/CNP/IBAN;
- daca hostul se schimba intre primary si final, `finalUrl` castiga;
- daca formularul trimite date in alta parte, `formActionHost` poate castiga peste `finalUrl`.

## Entry Points Permise

Launch Candidate v1 ramane user-initiated only:

- paste explicit;
- share/import/upload;
- `ACTION_SEND` text/html/url;
- `ACTION_PROCESS_TEXT` daca este implementat;
- QR scan;
- OCR/import imagine prin picker;
- file import prin `ACTION_OPEN_DOCUMENT`.

Nu implementam:

- Notification Listener;
- SMS auto-read;
- WhatsApp auto-read;
- Accessibility Service;
- Call Log;
- clipboard/background monitoring;
- VPN;
- overlay;
- broad storage;
- farming date.

## Evidence Model Minim

Launch Candidate v1 are nevoie de aceste concepte, chiar daca numele exacte se aliniaza ulterior cu codul Android existent:

- `EvidenceSignal`: provenance, source, kind, target hash, host/domain, claimed brand, strength, confidence, expiry, cap, policy version.
- `EvidenceSnapshot`: scanId, input type, primary/final URL, redirect chain, claimed brands, source states, signals, conflicts, redaction report, registry ref, async completeness, policy version.
- `GateResult`: decision, user label, reasons, recommended steps, evidence chips, technical details, conflicts, final/provisional state.
- `OfficialDomainEntry`: brand, official domains, delegated providers, tracking domains, payment providers, neverAskFor rules, version, freshness.
- `ScenarioEvidence`: scenario family/kind, requested assets, impersonated role, reliability, max text-only decision.

Raw input storage defaults to false. Use hashes/redacted summaries for diagnostics.

## EvidenceGate Laws

EvidenceGate este precedence/cap-based, nu score-based.

Hard laws:

- RAG cannot decide.
- Text keywords cannot decide hard danger alone.
- Hidden links cannot decide hard danger alone.
- Tracking links cannot decide hard danger alone.
- User feedback cannot decide hard danger until anti-abuse, review and TTL exist.
- Corpus similarity cannot decide hard danger alone.
- Web Risk no-match does not mean safe.
- urlscan clean does not mean safe.
- VirusTotal no detection does not mean safe.
- Official domain reduces false positives, but is not an absolute whitelist.
- Negative evidence never cancels positive dangerous evidence automatically.
- Same evidence + same policy version + same registry version must produce same decision.

## Decision Precedence

EvidenceGate evaluates in this order:

1. Hard malicious evidence -> `DO_NOT_CONTINUE`.
2. APK / sideload / remote access compound -> `DO_NOT_CONTINUE`.
3. Brand impersonation + unofficial/lookalike domain + secret/payment collection -> `DO_NOT_CONTINUE` or `NO_ENTER_DATA`.
4. Romanian scenario + URL + sensitive/unofficial destination -> `DO_NOT_CONTINUE` or `NO_ENTER_DATA`.
5. Text-only direct reply secret/money request -> `NO_REPLY`.
6. Known bad reply contact -> `NO_REPLY`.
7. Weak/ambiguous/marketing/tracking-only evidence -> `VERIFY_OFFICIAL`.
8. Incomplete scan/provider failure/low confidence extraction -> `INSUFFICIENT_EVIDENCE`.
9. Recognized official/delegated marketing flow with enough benign coherence -> `CONTINUE_WITH_CAUTION`.

## Can Produce `DO_NOT_CONTINUE`

Only these can produce `DO_NOT_CONTINUE` directly or as a high-confidence combination:

- Google Web Risk match for malware/social engineering/unwanted software.
- urlscan verdict malicious/phishing/malware/credential harvesting.
- VirusTotal malicious quorum when used as fallback under production license/policy.
- Confirmed bad URL/domain/contact from curated corpus with TTL and governance.
- Brand impersonation plus unofficial/lookalike final domain plus sensitive action.
- APK/sideload/remote access request in investment/bank/support/courier context.
- Official domain plus hard malicious provider result, with conflict logged for review.

## Can Produce `NO_ENTER_DATA`

Use `NO_ENTER_DATA` when the safest user action is not to enter secrets, even if we cannot prove malware/phishing conclusively:

- card/CVV/OTP/password/login/CNP/IBAN/payment request on unofficial or unvalidated domain;
- form action goes to unofficial or unrelated domain;
- marketplace `ca sa primesti banii` flow asks for card/OTP;
- bank/courier/ANAF/eMAG/Revolut claim asks for sensitive data outside official/delegated domain;
- urlscan clean or Web Risk no-match exists, but structural sensitive risk remains.

## Can Produce `NO_REPLY`

`NO_REPLY` is first-class because many Romanian scams are text-only:

- telefon stricat / numar nou + bani/cod/date;
- accident / nepot la ananghie + bani urgent;
- WhatsApp verification/device linking code request;
- BNR/banca/politie + `cont sigur` / credit fraudulos / transfer;
- message asks the user to reply with OTP, password, card data, CNP, IBAN or money transfer.

Text-only should not produce `DO_NOT_CONTINUE` unless a confirmed bad contact/campaign policy explicitly allows it. The user action is still firm: `Nu raspunde`.

## Can Produce `VERIFY_OFFICIAL`

These are capped at `VERIFY_OFFICIAL` unless combined with stronger evidence:

- marketing urgency: `voucher`, `premiu`, `reducere`, `ultima sansa`, `nu rata`;
- HTML button link;
- hidden link under button/image;
- tracking link;
- shortener without final resolution;
- redirect chain without bad final destination;
- brand mention without verified final URL;
- oferta/campanie promotionala pe domeniu oficial, dar neconfirmata de claim verifier;
- corpus similarity only;
- raw user report;
- low-confidence OCR;
- provider clean/no-match without benign coherence.

## Can Produce `CONTINUE_WITH_CAUTION`

`CONTINUE_WITH_CAUTION` is allowed only when all are true:

- final URL is known;
- final registered domain is official or delegated/partner for the claimed brand;
- official registry entry is valid and fresh enough;
- no sensitive form/action on unofficial destination;
- no hard malicious provider signal;
- no unresolved high-risk conflict;
- redaction did not remove critical evidence;
- provider states are sufficient for the current risk level.
- daca mesajul promoveaza o oferta/campanie/catalog/voucher, claim verifier-ul nu a ramas `not_found` sau `inconclusive`; pentru `Sigur` vrem confirmare explicita a contextului.

Never default to `CONTINUE_WITH_CAUTION`.

## Can Produce `INSUFFICIENT_EVIDENCE`

Use `INSUFFICIENT_EVIDENCE` when the app cannot verify responsibly:

- no usable URL and no strong text-only scenario;
- OCR low confidence;
- only webmail shell/app wrapper was scanned;
- redaction removed critical URL/form/context;
- Web Risk/urlscan unavailable and local evidence is neutral;
- async provider still pending and current evidence is not enough for a final label.

## Provider Policy

### Google Web Risk

Web Risk is the fast commercial-safe reputation source.

- match can produce `DO_NOT_CONTINUE`;
- no-match is not benign proof;
- query threat types: `MALWARE`, `SOCIAL_ENGINEERING`, `UNWANTED_SOFTWARE`, plus `SOCIAL_ENGINEERING_EXTENDED_COVERAGE` when enabled/allowed;
- run fast lookup on `primaryUrl`, then re-check `finalUrl` if redirect resolution changes host;
- cache by provider expiry;
- keys should live server-side/proxy for production.

### urlscan

urlscan preview is the product moat.

- submit only sanitized primary URL by default;
- use `private` by default;
- `unlisted` only when `private` is unavailable and the URL is redacted/no sensitive token remains;
- never submit `public`;
- cache/backoff for 404 pending, 429, timeouts;
- treat 404 during scan window as `PENDING`, not clean/error;
- treat 410 as unavailable/deleted result, not clean;
- parse final URL, redirect chain, screenshot/preview, forms, phishing/malware verdict;
- never send raw email or text body;
- redaction must remove tokens, PII, session IDs and auth-like query params.

### VirusTotal

VirusTotal is fallback/intensifier, not default every scan.

- run only for URL/domain/hash with high-risk context, provider conflict, urlscan unavailable/unclear or user-requested extended analysis;
- do not use VirusTotal Public API in commercial production;
- if VT remains in production, use Premium/Private Scanning/contract compatible mode;
- if licensing is not ready, VT is disabled in Launch Candidate v1 without blocking launch;
- one or low suspicious detections do not override official/structural context alone.

### RAG / AI

RAG runs after EvidenceGate.

- input: `GateResult` + redacted evidence summary;
- output: explanation, user copy, next steps;
- cannot change decision/action;
- cannot invent brand/domain/official status;
- cannot escalate marketing/corpus similarity to hard danger.

## Official Domains Registry

The registry prevents false positives. It is not a universal allowlist.

Each entry should include:

- brand/institution names and aliases;
- official domains;
- delegated providers;
- tracking domains and final fallback rules;
- payment processors where legitimate;
- `neverAskFor` rules;
- country/context notes;
- version/freshness/signature status.

Initial scope:

- ANAF / SPV / MF;
- FAN Courier / selfawb / FANbox;
- Posta Romana;
- eMAG;
- OLX;
- Revolut;
- BT, BCR, ING;
- Uber, Bolt;
- Glovo/Tazz.

If registry is stale or invalid, it cannot produce `CONTINUE_WITH_CAUTION` alone.

## Romania Scenario Corpus

The corpus is deterministic taxonomy, not RAG.

Launch Candidate v1 should prioritize:

- `FAMILY_NEW_PHONE`;
- `FAMILY_EMERGENCY_MONEY`;
- `ACCIDENT_OR_NEPHEW_AI_VOICE`;
- `WHATSAPP_TAKEOVER_VOTE`;
- `WHATSAPP_TAKEOVER_PETITION`;
- `COURIER_LOCKER_OR_ADDRESS_UPDATE`;
- `BNR_SAFE_ACCOUNT`;
- `FAKE_CREDIT_AUTHORITY_CHAIN`;
- `HIDROELECTRICA_INVESTMENT`;
- `CRYPTO_BROKER_INVESTMENT`;
- `MARKETPLACE_RECEIVE_MONEY`;
- `REMOTE_ACCESS_APP_INSTALL`;
- `APK_OR_SIDELOAD`.

Source policy:

- DNSC, Politia Romana, SigurantaOnline, ARB, Mastercard and brand warnings can seed reliable patterns.
- Reddit/community cases can seed test cases and pattern discovery only.
- Absence from corpus never means safe.
- Corpus exact bad URL/domain/contact needs TTL, source, review and anti-abuse before hard danger.

## Backend / Proxy Requirements

For production, API keys and third-party orchestration should not live in the APK.

Backend responsibilities:

- normalize provider outputs into `EvidenceSignal`;
- run Web Risk/urlscan/VT with cache and backoff;
- keep provider API keys server-side;
- enforce urlscan visibility and redaction;
- maintain official registry versions;
- expose source states and async status;
- avoid raw input storage by default;
- log rule IDs/source status/latency/conflicts without raw PII.

Android may keep a local offline gate/ruleset for fast fallback, but production threat providers should be proxied.

## UI Requirements

Result screen must be action-first:

- big user label at top;
- final domain/claimed brand when known;
- secure preview near top when available;
- 1-3 simple reasons;
- 1-3 next steps;
- evidence chips;
- provisional/final state;
- technical details collapsed behind `Arata detalii tehnice`.

If async analysis is pending, show:

```text
Verificarea sandbox poate actualiza rezultatul.
```

Do not show `Poti continua cu prudenta` while critical analysis needed for benign coherence is still pending.

Async monotonicity:

- `INSUFFICIENT_EVIDENCE` can upgrade to any verdict when evidence arrives.
- `VERIFY_OFFICIAL` can upgrade to `NO_ENTER_DATA` or `DO_NOT_CONTINUE`.
- `CONTINUE_WITH_CAUTION` can upgrade to `VERIFY_OFFICIAL`, `NO_ENTER_DATA` or `DO_NOT_CONTINUE`.
- `DO_NOT_CONTINUE` and `NO_ENTER_DATA` do not auto-downgrade silently in the same scan session.
- Downgrading a strong verdict requires manual re-scan or review.

## Privacy And Play Compliance

Manifest must avoid restricted or unnecessary permissions:

- no SMS/Call Log;
- no Notification Listener;
- no Accessibility;
- no broad media/storage;
- no `QUERY_ALL_PACKAGES`;
- no `MANAGE_EXTERNAL_STORAGE`;
- no background scraping.

Permission minimization for v1:

- avoid `POST_NOTIFICATIONS`;
- avoid broad media permissions by using Android Photo Picker / SAF;
- prefer Google Code Scanner / Document Scanner for QR/OCR if feasible, so the app may avoid `CAMERA`;
- if `CAMERA` stays in v1, it must be QR/OCR-only, runtime-requested and user-initiated.

Privacy Policy and Data Safety must disclose:

- user-initiated scans only;
- backend processing if used;
- data sent to Google Web Risk, urlscan, VirusTotal and AI provider if enabled;
- urlscan private/unlisted screenshot/DOM metadata;
- retention/deletion;
- no sale of data;
- no advertising profiling.

Store listing must not claim absolute protection or official affiliation with ANAF/FAN/eMAG/banks.

## Implementation Order

1. Add final data models or adapt current models to `EvidenceSignal`, `EvidenceSnapshot`, `GateResult`.
2. Implement `EvidenceGate` as a pure deterministic function.
3. Add cap/precedence policy for each signal kind.
4. Add official registry with delegated providers and freshness.
5. Add Romania scenario detector for text-only and URL+scenario combos.
6. Normalize existing local rules/Web Risk/urlscan/VT into `EvidenceSignal`.
7. Make RAG/explanation post-gate only.
8. Update Result UI to the six final labels and final/provisional states.
9. Move production provider keys/orchestration behind backend/proxy.
10. Complete privacy, manifest and store-listing audit.

## Acceptance Tests Required

At minimum, include these before release sign-off:

- Uber real promo -> `CONTINUE_WITH_CAUTION`.
- eMAG newsletter real -> `CONTINUE_WITH_CAUTION`.
- FAN real tracking -> `CONTINUE_WITH_CAUTION`.
- Bank newsletter real -> `CONTINUE_WITH_CAUTION`.
- Tracking link without final URL -> `VERIFY_OFFICIAL`.
- Promo text-only without URL -> `VERIFY_OFFICIAL` or `INSUFFICIENT_EVIDENCE`, never hard danger.
- ANAF fake payment/card form -> `DO_NOT_CONTINUE` or `NO_ENTER_DATA` based on evidence.
- FAN fake tax/card -> `DO_NOT_CONTINUE` or `NO_ENTER_DATA`.
- Revolut fake OTP/login form on unofficial domain -> `NO_ENTER_DATA` or `DO_NOT_CONTINUE`.
- APK remote access -> `DO_NOT_CONTINUE`.
- Web Risk malware/social engineering -> `DO_NOT_CONTINUE`.
- urlscan malicious + Web Risk no-match -> `DO_NOT_CONTINUE`.
- VT malicious quorum fallback -> `DO_NOT_CONTINUE`.
- VT one stale suspicious engine + official domain -> not hard danger.
- urlscan clean + card form unofficial -> `NO_ENTER_DATA`.
- Web Risk no-match + structural sensitive risk -> `NO_ENTER_DATA`.
- Hidden button link only -> `VERIFY_OFFICIAL`.
- Hidden/tracking link final official -> `CONTINUE_WITH_CAUTION`.
- Raw user report only -> `VERIFY_OFFICIAL`.
- Corpus similarity-only -> `VERIFY_OFFICIAL`.
- RAG says scam only -> max `VERIFY_OFFICIAL`; Gate ignores RAG.
- urlscan down + Web Risk unavailable + neutral local -> `INSUFFICIENT_EVIDENCE`.
- Webmail shell only -> `INSUFFICIENT_EVIDENCE`.
- OCR low confidence -> `INSUFFICIENT_EVIDENCE`.
- Official domain + hard malicious provider conflict -> `DO_NOT_CONTINUE` + review.
- Delegated payment provider verified -> `CONTINUE_WITH_CAUTION`.
- Unknown payment provider -> `NO_ENTER_DATA`.
- Shortener only no final -> `VERIFY_OFFICIAL`.
- Text-only asks OTP by reply -> `NO_REPLY`.
- Text-only vague OTP/card keyword without reply/contact -> `VERIFY_OFFICIAL`.
- Telefon stricat + numar nou + cere bani -> `NO_REPLY`.
- Accident/nepot + bani urgent -> `NO_REPLY`.
- WhatsApp vote/petition + verification code -> `NO_REPLY` or stronger if URL/form evidence exists.
- FANBOX/locker + unofficial domain without data request -> `VERIFY_OFFICIAL`.
- FANBOX/locker + unofficial domain + card/CVV -> `NO_ENTER_DATA` or `DO_NOT_CONTINUE`.
- BNR/politie/banca + `cont sigur` -> `NO_REPLY`.
- Hidroelectrica/investitii + formular date/card -> `NO_ENTER_DATA`.
- Broker/crypto + AnyDesk/remote access -> `DO_NOT_CONTINUE`.
- Marketplace/OLX `ca sa primesti banii` + card/OTP -> `NO_ENTER_DATA` or `DO_NOT_CONTINUE` if URL/form unofficial.

Each critical fixture should run in three modes:

- `FULL_ONLINE`: all provider adapters available.
- `DEGRADED_PROVIDER`: urlscan/Web Risk/VT timeout, 404/410/429, queued or unavailable cases.
- `LOCAL_ONLY`: backend down/offline local policy.

Each acceptance test must assert:

- exact action;
- stable decisive signal IDs;
- exact user headline.

## Open Decisions

These must be resolved while implementing, not by adding more speculative docs:

- exact enum names aligned with current Android code;
- whether Android and backend share policy through signed JSON or duplicated versioned Kotlin/spec;
- production VT license/API path;
- whether `NO_REPLY` is implemented immediately as a first-class internal status or mapped temporarily in UI;
- first signed registry version and ownership workflow;
- urlscan private availability, cost and rate limits;
- whether OCR stays local-only in Launch Candidate v1.

## Final Rule

When uncertain, choose the safer non-absolute action:

```text
Nu pot verifica suficient
```

or

```text
Verifica pe canalul oficial
```

Do not invent safety. Do not invent danger. Show what the link really does and what the user should do next.
