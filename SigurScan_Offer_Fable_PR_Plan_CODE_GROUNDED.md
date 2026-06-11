# SigurScan — „Verifică o ofertă/plată"
## Plan Fable pe PR-uri, ANCORAT ÎN COD (sursa de adevăr: `main` @ commit `2c91b43`)

> Acest document înlocuiește `00_README_FABLE_PR_PLAN.md` ca sursă de adevăr.
> Structura pe PR-uri a rămas cea propusă de GPT-5.5 (e corectă). Diferența: aici fiecare
> PR spune EXACT ce fișier/funcție există deja pe `main` și ce trebuie REFOLOSIT vs EXTINS vs CREAT.
> Regula de aur: **REUSE / EXTEND, NU RECREATE.** Funcția de factură e deja în producție pe `main`.

---

## PARTEA 0 — Ce există DEJA pe `main` (verificat în cod, nu presupus)

Funcția de scanare factură a fost integrată și e funcțională pe `main`. NU o rescrie. O EXTINZI la „ofertă".

### Servicii backend existente (`backend/services/`)

| Fișier | Ce expune | Refolosești pentru ofertă? |
|---|---|---|
| `invoice_parser.py` | `parse_invoice(ocr_text, pdf_links, qr_payloads) -> InvoiceFields` | DA — `OfferFields` EXTINDE `InvoiceFields` |
| `anaf_cui.py` | `async check_cui(cui, data=None) -> CuiResult{exists, checked, denumire, activ, data_inactivare, platitor_tva, enrolled_efactura, raw}` | DA — ca atare |
| `iban_validator.py` | `validate_iban(iban) -> IbanResult{valid_structure, bank_code, bank_name, is_trezorerie}` (MOD-97, `RO_BANK_CODES`) | DA — ca atare |
| `invoice_coherence.py` | `check_coherence(...) -> CoherenceResult{totals_match, tva_rate_plausible, dates_plausible, all_ok}` (`TOTAL_TOLERANCE=0.05`, `PLAUSIBLE_VAT_RATES`) | DA — ca atare |
| `invoice_readiness_gate.py` | `evaluate_readiness(fields, ocr_confidence=None) -> ReadinessGateResult`; `ReadinessState{READY, MISSING, BLOCKED, LOW_CONFIDENCE}`; `verdict_minimum()`; prag `confidence < 0.6` | DA — GENERALIZEAZĂ, nu duplica |
| `brand_registry.py` | `match_brand(...) -> BrandMatchResult{claimed_brand, domain_matches, iban_matches, cui_matches, impersonation_risk}`; `detect_claimed_brand(...)`; `BRAND_REGISTRY` (~40 branduri, doar CUI-uri ANAF-verificate) | DA — **SINGURA sursă de brand pe rutele offer/invoice** |
| `invoice_orchestrator.py` | `async scan_invoice(text, links=..., qr_payloads=...) -> result{fields, readiness, warnings, brand, brand_match, iban_valid, coherence, error}` | DA — **EXTINDE-l, NU face alt orchestrator** |
| `evidence_bundle.py` | `build_evidence_bundle(...)`, `build_evidence_bundle_v2(...)` — fact bundle privacy-safe; NU produce verdict | DA — ca atare |
| `verdict_gate.py` | `verdict as reduce_verdict(...)` — **GATE-UL UNIC**; `HARD_SENSITIVE` | DA — **singurul motor de verdict** |
| `scam_atlas.py` | `ScamAtlasEngine`, `classify_scam_family(text, claimed_brand) -> (family, confidence)`; `BRAND_REGISTRY` propriu (DOAR ruta mesaj/link) | DA — EXTINDE engine-ul pt OP-01..09, NU clasificator paralel |

### Orchestrator (`backend/main.py`)
- Endpoint: `POST /v1/scan/orchestrated` (+ `GET /v1/scan/orchestrated/{scan_id}`).
- Are deja fast-lane pentru factură (`_run_orchestrated_invoice_fast_lane`): apelează `scan_invoice` → `build_evidence_bundle` → `reduce_verdict`. **Un singur Gate.**
- Importă deja `build_evidence_bundle` și `reduce_verdict`.

### Teste (`backend/test_*.py` — NU `tests/`)
- 389/389 trec. `test_anaf_cui.py` (checked True/False, inexistent `date_generale:null`, timeout→fallback, timeout total→`checked=False`), `test_invoice_orchestration.py` (inclusiv `test_scan_deterministic_repeatable`: 2× același input → același rezultat).
- **Orice PR nou adaugă teste în același stil, în `backend/test_*.py`.**

---

## PARTEA 1 — Reguli de aur (obligatorii în toate PR-urile)

```text
1. REUSE / EXTEND, NU RECREATE. Dacă un serviciu există în tabelul de mai sus, importă-l.
2. UN SINGUR GATE: orice verdict trece prin verdict_gate.reduce_verdict. Interzis al doilea motor de scor.
3. UN SINGUR ORCHESTRATOR: extinde invoice_orchestrator.scan_invoice spre offer (sau generalizează-l
   la scan_offer cu input_type offer|invoice). NU crea un orchestrator paralel.
4. OfferFields EXTINDE InvoiceFields (factura e un caz particular de ofertă).
5. BRAND: doar brand_registry.match_brand pe rutele offer/invoice. scam_atlas.BRAND_REGISTRY rămâne DOAR pe ruta mesaj/link.
6. FAMILIE: extinde scam_atlas.ScamAtlasEngine.classify_scam_family pentru OP-01..09. NU al doilea clasificator.
7. READINESS: generalizează invoice_readiness_gate (stările rămân aceleași, pragul 0.6 rămâne).
8. VERDICT user-facing: SIGUR / SUSPECT / PERICULOS. Niciodată „100% sigur".
   - Marketing / preț bun / urgență / logo / PDF frumos = maximum SUSPECT solo.
   - Lipsă în registru = SUSPECT, nu automat PERICULOS.
   - PERICULOS cere COMBINAȚIE de semnale sau dovadă hard.
   - Sursă externă picată (anaf checked=False etc.) NU coboară riscul la SIGUR.
9. PRIVACY: nu stoca CI/CNP/selfie raw. Cache server-side cu HMAC peste câmpuri NON-PII, nu SHA peste PII.
10. LATENȚĂ: POST creează state și răspunde rapid; GET poll avansează muncă incrementală.
    Primul verdict e provizoriu+rapid; enrichment greu (web/reverse image) vine în poll-uri ulterioare.
```

---

## PARTEA 2 — PR-urile, ancorate pe cod

### PR 1 — Offer core: parser + readiness + payment + family + signals
**Branch:** `feature/offer-core-parser-readiness` (din `main`)

**REUSE (importă, nu rescrie):**
```text
invoice_parser.parse_invoice / InvoiceFields
iban_validator.validate_iban
invoice_coherence.check_coherence
invoice_readiness_gate.evaluate_readiness / ReadinessState
```

**EXTEND:**
```text
- OfferFields(InvoiceFields): adaugă issuer_name, issuer_cui (alias peste cui), issuer_registration_no,
  issuer_address, claimed_brand, payment_beneficiary, payment_method, payment_instructions, currency,
  document_type, urls, email_domains, license_number(turism), vin(auto), property_address(chirii),
  event_name(bilete), platform_name, input_type: Literal["offer","invoice"]="offer",
  extraction_confidence, missing_fields.
- offer_readiness: generalizează invoice_readiness_gate ca să accepte oferte fără CUI/total (ex. chirie PF),
  dar PĂSTREAZĂ ReadinessState + pragul 0.6. NU duplica fișierul; extinde-l sau wrap-uiește-l.
```

**CREATE (nu există pe main):**
```text
services/offer_parser.py            # extinde parse_invoice cu câmpurile offer; reuse regex existente
services/payment_method_classifier.py  # scara LOW/MEDIUM/HIGH/CRITICAL (vezi mai jos)
services/family_classifier.py       # WRAPPER subțire peste scam_atlas.ScamAtlasEngine pt OP-01..09 (NU paralel)
services/offer_signals.py           # mapează în semnale OFFER_*
backend/test_offer_parser.py, test_payment_method_classifier.py, test_offer_readiness.py, test_offer_signals.py
```

**Payment method scale (CRITICAL = stop):**
```text
LOW: card/platformă oficială, fără cerere CVV/OTP în document
MEDIUM: transfer către firmă verificabilă; cash la predare/inspecție
HIGH: transfer către PF pentru firmă/hotel/agenție; Revolut/PF/alias; avans înainte de vizionare/livrare
CRITICAL: Western Union / MoneyGram / gift card / crypto / QR crypto / cerere CVV-OTP pentru „primire bani"
```

**Semnale (offer_signals.py):**
```text
OFFER_MISSING_ANCHORS, OFFER_LOW_OCR_CONFIDENCE, OFFER_IBAN_INVALID_STRUCTURE, OFFER_IBAN_TREZORERIE,
OFFER_PAYMENT_METHOD_HIGH_RISK, OFFER_PAYMENT_METHOD_CRITICAL, OFFER_OFF_PLATFORM_PAYMENT,
OFFER_CARD_CVV_OTP_REQUEST, OFFER_ID_DOCUMENT_REQUEST, OFFER_PRICE_URGENCY, OFFER_TOTALS_INCOHERENT,
OFFER_VAT_INCOHERENT, OFFER_DATES_INCOHERENT, OFFER_HAS_QR_PAYMENT, OFFER_HAS_CRYPTO_WALLET, OFFER_FAMILY_CLASSIFIED
```

**DoD:** OfferFields ⊃ InvoiceFields; parser extins; family wrapper peste ScamAtlasEngine; payment scale; readiness generalizat (prag 0.6); semnale; teste verzi; fără calls externe noi.

**Prompt atomic Fable:**
```text
Implement PR1 only on branch feature/offer-core-parser-readiness from main.
REUSE invoice_parser/iban_validator/invoice_coherence/invoice_readiness_gate (they exist on main).
OfferFields must EXTEND InvoiceFields. family_classifier must wrap scam_atlas.ScamAtlasEngine, NOT duplicate it.
No new external calls, no Android, no legal layer, no web/registry. Add tests in backend/test_*.py.
```

---

### PR 2 — ANAF + IBAN context + EvidenceGate combos (ofertă)
**Branch:** `feature/offer-anaf-iban-gate` (din PR1)

**REUSE:** `anaf_cui.check_cui` (cu `CuiResult.checked` — deja corect: timeout→checked=False=UNKNOWN), `iban_validator.validate_iban`, `brand_registry.match_brand`, `verdict_gate.reduce_verdict`, `invoice_orchestrator.scan_invoice` (ca model de orchestrare).

**EXTEND:** `invoice_orchestrator` → suportă `input_type="offer"` (sau `scan_offer` care refolosește aceleași servicii + cele din PR1) și alimentează ACELAȘI `build_evidence_bundle` → `reduce_verdict`.

**CREATE:**
```text
services/offer_entity_verifier.py        # aliniere issuer_name vs CuiResult.denumire (distanță), activ/inactiv
services/offer_evidence_gate_mapper.py   # mapează semnale->intrări pentru reduce_verdict. NU motor nou.
backend/test_offer_entity_verifier.py, test_offer_gate_combos.py, test_anaf_cui_offer.py
```

**Combo-uri PERICULOS (deterministe, prin reduce_verdict):**
```text
CUI inexistent(checked=True)/inactiv + document pretinde firmă + avans/plată
ANAF/stat + IBAN comercial + cerere plată
brand/platformă + plată off-platform + cerere card/CVV/OTP
IBAN invalid + cerere plată + urgență
crypto/gift card/WU/MoneyGram + plată ofertă
cerere CI/CNP/selfie + context credit/contract/rezervare/plată
```
**SUSPECT (nu periculos):** CUI lipsă dar OCR bun; `anaf checked=False`(timeout) + plată high; nume ușor diferit; IBAN valid dar beneficiar neextractibil; doar urgență/preț.

**DoD:** entity verifier; combo-uri mapate prin reduce_verdict; `checked=False` NU → SIGUR și NU → periculos; false-positive guards rămân ne-periculoase; teste verzi.

**Prompt atomic Fable:**
```text
Implement PR2 only on feature/offer-anaf-iban-gate from PR1.
REUSE anaf_cui.check_cui (checked flag), iban_validator, brand_registry.match_brand, verdict_gate.reduce_verdict.
EXTEND invoice_orchestrator for input_type=offer feeding the SAME build_evidence_bundle->reduce_verdict.
Do NOT create a second verdict engine. Add EvidenceGate combos + tests. No web, no Android, no registry snapshots.
```

---

### PR 3 — Android: intrare ofertă + confirmare câmpuri
**Branch:** `feature/offer-android-field-confirmation` (din PR2)

**Scope:** card Home „Verifică o ofertă/plată"; `stageOfferInput()`; `inputType="offer"`; reuse share/file/photo/OCR existente; ecran de confirmare câmpuri (Emitent, CUI, IBAN, Beneficiar, Sumă, Metodă plată, Link/QR, Tip ofertă); reuse ecran verdict.

**Contract minimal pe care îl consumă Android** (backend îl întoarce deja prin orchestrator):
```json
{ "scan_id":"...", "status":"provisional|final|pending",
  "offer_fields":{ "issuer_name":"","issuer_cui":"","iban":"","payment_beneficiary":"",
    "total_amount":"","currency":"RON","payment_method":"","document_type":"","family":"" },
  "result":{ "is_final":false,"verdict":"SIGUR|SUSPECT|PERICULOS","reasons":[],"safe_actions":[] } }
```
**NU:** fără permisiuni noi sensibile (SMS/accessibility/call), fără redesign global, fără monitorizare automată, fără legal layer complet (doar placeholder „Ce spune legea" dacă PR5 nu e gata).

**Copy verdicte:**
```text
SIGUR: Nu am găsit semnale clare de fraudă.
SUSPECT: Verifică pe canalul oficial înainte să plătești.
PERICULOS: Nu plăti. Datele ofertei nu se aliniază sau metoda de plată e riscantă.
```
**DoD:** card Home; `inputType=offer` trimis; ecran confirmare funcțional; verdict cu motive + safe actions; zero permisiuni noi; build/preview compilează.

---

### PR 4 — Registry snapshot adapters (onest)
**Branch:** `feature/offer-registry-snapshots` (din PR2/PR3)

**CREATE:** interfață `RegistryVerificationResult{source_id, status: MATCH|NO_MATCH|INCONCLUSIVE|NOT_CONFIGURED|SOURCE_TIMEOUT|SOURCE_ERROR, confidence, matched_entity_name, ...}` + adaptere.
**P1 reale dacă sursa e simplă:** SITUR (turism), ONRC CSV snapshot, BNR/ASF/ANPC (status onest). **Doar stub `NOT_CONFIGURED`:** ANCPI, RAR Auto-Pass, ITM/ANOFM.
**Reguli:** `NO_MATCH` = max SUSPECT solo; `MATCH` = context, nu safe absolut; `SOURCE_*`/`NOT_CONFIGURED` = neutral-spre-suspect, niciodată safe. Fără date hardcodate fake în producție.
**DoD:** interfață + loader cu metadata sursă + min. o sursă reală sau `NOT_CONFIGURED` explicit + teste match/no_match/error/not_configured.

---

### PR 5 — Legal layer „Ce spune legea" (educativ, determinist)
**Branch:** `feature/offer-legal-layer` (din PR3)

**CREATE:** `services/legal_layer.py` + `backend/data/legal_kb.json` + UI card.
**Reguli:** NU schimbă verdictul; NU inventează articole; întoarce doar carduri din KB; fără mapping → empty. Label UI „Ce spune legea", NU „Jurist"/„Avocat". Disclaimer mereu prezent: „Informații juridice generale, nu sfat juridic personalizat...".
**Trigger→card (exemple):** avans+dispariție→înșelăciune (Cod penal art.244); contract/factură falsă→fals/uz de fals; cerere CI/CNP→risc furt identitate; card/CVV/OTP→fraudă instrumente de plată; off-platform→pierdere protecție platformă.
**DoD:** KB determinist; mapping semnale→carduri; UI title/summary/actions/disclaimer; teste că verdictul NU se modifică.

---

### PR 6 — Web confirm / reverse image ASYNC (P2)
**Branch:** `feature/offer-web-confirm-async` (din PR3/PR4). **NU înainte ca PR1–3 să fie stabile.**

**Scope:** domain compare (document vs domeniu oficial), query templates per familie, source snippets, reverse image DOAR cu provider conform — altfel `NOT_CONFIGURED`.
**Reguli:** nu blochează primul verdict; `not found` = max SUSPECT solo; community/noisy = max SUSPECT solo; domain mismatch + cerere plată = high combo. Fără API plătit, fără queue nou dacă arhitectura nu o suportă deja.
**DoD:** web_confirm întoarce evidence structurat; fără blocare provizoriu; fără verdict hard din surse noisy; reverse image grațios `NOT_CONFIGURED`; teste.

---

## PARTEA 3 — Ce NU se construiește acum (carry din planul GPT)
```text
- reverse image obligatoriu (P2, async, nu decide verdict)
- web search live ca verdict hard (not found != periculos)
- toate registrele într-un PR
- IBAN -> titular real (nu există lookup public sigur)
- legal advice personalizat (doar „Ce spune legea")
- cache cu SHA peste PII (folosește HMAC peste câmpuri non-PII)
- „zero false-positive global" (doar pe false-positive guard set)
```

## PARTEA 4 — Ordinea de merge
```text
PR0  = invoice-scan deja pe main (DONE, commit 2c91b43)
PR1 (din main) -> PR2 -> PR3 -> [PR4, PR5] -> PR6
Fiecare PR: mic, testabil, revert-abil. Nu lucra pe main. Nu merge singur.
```
