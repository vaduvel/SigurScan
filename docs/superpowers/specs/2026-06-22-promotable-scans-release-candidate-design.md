# Promotable Scans Release Candidate Design

## Goal

Ship only scan flows that can be verified end to end on Android and Cloud Run:
the user can enter content, the app extracts the relevant evidence, the backend
returns a final verdict, and every reachable URL gets a non-blocking secure
preview or an explicit terminal explanation.

## Scope Decision

The release-candidate scan set is:

1. Typed or shared text and URLs.
2. QR codes from the camera or an imported image.
3. Shared text, HTML and EML email content.
4. Imported images and PDFs, including OCR and extracted links.
5. Invoice capture from camera, image or PDF, with optional UBL e-Factura XML.
6. Offer text and offer attachments.

Audio-file transcription and live speaker analysis are intentionally excluded
from promoted claims until a real ASR engine is bundled, enabled and verified
on the Nokia device. The app may retain the user-initiated audio intake and
transcript fallback, but it must not claim to analyse raw audio yet.

## Options Considered

### A. Promote every visible tile now

Rejected. An available intent filter or a screen is not enough if the feature
ends in a local fallback instead of a complete backend evidence pipeline.

### B. Promote only contract-complete scan flows

Chosen. Each flow must prove Android intake, extraction, orchestration, final
verdict rendering, preview handling and terminal error behavior. This keeps
the product honest while preserving the existing shared pipeline.

### C. Test backend routes only

Rejected. The Android app is the product surface. A correct endpoint without
a reachable UI path, correct state transitions and a device check is incomplete.

## Shared Contract

All promoted flows obey the following contract:

1. Android preserves the user-selected content and source channel as evidence.
2. Parsing extracts text, links, QR payloads or invoice fields without creating
   a local guessed risk verdict.
3. The result enters the orchestrated backend path or the invoice-specific
   evidence reducer, never a deprecated final-result shortcut.
4. A provisional backend response is rendered as neutral progress, not a
   risk label. A final response alone renders SAFE, UNVERIFIED, SUSPECT or
   DANGEROUS.
5. A reachable URL receives a preview asynchronously. A final verdict never
   waits for a screenshot. If preview generation terminates without an image,
   the UI names the reason and retains the verdict.
6. Extraction failures are explicit, actionable and neutral. They do not become
   a local SUSPECT or SAFE decision.

## Flow Matrix

| Flow | Android intake | Backend path | Final evidence | Preview rule |
| --- | --- | --- | --- | --- |
| URL/text | paste, type, Share/Process Text | orchestrated | raw text, URLs, source channel | for selected reachable URL |
| QR | camera/imported image | orchestrated with `qr` and `qr_scan` provenance | decoded payload plus extracted URLs | for decoded reachable URL |
| Email | Share or file import of text/HTML/EML | extract then orchestrated | body, sender metadata when available, links | for extracted reachable URL |
| Image/PDF | picker or shared URI | extract then orchestrated | OCR text, PDF annotations, links | for extracted reachable URL |
| Invoice | camera or document; optional XML | invoice orchestrator and invoice truth reducer | issuer, CUI, payment instruction, XML consistency and links | for invoice links; no fake preview requirement when no URL exists |
| Offer | text or attachment intake | offer extraction then orchestrated | claimed offer, payment method, links and channel | for extracted reachable URL |

## Acceptance Gates

Every promoted flow must have all of the following before release:

1. A focused backend contract test for success, malformed or unreadable input,
   and a safety-relevant case.
2. An Android unit test proving the UI routes the evidence to the correct
   backend request and renders terminal states correctly.
3. A clean and a malicious or suspicious fixture whose expected behavior comes
   from independent evidence, not a per-domain exception.
4. A Cloud Run smoke case using active public content or stable official content
   with configured providers. Results are recorded with timestamp and provider
   statuses; unavailable providers are reported rather than silently skipped.
5. An Android device verification for camera or share flows where applicable.
6. No scan can remain in progress after a terminal backend status, and no
   completed result can hide a ready preview.

## Reliability and Product Boundaries

- SAFE requires affirmative evidence according to the relevant reducer. Missing
  beneficiary ownership on an otherwise coherent invoice is guided verification,
  not a fraud accusation.
- DANGEROUS requires a positive fraud conflict or a hard malicious provider
  signal; lack of an OCR field or absent preview is not enough.
- The generic gate cannot overwrite an invoice-truth final result with a soft
  semantic signal.
- Provider errors are visible as evidence gaps and cannot silently become SAFE.
- Privacy sanitization remains in force for persisted jobs and external preview
  submissions; local feed matching may use hashes, never retained raw secrets.

## Execution Order

1. Build an evidence matrix from the existing code and tests for the six flows.
2. Reproduce the first broken contract per flow and add a failing regression test.
3. Repair the smallest shared layer that fixes the contract without per-case
   domain or phrase allowlists.
4. Run backend and Android suites, then Cloud Run and device smoke tests.
5. Publish a release report listing promoted flows, deferred audio, provider
   availability and any remaining non-promotable behavior.

