# Invoice Scanner Production Architecture

## Goal

Make invoice scanning useful without overclaiming certainty:

- `DANGEROUS` only on positive fraud evidence.
- Unknown payment destination is not fraud by itself.
- The UI must separate document confidence from payment-destination confidence.
- A confirmed CUI/company does not confirm the IBAN owner.

## Current Building Blocks

### Input and Parsing

- `services/invoice_parser.py`
  - Extracts issuer, CUI/CIF, invoice number, dates, totals, currency, links, QR payloads, IBANs, payment beneficiary text.
  - Produces `InvoiceFields`.
- `services/efactura_xml.py`
  - Parses UBL/e-Factura XML and compares uploaded invoice vs official XML.
  - High value when user provides XML from SPV/e-Factura.
- Android camera/upload flow
  - OCR/photo/PDF path feeds the backend invoice scanner.

### Company Identity

- `services/anaf_cui.py`
  - ANAF direct check: company exists, active/inactive, VAT, e-Factura enrollment.
  - OpenAPI.ro fallback is already gated by `allow_paid_fallback`.
  - This confirms company identity, not IBAN ownership.
- `services/registry_verification/*`
  - Registry verification scaffolding for offer/company checks.
- `services/brand_truth_registry.py`
  - Local brand/legal identity truth where available.

### Payment Destination

- `services/iban_validator.py`
  - IBAN format, MOD-97 checksum, country length, RO bank code, Trezorerie flag.
  - Does not identify owner.
- `services/payment_destination_registry.py`
  - Positive registry of official/known payment destinations.
  - Trust tiers:
    - `T0_PARTNER_SIGNED`
    - `T1_PUBLIC_OFFICIAL`
    - `T2_OFFICIAL_DOCUMENT_CHAIN`
    - `T3_USER_LOCAL_TRUSTED`
    - `T4_STRUCTURALLY_VALID_UNKNOWN`
    - `T5_DANGEROUS_MISMATCH`
  - Only T0/T1/T2 active high-confidence exact matches can contribute to SAFE.
- `services/public_payment_destination_crawler.py`
  - New crawler/extractor for public official pages, PDFs, JSON, XLSX, CKAN/data.gov resources.
  - Produces review candidates by default.
  - Does not auto-promote candidates to SAFE.
- `services/vendor_memory.py`
  - Tracks known CUI -> IBAN history.
  - Detects changed IBAN for previously seen supplier.
- `services/negative_iban_registry.py`
  - Negative IBAN reports / known fraud destinations.
- SANB / BNDS
  - Real Romania payee-name mechanism, but user-assisted or partner/PSP access.
  - Not currently a callable backend provider.

### Fraud / BEC Signals

- `services/b2b_invoice_signals.py`
  - Detects BEC and invoice fraud patterns:
    - changed/new IBAN
    - thread manipulation
    - fake e-Factura/ANAF payment claims
    - urgent/confidential payment instructions
    - supplier impersonation and payroll/employee data asks
- `services/payment_method_classifier.py`
  - Classifies payment method risk, including Trezorerie and other context.
- `services/invoice_coherence.py`
  - Checks structural invoice consistency.
- `services/invoice_readiness_gate.py`
  - Determines whether enough invoice data exists for a meaningful verdict.

### Orchestration and Evidence

- `services/invoice_orchestrator.py`
  - Main invoice scan path.
  - Combines parsed fields, ANAF/OpenAPI, IBAN validation, registry match, negative IBAN, BEC flags, vendor memory, e-Factura comparison.
  - Builds `payment_destination` provider evidence.
  - Builds invoice evidence bundle for gate/verdict.

## Required Product Model

Invoice scan must expose two separate concepts:

1. `document_status`
   - Is this invoice structurally coherent?
   - Does the issuer identity make sense?
   - Does ANAF/OpenAPI confirm the company?
   - Are totals/dates/CUI/issuer consistent?

2. `payment_destination_status`
   - Is the IBAN valid?
   - Is the IBAN confirmed for this issuer?
   - Is it unknown first-seen?
   - Has it changed from known history?
   - Is it known to belong elsewhere or reported negative?

The final user label can stay simple, but the internal model must not collapse these two statuses.

## Payment Destination Confidence

### `authoritative_match`

Sources:

- SANB/BNDS/VoP partner response.
- User-uploaded e-Factura XML from trusted source if payment fields match invoice.
- Signed partner feed.

Effect:

- Can contribute to SAFE.
- Can downgrade mismatch to DANGEROUS.

### `strong_match`

Sources:

- T0/T1/T2 active exact match from `payment_destination_registry`.
- Repeated local vendor history confirmed by user.

Effect:

- Can contribute to SAFE.
- History mismatch can become SUSPECT/DANGEROUS depending on BEC pressure.

### `public_source_match`

Sources:

- Public official page/document crawled and reviewed.
- Public contract/procurement dataset.

Effect:

- Can raise confidence after review.
- By default crawler output is `needs_review` and cannot contribute to SAFE.

### `unknown_first_seen`

Sources:

- Valid IBAN, company identity coherent, no registry/history match.

Effect:

- Not DANGEROUS.
- Not full SAFE for payment.
- User-facing: "Factura pare in regula, dar destinatia de plata nu a fost confirmata automat."

### `changed_from_history`

Sources:

- Same CUI/supplier seen before with a different IBAN.

Effect:

- SUSPECT by default.
- DANGEROUS if combined with urgent/confidential/new-account wording or channel mismatch.

### `mismatch`

Sources:

- IBAN belongs to a different known entity.
- e-Factura XML/registry/history contradicts printed IBAN.
- SANB/VoP says no-match.

Effect:

- DANGEROUS.

### `reported_negative`

Sources:

- Negative IBAN registry, user reports, OSINT with provenance.

Effect:

- DANGEROUS.

## Verdict Matrix

| Situation | Document | Payment destination | User result |
|---|---:|---:|---|
| Company active, coherent invoice, confirmed official IBAN | OK | Confirmed | SAFE |
| Company active, coherent invoice, valid first-seen IBAN | OK | Unconfirmed | Verifică înainte să plătești, not DANGEROUS |
| Company active, known supplier, IBAN changed | OK | Changed | SUSPECT |
| IBAN changed + urgent/secret/new account wording | Risky | Changed + pressure | DANGEROUS |
| Company inactive/nonexistent + payment request | Bad | Any | DANGEROUS or SUSPECT depending evidence |
| IBAN invalid MOD-97 | Any | Invalid | SUSPECT |
| IBAN reported negative | Any | Negative | DANGEROUS |
| Printed invoice differs from official e-Factura XML | Bad | Mismatch | DANGEROUS |
| Real CUI + IBAN known for another brand/entity | Bad | Mismatch | DANGEROUS |
| Missing CUI/issuer but valid IBAN | Weak | Unknown | UNVERIFIED / needs more data |

## External Providers

### ANAF

Use for:

- Company exists.
- Company active/inactive.
- VAT/e-Factura enrollment where available.

Do not use for:

- IBAN ownership.

### OpenAPI.ro

Use as paid fallback only:

- ANAF failure/timeout.
- High-value invoice.
- Company appears suspicious/ghost-like.
- Need financial/balance-sheet enrichment.

Do not spend quota for:

- Ordinary invoices where ANAF works.
- IBAN ownership; public docs do not show payee-name verification.

### SANB / BNDS / VoP

Use if available:

- Best possible source for beneficiary name vs IBAN.

Current practical path:

- User-assisted SANB:
  - Copy IBAN.
  - Open banking app.
  - Start payment without finalizing.
  - Compare displayed beneficiary name.
  - User marks match/no match/unavailable.

Future path:

- Bank/PSP/TRANSFOND partnership.

## Production-Grade Rules

1. Never mark an invoice DANGEROUS only because IBAN owner is unknown.
2. DANGEROUS requires positive fraud evidence.
3. `Date confirmate` requires payment-destination confidence, not just company identity.
4. Company identity and payment destination are separate statuses.
5. Crawler data is candidate evidence until reviewed or signed.
6. User-local history can protect the same user/org without becoming a global truth source.
7. Full raw IBANs remain backend-only; Android receives masked IBAN/status.
8. Mistral/semantic layer should explain BEC/social-engineering context, not override hard payment mismatch evidence.

## Implementation Phases

### Phase 1: Contract Cleanup

- Ensure invoice API returns:
  - `document_status`
  - `company_identity_status`
  - `iban_structure_status`
  - `payment_destination_status`
  - `payment_destination_confidence`
  - `safe_to_pay`
  - `recommended_action`
- Android must display document verdict and payment-destination warning separately.

### Phase 2: Reframe False Positives

- Change invoice verdict mapping so `unknown_first_seen` is not DANGEROUS.
- Keep IBAN-swap, mismatch, reported negative and fake e-Factura paths DANGEROUS.
- Regression tests:
  - B2B safe controls must not be DANGEROUS.
  - IBAN-swap cases must stay SUSPECT/DANGEROUS.

### Phase 3: Payment Destination Corpus

- Run crawler into review queue.
- Promote only reviewed official sources to active T1/T2.
- Keep public/procurement datasets as medium-confidence/contextual unless manually reviewed.

### Phase 4: User-Local Memory

- Store confirmed supplier IBANs per user/org.
- First seen valid IBAN remains unconfirmed.
- Subsequent changed IBAN triggers warning.
- User can confirm via SANB and mark trusted locally.

### Phase 5: Provider Escalation

- ANAF first.
- OpenAPI.ro fallback only on failures/high-risk/high-value.
- Future VoP/SANB partner provider if feasible.

### Phase 6: Evaluation

- Run offline deterministic suite:
  - safe B2B controls
  - real/fake B2B packs
  - adversarial negation
  - OCR degraded invoices
- Run semantic/Mistral suite with throttling and retries.
- Run live provider smoke on selected hard cases.
