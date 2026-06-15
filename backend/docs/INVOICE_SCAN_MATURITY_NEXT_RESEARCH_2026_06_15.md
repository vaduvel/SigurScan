# Invoice Scan Maturity - Next Research Pack

Date: 2026-06-15

## Why This Exists

The invoice backend is now strong on IBAN/payment-destination evidence, but the next
production-grade jump is not another random list of IBANs. The next gap is a
controlled golden corpus that proves the product behaves correctly across:

- BEC / invoice-redirection patterns.
- Romanian e-Factura / invoice structure variants.
- OCR/camera degradation.
- Multi-page and multi-IBAN invoices.
- Brand impersonation with a real CUI and a fraudster account.

## High-Value Sources Already Confirmed

### Invoice Redirection / BEC

- BRD cyber-threat guidance:
  `https://www.brd.ro/en/careful-cyber-threats`
  - Product pattern: fraudster compromises or imitates email between partners,
    sends a modified invoice, and asks payment into a new vendor account.
  - Test implication: "new account / changed IBAN / updated invoice" should be
    suspicious; combined with foreign/personal/unknown IBAN should be dangerous.

- Politia Romana / IPJ Galati invoice-fraud guidance:
  `https://gl.politiaromana.ro/files/userfiles/IPJ_Galati/CYBERSCAM/Invoice-fraud-RO.pdf`
  - Product pattern: attacker claims to represent the supplier and asks the
    victim to change bank/payment details.
  - Test implication: known supplier plus changed account wording is never a
    clean SAFE path without independent verification.

- Europol invoice fraud material:
  `https://www.europol.europa.eu/cms/sites/default/files/documents/6_invoice_fraud.pdf`
  - Product pattern: the new account is controlled by the fraudster.
  - Test implication: "noul cont", "date bancare actualizate", "cont nou" are
    high-risk language, especially with unknown/foreign/personal destination.

- FBI Business Email Compromise:
  `https://www.fbi.gov/how-we-can-help-you/scams-and-safety/common-frauds-and-scams/business-email-compromise`
  - Product pattern: apparent vendor sends an invoice with updated payment
    information, but the update is fraudulent.

- ANAF false e-Factura messages:
  `https://static.anaf.ro/static/3/Anaf/20240130140059_mesaje%20false.pdf`
  - Product pattern: ANAF/e-Factura impersonation through false messages, links,
    or attachments.

### Legal / Structural Invoice Requirements

- ANAF invoice type guide:
  `https://static.anaf.ro/static/10/Anaf/Informatii_R/Ghid%20cod%20facturi_final%20v2.9.pdf`
  - Product pattern: invoice type 380 has defined structure/content and payment
    terms can be part of invoice context.

- Ministry of Finance e-Factura technical page:
  `https://mfinante.gov.ro/web/efactura/informatii-tehnice`
  - Product pattern: XML/UBL is the authoritative structured form when available.

- ANAF RO e-Factura guide:
  `https://static.anaf.ro/static/10/Anaf/AsistentaContribuabili_r/Ghid_RO_eFactura.pdf`
  - Product pattern: PDF alone is not the formal electronic invoice; XML is the
    structured artifact. If the app later receives XML, it should parse XML before OCR.

- ANAF invoice/autofactura material:
  `https://static.anaf.ro/static/10/Iasi/material_informativ_09-11-2021.pdf`
  - Product pattern: signature/stamp are not required invoice elements, so absence
    of stamp/signature must not increase risk.

## Rules To Add As Golden Tests

1. Modified invoice / new supplier account.
   - Indicators: "cont nou", "schimbare IBAN", "date bancare actualizate",
     "ignore previous invoice", "updated invoice".
   - Expected: SUSPECT with known company and unknown RO IBAN; DANGEROUS with
     foreign IBAN, personal beneficiary, or vendor-memory mismatch.

2. Real CUI + unknown payment destination.
   - Expected: SUSPECT, not SAFE.
   - Escalate to DANGEROUS only with pressure, sensitive-data request, or known
     fraud/payment mismatch evidence.

3. Real CUI + official IBAN for another brand.
   - Expected: DANGEROUS or strong SUSPECT depending context; never SAFE.

4. Real CUI + personal beneficiary near IBAN.
   - Expected: DANGEROUS.

5. Multiple IBANs on one invoice.
   - Expected: parse all IBANs; primary payment destination should prefer the
     IBAN nearest payment instructions, not random first account.

6. Masked/reference-only IBAN.
   - Expected: never exact-match SAFE; can appear only as reference context.

7. Official high-confidence payment destination, Android/native source, clean CUI.
   - Expected: SAFE is allowed only if readiness/coherence/canal also pass.

8. Official medium-confidence/contextual IBAN.
   - Expected: match as evidence but cannot contribute to SAFE.

9. Invoice with "plata cu cardul pe portal" but no CVV/OTP request.
   - Expected: not `SENSITIVE_DATA_REQUESTED`.

10. Invoice requesting card number/CVV/OTP/PIN.
    - Expected: DANGEROUS.

11. e-Factura/XML available.
    - Expected: structured XML parser should be preferred over OCR text.

12. Poor OCR with missing CUI or missing total.
    - Expected: readiness blocks SAFE; result should explain missing fields.

13. ANAF/e-Factura message asking for payment, bank details, or external links.
    - Expected: DANGEROUS.

14. QR/link payment domain is not aligned with supplier official domain.
    - Expected: DANGEROUS when claimed supplier is known and URL domain is
      unrelated/lookalike.

15. Invoice thread/contact details changed and asks user to confirm using the
    new phone/email from the invoice itself.
    - Expected: SUSPECT; DANGEROUS if combined with new IBAN or pressure.

16. Known supplier, first-time unknown IBAN, no pressure and no history.
    - Expected: UNVERIFIED/SUSPECT, not SAFE.

17. Same supplier/CUI, IBAN identical to verified history, native channel,
    coherent totals, no external pressure.
    - Expected: SAFE can be allowed.

## Payment Registry Delta From Agent Research

Integrated as active backend data:

- `apa_canal_galati`: official invoice-payment accounts from
  `https://www.apa-canal.ro/relatii-clienti/modalitati-de-plata`.
  High confidence; exact matches may contribute to SAFE only with aligned
  issuer/channel/readiness.
- `salubris_iasi`: official invoice-payment accounts from
  `https://salubris.ro/facturarea-serviciilor-de-salubritate/`.
  High confidence; exact matches may contribute to SAFE only with aligned
  issuer/channel/readiness.
- `compania_apa_olt`: contextual accounts from `https://caolt.ro/contact.html`.
  Medium confidence; match is evidence only, not SAFE contributor.
- `retim_ecologic_service`: contextual account from official specimen contract.
  Medium confidence; match is evidence only, not SAFE contributor.
- `emag_ads_dante`: eMAG Ads / merchant-profile account, not general eMAG retail
  invoice payment. Medium confidence; evidence only.

Explicitly not integrated as SAFE whitelist:

- Supercom: official channel-only payment page says payment goes to the account
  mentioned on invoice; no fixed public IBAN.
- eMAG retail: bank transfer is based on proforma/payment flow, no static public
  retail invoice IBAN.
- FAN Courier: no public invoice-payment IBAN; anti-phishing/channel evidence
  only.
- Sameday campaign account: official but not general invoice-payment destination.
- YOXO and Focus Sat: channel-only/card/app flows, no static public invoice IBAN.
- Delgaz/Distrigaz corporate/procurement/contact IBANs: context only; no broad
  customer invoice SAFE whitelist.

## Golden Corpus Shape

Use one fixture per case:

```json
{
  "case_id": "invoice_bec_changed_iban_foreign_001",
  "input": {
    "kind": "ocr_text",
    "source_channel": "email",
    "text": "..."
  },
  "expected_fields": {
    "cui": "12345678",
    "iban": "DE89370400440532013000",
    "all_ibans": ["DE89370400440532013000"],
    "payment_beneficiary": null,
    "total": "5000.00",
    "currency": "RON"
  },
  "expected_flags": [
    "ACCOUNT_CHANGE_LANGUAGE",
    "FOREIGN_IBAN"
  ],
  "expected_verdict": "DANGEROUS",
  "notes": "BEC changed vendor account pattern."
}
```

## Android/OCR QA Checklist

- Camera capture:
  - Single-page invoice, good lighting.
  - Low-light invoice.
  - Glare on glossy paper.
  - Skewed/perspective image.
  - Cropped top where issuer/CUI is missing.
  - Cropped bottom where IBAN/total is missing.
  - Multi-page invoice where CUI is page 1 and IBAN is page 2.

- File upload:
  - Native PDF with embedded text.
  - Scanned PDF image-only.
  - PDF containing payment URL.
  - Very large PDF, should fail gracefully.

- Result UX:
  - Missing fields should say exactly what is missing.
  - Preview/OCR unavailable must not look like an unfinished scan.
  - Official IBAN match should show masked IBAN only.
  - Unknown IBAN should not expose full IBAN client-side.

## Remaining Research Needed

Ask agents/researchers for:

1. 20 official/public examples of invoice-redirection/BEC language in Romanian,
   English, or EU guidance, mapped to regex indicators.
2. 30 synthetic but realistic Romanian invoice OCR snippets covering the checklist.
3. Official e-Factura XML examples or schema examples that can be sanitized into fixtures.
4. More official payment destinations only for gaps, not duplicates:
   - municipal utilities,
   - public institutions,
   - insurance premium payment pages,
   - waste/salubritate providers,
   - rent/admin/building-management invoices if official sources exist.
