# SigurScan Research Coverage Audit - 2026-06-15

Generated from repo state: `b74e1ce`.

Scope:
- `sigurscan_imm_b2b_invoice_fraud_round3_2026_06_15.zip`
- `payment_destination_registry_ro_deepresearch_pass1_2026_06_15.zip`
- RDAP / Cloudflare MX brace-bug note from the handoff

Policy:
- Official complete IBANs go into the positive payment destination registry.
- Brand safety statements without complete official IBANs go into advisory / never-asks knowledge.
- Research signals must be evidence contributors, not separate verdict engines.

## Summary

- B2B Round3 signals represented: `12/12` (`11` full, `1` partial).
- Payment pass1 entities represented: `17/17`.
- RDAP / Cloudflare MX brace bug: `fixed`.

## B2B Round3 Signals

| Signal | Implemented evidence flags | Status |
| --- | --- | --- |
| `osim_trademark_fee_unofficial_sender` | `OSIM_TRADEMARK_FEE_UNOFFICIAL_SENDER` | OK `covered` |
| `legal_demand_payment_to_new_iban` | `LEGAL_DEMAND_PAYMENT_TO_NEW_IBAN` | OK `covered` |
| `domain_renewal_invoice_no_existing_vendor` | `DOMAIN_RENEWAL_INVOICE_NO_EXISTING_VENDOR` | OK `covered` |
| `grant_consulting_fee_before_contract` | `GRANT_CONSULTING_FEE_BEFORE_CONTRACT` | OK `covered` |
| `saas_license_audit_urgent_payment` | `SAAS_LICENSE_AUDIT_URGENT_PAYMENT` | OK `covered` |
| `po_or_overpayment_return_request` | `PO_OR_OVERPAYMENT_RETURN_REQUEST` | OK `covered` |
| `new_vendor_public_procurement_fee` | `NEW_VENDOR_PUBLIC_PROCUREMENT_FEE` | OK `covered` |
| `payroll_or_employee_data_request_via_invoice_thread` | `PAYROLL_OR_EMPLOYEE_DATA_REQUEST_VIA_INVOICE_THREAD` | OK `covered` |
| `official_registry_claim_but_no_provenance` | `OFFICIAL_REGISTRY_CLAIM_BUT_NO_PROVENANCE` | OK `covered` |
| `invoice_attachment_has_payment_link_mismatch` | `PHISHING_LINK_IN_INVOICE_EMAIL, PAYMENT_LINK_UNKNOWN_PSP` | OK `covered_by_generic_payment_link_logic` |
| `urgent_payment_override_no_ticket` | `URGENT_PAYMENT_OVERRIDE_NO_TICKET` | OK `covered` |
| `efactura_or_official_document_mismatch` | `EFACTURA_CLAIM_WITHOUT_DOCUMENT` | PARTIAL `partial_no_xml_diff_engine_yet` |

Notes:
- `efactura_or_official_document_mismatch` is intentionally marked partial: the backend detects missing e-Factura proof, but does not yet compare official XML/PDF content against an email PDF field-by-field.
- `invoice_attachment_has_payment_link_mismatch` is covered by the generic payment-link / anchor-mismatch evidence, not a dedicated one-off flag.

## Payment Destination Pass1

| Entity | Expected layer | Status | Note |
| --- | --- | --- | --- |
| `ppc_energy` | `positive_registry` | OK `present` | positive payment destination registry |
| `eon_energie_romania` | `positive_registry` | OK `present` | positive payment destination registry |
| `hidroelectrica` | `positive_registry` | OK `present` | positive payment destination registry |
| `engie_romania` | `positive_registry` | OK `present` | positive payment destination registry |
| `electrica_furnizare` | `positive_registry` | OK `present` | positive payment destination registry |
| `digi_romania` | `positive_registry` | OK `present` | positive payment destination registry |
| `orange_romania` | `positive_registry` | OK `present` | positive payment destination registry |
| `vodafone_romania` | `positive_registry` | OK `present` | positive payment destination registry |
| `aquatim` | `positive_registry` | OK `present` | positive payment destination registry |
| `apavital_iasi` | `positive_registry` | OK `present` | positive payment destination registry |
| `compania_apa_brasov` | `positive_registry` | OK `present` | positive payment destination registry |
| `ghiseul_ro` | `advisory_never_asks` | ADVISORY `advisory_present` | advisory/never-asks, not safe-contributing IBAN registry |
| `fan_courier` | `advisory_never_asks` | ADVISORY `advisory_present` | advisory/never-asks, not safe-contributing IBAN registry |
| `olx` | `advisory_never_asks` | ADVISORY `advisory_present` | advisory/never-asks, not safe-contributing IBAN registry |
| `banca_transilvania` | `advisory_never_asks` | ADVISORY `advisory_present` | advisory/never-asks, not safe-contributing IBAN registry |
| `bcr` | `advisory_never_asks` | ADVISORY `advisory_present` | advisory/never-asks, not safe-contributing IBAN registry |
| `ing` | `advisory_never_asks` | ADVISORY `advisory_present` | advisory/never-asks, not safe-contributing IBAN registry |

Rejected from positive payment registry:
- `ghiseul_ro`, `fan_courier`, `olx`, `banca_transilvania`, `bcr`, `ing`: pass1 did not provide complete official payment IBANs for these entities. They are intentionally treated as advisory / never-asks knowledge, not as SAFE-contributing destination accounts.

## RDAP / MX Brace Bug

Status: OK `fixed`.

Verified files:
- `backend/services/whois_ssl_signals.py`: RDAP URL is `f"https://rdap.org/domain/{domain}"`.
- `backend/services/redirect_resolver.py`: RDAP and Cloudflare MX URLs are formatted without literal braces.

## Next Coverage Work

1. Add an official XML/PDF e-Factura diff path before marking `efactura_or_official_document_mismatch` as fully covered.
2. Expand pass1 `needs_confirmation` entities only when official complete IBANs or official never-asks statements are available.
3. Keep this audit updated when new research packs are imported.
