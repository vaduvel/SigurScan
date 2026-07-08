# ANAF CUI verification for payment_destination_registry

Cross-checks every CUI in `backend/data/payment_destination_registry/*.json`
against the official ANAF VAT-payer web service (source of truth for CUI, legal
name, and active/radiat status). Motivated by the Altex false-positive, where the
seed carried a wrong CUI (`13831166` instead of the real `2864518`).

## Why
Seed freshness metadata (`generated_at`, `reverify_interval`) proves *when* a row
was written, not that the CUI is *correct*. This is the "verificăm, nu presupunem"
check against ANAF.

## Requirements
- Python 3 stdlib only (no pip).
- Outbound network to https://webservicesp.anaf.ro (public, no auth/token).

## Run
```bash
# Full verification (calls ANAF)
python3 backend/tools/verify_registry_cui_anaf.py \
  --dir backend/data/payment_destination_registry \
  --out-json cui_verification_report.json \
  --out-csv cui_discrepancies.csv

# Offline: just extract the CUI list, no network
python3 backend/tools/verify_registry_cui_anaf.py \
  --dir backend/data/payment_destination_registry \
  --offline-extract-only --out-json cui_extract.json
```

## Output
- `cui_verification_report.json` — summary + per-entry results.
- `cui_discrepancies.csv` — only the rows needing attention.

Status codes:
- `OK` — CUI found in ANAF, active, name matches.
- `CUI_NOT_FOUND_IN_ANAF` — CUI not returned (invalid / typo / radiat).
- `INACTIVE_OR_RADIATED` — entity flagged inactive/radiat by ANAF.
- `NAME_MISMATCH` — ANAF denumire differs from the registry `legal_name`.

## CI wiring (R4)
- **Scheduled real check:** `.github/workflows/anaf-cui-verify.yml` runs this tool
  weekly (+ manual dispatch) with `--fail-on-discrepancy`, uploading the report as
  an artifact. It is off the PR/push path on purpose — the ANAF call needs network
  and is rate-limited, so gating unrelated PRs on it would be flaky.
- **Deterministic guard (normal CI):** `backend/test_anaf_cui_verification.py`
  exercises the checker logic offline (mocked ANAF), including the "broken CUI ⇒
  non-zero exit" gate, so the tool itself can't regress silently.
- `--fail-on-discrepancy` makes the tool exit `1` when any entry is not `OK`.

## ANAF API
`POST https://webservicesp.anaf.ro/api/PlatitorTvaRest/v9/tva` (the VAT-payer
service; **not** `v9/persoana`). Body `[{"cui": <int>, "data": "YYYY-MM-DD"}]`,
max 100 CUIs/request, ~1 req/s. Public, no auth/token.

## Notes / next steps
- Read-only. It does NOT write back to the registry.
- Known first fix once verified: Altex CUI `13831166` → `2864518`.
- Consider wiring this as an ANAF verification step into
  `backend/services/public_payment_destination_crawler.py`, which currently only
  self-compares source vs parsed CUI (`no_public_iban_owner_lookup: true`).
