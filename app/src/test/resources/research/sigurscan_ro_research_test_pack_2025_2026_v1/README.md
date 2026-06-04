# SigurScan Romania Research/Test Pack 2025-2026 v1

Created: 2026-06-04

This pack is a data/test layer only. It does **not** redesign SigurScan architecture.

## Files

1. `official_registry_updates.json` — official domains/channels and confidence.
2. `brand_warnings.json` — verified/candidate never-ask-for statements.
3. `scenario_corpus.json` — Romanian scam scenario corpus with source links.
4. `false_positive_guard_tests.json` — legitimate or borderline cases that must not become `PERICULOS` just because they look like marketing/tracking/phishing.
5. `html_email_parser_torture_tests.json` — parser extraction stress cases for HTML email.
6. `live_provider_smoke_tests.json` — max 20 safe live provider smoke cases.
7. `source_index.json` — URL, publication/access dates, type, confidence.

## Verdicts

Allowed final verdicts in this pack:

- `SIGUR`
- `SUSPECT`
- `PERICULOS`

## Non-negotiable rules

- Marketing text alone is not `PERICULOS`.
- A link under a button is not `PERICULOS` alone.
- Tracking/redirect links are not `PERICULOS` alone.
- Corpus/RAG similarity-only is max `SUSPECT` unless combined with provider/sandbox/confirmed campaign/domain evidence.
- Community/noisy sources are for pattern discovery and tests only.
- CI scam URLs use reserved `.test`, `.invalid`, `.example` domains.
- Live provider smoke tests use safe official/example/httpbin URLs or skip reserved domains.

## Runtime use recommendation

- Load registry and brand warnings as signal generators.
- Use scenario corpus for corpus/RAG comparison signals, not as final verdict source.
- Use false positive guards in regression tests before shipping any new scoring change.
- Use live smoke tests only for provider integration health checks, rate-limited and not as deterministic regression tests.
