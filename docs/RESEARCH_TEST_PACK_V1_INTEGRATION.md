# SigurScan Research Test Pack v1 Integration

**Source ZIPs:**

- `/Users/vaduvageorge/Downloads/sigurscan_research_test_pack.zip`
- `/Users/vaduvageorge/Downloads/sigurscan_ro_research_test_pack_2025_2026_v1.zip`

**Imported as test resources:**

- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/app/src/test/resources/research/sigurscan_research_test_pack_v1/`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/app/src/test/resources/research/sigurscan_ro_research_test_pack_2025_2026_v1/`

## What The Pack Contains

- `official_registry_updates.json`: 20 official registry candidate entries.
- `brand_warnings.json`: 10 brand/public warning entries.
- `scenario_corpus.json`: 12 Romania scenario corpus cases.
- `false_positive_guard_tests.json`: 10 cases that must not become `PERICULOS`.
- `html_email_parser_torture_tests.json`: 15 parser torture cases for hidden/obfuscated links.
- `live_provider_smoke_tests.json`: 13 live provider smoke cases.
- `source_index.json`: 26 source references with confidence/classification.

Additional RO 2025-2026 pack:

- `official_registry_updates.json`: 24 records.
- `brand_warnings.json`: 16 records.
- `scenario_corpus.json`: 21 records.
- `false_positive_guard_tests.json`: 50 cases.
- `html_email_parser_torture_tests.json`: 40 parser torture cases.
- `live_provider_smoke_tests.json`: 20 safe live provider smoke cases.
- `source_index.json`: 41 source references.

## What Was Integrated Now

### HTML Parser Torture Tests

Test file:

- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/app/src/test/java/ro/sigurscan/app/ResearchPackHtmlParserTest.kt`

The runner now loads both research packs and supports both schemas:

- object root with `tests`
- list root with `test_id`, `html_mime_fragment`, and `expected_extracted_targets`

Coverage:

- display-vs-href mismatch
- button link
- punycode
- homoglyph host
- zero-width host obfuscation
- data URI redirect
- meta refresh
- JavaScript redirect
- hidden form action
- tracking-only email
- nested redirect parameter
- BIDI-cleaned URL
- multiple anchors with actionable phishing CTA
- entity encoded host
- IP literal host

Implementation impact:

- `HtmlLinkExtractor` now extracts generic nested redirect targets from query parameters such as `url`, `redirect`, `target`, `destination`, `next`, `continue`, `to`, `link`, and `href`.
- This matters because phishing and marketing redirects often hide the real destination inside query params, not only in known wrappers like Google/Facebook/Microsoft.

### False-Positive Guard Tests

Test file:

- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/app/src/test/java/ro/sigurscan/app/ResearchPackFalsePositiveGuardTest.kt`

The runner now loads both research packs and supports both schemas:

- object root with `tests`, `input`, and `present_signals`
- list root with `test_id`, `sample_text`, `expected_extracted_targets`, and `expected_final_verdict`

Coverage:

- bank newsletter with tracking CTA
- normal marketing message
- real courier tracking
- young official subdomain
- redirect ending on official domain
- article path containing brand keyword
- non-brand IDN/punycode host
- unsubscribe link
- first-party login form on official bank domain
- legit OLX listing

Current assertion:

- None of these cases may return a dangerous action (`DO_NOT_CONTINUE`, `NO_ENTER_DATA`, `NO_REPLY`).

Why not assert all as `SIGUR`:

- Some cases may correctly remain `SUSPECT` if claim verification is missing, tracking domain is not approved, or evidence is incomplete.
- The hard requirement is anti-false-positive: marketing/tracking/button/brand keyword alone must never become `PERICULOS`.

## What Is Not Integrated Yet

### Official Registry Updates

The current runtime knowledge pack and the research packs overlap. The packs should be used as source-aware merge input, not blindly replacing existing knowledge.

Next action:

- Build a merge tool that compares `brand_id`, official domains, aliases, and `neverAskFor` assets.
- Import only missing or higher-confidence fields.

### Brand Warnings

The current runtime knowledge pack and the research packs overlap. The packs are useful for source cross-checking and scenario coverage, not wholesale replacement.

Next action:

- Add a source-aware merge that preserves official entries and marks community-only warnings as weak.

### Scenario Corpus

The current Android compact corpus and the research packs overlap. The packs are useful as curated regression companions and source-backed scenario additions.

Next action:

- Add scenario corpus comparison tests to ensure official high-confidence scenarios remain represented.

### Live Provider Smoke Tests

The live smoke file is intentionally not run in CI. It should be used manually or nightly with strict rate limits.

Next action:

- Add a backend opt-in smoke runner that requires `SIGURSCAN_RUN_LIVE_PROVIDER_SMOKE=1`.
- Never run `.test`, `.invalid`, or `.example` fixtures against live providers.

## Verification

Commands run after import:

```bash
cd /Users/vaduvageorge/AndroidStudioProjects/SigurScan
JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home" ./gradlew :app:testDebugUnitTest --tests ro.sigurscan.app.ResearchPackHtmlParserTest --tests ro.sigurscan.app.ResearchPackFalsePositiveGuardTest
```

Result:

- `BUILD SUCCESSFUL`

Full regression after parser fix:

```bash
cd /Users/vaduvageorge/AndroidStudioProjects/SigurScan
JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home" ./gradlew :app:testDebugUnitTest
cd backend && pytest -q
```

Result after the RO 2025-2026 pack and live-provider fixes:

- Android unit tests: `BUILD SUCCESSFUL`
- Backend tests: `79 passed`
