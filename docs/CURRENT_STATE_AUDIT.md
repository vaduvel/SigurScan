# SigurScan Current-State Audit

**Date:** 2026-06-04

**Scope:** Baseline audit before continuing the master sprint roadmap. This document checks whether the current SigurScan code already follows the new architecture: user input -> extraction -> provider pillars -> knowledge/corpus/RAG context -> deterministic gate -> simple user verdict.

## Executive Verdict

SigurScan is already much closer to the target architecture than the older discussions suggested. The important pieces exist in the correct project:

- Android native app is under `/Users/vaduvageorge/AndroidStudioProjects/SigurScan`.
- Backend is under `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/backend`.
- `EvidenceGate` is the single final gate on Android.
- urlscan/Web Risk/VT/claim verifier are modeled as provider states.
- VT is not mandatory for clean official URLs when policy skips it.
- Backend has orchestrated scan tests that wait for urlscan preview before returning a safe result.
- Romania knowledge layer is present on both Android and backend.

The next work should therefore not invent another gate. It should tighten the existing pipeline, tests, UI, and live smoke verification.

## What Is Already Good

### Provider Pillar Contract

Files:

- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/app/src/main/java/ro/sigurscan/app/EvidenceGate.kt`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/app/src/main/java/ro/sigurscan/app/EvidenceSignalNormalizer.kt`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/app/src/main/java/ro/sigurscan/app/ScannerViewModel.kt`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/backend/main.py`

Current behavior:

- URL-bearing snapshots require Web Risk and urlscan as required pillars.
- Claim verifier becomes required when a message claims a brand/offer or contains claim-like marketing/context signals.
- VT is a fallback/extra provider, not a hard blocker for every clean official URL.
- Pending provider state returns `INSUFFICIENT_EVIDENCE`/`Suspect` as provisional, not `Sigur` or `Periculos`.
- Local-only completeness returns insufficient evidence for URL-bearing scans.

Why this matters:

- It prevents the YOXO/SMYK/eMAG false-positive failure mode where local text rules panic before provider scans finish.
- It prevents fake certainty when urlscan/Web Risk did not run.

### Backend Orchestrated Scan

Files:

- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/backend/main.py`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/backend/test_backend.py`

Current behavior covered by tests:

- Official clean YOXO flow stays `scanning` while urlscan preview is pending.
- Clean flow completes as `SIGUR` only after urlscan result/preview is available.
- urlscan result without screenshot keeps scan pending.
- Backend provider gate can mark clean official destination as low risk without VT.

Why this matters:

- This matches the product rule that the preview of the final URL is a star feature, not optional decoration.

### Knowledge Layer

Files:

- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/app/src/main/java/ro/sigurscan/app/SigurScanKnowledgePack.kt`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/app/src/main/java/ro/sigurscan/app/ScamKnowledgeLayer.kt`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/backend/data/brand_knowledge_pack.json`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/backend/data/scam_atlas_seed.json`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/backend/services/offer_claim_verifier.py`

Current behavior:

- Official registry, brand warnings, claim verifier targets, and Romania scenario corpus exist.
- Backend knowledge is generated from Android knowledge.
- Claim verifier has tests for YOXO and iDroid-like service status.

Why this matters:

- New research can be merged into the existing knowledge pack instead of creating a second brain.

## Risks Still Open

### Risk 1: Final UI Can Still Feel Like "Suspect" Instead Of "Still Scanning"

The gate returns `INSUFFICIENT_EVIDENCE` with `PROVISIONAL` finality while providers are pending. This is technically correct, but the user-facing UI must make it feel like "scanarea inca ruleaza", not a final accusation.

Needed:

- Result UI must distinguish provisional scanning state from final `SUSPECT`.
- User should see "Se scaneaza linkul final..." until provider pillars complete.

### Risk 2: Android Monolith Makes Safe UI Changes Hard

Files:

- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/app/src/main/java/ro/sigurscan/app/MainActivity.kt`
- `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/app/src/main/java/ro/sigurscan/app/ScannerViewModel.kt`

Current issue:

- `MainActivity.kt` and `ScannerViewModel.kt` are very large.
- This makes UI/result-state changes riskier than they should be.

Needed:

- Do not start with Hilt/Room.
- First extract result UI and scan input UI into focused components after pipeline tests are stable.

### Risk 3: Provider Pending States Are Conservative

Current behavior:

- Android initial pending assessment marks all online providers as pending while backend orchestration starts.

This is safe because it prevents early verdicts, but it may be overly conservative. The backend's `pillars` response should become the source of truth as soon as it arrives, especially for `not_required` VT or claim verifier states.

Needed:

- Keep initial pending state conservative.
- Ensure response pillars replace preliminary pending states correctly.
- Add tests for `not_required` claim verifier and VT not blocking `SIGUR`.

### Risk 4: Live Provider Smoke Is Still Limited

Current behavior:

- There are backend/unit tests and prior live smoke notes.
- There is no fresh live smoke report after the latest roadmap.

Needed:

- Run a capped provider live smoke pack with 5-10 safe cases.
- Do not run fixture packs against live providers.

### Risk 5: Store/Production Security Still Needs Final Audit

Known areas:

- Supabase RLS and anon access.
- Backend rate limits/API key requirements in production.
- Privacy Policy/Data Safety disclosures.
- No accidental secrets in APK.

Needed:

- Complete Sprint 9 before any public launch.

## Recommended Next Action

Start with Sprint 1 from `/Users/vaduvageorge/AndroidStudioProjects/SigurScan/docs/SIGURSCAN_MASTER_SPRINT_ROADMAP.md`.

Concrete first implementation target:

1. Add focused tests for provider `not_required` / `SKIPPED` behavior.
2. Add tests proving URL-bearing text cannot become final `Periculos` or `Sigur` from local/corpus evidence while Web Risk/urlscan are pending.
3. Improve UI copy for provisional state so the user sees "Se scaneaza", not a final "Suspect".

This work does not depend on the incoming research pack and prevents the most expensive product failure: false positives from incomplete evidence.

