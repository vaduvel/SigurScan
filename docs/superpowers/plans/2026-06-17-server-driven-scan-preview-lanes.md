# Server Driven Scan And Preview Lanes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make SigurScan scans stop treating preview generation as part of verdict finalization, then migrate orchestration toward server-driven jobs with read-only status and revision-based long-polling.

**Architecture:** Split the product behavior into a fast verdict lane and a slower preview lane. The patch is backward-compatible: Android stops scan loading when a final verdict arrives and runs only a bounded, non-blocking preview refresh. Backend now has a read-only status contract with revision plus an internal worker endpoint that can be driven by Cloud Tasks so Cloud Run does not depend on in-process background tasks.

**Tech Stack:** Android Kotlin ViewModel/unit tests, FastAPI backend, existing orchestrated scan endpoints, Cloud Run, optional Upstash/Supabase shared state, future Cloud Tasks for preview lane.

---

### Task 1: Android Decouples Verdict Loading From Preview

**Files:**
- Modify: `app/src/main/java/ro/sigurscan/app/ScannerViewModel.kt`
- Modify: `app/src/test/java/ro/sigurscan/app/ScannerViewModelTest.kt`

- [x] **Step 1: Write failing tests**

Change `finalUrlscanPendingPreviewKeepsPollingAfterFinalVerdict` so `shouldContinueOrchestratedPolling(response)` is false for a final verdict with pending preview. Add a separate assertion for a new helper named `shouldRefreshFinalOrchestratedPreview(response)` returning true.

- [x] **Step 2: Run test to verify red**

Run: `JAVA_HOME='/Applications/Android Studio.app/Contents/jbr/Contents/Home' ./gradlew testDebugUnitTest --tests ro.sigurscan.app.ScannerViewModelTest`

Expected: fails because `shouldContinueOrchestratedPolling(response)` still returns true and `shouldRefreshFinalOrchestratedPreview` does not exist.

- [x] **Step 3: Implement minimal Android change**

Make `shouldContinueOrchestratedPolling` ignore preview pending once `result.isFinal == true` and `status == complete`. Add `shouldRefreshFinalOrchestratedPreview` for bounded preview refresh only.

- [x] **Step 4: Run Android tests**

Run: `JAVA_HOME='/Applications/Android Studio.app/Contents/jbr/Contents/Home' ./gradlew testDebugUnitTest`

Expected: build successful.

### Task 2: Smoke Runner Measures Preview Separately

**Files:**
- Modify: `backend/eval/live_provider_smoke_runner.py`

- [x] **Step 1: Write failing test or validate with live report**

Use an existing live scan where first complete payload has `preview.status=pending` and later payload has `preview.status=ready`. The runner must not report `time_to_preview_screenshot_sec=null` if the screenshot becomes ready inside the case budget.

- [x] **Step 2: Implement bounded preview wait**

After final verdict, keep polling only until preview is ready/unavailable or the case budget expires. This is measurement-only; it does not change verdict pass/fail.

- [ ] **Step 3: Run live smoke after deploy**

Run provider smoke against `https://api.sigurscan.com`.

Expected: verdict `5/5`, preview timing populated for cases where screenshot appears.

### Task 3: Backend Read-Only Status Contract

**Files:**
- Modify: `backend/main.py`
- Modify: `backend/test_backend.py`

- [x] **Step 1: Add tests for read-only status response**

Add tests for a status payload shape with `revision`, `verdict_state`, `preview_state`, and `changed`. The compatibility endpoint can still exist, but the new status route must not call `_refresh_orchestrated_job`.

- [x] **Step 2: Implement `/v1/scan/orchestrated/{scan_id}/status`**

Return stored job state only. Support `after_revision` and bounded `wait`, but keep phase one simple with short store polling and no pipeline mutation.

- [x] **Step 3: Run backend tests**

Run: `/opt/homebrew/bin/python3 -m pytest -q test_backend.py test_evaluation_metrics.py`

Expected: pass.

### Task 4: Cloud Tasks Worker Lane

**Files:**
- Modify: `backend/main.py`
- Modify: `backend/test_backend.py`
- Modify: `backend/.env.example`
- Modify: `app/src/main/java/ro/sigurscan/app/SigurScanApi.kt`
- Modify: `app/src/main/java/ro/sigurscan/app/ScannerViewModel.kt`
- Modify: `app/src/test/java/ro/sigurscan/app/ScannerViewModelTest.kt`

- [x] **Step 1: Add internal endpoint contract tests**

`POST /internal/orchestrated/{scan_id}/advance` requires an internal task secret or API key, advances one bounded worker step, and is protected by the existing orchestrated scan lock.

- [x] **Step 2: Enqueue worker task after intake and while not terminal**

Use Cloud Tasks when configured. Do not use `asyncio.create_task` as the production path on Cloud Run. The task payload contains only `scan_id`, not raw user input.

- [x] **Step 3: Add retry/backoff and terminal preview states**

Preview states: `pending`, `ready`, `timeout`, `not_applicable`.

- [ ] **Step 4: Deploy and smoke test**

Deploy Cloud Run, run live provider smoke, then verify Android no longer spins while preview matures.
