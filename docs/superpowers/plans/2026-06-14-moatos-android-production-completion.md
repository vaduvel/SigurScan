# MoatOS Android Production Completion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the backend MoatOS PR-5..PR-8 capabilities into real Android user/device features and create the foundations for PR-9/PR-10 without fake/demo paths.

**Architecture:** Implement one vertical slice at a time. Device-facing capabilities must have a typed API model, persisted local state, deterministic local decision logic, Android UI/manifest integration, unit tests, build verification, and live API smoke where applicable. Call screening must use offline cache only during calls; no network call is allowed in `onScreenCall`.

**Tech Stack:** Kotlin, Jetpack Compose, Retrofit/Gson, Android CallScreeningService/RoleManager, SharedPreferences/EncryptedSharedPreferences, JUnit, FastAPI backend live on Cloud Run.

---

## Task 1: PR-5 Radar Hot-Cache + CallScreening Foundation

**Files:**
- Modify: `app/src/main/java/ro/sigurscan/app/SigurScanApi.kt`
- Create: `app/src/main/java/ro/sigurscan/app/RadarHotCache.kt`
- Create: `app/src/main/java/ro/sigurscan/app/SigurScanCallScreeningService.kt`
- Modify: `app/src/main/java/ro/sigurscan/app/ScannerViewModel.kt`
- Modify: `app/src/main/java/ro/sigurscan/app/MainActivity.kt`
- Modify: `app/src/main/AndroidManifest.xml`
- Create: `app/src/test/java/ro/sigurscan/app/RadarHotCacheTest.kt`

- [ ] **Step 1: Write failing tests for phone normalization, cache freshness, and offline call decision**

Run: `JAVA_HOME='/Applications/Android Studio.app/Contents/jbr/Contents/Home' ./gradlew testDebugUnitTest --tests 'ro.sigurscan.app.RadarHotCacheTest'`

Expected before implementation: compilation fails because `RadarHotCache`, `PhoneNumberHasher`, or decision functions do not exist.

- [ ] **Step 2: Add typed Retrofit models and endpoint**

Add `RadarHotCacheResponse`, `RadarHotCampaign`, `RadarNumberReputation`, and `@GET("v1/radar/hot-iocs") suspend fun getRadarHotIocs(): RadarHotCacheResponse`.

- [ ] **Step 3: Implement offline cache and deterministic call decision**

Rules:
- Normalize RO numbers consistently.
- Hash phone numbers as SHA-256 of normalized phone number.
- Treat exact `phone_hash` hit as `WARN`.
- Treat campaign `phone_hash_prefixes` hit as `WARN`.
- Never auto-reject calls in v1; service may silence only when OS supports it and decision is warn.
- Expired/missing cache returns `ALLOW`.

- [ ] **Step 4: Add CallScreeningService**

Service must:
- Read only local hot-cache.
- Never call network in `onScreenCall`.
- Use `CallResponse.Builder`.
- For `WARN`, set `setSilenceCall(true)` if available; do not reject/disallow by default.

- [ ] **Step 5: Add manifest service and permissions**

Add `android.permission.READ_PHONE_STATE` and service with `android.permission.BIND_SCREENING_SERVICE`.

- [ ] **Step 6: Add Radar tab controls**

Expose:
- Last hot-cache sync time/count.
- Button to sync `/v1/radar/hot-iocs`.
- Button to open system role settings/request Call Screening role.

- [ ] **Step 7: Verify**

Run:
- `JAVA_HOME='/Applications/Android Studio.app/Contents/jbr/Contents/Home' ./gradlew testDebugUnitTest assembleDebug`
- Live smoke `https://api.sigurscan.com/v1/radar/hot-iocs`

## Task 2: PR-7 BTR Sync + On-Device Inbox Foundation

**Files:**
- Modify: `app/src/main/java/ro/sigurscan/app/SigurScanApi.kt`
- Create: `app/src/main/java/ro/sigurscan/app/BtrSyncStore.kt`
- Create: `app/src/main/java/ro/sigurscan/app/InboxProvenanceEngine.kt`
- Modify: `app/src/main/java/ro/sigurscan/app/ScannerViewModel.kt`
- Modify: `app/src/main/java/ro/sigurscan/app/MainActivity.kt`
- Create: `app/src/test/java/ro/sigurscan/app/BtrSyncStoreTest.kt`
- Create: `app/src/test/java/ro/sigurscan/app/InboxProvenanceEngineTest.kt`

Acceptance:
- App can pull `/v1/btr/sync`.
- If client version equals server version, no-op response is handled.
- Raw SMS/body is never sent to backend by this feature.
- On-device engine can classify a redacted/local signal bundle against BTR manifests.

## Task 3: PR-8 Post-Incident Action Plan Flow

**Files:**
- Modify: `app/src/main/java/ro/sigurscan/app/SigurScanApi.kt`
- Modify: `app/src/main/java/ro/sigurscan/app/ScannerViewModel.kt`
- Modify: `app/src/main/java/ro/sigurscan/app/MainActivity.kt`
- Create: `app/src/test/java/ro/sigurscan/app/ActionPlanRequestTest.kt`

Acceptance:
- User can choose actual impacts (`shared_card`, `shared_otp`, `paid_transfer`, etc.) after a risky verdict.
- App calls `/v1/legal/action-plan`.
- Result replaces/augments preventive action plan.
- SAFE verdicts do not show post-incident flow.

## Task 4: PR-6 Cercul + Guardian Android Flow

**Files:**
- Modify: `app/src/main/java/ro/sigurscan/app/SigurScanApi.kt`
- Create: `app/src/main/java/ro/sigurscan/app/CircleVerificationModels.kt`
- Modify: `app/src/main/java/ro/sigurscan/app/ScannerViewModel.kt`
- Modify: `app/src/main/java/ro/sigurscan/app/MainActivity.kt`
- Create: `app/src/test/java/ro/sigurscan/app/CircleVerificationModelTest.kt`

Acceptance:
- Pair/ping/respond/revoke and Guardian second-opinion have typed API models.
- UI never exposes raw protected content to guardian by default.
- `full_with_consent` requires explicit consent toggle.

## Task 5: PR-9/PR-10 Audio Feasibility Gate

**Files:**
- Create: `docs/ANDROID_AUDIO_CAPTURE_POLICY_2026-06-14.md`
- Create: `app/src/main/java/ro/sigurscan/app/AudioSafetyPolicy.kt`
- Create: `app/src/test/java/ro/sigurscan/app/AudioSafetyPolicyTest.kt`

Acceptance:
- No hidden call recording.
- No claim of Vosk/ASR production readiness until model asset, consent UI, privacy disclosure, and on-device QA exist.
- Feature flag/audio policy must block audio capture by default.

