# Promotable Scan Release Candidate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make each promoted SigurScan scan path preserve evidence provenance, reach the correct backend reducer, render a terminal verdict correctly, and surface its preview independently.

**Architecture:** Android remains responsible for user-initiated intake and evidence staging. The backend remains responsible for extraction, provider work, invoice truth and final verdicts. The Android client renders only backend final verdicts; it keeps preview refresh asynchronous after a final verdict. Tests prove the contract at each boundary before a Cloud Run and Nokia verification run.

**Tech Stack:** Kotlin/Compose, CameraX, ML Kit, Retrofit, FastAPI, pytest, Cloud Run, MobAI/ADB.

---

## File Map

- `app/src/main/java/ro/sigurscan/app/MainActivity.kt`: connects live-camera QR callbacks to `ScannerViewModel`.
- `app/src/main/java/ro/sigurscan/app/ScannerViewModelImageQr.kt`: owns QR payload staging and local extraction failure presentation.
- `app/src/main/java/ro/sigurscan/app/ScannerViewModelSharedIntake.kt`: owns Share Sheet, HTML, EML, PDF and image intake routing.
- `app/src/main/java/ro/sigurscan/app/ScannerViewModelDocumentScan.kt`: owns invoice and offer document routes.
- `app/src/main/java/ro/sigurscan/app/ScannerViewModelOrchestratedScan.kt`: owns final-result polling and asynchronous preview refresh.
- `app/src/test/java/ro/sigurscan/app/ScannerViewModelTest.kt`: existing Android contract-test home.
- `backend/test_promotable_scan_contract.py`: new FastAPI extractor and orchestrated-contract matrix.
- `backend/test_backend.py`: existing final-verdict and preview contract coverage.
- `backend/tools/run_live_cases_incremental.py`: resumable, opt-in Cloud Run smoke runner.
- `docs/RELEASE_CANDIDATE_SCAN_AUDIT_2026-06-22.md`: final evidence report, including deferred audio.

### Task 1: Lock the Live QR Provenance Contract

**Files:**
- Modify: `app/src/test/java/ro/sigurscan/app/ScannerViewModelTest.kt`
- Modify: `app/src/main/java/ro/sigurscan/app/ScannerViewModelImageQr.kt`
- Modify: `app/src/main/java/ro/sigurscan/app/MainActivity.kt`

- [ ] **Step 1: Write the failing Android source-contract test**

Add this test to `ScannerViewModelTest.kt`:

```kotlin
@Test
fun liveQrCameraPayloadPreservesQrProvenanceBeforeOrchestration() {
    val activitySource = File("src/main/java/ro/sigurscan/app/MainActivity.kt").readText()
    val qrSource = File("src/main/java/ro/sigurscan/app/ScannerViewModelImageQr.kt").readText()

    assertTrue(activitySource.contains("viewModel.onLiveQrDecoded(value)"))
    assertTrue(qrSource.contains("fun ScannerViewModel.onLiveQrDecoded(payload: String)"))
    assertTrue(qrSource.contains("stagedEvidenceInputKind = \"qr\""))
    assertTrue(qrSource.contains("stagedEvidenceChannel = \"qr_scan\""))
    assertTrue(qrSource.contains("stagedEvidenceText = qrText"))
    assertTrue(qrSource.contains("onScanClick()"))
}
```

- [ ] **Step 2: Run the test and verify it fails**

Run:

```bash
./gradlew testDebugUnitTest --tests ro.sigurscan.app.ScannerViewModelTest.liveQrCameraPayloadPreservesQrProvenanceBeforeOrchestration
```

Expected: FAIL because the camera callback assigns `viewModel.text` directly and no `onLiveQrDecoded` contract exists.

- [ ] **Step 3: Add one shared QR staging function**

Add this exact behavior in `ScannerViewModelImageQr.kt`:

```kotlin
fun ScannerViewModel.onLiveQrDecoded(payload: String) {
    val qrText = payload.trim()
    if (qrText.isBlank()) {
        publishQrExtractionIncomplete("Nu am găsit un cod QR lizibil în imagine.")
        return
    }
    text = qrText
    stagedEvidenceHtml = null
    stagedEvidenceLinks = extractUrls(qrText)
    stagedEvidenceText = qrText
    stagedEvidenceInputKind = "qr"
    stagedEvidenceChannel = "qr_scan"
    onScanClick()
}
```

Refactor `onQrPicked` to call `onLiveQrDecoded(qrText)` after ML Kit succeeds, so imported and live QR flows have exactly one staging contract.

- [ ] **Step 4: Route the camera callback through the shared function**

Replace the body of the `onQrCodeScanned` callback in `MainActivity.kt` with:

```kotlin
onQrCodeScanned = { value ->
    viewModel.onLiveQrDecoded(value)
    closeQrScanner()
}
```

- [ ] **Step 5: Run targeted Android tests**

Run:

```bash
./gradlew testDebugUnitTest --tests ro.sigurscan.app.ScannerViewModelTest
```

Expected: PASS. The existing imported-QR tests and the new live-camera QR test pass together.

- [ ] **Step 6: Commit the vertical fix**

```bash
git add app/src/main/java/ro/sigurscan/app/MainActivity.kt \
  app/src/main/java/ro/sigurscan/app/ScannerViewModelImageQr.kt \
  app/src/test/java/ro/sigurscan/app/ScannerViewModelTest.kt
git commit -m "fix(android): preserve provenance for live QR scans"
```

### Task 2: Add the Android Promoted-Flow Contract Matrix

**Files:**
- Modify: `app/src/test/java/ro/sigurscan/app/ScannerViewModelTest.kt`

- [ ] **Step 1: Write the flow-matrix test**

Add a test that loads the five existing flow owners and asserts the shared architecture:

```kotlin
@Test
fun promotedScanFlowsUseExtractionThenTheCorrectBackendPipeline() {
    val shared = File("src/main/java/ro/sigurscan/app/ScannerViewModelSharedIntake.kt").readText()
    val imageQr = File("src/main/java/ro/sigurscan/app/ScannerViewModelImageQr.kt").readText()
    val document = File("src/main/java/ro/sigurscan/app/ScannerViewModelDocumentScan.kt").readText()
    val orchestration = File("src/main/java/ro/sigurscan/app/ScannerViewModelOrchestratedScan.kt").readText()

    assertTrue(imageQr.contains("uploadApi.extractImage"))
    assertTrue(shared.contains("uploadApi.extractPdf"))
    assertTrue(shared.contains("MailShareInputAssembler.buildMailScanInput"))
    assertTrue(shared.contains("stagedEvidenceHtml = htmlContentSource"))
    assertTrue(document.contains("uploadApi.scanInvoice"))
    assertTrue(document.contains("runBackendOrchestratedScan(confirmedInput"))
    assertTrue(orchestration.contains("launchFinalOrchestratedPreviewRefresh"))
    assertFalse(orchestration.contains("api.scanImage("))
    assertFalse(orchestration.contains("api.scanPdf("))
    assertFalse(orchestration.contains("api.scanEmail("))
}
```

- [ ] **Step 2: Run the test and investigate every failure**

Run:

```bash
./gradlew testDebugUnitTest --tests ro.sigurscan.app.ScannerViewModelTest.promotedScanFlowsUseExtractionThenTheCorrectBackendPipeline
```

Expected: PASS after Task 1. Any failure identifies an actual broken ingress contract and must be fixed in the owning extension file, not by adding a special-case verdict rule.

- [ ] **Step 3: Commit the test-only contract guard**

```bash
git add app/src/test/java/ro/sigurscan/app/ScannerViewModelTest.kt
git commit -m "test(android): guard promoted scan pipeline contracts"
```

### Task 3: Add FastAPI Extractor and Finalization Contract Coverage

**Files:**
- Create: `backend/test_promotable_scan_contract.py`
- Modify: `backend/test_backend.py` only if a shared polling helper needs an import

- [ ] **Step 1: Write failing extractor contract tests**

Create `backend/test_promotable_scan_contract.py` with tests that monkeypatch the extractor implementation and call the real FastAPI endpoints. Each test asserts intake evidence only, never a local verdict:

```python
PNG_BYTES = b"\x89PNG\r\n\x1a\nrelease-contract"

def test_image_extractor_returns_evidence_without_final_verdict(monkeypatch):
    client = TestClient(app_main.app)

    async def fake_extract_text_for_scan(filename, file_bytes, extract_fn):
        return "Verifica https://www.yoxo.ro/", None

    monkeypatch.setattr(app_main, "extract_text_for_scan", fake_extract_text_for_scan)
    response = client.post(
        "/v1/extract/image",
        files={"image_file": ("scan.png", PNG_BYTES, "image/png")},
        data={"source_channel": "release_contract_image"},
    )
    body = response.json()
    assert response.status_code == 200
    assert body["input_type"] == "image_ocr"
    assert body["source_channel"] == "release_contract_image"
    assert "https://www.yoxo.ro/" in body["extracted_urls"]
    assert "user_risk_label" not in body

def test_pdf_and_email_extractors_return_intake_evidence_without_final_verdict(monkeypatch):
    client = TestClient(app_main.app)
    pdf = b"%PDF-1.7\n1 0 obj << /A << /S /URI /URI (https://www.yoxo.ro/) >> >> endobj\n%%EOF"

    async def fake_extract_text_for_scan(filename, file_bytes, extract_fn):
        return "Oferta oficiala https://www.yoxo.ro/", None

    monkeypatch.setattr(app_main, "extract_text_for_scan", fake_extract_text_for_scan)
    pdf_response = client.post(
        "/v1/extract/pdf",
        files={"pdf_file": ("offer.pdf", pdf, "application/pdf")},
        data={"source_channel": "release_contract_pdf"},
    )
    pdf_body = pdf_response.json()
    assert pdf_response.status_code == 200
    assert pdf_body["input_type"] == "pdf_ocr"
    assert pdf_body["source_channel"] == "release_contract_pdf"
    assert "https://www.yoxo.ro/" in pdf_body["extracted_urls"]
    assert "user_risk_label" not in pdf_body

    email_response = client.post(
        "/v1/extract/email",
        data={
            "html_content": "<a href='https://www.yoxo.ro/'>Vezi oferta</a>",
            "source_channel": "release_contract_email",
        },
    )
    email_body = email_response.json()
    assert email_response.status_code == 200
    assert email_body["input_type"] == "email"
    assert email_body["source_channel"] == "release_contract_email"
    assert "https://www.yoxo.ro/" in email_body["extracted_urls"]
    assert "user_risk_label" not in email_body
```

Import `TestClient` and `main as app_main` in this test file. Keep the bytes inline so the test is hermetic and never calls OCR, a provider or a real URL.

- [ ] **Step 2: Run the existing final-result versus preview contracts**

Run these existing tests, which already exercise the real orchestrated status payload with URLScan mocks:

```bash
python3 -m pytest \
  backend/test_backend.py::test_orchestrated_official_clean_safe_finalizes_before_urlscan_result \
  backend/test_backend.py::test_orchestrated_scan_keeps_clean_verdict_when_urlscan_screenshot_times_out \
  backend/test_backend.py::test_orchestrated_scan_finalizes_when_urlscan_report_exists_but_screenshot_is_not_ready \
  -q
```

Expected: PASS. These are the regression proof that `result.is_final` and the verdict survive pending or unavailable screenshots.

- [ ] **Step 3: Run the new backend contract suite**

Run:

```bash
python3 -m pytest backend/test_promotable_scan_contract.py -q
```

Expected: PASS. The test suite must cover image, PDF, email and preview terminal states through real route code.

- [ ] **Step 4: Commit backend contract coverage**

```bash
git add backend/test_promotable_scan_contract.py backend/test_backend.py
git commit -m "test(backend): cover promoted scan intake contracts"
```

### Task 4: Verify Invoice and Offer Boundaries Without Weakening Fraud Detection

**Files:**
- Modify only if a regression is proven: `backend/services/invoice_orchestrator.py`
- Modify only if a regression is proven: `backend/services/invoice_truth_v4.py`
- Modify only if a regression is proven: `app/src/main/java/ro/sigurscan/app/ScannerViewModelDocumentScan.kt`
- Modify: `app/src/test/java/ro/sigurscan/app/ScannerViewModelTest.kt`

- [ ] **Step 1: Run the existing invoice product-language regressions**

Run the tests that already encode the approved invoice rule: coherent issuer plus unconfirmed beneficiary becomes guided verification, while an explicit BEC account change remains dangerous.

```bash
python3 -m pytest \
  backend/test_invoice_truth_v4.py::test_invoice_truth_keeps_clean_unknown_iban_human_clear_not_red \
  backend/test_invoice_truth_v4.py::test_invoice_truth_sanb_match_does_not_make_unconfirmed_invoice_safe \
  backend/test_invoice_truth_v4.py::test_invoice_truth_free_reply_to_account_change_is_bec_hard_conflict \
  backend/test_invoice_truth_v4.py::test_invoice_truth_qr_printed_iban_conflict_is_nu_plati \
  -q
```

- [ ] **Step 2: Add the offer confirmation routing regression**

Add this source-contract test to `ScannerViewModelTest.kt`:

```kotlin
@Test
fun offerConfirmationRoutesToOfferOrchestrationInsteadOfInvoiceUpload() {
    val source = File("src/main/java/ro/sigurscan/app/ScannerViewModelDocumentScan.kt").readText()
    val start = source.indexOf("fun ScannerViewModel.confirmOfferAndScan")
    val end = source.indexOf("internal fun ScannerViewModel.normalizeOfferLinks", start)
    val flow = source.substring(start, end)

    assertTrue(flow.contains("runBackendOrchestratedScan(confirmedInput"))
    assertTrue(flow.contains("forcedInputType = \"offer\""))
    assertFalse(flow.contains("uploadApi.scanInvoice"))
}
```

- [ ] **Step 3: Run focused invoice and offer suites**

Run:

```bash
python3 -m pytest backend/test_invoice_truth_v4.py backend/test_invoice_endpoint.py backend/test_offer_orchestration.py backend/test_invoice_soft_semantic_override.py -q
./gradlew testDebugUnitTest --tests ro.sigurscan.app.ScannerViewModelTest
```

Expected: PASS. If a test fails, change only the invoice reducer, offer route, or presentation layer that owns the contradiction; never add a per-company or per-IBAN exception.

- [ ] **Step 4: Commit the new Android offer guard and any minimal repair**

```bash
git add app/src/test/java/ro/sigurscan/app/ScannerViewModelTest.kt \
  backend/services/invoice_orchestrator.py backend/services/invoice_truth_v4.py \
  app/src/main/java/ro/sigurscan/app/ScannerViewModelDocumentScan.kt
git commit -m "test: lock invoice and offer release boundaries"
```

### Task 5: Full Automated Regression and Release Build

**Files:**
- Create: `docs/RELEASE_CANDIDATE_SCAN_AUDIT_2026-06-22.md`

- [ ] **Step 1: Run the complete backend suite**

Run:

```bash
python3 -m pytest backend -q
```

Expected: zero failures. Record the pass count and any warning in the release report.

- [ ] **Step 2: Run Android JVM tests and create a release artifact**

Run:

```bash
./gradlew testDebugUnitTest
./gradlew assembleRelease
```

Expected: both succeed. Record the APK path and SHA-256 in the release report; do not record API keys.

- [ ] **Step 3: Write the release evidence report**

Create a report with six rows, one per promoted flow. Each row records Android contract test, backend contract test, final verdict behavior, preview behavior, and whether it requires a physical-device check. Add a separate explicit row: `audio/live-call: NOT PROMOTED - ASR deferred`.

- [ ] **Step 4: Commit release evidence**

```bash
git add docs/RELEASE_CANDIDATE_SCAN_AUDIT_2026-06-22.md
git commit -m "docs: record release candidate scan evidence"
```

### Task 6: Cloud Run and Nokia Release Checks

**Files:**
- Create: `build/reports/release_candidate_live_smoke_2026-06-22.json` (ignored runtime evidence)

- [ ] **Step 1: Deploy only after Task 5 is green**

Run the repository deployment command from the validated commit. Confirm the new Cloud Run revision has 100 percent traffic before sending live scans.

- [ ] **Step 2: Run a controlled Cloud Run provider batch**

Use the existing resumable runner with the production API key already available in the operator environment:

```bash
SIGURSCAN_RUN_LIVE_PROVIDER_SMOKE=1 \
SIGURSCAN_LIVE_SMOKE_API_KEY="$SIGURSCAN_LIVE_SMOKE_API_KEY" \
python3 backend/tools/run_live_cases_incremental.py \
  --base-url https://api.sigurscan.com \
  --cases-file backend/eval/live_public_scam_cases_2026_06_16.json \
  --output build/reports/release_candidate_live_smoke_2026-06-22.json \
  --limit 12 \
  --timeout 120
```

This case pack contains public-source scam reproductions with source references. Do not add `.test`, `.example` or `.invalid` targets. Record provider availability and every `UNVERIFIED` result; an unavailable provider is evidence to investigate, not a passing result.

- [ ] **Step 3: Validate the Nokia with MobAI**

Install the release APK on Nokia and verify these user-visible flows:

1. Camera QR from a safe public QR: neutral progress, final verdict, then preview.
2. Imported QR image: same provenance and final flow as camera QR.
3. Shared email or HTML: extracted link plus final verdict and preview.
4. Imported PDF/image: extraction failure remains neutral; valid link reaches an orchestrated result.
5. Invoice camera or upload: source chooser, invoice result and SANB guidance where beneficiary ownership is unconfirmed.
6. Offer document: confirmation sheet, then orchestrated result after confirmation.

Capture screenshots and logcat only for failures. Do not report a feature as promoted if its device route cannot be completed.

- [ ] **Step 4: Publish the branch only after acceptance gates pass**

```bash
git status --short
git push origin codex/release-candidate-scan-audit-2026-06-22
```

Expected: clean tracked worktree, pushed branch and a report that distinguishes passed flows, unavailable external providers, deferred audio and unresolved failures.
