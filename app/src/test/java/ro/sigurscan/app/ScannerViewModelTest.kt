package ro.sigurscan.app

import org.junit.Test
import org.junit.Assert.*
import java.io.File

class ScannerViewModelTest {

    private fun extractHtmlLinks(content: String): List<String> {
        return HtmlLinkExtractor.extractHtmlLinks(content)
    }

    @Test
    fun orchestratedPollingAdvancesInternalStagesQuickly() {
        val response = OrchestratedScanResponse(
            scanId = "orch-internal",
            status = "scanning",
            pillars = mapOf(
                "urlscan" to OrchestratedPillarState(
                    status = "pending",
                    required = false,
                    details = "urlscan verdict nu a pornit."
                )
            )
        )

        assertEquals(1_000L, orchestratedPollDelayMillis(response))
    }

    @Test
    fun orchestratedPollingBacksOffWhileUrlscanProcesses() {
        val response = OrchestratedScanResponse(
            scanId = "orch-urlscan",
            status = "scanning",
            pillars = mapOf(
                "urlscan" to OrchestratedPillarState(
                    status = "pending",
                    required = false,
                    details = "urlscan verdict este in procesare.",
                    ref = "urlscan-uuid"
                )
            )
        )

        assertEquals(3_000L, orchestratedPollDelayMillis(response))
    }

    @Test
    fun orchestratedPollingBudgetOutlivesBackendControlledTimeouts() {
        assertTrue(ORCHESTRATED_POLLING_BUDGET_MILLIS >= 180_000L)
    }

    @Test
    fun resultCacheKeyNormalizesWhitespaceAndUrls() {
        val first = scanResultCacheKey(
            rawInput = "  Verifică   oferta aici: example.com/path  ",
            htmlPayload = null,
            urls = listOf("example.com/path")
        )
        val second = scanResultCacheKey(
            rawInput = "Verifică oferta aici: example.com/path",
            htmlPayload = null,
            urls = listOf("https://example.com/path")
        )

        assertEquals(first, second)
    }

    @Test
    fun resultCacheKeyNormalizesUrlOnlyInput() {
        val first = scanResultCacheKey(
            rawInput = "example.com/path",
            htmlPayload = null,
            urls = listOf("example.com/path")
        )
        val second = scanResultCacheKey(
            rawInput = "https://example.com/path",
            htmlPayload = null,
            urls = listOf("https://example.com/path")
        )

        assertEquals(first, second)
    }

    @Test
    fun resultCacheKeyChangesWhenDestinationChanges() {
        val first = scanResultCacheKey(
            rawInput = "Urmărește coletul aici",
            htmlPayload = null,
            urls = listOf("https://fan.example/track")
        )
        val second = scanResultCacheKey(
            rawInput = "Urmărește coletul aici",
            htmlPayload = null,
            urls = listOf("https://fan.example/pay")
        )

        assertNotEquals(first, second)
    }

    @Test
    fun resultCacheTtlMatchesThreatIntelFreshnessWindow() {
        assertEquals(12L * 60L * 60L * 1000L, RESULT_CACHE_TTL_MILLIS)
    }

    @Test
    fun resultCacheHitShortCircuitsBackendUnlessUserForcesRefresh() {
        val viewModelSource = File("src/main/java/ro/sigurscan/app/ScannerViewModel.kt").readText()
        val scanStart = viewModelSource.indexOf("fun onScanClick(forceRefresh: Boolean = false)")
        val scanEnd = viewModelSource.indexOf("private fun isTrustedOfficialUrl", scanStart)
        assertTrue("onScanClick must exist.", scanStart >= 0 && scanEnd > scanStart)

        val scanFlow = viewModelSource.substring(scanStart, scanEnd)
        val cacheGuardIndex = scanFlow.indexOf("if (!forceRefresh)")
        val cacheHitIndex = scanFlow.indexOf("cachedAssessmentFor(cacheKey)?.let")
        val backendScanIndex = scanFlow.indexOf("runBackendOrchestratedScan(rawInput, htmlPayload, urls)")
        assertTrue("Result cache must be guarded by forceRefresh=false.", cacheGuardIndex >= 0)
        assertTrue("Result cache hit must be checked before backend orchestration.", cacheHitIndex > cacheGuardIndex)
        assertTrue("Backend orchestration must still run on cache miss or forced refresh.", backendScanIndex > cacheHitIndex)

        val cacheHitFlow = scanFlow.substring(cacheHitIndex, backendScanIndex)
        assertTrue("Cache hit must publish the cached assessment.", cacheHitFlow.contains("assessment = cached"))
        assertTrue("Cache hit must stop the loading state immediately.", cacheHitFlow.contains("loading = false"))
        assertTrue("Cache hit must not continue into backend orchestration.", cacheHitFlow.contains("return@launch"))
    }

    @Test
    fun resultCacheOnlyStoresFinalGateResultsAndStripsCacheStatus() {
        val viewModelSource = File("src/main/java/ro/sigurscan/app/ScannerViewModel.kt").readText()
        val saveStart = viewModelSource.indexOf("private fun saveFinalAssessmentToResultCache")
        val saveEnd = viewModelSource.indexOf("private fun trimResultCache", saveStart)
        assertTrue("saveFinalAssessmentToResultCache must exist.", saveStart >= 0 && saveEnd > saveStart)

        val saveFlow = viewModelSource.substring(saveStart, saveEnd)
        assertTrue(
            "Only final backend/gate results may be cached; provisional scans must keep polling instead.",
            saveFlow.contains("assessment.gateResult?.finality != GateFinality.FINAL")
        )
        assertTrue(
            "Cached records must be stored cleanly so a future cache hit adds fresh cacheStatus metadata.",
            saveFlow.contains("assessment.copy(cacheStatus = null)")
        )
        assertTrue("Cached records must expire on the shared freshness TTL.", saveFlow.contains("now + RESULT_CACHE_TTL_MILLIS"))
        assertTrue("Cache writes must enforce the LRU cap.", saveFlow.contains("trimResultCache()"))
        assertTrue("Cache writes must persist across app restarts.", saveFlow.contains("persistResultCache()"))
    }

    @Test
    fun finalOrchestratedVerdictStopsLoadingBeforePreviewRefresh() {
        val viewModelSource = File("src/main/java/ro/sigurscan/app/ScannerViewModel.kt").readText()
        val publishStart = viewModelSource.indexOf("private suspend fun publishOrchestratedResponse")
        val publishEnd = viewModelSource.indexOf("private fun shouldContinueOrchestratedPolling", publishStart)
        assertTrue("publishOrchestratedResponse must exist.", publishStart >= 0 && publishEnd > publishStart)

        val publishFlow = viewModelSource.substring(publishStart, publishEnd)
        val finalGateIndex = publishFlow.indexOf("updated.gateResult?.finality == GateFinality.FINAL")
        val loadingStopIndex = publishFlow.indexOf("loading = false", finalGateIndex)
        val cacheSaveIndex = publishFlow.indexOf("saveFinalAssessmentToResultCache", finalGateIndex)
        assertTrue("Final orchestrated verdict branch must exist.", finalGateIndex >= 0)
        assertTrue(
            "A final verdict must stop the main loading spinner before any preview/background work continues.",
            loadingStopIndex > finalGateIndex && loadingStopIndex < cacheSaveIndex
        )
        assertTrue(
            "Preview refresh must remain a background follow-up, not the condition for stopping loading.",
            publishFlow.contains("scheduleSandboxScreenshotRefresh(response.scanId, remoteScreenshotUrl)")
        )
    }

    @Test
    fun orchestratedVerdictPublishDoesNotSynchronouslyDownloadScreenshot() {
        val viewModelSource = File("src/main/java/ro/sigurscan/app/ScannerViewModel.kt").readText()
        val publishStart = viewModelSource.indexOf("private suspend fun publishOrchestratedResponse")
        val publishEnd = viewModelSource.indexOf("private fun shouldContinueOrchestratedPolling", publishStart)
        assertTrue("publishOrchestratedResponse must exist.", publishStart >= 0 && publishEnd > publishStart)

        val publishFlow = viewModelSource.substring(publishStart, publishEnd)
        assertFalse(
            "Publishing a backend verdict must not block on screenshot download; preview local caching belongs in background refresh.",
            publishFlow.contains("downloadSandboxScreenshotProxy")
        )
        assertFalse(
            "Publishing a backend verdict must not enter IO just to localize the screenshot before showing the verdict.",
            publishFlow.contains("withContext(Dispatchers.IO)")
        )
    }

    @Test
    fun resultCacheExpiryRemovesStaleRecordsInsteadOfServingOldVerdicts() {
        val viewModelSource = File("src/main/java/ro/sigurscan/app/ScannerViewModel.kt").readText()
        val cacheStart = viewModelSource.indexOf("private fun cachedAssessmentFor")
        val cacheEnd = viewModelSource.indexOf("private fun saveFinalAssessmentToResultCache", cacheStart)
        assertTrue("cachedAssessmentFor must exist.", cacheStart >= 0 && cacheEnd > cacheStart)

        val cacheFlow = viewModelSource.substring(cacheStart, cacheEnd)
        assertTrue("Fresh cache entries may be served.", cacheFlow.contains("cached.expiresAtMillis > now"))
        assertTrue(
            "Stale cache entries must be removed so old provider results cannot become permanent truth.",
            cacheFlow.contains("resultCache.remove(cacheKey)")
        )
        assertTrue("Stale cache eviction must be persisted.", cacheFlow.contains("persistResultCache()"))
        assertTrue("Cache hits must be visible to the user.", cacheFlow.contains("Verificat anterior"))
    }

    @Test
    fun cachedResultUiClearlyOffersRescanWithoutChangingVerdictCopy() {
        val activitySource = File("src/main/java/ro/sigurscan/app/MainActivity.kt").readText()
        assertTrue(
            "Result screen must pass a forced refresh action to bypass cached verdicts.",
            activitySource.contains("onRescan = { viewModel.onScanClick(forceRefresh = true) }")
        )
        assertTrue(
            "Cached results must show a clear rescan action for a fresh provider run.",
            activitySource.contains("Text(\"Rescanează acum\"")
        )
        assertTrue(
            "Cached results must be labelled as previously verified, not as a new live scan.",
            activitySource.contains("if (assessment.cacheStatus != null) \"Verificat anterior\" else null")
        )
    }

    @Test
    fun uploadedMediaAndMailUseOrchestratedPipelineAfterExtraction() {
        val viewModelSource = File("src/main/java/ro/sigurscan/app/ScannerViewModel.kt").readText()
        val apiSource = File("src/main/java/ro/sigurscan/app/SigurScanApi.kt").readText()
        val forbiddenDirectFinalScans = Regex("""api\.scan(?:Image|Pdf|Email)\(""")
        val forbiddenLegacyEndpoints = listOf(
            """@POST("v1/scan/image")""",
            """@POST("v1/scan/pdf")""",
            """@POST("v1/scan/email")""",
            """@POST("v1/scan/text")""",
            """@POST("v1/scan/url")"""
        )

        assertFalse(
            "Image/PDF/email UI flows must not call legacy final scan endpoints directly. " +
                "They may extract content, but final verdict must go through startOrchestratedScan + polling.",
            forbiddenDirectFinalScans.containsMatchIn(viewModelSource)
        )
        forbiddenLegacyEndpoints.forEach { endpoint ->
            assertFalse(
                "Android Retrofit API must not expose legacy final verdict endpoint $endpoint. " +
                    "Use extract endpoints for intake and /v1/scan/orchestrated for verdict.",
                apiSource.contains(endpoint)
            )
        }
    }

    @Test
    fun sharedIntentMixedTextAndFilesKeepsBothEvidencePaths() {
        val activitySource = File("src/main/java/ro/sigurscan/app/MainActivity.kt").readText()
        val plannerSource = File("src/main/java/ro/sigurscan/app/SharedIntentIntakePlanner.kt").readText()
        val viewModelSource = File("src/main/java/ro/sigurscan/app/ScannerViewModel.kt").readText()

        assertTrue(
            "stageSharedTextPayload must be able to keep attached streams when an email/share intent contains both HTML/text and files.",
            viewModelSource.contains("preservePendingFiles: Boolean = false")
        )
        assertTrue(
            "stageSharedFile must be able to append files without wiping the already-staged HTML/text evidence.",
            viewModelSource.contains("preserveSharedTextState: Boolean = false")
        )
        assertTrue(
            "MainActivity must use the same intake planner and executor for cold start and onNewIntent.",
            activitySource.contains("buildSharedIntentIntakePlan(intent)") &&
                activitySource.contains("executeSharedIntentIntakePlan(")
        )
        assertTrue(
            "The intake executor must stage every stream while preserving the already-staged HTML/text evidence.",
            plannerSource.contains("plan.streams.forEach") &&
                plannerSource.contains("preserveSharedTextState = plan.textPayload != null")
        )
        assertTrue(
            "Mixed text/files must start the text scan only after every attachment has been staged.",
            plannerSource.indexOf("plan.streams.forEach") in 0 until plannerSource.indexOf("when (plan.autoScan)")
        )
    }

    @Test
    fun qrImageFailurePublishesIncompleteEvidenceInsteadOfSilentStop() {
        val viewModelSource = File("src/main/java/ro/sigurscan/app/ScannerViewModel.kt").readText()
        val qrStart = viewModelSource.indexOf("fun onQrPicked(uri: Uri, context: Context)")
        val qrEnd = viewModelSource.indexOf("fun onImagePicked(uri: Uri, context: Context)", qrStart)
        assertTrue("onQrPicked must exist.", qrStart >= 0 && qrEnd > qrStart)

        val qrFlow = viewModelSource.substring(qrStart, qrEnd)
        assertTrue(
            "QR image import must show an incomplete-evidence result when no QR is readable.",
            qrFlow.contains("publishQrExtractionIncomplete(\"Nu am găsit un cod QR lizibil în imagine.\")")
        )
        assertTrue(
            "QR image import must show an incomplete-evidence result when MLKit fails.",
            qrFlow.contains("publishQrExtractionIncomplete(\"Nu am putut citi codul QR din imagine. Reîncearcă cu o poză mai clară.\")")
        )
        assertTrue(
            "QR incomplete result must stay unknown, not local-risk.",
            qrFlow.contains("""riskLevel = "unknown"""")
        )
    }

    @Test
    fun qrImageSuccessRoutesThroughOrchestratedScanWithQrEvidence() {
        val viewModelSource = File("src/main/java/ro/sigurscan/app/ScannerViewModel.kt").readText()
        val qrStart = viewModelSource.indexOf("fun onQrPicked(uri: Uri, context: Context)")
        val qrEnd = viewModelSource.indexOf("fun onImagePicked(uri: Uri, context: Context)", qrStart)
        assertTrue("onQrPicked must exist.", qrStart >= 0 && qrEnd > qrStart)

        val qrFlow = viewModelSource.substring(qrStart, qrEnd)
        val successStart = qrFlow.indexOf("if (!qrText.isNullOrBlank())")
        val failureStart = qrFlow.indexOf("} else {", successStart)
        assertTrue("QR success branch must exist.", successStart >= 0 && failureStart > successStart)

        val successFlow = qrFlow.substring(successStart, failureStart)
        assertTrue("QR text must become the scan input.", successFlow.contains("text = qrText"))
        assertTrue("QR scan must extract any embedded URL before orchestrating.", successFlow.contains("stagedEvidenceLinks = extractUrls(qrText)"))
        assertTrue("QR scan must keep the raw decoded payload as evidence.", successFlow.contains("stagedEvidenceText = qrText"))
        assertTrue("QR scan must preserve the input kind for the backend evidence bundle.", successFlow.contains("""stagedEvidenceInputKind = "qr""""))
        assertTrue("QR scan must preserve the QR channel for the backend evidence bundle.", successFlow.contains("""stagedEvidenceChannel = "qr_scan""""))
        assertTrue("QR success must use the same orchestrated scan path as typed/shared text.", successFlow.contains("onScanClick()"))
        assertFalse("QR success must not publish a local guessed verdict.", successFlow.contains("publishQrExtractionIncomplete"))
        assertFalse("QR success must not call backend extraction endpoints directly.", successFlow.contains("api.extract"))
    }

    @Test
    fun imageOcrRunsOnDeviceBeforeCloudFallback() {
        val viewModelSource = File("src/main/java/ro/sigurscan/app/ScannerViewModel.kt").readText()
        val imageStart = viewModelSource.indexOf("fun onImagePicked(uri: Uri, context: Context)")
        val imageEnd = viewModelSource.indexOf("private suspend fun runLocalImageOcrScanIfPossible", imageStart)
        assertTrue("onImagePicked must exist before the local OCR helper.", imageStart >= 0 && imageEnd > imageStart)

        val imageFlow = viewModelSource.substring(imageStart, imageEnd)
        val localOcrIndex = imageFlow.indexOf("runLocalImageOcrScanIfPossible(uri, context)")
        val cloudOcrIndex = imageFlow.indexOf("api.extractImage(body, source)")
        assertTrue("Image scan must try ML Kit/on-device OCR first.", localOcrIndex >= 0)
        assertTrue("Image scan may call cloud OCR only as fallback.", cloudOcrIndex > localOcrIndex)
        assertTrue(
            "Cloud OCR fallback should be clearly gated behind local OCR being unclear.",
            imageFlow.contains("OCR local neclar. Încercăm extragerea cloud...")
        )
    }

    @Test
    fun pdfAndUnsupportedFileFailuresStayExplicitAndNonVerdict() {
        val viewModelSource = File("src/main/java/ro/sigurscan/app/ScannerViewModel.kt").readText()
        val fileStart = viewModelSource.indexOf("fun onFilePicked(uri: Uri, context: Context)")
        val fileEnd = viewModelSource.indexOf("private fun getFileName", fileStart)
        assertTrue("onFilePicked must exist.", fileStart >= 0 && fileEnd > fileStart)

        val fileFlow = viewModelSource.substring(fileStart, fileEnd)
        assertTrue(
            "Unsupported file imports must return a clear incomplete-evidence state, not a guessed verdict.",
            fileFlow.contains("Tipul fișierului nu este suportat pentru scanare")
        )
        assertTrue(
            "Outlook .msg must be explicitly rejected until a real extractor exists.",
            fileFlow.contains("Fișierele Outlook .msg nu sunt încă suportate")
        )
        assertTrue(
            "Oversized PDFs/files must be stopped before upload with a clear message.",
            fileFlow.contains("Fișierul depășește limita de")
        )
        assertTrue(
            "Oversized/unsupported file paths must stay unknown, not local-risk.",
            fileFlow.contains("""riskLevel = "unknown"""")
        )
        assertFalse(
            "PDF incomplete paths should use the same pdf_ocr telemetry channel consistently.",
            fileFlow.contains("""channel = "pdf"""")
        )
    }

    @Test
    fun neutralPendingAssessmentBuilderCannotEmitRiskVerdict() {
        val viewModelSource = File("src/main/java/ro/sigurscan/app/ScannerViewModel.kt").readText()
        assertFalse(
            "ScannerViewModel must not keep an offline verdict evaluator; pending UI state is not a verdict.",
            viewModelSource.contains("evaluateOfflineText")
        )
        val start = viewModelSource.indexOf("private fun buildNeutralPendingAssessment(scannedText: String): OfflineAssessment")
        val end = viewModelSource.indexOf("fun onCommunityReport()", start)
        assertTrue("Neutral pending-state builder must exist and stay non-verdict.", start >= 0 && end > start)

        val functionBody = viewModelSource.substring(start, end)
        assertTrue(functionBody.contains("""riskLevel = "unknown""""))
        assertTrue(functionBody.contains("""riskScore = 0"""))
        assertFalse(functionBody.contains("""riskLevel = "low""""))
        assertFalse(functionBody.contains("""riskLevel = "medium""""))
        assertFalse(functionBody.contains("""riskLevel = "high""""))
        assertFalse(functionBody.contains("DANGEROUS"))
        assertFalse(functionBody.contains("SUSPECT"))
        assertFalse(functionBody.contains("SAFE"))
    }

    @Test
    fun testHtmlLinkExtraction() {
        val html = """
            <html>
                <body>
                    <p>Click pe butonul de mai jos:</p>
                    <a href="https://confirmare-plata.ru/anaf">CONFIRMARE</a>
                </body>
            </html>
        """.trimIndent()
        val links = extractHtmlLinks(html)
        assertEquals(1, links.size)
        assertEquals("https://confirmare-plata.ru/anaf", links[0])
    }

    @Test
    fun testHiddenButtonOnclickLinkExtraction() {
        val html = """
            <html>
                <body>
                    <button onclick="window.location.href='https://scam-example.com/verify'">Apasă aici</button>
                </body>
            </html>
        """.trimIndent()

        val links = extractHtmlLinks(html)
        assertTrue(links.contains("https://scam-example.com/verify"))
    }

    @Test
    fun testFormActionLinkExtraction() {
        val html = """
            <form action="https://phishing.example.net/login">
                <button type="submit">Confirmă cont</button>
            </form>
        """.trimIndent()
        val links = extractHtmlLinks(html)
        assertTrue(links.contains("https://phishing.example.net/login"))
    }

    @Test
    fun testDataAndObfuscatedLinkExtraction() {
        val html = """
            <html>
                <body>
                    <a data-href="https://hidden.example.org/track">Apasă aici</a>
                    <div onclick="window.open('https://popup.example.org/landing')">Mai jos</div>
                </body>
            </html>
        """.trimIndent()
        val links = extractHtmlLinks(html)
        assertTrue(links.contains("https://hidden.example.org/track"))
        assertTrue(links.contains("https://popup.example.org/landing"))
    }

    @Test
    fun testFormActionAndOnsubmitLinkExtraction() {
        val html = """
            <html>
                <body>
                    <form action="https://checkout.example.net/confirm" onsubmit="return false;">
                        <button type="submit" formaction="https://fallback.example.net/submit">Trimite</button>
                    </form>
                </body>
            </html>
        """.trimIndent()
        val links = extractHtmlLinks(html)
        assertTrue(links.contains("https://checkout.example.net/confirm"))
        assertTrue(links.contains("https://fallback.example.net/submit"))
    }

    @Test
    fun testScriptRedirectEncodedLinkExtraction() {
        val encoded = "aHR0cHM6Ly9wcm9uY2UuZXhhbXBsZS5uZXQvaW9uZXQ/cD05"
        val html = """
            <html>
                <body>
                    <button onclick="window.location.assign(atob('$encoded')); return false;">Continuă</button>
                </body>
            </html>
        """.trimIndent()
        val links = extractHtmlLinks(html)
        assertTrue(links.contains("https://pronce.example.net/ionet?p=9"))
    }

    @Test
    fun testStyleAndDataSourceLinkExtraction() {
        val html = """
            <html>
                <body>
                    <div style="background:url('https://style-trace.example.net/overlay.png')">Click mai jos</div>
                    <button data-action="https://meta-action.example.net/track">Verifică</button>
                </body>
            </html>
        """.trimIndent()
        val links = extractHtmlLinks(html)
        assertTrue(links.contains("https://style-trace.example.net/overlay.png"))
        assertTrue(links.contains("https://meta-action.example.net/track"))
    }

    @Test
    fun testStyleBlockLinkExtraction() {
        val html = """
            <html>
                <head>
                    <style>
                        .hero { background-image: url(https://css-background.example.net/banner.png); }
                        @import url("https://css-import.example.net/import.css");
                    </style>
                </head>
            </html>
        """.trimIndent()
        val links = extractHtmlLinks(html)
        assertTrue(links.contains("https://css-background.example.net/banner.png"))
        assertTrue(links.contains("https://css-import.example.net/import.css"))
    }

    @Test
    fun testBase64ObfuscationLinkExtraction() {
        val encoded = "aHR0cHM6Ly9iYXNlNjQuZXhhbXBsZS5uZXQvY2hlY2suZG9uZQ=="
        val html = """
            <a onclick="window.location = atob('$encoded')">Continuă</a>
        """.trimIndent()
        val links = extractHtmlLinks(html)
        assertTrue(links.contains("https://base64.example.net/check.done"))
    }

    @Test
    fun testConcatenatedScriptLinkExtraction() {
        val html = """
            <button onclick="window.location.href='https://' + 'concat-test.example.net' + '/unlock'">Apasă aici</button>
        """.trimIndent()
        val links = extractHtmlLinks(html)
        assertTrue(links.contains("https://concat-test.example.net/unlock"))
    }

    @Test
    fun testHarderObfuscatedScriptLinkExtraction() {
        val encodedUrl = "aHR0cHM6Ly9sb2dpbi5leGFtcGxlLm5ldC92ZXJpZnk="
        val html = """
            <button onclick="window.location='https://' + 'hard' + '-test' + '.example.net' + '/verify?step=1'">Pas 1</button>
            <a onclick="window.open(atob('$encodedUrl'))">Pas 2</a>
            <a href="https://&#x68;&#x61;&#x72;&#x64;&#x65;&#x72;&#x2d;&#x65;&#x6e;&#x74;&#x69;&#x74;&#x79;.example.net/decode">
                Pas 3
            </a>
            <div onmouseover="location.href=unescape('https%3A%2F%2Funescape.example.net%2Fwarn')">Pas 4</div>
            <a onclick="location.assign(decodeURIComponent('https%3A%2F%2Fdecode.example.net%2Fpath'))">Pas 5</a>
        <form onsubmit="window.location.replace('https://%65%78%61%6d%70%6c%65.com/%66%69%6c%74%72%61%74%65')">Pas 6</form>
        """.trimIndent()
        val links = extractHtmlLinks(html)
        val extractedMessage = "Extracted links: ${links.joinToString(", ")}"
        assertTrue(extractedMessage, links.contains("https://hard-test.example.net/verify?step=1"))
        assertTrue(extractedMessage, links.contains("https://login.example.net/verify"))
        assertTrue(extractedMessage, links.contains("https://harder-entity.example.net/decode"))
        assertTrue(extractedMessage, links.contains("https://unescape.example.net/warn"))
        assertTrue(extractedMessage, links.contains("https://decode.example.net/path"))
        assertTrue(extractedMessage, links.contains("https://example.com/filtrate"))
    }

    @Test
    fun testHtmlEntityEncodedLinkExtraction() {
        val html = """
            <a href="https://&#x65;&#x78;&#x61;&#x6d;&#x70;&#x6c;&#x65;&#x2e;&#x63;&#x6f;&#x6d;">link</a>
            <a href="https://&#101;&#120;&#97;&#109;&#112;&#108;&#101;&#46;&#99;&#111;&#109;/entity">entity</a>
        """.trimIndent()
        val links = extractHtmlLinks(html)
        assertTrue(links.contains("https://example.com"))
        assertTrue(links.contains("https://example.com/entity"))
    }

    @Test
    fun testSelfLocationRedirectLinkExtraction() {
        val html = """
            <button onclick="self.location='https://self-link.example.org/verify'">Apasă mai jos</button>
        """.trimIndent()
        val links = extractHtmlLinks(html)
        assertTrue(links.contains("https://self-link.example.org/verify"))
    }

    @Test
    fun testMetaRefreshLinkExtraction() {
        val html = """
            <meta http-equiv="refresh" content="0;url=https://meta-refresh.example.com/redirect" />
        """.trimIndent()
        val links = extractHtmlLinks(html)
        assertTrue(links.contains("https://meta-refresh.example.com/redirect"))
    }

    @Test
    fun testScriptBlockLinkExtraction() {
        val encoded = "aHR0cHM6Ly9zY3JpcHQuZXhhbXBsZS5jb20vc2NyaXB0"
        val html = """
            <script>
              const base = 'https://';
              const host = 'script-block.example.com';
              const path = '/payload';
              window.location.href = base + host + path;
              window.open(atob('$encoded'));
              location.assign('https://assign.example.com/next');
            </script>
        """.trimIndent()
        val links = extractHtmlLinks(html)
        val extractedMessage = "Extracted links: ${links.joinToString(", ")}"
        assertTrue(extractedMessage, links.contains("https://script-block.example.com/payload"))
        assertTrue(extractedMessage, links.contains("https://script.example.com/script"))
        assertTrue(extractedMessage, links.contains("https://assign.example.com/next"))
    }

    @Test
    fun testSrcSetAndHiddenWrapperLinkExtraction() {
        val html = """
            <div onpointerdown="window.location='https://pointer-down.example.net/route'">
                <img srcset="/fallback 1x, https://imgset.example.net/photo.jpg 2x" alt="img">
            </div>
        """.trimIndent()
        val links = extractHtmlLinks(html)
        assertTrue(links.contains("https://pointer-down.example.net/route"))
        assertTrue(links.contains("https://imgset.example.net/photo.jpg"))
    }

    @Test
    fun testTemplateLiteralScriptLinkExtraction() {
        val html = """
            <script>
              const domain = 'template-link.example.com';
              const path = '/payload';
              window.location.href = `https://${'$'}{domain}${'$'}{path}`;
            </script>
        """.trimIndent()
        val links = extractHtmlLinks(html)
        assertTrue(links.contains("https://template-link.example.com/payload"))
    }

    @Test
    fun testVariableAliasLinkExtraction() {
        val html = """
            <script>
              const base = 'https://';
              const host = 'alias-link.example.com';
              const path = '/safe';
              const link = base + host + path;
              window.location = link;
            </script>
        """.trimIndent()
        val links = extractHtmlLinks(html)
        assertTrue(links.contains("https://alias-link.example.com/safe"))
    }

    @Test
    fun testBaseHrefResolvesRelativeButtonTarget() {
        val html = """
            <html>
                <head><base href="https://homebank-update.test/secure/"></head>
                <body><a href="../login">Actualizează HomeBank</a></body>
            </html>
        """.trimIndent()

        val links = extractHtmlLinks(html)
        assertTrue(links.contains("https://homebank-update.test/login"))
    }

    @Test
    fun testConditionalMsoAndVmlLinksAreExtracted() {
        val html = """
            <!--[if mso]>
              <v:roundrect href="https://bcr.ro/login">Intră în cont</v:roundrect>
            <![endif]-->
            <!--[if !mso]><!-->
              <a href="https://bcr-login-alert.test/login">Intră în cont</a>
            <!--<![endif]-->
        """.trimIndent()

        val links = extractHtmlLinks(html)
        assertTrue(links.contains("https://bcr.ro/login"))
        assertTrue(links.contains("https://bcr-login-alert.test/login"))
    }

    @Test
    fun testGenericOpenRedirectTargetIsExtracted() {
        val html = """
            <a href="https://trusted.example.com/redirect?next=https%3A%2F%2Fevil-landing.test%2Flogin">Continuă</a>
        """.trimIndent()

        val links = extractHtmlLinks(html)
        assertTrue(links.contains("https://evil-landing.test/login"))
    }

    @Test
    fun testUserInfoAtUrlKeepsActualHostCandidate() {
        val html = """<a href="https://bcr.ro@evil-bank.test/login">bcr.ro</a>"""

        val links = extractHtmlLinks(html)
        assertTrue(links.contains("https://bcr.ro@evil-bank.test/login"))
    }

    @Test
    fun testUnicodeIdnHostIsExtractedAsPunycode() {
        val html = """<a href="https://еmag.ro/login">eMAG</a>"""

        val links = extractHtmlLinks(html)
        assertTrue(links.contains("https://xn--mag-qdd.ro/login"))
    }

}
