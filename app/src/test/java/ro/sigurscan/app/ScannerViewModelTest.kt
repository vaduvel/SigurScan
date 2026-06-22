package ro.sigurscan.app

import org.junit.Test
import org.junit.Assert.*
import java.io.File

class ScannerViewModelTest {

    /**
     * Concatenated source of the whole UI package. The Compose UI was split out of the former
     * MainActivity.kt monolith into cohesive sibling files (ScanScreen.kt, RadarScreen.kt,
     * ResultCard.kt, SharedIntentHandling.kt, …); these architecture-guard assertions check that
     * the UI layer contains the expected wiring regardless of which file now holds it.
     */
    private fun uiPackageSource(): String =
        File("src/main/java/ro/sigurscan/app")
            .walkTopDown()
            .filter { it.isFile && it.extension == "kt" }
            .joinToString("\n") { it.readText() }

    /**
     * Concatenated source of ScannerViewModel.kt and the domain extension files split out of it
     * (ScannerViewModelDocumentScan.kt, …). The core ScannerViewModel.kt sorts first, so guards
     * that use indexOf to bound a core method body still operate on a contiguous region.
     */
    private fun viewModelSource(): String =
        File("src/main/java/ro/sigurscan/app")
            .listFiles { f -> f.isFile && f.name.startsWith("ScannerViewModel") && f.extension == "kt" }!!
            .sortedBy { it.name }
            .joinToString("\n") { it.readText() }

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
    fun orchestratedPollingHonorsBoundedBackendPollAfter() {
        val fast = OrchestratedScanResponse(
            scanId = "orch-fast",
            status = "scanning",
            pollAfterMs = 250L
        )
        val requested = OrchestratedScanResponse(
            scanId = "orch-requested",
            status = "scanning",
            pollAfterMs = 1_500L
        )
        val slow = OrchestratedScanResponse(
            scanId = "orch-slow",
            status = "scanning",
            pollAfterMs = 15_000L
        )

        assertEquals(500L, orchestratedPollDelayMillis(fast))
        assertEquals(1_500L, orchestratedPollDelayMillis(requested))
        assertEquals(5_000L, orchestratedPollDelayMillis(slow))
    }

    @Test
    fun orchestratedPollingBudgetOutlivesBackendControlledTimeouts() {
        assertTrue(ORCHESTRATED_POLLING_BUDGET_MILLIS >= 180_000L)
    }

    @Test
    fun finalUrlUnresolvedPreviewMessageOverridesGenericFinalScanCopy() {
        val preview = OrchestratedPreview(
            finalUrl = "https://flixsou.site/streaming/watch.php",
            status = "unavailable",
            reason = "final_url_unresolved",
            details = "Destinatia finala nu poate fi incarcata/verificata. Nu continua fara verificare oficiala."
        )

        val message = orchestratedScanServerInfo(
            statusMessage = "Scanarea este finalizata.",
            preview = preview,
            isFinal = true
        )

        assertTrue(message.contains("Destinatia finala"))
        assertTrue(message.contains("Nu continua"))
        assertFalse(message.contains("Scanarea completă a fost finalizată."))
    }

    @Test
    fun provisionalOrchestratedMessageMentionsRiskSourcesInsteadOfPreview() {
        val message = orchestratedScanServerInfo(
            statusMessage = null,
            preview = OrchestratedPreview(
                status = "pending",
                reason = "urlscan_pending",
                finalUrl = "https://www.smart-menu.ro/qr/menu-demo"
            ),
            isFinal = false
        )

        assertTrue(message.contains("destinația") || message.contains("destinatia"))
        assertTrue(message.contains("sursele de risc"))
        assertFalse(message.contains("preview", ignoreCase = true))
    }

    @Test
    fun provisionalOrchestratedMessageHidesBackendPillarJargon() {
        val message = orchestratedScanServerInfo(
            statusMessage = "Scanarea continua pana cand pilonii necesari returneaza date.",
            preview = OrchestratedPreview(
                status = "pending",
                reason = "urlscan_pending",
                finalUrl = "https://www.yoxo.ro"
            ),
            isFinal = false
        ).lowercase()

        assertTrue(message.contains("verific"))
        assertFalse(message.contains("pilon"))
        assertFalse(message.contains("provider"))
    }

    @Test
    fun finalUrlscanPendingPreviewStopsScanPollingAfterFinalVerdict() {
        val response = OrchestratedScanResponse(
            scanId = "orch-yoxo-preview",
            status = "complete",
            preview = OrchestratedPreview(
                status = "pending",
                reason = "urlscan_screenshot_pending",
                reportUrl = "https://urlscan.io/result/urlscan-yoxo-1/",
                finalUrl = "https://reconditionate.yoxo.ro/oferte-speciale"
            ),
            result = ScanResponse(
                scanId = "orch-yoxo-preview",
                riskScore = 10,
                riskLevel = "low",
                detectedFamily = "Destinație oficială",
                reasons = emptyList(),
                safeActions = emptyList(),
                userRiskLabel = "SAFE",
                isFinal = true
            )
        )

        assertFalse(shouldContinueOrchestratedPolling(response))
        assertTrue(shouldRefreshFinalOrchestratedPreview(response))
        assertTrue(orchestratedPreviewStillPending(response.preview))
    }

    @Test
    fun finalPendingPreviewKeepsEvidenceCompletenessPartial() {
        val completeness = orchestratedEvidenceCompleteness(
            preview = OrchestratedPreview(
                status = "pending",
                reason = "urlscan_screenshot_pending",
                finalUrl = "https://reconditionate.yoxo.ro/oferte-speciale"
            ),
            providerStates = mapOf(
                ProviderId.WEB_RISK to ProviderState(ProviderId.WEB_RISK, ProviderStatus.OK),
                ProviderId.URLSCAN to ProviderState(ProviderId.URLSCAN, ProviderStatus.PENDING)
            ),
            finalUrl = "https://reconditionate.yoxo.ro/oferte-speciale"
        )

        assertEquals(EvidenceCompleteness.PARTIAL_ONLINE, completeness)
    }

    @Test
    fun finalUnavailablePreviewWithTerminalProviderErrorIsComplete() {
        val completeness = orchestratedEvidenceCompleteness(
            preview = OrchestratedPreview(
                status = "unavailable",
                reason = "final_url_unresolved",
                finalUrl = "https://anaf-spv.info/login/verify"
            ),
            providerStates = mapOf(
                ProviderId.WEB_RISK to ProviderState(ProviderId.WEB_RISK, ProviderStatus.OK),
                ProviderId.URLSCAN to ProviderState(ProviderId.URLSCAN, ProviderStatus.ERROR)
            ),
            finalUrl = "https://anaf-spv.info/login/verify",
            isFinal = true
        )

        assertEquals(EvidenceCompleteness.FULL, completeness)
    }

    @Test
    fun provisionalUnavailablePreviewStillKeepsEvidenceCompletenessPartial() {
        val completeness = orchestratedEvidenceCompleteness(
            preview = OrchestratedPreview(
                status = "unavailable",
                reason = "final_url_unresolved",
                finalUrl = "https://anaf-spv.info/login/verify"
            ),
            providerStates = mapOf(
                ProviderId.WEB_RISK to ProviderState(ProviderId.WEB_RISK, ProviderStatus.OK),
                ProviderId.URLSCAN to ProviderState(ProviderId.URLSCAN, ProviderStatus.ERROR)
            ),
            finalUrl = "https://anaf-spv.info/login/verify",
            isFinal = false
        )

        assertEquals(EvidenceCompleteness.PARTIAL_ONLINE, completeness)
    }

    @Test
    fun backendEvidenceIsPassedToEvidenceNormalizerForOrchestratedResults() {
        val viewModelSource = viewModelSource()
        val mapperStart = viewModelSource.indexOf("internal fun ScannerViewModel.buildAssessmentFromBackendScanResponse")
        val mapperEnd = viewModelSource.indexOf("internal fun ScannerViewModel.buildPendingAssessmentFromOrchestratedResponse", mapperStart)
        assertTrue("buildAssessmentFromBackendScanResponse must exist.", mapperStart >= 0 && mapperEnd > mapperStart)

        val mapperBody = viewModelSource.substring(mapperStart, mapperEnd)
        assertTrue(
            "Backend evidence must be forwarded so infra DNS/RDAP/transport signals are not dropped.",
            mapperBody.contains("backendEvidence = evidence")
        )
    }

    @Test
    fun readyPreviewStopsPollingAfterFinalVerdict() {
        val response = OrchestratedScanResponse(
            scanId = "orch-yoxo-preview-ready",
            status = "complete",
            preview = OrchestratedPreview(
                status = "ready",
                screenshotUrl = "https://api.sigurscan.com/v1/sandbox/urlscan/urlscan-yoxo-1/screenshot",
                finalUrl = "https://reconditionate.yoxo.ro/oferte-speciale"
            ),
            result = ScanResponse(
                scanId = "orch-yoxo-preview-ready",
                riskScore = 10,
                riskLevel = "low",
                detectedFamily = "Destinație oficială",
                reasons = emptyList(),
                safeActions = emptyList(),
                userRiskLabel = "SAFE",
                isFinal = true
            )
        )

        assertFalse(shouldContinueOrchestratedPolling(response))
        assertFalse(orchestratedPreviewStillPending(response.preview))
    }

    @Test
    fun finalPendingPreviewMessageShowsGenerationInsteadOfGenericCompletion() {
        val message = orchestratedScanServerInfo(
            statusMessage = "Scanarea este finalizata.",
            preview = OrchestratedPreview(
                status = "pending",
                reason = "urlscan_screenshot_pending",
                finalUrl = "https://reconditionate.yoxo.ro/oferte-speciale"
            ),
            isFinal = true
        )

        assertTrue(message.contains("Preview-ul securizat"))
        assertTrue(message.contains("generează"))
        assertFalse(message.contains("Scanarea completă a fost finalizată."))
    }

    @Test
    fun finalUrlscanScreenshotTimeoutMessageShowsPreviewUnavailable() {
        val message = orchestratedScanServerInfo(
            statusMessage = "Scanarea este finalizata.",
            preview = OrchestratedPreview(
                status = "unavailable",
                reason = "urlscan_screenshot_timeout",
                finalUrl = "https://reconditionate.yoxo.ro/oferte-speciale"
            ),
            isFinal = true
        )

        assertTrue(message.contains("Preview-ul securizat nu a fost gata"))
        assertFalse(message.contains("generează"))
        assertFalse(message.contains("Scanarea completă a fost finalizată."))
    }

    @Test
    fun backendPreviewTimeoutShowsPreviewUnavailableAfterServerTerminalState() {
        val message = orchestratedScanServerInfo(
            statusMessage = "Scanarea este finalizata.",
            preview = OrchestratedPreview(
                status = "unavailable",
                reason = "urlscan_timeout",
                finalUrl = "https://www.smart-menu.ro/qr/vbiwmbouhu"
            ),
            isFinal = true
        )

        assertTrue(message.contains("Preview-ul securizat nu a fost gata"))
        assertFalse(message.contains("generează"))
    }

    @Test
    fun finalPreviewRefreshKeepsPendingInsteadOfPublishingLocalUnavailableTimeout() {
        val viewModelSource = viewModelSource()
        val helperStart = viewModelSource.indexOf("internal fun ScannerViewModel.launchFinalOrchestratedPreviewRefresh")
        val helperEnd = viewModelSource.indexOf("internal fun ScannerViewModel.buildDegradedAssessmentFromBackendScanResponse", helperStart)
        assertTrue("Preview refresh helper must exist.", helperStart >= 0 && helperEnd > helperStart)

        val helperFlow = viewModelSource.substring(helperStart, helperEnd)
        assertTrue(
            "After a final verdict, Android must keep refreshing a pending preview until the backend returns a terminal preview state.",
            helperFlow.contains("while (shouldRefreshFinalOrchestratedPreview(response))")
        )
        assertFalse(
            "Android must not invent a local preview timeout; unavailable belongs to backend terminal reasons.",
            helperFlow.contains("publishFinalOrchestratedPreviewTimeout") ||
                helperFlow.contains("android_final_preview_refresh_timeout")
        )
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
    fun urlOnlyOrchestratedRequestPreservesActiveEvidenceChannelForQrScans() {
        val viewModelSource = viewModelSource()
        val requestStart = viewModelSource.indexOf("internal fun ScannerViewModel.orchestratedRequest")
        val requestEnd = viewModelSource.indexOf("internal fun ScannerViewModel.linksFromExtraction", requestStart)
        assertTrue("orchestratedRequest must exist.", requestStart >= 0 && requestEnd > requestStart)

        val requestFlow = viewModelSource.substring(requestStart, requestEnd)
        val urlOnlyBranch = requestFlow.substring(
            requestFlow.indexOf("urls.isNotEmpty() && looksLikeUrlOnly"),
            requestFlow.indexOf("else -> OrchestratedScanRequest")
        )

        assertTrue(
            "URL-only scans must preserve qr_scan/share channel instead of flattening every URL into android_url_scan.",
            urlOnlyBranch.contains("sourceChannel = activeEvidenceChannel(rawInput) ?: \"android_url_scan\"")
        )
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
        val viewModelSource = viewModelSource()
        val scanStart = viewModelSource.indexOf("fun ScannerViewModel.onScanClick(forceRefresh: Boolean = false)")
        val scanEnd = viewModelSource.indexOf("internal fun ScannerViewModel.isTrustedOfficialUrl", scanStart)
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
        val viewModelSource = viewModelSource()
        val saveStart = viewModelSource.indexOf("internal fun ScannerViewModel.saveFinalAssessmentToResultCache")
        val saveEnd = viewModelSource.indexOf("internal fun ScannerViewModel.trimResultCache", saveStart)
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
    fun finalPendingPreviewIsNotCachedAsCompleteResult() {
        val viewModelSource = viewModelSource()
        val publishStart = viewModelSource.indexOf("internal suspend fun ScannerViewModel.publishOrchestratedResponse")
        val publishEnd = viewModelSource.indexOf("internal fun ScannerViewModel.shouldCacheFinalAssessment", publishStart)
        assertTrue("publishOrchestratedResponse must exist.", publishStart >= 0 && publishEnd > publishStart)

        val publishFlow = viewModelSource.substring(publishStart, publishEnd)
        assertTrue(
            "Final cache writes must wait until the preview is not pending, otherwise future scans show an old no-preview result.",
            publishFlow.contains("shouldCacheFinalAssessment(response, updated)")
        )
        assertTrue(
            "Final cache writes must be inside the cacheability guard.",
            publishFlow.contains("if (shouldCacheFinalAssessment(response, updated))") &&
                publishFlow.indexOf("saveFinalAssessmentToResultCache(resultCacheKey, updated)") >
                publishFlow.indexOf("if (shouldCacheFinalAssessment(response, updated))")
        )
    }

    @Test
    fun finalOrchestratedVerdictStopsLoadingBeforePreviewRefresh() {
        val viewModelSource = viewModelSource()
        val publishStart = viewModelSource.indexOf("internal suspend fun ScannerViewModel.publishOrchestratedResponse")
        val publishEnd = viewModelSource.indexOf("internal fun ScannerViewModel.shouldCacheFinalAssessment", publishStart)
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
        val viewModelSource = viewModelSource()
        val publishStart = viewModelSource.indexOf("internal suspend fun ScannerViewModel.publishOrchestratedResponse")
        val publishEnd = viewModelSource.indexOf("internal fun ScannerViewModel.shouldCacheFinalAssessment", publishStart)
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
    fun orchestratedPollingBudgetPublishesExplicitTimeoutState() {
        val viewModelSource = viewModelSource()
        val runStart = viewModelSource.indexOf("internal suspend fun ScannerViewModel.runBackendOrchestratedScan")
        val runEnd = viewModelSource.indexOf("fun ScannerViewModel.onScanClick", runStart)
        assertTrue("runBackendOrchestratedScan must exist.", runStart >= 0 && runEnd > runStart)

        val runFlow = viewModelSource.substring(runStart, runEnd)
        val loopIndex = runFlow.indexOf("while (shouldContinueOrchestratedPolling(response)")
        val timeoutPublishIndex = runFlow.indexOf("publishOrchestratedPollingTimeout(response, rawInput, urls, response.scanId)")
        assertTrue("Polling loop must exist.", loopIndex >= 0)
        assertTrue(
            "When the polling budget expires, Android must publish an explicit non-spinning state instead of leaving the UI in progress.",
            timeoutPublishIndex > loopIndex
        )

        val timeoutStart = viewModelSource.indexOf("internal suspend fun ScannerViewModel.publishOrchestratedPollingTimeout")
        val timeoutEnd = viewModelSource.indexOf("fun ScannerViewModel.onScanClick", timeoutStart)
        assertTrue("publishOrchestratedPollingTimeout must exist.", timeoutStart >= 0 && timeoutEnd > timeoutStart)
        val timeoutFlow = viewModelSource.substring(timeoutStart, timeoutEnd)
        assertTrue(timeoutFlow.contains("Verificarea a durat prea mult"))
        assertTrue(timeoutFlow.contains("loading = false"))
    }

    @Test
    fun finalVerdictPreviewRefreshIsSeparateFromScanPollingLoop() {
        val viewModelSource = viewModelSource()
        val runStart = viewModelSource.indexOf("internal suspend fun ScannerViewModel.runBackendOrchestratedScan")
        val runEnd = viewModelSource.indexOf("fun ScannerViewModel.onScanClick", runStart)
        assertTrue("runBackendOrchestratedScan must exist.", runStart >= 0 && runEnd > runStart)

        val runFlow = viewModelSource.substring(runStart, runEnd)
        val timeoutIndex = runFlow.indexOf("publishOrchestratedPollingTimeout(response, rawInput, urls, response.scanId)")
        val refreshIndex = runFlow.indexOf("launchFinalOrchestratedPreviewRefresh(response, rawInput, urls, response.scanId, resultCacheKey)")
        assertTrue(
            "Final verdict preview refresh must run after scan polling has ended, not as a reason to keep the main loading loop alive.",
            refreshIndex > timeoutIndex
        )
        assertTrue(
            "Preview refresh must have a bounded helper.",
            viewModelSource.contains("internal fun ScannerViewModel.launchFinalOrchestratedPreviewRefresh")
        )
        val helperStart = viewModelSource.indexOf("internal fun ScannerViewModel.launchFinalOrchestratedPreviewRefresh")
        val helperEnd = viewModelSource.indexOf("internal fun ScannerViewModel.buildDegradedAssessmentFromBackendScanResponse", helperStart)
        assertTrue("Preview refresh helper must be followed by degraded mapping helper.", helperStart >= 0 && helperEnd > helperStart)
        assertFalse(
            "Preview refresh must not reuse shouldContinueOrchestratedPolling as its stop condition.",
            viewModelSource.substring(helperStart, helperEnd).contains("shouldContinueOrchestratedPolling")
        )
        val helperFlow = viewModelSource.substring(helperStart, helperEnd)
        val activePollIndex = helperFlow.indexOf("getOrchestratedScan(response.scanId)")
        val statusPollIndex = helperFlow.indexOf("getOrchestratedScanStatus")
        assertTrue(
            "Final preview refresh must poll the active scan endpoint so urlscan screenshot collection can advance after the verdict.",
            activePollIndex >= 0
        )
        assertTrue(
            "Final preview refresh should keep the read-only status endpoint only as a compatibility fallback.",
            statusPollIndex >= 0
        )
        assertTrue(
            "The active scan endpoint must be attempted before the read-only status endpoint during final preview refresh.",
            activePollIndex < statusPollIndex
        )

        val apiSource = File("src/main/java/ro/sigurscan/app/SigurScanApi.kt").readText()
        assertTrue(
            "Retrofit API must expose the read-only orchestrated status endpoint.",
            apiSource.contains("@GET(\"v1/scan/orchestrated/{scan_id}/status\")")
        )
    }

    @Test
    fun resultCacheExpiryRemovesStaleRecordsInsteadOfServingOldVerdicts() {
        val viewModelSource = viewModelSource()
        assertTrue(
            "Result cache storage key must be versioned so backend verdict contract changes can invalidate stale local verdicts.",
            viewModelSource.contains("scan_result_cache_v3")
        )
        assertFalse(
            "Old result cache v2 must not be read after the public-navigation verdict contract changed.",
            viewModelSource.contains("scan_result_cache_v2")
        )
        assertFalse(
            "Old result cache v1 must not be read after the preview/verdict contract changed.",
            viewModelSource.contains("scan_result_cache_v1")
        )
        val cacheStart = viewModelSource.indexOf("internal fun ScannerViewModel.cachedAssessmentFor")
        val cacheEnd = viewModelSource.indexOf("internal fun ScannerViewModel.saveFinalAssessmentToResultCache", cacheStart)
        assertTrue("cachedAssessmentFor must exist.", cacheStart >= 0 && cacheEnd > cacheStart)

        val cacheFlow = viewModelSource.substring(cacheStart, cacheEnd)
        assertTrue("Fresh cache entries may be served.", cacheFlow.contains("cached.expiresAtMillis > now"))
        assertTrue(
            "Stale cache entries must be removed so old provider results cannot become permanent truth.",
            cacheFlow.contains("resultCache.remove(cacheKey)")
        )
        assertTrue("Stale cache eviction must be persisted.", cacheFlow.contains("persistResultCache()"))
        assertTrue("Cache hits must be visible to the user.", cacheFlow.contains("Verificat anterior"))
        assertTrue(
            "Cached URL preview records that need refresh must be evicted before serving stale UI.",
            cacheFlow.contains("cachedPreviewNeedsRefresh(cached.assessment)")
        )

        // Orchestration/cache helper functions were extracted out of the ScannerViewModel monolith
        // into ScannerOrchestration.kt; the verdict-freshness logic now lives there.
        val orchestrationSource = File("src/main/java/ro/sigurscan/app/ScannerOrchestration.kt").readText()
        val helperStart = orchestrationSource.indexOf("internal fun cachedPreviewNeedsRefresh")
        val helperEnd = orchestrationSource.indexOf("internal fun orchestratedScanServerInfo", helperStart)
        assertTrue("cachedPreviewNeedsRefresh must exist.", helperStart >= 0 && helperEnd > helperStart)
        val helperFlow = orchestrationSource.substring(helperStart, helperEnd)
        assertTrue("URL results without screenshots must refresh.", helperFlow.contains("screenshotUrl.isBlank()"))
        assertTrue("Cleartext screenshot URLs must refresh.", helperFlow.contains("startsWith(\"http://\")"))
        assertTrue("Internal Cloud Run screenshot URLs must refresh.", helperFlow.contains("\".run.app/\""))
    }

    @Test
    fun cachedResultUiClearlyOffersRescanWithoutChangingVerdictCopy() {
        val activitySource = uiPackageSource()
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
        val viewModelSource = viewModelSource()
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
        val activitySource = uiPackageSource()
        val plannerSource = File("src/main/java/ro/sigurscan/app/SharedIntentIntakePlanner.kt").readText()
        val viewModelSource = viewModelSource()

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
    fun processTextIntentUsesSharedIntakePipeline() {
        val activitySource = uiPackageSource()
        val plannerSource = File("src/main/java/ro/sigurscan/app/SharedIntentIntakePlanner.kt").readText()

        assertTrue(
            "ACTION_PROCESS_TEXT must be accepted by the same shared-intake planner as SEND/SEND_MULTIPLE.",
            plannerSource.contains("Intent.ACTION_PROCESS_TEXT")
        )
        assertTrue(
            "Selected text must read EXTRA_PROCESS_TEXT, not only EXTRA_TEXT.",
            activitySource.contains("Intent.EXTRA_PROCESS_TEXT")
        )
    }

    @Test
    fun qrImageFailurePublishesIncompleteEvidenceInsteadOfSilentStop() {
        val viewModelSource = viewModelSource()
        val qrStart = viewModelSource.indexOf("fun ScannerViewModel.onQrPicked(uri: Uri, context: Context)")
        val qrEnd = viewModelSource.indexOf("fun ScannerViewModel.onImagePicked(uri: Uri, context: Context)", qrStart)
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
        val viewModelSource = viewModelSource()
        val qrStart = viewModelSource.indexOf("fun ScannerViewModel.onQrPicked(uri: Uri, context: Context)")
        val qrEnd = viewModelSource.indexOf("fun ScannerViewModel.onImagePicked(uri: Uri, context: Context)", qrStart)
        assertTrue("onQrPicked must exist.", qrStart >= 0 && qrEnd > qrStart)

        val qrFlow = viewModelSource.substring(qrStart, qrEnd)
        val successStart = qrFlow.indexOf("if (!qrText.isNullOrBlank())")
        val failureStart = qrFlow.indexOf("} else {", successStart)
        assertTrue("QR success branch must exist.", successStart >= 0 && failureStart > successStart)

        val successFlow = qrFlow.substring(successStart, failureStart)
        assertTrue("QR import must use the shared QR provenance staging path.", successFlow.contains("onLiveQrDecoded(qrText)"))
        assertFalse("QR success must not publish a local guessed verdict.", successFlow.contains("publishQrExtractionIncomplete"))
        assertFalse("QR success must not call backend extraction endpoints directly.", successFlow.contains("api.extract"))
    }

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

    @Test
    fun qrImageImportLeavesLoadingStateBeforeForwardingDecodedPayload() {
        val qrSource = File("src/main/java/ro/sigurscan/app/ScannerViewModelImageQr.kt").readText()
        val imagePickerStart = qrSource.indexOf("fun ScannerViewModel.onQrPicked")
        val decodedPayload = qrSource.indexOf("onLiveQrDecoded(qrText)", imagePickerStart)
        val loadingReset = qrSource.indexOf("loading = false", imagePickerStart)

        assertTrue("QR import needs a terminal timeout so the loading UI cannot hang forever.", qrSource.contains("QR_IMAGE_DECODE_TIMEOUT_MILLIS"))
        assertTrue("QR import must complete loading before forwarding a decoded payload to onScanClick.", loadingReset in (imagePickerStart + 1) until decodedPayload)
    }

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

    @Test
    fun offerConfirmationRoutesToOfferOrchestrationInsteadOfInvoiceUpload() {
        val source = File("src/main/java/ro/sigurscan/app/ScannerViewModelDocumentScan.kt").readText()
        val start = source.indexOf("fun ScannerViewModel.confirmOfferAndScan")
        val end = source.indexOf("internal fun ScannerViewModel.normalizeOfferLinks", start)
        assertTrue("confirmOfferAndScan must exist.", start >= 0 && end > start)

        val flow = source.substring(start, end)
        assertTrue(flow.contains("runBackendOrchestratedScan(confirmedInput"))
        assertTrue(flow.contains("forcedInputType = \"offer\""))
        assertFalse(flow.contains("uploadApi.scanInvoice"))
    }

    @Test
    fun imageUploadUsesCloudQrExtractorBeforeLocalOcrFallback() {
        val viewModelSource = viewModelSource()
        val imageStart = viewModelSource.indexOf("fun ScannerViewModel.onImagePicked(uri: Uri, context: Context)")
        val imageEnd = viewModelSource.indexOf("internal suspend fun ScannerViewModel.runLocalImageOcrScanIfPossible", imageStart)
        assertTrue("onImagePicked must exist before the local OCR helper.", imageStart >= 0 && imageEnd > imageStart)

        val imageFlow = viewModelSource.substring(imageStart, imageEnd)
        val localOcrIndex = imageFlow.indexOf("runLocalImageOcrScanIfPossible(uri, context)")
        val cloudOcrIndex = imageFlow.indexOf("uploadApi.extractImage(body, source)")
        assertTrue("Image scan must keep local OCR as fallback.", localOcrIndex >= 0)
        assertTrue("Image scan must use backend extraction first so QR payloads are decoded.", cloudOcrIndex >= 0 && cloudOcrIndex < localOcrIndex)
        assertTrue(
            "Backend extraction status should name QR decoding, not only OCR.",
            imageFlow.contains("Extragem text, linkuri și coduri QR din imagine...")
        )
        assertTrue(
            "Image upload must be normalized under the backend image limit before calling extraction.",
            imageFlow.contains("prepareInvoiceImageUpload(") &&
                imageFlow.contains("maxBytes = ScannerViewModel.MAX_IMAGE_UPLOAD_BYTES")
        )
        assertTrue(
            "Android image upload limit must match backend MAX_IMAGE_BYTES, not the larger generic file limit.",
            viewModelSource.contains("internal const val MAX_IMAGE_UPLOAD_BYTES = 10L * 1024L * 1024L")
        )
        assertTrue(
            "Android must preserve backend QR payloads as URL evidence for preview/orchestration.",
            viewModelSource.contains("(response.qrPayloads ?: emptyList()).flatMap { extractUrls(it) }")
        )
        assertTrue(
            "ExtractionResponse must deserialize qr_payloads from backend extraction.",
            File("src/main/java/ro/sigurscan/app/SigurScanApi.kt").readText()
                .contains("@SerializedName(\"qr_payloads\") val qrPayloads: List<String>? = null")
        )
        assertTrue(
            "Local OCR fallback should remain available when upload cannot run.",
            imageFlow.contains("Extragerea cloud nu a reușit. Încercăm OCR local...")
        )
    }

    @Test
    fun invoiceCanBeCapturedWithCameraAndRoutedToInvoiceEndpoint() {
        val activitySource = uiPackageSource()
        val manifestSource = File("src/main/AndroidManifest.xml").readText()
        val viewModelSource = viewModelSource()
        val apiSource = File("src/main/java/ro/sigurscan/app/SigurScanApi.kt").readText()

        assertTrue(
            "Invoice capture must use Android's camera capture contract, not only document picker.",
            activitySource.contains("ActivityResultContracts.TakePicture()")
        )
        assertTrue(
            "Invoice capture needs a FileProvider URI for the camera app output.",
            activitySource.contains("createInvoiceCaptureUri(context)")
        )
        assertTrue(
            "Successful invoice photo capture must stage the photo for the same optional XML + invoice endpoint flow.",
            activitySource.contains("stageInvoiceForOptionalXml(capturedUri)") &&
                activitySource.contains("viewModel.scanInvoiceFromDocument(invoiceUri, context)")
        )
        assertTrue(
            "Invoice camera capture must request CAMERA permission before launching TakePicture.",
            activitySource.contains("invoiceCameraPermissionLauncher") &&
                activitySource.contains("ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA)")
        )
        assertTrue(
            "Invoice scan must use one entry point and then offer camera or document choices.",
            activitySource.contains("InvoiceSourceChooserDialog") &&
                activitySource.contains("Fă poză") &&
                activitySource.contains("Încarcă imagine/PDF")
        )
        assertTrue(
            "Invoice flow must offer optional official e-Factura XML after selecting the invoice.",
            activitySource.contains("OfficialInvoiceXmlChooserDialog") &&
                activitySource.contains("Atașează XML e-Factura") &&
                activitySource.contains("Continuă fără XML")
        )
        assertTrue(
            "Closing the optional XML dialog must continue the invoice scan without XML, not discard the staged invoice.",
            activitySource.contains("fun continueInvoiceWithoutOfficialXml()") &&
                activitySource.contains("onDismiss = { continueInvoiceWithoutOfficialXml() }") &&
                activitySource.contains("onSkip = { continueInvoiceWithoutOfficialXml() }")
        )
        assertTrue(
            "Invoice API upload must support optional official_xml_file without replacing pdf_file/image_file.",
            apiSource.contains("officialXmlFile") &&
                viewModelSource.contains("officialXmlUri: Uri? = null") &&
                viewModelSource.contains("""createFormData("official_xml_file"""")
        )
        assertTrue(
            "Large invoice images must be normalized before upload so Cloud OCR does not receive raw multi-megabyte camera files.",
            viewModelSource.contains("prepareInvoiceImageUpload(uri, context)") &&
                viewModelSource.contains("MAX_INVOICE_IMAGE_EDGE_PX") &&
                viewModelSource.contains("image/jpeg")
        )
        assertFalse(
            "Invoice camera must not be a second standalone tile next to Scanează Factură.",
            activitySource.contains("InvoiceCaptureEntryCard")
        )
        assertTrue(
            "Manifest must declare a FileProvider for camera output URIs.",
            manifestSource.contains("androidx.core.content.FileProvider") &&
                manifestSource.contains("android.support.FILE_PROVIDER_PATHS")
        )
    }

    @Test
    fun pdfAndUnsupportedFileFailuresStayExplicitAndNonVerdict() {
        val viewModelSource = viewModelSource()
        val fileStart = viewModelSource.indexOf("fun ScannerViewModel.onFilePicked(uri: Uri, context: Context)")
        val fileEnd = viewModelSource.indexOf("internal fun ScannerViewModel.getFileName", fileStart)
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
    fun emailAndHtmlImportsReleaseLoadingBeforeTriggeringScan() {
        val viewModelSource = viewModelSource()
        val fileStart = viewModelSource.indexOf("fun ScannerViewModel.onFilePicked(uri: Uri, context: Context)")
        val fileEnd = viewModelSource.indexOf("internal fun ScannerViewModel.getFileName", fileStart)
        assertTrue("onFilePicked must exist.", fileStart >= 0 && fileEnd > fileStart)

        val fileFlow = viewModelSource.substring(fileStart, fileEnd)
        val emailFlowStart = fileFlow.indexOf("if (importKind == FileImportKind.HTML || importKind == FileImportKind.EMAIL) {")
        val emailFlowEnd = fileFlow.indexOf("""loading = true
    loadingMsg = "Analizăm documentul PDF..."""", emailFlowStart)
        assertTrue("HTML/EML file-import branch must exist before the PDF branch.", emailFlowStart >= 0 && emailFlowEnd > emailFlowStart)

        val emailFlow = fileFlow.substring(emailFlowStart, emailFlowEnd)
        val resetThenScan = Regex("""loading = false\s+loadingMsg = ""\s+onScanClick\(\)""")
        assertTrue(
            "HTML/EML imports must clear the file-loading state before triggering orchestrated scan, otherwise the UI stays blocked on 'Analizăm fișierul email...'.",
            resetThenScan.findAll(emailFlow).count() >= 2
        )
    }

    @Test
    fun audioShareIsAcceptedButFallsBackToTranscriptUntilAsrIsEnabled() {
        val manifestSource = File("src/main/AndroidManifest.xml").readText()
        val activitySource = uiPackageSource()
        val classifierSource = File("src/main/java/ro/sigurscan/app/FileImportClassifier.kt").readText()
        val viewModelSource = viewModelSource()
        val fileStart = viewModelSource.indexOf("fun ScannerViewModel.onFilePicked(uri: Uri, context: Context)")
        val fileEnd = viewModelSource.indexOf("internal fun ScannerViewModel.getFileName", fileStart)
        assertTrue("onFilePicked must exist.", fileStart >= 0 && fileEnd > fileStart)
        val fileFlow = viewModelSource.substring(fileStart, fileEnd)

        assertTrue("Manifest must expose user-initiated audio shares.", manifestSource.contains("""android:mimeType="audio/*""""))
        assertTrue("Audio shares should be labeled distinctly in the pending-file UI.", activitySource.contains("Audio partajat"))
        assertTrue("Audio MIME/extensions need a dedicated classifier result, not generic unsupported.", classifierSource.contains("FileImportKind.AUDIO"))
        assertTrue(
            "Audio files must not be sent through PDF/image extraction while ASR is disabled.",
            fileFlow.indexOf("FileImportKind.AUDIO") in 0 until fileFlow.indexOf("FileImportKind.TEXT")
        )
        assertTrue(
            "Audio share fallback must tell the user to provide a transcript instead of silently failing.",
            fileFlow.contains("Audio primit. Transcrierea audio nu este activă încă; poți lipi transcriptul.")
        )
        assertTrue(
            "Audio share fallback should use explicit audio telemetry.",
            fileFlow.contains("""inputKind = "import_audio_file"""") &&
                fileFlow.contains("""channel = "audio_share"""")
        )
    }

    @Test
    fun neutralPendingAssessmentBuilderCannotEmitRiskVerdict() {
        val viewModelSource = viewModelSource()
        assertFalse(
            "ScannerViewModel must not keep an offline verdict evaluator; pending UI state is not a verdict.",
            viewModelSource.contains("evaluateOfflineText")
        )
        val start = viewModelSource.indexOf("internal fun buildNeutralPendingAssessment(scannedText: String): OfflineAssessment")
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
    fun radarManualPhoneReportUsesHashOnlyCommunityPayload() {
        // Radar logic was extracted from the ScannerViewModel God object into ScannerViewModelRadar.kt
        // as extension functions; the hash-only community payload behaviour is unchanged.
        val viewModelSource = File("src/main/java/ro/sigurscan/app/ScannerViewModelRadar.kt").readText()
        val start = viewModelSource.indexOf("fun ScannerViewModel.reportRadarPhoneNumber(")
        val end = viewModelSource.indexOf("fun ScannerViewModel.refreshRadarScreeningAudit()", start)

        assertTrue("Radar manual phone report flow must exist.", start >= 0 && end > start)

        val functionBody = viewModelSource.substring(start, end)
        assertTrue(functionBody.contains("PhoneNumberHasher.normalizePhoneNumber(rawPhone)"))
        assertTrue(functionBody.contains("PhoneNumberHasher.hashPhone(normalizedPhone)"))
        assertTrue(functionBody.contains("""targetType = "phone""""))
        assertTrue(functionBody.contains("""source = "android_radar_manual""""))
        assertFalse(
            "Community report payload must not send the raw phone number.",
            functionBody.contains("hash = normalizedPhone") || functionBody.contains("hash = rawPhone")
        )
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

    @Test
    fun bottomNavigationKeepsTabsAboveSystemGestureArea() {
        val activitySource = uiPackageSource()
        val bottomNavStart = activitySource.indexOf("fun BottomNavigationBar(activeTab: String, onTabClick: (String) -> Unit)")
        val bottomNavEnd = activitySource.indexOf("// ─────────────────────────────────────────────────────────────", bottomNavStart)
        assertTrue("BottomNavigationBar must exist.", bottomNavStart >= 0 && bottomNavEnd > bottomNavStart)

        val bottomNavSource = activitySource.substring(bottomNavStart, bottomNavEnd)
        assertTrue(
            "Bottom navigation must reserve navigation bar inset on gesture-navigation phones and keep the central scan slot tappable beyond the icon itself.",
            bottomNavSource.contains("WindowInsets.navigationBars.asPaddingValues().calculateBottomPadding()") &&
                bottomNavSource.contains(".height(80.dp + navigationBarInset)") &&
                bottomNavSource.contains(".padding(bottom = navigationBarInset)") &&
                bottomNavSource.contains(".fillMaxHeight()") &&
                bottomNavSource.contains(".clickable { onTabClick(\"scan\") }")
        )
    }

}
