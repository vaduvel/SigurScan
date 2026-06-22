package ro.sigurscan.app

import android.Manifest
import android.app.Application
import android.content.Context
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import android.graphics.pdf.PdfRenderer
import android.os.ParcelFileDescriptor
import android.provider.OpenableColumns
import android.content.SharedPreferences
import android.text.Html
import android.util.Base64
import android.util.Log
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.core.content.ContextCompat
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.common.InputImage
import com.google.mlkit.vision.text.TextRecognition
import com.google.mlkit.vision.text.latin.TextRecognizerOptions
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.launch
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.serialization.Serializable
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.MultipartBody
import okhttp3.OkHttpClient
import okhttp3.RequestBody.Companion.asRequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Request
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import java.io.File
import java.io.ByteArrayOutputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.SocketTimeoutException
import java.net.URI
import java.net.UnknownHostException
import java.net.URLDecoder
import java.security.MessageDigest
import java.nio.charset.StandardCharsets
import java.util.*
import java.util.concurrent.TimeUnit
import java.util.regex.Pattern
import javax.net.ssl.SSLException
import kotlin.math.roundToInt
import kotlin.math.max
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.coroutines.suspendCoroutine
import retrofit2.HttpException

// The orchestrated backend-scan pipeline (preliminary assessment, result cache, polling,
// response mapping, onScanClick entry point), extracted from the ScannerViewModel God object
// as behaviour-preserving extension functions.

internal fun ScannerViewModel.startPreliminaryUrlAssessment(rawInput: String, urls: List<String>): OfflineAssessment? {
    val primaryUrl = urls.firstOrNull()?.let(::normalizeUrl) ?: return null
    val pendingIntel = ThreatIntelSourceResult(
        source = "urlscan.io",
        verdict = "Pending",
        severity = "unknown",
        details = "Se generează captura paginii finale."
    )
    val preliminary = buildNeutralPendingAssessment(rawInput).copy(
        serverInfo = "Se generează captura paginii finale...",
        redirectChain = listOf(primaryUrl),
        finalUrl = primaryUrl,
        reputationVerdict = "Se verifică",
        domainAgeText = "Se verifică",
        sslStatus = if (primaryUrl.startsWith("https", ignoreCase = true)) "Valid (HTTPS)" else "Neverificat",
        aiConfidence = "Analiză online în curs",
        threatIntel = listOf(pendingIntel)
    )
    val guarded = applyEvidenceGate(
        current = preliminary,
        rawInput = rawInput,
        primaryUrl = primaryUrl,
        finalUrl = primaryUrl,
        redirectChain = listOf(primaryUrl),
        threatIntel = listOf(pendingIntel),
        providerStates = pendingOnlineProviderStates(),
        completeness = EvidenceCompleteness.PARTIAL_ONLINE
    )
    assessment = guarded
    addToHistory(guarded)
    triggerSandboxAnalysis(primaryUrl, guarded.scanId)
    return guarded
}

internal fun ScannerViewModel.startBackendOrchestratedPendingAssessment(rawInput: String, urls: List<String>): OfflineAssessment? {
    val primaryUrl = urls.firstOrNull()?.let(::normalizeUrl)
    val pendingIntel = ThreatIntelSourceResult(
        source = "SigurScan Backend",
        verdict = "Scanning",
        severity = "unknown",
        details = "Scanarea rulează pe backend prin pilonii necesari."
    )
    val preliminary = buildNeutralPendingAssessment(rawInput).copy(
        scanId = UUID.randomUUID().toString(),
        serverInfo = "Scanarea rulează. Așteptăm rezultatele complete.",
        redirectChain = primaryUrl?.let { listOf(it) }.orEmpty(),
        finalUrl = primaryUrl,
        reputationVerdict = "Se verifică",
        domainAgeText = "Se verifică",
        sslStatus = primaryUrl?.let { if (it.startsWith("https", ignoreCase = true)) "Valid (HTTPS)" else "Neverificat" } ?: "Neverificat",
        aiConfidence = "Analiză online în curs",
        threatIntel = listOf(pendingIntel)
    )
    val guarded = applyEvidenceGate(
        current = preliminary,
        rawInput = rawInput,
        primaryUrl = primaryUrl,
        finalUrl = null,
        redirectChain = primaryUrl?.let { listOf(it) }.orEmpty(),
        threatIntel = listOf(pendingIntel),
        providerStates = pendingOnlineProviderStates(),
        completeness = EvidenceCompleteness.PARTIAL_ONLINE
    )
    assessment = guarded
    return guarded
}

internal fun ScannerViewModel.publishAssessmentResult(existingScanId: String?, updated: OfflineAssessment) {
    val isFinal = updated.gateResult?.finality == GateFinality.FINAL
    if (existingScanId != null && currentAssessmentForScan(existingScanId) != null) {
        if (isFinal) {
            replaceAssessment(existingScanId, updated)
            if (historyItems.none { it.scanId == updated.scanId }) {
                historyItems.add(0, updated)
                calculateStats()
                saveHistory()
            }
        } else {
            val idx = historyItems.indexOfFirst { it.scanId == existingScanId }
            if (idx >= 0) {
                historyItems[idx] = updated
                calculateStats()
            }
            if (assessment?.scanId == existingScanId) {
                assessment = updated
            }
        }
    } else {
        assessment = updated
        if (isFinal) {
            addToHistory(updated)
        }
    }
}

internal fun ScannerViewModel.cachedAssessmentFor(cacheKey: String): OfflineAssessment? {
    val now = System.currentTimeMillis()
    val cached = resultCache[cacheKey] ?: return null
    if (cachedPreviewNeedsRefresh(cached.assessment)) {
        resultCache.remove(cacheKey)
        persistResultCache()
        return null
    }
    return if (cached.expiresAtMillis > now) {
        cached.assessment.copy(
            cacheStatus = ScanCacheStatus(
                cacheKey = cached.cacheKey,
                cachedAtMillis = cached.cachedAtMillis,
                expiresAtMillis = cached.expiresAtMillis,
                source = "local"
            ),
            serverInfo = "Verificat anterior. Poți rescana dacă vrei o verificare proaspătă."
        )
    } else {
        resultCache.remove(cacheKey)
        persistResultCache()
        null
    }
}

internal fun ScannerViewModel.saveFinalAssessmentToResultCache(cacheKey: String, assessment: OfflineAssessment) {
    if (assessment.gateResult?.finality != GateFinality.FINAL) return
    val now = System.currentTimeMillis()
    resultCache[cacheKey] = ScannerViewModel.CachedAssessmentRecord(
        cacheKey = cacheKey,
        assessment = assessment.copy(cacheStatus = null),
        cachedAtMillis = now,
        expiresAtMillis = now + RESULT_CACHE_TTL_MILLIS
    )
    trimResultCache()
    persistResultCache()
}

internal fun ScannerViewModel.trimResultCache() {
    if (resultCache.size <= ScannerViewModel.MAX_RESULT_CACHE_ITEMS) return
    val keep = resultCache.values
        .sortedByDescending { it.cachedAtMillis }
        .take(ScannerViewModel.MAX_RESULT_CACHE_ITEMS)
    resultCache.clear()
    keep.forEach { resultCache[it.cacheKey] = it }
}

internal fun ScannerViewModel.persistResultCache() {
    val now = System.currentTimeMillis()
    val snapshot = resultCache.values
        .filter { it.expiresAtMillis > now }
        .sortedByDescending { it.cachedAtMillis }
        .take(ScannerViewModel.MAX_RESULT_CACHE_ITEMS)
    viewModelScope.launch(Dispatchers.IO) {
        prefs.edit().putString(ScannerViewModel.RESULT_CACHE_PREF_KEY, gson.toJson(snapshot)).apply()
    }
}

internal fun ScannerViewModel.isSameNormalizedUrl(left: String?, right: String?): Boolean {
    val normalizedLeft = normalizeCandidateUrl(left) ?: left?.let(::normalizeUrl)
    val normalizedRight = normalizeCandidateUrl(right) ?: right?.let(::normalizeUrl)
    return !normalizedLeft.isNullOrBlank() && normalizedLeft == normalizedRight
}

internal fun ScannerViewModel.orchestratedRequest(
    rawInput: String,
    htmlPayload: String?,
    urls: List<String>,
    forcedInputType: String? = null,
    emailAuth: Map<String, Any>? = null
): OrchestratedScanRequest {
    if (forcedInputType == "offer") {
        return OrchestratedScanRequest(
            inputType = "offer",
            text = rawInput.ifBlank { urls.joinToString("\n") },
            sourceChannel = activeEvidenceChannel(rawInput) ?: "android_offer_scan"
        )
    }

    return when {
        !htmlPayload.isNullOrBlank() -> OrchestratedScanRequest(
            inputType = "email_html",
            text = rawInput,
            htmlContent = htmlPayload,
            sourceChannel = activeEvidenceChannel(rawInput) ?: "android_html_share",
            emailAuth = emailAuth
        )
        urls.isNotEmpty() && looksLikeUrlOnly(rawInput.trim(), urls.first()) -> OrchestratedScanRequest(
            inputType = "url",
            url = normalizeUrl(urls.first()),
            sourceChannel = activeEvidenceChannel(rawInput) ?: "android_url_scan"
        )
        else -> OrchestratedScanRequest(
            inputType = if (emailAuth != null) "email" else "text",
            text = rawInput,
            sourceChannel = activeEvidenceChannel(rawInput) ?: "android_native",
            emailAuth = emailAuth
        )
    }
}

internal fun ScannerViewModel.linksFromExtraction(response: ExtractionResponse, extractedText: String): List<String> {
    return (
        (response.extractedUrls ?: emptyList()) +
            (response.qrPayloads ?: emptyList()).flatMap { extractUrls(it) } +
            extractUrls(extractedText) +
            extractHtmlLinks(extractedText) +
            response.htmlContent.orEmpty().let { html ->
                if (html.isBlank()) emptyList() else extractHtmlLinks(html)
            }
        )
        .mapNotNull { normalizeCandidateUrl(it) ?: it.takeIf { candidate -> candidate.isNotBlank() } }
        .distinct()
}

internal suspend fun ScannerViewModel.runBackendOrchestratedScanFromExtraction(
    response: ExtractionResponse,
    fileName: String,
    inputKind: String,
    channel: String,
    forcedInputType: String? = null
) {
    val extractedText = response.redactedText.orEmpty().trim()
    val htmlPayload = response.htmlContent?.takeIf { it.isNotBlank() }
    val links = linksFromExtraction(response, extractedText)
    if (extractedText.isBlank() && links.isEmpty()) {
        val result = applyEvidenceGate(
            current = OfflineAssessment(
                family = "Scanare incompletă",
                riskScore = 0,
                riskLevel = "unknown",
                reasons = listOf(response.warning ?: "Nu am putut extrage text sau linkuri verificabile din fișier."),
                safeActions = listOf("Reîncearcă scanarea sau trimite textul/linkul în format editabil."),
                keyDangers = listOf("Nu avem suficiente dovezi tehnice pentru verdict."),
                originalText = "Nu s-a extras conținut verificabil din $fileName."
            ),
            rawInput = "Conținut neextras: $fileName",
            inputKind = inputKind,
            channel = channel,
            providerStates = unavailableProviderStates(),
            completeness = EvidenceCompleteness.LOCAL_ONLY
        )
        publishAssessmentResult(null, result)
        return
    }

    val assembledInput = MailShareInputAssembler.buildMailScanInput(
        extractedText.ifBlank { "Conținut extras din $fileName." },
        links,
        fileName
    )
    text = assembledInput
    stagedEvidenceHtml = htmlPayload
    stagedEvidenceLinks = links
    stagedEvidenceText = assembledInput
    stagedEvidenceInputKind = inputKind
    stagedEvidenceChannel = channel
    runBackendOrchestratedScan(
        assembledInput,
        htmlPayload,
        links,
        forcedInputType = forcedInputType,
        emailAuth = response.emailAuth
    )
}

internal fun ScannerViewModel.providerStatesFromOrchestratedPillars(
    pillars: Map<String, OrchestratedPillarState>?
): Map<ProviderId, ProviderState> {
    fun mapStatus(value: String?): ProviderStatus = when (value?.lowercase(Locale.US)) {
        "ok" -> ProviderStatus.OK
        "pending" -> ProviderStatus.PENDING
        "not_required" -> ProviderStatus.SKIPPED
        "rate_limited" -> ProviderStatus.RATE_LIMITED
        "timeout" -> ProviderStatus.TIMEOUT
        "error" -> ProviderStatus.ERROR
        else -> ProviderStatus.NOT_RUN
    }

    fun state(key: String, provider: ProviderId): ProviderState? {
        val raw = pillars?.get(key) ?: return null
        return ProviderState(
            provider = provider,
            status = mapStatus(raw.status),
            note = raw.details
        )
    }

    return listOfNotNull(
        state("google_web_risk", ProviderId.WEB_RISK),
        state("urlscan", ProviderId.URLSCAN),
        state("phishing_database", ProviderId.PHISHING_DATABASE),
        state("claim_verifier", ProviderId.CLAIM_VERIFIER)
    ).associateBy { it.provider }
}

internal fun ScannerViewModel.buildAssessmentFromBackendScanResponse(
    response: ScanResponse,
    rawInput: String,
    urls: List<String>,
    preview: OrchestratedPreview? = null,
    orchestratedStatusMessage: String? = null,
    providerStates: Map<ProviderId, ProviderState> = emptyMap()
): OfflineAssessment {
    val evidence = response.evidence
    val extractedUrls = mapList(evidence?.get("extracted_urls")).ifEmpty {
        response.extractedUrls ?: response.resolvedUrls ?: emptyList()
    }
    val firstUrlEntry = extractedUrls.firstOrNull()
    val backendPrimaryUrl = pickPrimaryThreatIntelUrl(response, rawInput).takeIf { it.isNotBlank() }
    val intelSummary = evidence?.get("external_intel_summary") as? Map<*, *>
    val reputation = if (intelSummary.isNullOrEmpty()) "Se verifică" else "Verificat prin ${intelSummary.size} surse"
    val ageDays = (firstUrlEntry?.get("domain_age_days") as? Double)?.toInt()
    val ageText = when {
        ageDays == null -> "Necunoscută"
        ageDays > 365 -> "${ageDays / 365} ani+"
        else -> "$ageDays zile"
    }
    val resolvedFinalUrl = normalizeCandidateUrl(preview?.finalUrl)
        ?: normalizeCandidateUrl(firstUrlEntry?.get("final_url")?.toString())
        ?: backendPrimaryUrl
        ?: ""
    val chain = mapList(firstUrlEntry?.get("redirect_chain"))
        .mapNotNull { normalizeCandidateUrl(it["url"]?.toString()) }
        .ifEmpty { listOfNotNull(backendPrimaryUrl, resolvedFinalUrl.takeIf { it.isNotBlank() }) }
        .distinct()
    val threatIntel = buildThreatIntel(evidence, response)
    val visualEvidenceUrl = normalizeCandidateUrl(resolvedFinalUrl)
        ?: backendPrimaryUrl
        ?: urls.firstOrNull()
        ?: ""
    val result = OfflineAssessment(
        scanId = response.scanId,
        family = when {
            response.riskLevel == "critical" || response.riskLevel == "high" -> response.detectedFamily ?: "Scam detectat"
            response.riskLevel == "low" -> "Destinație verificată"
            else -> response.detectedFamily ?: "Analiză în curs"
        },
        riskScore = response.riskScore,
        riskLevel = response.riskLevel,
        reasons = response.reasons ?: emptyList(),
        safeActions = response.safeActions ?: emptyList(),
        keyDangers = response.keyDangers ?: emptyList(),
        originalText = rawInput,
        serverInfo = orchestratedScanServerInfo(
            statusMessage = orchestratedStatusMessage,
            preview = preview,
            isFinal = response.isFinal != false
        ),
        redirectChain = chain,
        finalUrl = visualEvidenceUrl.takeIf { it.isNotBlank() },
        offerAnalysis = response.offerAnalysis,
        reputationVerdict = reputation,
        domainAgeText = ageText,
        sslStatus = if (visualEvidenceUrl.startsWith("https", ignoreCase = true)) "Valid (HTTPS)" else "Neverificat",
        aiConfidence = response.aiVerdict ?: "Analiză automată finalizată",
        detectedButtons = mapButtons(response.buttons),
        emailAuth = mapEmailAuth(response.emailAuth),
        threatIntel = threatIntel,
        screenshotUrl = preview?.screenshotUrl,
        sandboxReportUrl = preview?.reportUrl,
        offerEvidence = offerEvidenceFrom(evidence),
        legal = response.legal,
        actionPlan = response.actionPlan
    )
    val snapshot = EvidenceSignalNormalizer.buildSnapshot(
        EvidenceNormalizerInput(
            scanId = response.scanId,
            inputKind = activeEvidenceInputKind(rawInput) ?: inferEvidenceInputKind(rawInput),
            channel = activeEvidenceChannel(rawInput) ?: inferEvidenceChannel(rawInput),
            rawText = rawInput,
            htmlContent = activeEvidenceHtml(rawInput),
            extractedLinks = activeEvidenceLinks(rawInput),
            primaryUrl = backendPrimaryUrl ?: urls.firstOrNull(),
            finalUrl = visualEvidenceUrl.takeIf { it.isNotBlank() },
            redirectChain = chain,
            threatIntel = threatIntel,
            providerStates = providerStates,
            backendEvidence = evidence,
            backendReasons = response.reasons ?: emptyList(),
            completeness = orchestratedEvidenceCompleteness(
                preview = preview,
                providerStates = providerStates,
                finalUrl = visualEvidenceUrl.takeIf { it.isNotBlank() }
            ),
            registryVersion = BrandKnowledgeRegistry.registryVersion(),
            corpusVersion = BrandKnowledgeRegistry.corpusVersion(),
            phishingDatabaseConfigured = true
        )
    )
    val gateResult = backendGateResult(response)
    return withGate(result,
        snapshot = snapshot,
        gateResult = gateResult,
        rawInput = rawInput,
        mergedThreatIntel = threatIntel
    )
}

internal fun ScannerViewModel.buildPendingAssessmentFromOrchestratedResponse(
    response: OrchestratedScanResponse,
    rawInput: String,
    urls: List<String>
): OfflineAssessment {
    val primaryUrl = normalizeCandidateUrl(response.preview?.finalUrl)
        ?: urls.firstOrNull()?.let(::normalizeUrl)
    val threatIntel = listOf(
        ThreatIntelSourceResult(
            source = "SigurScan Backend",
            verdict = "Scanning",
            severity = "unknown",
            details = response.statusMessage ?: "Scanarea rulează."
        )
    )
    val base = currentAssessmentForScan(response.scanId) ?: buildNeutralPendingAssessment(rawInput).copy(scanId = response.scanId)
    val updated = base.copy(
        scanId = response.scanId,
        serverInfo = response.statusMessage ?: "Scanarea rulează. Așteptăm rezultatele complete.",
        redirectChain = primaryUrl?.let { listOf(it) }.orEmpty(),
        finalUrl = primaryUrl,
        reputationVerdict = "Se verifică",
        domainAgeText = "Se verifică",
        sslStatus = primaryUrl?.let { if (it.startsWith("https", ignoreCase = true)) "Valid (HTTPS)" else "Neverificat" } ?: "Neverificat",
        aiConfidence = "Analiză online în curs",
        threatIntel = threatIntel,
        screenshotUrl = response.preview?.screenshotUrl,
        sandboxReportUrl = response.preview?.reportUrl
    )
    val snapshot = EvidenceSignalNormalizer.buildSnapshot(
        EvidenceNormalizerInput(
            scanId = response.scanId,
            inputKind = activeEvidenceInputKind(rawInput) ?: inferEvidenceInputKind(rawInput),
            channel = activeEvidenceChannel(rawInput) ?: inferEvidenceChannel(rawInput),
            rawText = rawInput,
            htmlContent = activeEvidenceHtml(rawInput),
            extractedLinks = activeEvidenceLinks(rawInput),
            primaryUrl = urls.firstOrNull(),
            finalUrl = response.preview?.finalUrl,
            redirectChain = primaryUrl?.let { listOf(it) }.orEmpty(),
            threatIntel = threatIntel,
            providerStates = providerStatesFromOrchestratedPillars(response.pillars),
            completeness = EvidenceCompleteness.PARTIAL_ONLINE,
            registryVersion = BrandKnowledgeRegistry.registryVersion(),
            corpusVersion = BrandKnowledgeRegistry.corpusVersion(),
            phishingDatabaseConfigured = true
        )
    )
    return withGate(updated,
        snapshot = snapshot,
        gateResult = backendScanInProgressGateResult(),
        rawInput = rawInput,
        mergedThreatIntel = threatIntel
    )
}

internal suspend fun ScannerViewModel.publishOrchestratedResponse(
    response: OrchestratedScanResponse,
    rawInput: String,
    urls: List<String>,
    existingScanId: String?,
    resultCacheKey: String? = null
) {
    val providerStates = providerStatesFromOrchestratedPillars(response.pillars)
    val remoteScreenshotUrl = response.preview?.screenshotUrl
    val preview = response.preview
    val updated = response.result?.let {
        try {
            buildAssessmentFromBackendScanResponse(
                response = it,
                rawInput = rawInput,
                urls = urls,
                preview = preview,
                orchestratedStatusMessage = response.statusMessage,
                providerStates = providerStates
            )
        } catch (mappingError: Exception) {
            Log.w(
                "SigurScan",
                "orchestrated response mapping failed: ${classifyOrchestratedError(mappingError)}",
                mappingError
            )
            buildDegradedAssessmentFromBackendScanResponse(
                response = it,
                rawInput = rawInput,
                urls = urls,
                preview = preview,
                orchestratedStatusMessage = response.statusMessage,
                providerStates = providerStates
            )
        }
    } ?: buildPendingAssessmentFromOrchestratedResponse(response, rawInput, urls)
    publishAssessmentResult(existingScanId ?: response.scanId, updated)
    if (response.result != null && updated.gateResult?.finality == GateFinality.FINAL) {
        loading = false
        if (!resultCacheKey.isNullOrBlank()) {
            if (shouldCacheFinalAssessment(response, updated)) {
                saveFinalAssessmentToResultCache(resultCacheKey, updated)
            }
        }
    }
    if (response.result != null && !remoteScreenshotUrl.isNullOrBlank()) {
        scheduleSandboxScreenshotRefresh(response.scanId, remoteScreenshotUrl)
    }
}

internal fun ScannerViewModel.shouldCacheFinalAssessment(
    response: OrchestratedScanResponse,
    assessment: OfflineAssessment
): Boolean {
    if (assessment.gateResult?.finality != GateFinality.FINAL) return false
    if (orchestratedPreviewStillPending(response.preview)) return false
    return true
}

internal suspend fun ScannerViewModel.publishOrchestratedPollingTimeout(
    response: OrchestratedScanResponse,
    rawInput: String,
    urls: List<String>,
    existingScanId: String?
) {
    val timeoutPreview = response.preview?.copy(
        status = "unavailable",
        reason = response.preview.reason ?: "android_polling_timeout",
        details = response.preview.details
            ?: "Preview-ul securizat nu a fost gata la timp. Verdictul curent rămâne afișat; rescanează pentru o captură proaspătă."
    ) ?: OrchestratedPreview(
        status = "unavailable",
        reason = "android_polling_timeout",
        details = "Verificarea a durat prea mult. Reîncearcă scanarea pentru rezultate proaspete.",
        finalUrl = urls.firstOrNull()
    )
    val timeoutResponse = response.copy(
        statusMessage = "Verificarea a durat prea mult. Rezultatul curent a fost afișat; poți rescana pentru actualizare.",
        preview = timeoutPreview
    )
    publishOrchestratedResponse(timeoutResponse, rawInput, urls, existingScanId)
    loading = false
    loadingMsg = ""
}

internal suspend fun ScannerViewModel.runBackendOrchestratedScan(
    rawInput: String,
    htmlPayload: String?,
    urls: List<String>,
    forcedInputType: String? = null,
    emailAuth: Map<String, Any>? = null
) {
    val cacheMaterial = if (forcedInputType.isNullOrBlank()) rawInput else "input_type=$forcedInputType\n$rawInput"
    val resultCacheKey = scanResultCacheKey(cacheMaterial, htmlPayload, urls)
    val preliminary = startBackendOrchestratedPendingAssessment(rawInput, urls)
    var response = scanStartApi.startOrchestratedScan(orchestratedRequest(rawInput, htmlPayload, urls, forcedInputType, emailAuth))
    publishOrchestratedResponse(response, rawInput, urls, preliminary?.scanId, resultCacheKey)

    val pollingDeadlineNanos = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(ORCHESTRATED_POLLING_BUDGET_MILLIS)
    var pollingFailures = 0
    while (shouldContinueOrchestratedPolling(response) && System.nanoTime() < pollingDeadlineNanos) {
        kotlinx.coroutines.delay(orchestratedPollDelayMillis(response))
        response = try {
            scanPollApi.getOrchestratedScan(response.scanId).also {
                pollingFailures = 0
            }
        } catch (pollError: Exception) {
            pollingFailures += 1
            Log.w("SigurScan", "orchestrated poll failed: ${pollError.javaClass.simpleName}")
            if (pollingFailures >= 3) {
                break
            }
            continue
        }
        publishOrchestratedResponse(response, rawInput, urls, response.scanId, resultCacheKey)
    }
    if (shouldContinueOrchestratedPolling(response)) {
        publishOrchestratedPollingTimeout(response, rawInput, urls, response.scanId)
    } else {
        launchFinalOrchestratedPreviewRefresh(response, rawInput, urls, response.scanId, resultCacheKey)
    }
}

internal fun ScannerViewModel.launchFinalOrchestratedPreviewRefresh(
    initialResponse: OrchestratedScanResponse,
    rawInput: String,
    urls: List<String>,
    existingScanId: String?,
    resultCacheKey: String?
) {
    if (!shouldRefreshFinalOrchestratedPreview(initialResponse)) return
    viewModelScope.launch {
        var response = initialResponse
        var refreshFailures = 0
        while (shouldRefreshFinalOrchestratedPreview(response)) {
            kotlinx.coroutines.delay(orchestratedPollDelayMillis(response))
            response = try {
                scanPollApi.getOrchestratedScan(response.scanId).also {
                    refreshFailures = 0
                }
            } catch (pollError: Exception) {
                Log.w("SigurScan", "orchestrated preview active refresh failed: ${pollError.javaClass.simpleName}")
                try {
                    scanPollApi.getOrchestratedScanStatus(response.scanId).also {
                        refreshFailures = 0
                    }
                } catch (statusError: Exception) {
                    refreshFailures += 1
                    Log.w("SigurScan", "orchestrated preview status refresh failed: ${statusError.javaClass.simpleName}")
                    if (refreshFailures >= 3) {
                        return@launch
                    }
                    continue
                }
            }
            publishOrchestratedResponse(response, rawInput, urls, existingScanId, resultCacheKey)
        }
    }
}

internal fun ScannerViewModel.buildDegradedAssessmentFromBackendScanResponse(
    response: ScanResponse,
    rawInput: String,
    urls: List<String>,
    preview: OrchestratedPreview? = null,
    orchestratedStatusMessage: String? = null,
    providerStates: Map<ProviderId, ProviderState> = emptyMap()
): OfflineAssessment {
    val finalUrl = normalizeCandidateUrl(preview?.finalUrl)
        ?: urls.firstOrNull()?.let(::normalizeUrl)
    val redirectChain = listOfNotNull(finalUrl)
    val threatIntel = listOf(
        ThreatIntelSourceResult(
            source = "SigurScan Backend",
            verdict = response.userRiskLabel ?: response.riskLevel.ifBlank { "UNKNOWN" },
            severity = response.riskLevel.ifBlank { "unknown" },
            details = response.reasons?.firstOrNull()
        )
    )
    val base = OfflineAssessment(
        scanId = response.scanId,
        family = when {
            response.riskLevel == "critical" || response.riskLevel == "high" -> response.detectedFamily ?: "Scam detectat"
            response.riskLevel == "low" -> "Destinație verificată"
            else -> response.detectedFamily ?: "Analiză finalizată"
        },
        riskScore = response.riskScore,
        riskLevel = response.riskLevel,
        reasons = response.reasons ?: emptyList(),
        safeActions = response.safeActions ?: emptyList(),
        keyDangers = response.keyDangers ?: emptyList(),
        originalText = rawInput,
        screenshotUrl = preview?.screenshotUrl,
        serverInfo = orchestratedScanServerInfo(
            statusMessage = orchestratedStatusMessage,
            preview = preview,
            isFinal = response.isFinal != false
        ),
        redirectChain = redirectChain,
        finalUrl = finalUrl,
        reputationVerdict = if (providerStates.isEmpty()) "Se verifică" else "Verificat prin ${providerStates.size} surse",
        domainAgeText = "Se verifică",
        sslStatus = if (finalUrl?.startsWith("https", ignoreCase = true) == true) "Valid (HTTPS)" else "Neverificat",
        aiConfidence = response.aiVerdict ?: "Analiză automată finalizată",
        threatIntel = threatIntel,
        sandboxReportUrl = preview?.reportUrl,
        legal = response.legal,
        actionPlan = response.actionPlan
    )
    val snapshot = EvidenceSnapshot(
        scanId = response.scanId,
        inputKind = activeEvidenceInputKind(rawInput) ?: inferEvidenceInputKind(rawInput),
        channel = activeEvidenceChannel(rawInput) ?: inferEvidenceChannel(rawInput),
        primaryUrl = urls.firstOrNull(),
        finalUrl = finalUrl,
        redirectChain = redirectChain,
        providerStates = providerStates,
        registryVersion = BrandKnowledgeRegistry.registryVersion(),
        corpusVersion = BrandKnowledgeRegistry.corpusVersion(),
        completeness = orchestratedEvidenceCompleteness(preview, providerStates, finalUrl)
    )
    return withGate(base, snapshot, backendGateResult(response), rawInput, threatIntel)
}

internal fun ScannerViewModel.classifyOrchestratedError(error: Throwable): String = when (error) {
    is HttpException -> "HTTP_${error.code()}"
    is SocketTimeoutException -> "TIMEOUT"
    is UnknownHostException -> "DNS"
    is SSLException -> "SSL"
    is IOException -> "IO"
    is IllegalStateException -> "STATE"
    is ClassCastException -> "CAST"
    else -> error.javaClass.simpleName.ifBlank { "UNKNOWN" }
}

fun ScannerViewModel.onScanClick(forceRefresh: Boolean = false) {
    if (loading || text.isBlank()) return
    loading = true
    clearVisibleResultForNewScan()
    loadingMsg = "Analizăm textul și link-urile..."

    viewModelScope.launch {
        val rawInput = text
        val htmlPayload = activeEvidenceHtml(rawInput)
        val urls = activeEvidenceLinks(rawInput).ifEmpty { extractUrls(rawInput) }
        try {
            val cacheKey = scanResultCacheKey(rawInput, htmlPayload, urls)
            if (!forceRefresh) {
                cachedAssessmentFor(cacheKey)?.let { cached ->
                    assessment = cached
                    loading = false
                    return@launch
                }
            }
            runBackendOrchestratedScan(rawInput, htmlPayload, urls)
            return@launch
        } catch (orchestratedError: Exception) {
            val diagnosticCode = classifyOrchestratedError(orchestratedError)
            Log.w("SigurScan", "orchestrated scan failed: $diagnosticCode", orchestratedError)
            assessment?.takeIf { current ->
                current.originalText == rawInput &&
                    (
                        current.gateResult?.finality == GateFinality.FINAL ||
                            current.gateResult?.asyncExpected == true
                        )
            }?.let {
                return@launch
            }
            val fallbackPrimaryUrl = urls.firstOrNull()?.let(::normalizeUrl)
            val result = applyEvidenceGate(
                current = buildNeutralPendingAssessment(rawInput).copy(
                    scanId = UUID.randomUUID().toString(),
                    serverInfo = "Nu am putut obține rezultatele pilonilor. Reîncearcă scanarea. Cod: $diagnosticCode.",
                    finalUrl = fallbackPrimaryUrl,
                    redirectChain = fallbackPrimaryUrl?.let { listOf(it) }.orEmpty()
                ),
                rawInput = rawInput,
                primaryUrl = fallbackPrimaryUrl,
                finalUrl = null,
                redirectChain = fallbackPrimaryUrl?.let { listOf(it) }.orEmpty(),
                providerStates = unavailableProviderStates(),
                completeness = EvidenceCompleteness.PARTIAL_ONLINE
            )
            publishAssessmentResult(null, result)
            return@launch
        } finally {
            loading = false
        }
    }
}

internal fun ScannerViewModel.isTrustedOfficialUrl(url: String): Boolean {
    val host = runCatching {
        Uri.parse(normalizeUrl(url)).host?.lowercase(Locale.ROOT).orEmpty()
    }.getOrDefault("")
    if (host.isBlank()) return false

    return BrandKnowledgeRegistry.isOfficialHost(host)
}
