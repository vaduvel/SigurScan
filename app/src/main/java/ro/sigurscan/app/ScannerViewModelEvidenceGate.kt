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

// Evidence-gate evaluation (applyEvidenceGate, withGate, threat-intel re-evaluation,
// evidence-input inference and provider-state helpers), extracted from the ScannerViewModel
// God object as behaviour-preserving extension functions.

internal fun ScannerViewModel.applyEvidenceGate(
    current: OfflineAssessment,
    rawInput: String,
    inputKind: String = activeEvidenceInputKind(rawInput) ?: inferEvidenceInputKind(rawInput),
    channel: String = activeEvidenceChannel(rawInput) ?: inferEvidenceChannel(rawInput),
    htmlContent: String? = activeEvidenceHtml(rawInput),
    extractedLinks: List<String> = activeEvidenceLinks(rawInput),
    primaryUrl: String? = null,
    finalUrl: String? = current.finalUrl,
    redirectChain: List<String> = current.redirectChain,
    threatIntel: List<ThreatIntelSourceResult> = current.threatIntel,
    providerStates: Map<ProviderId, ProviderState> = emptyMap(),
    completeness: EvidenceCompleteness? = null
): OfflineAssessment {
    val snapshot = EvidenceSignalNormalizer.buildSnapshot(
        EvidenceNormalizerInput(
            scanId = current.scanId,
            inputKind = inputKind,
            channel = channel,
            rawText = rawInput,
            htmlContent = htmlContent,
            extractedLinks = extractedLinks,
            primaryUrl = primaryUrl,
            finalUrl = finalUrl,
            redirectChain = redirectChain,
            senderDomain = null,
            threatIntel = threatIntel,
            providerStates = providerStates,
            completeness = completeness,
            registryVersion = BrandKnowledgeRegistry.registryVersion(),
            corpusVersion = BrandKnowledgeRegistry.corpusVersion(),
            phishingDatabaseConfigured = true
        )
    )
    val gateResult = evidenceGate.evaluate(snapshot)
    return withGate(current, snapshot, gateResult, rawInput, threatIntel)
}

// Plain member function (not a member extension) so the orchestrated-scan extension
// functions in ScannerViewModelOrchestratedScan.kt can apply the gate. Takes the
// assessment as `self` instead of an extension receiver.
internal fun ScannerViewModel.withGate(
    self: OfflineAssessment,
    snapshot: EvidenceSnapshot,
    gateResult: GateResult,
    rawInput: String,
    mergedThreatIntel: List<ThreatIntelSourceResult> = self.threatIntel
): OfflineAssessment {
    val gateReason = GateResultPresentation.reasonText(gateResult, snapshot)
    val gateActions = GateResultPresentation.recommendedActions(gateResult)
    return self.copy(
        family = GateResultPresentation.familyLabel(gateResult.action, self.family),
        riskScore = GateResultPresentation.legacyRiskScore(gateResult.action),
        riskLevel = GateResultPresentation.legacyRiskLevel(gateResult.action),
        reasons = (listOf(gateReason) + self.reasons).map { it.trim() }.filter { it.isNotBlank() }.distinct(),
        safeActions = (gateActions + self.safeActions).map { it.trim() }.filter { it.isNotBlank() }.distinct(),
        keyDangers = when (gateResult.action) {
            GateAction.DO_NOT_CONTINUE,
            GateAction.NO_ENTER_DATA,
            GateAction.NO_REPLY -> (listOf(GateResultPresentation.supportText(gateResult)) + self.keyDangers)
            else -> self.keyDangers
        }.map { it.trim() }.filter { it.isNotBlank() }.distinct(),
        originalText = redactedAuditSummary(rawInput, snapshot),
        finalUrl = snapshot.formActionUrl ?: snapshot.finalUrl ?: self.finalUrl,
        redirectChain = snapshot.redirectChain.ifEmpty { self.redirectChain },
        threatIntel = mergedThreatIntel,
        evidenceSnapshot = snapshot,
        gateResult = gateResult,
        inputFidelity = sharedContentFidelity
    )
}

internal fun ScannerViewModel.reevaluateGateWithThreatIntel(
    current: OfflineAssessment,
    threatIntel: List<ThreatIntelSourceResult>,
    finalUrl: String? = current.finalUrl,
    redirectChain: List<String> = current.redirectChain
): OfflineAssessment {
    val previous = current.evidenceSnapshot
    if (previous == null) {
        return applyEvidenceGate(
            current = current.copy(threatIntel = threatIntel, finalUrl = finalUrl, redirectChain = redirectChain),
            rawInput = current.originalText,
            primaryUrl = redirectChain.firstOrNull() ?: current.finalUrl,
            finalUrl = finalUrl,
            redirectChain = redirectChain,
            threatIntel = threatIntel,
            completeness = EvidenceCompleteness.PARTIAL_ONLINE
        )
    }

    val threatSnapshot = EvidenceSignalNormalizer.buildSnapshot(
        EvidenceNormalizerInput(
            scanId = current.scanId,
            inputKind = previous.inputKind,
            channel = previous.channel,
            rawText = "",
            primaryUrl = previous.primaryUrl,
            finalUrl = finalUrl ?: previous.finalUrl,
            redirectChain = redirectChain.ifEmpty { previous.redirectChain },
            threatIntel = threatIntel,
            providerStates = previous.providerStates,
            completeness = EvidenceCompleteness.PARTIAL_ONLINE,
            registryVersion = BrandKnowledgeRegistry.registryVersion(),
            corpusVersion = BrandKnowledgeRegistry.corpusVersion(),
            phishingDatabaseConfigured = true
        )
    )
    val providerIds = setOf(ProviderId.WEB_RISK, ProviderId.URLSCAN, ProviderId.PHISHING_DATABASE, ProviderId.CLAIM_VERIFIER)
    val retainedSignals = previous.signals.filterNot { it.provider in providerIds }
    val mergedSnapshot = previous.copy(
        finalUrl = threatSnapshot.finalUrl ?: previous.finalUrl,
        redirectChain = threatSnapshot.redirectChain.ifEmpty { previous.redirectChain },
        signals = (retainedSignals + threatSnapshot.signals).distinctBy { listOf(it.source, it.code, it.targetKey, it.provider).joinToString("|") },
        providerStates = previous.providerStates + threatSnapshot.providerStates,
        completeness = EvidenceCompleteness.PARTIAL_ONLINE
    )
    val gateResult = evidenceGate.evaluate(mergedSnapshot)
    return withGate(current.copy(threatIntel = threatIntel), 
        snapshot = mergedSnapshot,
        gateResult = gateResult,
        rawInput = current.originalText,
        mergedThreatIntel = threatIntel
    )
}

internal fun ScannerViewModel.inferEvidenceInputKind(rawInput: String): String = when {
    sharedContentFidelity == SharedContentFidelity.FULL_HTML -> "share_html_email"
    sharedContentFidelity == SharedContentFidelity.FILE_OR_EMAIL -> "import_file"
    looksLikeUrlOnly(rawInput.trim(), extractUrls(rawInput).firstOrNull().orEmpty()) -> "paste_url"
    else -> "paste_text"
}

internal fun ScannerViewModel.inferEvidenceChannel(rawInput: String): String = when {
    sharedContentFidelity == SharedContentFidelity.FULL_HTML -> "email_html"
    sharedContentFidelity == SharedContentFidelity.PLAIN_TEXT_ONLY -> "visible_text"
    sharedContentFidelity == SharedContentFidelity.FILE_OR_EMAIL -> "file_or_email"
    extractUrls(rawInput).isNotEmpty() -> "text_with_url"
    else -> "text"
}

internal fun ScannerViewModel.activeEvidenceHtml(rawInput: String): String? {
    return stagedEvidenceHtml?.takeIf { stagedEvidenceText == rawInput }
}

internal fun ScannerViewModel.activeEvidenceLinks(rawInput: String): List<String> {
    return stagedEvidenceLinks.takeIf { stagedEvidenceText == rawInput && it.isNotEmpty() }
        ?: (extractUrls(rawInput) + extractHtmlLinks(rawInput)).distinct()
}

internal fun ScannerViewModel.activeEvidenceInputKind(rawInput: String): String? {
    return stagedEvidenceInputKind?.takeIf { stagedEvidenceText == rawInput }
}

internal fun ScannerViewModel.activeEvidenceChannel(rawInput: String): String? {
    return stagedEvidenceChannel?.takeIf { stagedEvidenceText == rawInput }
}

internal fun ScannerViewModel.redactedAuditSummary(rawInput: String, snapshot: EvidenceSnapshot): String {
    val hash = MessageDigest.getInstance("SHA-256")
        .digest(rawInput.toByteArray(StandardCharsets.UTF_8))
        .joinToString("") { "%02x".format(it) }
        .take(16)
    val target = snapshot.formActionHost ?: snapshot.finalUrl ?: snapshot.primaryUrl ?: "no-target"
    return "scan=${snapshot.inputKind}; channel=${snapshot.channel}; target=${target.take(96)}; inputHash=$hash"
}

internal fun ScannerViewModel.unavailableProviderStates(): Map<ProviderId, ProviderState> = mapOf(
    ProviderId.WEB_RISK to ProviderState(ProviderId.WEB_RISK, ProviderStatus.ERROR, note = "Backend/provider unavailable"),
    ProviderId.URLSCAN to ProviderState(ProviderId.URLSCAN, ProviderStatus.ERROR, note = "Backend/provider unavailable"),
    ProviderId.PHISHING_DATABASE to ProviderState(ProviderId.PHISHING_DATABASE, ProviderStatus.ERROR, note = "Phishing.Database unavailable"),
    ProviderId.CLAIM_VERIFIER to ProviderState(ProviderId.CLAIM_VERIFIER, ProviderStatus.ERROR, note = "Offer/claim verification unavailable")
)

internal fun ScannerViewModel.pendingOnlineProviderStates(): Map<ProviderId, ProviderState> = mapOf(
    ProviderId.WEB_RISK to ProviderState(ProviderId.WEB_RISK, ProviderStatus.PENDING, note = "Backend reputation check running"),
    ProviderId.URLSCAN to ProviderState(ProviderId.URLSCAN, ProviderStatus.PENDING, note = "Sandbox preview running"),
    ProviderId.PHISHING_DATABASE to ProviderState(ProviderId.PHISHING_DATABASE, ProviderStatus.PENDING, note = "Phishing.Database reputation check running"),
    ProviderId.CLAIM_VERIFIER to ProviderState(ProviderId.CLAIM_VERIFIER, ProviderStatus.PENDING, note = "Offer/claim verification running")
)

internal fun ScannerViewModel.backendUnavailableWhileSandboxRuns(): Map<ProviderId, ProviderState> = mapOf(
    ProviderId.WEB_RISK to ProviderState(ProviderId.WEB_RISK, ProviderStatus.ERROR, note = "Backend reputation check unavailable"),
    ProviderId.URLSCAN to ProviderState(ProviderId.URLSCAN, ProviderStatus.PENDING, note = "Sandbox preview still running"),
    ProviderId.PHISHING_DATABASE to ProviderState(ProviderId.PHISHING_DATABASE, ProviderStatus.ERROR, note = "Phishing.Database unavailable"),
    ProviderId.CLAIM_VERIFIER to ProviderState(ProviderId.CLAIM_VERIFIER, ProviderStatus.ERROR, note = "Offer/claim verification unavailable")
)
