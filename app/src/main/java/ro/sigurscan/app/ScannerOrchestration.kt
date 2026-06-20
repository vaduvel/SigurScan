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

internal fun urlscanScreenshotUrl(uuid: String): String = "https://urlscan.io/screenshots/$uuid.png"

internal fun urlscanReportUrl(uuid: String): String = "https://urlscan.io/result/$uuid/"

internal const val ORCHESTRATED_POLLING_BUDGET_MILLIS = 180_000L

internal fun orchestratedPollDelayMillis(response: OrchestratedScanResponse): Long {
    response.pollAfterMs
        ?.coerceIn(500L, 5_000L)
        ?.let { return it }
    val urlscan = response.pillars?.get("urlscan")
    return if (
        urlscan?.status.equals("pending", ignoreCase = true) &&
        !urlscan?.ref.isNullOrBlank()
    ) {
        3_000L
    } else {
        1_000L
    }
}

internal fun orchestratedPreviewStillPending(preview: OrchestratedPreview?): Boolean {
    if (preview == null) return false
    if (!preview.screenshotUrl.isNullOrBlank()) return false
    val status = preview.status?.trim()?.lowercase(Locale.US)
    val reason = preview.reason?.trim()?.lowercase(Locale.US)
    return status == "pending" ||
        reason in setOf("urlscan_pending", "urlscan_screenshot_pending")
}

internal fun orchestratedEvidenceCompleteness(
    preview: OrchestratedPreview?,
    providerStates: Map<ProviderId, ProviderState>,
    finalUrl: String?,
    isFinal: Boolean = false
): EvidenceCompleteness {
    if (orchestratedPreviewStillPending(preview)) return EvidenceCompleteness.PARTIAL_ONLINE
    if (providerStates.values.any { it.status == ProviderStatus.PENDING }) {
        return EvidenceCompleteness.PARTIAL_ONLINE
    }
    val hasProviderFailure = providerStates.values.any {
        it.status in setOf(ProviderStatus.TIMEOUT, ProviderStatus.RATE_LIMITED, ProviderStatus.ERROR)
    }
    if (!isFinal && (hasProviderFailure || providerStates.values.any { it.status == ProviderStatus.OK })) {
        return EvidenceCompleteness.PARTIAL_ONLINE
    }
    if (!isFinal) return EvidenceCompleteness.LOCAL_ONLY
    if (!finalUrl.isNullOrBlank()) return EvidenceCompleteness.FULL
    if (providerStates.values.any { it.status == ProviderStatus.OK }) return EvidenceCompleteness.PARTIAL_ONLINE
    return EvidenceCompleteness.LOCAL_ONLY
}

internal fun shouldContinueOrchestratedPolling(response: OrchestratedScanResponse): Boolean {
    if (response.result == null) return true
    if (response.result.isFinal == false) return true
    return false
}

internal fun shouldRefreshFinalOrchestratedPreview(response: OrchestratedScanResponse): Boolean {
    if (response.result == null) return false
    if (response.result.isFinal == false) return false
    return orchestratedPreviewStillPending(response.preview)
}

internal fun cachedPreviewNeedsRefresh(assessment: OfflineAssessment): Boolean {
    if (assessment.finalUrl == null) return false
    val screenshotUrl = assessment.screenshotUrl?.trim().orEmpty()
    if (screenshotUrl.isBlank()) return true
    val normalized = screenshotUrl.lowercase(Locale.US)
    return normalized.startsWith("http://") ||
        ".run.app/" in normalized ||
        "sigurscan-backend.vercel.app" in normalized ||
        "nudaclick-backend.vercel.app" in normalized
}

internal fun orchestratedScanServerInfo(
    statusMessage: String?,
    preview: OrchestratedPreview?,
    isFinal: Boolean
): String {
    val previewReason = preview?.reason?.trim()?.lowercase(Locale.US)
    val previewDetails = preview?.details?.trim().orEmpty()
    if (previewReason == "final_url_unresolved") {
        return previewDetails.ifBlank {
            "Destinatia finala nu poate fi incarcata/verificata. Nu continua fara verificare oficiala."
        }
    }
    if (isFinal && preview?.status?.trim()?.lowercase(Locale.US) == "unavailable") {
        return previewDetails.ifBlank {
            when (previewReason) {
                "urlscan_timeout", "urlscan_screenshot_timeout", "android_polling_timeout" ->
                    "Preview-ul securizat nu a fost gata la timp. Verdictul final rămâne afișat; rescanează pentru o captură proaspătă."
                else ->
                    "Preview-ul securizat nu este disponibil momentan. Folosește verdictul final și verifică destinația oficială înainte de orice acțiune sensibilă."
            }
        }
    }
    if (isFinal && orchestratedPreviewStillPending(preview)) {
        return "Preview-ul securizat se generează."
    }
    return if (!isFinal) {
        userSafeOrchestratedStatusMessage(statusMessage)
    } else {
        "Scanarea completă a fost finalizată."
    }
}

internal fun userSafeOrchestratedStatusMessage(statusMessage: String?): String {
    val value = statusMessage?.trim()?.takeIf { it.isNotBlank() }
        ?: return "Se verifică destinația și sursele de risc."
    val normalized = value.lowercase(Locale.US)
    return if (
        normalized.contains("pilon") ||
        normalized.contains("pillar") ||
        normalized.contains("provider")
    ) {
        "Se verifică destinația și sursele de risc."
    } else {
        value.take(140)
    }
}

internal const val RESULT_CACHE_TTL_MILLIS = 12L * 60L * 60L * 1000L

internal fun normalizedScanResultCacheMaterial(
    rawInput: String,
    htmlPayload: String?,
    urls: List<String>
): String {
    val normalizedText = rawInput.trim().replace(Regex("\\s+"), " ")
    val normalizedUrls = urls
        .mapNotNull { HtmlLinkExtractor.normalizeCandidateUrl(it) ?: UrlTextExtractor.normalizeCandidate(it) }
        .map { it.trim().trimEnd('.', ',', ';').lowercase(Locale.US) }
        .distinct()
        .sorted()
    val urlOnlyInput = normalizedUrls.size == 1 &&
        !normalizedText.any { it.isWhitespace() } &&
        (HtmlLinkExtractor.normalizeCandidateUrl(normalizedText) ?: UrlTextExtractor.normalizeCandidate(normalizedText))
            ?.trim()
            ?.trimEnd('.', ',', ';')
            ?.lowercase(Locale.US) == normalizedUrls.first()
    val cacheText = if (urlOnlyInput) {
        "url:${normalizedUrls.first()}"
    } else {
        normalizedText
    }
    val normalizedHtmlHash = htmlPayload
        ?.trim()
        ?.takeIf { it.isNotBlank() }
        ?.replace(Regex("\\s+"), " ")
        ?.let(::sha256Hex)
        .orEmpty()

    return buildString {
        appendLine("sigurscan-result-cache-v1")
        appendLine("text=$cacheText")
        appendLine("urls=${normalizedUrls.joinToString("|")}")
        append("html_sha=$normalizedHtmlHash")
    }
}

internal fun scanResultCacheKey(rawInput: String, htmlPayload: String?, urls: List<String>): String {
    return sha256Hex(normalizedScanResultCacheMaterial(rawInput, htmlPayload, urls))
}

internal fun sha256Hex(value: String): String {
    return MessageDigest.getInstance("SHA-256")
        .digest(value.toByteArray(StandardCharsets.UTF_8))
        .joinToString("") { "%02x".format(it) }
}

internal fun guardianRedactedSummaryFromAssessment(assessment: OfflineAssessment?): Map<String, Any> {
    if (assessment == null) {
        return mapOf(
            "source" to "android_guardian_request",
            "has_scan" to false,
            "raw_text_shared" to false
        )
    }

    val finalHost = assessment.finalUrl
        ?.let { runCatching { URI(it).host }.getOrNull() }
        ?.takeIf { it.isNotBlank() }

    return buildMap {
        put("source", "android_guardian_request")
        put("has_scan", true)
        put("scan_id", assessment.scanId)
        put("risk_level", assessment.riskLevel)
        put("risk_score", assessment.riskScore)
        put("family", assessment.family)
        finalHost?.let { put("final_host", it) }
        put("reason_count", assessment.reasons.size)
        put("key_danger_count", assessment.keyDangers.size)
        put("raw_text_shared", false)
    }
}
