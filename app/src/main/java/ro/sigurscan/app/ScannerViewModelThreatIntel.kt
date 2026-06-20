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

// Domain logic extracted from the ScannerViewModel God object into behaviour-preserving
// extension functions operating on the ViewModel's observable state.

internal fun ScannerViewModel.mapButtons(rawButtons: List<Map<String, Any>>?): List<String> {
    if (rawButtons == null || rawButtons.isEmpty()) return emptyList()

    return rawButtons.mapNotNull { button ->
        val label = (button["text"] ?: button["label"] ?: "").toString().trim()
        val url = (button["url"] ?: button["href"] ?: button["action"] ?: "").toString().trim()
        if (url.isBlank()) return@mapNotNull null
        val prettyLabel = if (label.isBlank()) "Buton" else label
        "$prettyLabel → $url"
    }.filter { it.isNotBlank() }.distinct()
}

internal fun ScannerViewModel.mapEmailAuth(rawEmailAuth: Map<String, Any>?): String? {
    if (rawEmailAuth == null) return null
    fun pick(vararg keys: String): String? {
        val value = keys.firstNotNullOfOrNull { key -> rawEmailAuth[key]?.toString() }?.trim()
        return value?.takeIf { it.isNotBlank() }
    }

    val dkim = pick("dkim", "dkim_result", "dkim_check")
    val spf = pick("spf", "spf_result", "spf_check")
    val dmarc = pick("dmarc", "dmarc_result", "dmarc_status")
    val details = listOfNotNull(
        dkim?.let { "DKIM: $it" },
        spf?.let { "SPF: $it" },
        dmarc?.let { "DMARC: $it" }
    )
    return if (details.isNotEmpty()) details.joinToString(" | ") else null
}

internal fun ScannerViewModel.mapList(value: Any?): List<Map<*, *>> {
    return (value as? List<*>)?.filterIsInstance<Map<*, *>>() ?: emptyList()
}

internal fun ScannerViewModel.buildThreatIntel(evidence: Map<String, Any>?, response: ScanResponse): List<ThreatIntelSourceResult> {
    val results = mutableListOf(
        ThreatIntelSourceResult(
            source = "SigurScan Backend",
            verdict = response.riskLevel.uppercase(Locale.getDefault()),
            severity = response.riskLevel,
            details = "Analiza principală a fost primită."
        )
    )

    val summary = evidence?.get("external_intel_summary") as? Map<*, *>
    summary?.forEach { (rawSource, rawPayload) ->
        val source = rawSource?.toString()?.takeIf { it.isNotBlank() } ?: return@forEach
        val payload = rawPayload as? Map<*, *>
        val verdict = firstString(payload, "verdict", "status", "result", "threat", "category")
            ?: rawPayload?.toString()?.take(80)
            ?: "raport primit"
        val severity = firstString(payload, "severity", "risk_level", "level") ?: inferSeverity(verdict)
        val details = threatIntelDetails(payload)
        results.add(
            ThreatIntelSourceResult(
                source = source.replaceFirstChar { if (it.isLowerCase()) it.titlecase(Locale.getDefault()) else it.toString() },
                verdict = verdict,
                severity = severity,
                details = details
            )
        )
    }

    val claimPayload = firstMap(
        evidence,
        "offer_claim_verification",
        "claim_verification",
        "offer_claim",
        "claim_verifier"
    )
    if (claimPayload != null && results.none { providerSourceKeyForScan(it.source).contains("offerclaim") || providerSourceKeyForScan(it.source).contains("aiofferwebcheck") }) {
        val verdict = firstString(
            claimPayload,
            "verdict",
            "status",
            "result",
            "claim_status",
            "official_source_found"
        ) ?: "inconclusive"
        val details = threatIntelDetails(claimPayload)
        results.add(
            ThreatIntelSourceResult(
                source = "ai_offer_web_check",
                verdict = verdict,
                severity = inferSeverity(verdict),
                details = details
            )
        )
    }

    if (
        !response.offerAnalysis.isNullOrBlank() &&
        results.none { providerSourceKeyForScan(it.source).contains("offerclaim") || providerSourceKeyForScan(it.source).contains("aiofferwebcheck") }
    ) {
        results.add(
            ThreatIntelSourceResult(
                source = "ai_offer_web_check",
                verdict = "inconclusive",
                severity = "unknown",
                details = response.offerAnalysis.take(500)
            )
        )
    }

    return results.distinctBy { it.source.lowercase(Locale.getDefault()) }
}

internal fun ScannerViewModel.offerEvidenceFrom(evidence: Map<String, Any>?): OfferEvidenceSummary? {
    val offer = firstMap(evidence, "offer") ?: return null
    val fieldsMap = offer["fields"] as? Map<*, *> ?: emptyMap<Any, Any>()
    val entityMap = offer["entity"] as? Map<*, *>
    val coherenceMap = offer["coherence"] as? Map<*, *>
    val gateMap = offer["verdict_gate"] as? Map<*, *>
    val signals = (offer["signals"] as? List<*>)
        ?.mapNotNull { it?.toString()?.trim()?.takeIf { value -> value.isNotBlank() } }
        ?.distinct()
        .orEmpty()
    val warnings = (offer["warnings"] as? List<*>)
        ?.mapNotNull { it?.toString()?.trim()?.takeIf { value -> value.isNotBlank() } }
        ?.distinct()
        .orEmpty()

    return OfferEvidenceSummary(
        fields = OfferFieldsSummary(
            issuerName = firstString(fieldsMap, "issuer_name"),
            issuerCui = firstString(fieldsMap, "issuer_cui"),
            iban = firstString(fieldsMap, "iban"),
            paymentBeneficiary = firstString(fieldsMap, "payment_beneficiary"),
            totalAmount = firstDouble(fieldsMap, "total_amount"),
            currency = firstString(fieldsMap, "currency"),
            paymentMethod = firstString(fieldsMap, "payment_method"),
            documentType = firstString(fieldsMap, "document_type"),
            familyCode = firstString(fieldsMap, "family")
        ),
        signals = signals,
        warnings = warnings,
        entity = entityMap?.let {
            OfferEntitySummary(
                cuiChecked = firstBoolean(it, "cui_checked"),
                cuiExists = firstBoolean(it, "cui_exists"),
                cuiActive = firstBoolean(it, "cui_active"),
                denumire = firstString(it, "denumire"),
                nameMatches = firstBoolean(it, "name_matches"),
                brandImpersonation = firstBoolean(it, "brand_impersonation")
            )
        },
        coherenceOk = firstBoolean(coherenceMap, "all_ok"),
        gateLabel = firstString(gateMap, "label")
    )
}

internal fun ScannerViewModel.threatIntelDetails(payload: Map<*, *>?): String? {
    if (payload == null) return null
    val base = firstString(payload, "details", "description", "message", "summary", "source_url")
    val officialDomains = (payload["official_domains"] as? List<*>)
        ?.mapNotNull { it?.toString()?.takeIf { value -> value.isNotBlank() } }
        ?.joinToString(",")
    val officialSourceFound = payload["official_source_found"]?.toString()
    val matchedAssets = (payload["matched_assets"] as? List<*>)
        ?.mapNotNull { it?.toString()?.takeIf { value -> value.isNotBlank() } }
        ?.joinToString(",")
    val knowledgeTarget = firstString(payload, "knowledge_target")
    val signal = firstString(payload, "signal")
    return listOfNotNull(
        base,
        officialDomains?.let { "official_domains=$it" },
        officialSourceFound?.let { "official_source_found=$it" },
        matchedAssets?.let { "matched_assets=$it" },
        knowledgeTarget?.let { "knowledge_target=$it" },
        signal?.let { "signal=$it" }
    ).joinToString("; ").takeIf { it.isNotBlank() }
}

internal fun ScannerViewModel.firstMap(map: Map<String, Any>?, vararg keys: String): Map<*, *>? {
    if (map == null) return null
    return keys.firstNotNullOfOrNull { key ->
        map[key] as? Map<*, *>
    }
}

internal fun ScannerViewModel.firstString(map: Map<*, *>?, vararg keys: String): String? {
    if (map == null) return null
    return keys.firstNotNullOfOrNull { key ->
        map[key]?.toString()?.trim()?.takeIf { it.isNotBlank() && it != "null" }
    }
}

internal fun ScannerViewModel.firstBoolean(map: Map<*, *>?, vararg keys: String): Boolean? {
    if (map == null) return null
    return keys.firstNotNullOfOrNull { key ->
        when (val value = map[key]) {
            is Boolean -> value
            is String -> when (value.trim().lowercase(Locale.US)) {
                "true", "yes", "da", "1" -> true
                "false", "no", "nu", "0" -> false
                else -> null
            }
            is Number -> value.toInt() != 0
            else -> null
        }
    }
}

internal fun ScannerViewModel.firstDouble(map: Map<*, *>?, vararg keys: String): Double? {
    if (map == null) return null
    return keys.firstNotNullOfOrNull { key ->
        when (val value = map[key]) {
            is Number -> value.toDouble()
            is String -> value.trim().replace(",", ".").toDoubleOrNull()
            else -> null
        }
    }
}

internal fun ScannerViewModel.providerSourceKeyForScan(value: String): String {
    return value.lowercase(Locale.US).filter { it.isLetterOrDigit() }
}

internal fun ScannerViewModel.inferSeverity(value: String): String {
    val normalized = value.lowercase(Locale.getDefault())
    return when {
        listOf("malicious", "phishing", "malware", "danger", "high", "critical", "unsafe").any { normalized.contains(it) } -> "high"
        listOf("suspicious", "medium", "warning", "unknown", "unrated").any { normalized.contains(it) } -> "medium"
        listOf("safe", "clean", "harmless", "low").any { normalized.contains(it) } -> "low"
        else -> "unknown"
    }
}

internal fun ScannerViewModel.upsertThreatIntel(
    current: List<ThreatIntelSourceResult>,
    item: ThreatIntelSourceResult
): List<ThreatIntelSourceResult> {
    return (current.filterNot { it.source.equals(item.source, ignoreCase = true) } + item)
}

internal fun ScannerViewModel.summarizeUrlscanResult(result: Map<*, *>?, attempts: Int): ThreatIntelSourceResult {
    val page = result?.get("page") as? Map<*, *>
    val verdicts = result?.get("verdicts") as? Map<*, *>
    val overall = verdicts?.get("overall") as? Map<*, *>

    val isMalicious = overall?.get("malicious") as? Boolean ?: false
    val score = (overall?.get("score") as? Number)?.toInt()
    val verdict = when {
        isMalicious -> "Malicious"
        score != null && score > 0 -> "Suspicious score $score"
        else -> "No malicious verdict"
    }
    val severity = when {
        isMalicious -> "high"
        score != null && score > 0 -> "medium"
        else -> "low"
    }

    val parts = mutableListOf("Analiză Sandbox finalizată (${attempts} verificări)")
    page?.get("status")?.toString()?.takeIf { it.isNotBlank() }?.let { parts.add("HTTP $it") }
    page?.get("ip")?.toString()?.takeIf { it.isNotBlank() }?.let { parts.add("IP $it") }
    page?.get("country")?.toString()?.takeIf { it.isNotBlank() }?.let { parts.add("Țară $it") }
    page?.get("server")?.toString()?.takeIf { it.isNotBlank() }?.let { parts.add("Server $it") }

    return ThreatIntelSourceResult(
        source = "urlscan.io",
        verdict = verdict,
        severity = severity,
        details = parts.joinToString(" • ")
    )
}

internal fun ScannerViewModel.pickPrimaryThreatIntelUrl(response: ScanResponse, rawText: String = text): String {
    val candidates = linkedSetOf<String>()

    response.extractedUrls?.forEach { item ->
        pickUrlFromMap(item)?.let { candidates.add(it) }
    }

    response.resolvedUrls?.forEach { item ->
        pickUrlFromMap(item)?.let { candidates.add(it) }
    }

    val evidenceMap = response.evidence
    mapList(evidenceMap?.get("extracted_urls")).forEach { item ->
        pickUrlFromMap(item)?.let { candidates.add(it) }
    }
    mapList(evidenceMap?.get("resolved_urls")).forEach { item ->
        pickUrlFromMap(item)?.let { candidates.add(it) }
    }

    evidenceMap?.let { map ->
        listOf("url", "final_url", "redirect_url", "source_url", "destination_url").forEach { key ->
            val candidate = map[key]?.toString()
            normalizeCandidateUrl(candidate)?.let { candidates.add(it) }
        }
        val intelSummary = map["external_intel_summary"] as? Map<*, *>
        intelSummary?.values?.filterIsInstance<Map<*, *>>()?.forEach { sourcePayload ->
            normalizeCandidateUrl(sourcePayload["url_example"]?.toString())?.let { candidates.add(it) }
        }
    }

    extractUrls(rawText).forEach {
        normalizeCandidateUrl(it)?.let { candidates.add(it) }
            ?: if (it.startsWith("www.", ignoreCase = true)) {
                candidates.add(normalizeUrl(it))
            } else {
                null
            }
    }

    return PrimaryUrlPicker.pick(
        candidates = candidates,
        rawText = rawText
    )
}

internal fun ScannerViewModel.pickUrlFromMap(item: Map<*, *>): String? {
    val directCandidates = listOf(
        item["url"],
        item["final_url"],
        item["source_url"],
        item["destination_url"],
        item["redirect_url"],
        item["link"],
        item["href"]
    )

    directCandidates.forEach { candidate ->
        normalizeCandidateUrl(candidate?.toString())?.let { return it }
    }

    return null
}

internal suspend fun ScannerViewModel.enrichThreatIntelFromServices(
    targetUrl: String,
    existingThreatIntel: List<ThreatIntelSourceResult>,
    riskLevel: String
): List<ThreatIntelSourceResult> = coroutineScope {
    var result = existingThreatIntel.toMutableList()

    val url = normalizeCandidateUrl(targetUrl)
        ?: normalizeUrl(targetUrl)

    val webRisk = async { fetchGoogleWebRiskThreatIntel(url) }.await()
    webRisk?.let { result = upsertThreatIntel(result, it).toMutableList() }

    return@coroutineScope result.distinctBy { it.source.lowercase(Locale.getDefault()) }
}

internal fun ScannerViewModel.parseThreatIntelEngineFlags(raw: Any?): String {
    val map = raw as? Map<*, *> ?: return ""
    val flagged = mutableListOf<String>()

    map.forEach { (rawEngine, rawResult) ->
        val engine = rawEngine?.toString() ?: return@forEach
        val cat = firstString(rawResult as? Map<*, *>, "category", "result", "method")
        if (!cat.isNullOrBlank() && (cat.equals("malicious", ignoreCase = true) || cat.equals("suspicious", ignoreCase = true))) {
            flagged.add(engine)
        }
    }

    return flagged.take(4).joinToString(", ")
}

internal suspend fun ScannerViewModel.fetchGoogleWebRiskThreatIntel(url: String): ThreatIntelSourceResult? {
    if (GOOGLE_WEB_RISK_API_KEY.isBlank()) return null

    getCachedWebRiskResult(url)?.let { return it }

    val urlWithKey = okhttp3.HttpUrl.Builder()
        .scheme("https")
        .host("webrisk.googleapis.com")
        .addPathSegments("v1/uris:search")
        .addQueryParameter("uri", url)
        .addQueryParameter("threatTypes", "MALWARE")
        .addQueryParameter("threatTypes", "SOCIAL_ENGINEERING")
        .addQueryParameter("threatTypes", "UNWANTED_SOFTWARE")
        .addQueryParameter("threatTypes", "SOCIAL_ENGINEERING_EXTENDED_COVERAGE")
        .addQueryParameter("key", GOOGLE_WEB_RISK_API_KEY)
        .build()

    val request = Request.Builder()
        .url(urlWithKey)
        .get()
        .build()

    return runCatching {
        threatIntelClient.newCall(request).execute().use { response ->
            val responseBody = response.body?.string() ?: return@runCatching null
            if (!response.isSuccessful) return@runCatching null

            val payload = gson.fromJson(responseBody, Map::class.java) as? Map<*, *> ?: return@runCatching null
            val threat = payload["threat"] as? Map<*, *>
            if (threat.isNullOrEmpty()) {
                return@runCatching cacheWebRiskResult(
                    url,
                    ThreatIntelSourceResult(
                        source = "Google Web Risk",
                        verdict = "No Threats",
                        severity = "low",
                        details = "URL nou sau fără semnale de tip phishing/malware în baza Google Web Risk."
                    ),
                    expiresAtMillis = System.currentTimeMillis() + ScannerViewModel.WEB_RISK_NO_THREAT_CACHE_MS
                )
            }

            val threatTypes = (threat["threatTypes"] as? List<*>)
                ?.mapNotNull { it?.toString() }
                ?.distinct()
                ?.sorted()
                ?: emptyList()
            val expireTime = firstString(threat, "expireTime")

            val result = ThreatIntelSourceResult(
                source = "Google Web Risk",
                verdict = "Threats Detected",
                severity = "high",
                details = buildString {
                    append("Tipuri: ${threatTypes.joinToString(",")}.")
                    if (!expireTime.isNullOrBlank()) {
                        append(" Expiră: $expireTime.")
                    }
                }
            )
            cacheWebRiskResult(
                url,
                result,
                expiresAtMillis = parseWebRiskExpireTimeMillis(expireTime)
                    ?: (System.currentTimeMillis() + ScannerViewModel.WEB_RISK_THREAT_FALLBACK_CACHE_MS)
            )
        }
    }.getOrElse { null }
}

internal fun ScannerViewModel.getCachedWebRiskResult(url: String): ThreatIntelSourceResult? {
    val cacheKey = url.lowercase(Locale.US)
    val cached = webRiskCache[cacheKey] ?: return null
    return if (cached.expiresAtMillis > System.currentTimeMillis()) {
        cached.result
    } else {
        webRiskCache.remove(cacheKey)
        null
    }
}

internal fun ScannerViewModel.cacheWebRiskResult(
    url: String,
    result: ThreatIntelSourceResult,
    expiresAtMillis: Long
): ThreatIntelSourceResult {
    webRiskCache[url.lowercase(Locale.US)] = ScannerViewModel.CachedThreatIntelResult(
        result = result,
        expiresAtMillis = expiresAtMillis
    )
    return result
}

internal fun ScannerViewModel.parseWebRiskExpireTimeMillis(expireTime: String?): Long? {
    if (expireTime.isNullOrBlank()) return null
    val normalized = normalizeWebRiskTimestamp(expireTime) ?: return null
    val formatter = java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US).apply {
        timeZone = TimeZone.getTimeZone("UTC")
    }
    return runCatching { formatter.parse(normalized)?.time }
        .getOrNull()
        ?.takeIf { it > System.currentTimeMillis() }
}

internal fun ScannerViewModel.normalizeWebRiskTimestamp(raw: String): String? {
    val trimmed = raw.trim()
    if (!trimmed.endsWith("Z")) return null
    val withoutZone = trimmed.dropLast(1)
    val dotIndex = withoutZone.indexOf('.')
    return if (dotIndex == -1) {
        "$withoutZone.000Z"
    } else {
        val seconds = withoutZone.substring(0, dotIndex)
        val fraction = withoutZone.substring(dotIndex + 1)
            .take(3)
            .padEnd(3, '0')
        "$seconds.${fraction}Z"
    }
}

internal fun ScannerViewModel.virusTotalUrlId(url: String): String {
    val trimmed = normalizeCandidateUrl(url) ?: return ""
    return Base64.encodeToString(trimmed.toByteArray(StandardCharsets.UTF_8), Base64.URL_SAFE or Base64.NO_WRAP)
        .replace("=", "")
}

internal fun ScannerViewModel.asInt(raw: Any?): Int {
    return when (raw) {
        is Number -> raw.toInt()
        is String -> raw.toIntOrNull() ?: 0
        else -> 0
    }
}

internal suspend fun ScannerViewModel.updateThreatIntelInHistory(scanId: String, threatIntel: List<ThreatIntelSourceResult>) {
    withContext(Dispatchers.Main) {
        val merged = threatIntel.distinctBy { it.source.lowercase(Locale.getDefault()) }
        val current = currentAssessmentForScan(scanId)
        if (current != null) {
            val updated = reevaluateGateWithThreatIntel(
                current = current,
                threatIntel = merged,
                finalUrl = current.finalUrl,
                redirectChain = current.redirectChain
            )
            replaceAssessment(scanId, updated)
        }
    }
}
