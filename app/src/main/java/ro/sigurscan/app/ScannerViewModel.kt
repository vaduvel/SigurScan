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
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.common.InputImage
import com.google.mlkit.vision.text.TextRecognition
import com.google.mlkit.vision.text.latin.TextRecognizerOptions
import kotlinx.coroutines.Job
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

class ScannerViewModel(application: Application) : AndroidViewModel(application) {
    internal data class PdfFallbackExtraction(
        val extractedText: String,
        val extractedLinks: Set<String> = emptySet()
    )
    internal data class PendingInvoiceScanSource(
        val uri: Uri,
        val officialXmlUri: Uri? = null
    )
    internal data class CachedThreatIntelResult(
        val result: ThreatIntelSourceResult,
        val expiresAtMillis: Long
    )
    internal data class CachedAssessmentRecord(
        val cacheKey: String,
        val assessment: OfflineAssessment,
        val cachedAtMillis: Long,
        val expiresAtMillis: Long
    )
    private data class PersistedStartupState(
        val history: List<OfflineAssessment> = emptyList(),
        val resultCache: List<CachedAssessmentRecord> = emptyList(),
        val triageProgress: Map<String, Set<Int>> = emptyMap(),
        val completedLessons: Set<String> = emptySet(),
        val familyMembers: List<FamilyMember> = emptyList(),
        val familyAlerts: List<FamilyAlert> = emptyList()
    )

    internal companion object {
        internal const val MAX_UPLOAD_BYTES = 25L * 1024L * 1024L
        internal const val MAX_IMAGE_UPLOAD_BYTES = 10L * 1024L * 1024L
        internal const val MAX_INVOICE_IMAGE_EDGE_PX = 1800
        internal const val INVOICE_IMAGE_JPEG_QUALITY = 88
        internal const val TMP_UPLOAD_PREFIX = "temp_upload_"
        internal const val WEB_RISK_NO_THREAT_CACHE_MS = 10L * 60L * 1000L
        internal const val WEB_RISK_THREAT_FALLBACK_CACHE_MS = 5L * 60L * 1000L
        internal const val RESULT_CACHE_PREF_KEY = "scan_result_cache_v3"
        internal const val MAX_RESULT_CACHE_ITEMS = 50
        internal const val URLSCAN_PERSONA_COUNTRY = "ro"
        internal const val URLSCAN_MOBILE_ANDROID_AGENT =
            "Mozilla/5.0 (Linux; Android 15; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
    }

    var text by mutableStateOf("")
    var loading by mutableStateOf(false)
    var loadingMsg by mutableStateOf("")
    var assessment by mutableStateOf<OfflineAssessment?>(null)
    var invoiceResult by mutableStateOf<InvoiceScanResponse?>(null)
    var invoiceSanbStatus by mutableStateOf<String?>(null)
    internal var lastInvoiceScanSource: PendingInvoiceScanSource? = null
    var pendingOfferConfirmation by mutableStateOf<PendingOfferConfirmation?>(null)
    var pendingSharedInput by mutableStateOf<String?>(null)
    var pendingSharedSourceLabel by mutableStateOf("Conținut partajat")
    var pendingSharedFiles by mutableStateOf<List<PendingSharedFile>>(emptyList())
    var sharedContentFidelity by mutableStateOf<SharedContentFidelity?>(null)
    var sharedContentSourceLabel by mutableStateOf("Conținut partajat")
    
    // Navigation state
    var currentTab by mutableStateOf("scan")
    
    // History
    var historyItems = mutableStateListOf<OfflineAssessment>()
    
    // Cyber Hero Stats
    var cyberScore by mutableStateOf(0)
    var scamsBlocked by mutableStateOf(0)
    
    // Reports state
    var readiness by mutableStateOf<ReadinessResponse?>(null)
    var quality by mutableStateOf<QualityResponse?>(null)
    var feedbackSamples by mutableStateOf<FeedbackSamplesResponse?>(null)
    var reputationStats by mutableStateOf<ReputationCacheStats?>(null)
    var reportsLoading by mutableStateOf(false)
    
    // Realtime Alerts
    var activeCampaignAlert by mutableStateOf<String?>(null)
    var liveCampaignEvent by mutableStateOf<String?>(null)
    var campaigns = mutableStateListOf<ScamCampaign>()
    var campaignsLoading by mutableStateOf(false)
    var campaignsLoadState by mutableStateOf(CampaignLoadState.NOT_LOADED)
    var radarHotCache by mutableStateOf<RadarHotCacheSnapshot?>(null)
    var radarHotCacheLoading by mutableStateOf(false)
    var radarHotCacheStatus by mutableStateOf<String?>(null)
    var radarScreeningAudit by mutableStateOf<RadarScreeningAudit?>(null)
    var radarReportPhoneInput by mutableStateOf("")
    var radarReportPhoneLoading by mutableStateOf(false)
    var radarReportPhoneStatus by mutableStateOf<String?>(null)
    var btrSyncSnapshot by mutableStateOf<BtrSyncSnapshot?>(null)
    var btrSyncLoading by mutableStateOf(false)
    var btrSyncStatus by mutableStateOf<String?>(null)
    var inboxProvenanceVerdict by mutableStateOf<InboxProvenanceVerdict?>(null)
    var inboxProvenanceStatus by mutableStateOf<String?>(null)
    var actionPlanLoading by mutableStateOf(false)
    var actionPlanStatus by mutableStateOf<String?>(null)
    var officialReportLoading by mutableStateOf(false)
    var officialReportStatus by mutableStateOf<String?>(null)
    var officialReportPackage by mutableStateOf<OneTapReportPackage?>(null)
    var circleSnapshot by mutableStateOf(CircleProtectionSnapshot())
    var circleLoading by mutableStateOf(false)
    var circleStatus by mutableStateOf<String?>(null)
    var guardianLoading by mutableStateOf(false)
    var guardianStatus by mutableStateOf<String?>(null)
    var audioReadiness by mutableStateOf(
        AudioReadinessSnapshot(
            featureFlagEnabled = BuildConfig.SIGURSCAN_ENABLE_AUDIO_ASR,
            modelAvailable = false
        )
    )
    var audioReadinessStatus by mutableStateOf<String?>(null)
    var audioEvidenceResult by mutableStateOf<AudioEvidenceResult?>(null)
    var speakerGuardSnapshot by mutableStateOf(SpeakerGuardSnapshot())
    internal var speakerGuardServiceUpdatesJob: Job? = null

    // Family protection
    var familyMembers = mutableStateListOf<FamilyMember>()
    var familyAlerts = mutableStateListOf<FamilyAlert>()

    // Triage + education state
    var triageStepProgress by mutableStateOf<Map<String, Set<Int>>>(emptyMap())
    var completedLessons by mutableStateOf<Set<String>>(emptySet())

    val triageScenarios = mapOf(
        "card" to listOf(
            "Blochează imediat cardul" to "Din aplicația bancară, blochează cardul sau tranzacțiile offline/online.",
            "Sunați la banca ta" to "Contactează telefonic instituția, nu prin link-uri sau mesaje primite.",
            "Verifică tranzacțiile" to "Închide sesiunile și verifică ultimele plăți suspecte."
        ),
        "whatsapp" to listOf(
            "Verifică dispozitivele conectate" to "WhatsApp > Setări > Dispozitive, deconectează ce nu recunoști.",
            "Activează verificarea în doi pași" to "Folosește cod PIN și PIN de acces pentru backup codes.",
            "Anunță familia" to "Avertizează persoanele apropiate că telefonul poate fi compromis."
        ),
        "anydesk" to listOf(
            "Deconectează internetul" to "Activează modul avion până ai clarificat incidentul.",
            "Șterge aplicațiile remote" to "Elimină aplicațiile de control instalate neautorizat.",
            "Schimbă parolele" to "Actualizează parolele conturilor importante de pe un alt dispozitiv sigur."
        ),
        "personal" to listOf(
            "Înștiințează DNSC (1911)" to "Completează sesizarea oficială, dacă datele personale au fost trimise.",
            "Monitorizează conturile" to "Verifică zilnic semnalări de activitate neobișnuită.",
            "Blochează documentele" to "Dacă ai depus acte, ia măsuri pentru înlocuire imediată."
        )
    )
    
    internal val prefs: SharedPreferences by lazy { SigurScanClientIdentity.securePrefs(application) }
    private val clientInstanceId: String by lazy { SigurScanClientIdentity.loadOrCreateClientInstanceId(application) }
    internal val gson = Gson()
    internal val recognizer by lazy { TextRecognition.getClient(TextRecognizerOptions.DEFAULT_OPTIONS) }
    internal val barcodeScanner by lazy { BarcodeScanning.getClient() }
    internal val URLSCAN_API_KEY = BuildConfig.URLSCAN_API_KEY
    internal val GOOGLE_WEB_RISK_API_KEY = BuildConfig.GOOGLE_WEB_RISK_API_KEY
    internal val pendingScreenshotRefreshes = mutableSetOf<String>()
    internal val threatIntelClient = OkHttpClient.Builder()
        .callTimeout(12, TimeUnit.SECONDS)
        .readTimeout(12, TimeUnit.SECONDS)
        .connectTimeout(12, TimeUnit.SECONDS)
        .addInterceptor(HttpLoggingInterceptor().apply {
            level = HttpLoggingInterceptor.Level.NONE
        })
        .build()
    internal val webRiskCache = Collections.synchronizedMap(mutableMapOf<String, CachedThreatIntelResult>())
    internal val evidenceGate = EvidenceGate()
    internal var stagedEvidenceHtml: String? = null
    internal var stagedEvidenceLinks: List<String> = emptyList()
    internal var stagedEvidenceText: String? = null
    internal var stagedEvidenceInputKind: String? = null
    internal var stagedEvidenceChannel: String? = null
    internal val resultCache = Collections.synchronizedMap(LinkedHashMap<String, CachedAssessmentRecord>())
    internal val radarHotCacheStore by lazy { RadarHotCacheStore.fromContext(application) }
    internal val radarScreeningAuditStore by lazy { RadarScreeningAuditStore.fromContext(application) }
    internal val btrSyncStore by lazy { BtrSyncStore.fromContext(application) }
    private val playIntegrityTokenProvider by lazy {
        if (BuildConfig.SIGURSCAN_ENABLE_PLAY_INTEGRITY) {
            PlayIntegrityTokenProvider.fromContext(
                application,
                configuredSigurScanBackendBaseUrl(),
                BuildConfig.SIGURSCAN_API_KEY,
                clientInstanceId
            )
        } else {
            PlayIntegrityTokenProvider.disabled()
        }
    }

    private fun buildApiClient(
        callTimeoutSeconds: Long,
        readTimeoutSeconds: Long,
        writeTimeoutSeconds: Long,
        connectTimeoutSeconds: Long
    ): SigurScanApi {
        return buildSigurScanApiClient(
            callTimeoutSeconds = callTimeoutSeconds,
            readTimeoutSeconds = readTimeoutSeconds,
            writeTimeoutSeconds = writeTimeoutSeconds,
            connectTimeoutSeconds = connectTimeoutSeconds,
            clientInstanceId = clientInstanceId,
            integrityTokenProvider = { playIntegrityTokenProvider.currentToken() }
        )
    }
    internal val api: SigurScanApi by lazy {
        buildApiClient(
            callTimeoutSeconds = 75,
            readTimeoutSeconds = 75,
            writeTimeoutSeconds = 30,
            connectTimeoutSeconds = 20
        )
    }
    internal val scanStartApi: SigurScanApi by lazy {
        buildApiClient(
            callTimeoutSeconds = 15,
            readTimeoutSeconds = 15,
            writeTimeoutSeconds = 15,
            connectTimeoutSeconds = 8
        )
    }
    internal val scanPollApi: SigurScanApi by lazy {
        buildApiClient(
            callTimeoutSeconds = 10,
            readTimeoutSeconds = 10,
            writeTimeoutSeconds = 10,
            connectTimeoutSeconds = 5
        )
    }
    internal val uploadApi: SigurScanApi by lazy {
        buildApiClient(
            callTimeoutSeconds = 75,
            readTimeoutSeconds = 75,
            writeTimeoutSeconds = 45,
            connectTimeoutSeconds = 20
        )
    }

    init {
        calculateStats()
        viewModelScope.launch(Dispatchers.IO) {
            BrandKnowledgeRegistry.initialize(application)
            val persisted = loadPersistedStartupState()
            cleanupLegacyTempUploads()
            withContext(Dispatchers.Main) {
                applyPersistedStartupState(persisted)
                radarHotCache = radarHotCacheStore.load()
                radarScreeningAudit = radarScreeningAuditStore.load()
                btrSyncSnapshot = btrSyncStore.load()
                circleSnapshot = loadCircleProtectionSnapshot()
                audioReadinessStatus = "Pune celălalt telefon pe difuzor, apoi apasă Pornește ascultarea."
            }
        }
    }

    private fun loadPersistedStartupState(): PersistedStartupState {
        return PersistedStartupState(
            history = runCatching {
                val raw = prefs.getString("history", null) ?: return@runCatching emptyList()
                val type = object : TypeToken<List<OfflineAssessment>>() {}.type
                gson.fromJson<List<OfflineAssessment>>(raw, type).take(50)
            }.getOrDefault(emptyList()),
            resultCache = runCatching {
                val raw = prefs.getString(RESULT_CACHE_PREF_KEY, null) ?: return@runCatching emptyList()
                val type = object : TypeToken<List<CachedAssessmentRecord>>() {}.type
                val now = System.currentTimeMillis()
                gson.fromJson<List<CachedAssessmentRecord>>(raw, type)
                    .filter { it.expiresAtMillis > now }
                    .take(MAX_RESULT_CACHE_ITEMS)
            }.getOrDefault(emptyList()),
            triageProgress = runCatching {
                val raw = prefs.getString("triage_steps_state", null) ?: return@runCatching emptyMap()
                val type = object : TypeToken<Map<String, List<Int>>>() {}.type
                val values: Map<String, List<Int>> = gson.fromJson(raw, type)
                values.mapValues { it.value.toSet() }
            }.getOrDefault(emptyMap()),
            completedLessons = runCatching {
                val raw = prefs.getString("education_lessons_done", null) ?: return@runCatching emptySet()
                val type = object : TypeToken<Set<String>>() {}.type
                gson.fromJson<Set<String>>(raw, type)
            }.getOrDefault(emptySet()),
            familyMembers = runCatching {
                val raw = prefs.getString("family_members_state", null) ?: return@runCatching emptyList()
                val type = object : TypeToken<List<FamilyMember>>() {}.type
                gson.fromJson<List<FamilyMember>>(raw, type)
            }.getOrDefault(emptyList()),
            familyAlerts = runCatching {
                val raw = prefs.getString("family_alerts_state", null) ?: return@runCatching emptyList()
                val type = object : TypeToken<List<FamilyAlert>>() {}.type
                gson.fromJson<List<FamilyAlert>>(raw, type)
            }.getOrDefault(emptyList())
        )
    }

    private fun applyPersistedStartupState(state: PersistedStartupState) {
        historyItems.clear()
        historyItems.addAll(state.history)
        resultCache.clear()
        state.resultCache.forEach { resultCache[it.cacheKey] = it }
        triageStepProgress = state.triageProgress
        completedLessons = state.completedLessons
        familyMembers.clear()
        familyMembers.addAll(state.familyMembers)
        familyAlerts.clear()
        familyAlerts.addAll(state.familyAlerts)
        calculateStats()
    }

    fun clearLiveCampaignEvent() {
        liveCampaignEvent = null
    }

    fun submitFeedback(feedback: String) {
        val current = assessment ?: return
        viewModelScope.launch {
            try {
                api.sendFeedback(FeedbackRequest(
                    scanId = current.scanId,
                    feedback = feedback,
                    predictedRiskScore = current.riskScore,
                    riskLevel = current.riskLevel,
                    signalIds = current.evidenceSnapshot?.signals?.map { it.code.name }.orEmpty(),
                    notes = "android_native"
                ))
                cyberScore += 5
            } catch (_: Exception) {
            }
        }
    }

    internal fun calculateStats() {
        scamsBlocked = historyItems.count { it.riskLevel in listOf("high", "critical", "dangerous") }
        cyberScore = Math.min(100, (historyItems.size * 5) + (scamsBlocked * 10))
    }

    private val URL_REGEX = Pattern.compile("(?:https?://|www\\.)[\\w\\-.~:/?#\\[\\]@!$&'()*+,;=%]+", Pattern.CASE_INSENSITIVE)


    internal fun normalizeCandidateUrl(raw: String?): String? {
        if (raw == null) return null

        var candidate = raw
            .trim()
            .replace("&nbsp;", " ")
            .replace("\\u0026", "&")
            .trimEnd('.', ',', ';', '"', '\'', ')')

        if (candidate.startsWith("javascript:", ignoreCase = true)) {
            val inner = candidate.removePrefix("javascript:").trim()
            val matcher = URL_REGEX.matcher(inner)
            if (!matcher.find()) return null
            candidate = matcher.group()
        }

        if (candidate.contains("%2f", ignoreCase = true) || candidate.contains("%3a", ignoreCase = true)) {
            runCatching {
                candidate = URLDecoder.decode(candidate, StandardCharsets.UTF_8.name())
            }
        }

        return when {
            candidate.startsWith("https://") || candidate.startsWith("http://") -> candidate
            candidate.startsWith("//") -> "https:$candidate"
            else -> UrlTextExtractor.normalizeCandidate(candidate)
        }
    }

    internal fun sanitizeSharedText(content: String): String {
        return MailShareInputAssembler.sanitizeSharedText(content)
    }

    internal fun currentAssessmentForScan(scanId: String): OfflineAssessment? {
        return assessment?.takeIf { it.scanId == scanId }
            ?: historyItems.firstOrNull { it.scanId == scanId }
    }

    internal fun updateAssessmentAndHistory(
        scanId: String,
        transform: (OfflineAssessment) -> OfflineAssessment
    ) {
        val current = currentAssessmentForScan(scanId) ?: return
        replaceAssessment(scanId, transform(current))
    }

    internal fun replaceAssessment(scanId: String, updated: OfflineAssessment) {
        val idx = historyItems.indexOfFirst { it.scanId == scanId }
        if (idx >= 0) {
            historyItems[idx] = updated
        }
        if (assessment?.scanId == scanId) {
            assessment = updated
        }
        calculateStats()
        saveHistory()
    }

    internal fun buildNeutralPendingAssessment(scannedText: String): OfflineAssessment {
        val urls = extractUrls(scannedText)

        return OfflineAssessment(
            family = if (urls.isNotEmpty()) "Scanare în curs" else "Scanare incompletă",
            riskScore = 0,
            riskLevel = "unknown",
            reasons = if (urls.isNotEmpty()) {
                listOf("Se scanează linkul. Revenim cu verdictul după verificare.")
            } else {
                listOf("Nu am găsit un link complet pentru scanare.")
            },
            safeActions = listOf(
                "Așteaptă finalizarea scanării.",
                "Nu introduce date până nu primești verdictul."
            ),
            keyDangers = emptyList(),
            originalText = scannedText,
            offerAnalysis = null
        )
    }

    fun onCommunityReport() {
        viewModelScope.launch {
            try {
                val current = assessment ?: return@launch
                val target = communityReportTarget(current)
                val report = CommunityReport(
                    hash = target.hash,
                    riskLevel = current.riskLevel,
                    family = current.family,
                    targetType = target.targetType
                )
                api.sendCommunityReport(report)
                cyberScore += 20
            } catch (_: Exception) {
            }
        }
    }

    internal fun extractUrls(input: String): List<String> {
        return UrlTextExtractor.extract(input)
    }

    internal fun looksLikeUrlOnly(input: String, firstUrl: String): Boolean {
        val normalizedInput = input.removeSuffix(".").removeSuffix(",")
        if (normalizedInput.any { it.isWhitespace() }) return false
        UrlTextExtractor.normalizeCandidate(normalizedInput)?.let { normalized ->
            if (normalized.equals(firstUrl, ignoreCase = true)) return true
        }
        return normalizedInput.equals(firstUrl, ignoreCase = true) ||
                normalizedInput.startsWith("http://", ignoreCase = true) ||
                normalizedInput.startsWith("https://", ignoreCase = true) ||
                normalizedInput.startsWith("www.", ignoreCase = true)
    }

    internal fun normalizeUrl(url: String): String {
        val cleaned = url.trim().trimEnd('.', ',', ';', ')', ']')
        return if (cleaned.startsWith("http://", ignoreCase = true) ||
            cleaned.startsWith("https://", ignoreCase = true)
        ) cleaned else "https://$cleaned"
    }

    fun loadReports() {
        if (reportsLoading) return
        reportsLoading = true
        viewModelScope.launch {
            try {
                readiness = api.getReadiness()
                quality = api.getQuality()
                feedbackSamples = api.getFeedbackSamples()
                reputationStats = api.getReputationStats()
            } catch (e: Exception) {
            } finally {
                reportsLoading = false
            }
        }
    }

    fun reset() {
        assessment = null
        invoiceResult = null
        invoiceSanbStatus = null
        lastInvoiceScanSource = null
        pendingOfferConfirmation = null
        officialReportPackage = null
        officialReportStatus = null
        text = ""
        clearAllPendingShared()
    }

    override fun onCleared() {
        speakerGuardServiceUpdatesJob?.cancel()
        speakerGuardServiceUpdatesJob = null
        super.onCleared()
    }
}
