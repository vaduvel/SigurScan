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
        internal const val MAX_INVOICE_IMAGE_EDGE_PX = 1800
        internal const val INVOICE_IMAGE_JPEG_QUALITY = 88
        internal const val TMP_UPLOAD_PREFIX = "temp_upload_"
        internal const val WEB_RISK_NO_THREAT_CACHE_MS = 10L * 60L * 1000L
        internal const val WEB_RISK_THREAT_FALLBACK_CACHE_MS = 5L * 60L * 1000L
        internal const val RESULT_CACHE_PREF_KEY = "scan_result_cache_v3"
        internal const val MAX_RESULT_CACHE_ITEMS = 50
        private const val URLSCAN_PERSONA_COUNTRY = "ro"
        private const val URLSCAN_MOBILE_ANDROID_AGENT =
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
    internal var speakerGuardSession: SpeakerGuardSession? = null

    // Family protection
    var familyMembers = mutableStateListOf<FamilyMember>()
    var familyAlerts = mutableStateListOf<FamilyAlert>()
    var familyResilienceScore by mutableStateOf(75)

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
    
    internal val prefs: SharedPreferences by lazy { createSecurePrefs(application) }
    private val clientInstanceId: String by lazy { loadOrCreateClientInstanceId() }
    internal val gson = Gson()
    internal val recognizer by lazy { TextRecognition.getClient(TextRecognizerOptions.DEFAULT_OPTIONS) }
    internal val barcodeScanner by lazy { BarcodeScanning.getClient() }
    private val URLSCAN_API_KEY = BuildConfig.URLSCAN_API_KEY
    internal val GOOGLE_WEB_RISK_API_KEY = BuildConfig.GOOGLE_WEB_RISK_API_KEY
    private val pendingScreenshotRefreshes = mutableSetOf<String>()
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
                configuredBackendBaseUrl(),
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
        val logging = HttpLoggingInterceptor().apply {
            level = HttpLoggingInterceptor.Level.NONE
        }
        val client = OkHttpClient.Builder()
            .callTimeout(callTimeoutSeconds, TimeUnit.SECONDS)
            .readTimeout(readTimeoutSeconds, TimeUnit.SECONDS)
            .writeTimeout(writeTimeoutSeconds, TimeUnit.SECONDS)
            .connectTimeout(connectTimeoutSeconds, TimeUnit.SECONDS)
            .addInterceptor(
                ApiKeyInterceptor(
                    rawApiKey = BuildConfig.SIGURSCAN_API_KEY,
                    clientInstanceId = clientInstanceId,
                    integrityTokenProvider = { playIntegrityTokenProvider.currentToken() }
                )
            )
            .addInterceptor(logging)
            .build()

        val backendBaseUrl = configuredBackendBaseUrl()

        return Retrofit.Builder()
            .baseUrl(backendBaseUrl)
            .client(client)
            .addConverterFactory(GsonConverterFactory.create())
            .build()
            .create(SigurScanApi::class.java)
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

    private fun configuredBackendBaseUrl(): String {
        val configured = BuildConfig.SIGURSCAN_BACKEND_BASE_URL.trim()
        val allowed = configured.takeIf {
            it.startsWith("https://", ignoreCase = true) ||
                (BuildConfig.DEBUG && it.startsWith("http://", ignoreCase = true))
        }
        return (allowed ?: "https://offline.sigurscan.invalid/")
            .let { if (it.endsWith("/")) it else "$it/" }
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
                audioReadinessStatus = "Apasă readiness sau pornește Speaker Guard pentru verificarea locală."
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
        refreshFamilyResilienceScore()
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


    private fun createSecurePrefs(application: Application): SharedPreferences {
        val encryptedPrefs = runCatching {
            val masterKey = MasterKey.Builder(application)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()

            EncryptedSharedPreferences.create(
                application,
                "sigurscan_prefs",
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )
        }.getOrNull()

        return encryptedPrefs ?: application.getSharedPreferences("sigurscan_prefs", Context.MODE_PRIVATE)
    }

    private fun loadOrCreateClientInstanceId(): String {
        val existing = prefs.getString("client_instance_id", null)
            ?.trim()
            ?.takeIf { it.length in 8..128 }
        if (existing != null) return existing

        val generated = UUID.randomUUID().toString()
        prefs.edit().putString("client_instance_id", generated).apply()
        return generated
    }

    fun stageSharedTextPayload(
        payload: String,
        sourceLabel: String,
        preserveHtml: Boolean = false,
        autoScan: Boolean = false,
        fidelity: SharedContentFidelity = if (preserveHtml) SharedContentFidelity.FULL_HTML else SharedContentFidelity.PLAIN_TEXT_ONLY,
        preservePendingFiles: Boolean = false
    ) {
        if (payload.isBlank()) return
        val decoded = if (preserveHtml) payload else runCatching {
            URLDecoder.decode(payload, StandardCharsets.UTF_8.name())
        }.getOrElse { payload }
        val normalized = if (preserveHtml) {
            MailShareInputAssembler.buildMailScanInput(decoded, extractHtmlLinks(decoded), sourceLabel)
        } else {
            sanitizeSharedText(decoded)
        }
        stagedEvidenceHtml = decoded.takeIf { preserveHtml }
        stagedEvidenceLinks = if (preserveHtml) extractHtmlLinks(decoded) else extractUrls(normalized)
        stagedEvidenceText = normalized
        stagedEvidenceInputKind = if (preserveHtml) "share_html_email" else "share_text"
        stagedEvidenceChannel = if (preserveHtml) "email_html" else "visible_text"
        text = normalized
        pendingSharedSourceLabel = sourceLabel
        sharedContentSourceLabel = sourceLabel
        sharedContentFidelity = fidelity
        if (!preservePendingFiles) {
            pendingSharedFiles = emptyList()
        }
        currentTab = "scan"

        if (autoScan) {
            pendingSharedInput = null
            onScanClick()
        } else {
            pendingSharedInput = normalized
        }
    }

    fun stageSharedFile(
        uri: Uri,
        context: Context,
        sourceLabel: String,
        preserveSharedTextState: Boolean = false
    ) {
        if (uri.toString().isBlank()) return

        val mime = runCatching {
            context.contentResolver.getType(uri)?.lowercase(Locale.getDefault()) ?: ""
        }.getOrElse { "" }

        val fileName = runCatching {
            getFileName(uri, context)
        }.getOrElse { "document" }

        if (!preserveSharedTextState) {
            pendingSharedInput = null
            pendingSharedSourceLabel = sourceLabel
            sharedContentSourceLabel = sourceLabel
            sharedContentFidelity = SharedContentFidelity.FILE_OR_EMAIL
            stagedEvidenceHtml = null
            stagedEvidenceLinks = emptyList()
            stagedEvidenceText = null
            stagedEvidenceInputKind = "import_file"
            stagedEvidenceChannel = "file_or_email"
            text = ""
        }
        currentTab = "scan"
        pendingSharedFiles = pendingSharedFiles + PendingSharedFile(
            uri = uri,
            fileName = fileName,
            mimeType = mime,
            sourceLabel = sourceLabel
        )
    }

    fun clearPendingSharedFiles() {
        pendingSharedFiles = emptyList()
    }

    fun clearPendingSharedInput() {
        pendingSharedInput = null
        pendingSharedSourceLabel = "Conținut partajat"
    }

    fun clearAllPendingShared() {
        clearPendingSharedInput()
        clearPendingSharedFiles()
        pendingOfferConfirmation = null
        clearSharedContentStatus()
        stagedEvidenceHtml = null
        stagedEvidenceLinks = emptyList()
        stagedEvidenceText = null
        stagedEvidenceInputKind = null
        stagedEvidenceChannel = null
    }

    fun clearSharedContentStatus() {
        sharedContentFidelity = null
        sharedContentSourceLabel = "Conținut partajat"
    }

    fun removePendingSharedFile(fileId: String) {
        pendingSharedFiles = pendingSharedFiles.filterNot { it.id == fileId }
    }

    fun scanPendingSharedFile(fileId: String, context: Context) {
        val pendingFile = pendingSharedFiles.firstOrNull { it.id == fileId } ?: return
        pendingSharedFiles = pendingSharedFiles.filterNot { it.id == fileId }
        clearPendingSharedInput()

        val mime = pendingFile.mimeType
        if (mime.startsWith("image/")) {
            onImagePicked(pendingFile.uri, context)
        } else {
            onFilePicked(pendingFile.uri, context)
        }
    }

    fun scanPendingSharedText() {
        val pending = pendingSharedInput
        pendingSharedInput = null
        if (text.isBlank()) text = pending.orEmpty()
        onScanClick()
    }

    internal fun triggerSandboxAnalysis(url: String, scanId: String? = assessment?.scanId) {
        val targetScanId = scanId ?: return
        viewModelScope.launch(kotlinx.coroutines.Dispatchers.IO) {
            try {
                if (tryBackendSandboxAnalysis(url, targetScanId)) {
                    return@launch
                }

                if (URLSCAN_API_KEY.isBlank()) {
                    applySandboxThreatIntelUpdate(
                        scanId = targetScanId,
                        item = ThreatIntelSourceResult(
                            source = "urlscan.io",
                            verdict = "Skipped",
                            severity = "unknown",
                            details = "Captura paginii finale nu este configurată."
                        ),
                        serverInfo = "Captura paginii finale nu este configurată momentan."
                    )
                    return@launch
                }

                val client = OkHttpClient()
                val mediaType = "application/json".toMediaTypeOrNull()
                val body = ThreatIntelOrchestrator.buildUrlscanSubmissionBody(
                    url = url,
                    visibility = "private",
                    country = URLSCAN_PERSONA_COUNTRY,
                    customAgent = URLSCAN_MOBILE_ANDROID_AGENT
                ).toRequestBody(mediaType)
                var request = okhttp3.Request.Builder()
                    .url("https://urlscan.io/api/v1/scan/")
                    .post(body)
                    .addHeader("api-key", URLSCAN_API_KEY)
                    .build()

                var response = client.newCall(request).execute()
                var responseBody = response.body?.string()
                if (!response.isSuccessful && response.code in listOf(400, 403, 422)) {
                    response.close()
                    val fallbackBody = ThreatIntelOrchestrator.buildUrlscanSubmissionBody(
                        url = url,
                        visibility = "unlisted",
                        country = URLSCAN_PERSONA_COUNTRY,
                        customAgent = URLSCAN_MOBILE_ANDROID_AGENT
                    ).toRequestBody(mediaType)
                    request = okhttp3.Request.Builder()
                        .url("https://urlscan.io/api/v1/scan/")
                        .post(fallbackBody)
                        .addHeader("api-key", URLSCAN_API_KEY)
                        .build()
                    response = client.newCall(request).execute()
                    responseBody = response.body?.string()
                }
                
                if (response.isSuccessful && responseBody != null) {
                    val scanSubmission = gson.fromJson(responseBody, Map::class.java)
                    val uuid = scanSubmission["uuid"] as? String
                    
                    if (uuid != null) {
                        val reportUrl = urlscanReportUrl(uuid)
                        applySandboxThreatIntelUpdate(
                            scanId = targetScanId,
                            item = ThreatIntelSourceResult(
                                source = "urlscan.io",
                                verdict = "Pending",
                                severity = "unknown",
                                details = "Se generează captura paginii finale."
                            ),
                            serverInfo = "Se generează captura paginii finale...",
                            reportUrl = reportUrl,
                            finalUrl = url
                        )

                        // urlscan recomandă să așteptăm înainte de polling ca să reducem 404/rate-limit noise.
                        kotlinx.coroutines.delay(10000)
                        var isFinished = false
                        var attempts = 0
                        val maxAttempts = 9 // Așteptăm maxim ~55 de secunde: 10s inițial + 9 * 5s

                        while (!isFinished && attempts < maxAttempts) {
                            attempts++
                            kotlinx.coroutines.delay(5000)

                            val checkRequest = okhttp3.Request.Builder()
                                .url("https://urlscan.io/api/v1/result/$uuid/")
                                .addHeader("api-key", URLSCAN_API_KEY)
                                .build()
                            
                            val checkResponse = client.newCall(checkRequest).execute()
                            if (checkResponse.code == 200) {
                                isFinished = true
                                val resultBody = checkResponse.body?.string()
                                val resultMap = runCatching {
                                    gson.fromJson(resultBody, Map::class.java) as? Map<*, *>
                                }.getOrNull()
                                val summary = summarizeUrlscanResult(resultMap, attempts)
                                val screenshotUrl = downloadUrlscanScreenshot(uuid, client)
                                
                                kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Main) {
                                    val current = currentAssessmentForScan(targetScanId)
                                    if (current != null) {
                                        val mergedThreatIntel = upsertThreatIntel(current.threatIntel, summary)
                                        val gated = reevaluateGateWithThreatIntel(
                                            current = current.copy(
                                                screenshotUrl = screenshotUrl,
                                                serverInfo = if (screenshotUrl == null) {
                                                    "Captura paginii finale nu a putut fi descărcată momentan."
                                                } else {
                                                    "Captura paginii finale a fost generată."
                                                },
                                                sandboxReportUrl = reportUrl
                                            ),
                                            threatIntel = mergedThreatIntel,
                                            finalUrl = url
                                        )
                                        replaceAssessment(targetScanId, gated)
                                    }
                                }
                            } else if (checkResponse.code == 404) {
                                // Încă se procesează, continuăm polling-ul
                                applySandboxThreatIntelUpdate(
                                    scanId = targetScanId,
                                    item = ThreatIntelSourceResult(
                                        source = "urlscan.io",
                                        verdict = "Pending",
                                        severity = "unknown",
                                        details = "Se generează captura paginii finale."
                                    ),
                                    serverInfo = "Se generează captura paginii finale... (Pas $attempts/$maxAttempts)",
                                    reportUrl = reportUrl,
                                    finalUrl = url
                                )
                            } else {
                                // Altă eroare, ne oprim
                                applySandboxThreatIntelUpdate(
                                    scanId = targetScanId,
                                    item = ThreatIntelSourceResult(
                                        source = "urlscan.io",
                                        verdict = "Error",
                                        severity = "unknown",
                                        details = "Verificarea vizuală nu a răspuns complet."
                                    ),
                                    serverInfo = "Captura paginii finale nu a răspuns complet.",
                                    reportUrl = reportUrl,
                                    finalUrl = url
                                )
                                break
                            }
                        }

                        if (!isFinished) {
                            applySandboxThreatIntelUpdate(
                                scanId = targetScanId,
                                item = ThreatIntelSourceResult(
                                    source = "urlscan.io",
                                    verdict = "Timeout",
                                    severity = "unknown",
                                    details = "Captura paginii finale nu a fost gata la timp."
                                ),
                                serverInfo = "Captura paginii finale nu a fost gata la timp. Reîncearcă scanarea.",
                                reportUrl = reportUrl,
                                finalUrl = url
                            )
                        }
                    }
                } else {
                    applySandboxThreatIntelUpdate(
                        scanId = targetScanId,
                        item = ThreatIntelSourceResult(
                            source = "urlscan.io",
                            verdict = "Error",
                            severity = "unknown",
                            details = "Nu am putut porni verificarea vizuală."
                        ),
                        serverInfo = "Nu am putut porni captura paginii finale.",
                        finalUrl = url
                    )
                }
            } catch (e: Exception) {
                applySandboxThreatIntelUpdate(
                    scanId = targetScanId,
                    item = ThreatIntelSourceResult(
                        source = "urlscan.io",
                        verdict = "Error",
                        severity = "unknown",
                        details = "Nu am putut genera captura paginii finale."
                    ),
                    serverInfo = "Nu am putut genera captura paginii finale momentan.",
                    finalUrl = url
                )
            }
        }
    }

    private suspend fun tryBackendSandboxAnalysis(url: String, scanId: String): Boolean {
        return try {
            val submitted = api.submitUrlscanSandbox(
                UrlscanSandboxSubmitRequest(
                    url = url,
                    visibility = "private",
                    country = URLSCAN_PERSONA_COUNTRY,
                    customagent = URLSCAN_MOBILE_ANDROID_AGENT,
                    sourceChannel = "android_native"
                )
            )
            val uuid = submitted.uuid?.takeIf { it.isNotBlank() } ?: return false
            val reportUrl = submitted.reportUrl
            val screenshotUrl = submitted.screenshotUrl

            applySandboxThreatIntelUpdate(
                scanId = scanId,
                item = ThreatIntelSourceResult(
                    source = "urlscan.io",
                    verdict = "Pending",
                    severity = "unknown",
                    details = "Se generează captura paginii finale."
                ),
                serverInfo = "Se generează captura paginii finale...",
                reportUrl = reportUrl,
                screenshotUrl = null,
                finalUrl = url
            )

            kotlinx.coroutines.delay(10000)
            var isFinished = false
            val maxAttempts = 9
            for (attempt in 1..maxAttempts) {
                kotlinx.coroutines.delay(5000)
                val result = api.getUrlscanSandboxResult(uuid)
                val status = result.status.orEmpty().lowercase(Locale.US)
                if (status == "pending") {
                    applySandboxThreatIntelUpdate(
                        scanId = scanId,
                        item = ThreatIntelSourceResult(
                            source = "urlscan.io",
                            verdict = "Pending",
                            severity = "unknown",
                            details = "Se generează captura paginii finale."
                        ),
                        serverInfo = "Se generează captura paginii finale... (Pas $attempt/$maxAttempts)",
                        reportUrl = result.reportUrl ?: reportUrl,
                        screenshotUrl = null,
                        finalUrl = result.finalUrl ?: submitted.submittedUrl ?: url
                    )
                    continue
                }

                isFinished = true
                val details = result.details ?: "Captura paginii finale a fost generată."
                val remoteScreenshotUrl = result.screenshotUrl ?: screenshotUrl
                val stableScreenshotUrl = downloadSandboxScreenshotProxy(remoteScreenshotUrl) ?: remoteScreenshotUrl
                applySandboxThreatIntelUpdate(
                    scanId = scanId,
                    item = ThreatIntelSourceResult(
                        source = "urlscan.io",
                        verdict = result.verdict ?: "No malicious classification",
                        severity = result.severity ?: "low",
                        details = details
                    ),
                    serverInfo = details,
                    reportUrl = result.reportUrl ?: reportUrl,
                    screenshotUrl = stableScreenshotUrl,
                    finalUrl = result.finalUrl ?: submitted.submittedUrl ?: url
                )
                break
            }

            if (!isFinished) {
                applySandboxThreatIntelUpdate(
                    scanId = scanId,
                    item = ThreatIntelSourceResult(
                        source = "urlscan.io",
                        verdict = "Timeout",
                        severity = "unknown",
                        details = "Captura paginii finale nu a fost gata la timp."
                    ),
                    serverInfo = "Captura paginii finale nu a fost gata la timp. Scanarea poate continua după reîncercare.",
                    reportUrl = reportUrl,
                    screenshotUrl = null,
                    finalUrl = submitted.submittedUrl ?: url
                )
            }

            true
        } catch (_: Exception) {
            false
        }
    }

    private suspend fun applySandboxThreatIntelUpdate(
        scanId: String,
        item: ThreatIntelSourceResult,
        serverInfo: String,
        reportUrl: String? = null,
        screenshotUrl: String? = null,
        finalUrl: String? = null
    ) {
        withContext(Dispatchers.Main) {
            val current = currentAssessmentForScan(scanId) ?: return@withContext
            val mergedThreatIntel = upsertThreatIntel(current.threatIntel, item)
            val gated = reevaluateGateWithThreatIntel(
                current = current.copy(
                    screenshotUrl = screenshotUrl ?: current.screenshotUrl,
                    serverInfo = serverInfo,
                    sandboxReportUrl = reportUrl ?: current.sandboxReportUrl
                ),
                threatIntel = mergedThreatIntel,
                finalUrl = finalUrl ?: current.finalUrl,
                redirectChain = current.redirectChain
            )
            replaceAssessment(scanId, gated)
        }
    }

    private fun downloadUrlscanScreenshot(uuid: String, client: OkHttpClient): String? {
        if (URLSCAN_API_KEY.isBlank()) return null

        val request = Request.Builder()
            .url(urlscanScreenshotUrl(uuid))
            .addHeader("api-key", URLSCAN_API_KEY)
            .build()

        return runCatching {
            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) return@runCatching null
                val bytes = response.body?.bytes() ?: return@runCatching null
                if (bytes.isEmpty()) return@runCatching null

                val dir = File(getApplication<Application>().cacheDir, "urlscan-screenshots").apply {
                    mkdirs()
                }
                val safeUuid = uuid.replace(Regex("[^A-Za-z0-9._-]"), "_")
                val screenshotFile = File(dir, "$safeUuid.png")
                FileOutputStream(screenshotFile).use { it.write(bytes) }
                Uri.fromFile(screenshotFile).toString()
            }
        }.getOrNull()
    }

    private fun downloadSandboxScreenshotProxy(screenshotUrl: String?): String? {
        if (screenshotUrl.isNullOrBlank()) return null
        if (screenshotUrl.startsWith("file://", ignoreCase = true)) return screenshotUrl

        val request = Request.Builder()
            .url(screenshotUrl)
            .build()

        return runCatching {
            threatIntelClient.newCall(request).execute().use { response ->
                if (!response.isSuccessful) return@runCatching null
                val bytes = response.body?.bytes() ?: return@runCatching null
                if (bytes.isEmpty()) return@runCatching null

                val dir = File(getApplication<Application>().cacheDir, "urlscan-screenshots").apply {
                    mkdirs()
                }
                val digest = MessageDigest.getInstance("SHA-256")
                    .digest(screenshotUrl.toByteArray(StandardCharsets.UTF_8))
                    .joinToString("") { "%02x".format(it) }
                    .take(32)
                val screenshotFile = File(dir, "backend-$digest.png")
                FileOutputStream(screenshotFile).use { it.write(bytes) }
                Uri.fromFile(screenshotFile).toString()
            }
        }.getOrNull()
    }

    internal fun scheduleSandboxScreenshotRefresh(scanId: String, screenshotUrl: String) {
        if (!pendingScreenshotRefreshes.add(scanId)) return
        viewModelScope.launch(Dispatchers.IO) {
            try {
                repeat(8) { attempt ->
                    if (attempt > 0) kotlinx.coroutines.delay(10_000L)
                    val stableScreenshot = downloadSandboxScreenshotProxy(screenshotUrl)
                    if (stableScreenshot != null) {
                        withContext(Dispatchers.Main) {
                            updateAssessmentAndHistory(scanId) { current ->
                                current.copy(screenshotUrl = stableScreenshot)
                            }
                        }
                        return@launch
                    }
                }
            } finally {
                withContext(Dispatchers.Main) {
                    pendingScreenshotRefreshes.remove(scanId)
                }
            }
        }
    }

    fun onSharedTextPayload(payload: String, mimeType: String? = null) {
        if (payload.isBlank()) return

        val isHtmlPayload = mimeType?.contains("html", ignoreCase = true) == true
            || payload.contains("<a", ignoreCase = true)
            || payload.contains("<html", ignoreCase = true)

        val normalizedPayload = if (isHtmlPayload) {
            payload
        } else {
            runCatching {
                URLDecoder.decode(payload, StandardCharsets.UTF_8.name())
            }.getOrNull() ?: payload
        }

        text = if (isHtmlPayload) {
            MailShareInputAssembler.buildMailScanInput(
                normalizedPayload,
                extractHtmlLinks(normalizedPayload),
                "Conținut text partajat"
            )
        } else {
            normalizedPayload
        }
        stagedEvidenceHtml = normalizedPayload.takeIf { isHtmlPayload }
        stagedEvidenceLinks = if (isHtmlPayload) extractHtmlLinks(normalizedPayload) else extractUrls(normalizedPayload)
        stagedEvidenceText = text
        stagedEvidenceInputKind = if (isHtmlPayload) "share_html_email" else "share_text"
        stagedEvidenceChannel = if (isHtmlPayload) "email_html" else "visible_text"

        onScanClick()
    }

    fun onFilePicked(uri: Uri, context: Context) {
        val fileName = getFileName(uri, context)
        val mimeType = runCatching {
            context.contentResolver.getType(uri)?.lowercase(Locale.getDefault()) ?: ""
        }.getOrDefault("")
        val importKind = FileImportClassifier.classify(fileName, mimeType)
        
        if (importKind == FileImportKind.UNSUPPORTED || importKind == FileImportKind.OUTLOOK_MSG_UNSUPPORTED) {
            val reason = if (importKind == FileImportKind.OUTLOOK_MSG_UNSUPPORTED) {
                "Fișierele Outlook .msg nu sunt încă suportate. Exportă mesajul ca .eml sau partajează conținutul direct din aplicația de email."
            } else {
                "Tipul fișierului nu este suportat pentru scanare. Acceptăm momentan PDF, EML, HTML și TXT."
            }
            assessment = applyEvidenceGate(
                current = OfflineAssessment(
                    family = "Tip fișier nesuportat",
                    riskScore = 0,
                    riskLevel = "unknown",
                    reasons = listOf(reason),
                    safeActions = listOf(
                        "Încarcă un PDF, .eml, .html sau .txt.",
                        "Pentru poze folosește opțiunea Screenshot/Imagine, iar pentru coduri QR folosește scanarea QR."
                    ),
                    keyDangers = listOf("Nu avem suficiente dovezi tehnice pentru verdict."),
                    originalText = "Fișierul nu a fost scanat: $fileName."
                ),
                rawInput = "Tip fișier nesuportat: $fileName",
                inputKind = "import_unsupported_file",
                channel = "file_import",
                providerStates = unavailableProviderStates(),
                completeness = EvidenceCompleteness.LOCAL_ONLY
            )
            loading = false
            return
        }

        if (importKind == FileImportKind.AUDIO) {
            publishAudioShareRequiresTranscript(fileName)
            return
        }

        if (importKind == FileImportKind.TEXT) {
            loading = true
            loadingMsg = "Analizăm fișierul text..."

            viewModelScope.launch {
                try {
                    val rawContent = readTextFromUri(uri, context)
                    val extractedLinks = extractUrls(rawContent) + extractHtmlLinks(rawContent)
                    text = MailShareInputAssembler.buildMailScanInput(rawContent, extractedLinks.distinct(), fileName)
                    stagedEvidenceHtml = null
                    stagedEvidenceLinks = extractedLinks.distinct()
                    stagedEvidenceText = text
                    stagedEvidenceInputKind = "import_text_file"
                    stagedEvidenceChannel = "text_file"
                    onScanClick()
                } catch (e: Exception) {
                    text = "Eroare la citirea textului: $fileName"
                    stagedEvidenceHtml = null
                    stagedEvidenceLinks = emptyList()
                    stagedEvidenceText = text
                    stagedEvidenceInputKind = "import_text_file"
                    stagedEvidenceChannel = "text_file"
                    onScanClick()
                }
            }
            return
        }

        if (importKind == FileImportKind.HTML || importKind == FileImportKind.EMAIL) {
            loading = true
            loadingMsg = if (importKind == FileImportKind.HTML) "Analizăm conținutul HTML..." else "Analizăm fișierul email..."

            viewModelScope.launch {
                try {
                    val rawContent = readTextFromUri(uri, context)
                    val parsedEmail = if (importKind == FileImportKind.EMAIL) EmailMessageParser.parse(rawContent) else null

                    val htmlContentSource = if (importKind == FileImportKind.EMAIL) {
                        parsedEmail?.htmlText?.ifBlank { rawContent } ?: rawContent
                    } else {
                        rawContent
                    }
                    val visibleMailText = if (importKind == FileImportKind.EMAIL) {
                        parsedEmail?.bodyForAnalysis?.ifBlank { rawContent } ?: rawContent
                    } else {
                        rawContent
                    }

                    val extractedHtmlLinks = extractHtmlLinks(htmlContentSource)
                    val extractedUrls = extractUrls(rawContent)
                    val visibleText = sanitizeSharedText(visibleMailText)
                    val allLinks = (extractedHtmlLinks + extractedUrls).distinct().filter { it.isNotBlank() }
                    val finalText = MailShareInputAssembler.buildMailScanInput(visibleText, allLinks, fileName)
                    text = finalText
                    stagedEvidenceHtml = htmlContentSource
                    stagedEvidenceLinks = allLinks
                    stagedEvidenceText = finalText
                    stagedEvidenceInputKind = if (importKind == FileImportKind.EMAIL) "import_email" else "import_html"
                    stagedEvidenceChannel = if (importKind == FileImportKind.EMAIL) "email_file" else "html_file"
                    loading = false
                    loadingMsg = ""
                    onScanClick()
                } catch (e: Exception) {
                    text = "Eroare la citirea conținutului: $fileName"
                    stagedEvidenceHtml = null
                    stagedEvidenceLinks = emptyList()
                    stagedEvidenceText = text
                    stagedEvidenceInputKind = if (importKind == FileImportKind.EMAIL) "import_email" else "import_html"
                    stagedEvidenceChannel = if (importKind == FileImportKind.EMAIL) "email_file" else "html_file"
                    loading = false
                    loadingMsg = ""
                    onScanClick()
                }
            }
            return
        }

        loading = true
        loadingMsg = "Analizăm documentul PDF..."
        
        viewModelScope.launch {
            if (!isUploadSizeAllowed(uri, context)) {
                val maxMb = MAX_UPLOAD_BYTES / (1024L * 1024L)
                assessment = applyEvidenceGate(
                    current = OfflineAssessment(
                        family = "Fișier prea mare",
                        riskScore = 0,
                        riskLevel = "unknown",
                        reasons = listOf("Fișierul depășește limita de ${maxMb}MB pentru scanarea cloud."),
                        safeActions = listOf(
                            "Încarcă PDF-ul/e-mailul împărțit în secțiuni mai mici.",
                            "Alternativ, copiază textul/ linkurile suspecte în câmpul de scanare."
                        ),
                        keyDangers = listOf("Nu s-a putut analiza conținutul server-side din cauza dimensiunii."),
                        originalText = "Fișierul nu a fost scanat: $fileName."
                    ),
                    rawInput = "Fișier prea mare: $fileName",
                    inputKind = "import_file",
                    channel = "file_or_email",
                    providerStates = unavailableProviderStates(),
                    completeness = EvidenceCompleteness.LOCAL_ONLY
                )
                loading = false
                return@launch
            }

            var file: File? = null
            try {
                file = uriToFile(uri, context, MAX_UPLOAD_BYTES)
                val requestFile = file.asRequestBody("application/pdf".toMediaTypeOrNull())
                val body = MultipartBody.Part.createFormData(
                    "pdf_file",
                    file.name, 
                    requestFile
                )
                val source = "android_file_upload".toRequestBody("text/plain".toMediaTypeOrNull())
                
                val response = uploadApi.extractPdf(body, source)
                runBackendOrchestratedScanFromExtraction(
                    response = response,
                    fileName = fileName,
                    inputKind = "import_pdf",
                    channel = "pdf_ocr"
                )
            } catch (e: Exception) {
                if (e is UploadSizeExceededException) {
                    val maxMb = MAX_UPLOAD_BYTES / (1024L * 1024L)
                    assessment = applyEvidenceGate(
                        current = OfflineAssessment(
                            family = "Fișier prea mare",
                            riskScore = 0,
                            riskLevel = "unknown",
                            reasons = listOf("Fișierul depășește limita de ${maxMb}MB pentru scanare cloud."),
                            safeActions = listOf(
                                "Încarcă PDF-ul/e-mailul împărțit în secțiuni mai mici.",
                                "Alternativ, copiază textul/ linkurile suspecte în câmpul de scanare."
                            ),
                            keyDangers = listOf("Nu s-a putut analiza conținutul server-side din cauza dimensiunii."),
                            originalText = "Fișierul nu a fost scanat: $fileName."
                        ),
                        rawInput = "Fișier prea mare: $fileName",
                        inputKind = "import_file",
                        channel = "file_or_email",
                        providerStates = unavailableProviderStates(),
                        completeness = EvidenceCompleteness.LOCAL_ONLY
                    )
                    loading = false
                    return@launch
                }

                loadingMsg = "Extragem textul din PDF pentru scanare..."
                val fallback = runCatching {
                    extractTextFromPdfFallback(uri, context)
                }.getOrNull() ?: PdfFallbackExtraction("", emptySet())

                if (fallback.extractedText.isNotBlank() || fallback.extractedLinks.isNotEmpty()) {
                    val extractedLinks = (
                        fallback.extractedLinks +
                            extractUrls(fallback.extractedText) +
                            extractHtmlLinks(fallback.extractedText)
                        ).distinct().filter { it.isNotBlank() }
                    text = MailShareInputAssembler.buildMailScanInput(
                        fallback.extractedText.ifBlank { "Document PDF fără text OCR detectabil." },
                        extractedLinks,
                        fileName
                    )
                    stagedEvidenceHtml = null
                    stagedEvidenceLinks = extractedLinks
                    stagedEvidenceText = text
                    stagedEvidenceInputKind = "import_pdf"
                    stagedEvidenceChannel = "pdf_ocr"
                    onScanClick()
                } else {
                    assessment = applyEvidenceGate(
                        current = OfflineAssessment(
                            family = "Scanare incompletă",
                            riskScore = 0,
                            riskLevel = "unknown",
                            reasons = listOf("Nu s-a putut analiza cloud, iar OCR-ul nu a extras text verificabil din PDF."),
                            safeActions = listOf("Reîncearcă scanarea sau trimite un PDF cu text/linkuri detectabile."),
                            keyDangers = listOf("Nu avem suficiente dovezi tehnice pentru verdict."),
                            originalText = "Eroare la analiza locală a documentului PDF."
                        ),
                        rawInput = "PDF fără text OCR verificabil: $fileName",
                        inputKind = "import_pdf",
                        channel = "pdf_ocr",
                        providerStates = unavailableProviderStates(),
                        completeness = EvidenceCompleteness.LOCAL_ONLY
                    )
                }
            } finally {
                file?.delete()
                loading = false
            }
        }
    }

    private fun publishAudioShareRequiresTranscript(fileName: String) {
        val reason = "Audio primit. Transcrierea audio nu este activă încă; poți lipi transcriptul."
        stagedEvidenceHtml = null
        stagedEvidenceLinks = emptyList()
        stagedEvidenceText = null
        stagedEvidenceInputKind = "import_audio_file"
        stagedEvidenceChannel = "audio_share"
        text = ""
        assessment = applyEvidenceGate(
            current = OfflineAssessment(
                family = "Audio primit",
                riskScore = 0,
                riskLevel = "unknown",
                reasons = listOf(reason),
                safeActions = listOf(
                    "Lipește transcriptul conversației sau partajează textul conversației către SigurScan.",
                    "Nu trimite bani, coduri sau date personale până nu verifici conversația printr-un canal oficial."
                ),
                keyDangers = listOf("Fișierul audio nu a fost transcris, deci nu avem dovezi suficiente pentru verdict."),
                originalText = "Audio primit, transcriere necesară: $fileName."
            ),
            rawInput = "Audio primit, transcriere necesară: $fileName",
            inputKind = "import_audio_file",
            channel = "audio_share",
            providerStates = unavailableProviderStates(),
            completeness = EvidenceCompleteness.LOCAL_ONLY
        )
        loading = false
        loadingMsg = ""
    }

    internal fun getFileName(uri: Uri, context: Context): String {
        var name = "document"
        val cursor = runCatching {
            context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
        }.getOrNull()
        cursor?.use {
            if (it.moveToFirst()) {
                val nameIndex = it.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                if (nameIndex != -1) name = it.getString(nameIndex)
            }
        }
        return name
    }

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

    private fun updateAssessmentAndHistory(
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
        speakerGuardSession?.stop()
        speakerGuardSession = null
        super.onCleared()
    }
}
