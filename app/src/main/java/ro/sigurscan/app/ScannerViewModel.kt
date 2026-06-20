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
    private data class PdfFallbackExtraction(
        val extractedText: String,
        val extractedLinks: Set<String> = emptySet()
    )
    private data class PendingInvoiceScanSource(
        val uri: Uri,
        val officialXmlUri: Uri? = null
    )
    internal data class CachedThreatIntelResult(
        val result: ThreatIntelSourceResult,
        val expiresAtMillis: Long
    )
    private data class CachedAssessmentRecord(
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
        private const val RESULT_CACHE_PREF_KEY = "scan_result_cache_v3"
        private const val MAX_RESULT_CACHE_ITEMS = 50
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
    private var lastInvoiceScanSource: PendingInvoiceScanSource? = null
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
    private val recognizer by lazy { TextRecognition.getClient(TextRecognizerOptions.DEFAULT_OPTIONS) }
    private val barcodeScanner by lazy { BarcodeScanning.getClient() }
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
    private val evidenceGate = EvidenceGate()
    private var stagedEvidenceHtml: String? = null
    private var stagedEvidenceLinks: List<String> = emptyList()
    private var stagedEvidenceText: String? = null
    private var stagedEvidenceInputKind: String? = null
    private var stagedEvidenceChannel: String? = null
    private val resultCache = Collections.synchronizedMap(LinkedHashMap<String, CachedAssessmentRecord>())
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
    private val scanStartApi: SigurScanApi by lazy {
        buildApiClient(
            callTimeoutSeconds = 15,
            readTimeoutSeconds = 15,
            writeTimeoutSeconds = 15,
            connectTimeoutSeconds = 8
        )
    }
    private val scanPollApi: SigurScanApi by lazy {
        buildApiClient(
            callTimeoutSeconds = 10,
            readTimeoutSeconds = 10,
            writeTimeoutSeconds = 10,
            connectTimeoutSeconds = 5
        )
    }
    private val uploadApi: SigurScanApi by lazy {
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

    fun requestPostIncidentActionPlan(impacts: List<String>) {
        val current = assessment ?: return
        if (actionPlanLoading || impacts.isEmpty()) return
        actionPlanLoading = true
        actionPlanStatus = "Construim planul pentru ce s-a întâmplat."
        viewModelScope.launch {
            try {
                val plan = api.getActionPlan(
                    ActionPlanRequest(
                        verdict = when (current.riskLevel.lowercase(Locale.US)) {
                            "high", "critical" -> "DANGEROUS"
                            "medium" -> "SUSPECT"
                            else -> current.gateResult?.action?.userLabel ?: "SUSPECT"
                        },
                        family = current.offerEvidence?.fields?.familyCode ?: current.family,
                        impacts = impacts,
                        targetType = if (current.finalUrl != null) "url" else null,
                        targetRedacted = current.finalUrl
                    )
                )
                val updated = current.copy(actionPlan = plan)
                assessment = updated
                replaceAssessment(current.scanId, updated)
                actionPlanStatus = "Plan actualizat pentru impacturile selectate."
            } catch (_: Exception) {
                actionPlanStatus = "Nu am putut actualiza planul. Reîncearcă."
            } finally {
                actionPlanLoading = false
            }
        }
    }

    fun requestOfficialReportPackage() {
        val current = assessment ?: return
        if (officialReportLoading) return
        officialReportLoading = true
        officialReportStatus = "Pregătim raportul oficial precompletat."
        viewModelScope.launch {
            try {
                val targetRedacted = current.finalUrl
                    ?.substringBefore("?")
                    ?.takeIf { it.isNotBlank() }
                    ?: "[redactat]"
                val report = api.buildOneTapReport(
                    OneTapReportRequest(
                        targetType = if (current.finalUrl != null) "url" else "unknown",
                        targetRedacted = targetRedacted,
                        family = current.offerEvidence?.fields?.familyCode ?: current.family,
                        verdict = when (current.riskLevel.lowercase(Locale.US)) {
                            "high", "critical" -> "DANGEROUS"
                            "medium" -> "SUSPECT"
                            else -> current.gateResult?.action?.userLabel ?: "SUSPECT"
                        },
                        redactedSummary = current.reasons.take(3).joinToString(" ")
                            .takeIf { it.isNotBlank() }
                    )
                )
                officialReportPackage = report
                officialReportStatus = "Raport pregătit: ${report.channels.orEmpty().size} canale."
            } catch (_: Exception) {
                officialReportStatus = "Nu am putut pregăti raportul oficial. Reîncearcă."
            } finally {
                officialReportLoading = false
            }
        }
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

    private fun calculateStats() {
        scamsBlocked = historyItems.count { it.riskLevel in listOf("high", "critical", "dangerous") }
        cyberScore = Math.min(100, (historyItems.size * 5) + (scamsBlocked * 10))
    }

    private val URL_REGEX = Pattern.compile("(?:https?://|www\\.)[\\w\\-.~:/?#\\[\\]@!$&'()*+,;=%]+", Pattern.CASE_INSENSITIVE)

    private fun applyEvidenceGate(
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
        return current.withGate(snapshot, gateResult, rawInput, threatIntel)
    }

    private fun OfflineAssessment.withGate(
        snapshot: EvidenceSnapshot,
        gateResult: GateResult,
        rawInput: String,
        mergedThreatIntel: List<ThreatIntelSourceResult> = threatIntel
    ): OfflineAssessment {
        val gateReason = GateResultPresentation.reasonText(gateResult, snapshot)
        val gateActions = GateResultPresentation.recommendedActions(gateResult)
        return copy(
            family = GateResultPresentation.familyLabel(gateResult.action, family),
            riskScore = GateResultPresentation.legacyRiskScore(gateResult.action),
            riskLevel = GateResultPresentation.legacyRiskLevel(gateResult.action),
            reasons = (listOf(gateReason) + reasons).map { it.trim() }.filter { it.isNotBlank() }.distinct(),
            safeActions = (gateActions + safeActions).map { it.trim() }.filter { it.isNotBlank() }.distinct(),
            keyDangers = when (gateResult.action) {
                GateAction.DO_NOT_CONTINUE,
                GateAction.NO_ENTER_DATA,
                GateAction.NO_REPLY -> (listOf(GateResultPresentation.supportText(gateResult)) + keyDangers)
                else -> keyDangers
            }.map { it.trim() }.filter { it.isNotBlank() }.distinct(),
            originalText = redactedAuditSummary(rawInput, snapshot),
            finalUrl = snapshot.formActionUrl ?: snapshot.finalUrl ?: finalUrl,
            redirectChain = snapshot.redirectChain.ifEmpty { redirectChain },
            threatIntel = mergedThreatIntel,
            evidenceSnapshot = snapshot,
            gateResult = gateResult,
            inputFidelity = sharedContentFidelity
        )
    }

    internal fun reevaluateGateWithThreatIntel(
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
        return current.copy(threatIntel = threatIntel).withGate(
            snapshot = mergedSnapshot,
            gateResult = gateResult,
            rawInput = current.originalText,
            mergedThreatIntel = threatIntel
        )
    }

    private fun inferEvidenceInputKind(rawInput: String): String = when {
        sharedContentFidelity == SharedContentFidelity.FULL_HTML -> "share_html_email"
        sharedContentFidelity == SharedContentFidelity.FILE_OR_EMAIL -> "import_file"
        looksLikeUrlOnly(rawInput.trim(), extractUrls(rawInput).firstOrNull().orEmpty()) -> "paste_url"
        else -> "paste_text"
    }

    private fun inferEvidenceChannel(rawInput: String): String = when {
        sharedContentFidelity == SharedContentFidelity.FULL_HTML -> "email_html"
        sharedContentFidelity == SharedContentFidelity.PLAIN_TEXT_ONLY -> "visible_text"
        sharedContentFidelity == SharedContentFidelity.FILE_OR_EMAIL -> "file_or_email"
        extractUrls(rawInput).isNotEmpty() -> "text_with_url"
        else -> "text"
    }

    private fun activeEvidenceHtml(rawInput: String): String? {
        return stagedEvidenceHtml?.takeIf { stagedEvidenceText == rawInput }
    }

    private fun activeEvidenceLinks(rawInput: String): List<String> {
        return stagedEvidenceLinks.takeIf { stagedEvidenceText == rawInput && it.isNotEmpty() }
            ?: (extractUrls(rawInput) + extractHtmlLinks(rawInput)).distinct()
    }

    private fun activeEvidenceInputKind(rawInput: String): String? {
        return stagedEvidenceInputKind?.takeIf { stagedEvidenceText == rawInput }
    }

    private fun activeEvidenceChannel(rawInput: String): String? {
        return stagedEvidenceChannel?.takeIf { stagedEvidenceText == rawInput }
    }

    private fun redactedAuditSummary(rawInput: String, snapshot: EvidenceSnapshot): String {
        val hash = MessageDigest.getInstance("SHA-256")
            .digest(rawInput.toByteArray(StandardCharsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
            .take(16)
        val target = snapshot.formActionHost ?: snapshot.finalUrl ?: snapshot.primaryUrl ?: "no-target"
        return "scan=${snapshot.inputKind}; channel=${snapshot.channel}; target=${target.take(96)}; inputHash=$hash"
    }

    private fun unavailableProviderStates(): Map<ProviderId, ProviderState> = mapOf(
        ProviderId.WEB_RISK to ProviderState(ProviderId.WEB_RISK, ProviderStatus.ERROR, note = "Backend/provider unavailable"),
        ProviderId.URLSCAN to ProviderState(ProviderId.URLSCAN, ProviderStatus.ERROR, note = "Backend/provider unavailable"),
        ProviderId.PHISHING_DATABASE to ProviderState(ProviderId.PHISHING_DATABASE, ProviderStatus.ERROR, note = "Phishing.Database unavailable"),
        ProviderId.CLAIM_VERIFIER to ProviderState(ProviderId.CLAIM_VERIFIER, ProviderStatus.ERROR, note = "Offer/claim verification unavailable")
    )

    private fun pendingOnlineProviderStates(): Map<ProviderId, ProviderState> = mapOf(
        ProviderId.WEB_RISK to ProviderState(ProviderId.WEB_RISK, ProviderStatus.PENDING, note = "Backend reputation check running"),
        ProviderId.URLSCAN to ProviderState(ProviderId.URLSCAN, ProviderStatus.PENDING, note = "Sandbox preview running"),
        ProviderId.PHISHING_DATABASE to ProviderState(ProviderId.PHISHING_DATABASE, ProviderStatus.PENDING, note = "Phishing.Database reputation check running"),
        ProviderId.CLAIM_VERIFIER to ProviderState(ProviderId.CLAIM_VERIFIER, ProviderStatus.PENDING, note = "Offer/claim verification running")
    )

    private fun backendUnavailableWhileSandboxRuns(): Map<ProviderId, ProviderState> = mapOf(
        ProviderId.WEB_RISK to ProviderState(ProviderId.WEB_RISK, ProviderStatus.ERROR, note = "Backend reputation check unavailable"),
        ProviderId.URLSCAN to ProviderState(ProviderId.URLSCAN, ProviderStatus.PENDING, note = "Sandbox preview still running"),
        ProviderId.PHISHING_DATABASE to ProviderState(ProviderId.PHISHING_DATABASE, ProviderStatus.ERROR, note = "Phishing.Database unavailable"),
        ProviderId.CLAIM_VERIFIER to ProviderState(ProviderId.CLAIM_VERIFIER, ProviderStatus.ERROR, note = "Offer/claim verification unavailable")
    )

    private fun startPreliminaryUrlAssessment(rawInput: String, urls: List<String>): OfflineAssessment? {
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

    private fun startBackendOrchestratedPendingAssessment(rawInput: String, urls: List<String>): OfflineAssessment? {
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

    private fun publishAssessmentResult(existingScanId: String?, updated: OfflineAssessment) {
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

    private fun cachedAssessmentFor(cacheKey: String): OfflineAssessment? {
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

    private fun saveFinalAssessmentToResultCache(cacheKey: String, assessment: OfflineAssessment) {
        if (assessment.gateResult?.finality != GateFinality.FINAL) return
        val now = System.currentTimeMillis()
        resultCache[cacheKey] = CachedAssessmentRecord(
            cacheKey = cacheKey,
            assessment = assessment.copy(cacheStatus = null),
            cachedAtMillis = now,
            expiresAtMillis = now + RESULT_CACHE_TTL_MILLIS
        )
        trimResultCache()
        persistResultCache()
    }

    private fun trimResultCache() {
        if (resultCache.size <= MAX_RESULT_CACHE_ITEMS) return
        val keep = resultCache.values
            .sortedByDescending { it.cachedAtMillis }
            .take(MAX_RESULT_CACHE_ITEMS)
        resultCache.clear()
        keep.forEach { resultCache[it.cacheKey] = it }
    }

    private fun persistResultCache() {
        val now = System.currentTimeMillis()
        val snapshot = resultCache.values
            .filter { it.expiresAtMillis > now }
            .sortedByDescending { it.cachedAtMillis }
            .take(MAX_RESULT_CACHE_ITEMS)
        viewModelScope.launch(Dispatchers.IO) {
            prefs.edit().putString(RESULT_CACHE_PREF_KEY, gson.toJson(snapshot)).apply()
        }
    }

    private fun isSameNormalizedUrl(left: String?, right: String?): Boolean {
        val normalizedLeft = normalizeCandidateUrl(left) ?: left?.let(::normalizeUrl)
        val normalizedRight = normalizeCandidateUrl(right) ?: right?.let(::normalizeUrl)
        return !normalizedLeft.isNullOrBlank() && normalizedLeft == normalizedRight
    }

    private fun orchestratedRequest(
        rawInput: String,
        htmlPayload: String?,
        urls: List<String>,
        forcedInputType: String? = null
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
                sourceChannel = activeEvidenceChannel(rawInput) ?: "android_html_share"
            )
            urls.isNotEmpty() && looksLikeUrlOnly(rawInput.trim(), urls.first()) -> OrchestratedScanRequest(
                inputType = "url",
                url = normalizeUrl(urls.first()),
                sourceChannel = activeEvidenceChannel(rawInput) ?: "android_url_scan"
            )
            else -> OrchestratedScanRequest(
                inputType = "text",
                text = rawInput,
                sourceChannel = activeEvidenceChannel(rawInput) ?: "android_native"
            )
        }
    }

    private fun linksFromExtraction(response: ExtractionResponse, extractedText: String): List<String> {
        return (
            (response.extractedUrls ?: emptyList()) +
                extractUrls(extractedText) +
                extractHtmlLinks(extractedText) +
                response.htmlContent.orEmpty().let { html ->
                    if (html.isBlank()) emptyList() else extractHtmlLinks(html)
                }
            )
            .mapNotNull { normalizeCandidateUrl(it) ?: it.takeIf { candidate -> candidate.isNotBlank() } }
            .distinct()
    }

    private suspend fun runBackendOrchestratedScanFromExtraction(
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
        runBackendOrchestratedScan(assembledInput, htmlPayload, links, forcedInputType = forcedInputType)
    }

    private fun providerStatesFromOrchestratedPillars(
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

    private fun buildAssessmentFromBackendScanResponse(
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
        return result.withGate(
            snapshot = snapshot,
            gateResult = gateResult,
            rawInput = rawInput,
            mergedThreatIntel = threatIntel
        )
    }

    private fun buildPendingAssessmentFromOrchestratedResponse(
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
        return updated.withGate(
            snapshot = snapshot,
            gateResult = backendScanInProgressGateResult(),
            rawInput = rawInput,
            mergedThreatIntel = threatIntel
        )
    }

    private suspend fun publishOrchestratedResponse(
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

    private fun shouldCacheFinalAssessment(
        response: OrchestratedScanResponse,
        assessment: OfflineAssessment
    ): Boolean {
        if (assessment.gateResult?.finality != GateFinality.FINAL) return false
        if (orchestratedPreviewStillPending(response.preview)) return false
        return true
    }

    private suspend fun publishOrchestratedPollingTimeout(
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

    private suspend fun runBackendOrchestratedScan(
        rawInput: String,
        htmlPayload: String?,
        urls: List<String>,
        forcedInputType: String? = null
    ) {
        val cacheMaterial = if (forcedInputType.isNullOrBlank()) rawInput else "input_type=$forcedInputType\n$rawInput"
        val resultCacheKey = scanResultCacheKey(cacheMaterial, htmlPayload, urls)
        val preliminary = startBackendOrchestratedPendingAssessment(rawInput, urls)
        var response = scanStartApi.startOrchestratedScan(orchestratedRequest(rawInput, htmlPayload, urls, forcedInputType))
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

    private fun launchFinalOrchestratedPreviewRefresh(
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

    private fun buildDegradedAssessmentFromBackendScanResponse(
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
        return base.withGate(snapshot, backendGateResult(response), rawInput, threatIntel)
    }

    private fun classifyOrchestratedError(error: Throwable): String = when (error) {
        is HttpException -> "HTTP_${error.code()}"
        is SocketTimeoutException -> "TIMEOUT"
        is UnknownHostException -> "DNS"
        is SSLException -> "SSL"
        is IOException -> "IO"
        is IllegalStateException -> "STATE"
        is ClassCastException -> "CAST"
        else -> error.javaClass.simpleName.ifBlank { "UNKNOWN" }
    }

    fun onScanClick(forceRefresh: Boolean = false) {
        if (loading || text.isBlank()) return
        loading = true
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

    private fun isTrustedOfficialUrl(url: String): Boolean {
        val host = runCatching {
            Uri.parse(normalizeUrl(url)).host?.lowercase(Locale.ROOT).orEmpty()
        }.getOrDefault("")
        if (host.isBlank()) return false

        return BrandKnowledgeRegistry.isOfficialHost(host)
    }

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

	    private fun triggerSandboxAnalysis(url: String, scanId: String? = assessment?.scanId) {
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

    private fun scheduleSandboxScreenshotRefresh(scanId: String, screenshotUrl: String) {
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

    fun onQrPicked(uri: Uri, context: Context) {
        loading = true
        loadingMsg = "Scanăm codul QR..."
        
        try {
            val image = InputImage.fromFilePath(context, uri)
            barcodeScanner.process(image)
                .addOnSuccessListener { barcodes ->
                    val qrText = barcodes.firstOrNull()?.rawValue?.trim()
                    if (!qrText.isNullOrBlank()) {
                        text = qrText
                        stagedEvidenceHtml = null
                        stagedEvidenceLinks = extractUrls(qrText)
                        stagedEvidenceText = qrText
                        stagedEvidenceInputKind = "qr"
                        stagedEvidenceChannel = "qr_scan"
                        onScanClick()
                    } else {
                        publishQrExtractionIncomplete("Nu am găsit un cod QR lizibil în imagine.")
                    }
                }
                .addOnFailureListener {
                    publishQrExtractionIncomplete("Nu am putut citi codul QR din imagine. Reîncearcă cu o poză mai clară.")
                }
        } catch (e: Exception) {
            publishQrExtractionIncomplete("Nu am putut deschide imaginea pentru citirea codului QR.")
        }
    }

    private fun publishQrExtractionIncomplete(reason: String) {
        val result = applyEvidenceGate(
            current = OfflineAssessment(
                family = "Scanare QR incompletă",
                riskScore = 0,
                riskLevel = "unknown",
                reasons = listOf(reason),
                safeActions = listOf("Reîncearcă scanarea QR sau copiază manual linkul/textul afișat lângă cod."),
                keyDangers = listOf("Nu avem suficiente dovezi tehnice pentru verdict."),
                originalText = "Nu s-a extras conținut verificabil din codul QR."
            ),
            rawInput = "QR fără conținut verificabil",
            inputKind = "qr",
            channel = "qr_scan",
            providerStates = unavailableProviderStates(),
            completeness = EvidenceCompleteness.LOCAL_ONLY
        )
        publishAssessmentResult(null, result)
        loading = false
    }

    fun onImagePicked(uri: Uri, context: Context) {
        loading = true
        loadingMsg = "Citim imaginea pe device..."
        
        viewModelScope.launch {
            var file: File? = null
            try {
                val handledLocally = runCatching {
                    runLocalImageOcrScanIfPossible(uri, context)
                }.getOrDefault(false)
                if (handledLocally) return@launch

                loadingMsg = "OCR local neclar. Încercăm extragerea cloud..."
                if (!isUploadSizeAllowed(uri, context)) {
                    publishImageExtractionIncomplete(
                        fileName = getFileName(uri, context),
                        reason = "Imaginea este prea mare pentru scanarea cloud, iar OCR-ul local nu a extras text verificabil."
                    )
                } else {
                    file = uriToFile(uri, context, MAX_UPLOAD_BYTES)
                    val requestFile = file.asRequestBody("image/*".toMediaTypeOrNull())
                    val body = MultipartBody.Part.createFormData("image_file", file.name, requestFile)
                    val source = "android_image_upload".toRequestBody("text/plain".toMediaTypeOrNull())

                    val response = uploadApi.extractImage(body, source)
                    runBackendOrchestratedScanFromExtraction(
                        response = response,
                        fileName = file.name,
                        inputKind = "upload_image",
                        channel = "image_ocr"
                    )
                }
            } catch (e: Exception) {
                val reason = if (e is UploadSizeExceededException) {
                    "Imaginea este prea mare pentru scanarea cloud, iar OCR-ul local nu a extras text verificabil."
                } else {
                    "Nu am putut extrage text verificabil din imagine. Reîncearcă cu o captură mai clară."
                }
                publishImageExtractionIncomplete(
                    fileName = getFileName(uri, context),
                    reason = reason
                )
            } finally {
                file?.delete()
                loading = false
            }
        }
    }

    private suspend fun runLocalImageOcrScanIfPossible(uri: Uri, context: Context): Boolean {
        val image = InputImage.fromFilePath(context, uri)
        val extractedText = runCatching { extractTextFromImage(image) }.getOrNull().orEmpty().trim()
        if (extractedText.isBlank()) return false

        val extractedLinks = (extractUrls(extractedText) + extractHtmlLinks(extractedText))
            .mapNotNull { normalizeCandidateUrl(it) ?: it.takeIf { candidate -> candidate.isNotBlank() } }
            .distinct()
        val assembledInput = MailShareInputAssembler.buildMailScanInput(
            extractedText,
            extractedLinks,
            getFileName(uri, context)
        )
        text = assembledInput
        stagedEvidenceHtml = null
        stagedEvidenceLinks = extractedLinks
        stagedEvidenceText = assembledInput
        stagedEvidenceInputKind = "upload_image"
        stagedEvidenceChannel = "image_ocr"
        runBackendOrchestratedScan(assembledInput, null, extractedLinks)
        return true
    }

    private fun publishImageExtractionIncomplete(fileName: String, reason: String) {
        val result = applyEvidenceGate(
            current = OfflineAssessment(
                family = "Scanare incompletă",
                riskScore = 0,
                riskLevel = "unknown",
                reasons = listOf(reason),
                safeActions = listOf("Reîncearcă scanarea cu o imagine mai clară sau copiază textul/linkul în câmpul de scanare."),
                keyDangers = listOf("Nu avem suficiente dovezi tehnice pentru verdict."),
                originalText = "Nu s-a extras conținut verificabil din $fileName."
            ),
            rawInput = "Imagine fără text OCR verificabil: $fileName",
            inputKind = "upload_image",
            channel = "image_ocr",
            providerStates = unavailableProviderStates(),
            completeness = EvidenceCompleteness.LOCAL_ONLY
        )
        publishAssessmentResult(null, result)
    }

    fun scanInvoiceFromDocument(
        uri: Uri,
        context: Context,
        officialXmlUri: Uri? = null,
        sanbAttestation: String? = null
    ) {
        loading = true
        loadingMsg = when {
            sanbAttestation != null -> "Actualizăm verdictul după verificarea beneficiarului..."
            officialXmlUri != null -> "Comparăm factura cu XML-ul e-Factura..."
            else -> "Scanăm factura prin OCR..."
        }
        invoiceSanbStatus = null
        if (sanbAttestation == null) {
            invoiceResult = null
        }
        lastInvoiceScanSource = PendingInvoiceScanSource(uri = uri, officialXmlUri = officialXmlUri)

        viewModelScope.launch {
            var file: File? = null
            var officialXmlFile: File? = null
            try {
                val fileName = getFileName(uri, context)
                val mimeType = context.contentResolver.getType(uri).orEmpty().lowercase(Locale.ROOT)
                val isPdf = mimeType.contains("pdf") || fileName.lowercase(Locale.ROOT).endsWith(".pdf")
                val isImage = mimeType.startsWith("image/") || fileName.lowercase(Locale.ROOT).matches(
                    Regex(""".*\.(jpg|jpeg|png|webp)$""")
                )
                if (!isPdf && !isImage) {
                    invoiceResult = InvoiceScanResponse(
                        error = "Alege o factură în format imagine sau PDF."
                    )
                    return@launch
                }

                loadingMsg = if (isPdf) "Scanăm factura PDF..." else "Optimizăm poza facturii..."
                file = if (isPdf) uriToFile(uri, context, MAX_UPLOAD_BYTES) else prepareInvoiceImageUpload(uri, context)
                val mediaType = if (isPdf) "application/pdf" else "image/jpeg"
                val partName = if (isPdf) "pdf_file" else "image_file"
                val requestFile = file.asRequestBody(mediaType.toMediaTypeOrNull())
                val body = MultipartBody.Part.createFormData(partName, fileName, requestFile)
                val source = "android_native".toRequestBody("text/plain".toMediaTypeOrNull())
                val sanbPart = sanbAttestation?.let {
                    it.toRequestBody("text/plain".toMediaTypeOrNull())
                }
                val officialPart = officialXmlUri?.let { xmlUri ->
                    val xmlFileName = getFileName(xmlUri, context)
                    val xmlMimeType = context.contentResolver.getType(xmlUri).orEmpty().lowercase(Locale.ROOT)
                    val isXml = xmlMimeType.contains("xml") || xmlFileName.lowercase(Locale.ROOT).endsWith(".xml")
                    if (!isXml) {
                        invoiceResult = InvoiceScanResponse(
                            error = "Alege XML-ul oficial e-Factura în format .xml."
                        )
                        return@launch
                    }
                    val xmlFile = uriToFile(xmlUri, context, MAX_UPLOAD_BYTES)
                    officialXmlFile = xmlFile
                    val xmlRequest = xmlFile.asRequestBody(
                        (xmlMimeType.ifBlank { "application/xml" }).toMediaTypeOrNull()
                    )
                    MultipartBody.Part.createFormData("official_xml_file", xmlFileName, xmlRequest)
                }

                invoiceResult = uploadApi.scanInvoice(body, source, officialPart, sanbPart)
                invoiceSanbStatus = when (sanbAttestation) {
                    "match", "close_match" -> "Ai confirmat în bancă faptul că beneficiarul se potrivește."
                    "no_match" -> "Ai confirmat în bancă faptul că beneficiarul nu se potrivește."
                    "not_shown" -> "Banca nu a afișat numele beneficiarului; verifică furnizorul pe canal oficial."
                    else -> null
                }
            } catch (e: Exception) {
                invoiceResult = InvoiceScanResponse(
                    error = "Eroare la scanarea facturii: ${e.localizedMessage ?: "conexiune eșuată"}"
                )
            } finally {
                file?.delete()
                officialXmlFile?.delete()
                loading = false
                loadingMsg = ""
            }
        }
    }

    fun submitInvoiceBeneficiaryAttestation(attestation: String, context: Context) {
        val normalized = when (attestation.trim().lowercase(Locale.ROOT)) {
            "match", "close_match", "no_match", "not_shown" -> attestation.trim().lowercase(Locale.ROOT)
            else -> return
        }
        val source = lastInvoiceScanSource
        if (source == null) {
            invoiceSanbStatus = "Nu mai avem documentul în sesiune. Reîncarcă factura și repetă verificarea."
            return
        }
        scanInvoiceFromDocument(
            uri = source.uri,
            context = context,
            officialXmlUri = source.officialXmlUri,
            sanbAttestation = normalized
        )
    }

    fun scanOfferFromDocument(uri: Uri, context: Context) {
        loading = true
        loadingMsg = "Pregătim verificarea ofertei..."
        invoiceResult = null
        assessment = null

        viewModelScope.launch {
            var file: File? = null
            try {
                val fileName = getFileName(uri, context)
                val mimeType = context.contentResolver.getType(uri).orEmpty().lowercase(Locale.ROOT)
                val lowerName = fileName.lowercase(Locale.ROOT)
                val isPdf = mimeType.contains("pdf") || lowerName.endsWith(".pdf")
                val isImage = mimeType.startsWith("image/") || lowerName.matches(
                    Regex(""".*\.(jpg|jpeg|png|webp)$""")
                )
                val importKind = FileImportClassifier.classify(fileName, mimeType)

                if (isImage) {
                    loadingMsg = "Citim oferta din imagine..."
                    val extractedText = runCatching {
                        extractTextFromImage(InputImage.fromFilePath(context, uri))
                    }.getOrNull().orEmpty().trim()

                    if (extractedText.isNotBlank()) {
                        stageOfferConfirmationFromExtractedText(
                            extractedText = extractedText,
                            links = emptyList(),
                            fileName = fileName,
                            inputKind = "offer_image",
                            channel = "offer_image_ocr"
                        )
                        return@launch
                    }

                    if (!isUploadSizeAllowed(uri, context)) {
                        publishOfferExtractionIncomplete(
                            fileName = fileName,
                            reason = "Imaginea este prea mare, iar OCR-ul local nu a extras text verificabil."
                        )
                        return@launch
                    }

                    loadingMsg = "OCR local neclar. Încercăm extragerea cloud..."
                    file = uriToFile(uri, context, MAX_UPLOAD_BYTES)
                    val requestFile = file.asRequestBody("image/*".toMediaTypeOrNull())
                    val body = MultipartBody.Part.createFormData("image_file", file.name, requestFile)
                    val source = "android_offer_image_upload".toRequestBody("text/plain".toMediaTypeOrNull())
                    val response = uploadApi.extractImage(body, source)
                    stageOfferConfirmationFromExtraction(
                        response = response,
                        fileName = fileName,
                        inputKind = "offer_image",
                        channel = "offer_image_ocr"
                    )
                    return@launch
                }

                if (isPdf) {
                    if (!isUploadSizeAllowed(uri, context)) {
                        publishOfferExtractionIncomplete(
                            fileName = fileName,
                            reason = "PDF-ul depășește limita de scanare cloud."
                        )
                        return@launch
                    }

                    loadingMsg = "Citim oferta din PDF..."
                    file = uriToFile(uri, context, MAX_UPLOAD_BYTES)
                    val requestFile = file.asRequestBody("application/pdf".toMediaTypeOrNull())
                    val body = MultipartBody.Part.createFormData("pdf_file", file.name, requestFile)
                    val source = "android_offer_pdf_upload".toRequestBody("text/plain".toMediaTypeOrNull())
                    val response = runCatching { uploadApi.extractPdf(body, source) }.getOrElse {
                        loadingMsg = "Extragem local textul din PDF..."
                        val fallback = runCatching { extractTextFromPdfFallback(uri, context) }.getOrNull()
                            ?: PdfFallbackExtraction("", emptySet())
                        if (fallback.extractedText.isBlank() && fallback.extractedLinks.isEmpty()) throw it
                        ExtractionResponse(
                            redactedText = fallback.extractedText,
                            extractedUrls = fallback.extractedLinks.toList()
                        )
                    }
                    stageOfferConfirmationFromExtraction(
                        response = response,
                        fileName = fileName,
                        inputKind = "offer_pdf",
                        channel = "offer_pdf_ocr"
                    )
                    return@launch
                }

                if (importKind == FileImportKind.TEXT || importKind == FileImportKind.HTML || importKind == FileImportKind.EMAIL) {
                    loadingMsg = "Citim textul ofertei..."
                    val rawContent = readTextFromUri(uri, context)
                    val parsedEmail = if (importKind == FileImportKind.EMAIL) EmailMessageParser.parse(rawContent) else null
                    val htmlContent = when (importKind) {
                        FileImportKind.EMAIL -> parsedEmail?.htmlText?.takeIf { it.isNotBlank() }
                        FileImportKind.HTML -> rawContent
                        else -> null
                    }
                    val visibleText = when (importKind) {
                        FileImportKind.EMAIL -> parsedEmail?.bodyForAnalysis?.ifBlank { rawContent } ?: rawContent
                        else -> rawContent
                    }
                    val links = (
                        extractUrls(rawContent) +
                            extractHtmlLinks(rawContent) +
                            htmlContent.orEmpty().let { html -> if (html.isBlank()) emptyList() else extractHtmlLinks(html) }
                        ).distinct()
                    stageOfferConfirmationFromExtractedText(
                        extractedText = sanitizeSharedText(visibleText),
                        links = links,
                        fileName = fileName,
                        inputKind = "offer_file",
                        channel = "offer_file_import",
                        htmlPayload = htmlContent
                    )
                    return@launch
                }

                publishOfferExtractionIncomplete(
                    fileName = fileName,
                    reason = "Alege o ofertă în format imagine, PDF, HTML, EML sau TXT."
                )
            } catch (e: Exception) {
                publishOfferExtractionIncomplete(
                    fileName = getFileName(uri, context),
                    reason = "Nu am putut citi oferta: ${e.localizedMessage ?: "conexiune eșuată"}"
                )
            } finally {
                file?.delete()
                loading = false
                loadingMsg = ""
            }
        }
    }

    private suspend fun runOfferScanFromExtractedText(
        extractedText: String,
        links: List<String>,
        fileName: String,
        inputKind: String,
        channel: String,
        htmlPayload: String? = null
    ) {
        val normalizedLinks = (
            links +
                extractUrls(extractedText) +
                extractHtmlLinks(extractedText) +
                htmlPayload.orEmpty().let { html -> if (html.isBlank()) emptyList() else extractHtmlLinks(html) }
            )
            .mapNotNull { normalizeCandidateUrl(it) ?: it.takeIf { candidate -> candidate.isNotBlank() } }
            .distinct()
        val assembledInput = MailShareInputAssembler.buildMailScanInput(
            extractedText.ifBlank { "Conținut ofertă extras din $fileName." },
            normalizedLinks,
            fileName
        )
        text = assembledInput
        stagedEvidenceHtml = htmlPayload
        stagedEvidenceLinks = normalizedLinks
        stagedEvidenceText = assembledInput
        stagedEvidenceInputKind = inputKind
        stagedEvidenceChannel = channel
        runBackendOrchestratedScan(assembledInput, htmlPayload, normalizedLinks, forcedInputType = "offer")
    }

    private fun stageOfferConfirmationFromExtraction(
        response: ExtractionResponse,
        fileName: String,
        inputKind: String,
        channel: String
    ) {
        val extractedText = response.redactedText.orEmpty().trim()
        val htmlPayload = response.htmlContent?.takeIf { it.isNotBlank() }
        val links = linksFromExtraction(response, extractedText)
        if (extractedText.isBlank() && links.isEmpty()) {
            publishOfferExtractionIncomplete(
                fileName = fileName,
                reason = response.warning ?: "Nu am putut extrage text sau linkuri verificabile din ofertă."
            )
            return
        }
        stageOfferConfirmationFromExtractedText(
            extractedText = extractedText.ifBlank { "Conținut extras din $fileName." },
            links = links,
            fileName = fileName,
            inputKind = inputKind,
            channel = channel,
            htmlPayload = htmlPayload
        )
    }

    private fun stageOfferConfirmationFromExtractedText(
        extractedText: String,
        links: List<String>,
        fileName: String,
        inputKind: String,
        channel: String,
        htmlPayload: String? = null
    ) {
        val normalizedLinks = normalizeOfferLinks(extractedText, links, htmlPayload)
        val fields = inferOfferConfirmationFields(extractedText)
        pendingOfferConfirmation = PendingOfferConfirmation(
            extractedText = extractedText,
            links = normalizedLinks,
            fileName = fileName,
            inputKind = inputKind,
            channel = channel,
            htmlPayload = htmlPayload,
            fields = fields
        )
        text = buildConfirmedOfferInput(extractedText, normalizedLinks, fields, fileName)
        stagedEvidenceHtml = htmlPayload
        stagedEvidenceLinks = normalizedLinks
        stagedEvidenceText = text
        stagedEvidenceInputKind = inputKind
        stagedEvidenceChannel = channel
        assessment = null
        invoiceResult = null
        loading = false
        loadingMsg = ""
    }

    fun cancelOfferConfirmation() {
        pendingOfferConfirmation = null
        loading = false
        loadingMsg = ""
    }

    fun confirmOfferAndScan(fields: OfferConfirmationFields) {
        val draft = pendingOfferConfirmation ?: return
        pendingOfferConfirmation = null
        invoiceResult = null
        assessment = null
        loading = true
        loadingMsg = "Verificăm oferta confirmată..."

        viewModelScope.launch {
            try {
                val normalizedLinks = normalizeOfferLinks(draft.extractedText, draft.links, draft.htmlPayload)
                val confirmedInput = buildConfirmedOfferInput(draft.extractedText, normalizedLinks, fields, draft.fileName)
                text = confirmedInput
                stagedEvidenceHtml = draft.htmlPayload
                stagedEvidenceLinks = normalizedLinks
                stagedEvidenceText = confirmedInput
                stagedEvidenceInputKind = draft.inputKind
                stagedEvidenceChannel = draft.channel
                runBackendOrchestratedScan(confirmedInput, draft.htmlPayload, normalizedLinks, forcedInputType = "offer")
            } catch (e: Exception) {
                publishOfferExtractionIncomplete(
                    fileName = draft.fileName,
                    reason = "Nu am putut trimite oferta la verificare: ${e.localizedMessage ?: "conexiune eșuată"}"
                )
            } finally {
                loading = false
                loadingMsg = ""
            }
        }
    }

    private fun normalizeOfferLinks(
        extractedText: String,
        links: List<String>,
        htmlPayload: String?
    ): List<String> {
        return (
            links +
                extractUrls(extractedText) +
                extractHtmlLinks(extractedText) +
                htmlPayload.orEmpty().let { html -> if (html.isBlank()) emptyList() else extractHtmlLinks(html) }
            )
            .mapNotNull { normalizeCandidateUrl(it) ?: it.takeIf { candidate -> candidate.isNotBlank() } }
            .distinct()
    }

    private fun inferOfferConfirmationFields(rawText: String): OfferConfirmationFields {
        val text = Html.fromHtml(rawText, Html.FROM_HTML_MODE_LEGACY).toString()
        val lines = text.lines().map { it.trim() }.filter { it.isNotBlank() }
        val issuerName = firstRegexGroup(
            text,
            Regex("""(?im)^\s*(?:emitent|furnizor|v[âa]nz[ăa]tor|companie|societate)\s*[:\-]\s*(.+)$""")
        ) ?: lines.firstOrNull { line ->
            !line.contains("iban", ignoreCase = true) &&
                !line.contains("cui", ignoreCase = true) &&
                !line.contains("total", ignoreCase = true) &&
                !line.contains("factur", ignoreCase = true) &&
                line.length in 3..80
        }.orEmpty()

        val cui = firstRegexGroup(
            text,
            Regex("""(?i)\b(?:CUI|CIF|Cod\s+fiscal|RO)\s*[:#\-]?\s*(?:RO)?\s*(\d{2,10})\b""")
        ).orEmpty()
        val iban = firstRegexGroup(
            text.replace(" ", ""),
            Regex("""(?i)\b(RO\d{2}[A-Z]{4}[A-Z0-9]{16})\b""")
        ).orEmpty().uppercase(Locale.US)
        val beneficiary = firstRegexGroup(
            text,
            Regex("""(?im)^\s*(?:beneficiar|titular|pl[ăa]te[șs]te\s+c[ăa]tre|plata\s+c[ăa]tre)\s*[:\-]\s*(.+)$""")
        ).orEmpty()
        val amountMatch = Regex(
            """(?i)\b(?:total|valoare|sum[ăa]|pre[țt]|avans)\b[^\d]{0,40}(\d{1,3}(?:[.\s]\d{3})*(?:[,.]\d{2})?|\d+(?:[,.]\d{2})?)\s*(RON|LEI|EUR|EURO|USD)?"""
        ).find(text)
        val amount = amountMatch?.groupValues?.getOrNull(1).orEmpty()
        val currency = amountMatch?.groupValues?.getOrNull(2)
            ?.takeIf { it.isNotBlank() }
            ?.uppercase(Locale.US)
            ?.let { if (it == "LEI") "RON" else it }
            ?: when {
                Regex("""(?i)\bEUR|EURO\b""").containsMatchIn(text) -> "EUR"
                Regex("""(?i)\bUSD\b""").containsMatchIn(text) -> "USD"
                else -> "RON"
            }
        val documentNumber = firstRegexGroup(
            text,
            Regex("""(?i)\b(?:nr\.?|num[ăa]r|ofert[ăa]|factur[ăa]|contract)\s*[:#\-]?\s*([A-Z0-9][A-Z0-9./\-]{2,})""")
        ).orEmpty()
        val documentDate = firstRegexGroup(
            text,
            Regex("""\b(\d{1,2}[./-]\d{1,2}[./-]\d{2,4})\b""")
        ).orEmpty()

        return OfferConfirmationFields(
            issuerName = issuerName.take(120),
            issuerCui = cui,
            iban = iban,
            paymentBeneficiary = beneficiary.take(120),
            totalAmount = amount,
            currency = currency,
            documentNumber = documentNumber,
            documentDate = documentDate
        )
    }

    private fun firstRegexGroup(text: String, regex: Regex): String? {
        return regex.find(text)?.groupValues?.getOrNull(1)?.trim()?.takeIf { it.isNotBlank() }
    }

    private fun buildConfirmedOfferInput(
        extractedText: String,
        links: List<String>,
        fields: OfferConfirmationFields,
        fileName: String
    ): String {
        val confirmed = listOfNotNull(
            fields.issuerName.takeIf { it.isNotBlank() }?.let { "Emitent confirmat: $it" },
            fields.issuerCui.takeIf { it.isNotBlank() }?.let { "CUI confirmat: $it" },
            fields.iban.takeIf { it.isNotBlank() }?.let { "IBAN confirmat: $it" },
            fields.paymentBeneficiary.takeIf { it.isNotBlank() }?.let { "Beneficiar plată confirmat: $it" },
            fields.totalAmount.takeIf { it.isNotBlank() }?.let { "Total confirmat: $it ${fields.currency.ifBlank { "RON" }}" },
            fields.documentNumber.takeIf { it.isNotBlank() }?.let { "Număr document confirmat: $it" },
            fields.documentDate.takeIf { it.isNotBlank() }?.let { "Dată document confirmată: $it" }
        )
        val analysisText = buildString {
            appendLine("Tip scanare: ofertă / plată.")
            appendLine("Fișier sursă: $fileName.")
            if (confirmed.isNotEmpty()) {
                appendLine("Câmpuri confirmate de utilizator:")
                confirmed.forEach { appendLine("- $it") }
            } else {
                appendLine("Utilizatorul nu a confirmat câmpuri structurate; analizează doar textul extras.")
            }
            appendLine()
            appendLine("Text extras din document/mesaj:")
            appendLine(extractedText)
        }
        return MailShareInputAssembler.buildMailScanInput(analysisText, links, fileName)
    }

    private fun publishOfferExtractionIncomplete(fileName: String, reason: String) {
        val result = applyEvidenceGate(
            current = OfflineAssessment(
                family = "Ofertă neverificată",
                riskScore = 0,
                riskLevel = "unknown",
                reasons = listOf(reason),
                safeActions = listOf("Reîncearcă cu o poză mai clară, un PDF cu text sau copiază oferta în câmpul de scanare."),
                keyDangers = listOf("Nu avem suficiente dovezi tehnice pentru verdict."),
                originalText = "Nu s-a extras conținut verificabil din $fileName."
            ),
            rawInput = "Ofertă fără conținut verificabil: $fileName",
            inputKind = "offer_upload",
            channel = "offer_file_import",
            providerStates = unavailableProviderStates(),
            completeness = EvidenceCompleteness.LOCAL_ONLY
        )
        publishAssessmentResult(null, result)
    }

    private suspend fun extractTextFromBitmap(bitmap: Bitmap): String = extractTextFromImage(InputImage.fromBitmap(bitmap, 0))

    private suspend fun extractTextFromImage(image: InputImage): String = suspendCoroutine { continuation ->
        recognizer.process(image)
            .addOnSuccessListener { result ->
                continuation.resume(result.text)
            }
            .addOnFailureListener { continuation.resumeWithException(it) }
    }

    private suspend fun extractTextFromPdfFallback(uri: Uri, context: Context): PdfFallbackExtraction = withContext(Dispatchers.IO) {
        val annotationLinks = runCatching {
            context.contentResolver.openInputStream(uri)?.use { input ->
                PdfLinkExtractor.extractPdfAnnotationLinks(input.readBytes())
            } ?: emptySet()
        }.getOrNull() ?: emptySet()
        val descriptor: ParcelFileDescriptor = context.contentResolver.openFileDescriptor(uri, "r")
            ?: return@withContext PdfFallbackExtraction(
                extractedText = "",
                extractedLinks = annotationLinks
            )

        descriptor.use { pfd ->
            val renderer = PdfRenderer(pfd)
            val extractedText = StringBuilder()

            try {
                val maxPages = renderer.pageCount.coerceAtMost(6)
                for (pageIndex in 0 until maxPages) {
                    val page = renderer.openPage(pageIndex)
                    try {
                        val scale = 2.2f
                        val width = (page.width * scale).roundToInt().coerceAtLeast(1)
                        val height = (page.height * scale).roundToInt().coerceAtLeast(1)
                        val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)
                        page.render(bitmap, null, null, PdfRenderer.Page.RENDER_MODE_FOR_DISPLAY)

                        val pageText = runCatching { extractTextFromBitmap(bitmap) }.getOrNull().orEmpty()
                        if (pageText.isNotBlank()) {
                            if (extractedText.isNotEmpty()) extractedText.append('\n')
                            extractedText.append(pageText)
                        }
                        bitmap.recycle()
                    } finally {
                        page.close()
                    }
                }
            } finally {
                renderer.close()
            }

            val textFromOcr = extractedText.toString().trim()
            val extractedLinks = linkedSetOf<String>()
            extractedLinks += annotationLinks
                .mapNotNull { normalizeCandidateUrl(it) ?: if (it.startsWith("www.", ignoreCase = true)) normalizeUrl(it) else null }
            extractedLinks += extractUrls(textFromOcr).mapNotNull { normalizeCandidateUrl(it) }
            extractedLinks += extractHtmlLinks(textFromOcr).mapNotNull { normalizeCandidateUrl(it) }

            return@withContext PdfFallbackExtraction(
                extractedText = textFromOcr,
                extractedLinks = extractedLinks
            )
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

    private fun getFileName(uri: Uri, context: Context): String {
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

    private fun sanitizeSharedText(content: String): String {
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

    private fun buildNeutralPendingAssessment(scannedText: String): OfflineAssessment {
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

    private fun looksLikeUrlOnly(input: String, firstUrl: String): Boolean {
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

    private fun addToHistory(item: OfflineAssessment) {
        historyItems.add(0, item)
        calculateStats()
        saveHistory()
    }

    fun deleteHistoryItem(item: OfflineAssessment) {
        historyItems.remove(item)
        saveHistory()
    }

    fun clearHistory() {
        historyItems.clear()
        saveHistory()
    }

    private fun saveHistory() {
        val snapshot = historyItems.toList().take(50)
        viewModelScope.launch(Dispatchers.IO) {
            val json = gson.toJson(snapshot)
            prefs.edit().putString("history", json).apply()
        }
    }

    private fun loadHistory() {
        val json = prefs.getString("history", null)
        if (json != null) {
            val type = object : TypeToken<List<OfflineAssessment>>() {}.type
            val items: List<OfflineAssessment> = gson.fromJson(json, type)
            historyItems.clear()
            historyItems.addAll(items)
        }
    }

    override fun onCleared() {
        speakerGuardSession?.stop()
        speakerGuardSession = null
        super.onCleared()
    }
}
