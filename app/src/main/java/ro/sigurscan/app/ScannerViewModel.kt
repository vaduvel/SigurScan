package ro.sigurscan.app

import android.app.Application
import android.content.Context
import android.graphics.Bitmap
import android.net.Uri
import android.graphics.pdf.PdfRenderer
import android.os.ParcelFileDescriptor
import android.provider.OpenableColumns
import android.content.SharedPreferences
import android.text.Html
import android.util.Base64
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
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
import java.io.FileOutputStream
import java.net.URLDecoder
import java.security.MessageDigest
import java.nio.charset.StandardCharsets
import java.util.*
import java.util.concurrent.TimeUnit
import java.util.regex.Pattern
import kotlin.math.roundToInt
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.coroutines.suspendCoroutine

@Serializable
data class ScamEvent(
    val scan_id: String,
    val input_type: String,
    val risk_score: Int,
    val risk_level: String,
    val detected_family: String? = null,
    val claimed_brand: String? = null,
    val urls: kotlinx.serialization.json.JsonElement? = null,
    val lat: Double? = null,
    val lon: Double? = null
)

data class ThreatIntelSourceResult(
    val source: String,
    val verdict: String,
    val severity: String = "unknown",
    val details: String? = null
)

data class OfflineAssessment(
    val scanId: String = UUID.randomUUID().toString(),
    val family: String,
    val riskScore: Int,
    val riskLevel: String,
    val reasons: List<String>,
    val safeActions: List<String>,
    val keyDangers: List<String>,
    val timestamp: Long = System.currentTimeMillis(),
    val originalText: String = "",
    val screenshotUrl: String? = null,
    val serverInfo: String? = null,
    val redirectChain: List<String> = emptyList(),
    val finalUrl: String? = null,
    val offerAnalysis: String? = null,
    // Cei 4 piloni de sinceritate
    val reputationVerdict: String = "Neverificat",
    val domainAgeText: String = "Necunoscută",
    val sslStatus: String = "Neverificat",
    val aiConfidence: String = "Analiză în curs",
    val detectedButtons: List<String> = emptyList(),
    val emailAuth: String? = null,
    val threatIntel: List<ThreatIntelSourceResult> = emptyList(),
    val sandboxReportUrl: String? = null,
    val evidenceSnapshot: EvidenceSnapshot? = null,
    val gateResult: GateResult? = null,
    val inputFidelity: SharedContentFidelity? = null
)

internal fun urlscanScreenshotUrl(uuid: String): String = "https://urlscan.io/screenshots/$uuid.png"

internal fun urlscanReportUrl(uuid: String): String = "https://urlscan.io/result/$uuid/"

internal const val ORCHESTRATED_POLLING_BUDGET_MILLIS = 180_000L

internal fun orchestratedPollDelayMillis(response: OrchestratedScanResponse): Long {
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

data class PendingSharedFile(
    val id: String = UUID.randomUUID().toString(),
    val uri: Uri,
    val fileName: String,
    val mimeType: String,
    val sourceLabel: String
)

data class FamilyMember(
    val id: String = UUID.randomUUID().toString(),
    val name: String,
    val contact: String,
    val isProtected: Boolean = true,
    val createdAt: Long = System.currentTimeMillis()
)

data class FamilyAlert(
    val id: String = UUID.randomUUID().toString(),
    val memberId: String,
    val memberName: String,
    val triggerLabel: String,
    val family: String,
    val riskLevel: String,
    val snapshot: String,
    val timestamp: Long = System.currentTimeMillis()
)

class ScannerViewModel(application: Application) : AndroidViewModel(application) {
    private data class PdfFallbackExtraction(
        val extractedText: String,
        val extractedLinks: Set<String> = emptySet()
    )
    private data class CachedThreatIntelResult(
        val result: ThreatIntelSourceResult,
        val expiresAtMillis: Long
    )
    private data class PersistedStartupState(
        val history: List<OfflineAssessment> = emptyList(),
        val triageProgress: Map<String, Set<Int>> = emptyMap(),
        val completedLessons: Set<String> = emptySet(),
        val familyMembers: List<FamilyMember> = emptyList(),
        val familyAlerts: List<FamilyAlert> = emptyList()
    )

    private companion object {
        private const val MAX_UPLOAD_BYTES = 25L * 1024L * 1024L
        private const val TMP_UPLOAD_PREFIX = "temp_upload_"
        private const val WEB_RISK_NO_THREAT_CACHE_MS = 10L * 60L * 1000L
        private const val WEB_RISK_THREAT_FALLBACK_CACHE_MS = 5L * 60L * 1000L
        private const val URLSCAN_PERSONA_COUNTRY = "ro"
        private const val URLSCAN_MOBILE_ANDROID_AGENT =
            "Mozilla/5.0 (Linux; Android 15; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36"
    }

    var text by mutableStateOf("")
    var loading by mutableStateOf(false)
    var loadingMsg by mutableStateOf("")
    var assessment by mutableStateOf<OfflineAssessment?>(null)
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
    
    private val prefs: SharedPreferences by lazy { createSecurePrefs(application) }
    private val gson = Gson()
    private val recognizer by lazy { TextRecognition.getClient(TextRecognizerOptions.DEFAULT_OPTIONS) }
    private val barcodeScanner by lazy { BarcodeScanning.getClient() }
    private val URLSCAN_API_KEY = BuildConfig.URLSCAN_API_KEY
    private val VIRUS_TOTAL_API_KEY = BuildConfig.VIRUS_TOTAL_API_KEY
    private val GOOGLE_WEB_RISK_API_KEY = BuildConfig.GOOGLE_WEB_RISK_API_KEY
    private val threatIntelClient = OkHttpClient.Builder()
        .callTimeout(12, TimeUnit.SECONDS)
        .readTimeout(12, TimeUnit.SECONDS)
        .connectTimeout(12, TimeUnit.SECONDS)
        .addInterceptor(HttpLoggingInterceptor().apply {
            level = HttpLoggingInterceptor.Level.NONE
        })
        .build()
    private val webRiskCache = Collections.synchronizedMap(mutableMapOf<String, CachedThreatIntelResult>())
    private val evidenceGate = EvidenceGate()
    private var stagedEvidenceHtml: String? = null
    private var stagedEvidenceLinks: List<String> = emptyList()
    private var stagedEvidenceText: String? = null
    private var stagedEvidenceInputKind: String? = null
    private var stagedEvidenceChannel: String? = null

    private val api: SigurScanApi by lazy {
        val logging = HttpLoggingInterceptor().apply {
            level = HttpLoggingInterceptor.Level.NONE
        }
	        val client = OkHttpClient.Builder()
	            .callTimeout(75, TimeUnit.SECONDS)
	            .readTimeout(75, TimeUnit.SECONDS)
	            .writeTimeout(30, TimeUnit.SECONDS)
	            .connectTimeout(20, TimeUnit.SECONDS)
	            .addInterceptor(logging)
	            .build()

        val backendBaseUrl = configuredBackendBaseUrl()

        Retrofit.Builder()
            .baseUrl(backendBaseUrl)
            .client(client)
            .addConverterFactory(GsonConverterFactory.create())
            .build()
            .create(SigurScanApi::class.java)
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
            }
        }
    }

    private fun loadPersistedStartupState(): PersistedStartupState {
        return PersistedStartupState(
            history = runCatching {
                val raw = prefs.getString("history", null) ?: return@runCatching emptyList()
                val type = object : TypeToken<List<OfflineAssessment>>() {}.type
                gson.fromJson<List<OfflineAssessment>>(raw, type)
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
        triageStepProgress = state.triageProgress
        completedLessons = state.completedLessons
        familyMembers.clear()
        familyMembers.addAll(state.familyMembers)
        familyAlerts.clear()
        familyAlerts.addAll(state.familyAlerts)
        refreshFamilyResilienceScore()
        calculateStats()
    }

    fun loadCampaigns() {
        campaignsLoading = true
        viewModelScope.launch {
            try {
                val list = api.getCampaigns()
                campaigns.clear()
                campaigns.addAll(list)
            } catch (_: Exception) {
                campaigns.clear()
            } finally {
                campaignsLoading = false
            }
        }
    }

    fun clearLiveCampaignEvent() {
        liveCampaignEvent = null
    }

    private fun loadTriageState() {
        val json = prefs.getString("triage_steps_state", null)
        if (json == null) return

        val type = object : TypeToken<Map<String, List<Int>>>() {}.type
        val values: Map<String, List<Int>> = gson.fromJson(json, type)
        triageStepProgress = values.mapValues { it.value.toSet() }
    }

    private fun saveTriageState() {
        val serializable = triageStepProgress.mapValues { it.value.toList() }
        val type = object : TypeToken<Map<String, List<Int>>>() {}.type
        prefs.edit().putString("triage_steps_state", gson.toJson(serializable, type)).apply()
    }

    fun isTriageStepDone(category: String, index: Int): Boolean {
        return triageStepProgress[category]?.contains(index) == true
    }

    fun setTriageStep(category: String, index: Int, done: Boolean) {
        val current = triageStepProgress[category]?.toMutableSet() ?: mutableSetOf()
        if (done) current.add(index) else current.remove(index)
        triageStepProgress = triageStepProgress.toMutableMap().apply { this[category] = current }
        saveTriageState()
    }

    private fun loadEducationState() {
        val raw = prefs.getString("education_lessons_done", null)
        if (raw == null) return
        val type = object : TypeToken<Set<String>>() {}.type
        completedLessons = gson.fromJson(raw, type)
    }

    private fun saveEducationState() {
        val type = object : TypeToken<Set<String>>() {}.type
        prefs.edit().putString("education_lessons_done", gson.toJson(completedLessons, type)).apply()
    }

    fun setLessonCompleted(lessonId: String, completed: Boolean = true) {
        completedLessons = if (completed) {
            completedLessons + lessonId
        } else {
            completedLessons - lessonId
        }
        saveEducationState()
    }

    private fun loadFamilyState() {
        val rawMembers = prefs.getString("family_members_state", null)
        if (rawMembers != null) {
            val memberType = object : TypeToken<List<FamilyMember>>() {}.type
            runCatching {
                val members: List<FamilyMember> = gson.fromJson(rawMembers, memberType)
                familyMembers.clear()
                familyMembers.addAll(members)
            }
        }

        val rawAlerts = prefs.getString("family_alerts_state", null)
        if (rawAlerts != null) {
            val alertType = object : TypeToken<List<FamilyAlert>>() {}.type
            runCatching {
                val alerts: List<FamilyAlert> = gson.fromJson(rawAlerts, alertType)
                familyAlerts.clear()
                familyAlerts.addAll(alerts)
            }
        }

        refreshFamilyResilienceScore()
    }

    private fun saveFamilyState() {
        val memberType = object : TypeToken<List<FamilyMember>>() {}.type
        val alertType = object : TypeToken<List<FamilyAlert>>() {}.type
        prefs.edit().putString("family_members_state", gson.toJson(familyMembers.toList(), memberType)).apply()
        prefs.edit().putString("family_alerts_state", gson.toJson(familyAlerts.toList(), alertType)).apply()
        refreshFamilyResilienceScore()
    }

    private fun refreshFamilyResilienceScore() {
        familyResilienceScore = if (familyMembers.isEmpty()) {
            75
        } else {
            val protectedMembers = familyMembers.count { it.isProtected }
            ((45 + (protectedMembers.toFloat() / familyMembers.size.toFloat()) * 55).roundToInt()).coerceIn(0, 100)
        }
    }

    fun addFamilyMember(name: String, contact: String) {
        if (name.isBlank() || contact.isBlank()) return
        val normalizedContact = contact.trim()
        if (familyMembers.any { it.contact.equals(normalizedContact, ignoreCase = true) }) return

        familyMembers.add(0, FamilyMember(name = name.trim(), contact = normalizedContact))
        saveFamilyState()
    }

    fun removeFamilyMember(memberId: String) {
        val removed = familyMembers.removeAll { it.id == memberId }
        if (removed) {
            familyAlerts.removeAll { it.memberId == memberId }
        }
        saveFamilyState()
    }

    fun toggleFamilyProtection(memberId: String, isProtected: Boolean) {
        val updated = familyMembers.map { if (it.id == memberId) it.copy(isProtected = isProtected) else it }
        familyMembers.clear()
        familyMembers.addAll(updated)
        saveFamilyState()
    }

    fun notifyFamilyForCurrentScan() {
        val current = assessment ?: return
        if (familyMembers.isEmpty()) return
        val enabled = familyMembers.filter { it.isProtected }
        if (enabled.isEmpty()) return
        val currentAlerts = familyAlerts.toList()

        val familyName = current.family.ifBlank { "Scam suspect" }
        val riskLevel = current.riskLevel.ifBlank { "low" }
        val snapshot = current.reasons.take(1).firstOrNull() ?: "Risc detectat pe mesajul curent."

        familyAlerts.clear()
        familyAlerts.addAll(
            enabled.map { member ->
                FamilyAlert(
                    memberId = member.id,
                    memberName = member.name,
                    triggerLabel = "alerta noua",
                    family = familyName,
                    riskLevel = riskLevel,
                    snapshot = snapshot
                )
            } + currentAlerts
        )
        if (familyAlerts.size > 12) {
            while (familyAlerts.size > 12) {
                familyAlerts.removeAt(familyAlerts.size - 1)
            }
        }
        saveFamilyState()
    }

    fun clearFamilyAlerts() {
        familyAlerts.clear()
        saveFamilyState()
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
                virusTotalConfigured = VIRUS_TOTAL_API_KEY.isNotBlank()
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

    private fun reevaluateGateWithThreatIntel(
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
                virusTotalConfigured = VIRUS_TOTAL_API_KEY.isNotBlank()
            )
        )
        val providerIds = setOf(ProviderId.WEB_RISK, ProviderId.URLSCAN, ProviderId.VIRUSTOTAL, ProviderId.CLAIM_VERIFIER)
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
        ProviderId.VIRUSTOTAL to ProviderState(ProviderId.VIRUSTOTAL, ProviderStatus.ERROR, note = "VirusTotal unavailable or not configured"),
        ProviderId.CLAIM_VERIFIER to ProviderState(ProviderId.CLAIM_VERIFIER, ProviderStatus.ERROR, note = "Offer/claim verification unavailable")
    )

    private fun pendingOnlineProviderStates(): Map<ProviderId, ProviderState> = mapOf(
        ProviderId.WEB_RISK to ProviderState(ProviderId.WEB_RISK, ProviderStatus.PENDING, note = "Backend reputation check running"),
        ProviderId.URLSCAN to ProviderState(ProviderId.URLSCAN, ProviderStatus.PENDING, note = "Sandbox preview running"),
        ProviderId.VIRUSTOTAL to ProviderState(ProviderId.VIRUSTOTAL, ProviderStatus.PENDING, note = "VirusTotal reputation check running"),
        ProviderId.CLAIM_VERIFIER to ProviderState(ProviderId.CLAIM_VERIFIER, ProviderStatus.PENDING, note = "Offer/claim verification running")
    )

    private fun backendUnavailableWhileSandboxRuns(): Map<ProviderId, ProviderState> = mapOf(
        ProviderId.WEB_RISK to ProviderState(ProviderId.WEB_RISK, ProviderStatus.ERROR, note = "Backend reputation check unavailable"),
        ProviderId.URLSCAN to ProviderState(ProviderId.URLSCAN, ProviderStatus.PENDING, note = "Sandbox preview still running"),
        ProviderId.VIRUSTOTAL to ProviderState(ProviderId.VIRUSTOTAL, ProviderStatus.ERROR, note = "VirusTotal unavailable or not configured"),
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
        val preliminary = evaluateOfflineText(rawInput).copy(
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
        val preliminary = evaluateOfflineText(rawInput).copy(
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

    private fun isSameNormalizedUrl(left: String?, right: String?): Boolean {
        val normalizedLeft = normalizeCandidateUrl(left) ?: left?.let(::normalizeUrl)
        val normalizedRight = normalizeCandidateUrl(right) ?: right?.let(::normalizeUrl)
        return !normalizedLeft.isNullOrBlank() && normalizedLeft == normalizedRight
    }

    private fun orchestratedRequest(rawInput: String, htmlPayload: String?, urls: List<String>): OrchestratedScanRequest {
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
                sourceChannel = "android_url_scan"
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
        channel: String
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
        runBackendOrchestratedScan(assembledInput, htmlPayload, links)
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
            state("virustotal", ProviderId.VIRUSTOTAL),
            state("claim_verifier", ProviderId.CLAIM_VERIFIER)
        ).associateBy { it.provider }
    }

    private fun buildAssessmentFromBackendScanResponse(
        response: ScanResponse,
        rawInput: String,
        urls: List<String>,
        preview: OrchestratedPreview? = null,
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
            serverInfo = if (response.isFinal == false) {
                "Avem un verdict provizoriu. Continuăm verificarea preview-ului securizat."
            } else {
                "Scanarea completă a fost finalizată."
            },
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
            sandboxReportUrl = preview?.reportUrl
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
                completeness = EvidenceCompleteness.FULL,
                registryVersion = BrandKnowledgeRegistry.registryVersion(),
                corpusVersion = BrandKnowledgeRegistry.corpusVersion(),
                virusTotalConfigured = VIRUS_TOTAL_API_KEY.isNotBlank()
            )
        )
        val gateResult = evidenceGate.evaluate(snapshot)
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
        val base = currentAssessmentForScan(response.scanId) ?: evaluateOfflineText(rawInput).copy(scanId = response.scanId)
        return applyEvidenceGate(
            current = base.copy(
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
            ),
            rawInput = rawInput,
            primaryUrl = urls.firstOrNull(),
            finalUrl = response.preview?.finalUrl,
            redirectChain = primaryUrl?.let { listOf(it) }.orEmpty(),
            threatIntel = threatIntel,
            providerStates = providerStatesFromOrchestratedPillars(response.pillars),
            completeness = EvidenceCompleteness.PARTIAL_ONLINE
        )
    }

    private suspend fun publishOrchestratedResponse(
        response: OrchestratedScanResponse,
        rawInput: String,
        urls: List<String>,
        existingScanId: String?
    ) {
        val providerStates = providerStatesFromOrchestratedPillars(response.pillars)
        val preview = if (response.result != null) {
            val stableScreenshot = withContext(Dispatchers.IO) {
                downloadSandboxScreenshotProxy(response.preview?.screenshotUrl)
            }
            response.preview?.copy(screenshotUrl = stableScreenshot ?: response.preview.screenshotUrl)
        } else {
            response.preview
        }
        val updated = response.result?.let {
            buildAssessmentFromBackendScanResponse(
                response = it,
                rawInput = rawInput,
                urls = urls,
                preview = preview,
                providerStates = providerStates
            )
        } ?: buildPendingAssessmentFromOrchestratedResponse(response, rawInput, urls)
        publishAssessmentResult(existingScanId ?: response.scanId, updated)
    }

    private fun shouldContinueOrchestratedPolling(response: OrchestratedScanResponse): Boolean {
        val status = response.status?.lowercase(Locale.US)
        if (status == "complete") return false
        return status == "scanning" ||
                status == "ready" ||
                response.result == null ||
                response.result.isFinal == false
    }

    private suspend fun runBackendOrchestratedScan(rawInput: String, htmlPayload: String?, urls: List<String>) {
        val preliminary = startBackendOrchestratedPendingAssessment(rawInput, urls)
        var response = api.startOrchestratedScan(orchestratedRequest(rawInput, htmlPayload, urls))
        publishOrchestratedResponse(response, rawInput, urls, preliminary?.scanId)

        val pollingDeadlineNanos = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(ORCHESTRATED_POLLING_BUDGET_MILLIS)
        while (shouldContinueOrchestratedPolling(response) && System.nanoTime() < pollingDeadlineNanos) {
            kotlinx.coroutines.delay(orchestratedPollDelayMillis(response))
            response = api.getOrchestratedScan(response.scanId)
            publishOrchestratedResponse(response, rawInput, urls, response.scanId)
        }
    }

    fun onScanClick() {
        if (text.isBlank()) return
        loading = true
        loadingMsg = "Analizăm textul și link-urile..."
        
        viewModelScope.launch {
            val rawInput = text
            val htmlPayload = activeEvidenceHtml(rawInput)
            val urls = activeEvidenceLinks(rawInput).ifEmpty { extractUrls(rawInput) }
            try {
                runBackendOrchestratedScan(rawInput, htmlPayload, urls)
                return@launch
            } catch (orchestratedError: Exception) {
                val fallbackPrimaryUrl = urls.firstOrNull()?.let(::normalizeUrl)
                val result = applyEvidenceGate(
                    current = evaluateOfflineText(rawInput).copy(
                        scanId = UUID.randomUUID().toString(),
                        serverInfo = "Nu am putut obține rezultatele pilonilor. Reîncearcă scanarea.",
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
            Uri.parse(normalizeUrl(url)).host?.lowercase(Locale.getDefault()).orEmpty()
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

    fun stageSharedTextPayload(
        payload: String,
        sourceLabel: String,
        preserveHtml: Boolean = false,
        autoScan: Boolean = false,
        fidelity: SharedContentFidelity = if (preserveHtml) SharedContentFidelity.FULL_HTML else SharedContentFidelity.PLAIN_TEXT_ONLY
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
        pendingSharedFiles = emptyList()
        currentTab = "scan"

        if (autoScan) {
            pendingSharedInput = null
            onScanClick()
        } else {
            pendingSharedInput = normalized
        }
    }

    fun stageSharedFile(uri: Uri, context: Context, sourceLabel: String) {
        if (uri.toString().isBlank()) return

        val mime = runCatching {
            context.contentResolver.getType(uri)?.lowercase(Locale.getDefault()) ?: ""
        }.getOrElse { "" }

        val fileName = runCatching {
            getFileName(uri, context)
        }.getOrElse { "document" }

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

    fun onQrPicked(uri: Uri, context: Context) {
        loading = true
        loadingMsg = "Scanăm codul QR..."
        
        try {
            val image = InputImage.fromFilePath(context, uri)
            barcodeScanner.process(image)
                .addOnSuccessListener { barcodes ->
                    val qrText = barcodes.firstOrNull()?.rawValue
                    if (qrText != null) {
                        text = qrText
                        stagedEvidenceHtml = null
                        stagedEvidenceLinks = extractUrls(qrText)
                        stagedEvidenceText = qrText
                        stagedEvidenceInputKind = "qr"
                        stagedEvidenceChannel = "qr_scan"
                        onScanClick()
                    } else {
                        loading = false
                    }
                }
                .addOnFailureListener {
                    loading = false
                }
        } catch (e: Exception) {
            loading = false
        }
    }

    fun onImagePicked(uri: Uri, context: Context) {
        loading = true
        loadingMsg = "Extragem textul din screenshot prin OCR..."
        
        viewModelScope.launch {
            var file: File? = null
            try {
                if (!isUploadSizeAllowed(uri, context)) {
                    loadingMsg = "Imaginea este prea mare pentru scanare cloud, încerc OCR local."
                    performLocalOcr(uri, context)
                } else {
                    file = uriToFile(uri, context, MAX_UPLOAD_BYTES)
                    val requestFile = file.asRequestBody("image/*".toMediaTypeOrNull())
                    val body = MultipartBody.Part.createFormData("image_file", file.name, requestFile)
                    val source = "android_image_upload".toRequestBody("text/plain".toMediaTypeOrNull())

                    val response = api.extractImage(body, source)
                    runBackendOrchestratedScanFromExtraction(
                        response = response,
                        fileName = file.name,
                        inputKind = "upload_image",
                        channel = "image_ocr"
                    )
                }
            } catch (e: Exception) {
                if (e is UploadSizeExceededException) {
                    loadingMsg = "Imaginea este prea mare pentru scanare cloud. Încerc OCR local."
                    performLocalOcr(uri, context)
                } else {
                    performLocalOcr(uri, context)
                }
            } finally {
                file?.delete()
                loading = false
            }
        }
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

    private fun performLocalOcr(uri: Uri, context: Context) {
        viewModelScope.launch {
            try {
                val image = InputImage.fromFilePath(context, uri)
                val extractedText = runCatching { extractTextFromImage(image) }.getOrNull().orEmpty()
                if (extractedText.isNotBlank()) {
                    text = extractedText
                    stagedEvidenceHtml = null
                    stagedEvidenceLinks = extractUrls(extractedText) + extractHtmlLinks(extractedText)
                    stagedEvidenceText = extractedText
                    stagedEvidenceInputKind = "upload_image"
                    stagedEvidenceChannel = "image_ocr"
                    onScanClick()
                }
            } catch (_: Exception) {
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
        val lowerName = fileName.lowercase(Locale.getDefault())
        val isPdf = lowerName.endsWith(".pdf") || mimeType.startsWith("application/pdf")
        val isHtml = lowerName.endsWith(".html") || lowerName.endsWith(".htm") || mimeType.startsWith("text/html")
        val isEml = lowerName.endsWith(".eml") || lowerName.endsWith(".msg") || mimeType == "message/rfc822"
        val isText = lowerName.endsWith(".txt") || mimeType == "text/plain"
        
        if (isText) {
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

        if (isHtml || isEml) {
            loading = true
            loadingMsg = if (isHtml) "Analizăm conținutul HTML..." else "Analizăm fișierul email..."

            viewModelScope.launch {
                try {
                    val rawContent = readTextFromUri(uri, context)
                    val parsedEmail = if (isEml) EmailMessageParser.parse(rawContent) else null

                    val htmlContentSource = if (isEml) {
                        parsedEmail?.htmlText?.ifBlank { rawContent } ?: rawContent
                    } else {
                        rawContent
                    }
                    val visibleMailText = if (isEml) {
                        parsedEmail?.bodyForAnalysis?.ifBlank { rawContent } ?: rawContent
                    } else {
                        rawContent
                    }

                    val extractedHtmlLinks = if (isHtml || isEml) {
                        extractHtmlLinks(htmlContentSource)
                    } else {
                        emptyList()
                    }
                    val extractedUrls = extractUrls(rawContent)
                    val visibleText = sanitizeSharedText(visibleMailText)
                    val allLinks = (extractedHtmlLinks + extractedUrls).distinct().filter { it.isNotBlank() }
                    val finalText = MailShareInputAssembler.buildMailScanInput(visibleText, allLinks, fileName)
                    text = finalText
                    stagedEvidenceHtml = htmlContentSource
                    stagedEvidenceLinks = allLinks
                    stagedEvidenceText = finalText
                    stagedEvidenceInputKind = if (isEml) "import_email" else "import_html"
                    stagedEvidenceChannel = if (isEml) "email_file" else "html_file"
                    onScanClick()
                } catch (e: Exception) {
                    text = "Eroare la citirea conținutului: $fileName"
                    stagedEvidenceHtml = null
                    stagedEvidenceLinks = emptyList()
                    stagedEvidenceText = text
                    stagedEvidenceInputKind = if (isEml) "import_email" else "import_html"
                    stagedEvidenceChannel = if (isEml) "email_file" else "html_file"
                    onScanClick()
                }
            }
            return
        }

        loading = true
        loadingMsg = if (isPdf) "Analizăm documentul PDF..." else "Analizăm fișierul email (.eml)..."
        
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
                val requestFile = file.asRequestBody(
                    (if (isPdf) "application/pdf" else "message/rfc822").toMediaTypeOrNull()
                )
                val body = MultipartBody.Part.createFormData(
                    if (isPdf) "pdf_file" else "email_file", 
                    file.name, 
                    requestFile
                )
                val source = "android_file_upload".toRequestBody("text/plain".toMediaTypeOrNull())
                
                val response = if (isPdf) api.extractPdf(body, source) else api.extractEmail(body, source)
                runBackendOrchestratedScanFromExtraction(
                    response = response,
                    fileName = fileName,
                    inputKind = if (isPdf) "import_pdf" else "import_email",
                    channel = if (isPdf) "pdf_ocr" else "email_file"
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

                if (isPdf) {
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
                            channel = "pdf",
                            providerStates = unavailableProviderStates(),
                            completeness = EvidenceCompleteness.LOCAL_ONLY
                        )
                    }
                } else {
                    assessment = applyEvidenceGate(
                        current = OfflineAssessment(
                            family = "Scanare incompletă",
                            riskScore = 0,
                            riskLevel = "unknown",
                            reasons = listOf("Nu s-a putut finaliza scanarea cloud a fișierului."),
                            safeActions = listOf("Reîncearcă scanarea când conexiunea este disponibilă."),
                            keyDangers = listOf("Nu avem suficiente dovezi tehnice pentru verdict."),
                            originalText = "Eroare conexiune server."
                        ),
                        rawInput = "Eroare conexiune server pentru fișier: $fileName",
                        inputKind = "import_file",
                        channel = "file_or_email",
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

    /*private fun extractHtmlLinksLegacy(content: String): List<String> {
        val links = mutableListOf<String>()
        val normalised = content.replace("\r", " ").replace("\n", " ")
        val htmlDecoded = Html.fromHtml(normalised, Html.FROM_HTML_MODE_LEGACY).toString()

        fun addCandidate(raw: String?) {
            normalizeCandidateUrl(raw)?.let { links.add(it) }
        }

        val linkAttributePatterns = listOf(
            "(?i)(href|src|action|formaction|data-href|xlink:href|poster|data-url|data-link|app-url)\\s*=\\s*('|")([^'\"\s>]+)",
            "(?i)data-[a-z0-9_-]+\\s*=\\s*('|")([^'\"]+)\\1"
        )

        val jsPatterns = listOf(
            "(?is)on(?:click|submit|touchstart|mousedown)\\s*=\\s*('|")([^'\"]*)\\1",
            "(?i)(?:window|document)\\.(?:location|location\\.href|location\\.replace|location\\.assign)\\s*=\\s*('|")([^'\"]+)\\1"
        )

        linkAttributePatterns.forEach { patternText ->
            val pattern = Regex(patternText, RegexOption.IGNORE_CASE)
            pattern.findAll(normalised).forEach { match ->
                addCandidate(match.groupValues.getOrNull(3))
            }
            pattern.findAll(htmlDecoded).forEach { match ->
                addCandidate(match.groupValues.getOrNull(3))
            }
        }

        jsPatterns.forEach { patternText ->
            val pattern = Regex(patternText, RegexOption.DOT_MATCHES_ALL)
            pattern.findAll(normalised).forEach { match ->
                val snippet = match.groupValues.getOrNull(2).orEmpty()
                URL_REGEX.matcher(snippet).let {
                    while (it.find()) {
                        addCandidate(it.group())
                    }
                }
                URL_REGEX.matcher(Html.fromHtml(snippet, Html.FROM_HTML_MODE_LEGACY).toString()).let {
                    while (it.find()) {
                        addCandidate(it.group())
                    }
                }
            }
            pattern.findAll(htmlDecoded).forEach { match ->
                val snippet = match.groupValues.getOrNull(2).orEmpty()
                URL_REGEX.matcher(snippet).let {
                    while (it.find()) {
                        addCandidate(it.group())
                    }
                }
            }
        }

        URL_REGEX.matcher(normalised).let {
            while (it.find()) {
                addCandidate(it.group())
            }
        }
        URL_REGEX.matcher(htmlDecoded).let {
            while (it.find()) {
                addCandidate(it.group())
            }
        }

        return links.distinct()
    }*/

    private fun extractHtmlLinksLegacy(content: String): List<String> {
        return HtmlLinkExtractor.extractHtmlLinks(content, this::decodeHtmlForParser)
    }

    private fun normalizeCandidateUrl(raw: String?): String? {
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

    private fun mapButtons(rawButtons: List<Map<String, Any>>?): List<String> {
        if (rawButtons == null || rawButtons.isEmpty()) return emptyList()

        return rawButtons.mapNotNull { button ->
            val label = (button["text"] ?: button["label"] ?: "").toString().trim()
            val url = (button["url"] ?: button["href"] ?: button["action"] ?: "").toString().trim()
            if (url.isBlank()) return@mapNotNull null
            val prettyLabel = if (label.isBlank()) "Buton" else label
            "$prettyLabel → $url"
        }.filter { it.isNotBlank() }.distinct()
    }

    private fun mapEmailAuth(rawEmailAuth: Map<String, Any>?): String? {
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

    private fun mapList(value: Any?): List<Map<*, *>> {
        return (value as? List<*>)?.filterIsInstance<Map<*, *>>() ?: emptyList()
    }

    private fun buildThreatIntel(evidence: Map<String, Any>?, response: ScanResponse): List<ThreatIntelSourceResult> {
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

    private fun threatIntelDetails(payload: Map<*, *>?): String? {
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

    private fun firstMap(map: Map<String, Any>?, vararg keys: String): Map<*, *>? {
        if (map == null) return null
        return keys.firstNotNullOfOrNull { key ->
            map[key] as? Map<*, *>
        }
    }

    private fun firstString(map: Map<*, *>?, vararg keys: String): String? {
        if (map == null) return null
        return keys.firstNotNullOfOrNull { key ->
            map[key]?.toString()?.trim()?.takeIf { it.isNotBlank() && it != "null" }
        }
    }

    private fun providerSourceKeyForScan(value: String): String {
        return value.lowercase(Locale.US).filter { it.isLetterOrDigit() }
    }

    private fun inferSeverity(value: String): String {
        val normalized = value.lowercase(Locale.getDefault())
        return when {
            listOf("malicious", "phishing", "malware", "danger", "high", "critical", "unsafe").any { normalized.contains(it) } -> "high"
            listOf("suspicious", "medium", "warning", "unknown", "unrated").any { normalized.contains(it) } -> "medium"
            listOf("safe", "clean", "harmless", "low").any { normalized.contains(it) } -> "low"
            else -> "unknown"
        }
    }

    private fun upsertThreatIntel(
        current: List<ThreatIntelSourceResult>,
        item: ThreatIntelSourceResult
    ): List<ThreatIntelSourceResult> {
        return (current.filterNot { it.source.equals(item.source, ignoreCase = true) } + item)
    }

    private fun summarizeUrlscanResult(result: Map<*, *>?, attempts: Int): ThreatIntelSourceResult {
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

    private fun pickPrimaryThreatIntelUrl(response: ScanResponse, rawText: String = text): String {
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

    private fun pickUrlFromMap(item: Map<*, *>): String? {
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

    private suspend fun enrichThreatIntelFromServices(
        targetUrl: String,
        existingThreatIntel: List<ThreatIntelSourceResult>,
        riskLevel: String
    ): List<ThreatIntelSourceResult> = coroutineScope {
        var result = existingThreatIntel.toMutableList()

        val url = normalizeCandidateUrl(targetUrl)
            ?: normalizeUrl(targetUrl)

        val webRisk = async { fetchGoogleWebRiskThreatIntel(url) }.await()
        webRisk?.let { result = upsertThreatIntel(result, it).toMutableList() }

        fetchVirusTotalThreatIntel(url)?.let {
            result = upsertThreatIntel(result, it).toMutableList()
        }

        return@coroutineScope result.distinctBy { it.source.lowercase(Locale.getDefault()) }
    }

    private suspend fun fetchVirusTotalThreatIntel(url: String): ThreatIntelSourceResult? {
        if (VIRUS_TOTAL_API_KEY.isBlank()) return null

        val urlId = virusTotalUrlId(url)
        if (urlId.isBlank()) return null

        val request = Request.Builder()
            .url("https://www.virustotal.com/api/v3/urls/$urlId")
            .addHeader("x-apikey", VIRUS_TOTAL_API_KEY)
            .addHeader("accept", "application/json")
            .build()

        return runCatching {
            threatIntelClient.newCall(request).execute().use { response ->
                val body = response.body?.string()
                if (!response.isSuccessful || body.isNullOrBlank()) {
                    if (response.code == 404) {
                        return@runCatching ThreatIntelSourceResult(
                            source = "VirusTotal",
                            verdict = "Not Found",
                            severity = "low",
                            details = "URL nou sau neindexat încă în baza VirusTotal."
                        )
                    }
                    return@runCatching null
                }

                val payload = gson.fromJson(body, Map::class.java) as? Map<*, *> ?: return@runCatching null
                val data = payload["data"] as? Map<*, *> ?: return@runCatching null
                val attributes = data["attributes"] as? Map<*, *> ?: return@runCatching null
                val stats = attributes["last_analysis_stats"] as? Map<*, *>
                if (stats == null) return@runCatching null

                val malicious = asInt(stats["malicious"])
                val suspicious = asInt(stats["suspicious"])
                val harmless = asInt(stats["harmless"])
                val undetected = asInt(stats["undetected"])
                val timeout = asInt(stats["timeout"])
                val total = malicious + suspicious + harmless + undetected + timeout
                val score = if (total > 0) ((malicious + suspicious) * 100.0 / total).roundToInt() else 0
                val verdict = when {
                    malicious > 0 -> "Malicious"
                    suspicious > 0 -> "Suspicious"
                    total > 0 -> "Clean"
                    else -> "Unknown"
                }

                val details = buildString {
                    append("VT score: $score. Engines: total=$total, malicious=$malicious, suspicious=$suspicious.")
                    val flagged = parseThreatIntelEngineFlags(attributes["last_analysis_results"])
                    if (flagged.isNotBlank()) {
                        append(" Flags: ")
                        append(flagged)
                    }
                }

                ThreatIntelSourceResult(
                    source = "VirusTotal",
                    verdict = verdict,
                    severity = if (verdict == "Clean") "low" else "high",
                    details = details
                )
            }
        }.getOrElse { null }
    }

    private fun parseThreatIntelEngineFlags(raw: Any?): String {
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

    private suspend fun fetchGoogleWebRiskThreatIntel(url: String): ThreatIntelSourceResult? {
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
                        expiresAtMillis = System.currentTimeMillis() + WEB_RISK_NO_THREAT_CACHE_MS
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
                        ?: (System.currentTimeMillis() + WEB_RISK_THREAT_FALLBACK_CACHE_MS)
                )
            }
        }.getOrElse { null }
    }

    private fun getCachedWebRiskResult(url: String): ThreatIntelSourceResult? {
        val cacheKey = url.lowercase(Locale.US)
        val cached = webRiskCache[cacheKey] ?: return null
        return if (cached.expiresAtMillis > System.currentTimeMillis()) {
            cached.result
        } else {
            webRiskCache.remove(cacheKey)
            null
        }
    }

    private fun cacheWebRiskResult(
        url: String,
        result: ThreatIntelSourceResult,
        expiresAtMillis: Long
    ): ThreatIntelSourceResult {
        webRiskCache[url.lowercase(Locale.US)] = CachedThreatIntelResult(
            result = result,
            expiresAtMillis = expiresAtMillis
        )
        return result
    }

    private fun parseWebRiskExpireTimeMillis(expireTime: String?): Long? {
        if (expireTime.isNullOrBlank()) return null
        val normalized = normalizeWebRiskTimestamp(expireTime) ?: return null
        val formatter = java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US).apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }
        return runCatching { formatter.parse(normalized)?.time }
            .getOrNull()
            ?.takeIf { it > System.currentTimeMillis() }
    }

    private fun normalizeWebRiskTimestamp(raw: String): String? {
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

    private fun virusTotalUrlId(url: String): String {
        val trimmed = normalizeCandidateUrl(url) ?: return ""
        return Base64.encodeToString(trimmed.toByteArray(StandardCharsets.UTF_8), Base64.URL_SAFE or Base64.NO_WRAP)
            .replace("=", "")
    }

    private fun asInt(raw: Any?): Int {
        return when (raw) {
            is Number -> raw.toInt()
            is String -> raw.toIntOrNull() ?: 0
            else -> 0
        }
    }

    private suspend fun updateThreatIntelInHistory(scanId: String, threatIntel: List<ThreatIntelSourceResult>) {
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

    private fun currentAssessmentForScan(scanId: String): OfflineAssessment? {
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

    private fun replaceAssessment(scanId: String, updated: OfflineAssessment) {
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

    private fun extractHtmlLinks(content: String): List<String> {
        if (content.isBlank()) return emptyList()
        return HtmlLinkExtractor.extractHtmlLinks(content, this::decodeHtmlForParser)
    }

    private fun decodeHtmlForParser(input: String): String {
        return Html.fromHtml(input, Html.FROM_HTML_MODE_LEGACY).toString()
    }

    private fun uriToFile(uri: Uri, context: Context, maxBytes: Long = MAX_UPLOAD_BYTES): File {
        val file = File(context.cacheDir, "${TMP_UPLOAD_PREFIX}${System.currentTimeMillis()}")
        var copiedBytes = 0L
        val buffer = ByteArray(8 * 1024)

        try {
            val inputStream = context.contentResolver.openInputStream(uri)
                ?: throw IllegalArgumentException("Nu s-a putut deschide fișierul.")

            FileOutputStream(file).use { outputStream ->
                inputStream.use { input ->
                    while (true) {
                        val read = input.read(buffer)
                        if (read == -1) break
                        copiedBytes += read.toLong()
                        if (copiedBytes > maxBytes) {
                            throw UploadSizeExceededException("Fișier prea mare pentru upload.")
                        }
                        outputStream.write(buffer, 0, read)
                    }
                }
            }
            return file
        } catch (sizeExceeded: UploadSizeExceededException) {
            file.delete()
            throw sizeExceeded
        } catch (e: Exception) {
            file.delete()
            throw e
        }
    }

    private fun cleanupLegacyTempUploads() {
        runCatching {
            val staleThresholdMs = 24L * 60L * 60L * 1000L
            val now = System.currentTimeMillis()
            getApplication<Application>().cacheDir.listFiles { file ->
                file.isFile && file.name.startsWith(TMP_UPLOAD_PREFIX)
            }?.forEach { file ->
                if (now - file.lastModified() > staleThresholdMs) {
                    file.delete()
                }
            }
        }
    }

    private class UploadSizeExceededException(message: String) : IllegalArgumentException(message)

    private fun isUploadSizeAllowed(uri: Uri, context: Context): Boolean {
        val sizeBytes = queryContentSize(uri, context) ?: return true
        return sizeBytes <= MAX_UPLOAD_BYTES
    }

    private fun queryContentSize(uri: Uri, context: Context): Long? {
        val cursor = runCatching {
            context.contentResolver.query(
                uri,
                arrayOf(OpenableColumns.SIZE),
                null,
                null,
                null
            )
        }.getOrNull()
        cursor?.use {
            if (!it.moveToFirst()) return null
            val sizeIndex = it.getColumnIndex(OpenableColumns.SIZE)
            if (sizeIndex == -1) return null
            return try {
                it.getLong(sizeIndex)
            } catch (_: Exception) {
                null
            }
        }
        return null
    }

    private fun readTextFromUri(uri: Uri, context: Context): String {
        context.contentResolver.openInputStream(uri)?.use { stream ->
            val reader = stream.bufferedReader(Charsets.UTF_8)
            return reader.use { it.readText() }
        }
        throw IllegalArgumentException("Nu se poate citi conținutul fișierului.")
    }

    private fun evaluateOfflineText(scannedText: String): OfflineAssessment {
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
                val hash = MessageDigest.getInstance("SHA-256")
                    .digest(current.originalText.toByteArray(StandardCharsets.UTF_8))
                    .joinToString("") { "%02x".format(it) }
                val report = CommunityReport(
                    hash = hash,
                    riskLevel = current.riskLevel,
                    family = current.family
                )
                api.sendCommunityReport(report)
                cyberScore += 20
            } catch (_: Exception) {
            }
        }
    }

    private fun extractUrls(input: String): List<String> {
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

    private fun normalizeUrl(url: String): String {
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
        val json = gson.toJson(historyItems.toList())
        prefs.edit().putString("history", json).apply()
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
}
