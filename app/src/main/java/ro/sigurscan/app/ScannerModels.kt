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

data class OfferFieldsSummary(
    val issuerName: String? = null,
    val issuerCui: String? = null,
    val iban: String? = null,
    val paymentBeneficiary: String? = null,
    val totalAmount: Double? = null,
    val currency: String? = null,
    val paymentMethod: String? = null,
    val documentType: String? = null,
    val familyCode: String? = null
)

data class OfferEntitySummary(
    val cuiChecked: Boolean? = null,
    val cuiExists: Boolean? = null,
    val cuiActive: Boolean? = null,
    val denumire: String? = null,
    val nameMatches: Boolean? = null,
    val brandImpersonation: Boolean? = null
)

data class OfferEvidenceSummary(
    val fields: OfferFieldsSummary = OfferFieldsSummary(),
    val signals: List<String> = emptyList(),
    val warnings: List<String> = emptyList(),
    val entity: OfferEntitySummary? = null,
    val coherenceOk: Boolean? = null,
    val gateLabel: String? = null
)

data class OfferConfirmationFields(
    val issuerName: String = "",
    val issuerCui: String = "",
    val iban: String = "",
    val paymentBeneficiary: String = "",
    val totalAmount: String = "",
    val currency: String = "RON",
    val documentNumber: String = "",
    val documentDate: String = ""
)

data class PendingOfferConfirmation(
    val extractedText: String,
    val links: List<String>,
    val fileName: String,
    val inputKind: String,
    val channel: String,
    val htmlPayload: String? = null,
    val fields: OfferConfirmationFields = OfferConfirmationFields()
)

data class ScanCacheStatus(
    val cacheKey: String,
    val cachedAtMillis: Long,
    val expiresAtMillis: Long,
    val source: String = "local"
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
    val offerEvidence: OfferEvidenceSummary? = null,
    val legal: LegalSection? = null,
    val actionPlan: ActionPlan? = null,
    val inputFidelity: SharedContentFidelity? = null,
    val cacheStatus: ScanCacheStatus? = null
)

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

data class CircleProtectionSnapshot(
    val link: CircleLinkResponse? = null,
    val ping: VerificationPingResponse? = null,
    val outcome: CirclePingOutcome? = null,
    val guardianOpinion: GuardianSecondOpinionResponse? = null
)

data class AudioReadinessSnapshot(
    val explicitConsent: Boolean = false,
    val privacyDisclosureAccepted: Boolean = false,
    val featureFlagEnabled: Boolean = false,
    val modelAvailable: Boolean = false,
    val nativeRuntimeAvailable: Boolean = false,
    val microphonePermissionGranted: Boolean = false,
    val decision: AudioCaptureDecision = AudioSafetyPolicy.canStartCapture(
        explicitConsent = false,
        modelAvailable = false,
        nativeRuntimeAvailable = false,
        privacyDisclosureAccepted = false,
        featureFlagEnabled = false,
        microphonePermissionGranted = false
    )
)

data class SpeakerGuardSnapshot(
    val active: Boolean = false,
    val phase: SpeakerGuardPhase = SpeakerGuardPhase.IDLE,
    val chunksAnalyzed: Int = 0,
    val chunksDropped: Int = 0,
    val latestVerdict: AudioEvidenceVerdict? = null,
    val latestReasonCode: String? = null,
    val latestArcFamily: String? = null,
    val latestLatencyMs: Long? = null,
    val startedAtEpochMillis: Long? = null,
    val status: String = "Urechea este oprită.",
    val rawAudioStored: Boolean = false
)
