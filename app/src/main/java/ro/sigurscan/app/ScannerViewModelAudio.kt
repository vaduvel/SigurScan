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

fun ScannerViewModel.setAudioConsent(value: Boolean) {
    audioReadiness = audioReadiness.copy(explicitConsent = value)
    refreshAudioReadiness()
}

fun ScannerViewModel.setAudioPrivacyDisclosureAccepted(value: Boolean) {
    audioReadiness = audioReadiness.copy(privacyDisclosureAccepted = value)
    refreshAudioReadiness()
}

fun ScannerViewModel.acceptSpeakerGuardConsent() {
    audioReadiness = audioReadiness.copy(
        explicitConsent = true,
        privacyDisclosureAccepted = true
    )
    refreshAudioReadiness()
}

fun ScannerViewModel.refreshAudioReadiness() {
    audioReadinessStatus = "Verific pregătirea locală."
    viewModelScope.launch {
        val (snapshot, reasons) = evaluateAudioReadiness(audioReadiness)
        audioReadiness = snapshot
        audioReadinessStatus = if (snapshot.decision.allowed) {
            "Urechea este pregătită. Audio-ul rămâne pe telefon."
        } else {
            "Urechea nu poate porni încă: ${audioReadinessReasonLabels(reasons).joinToString(", ")}."
        }
    }
}

fun ScannerViewModel.startSpeakerGuard() {
    if (speakerGuardSnapshot.active) return

    audioReadinessStatus = "Pregătesc ascultarea locală."
    viewModelScope.launch {
        val (snapshot, reasons) = evaluateAudioReadiness(audioReadiness)
        audioReadiness = snapshot
        val decision = snapshot.decision
        if (!decision.allowed) {
            audioReadinessStatus = "Urechea nu poate porni încă: ${audioReadinessReasonLabels(reasons).joinToString(", ")}."
            return@launch
        }
        radarScreeningAudit = null
        val modelFile = withContext(Dispatchers.IO) { prepareWhisperModelFile() }
        speakerGuardServiceUpdatesJob?.cancel()
        SpeakerGuardForegroundServiceEvents.clear()
        speakerGuardServiceUpdatesJob = SpeakerGuardForegroundServiceEvents.updates
            .onEach { update -> applySpeakerGuardUpdate(update) }
            .launchIn(viewModelScope)
        speakerGuardSnapshot = SpeakerGuardSnapshot(
            active = true,
            phase = SpeakerGuardPhase.LISTENING,
            status = "Pornește serviciul vizibil de microfon. Ține apelul pe difuzor.",
            rawAudioStored = false
        )
        audioReadinessStatus = speakerGuardSnapshot.status
        SpeakerGuardForegroundService.startCapture(getApplication(), modelFile.absolutePath)
    }
}

internal suspend fun ScannerViewModel.evaluateAudioReadiness(base: AudioReadinessSnapshot): Pair<AudioReadinessSnapshot, List<String>> {
    val app = getApplication<Application>()
    val result = withContext(Dispatchers.IO) {
        val microphonePermissionGranted = ContextCompat.checkSelfPermission(
            app,
            Manifest.permission.RECORD_AUDIO
        ) == PackageManager.PERMISSION_GRANTED
        val modelReadiness = runCatching {
            val assets = app.assets
            val existingFiles = AudioModelPackagePolicy.requiredFiles.filterTo(mutableSetOf()) { path ->
                runCatching {
                    assets.open("${AudioModelPackagePolicy.assetRoot}/$path").use { it.read() }
                    true
                }.getOrDefault(false)
            }
            if (!AudioModelPackagePolicy.isComplete(existingFiles)) {
                false to listOf("asr_model_missing")
            } else {
                val manifest = assets.open("${AudioModelPackagePolicy.assetRoot}/model-manifest.json").use { input ->
                    AudioModelPackagePolicy.parseManifest(input.bufferedReader().readText())
                }
                manifest.valid to manifest.reasonCodes
            }
        }.getOrDefault(false to listOf("asr_model_missing"))
        val nativeReady = WhisperCppNativeBridge.available
        Triple(microphonePermissionGranted, modelReadiness, nativeReady)
    }
    val (microphonePermissionGranted, modelReadiness, nativeReady) = result
    val updated = base.copy(
        featureFlagEnabled = BuildConfig.SIGURSCAN_ENABLE_AUDIO_ASR,
        modelAvailable = modelReadiness.first,
        nativeRuntimeAvailable = nativeReady,
        microphonePermissionGranted = microphonePermissionGranted
    )
    val decision = AudioSafetyPolicy.canStartCapture(
        explicitConsent = updated.explicitConsent,
        modelAvailable = updated.modelAvailable,
        nativeRuntimeAvailable = updated.nativeRuntimeAvailable,
        privacyDisclosureAccepted = updated.privacyDisclosureAccepted,
        featureFlagEnabled = updated.featureFlagEnabled,
        microphonePermissionGranted = updated.microphonePermissionGranted
    )
    val reasons = (decision.reasonCodes + modelReadiness.second).distinct()
    return updated.copy(decision = decision) to reasons
}

fun ScannerViewModel.stopSpeakerGuard() {
    SpeakerGuardForegroundService.stopCapture(getApplication())
    speakerGuardServiceUpdatesJob?.cancel()
    speakerGuardServiceUpdatesJob = null
    speakerGuardSnapshot = speakerGuardSnapshot.copy(
        active = false,
        phase = SpeakerGuardPhase.STOPPED,
        status = "Urechea este oprită."
    )
}

internal fun ScannerViewModel.applySpeakerGuardUpdate(update: SpeakerGuardUpdate) {
    val evidence = update.result?.evidence
    if (evidence != null) {
        audioEvidenceResult = evidence
    }
    val finalStoppedUnverifiedVerdict = if (
        !update.active &&
        update.phase != SpeakerGuardPhase.PROCESSING &&
        evidence == null &&
        speakerGuardSnapshot.latestVerdict == null &&
        update.reasonCode in setOf(
            "call_ended",
            "call_ended_no_capture",
            "call_ended_no_clear_audio",
            "call_ended_recording_silenced"
        )
    ) {
        AudioEvidenceVerdict.UNVERIFIED
    } else {
        null
    }
    val startedAt = when {
        update.active && speakerGuardSnapshot.startedAtEpochMillis == null -> System.currentTimeMillis()
        update.active -> speakerGuardSnapshot.startedAtEpochMillis
        else -> null
    }
    speakerGuardSnapshot = SpeakerGuardSnapshot(
        active = update.active,
        phase = update.phase,
        chunksAnalyzed = update.chunksAnalyzed,
        chunksDropped = update.chunksDropped,
        latestVerdict = evidence?.verdict ?: speakerGuardSnapshot.latestVerdict ?: finalStoppedUnverifiedVerdict,
        latestReasonCode = update.reasonCode ?: update.result?.reasonCode ?: speakerGuardSnapshot.latestReasonCode,
        latestArcFamily = evidence?.arcFamily ?: speakerGuardSnapshot.latestArcFamily,
        latestLatencyMs = update.latencyMs ?: speakerGuardSnapshot.latestLatencyMs,
        startedAtEpochMillis = startedAt,
        status = update.status,
        rawAudioStored = false
    )
    audioReadinessStatus = update.status
    if (!update.active && update.phase != SpeakerGuardPhase.PROCESSING) {
        speakerGuardServiceUpdatesJob?.cancel()
        speakerGuardServiceUpdatesJob = null
    }
}

internal fun ScannerViewModel.prepareWhisperModelFile(): File {
    val app = getApplication<Application>()
    val targetDir = File(app.filesDir, "asr/whispercpp")
    val targetFile = File(targetDir, "ggml-model.bin")
    targetDir.mkdirs()

    app.assets.open("${AudioModelPackagePolicy.assetRoot}/ggml-model.bin").use { input ->
        val expectedBytes = input.available().toLong()
        if (targetFile.exists() && targetFile.length() == expectedBytes) {
            return targetFile
        }
    }

    app.assets.open("${AudioModelPackagePolicy.assetRoot}/ggml-model.bin").use { input ->
        FileOutputStream(targetFile).use { output -> input.copyTo(output) }
    }
    return targetFile
}

fun ScannerViewModel.analyzeCurrentTextAsAudioTranscript() {
    val transcript = text
    if (transcript.isBlank()) {
        audioEvidenceResult = null
        audioReadinessStatus = "Scanează sau lipește mai întâi transcrierea apelului."
        return
    }

    val result = AudioTranscriptEvidence.analyze(transcript)
    audioEvidenceResult = result
    audioReadinessStatus = when (result.verdict) {
        AudioEvidenceVerdict.DANGEROUS -> "Analiza locală a transcrierii: PERICULOS."
        AudioEvidenceVerdict.SUSPECT -> "Analiza locală a transcrierii: SUSPECT."
        AudioEvidenceVerdict.UNVERIFIED -> "Analiza locală a transcrierii: nu sunt suficiente dovezi."
    }
}

private fun audioReadinessReasonLabels(reasons: List<String>): List<String> {
    return reasons.map { reason ->
        when (reason) {
            "feature_disabled" -> "funcția audio nu este activată în această versiune"
            "asr_model_missing" -> "modelul audio local lipsește"
            "native_runtime_missing" -> "runtime-ul audio local lipsește"
            "privacy_disclosure_missing" -> "confirmă că analiza rămâne pe telefon"
            "explicit_consent_missing" -> "apasă Ascultă pe difuzor ca să pornești"
            "microphone_permission_missing" -> "permite microfonul"
            else -> reason.replace('_', ' ')
        }
    }.distinct()
}
