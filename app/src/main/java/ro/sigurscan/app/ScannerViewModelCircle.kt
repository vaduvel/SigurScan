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

fun ScannerViewModel.runLocalInboxProvenanceCheck() {
    val current = assessment
    if (current == null) {
        inboxProvenanceVerdict = null
        inboxProvenanceStatus = "Scanează sau partajează întâi un mesaj/link."
        return
    }
    val observedDomain = observedDomainForInboxSignal(current)
    val verdict = InboxProvenanceEngine.evaluateLocalText(
        rawText = current.originalText,
        observedDomain = observedDomain,
        btr = btrSyncSnapshot
    )
    inboxProvenanceVerdict = verdict
    inboxProvenanceStatus = when (verdict.verdict) {
        OnDeviceInboxVerdict.SAFE -> "Verificare locală: canal oficial și fără cerere sensibilă."
        OnDeviceInboxVerdict.DANGEROUS -> "Verificare locală: brand oficial + cerere interzisă."
        OnDeviceInboxVerdict.SUSPECT -> "Verificare locală: necesită verificare suplimentară."
        OnDeviceInboxVerdict.UNVERIFIED -> "Verificare locală: registru lipsă sau identitate neconfirmată."
    }
}

internal fun ScannerViewModel.observedDomainForInboxSignal(current: OfflineAssessment): String? {
    val candidates = listOfNotNull(current.finalUrl, current.redirectChain.lastOrNull())
    return candidates.firstNotNullOfOrNull { raw ->
        runCatching { URI(raw).host }
            .getOrNull()
            ?.takeIf { it.isNotBlank() }
    }
}

internal fun ScannerViewModel.localProtectedUserId(): String {
    val existing = prefs.getString("circle_protected_user_id", null)
    if (!existing.isNullOrBlank()) return existing
    val generated = "local_protected_${UUID.randomUUID().toString().replace("-", "").take(12)}"
    prefs.edit().putString("circle_protected_user_id", generated).apply()
    return generated
}

internal fun ScannerViewModel.verifierUserId(member: FamilyMember): String {
    return "local_verifier_${sha256Hex("${member.id}:${member.contact}").take(16)}"
}

internal fun ScannerViewModel.loadCircleProtectionSnapshot(): CircleProtectionSnapshot {
    return runCatching {
        val raw = prefs.getString("circle_protection_snapshot", null) ?: return@runCatching CircleProtectionSnapshot()
        gson.fromJson(raw, CircleProtectionSnapshot::class.java) ?: CircleProtectionSnapshot()
    }.getOrDefault(CircleProtectionSnapshot())
}

internal fun ScannerViewModel.saveCircleProtectionSnapshot(snapshot: CircleProtectionSnapshot = circleSnapshot) {
    prefs.edit().putString("circle_protection_snapshot", gson.toJson(snapshot)).apply()
}

fun ScannerViewModel.createCirclePair(member: FamilyMember?) {
    if (circleLoading || member == null) return
    circleLoading = true
    circleStatus = "Creăm legătura de încredere cu ${member.name}."
    viewModelScope.launch {
        try {
            val link = api.createCirclePair(
                CirclePairRequest(
                    protectedId = localProtectedUserId(),
                    verifierId = verifierUserId(member),
                    consent = "explicit"
                )
            )
            val snapshot = circleSnapshot.copy(link = link, ping = null, outcome = null)
            circleSnapshot = snapshot
            saveCircleProtectionSnapshot(snapshot)
            circleStatus = "Cercul este activ cu ${member.name}. Verificatorul nu poate citi conținut și nu poate supraveghea."
        } catch (_: Exception) {
            circleStatus = "Nu am putut crea legătura Cercul. Verifică conexiunea și reîncearcă."
        } finally {
            circleLoading = false
        }
    }
}

fun ScannerViewModel.createCirclePing() {
    val link = circleSnapshot.link?.takeIf { it.active } ?: return
    if (circleLoading) return
    circleLoading = true
    circleStatus = "Trimitem ping metadata-only către Cercul tău."
    viewModelScope.launch {
        try {
            val ping = api.createCirclePing(CirclePingRequest(linkId = link.linkId))
            val snapshot = circleSnapshot.copy(ping = ping, outcome = null)
            circleSnapshot = snapshot
            saveCircleProtectionSnapshot(snapshot)
            circleStatus = "Ping creat. Confirmă rezultatul doar după verificarea out-of-band."
        } catch (_: Exception) {
            circleStatus = "Nu am putut crea ping-ul Cercul. Reîncearcă."
        } finally {
            circleLoading = false
        }
    }
}

fun ScannerViewModel.resolveCirclePing(response: String) {
    val ping = circleSnapshot.ping ?: return
    if (circleLoading) return
    circleLoading = true
    circleStatus = "Înregistrăm răspunsul verificării."
    viewModelScope.launch {
        try {
            val outcome = api.respondCirclePing(
                CircleRespondRequest(
                    pingId = ping.pingId,
                    response = response
                )
            )
            val snapshot = circleSnapshot.copy(outcome = outcome)
            circleSnapshot = snapshot
            saveCircleProtectionSnapshot(snapshot)
            circleStatus = when (outcome.status) {
                "CONFIRMED" -> "Cercul a confirmat identitatea prin canal separat."
                "REJECTED" -> "Cercul a respins identitatea. Sună persoana pe numărul salvat de tine."
                else -> "Cercul nu a confirmat. Nu continua fără verificare oficială."
            }
        } catch (_: Exception) {
            circleStatus = "Nu am putut înregistra răspunsul. Reîncearcă."
        } finally {
            circleLoading = false
        }
    }
}

fun ScannerViewModel.revokeCirclePair() {
    val link = circleSnapshot.link ?: return
    if (circleLoading) return
    circleLoading = true
    circleStatus = "Revocăm legătura Cercul."
    viewModelScope.launch {
        try {
            val revoked = api.revokeCirclePair(
                CircleRevokeRequest(
                    linkId = link.linkId,
                    byUser = link.protectedUserId
                )
            )
            val snapshot = circleSnapshot.copy(link = revoked, ping = null, outcome = null)
            circleSnapshot = snapshot
            saveCircleProtectionSnapshot(snapshot)
            circleStatus = "Legătura Cercul a fost revocată."
        } catch (_: Exception) {
            circleStatus = "Nu am putut revoca legătura. Reîncearcă."
        } finally {
            circleLoading = false
        }
    }
}

fun ScannerViewModel.requestGuardianSecondOpinion(member: FamilyMember?, shareLevel: String = "metadata_only", consent: Boolean = false) {
    if (guardianLoading || member == null) return
    guardianLoading = true
    guardianStatus = "Trimitem rezumatul redactat către Guardian."
    viewModelScope.launch {
        try {
            val opinion = api.requestGuardianSecondOpinion(
                GuardianSecondOpinionRequest(
                    caseId = assessment?.scanId ?: "manual_${System.currentTimeMillis()}",
                    protectedId = localProtectedUserId(),
                    guardianId = verifierUserId(member),
                    redactedSummary = guardianRedactedSummaryFromAssessment(assessment),
                    shareLevel = shareLevel,
                    consent = consent
                )
            )
            val snapshot = circleSnapshot.copy(guardianOpinion = opinion)
            circleSnapshot = snapshot
            saveCircleProtectionSnapshot(snapshot)
            guardianStatus = if (opinion.shareDowngraded) {
                "Guardian a primit doar metadata. Conținutul complet a fost blocat fără consimțământ."
            } else {
                "Guardian a primit cererea: ${opinion.shareLevel ?: "metadata_only"}."
            }
        } catch (_: Exception) {
            guardianStatus = "Nu am putut cere a doua opinie. Reîncearcă."
        } finally {
            guardianLoading = false
        }
    }
}
