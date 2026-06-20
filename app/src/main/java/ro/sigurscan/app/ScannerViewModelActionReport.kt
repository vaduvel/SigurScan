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

// Post-incident action plan and official report package, extracted from ScannerViewModel.

fun ScannerViewModel.requestPostIncidentActionPlan(impacts: List<String>) {
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

fun ScannerViewModel.requestOfficialReportPackage() {
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
