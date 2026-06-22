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
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.TimeUnit
import java.util.regex.Pattern
import javax.net.ssl.SSLException
import kotlin.math.roundToInt
import kotlin.math.max
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.coroutines.suspendCoroutine
import retrofit2.HttpException

// QR-code and image (camera/gallery) intake scanning, extracted from the ScannerViewModel
// God object as behaviour-preserving extension functions.

private const val QR_IMAGE_DECODE_TIMEOUT_MILLIS = 15_000L

fun ScannerViewModel.onLiveQrDecoded(payload: String) {
    val qrText = payload.trim()
    if (qrText.isBlank()) {
        publishQrExtractionIncomplete("Nu am găsit un cod QR lizibil în imagine.")
        return
    }
    text = qrText
    stagedEvidenceHtml = null
    stagedEvidenceLinks = extractUrls(qrText)
    stagedEvidenceText = qrText
    stagedEvidenceInputKind = "qr"
    stagedEvidenceChannel = "qr_scan"
    onScanClick()
}

fun ScannerViewModel.onQrPicked(uri: Uri, context: Context) {
    assessment = null
    loading = true
    loadingMsg = "Scanăm codul QR..."
    val completed = AtomicBoolean(false)

    viewModelScope.launch {
        kotlinx.coroutines.delay(QR_IMAGE_DECODE_TIMEOUT_MILLIS)
        if (completed.compareAndSet(false, true)) {
            publishQrExtractionIncomplete("Citirea codului QR a durat prea mult. Reîncearcă cu o poză mai clară.")
        }
    }

    try {
        val image = InputImage.fromFilePath(context, uri)
        barcodeScanner.process(image)
            .addOnSuccessListener { barcodes ->
                if (completed.compareAndSet(false, true)) {
                    val qrText = barcodes.firstOrNull()?.rawValue?.trim()
                    if (!qrText.isNullOrBlank()) {
                        loading = false
                        onLiveQrDecoded(qrText)
                    } else {
                        publishQrExtractionIncomplete("Nu am găsit un cod QR lizibil în imagine.")
                    }
                }
            }
            .addOnFailureListener {
                if (completed.compareAndSet(false, true)) {
                    publishQrExtractionIncomplete("Nu am putut citi codul QR din imagine. Reîncearcă cu o poză mai clară.")
                }
            }
    } catch (e: Exception) {
        if (completed.compareAndSet(false, true)) {
            publishQrExtractionIncomplete("Nu am putut deschide imaginea pentru citirea codului QR.")
        }
    }
}

internal fun ScannerViewModel.publishQrExtractionIncomplete(reason: String) {
    val result = localUnverifiedAssessment(
        current = OfflineAssessment(
            family = "Scanare QR incompletă",
            riskScore = 0,
            riskLevel = "unknown",
            reasons = listOf(reason),
            safeActions = listOf("Reîncearcă scanarea QR sau copiază manual linkul/textul afișat lângă cod."),
            keyDangers = listOf("Nu avem suficiente dovezi tehnice pentru verdict."),
            originalText = "Nu s-a extras conținut verificabil din codul QR."
        ),
        reasonCode = "LOCAL_QR_EXTRACTION_INCOMPLETE",
        inputKind = "qr",
        channel = "qr_scan"
    )
    publishAssessmentResult(null, result)
    loading = false
}

fun ScannerViewModel.onImagePicked(uri: Uri, context: Context) {
    assessment = null
    loading = true
    loadingMsg = "Pregătim imaginea pentru verificare..."

    viewModelScope.launch {
        var file: File? = null
        val fileName = getFileName(uri, context)
        try {
            loadingMsg = "Extragem text, linkuri și coduri QR din imagine..."
            file = prepareInvoiceImageUpload(
                uri,
                context,
                maxBytes = ScannerViewModel.MAX_IMAGE_UPLOAD_BYTES
            )
            val (uploadMime, uploadName) = resolveImageUploadMeta(file, fileName)
            val requestFile = file.asRequestBody(uploadMime.toMediaTypeOrNull())
            val body = MultipartBody.Part.createFormData("image_file", uploadName, requestFile)
            val source = "android_image_upload".toRequestBody("text/plain".toMediaTypeOrNull())

            val response = uploadApi.extractImage(body, source)
            runBackendOrchestratedScanFromExtraction(
                response = response,
                fileName = file.name,
                inputKind = "upload_image",
                channel = "image_ocr"
            )
            return@launch
        } catch (e: Exception) {
            loadingMsg = "Extragerea cloud nu a reușit. Încercăm OCR local..."
            val handledLocally = runCatching {
                runLocalImageOcrScanIfPossible(uri, context)
            }.getOrDefault(false)
            if (!handledLocally) {
                val reason = if (e is UploadSizeExceededException) {
                    "Imaginea este prea mare pentru scanarea cloud, iar OCR-ul local nu a extras text verificabil."
                } else {
                    "Nu am putut extrage text sau coduri QR verificabile din imagine. Reîncearcă cu o captură mai clară."
                }
                publishImageExtractionIncomplete(
                    fileName = fileName,
                    reason = reason
                )
            }
        } finally {
            file?.delete()
            loading = false
        }
    }
}

internal suspend fun ScannerViewModel.runLocalImageOcrScanIfPossible(uri: Uri, context: Context): Boolean {
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

internal fun ScannerViewModel.publishImageExtractionIncomplete(fileName: String, reason: String) {
    val result = localUnverifiedAssessment(
        current = OfflineAssessment(
            family = "Scanare incompletă",
            riskScore = 0,
            riskLevel = "unknown",
            reasons = listOf(reason),
            safeActions = listOf("Reîncearcă scanarea cu o imagine mai clară sau copiază textul/linkul în câmpul de scanare."),
            keyDangers = listOf("Nu avem suficiente dovezi tehnice pentru verdict."),
            originalText = "Nu s-a extras conținut verificabil din $fileName."
        ),
        reasonCode = "LOCAL_IMAGE_OCR_INCOMPLETE",
        inputKind = "upload_image",
        channel = "image_ocr"
    )
    publishAssessmentResult(null, result)
}
