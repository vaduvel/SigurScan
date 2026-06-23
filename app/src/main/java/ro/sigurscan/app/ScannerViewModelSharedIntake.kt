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

// Shared-content intake: staging shared text/files, dispatching pending scans, and the
// SEND / ACTION_VIEW / file-picker entry points — extracted from the ScannerViewModel God
// object as behaviour-preserving extension functions.

fun ScannerViewModel.stageSharedTextPayload(
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

fun ScannerViewModel.stageSharedFile(
    uri: Uri,
    context: Context,
    sourceLabel: String,
    fallbackMime: String = "",
    preserveSharedTextState: Boolean = false
) {
    if (uri.toString().isBlank()) return

    val fileName = runCatching {
        getFileName(uri, context)
    }.getOrElse { "document" }

    val resolverMime = runCatching {
        context.contentResolver.getType(uri)
    }.getOrElse { "" }
    val mime = resolveSharedMimeType(
        resolverMime = resolverMime,
        fallbackMime = fallbackMime,
        fileName = fileName
    )

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

fun ScannerViewModel.clearPendingSharedFiles() {
    pendingSharedFiles = emptyList()
}

fun ScannerViewModel.clearPendingSharedInput() {
    pendingSharedInput = null
    pendingSharedSourceLabel = "Conținut partajat"
}

fun ScannerViewModel.clearAllPendingShared() {
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

fun ScannerViewModel.clearSharedContentStatus() {
    sharedContentFidelity = null
    sharedContentSourceLabel = "Conținut partajat"
}

fun ScannerViewModel.removePendingSharedFile(fileId: String) {
    pendingSharedFiles = pendingSharedFiles.filterNot { it.id == fileId }
}

fun ScannerViewModel.scanPendingSharedFile(fileId: String, context: Context) {
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

fun ScannerViewModel.scanPendingSharedText() {
    val pending = pendingSharedInput
    pendingSharedInput = null
    if (text.isBlank()) text = pending.orEmpty()
    onScanClick()
}

fun ScannerViewModel.onSharedTextPayload(payload: String, mimeType: String? = null) {
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

fun ScannerViewModel.onFilePicked(uri: Uri, context: Context) {
    clearVisibleResultForNewScan()
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
        assessment = localUnverifiedAssessment(
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
            reasonCode = "LOCAL_FILE_UNSUPPORTED",
            inputKind = "import_unsupported_file",
            channel = "file_import"
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
                loading = false
                loadingMsg = ""
                onScanClick()
            } catch (e: Exception) {
                text = "Eroare la citirea textului: $fileName"
                stagedEvidenceHtml = null
                stagedEvidenceLinks = emptyList()
                stagedEvidenceText = text
                stagedEvidenceInputKind = "import_text_file"
                stagedEvidenceChannel = "text_file"
                loading = false
                loadingMsg = ""
                onScanClick()
            }
        }
        return
    }

    if (importKind == FileImportKind.EMAIL) {
        // Email scan verifies sender headers (SPF/DKIM/DMARC) FIRST, then body text,
        // then links. The header pillar needs the raw RFC822 headers, so we send the
        // .eml to /v1/extract/email (which returns email_auth) and route through the
        // orchestrated extraction path that threads that auth into the verdict.
        loading = true
        loadingMsg = "Verificăm expeditorul, textul și linkurile..."
        viewModelScope.launch {
            var file: File? = null
            try {
                file = uriToFile(uri, context, ScannerViewModel.MAX_UPLOAD_BYTES)
                val requestFile = file.asRequestBody("message/rfc822".toMediaTypeOrNull())
                val body = MultipartBody.Part.createFormData(
                    "email_file",
                    fileName.ifBlank { "email.eml" },
                    requestFile
                )
                val source = "android_email_upload".toRequestBody("text/plain".toMediaTypeOrNull())
                val response = uploadApi.extractEmail(body, source)
                runBackendOrchestratedScanFromExtraction(
                    response = response,
                    fileName = fileName,
                    inputKind = "import_email",
                    channel = "email_file"
                )
            } catch (e: Exception) {
                // Backend unreachable / invalid .eml: fall back to local parse
                // (no sender-auth pillar, but text + links still verified).
                runCatching {
                    val rawContent = readTextFromUri(uri, context)
                    val parsedEmail = EmailMessageParser.parse(rawContent)
                    val htmlContentSource = parsedEmail.htmlText.ifBlank { rawContent }
                    val visibleMailText = parsedEmail.bodyForAnalysis.ifBlank { rawContent }
                    val allLinks = (extractHtmlLinks(htmlContentSource) + extractUrls(rawContent))
                        .distinct().filter { it.isNotBlank() }
                    val finalText = MailShareInputAssembler.buildMailScanInput(
                        sanitizeSharedText(visibleMailText), allLinks, fileName
                    )
                    text = finalText
                    stagedEvidenceHtml = htmlContentSource
                    stagedEvidenceLinks = allLinks
                    stagedEvidenceText = finalText
                    stagedEvidenceInputKind = "import_email"
                    stagedEvidenceChannel = "email_file"
                    loading = false
                    loadingMsg = ""
                    onScanClick()
                }.onFailure {
                    text = "Eroare la citirea conținutului: $fileName"
                    stagedEvidenceHtml = null
                    stagedEvidenceLinks = emptyList()
                    stagedEvidenceText = text
                    stagedEvidenceInputKind = "import_email"
                    stagedEvidenceChannel = "email_file"
                    loading = false
                    loadingMsg = ""
                    onScanClick()
                }
            } finally {
                file?.delete()
                loading = false
                loadingMsg = ""
            }
        }
        return
    }

    if (importKind == FileImportKind.HTML) {
        loading = true
        loadingMsg = "Analizăm conținutul HTML..."

        viewModelScope.launch {
            try {
                val rawContent = readTextFromUri(uri, context)
                val extractedHtmlLinks = extractHtmlLinks(rawContent)
                val extractedUrls = extractUrls(rawContent)
                val visibleText = sanitizeSharedText(rawContent)
                val allLinks = (extractedHtmlLinks + extractedUrls).distinct().filter { it.isNotBlank() }
                val finalText = MailShareInputAssembler.buildMailScanInput(visibleText, allLinks, fileName)
                text = finalText
                stagedEvidenceHtml = rawContent
                stagedEvidenceLinks = allLinks
                stagedEvidenceText = finalText
                stagedEvidenceInputKind = "import_html"
                stagedEvidenceChannel = "html_file"
                loading = false
                loadingMsg = ""
                onScanClick()
            } catch (e: Exception) {
                text = "Eroare la citirea conținutului: $fileName"
                stagedEvidenceHtml = null
                stagedEvidenceLinks = emptyList()
                stagedEvidenceText = text
                stagedEvidenceInputKind = "import_html"
                stagedEvidenceChannel = "html_file"
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
            val maxMb = ScannerViewModel.MAX_UPLOAD_BYTES / (1024L * 1024L)
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
            file = uriToFile(uri, context, ScannerViewModel.MAX_UPLOAD_BYTES)
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
                val maxMb = ScannerViewModel.MAX_UPLOAD_BYTES / (1024L * 1024L)
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
            }.getOrNull() ?: ScannerViewModel.PdfFallbackExtraction("", emptySet())

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
                loading = false
                loadingMsg = ""
                onScanClick()
            } else {
                assessment = localUnverifiedAssessment(
                    current = OfflineAssessment(
                        family = "Scanare incompletă",
                        riskScore = 0,
                        riskLevel = "unknown",
                        reasons = listOf("Nu s-a putut analiza cloud, iar OCR-ul nu a extras text verificabil din PDF."),
                        safeActions = listOf("Reîncearcă scanarea sau trimite un PDF cu text/linkuri detectabile."),
                        keyDangers = listOf("Nu avem suficiente dovezi tehnice pentru verdict."),
                        originalText = "Eroare la analiza locală a documentului PDF."
                    ),
                    reasonCode = "LOCAL_PDF_EXTRACTION_INCOMPLETE",
                    inputKind = "import_pdf",
                    channel = "pdf_ocr"
                )
            }
        } finally {
            file?.delete()
            loading = false
        }
    }
}

internal fun ScannerViewModel.publishAudioShareRequiresTranscript(fileName: String) {
    val reason = "Audio primit. Transcrierea audio nu este activă încă; poți lipi transcriptul."
    stagedEvidenceHtml = null
    stagedEvidenceLinks = emptyList()
    stagedEvidenceText = null
    stagedEvidenceInputKind = "import_audio_file"
    stagedEvidenceChannel = "audio_share"
    text = ""
    assessment = localUnverifiedAssessment(
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
        reasonCode = "LOCAL_AUDIO_TRANSCRIPTION_REQUIRED",
        inputKind = "import_audio_file",
        channel = "audio_share"
    )
    loading = false
    loadingMsg = ""
}

internal fun ScannerViewModel.getFileName(uri: Uri, context: Context): String {
    var name = ""
    val cursor = runCatching {
        context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)
    }.getOrNull()
    cursor?.use {
        if (it.moveToFirst()) {
            val nameIndex = it.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (nameIndex != -1) name = it.getString(nameIndex).orEmpty()
        }
    }
    if (name.isNotBlank()) return name
    return Uri.decode(uri.lastPathSegment.orEmpty())
        .substringAfterLast('/')
        .substringBefore('?')
        .ifBlank { "document" }
}
