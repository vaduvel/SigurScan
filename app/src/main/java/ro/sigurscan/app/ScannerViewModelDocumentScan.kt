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

// Invoice/offer document scanning + OCR text extraction, extracted from the
// ScannerViewModel God object as behaviour-preserving extension functions.

fun ScannerViewModel.scanInvoiceFromDocument(
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
    lastInvoiceScanSource = ScannerViewModel.PendingInvoiceScanSource(uri = uri, officialXmlUri = officialXmlUri)

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
            file = if (isPdf) {
                uriToFile(uri, context, ScannerViewModel.MAX_UPLOAD_BYTES)
            } else {
                prepareInvoiceImageUpload(uri, context, ScannerViewModel.MAX_IMAGE_UPLOAD_BYTES)
            }
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
                val xmlFile = uriToFile(xmlUri, context, ScannerViewModel.MAX_UPLOAD_BYTES)
                officialXmlFile = xmlFile
                val xmlRequest = xmlFile.asRequestBody(
                    (xmlMimeType.ifBlank { "application/xml" }).toMediaTypeOrNull()
                )
                MultipartBody.Part.createFormData("official_xml_file", xmlFileName, xmlRequest)
            }

            val paymentCasePart = paymentCaseActive.toString()
                .toRequestBody("text/plain".toMediaTypeOrNull())
            val response = uploadApi.scanInvoice(body, source, officialPart, sanbPart, paymentCasePart)
            attachPaymentCaseArtifact(response.paymentCaseArtifactRef)
            invoiceResult = response
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

fun ScannerViewModel.submitInvoiceBeneficiaryAttestation(attestation: String, context: Context) {
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

fun ScannerViewModel.scanOfferFromDocument(uri: Uri, context: Context) {
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
                file = uriToFile(uri, context, ScannerViewModel.MAX_UPLOAD_BYTES)
                val (uploadMime, uploadName) = resolveImageUploadMeta(uri, context)
                val requestFile = file.asRequestBody(uploadMime.toMediaTypeOrNull())
                val body = MultipartBody.Part.createFormData("image_file", uploadName, requestFile)
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
                file = uriToFile(uri, context, ScannerViewModel.MAX_UPLOAD_BYTES)
                val requestFile = file.asRequestBody("application/pdf".toMediaTypeOrNull())
                val body = MultipartBody.Part.createFormData("pdf_file", file.name, requestFile)
                val source = "android_offer_pdf_upload".toRequestBody("text/plain".toMediaTypeOrNull())
                val response = runCatching { uploadApi.extractPdf(body, source) }.getOrElse {
                    loadingMsg = "Extragem local textul din PDF..."
                    val fallback = runCatching { extractTextFromPdfFallback(uri, context) }.getOrNull()
                        ?: ScannerViewModel.PdfFallbackExtraction("", emptySet())
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

internal suspend fun ScannerViewModel.runOfferScanFromExtractedText(
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

internal fun ScannerViewModel.stageOfferConfirmationFromExtraction(
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

internal fun ScannerViewModel.stageOfferConfirmationFromExtractedText(
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

fun ScannerViewModel.cancelOfferConfirmation() {
    pendingOfferConfirmation = null
    loading = false
    loadingMsg = ""
}

fun ScannerViewModel.confirmOfferAndScan(fields: OfferConfirmationFields) {
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

internal fun ScannerViewModel.normalizeOfferLinks(
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

internal fun ScannerViewModel.inferOfferConfirmationFields(rawText: String): OfferConfirmationFields {
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

internal fun ScannerViewModel.firstRegexGroup(text: String, regex: Regex): String? {
    return regex.find(text)?.groupValues?.getOrNull(1)?.trim()?.takeIf { it.isNotBlank() }
}

internal fun ScannerViewModel.buildConfirmedOfferInput(
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

internal fun ScannerViewModel.publishOfferExtractionIncomplete(fileName: String, reason: String) {
    val result = localUnverifiedAssessment(
        current = OfflineAssessment(
            family = "Ofertă neverificată",
            riskScore = 0,
            riskLevel = "info",
            reasons = listOf(reason),
            safeActions = listOf("Reîncearcă cu o poză mai clară, un PDF cu text sau copiază oferta în câmpul de scanare."),
            keyDangers = emptyList(),
            originalText = "Nu s-a extras conținut verificabil din $fileName."
        ),
        reasonCode = "LOCAL_OFFER_EXTRACTION_INCOMPLETE"
    )
    publishAssessmentResult(null, result)
}

internal suspend fun ScannerViewModel.extractTextFromBitmap(bitmap: Bitmap): String = extractTextFromImage(InputImage.fromBitmap(bitmap, 0))

internal suspend fun ScannerViewModel.extractTextFromImage(image: InputImage): String = suspendCoroutine { continuation ->
    recognizer.process(image)
        .addOnSuccessListener { result ->
            continuation.resume(result.text)
        }
        .addOnFailureListener { continuation.resumeWithException(it) }
}

internal suspend fun ScannerViewModel.extractTextFromPdfFallback(uri: Uri, context: Context): ScannerViewModel.PdfFallbackExtraction = withContext(Dispatchers.IO) {
    val annotationLinks = runCatching {
        context.contentResolver.openInputStream(uri)?.use { input ->
            PdfLinkExtractor.extractPdfAnnotationLinks(input.readBytes())
        } ?: emptySet()
    }.getOrNull() ?: emptySet()
    val descriptor: ParcelFileDescriptor = context.contentResolver.openFileDescriptor(uri, "r")
        ?: return@withContext ScannerViewModel.PdfFallbackExtraction(
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

        return@withContext ScannerViewModel.PdfFallbackExtraction(
            extractedText = textFromOcr,
            extractedLinks = extractedLinks
        )
    }
}
