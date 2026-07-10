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

internal fun ScannerViewModel.extractHtmlLinks(content: String): List<String> {
    if (content.isBlank()) return emptyList()
    return HtmlLinkExtractor.extractHtmlLinks(content, this::decodeHtmlForParser)
}

internal fun ScannerViewModel.decodeHtmlForParser(input: String): String {
    return Html.fromHtml(input, Html.FROM_HTML_MODE_LEGACY).toString()
}

internal fun ScannerViewModel.prepareInvoiceImageUpload(
    uri: Uri,
    context: Context,
    maxBytes: Long = ScannerViewModel.MAX_IMAGE_UPLOAD_BYTES
): File {
    val sourceSize = queryContentSize(uri, context)
    val normalized = runCatching { normalizeInvoiceImageToJpeg(uri, context, maxBytes) }.getOrNull()
    if (normalized != null && normalized.length() > 0L) {
        if (normalized.length() <= maxBytes) {
            return normalized
        }
        normalized.delete()
        throw UploadSizeExceededException("Imaginea facturii este prea mare pentru upload.")
    }
    if (sourceSize != null && sourceSize > maxBytes) {
        throw UploadSizeExceededException("Imaginea facturii este prea mare pentru upload.")
    }
    return uriToFile(uri, context, maxBytes)
}

internal fun ScannerViewModel.normalizeInvoiceImageToJpeg(
    uri: Uri,
    context: Context,
    maxBytes: Long = ScannerViewModel.MAX_IMAGE_UPLOAD_BYTES
): File? {
    val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
    val boundsStream = context.contentResolver.openInputStream(uri) ?: return null
    boundsStream.use { input ->
        BitmapFactory.decodeStream(input, null, bounds)
    }
    if (bounds.outWidth <= 0 || bounds.outHeight <= 0) return null

    val decodeOptions = BitmapFactory.Options().apply {
        inSampleSize = invoiceImageSampleSize(bounds.outWidth, bounds.outHeight)
        inPreferredConfig = Bitmap.Config.RGB_565
    }
    val bitmap = context.contentResolver.openInputStream(uri)?.use { input ->
        BitmapFactory.decodeStream(input, null, decodeOptions)
    } ?: return null

    val file = File(context.cacheDir, "${ScannerViewModel.TMP_UPLOAD_PREFIX}invoice_${System.currentTimeMillis()}.jpg")
    try {
        ByteArrayOutputStream().use { buffer ->
            if (!bitmap.compress(Bitmap.CompressFormat.JPEG, ScannerViewModel.INVOICE_IMAGE_JPEG_QUALITY, buffer)) {
                return null
            }
            val bytes = buffer.toByteArray()
            if (bytes.size.toLong() > maxBytes) {
                throw UploadSizeExceededException("Imaginea facturii este prea mare pentru upload.")
            }
            FileOutputStream(file).use { it.write(bytes) }
        }
        return file
    } catch (e: Exception) {
        file.delete()
        throw e
    } finally {
        bitmap.recycle()
    }
}

internal fun ScannerViewModel.invoiceImageSampleSize(width: Int, height: Int): Int {
    var sampleSize = 1
    var longest = max(width, height)
    while (longest / 2 >= ScannerViewModel.MAX_INVOICE_IMAGE_EDGE_PX) {
        sampleSize *= 2
        longest /= 2
    }
    return sampleSize
}

/**
 * Backendul (/v1/extract/image) acceptă uploadul doar dacă extensia SAU content-type-ul
 * sunt printre {jpg, jpeg, png, webp} / {image/jpeg, image/png, image/webp}. Fișierele
 * temporare nu au mereu extensie, iar un MIME wildcard nu e concret — trimitem MIME-ul
 * real + un nume cu extensie corectă (validatorul de magic-bytes acceptă oricare format).
 */
internal fun ScannerViewModel.resolveImageUploadMeta(uri: Uri, context: Context): Pair<String, String> {
    val rawMime = context.contentResolver.getType(uri)?.lowercase(Locale.ROOT)
    val mime = when (rawMime) {
        "image/png" -> "image/png"
        "image/webp" -> "image/webp"
        else -> "image/jpeg"
    }
    val ext = when (mime) {
        "image/png" -> ".png"
        "image/webp" -> ".webp"
        else -> ".jpg"
    }
    val baseName = getFileName(uri, context).substringBeforeLast('.', "image").ifBlank { "image" }
    return mime to "$baseName$ext"
}

internal fun ScannerViewModel.uriToFile(uri: Uri, context: Context, maxBytes: Long = ScannerViewModel.MAX_UPLOAD_BYTES): File {
    val file = File(context.cacheDir, "${ScannerViewModel.TMP_UPLOAD_PREFIX}${System.currentTimeMillis()}")
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

internal fun ScannerViewModel.cleanupLegacyTempUploads() {
    runCatching {
        val staleThresholdMs = 24L * 60L * 60L * 1000L
        val now = System.currentTimeMillis()
        getApplication<Application>().cacheDir.listFiles { file ->
            file.isFile && file.name.startsWith(ScannerViewModel.TMP_UPLOAD_PREFIX)
        }?.forEach { file ->
            if (now - file.lastModified() > staleThresholdMs) {
                file.delete()
            }
        }
    }
}

internal class UploadSizeExceededException(message: String) : IllegalArgumentException(message)

internal fun ScannerViewModel.isUploadSizeAllowed(uri: Uri, context: Context): Boolean {
    val sizeBytes = queryContentSize(uri, context) ?: return true
    return sizeBytes <= ScannerViewModel.MAX_UPLOAD_BYTES
}

internal fun ScannerViewModel.queryContentSize(uri: Uri, context: Context): Long? {
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

internal fun ScannerViewModel.readTextFromUri(uri: Uri, context: Context): String {
    context.contentResolver.openInputStream(uri)?.use { stream ->
        val reader = stream.bufferedReader(Charsets.UTF_8)
        return reader.use { it.readText() }
    }
    throw IllegalArgumentException("Nu se poate citi conținutul fișierului.")
}
