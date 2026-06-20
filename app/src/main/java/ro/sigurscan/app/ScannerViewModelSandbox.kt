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

// Sandbox (urlscan) analysis: triggering backend/urlscan sandbox runs, polling the result,
// applying threat-intel updates and stabilizing screenshots — extracted from the
// ScannerViewModel God object as behaviour-preserving extension functions.

internal fun ScannerViewModel.triggerSandboxAnalysis(url: String, scanId: String? = assessment?.scanId) {
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
                country = ScannerViewModel.URLSCAN_PERSONA_COUNTRY,
                customAgent = ScannerViewModel.URLSCAN_MOBILE_ANDROID_AGENT
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
                    country = ScannerViewModel.URLSCAN_PERSONA_COUNTRY,
                    customAgent = ScannerViewModel.URLSCAN_MOBILE_ANDROID_AGENT
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

internal suspend fun ScannerViewModel.tryBackendSandboxAnalysis(url: String, scanId: String): Boolean {
    return try {
        val submitted = api.submitUrlscanSandbox(
            UrlscanSandboxSubmitRequest(
                url = url,
                visibility = "private",
                country = ScannerViewModel.URLSCAN_PERSONA_COUNTRY,
                customagent = ScannerViewModel.URLSCAN_MOBILE_ANDROID_AGENT,
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

internal suspend fun ScannerViewModel.applySandboxThreatIntelUpdate(
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

internal fun ScannerViewModel.downloadUrlscanScreenshot(uuid: String, client: OkHttpClient): String? {
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

internal fun ScannerViewModel.downloadSandboxScreenshotProxy(screenshotUrl: String?): String? {
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

internal fun ScannerViewModel.scheduleSandboxScreenshotRefresh(scanId: String, screenshotUrl: String) {
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
