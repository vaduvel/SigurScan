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

fun ScannerViewModel.loadCampaigns() {
    if (campaignsLoading) return
    campaignsLoading = true
    campaignsLoadState = CampaignLoadState.LOADING
    viewModelScope.launch {
        try {
            val list = api.getCampaigns()
            campaigns.clear()
            campaigns.addAll(list)
            campaignsLoadState = CampaignLoadState.READY
        } catch (_: Exception) {
            campaignsLoadState = CampaignLoadState.ERROR
        } finally {
            campaignsLoading = false
        }
    }
}

fun ScannerViewModel.syncRadarHotCache() {
    if (radarHotCacheLoading) return
    radarHotCacheLoading = true
    radarHotCacheStatus = "Se sincronizează Radarul pentru apeluri."
    viewModelScope.launch {
        try {
            val response = api.getRadarHotIocs()
            val snapshot = RadarHotCacheSnapshot(
                generatedAtEpochMillis = System.currentTimeMillis(),
                ttlMinutes = response.ttlMinutes,
                hotCampaigns = response.hotCampaigns,
                numberReputation = response.numberReputation
            )
            radarHotCacheStore.save(snapshot)
            radarHotCache = snapshot
            radarHotCacheStatus = "Radar sincronizat: ${snapshot.hotCampaigns.size} campanii, ${snapshot.numberReputation.size} numere raportate."
        } catch (_: Exception) {
            radarHotCacheStatus = "Nu am putut sincroniza Radarul. Reîncearcă din aplicație."
        } finally {
            radarHotCacheLoading = false
        }
    }
}

fun ScannerViewModel.reportRadarPhoneNumber(rawPhone: String = radarReportPhoneInput) {
    if (radarReportPhoneLoading) return
    val normalizedPhone = PhoneNumberHasher.normalizePhoneNumber(rawPhone)
    val phoneDigits = normalizedPhone.count(Char::isDigit)
    if (normalizedPhone.isBlank() || phoneDigits !in 10..15) {
        radarReportPhoneStatus = "Introdu numărul primit, cu prefix dacă este din afara României."
        return
    }

    radarReportPhoneLoading = true
    radarReportPhoneStatus = "Raportăm doar amprenta numărului, nu numărul brut."
    viewModelScope.launch {
        try {
            api.sendCommunityReport(
                CommunityReport(
                    hash = PhoneNumberHasher.hashPhone(normalizedPhone),
                    riskLevel = "high",
                    family = "CONV_BANK_SAFE_ACCOUNT",
                    source = "android_radar_manual",
                    targetType = "phone"
                )
            )
            radarReportPhoneInput = ""
            radarReportPhoneStatus = "Numărul a fost raportat. Sincronizăm Radarul local."
            syncRadarHotCache()
        } catch (_: Exception) {
            radarReportPhoneStatus = "Nu am putut trimite raportul. Reîncearcă atunci când ai internet."
        } finally {
            radarReportPhoneLoading = false
        }
    }
}

fun ScannerViewModel.refreshRadarScreeningAudit() {
    radarScreeningAudit = radarScreeningAuditStore.load()
}

fun ScannerViewModel.syncBtrManifests() {
    if (btrSyncLoading) return
    btrSyncLoading = true
    btrSyncStatus = "Se sincronizează registrul oficial local."
    viewModelScope.launch {
        try {
            val currentVersion = btrSyncSnapshot?.version
            val response = api.getBtrSync(currentVersion)
            val snapshot = btrSyncStore.apply(response)
            btrSyncSnapshot = snapshot
            btrSyncStatus = if (response.changed) {
                "BTR sincronizat: ${snapshot?.manifests?.size ?: 0} manifeste oficiale."
            } else {
                "BTR este deja la zi: ${snapshot?.manifests?.size ?: 0} manifeste."
            }
        } catch (_: Exception) {
            btrSyncStatus = "Nu am putut sincroniza BTR. Reîncearcă din aplicație."
        } finally {
            btrSyncLoading = false
        }
    }
}
