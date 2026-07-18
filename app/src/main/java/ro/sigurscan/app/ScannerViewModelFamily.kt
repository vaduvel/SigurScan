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
import kotlin.math.max
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.coroutines.suspendCoroutine
import retrofit2.HttpException

// Domain logic extracted from the ScannerViewModel God object into cohesive extension
// functions. Behaviour is identical; the ViewModel keeps the observable state, while
// these functions operate on it. prefs/gson/api are module-internal on the ViewModel.

internal fun ScannerViewModel.loadFamilyState() {
    val rawMembers = prefs.getString("family_members_state", null)
    if (rawMembers != null) {
        val memberType = object : TypeToken<List<FamilyMember>>() {}.type
        runCatching {
            val members: List<FamilyMember> = gson.fromJson(rawMembers, memberType)
            familyMembers.clear()
            familyMembers.addAll(members)
        }
    }

    val rawAlerts = prefs.getString("family_alerts_state", null)
    if (rawAlerts != null) {
        val alertType = object : TypeToken<List<FamilyAlert>>() {}.type
        runCatching {
            val alerts: List<FamilyAlert> = gson.fromJson(rawAlerts, alertType)
            familyAlerts.clear()
            familyAlerts.addAll(alerts)
        }
    }

}

internal fun ScannerViewModel.saveFamilyState() {
    val memberType = object : TypeToken<List<FamilyMember>>() {}.type
    val alertType = object : TypeToken<List<FamilyAlert>>() {}.type
    prefs.edit().putString("family_members_state", gson.toJson(familyMembers.toList(), memberType)).apply()
    prefs.edit().putString("family_alerts_state", gson.toJson(familyAlerts.toList(), alertType)).apply()
}

internal fun familyProtectionSummary(members: List<FamilyMember>): String =
    if (members.isEmpty()) {
        "Protecția familiei nu este configurată."
    } else {
        val protectedMembers = members.count { it.isProtected }
        "Protecție activă pentru $protectedMembers din ${members.size} membri."
    }

fun ScannerViewModel.addFamilyMember(name: String, contact: String) {
    if (name.isBlank() || contact.isBlank()) return
    val normalizedContact = contact.trim()
    if (familyMembers.any { it.contact.equals(normalizedContact, ignoreCase = true) }) return

    familyMembers.add(0, FamilyMember(name = name.trim(), contact = normalizedContact))
    saveFamilyState()
}

fun ScannerViewModel.removeFamilyMember(memberId: String) {
    val removed = familyMembers.removeAll { it.id == memberId }
    if (removed) {
        familyAlerts.removeAll { it.memberId == memberId }
    }
    saveFamilyState()
}

fun ScannerViewModel.toggleFamilyProtection(memberId: String, isProtected: Boolean) {
    val updated = familyMembers.map { if (it.id == memberId) it.copy(isProtected = isProtected) else it }
    familyMembers.clear()
    familyMembers.addAll(updated)
    saveFamilyState()
}

fun ScannerViewModel.notifyFamilyForCurrentScan() {
    val current = assessment ?: return
    if (familyMembers.isEmpty()) return
    val enabled = familyMembers.filter { it.isProtected }
    if (enabled.isEmpty()) return
    val currentAlerts = familyAlerts.toList()

    val familyName = current.family.ifBlank { "Scam suspect" }
    val riskLevel = current.riskLevel.ifBlank { "low" }
    val snapshot = current.reasons.take(1).firstOrNull() ?: "Risc detectat pe mesajul curent."

    familyAlerts.clear()
    familyAlerts.addAll(
        enabled.map { member ->
            FamilyAlert(
                memberId = member.id,
                memberName = member.name,
                triggerLabel = "alerta noua",
                family = familyName,
                riskLevel = riskLevel,
                snapshot = snapshot
            )
        } + currentAlerts
    )
    if (familyAlerts.size > 12) {
        while (familyAlerts.size > 12) {
            familyAlerts.removeAt(familyAlerts.size - 1)
        }
    }
    saveFamilyState()
}

fun ScannerViewModel.clearFamilyAlerts() {
    familyAlerts.clear()
    saveFamilyState()
}
