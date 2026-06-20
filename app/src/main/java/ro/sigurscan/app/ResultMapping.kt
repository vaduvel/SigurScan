package ro.sigurscan.app

import android.Manifest
import android.app.role.RoleManager
import android.content.Intent
import android.content.Context
import android.graphics.BitmapFactory
import android.net.Uri
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS
import android.text.Html
import android.text.Spanned
import android.util.Log
import android.view.ViewGroup.LayoutParams
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.annotation.OptIn as AndroidxOptIn
import androidx.camera.core.Camera
import androidx.camera.core.CameraSelector
import androidx.camera.core.ExperimentalGetImage
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview as CameraPreview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.border
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.ui.draw.clip
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material.icons.filled.*
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalUriHandler
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.em
import androidx.compose.ui.unit.sp
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.viewinterop.AndroidView
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import androidx.compose.ui.platform.LocalLifecycleOwner
import coil.compose.SubcomposeAsyncImage
import ro.sigurscan.app.ui.theme.SigurScanTheme
import ro.sigurscan.app.ui.theme.SigurColors
import org.json.JSONArray
import org.json.JSONObject
import android.webkit.WebResourceRequest
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.BarcodeScannerOptions
import com.google.mlkit.vision.common.InputImage
import java.text.SimpleDateFormat
import java.io.File
import java.util.*
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.math.max
import kotlin.math.min
import kotlin.math.pow

internal data class UserActionDecision(
    val headline: String,
    val supportText: String,
    val nextBestAction: String
)

internal fun mapUserActionDecision(assessment: OfflineAssessment, riskUi: RiskDisplayState): UserActionDecision {
    assessment.gateResult?.let { gateResult ->
        return UserActionDecision(
            headline = GateResultPresentation.userHeadline(gateResult),
            supportText = GateResultPresentation.supportText(gateResult),
            nextBestAction = GateResultPresentation.primaryAction(gateResult)
        )
    }

    val normalizedText = assessment.originalText.lowercase(Locale.getDefault())
    val asksForSensitiveData = containsAny(
        normalizedText,
        listOf("card", "cvv", "cvc", "otp", "parola", "pin", "iban", "cod")
    )
    val looksLikeEmail = assessment.emailAuth != null || containsAny(
        normalizedText,
        listOf("from:", "subject:", "reply-to:", "expeditor", "subiect")
    )

    return when (riskUi.level) {
        "Periculos" -> UserActionDecision(
            headline = when {
                asksForSensitiveData -> "Nu introduce date"
                looksLikeEmail -> "Nu răspunde"
                else -> "Nu continua"
            },
            supportText = "Am găsit semnale puternice de risc. Verifică direct în aplicația sau pe site-ul oficial.",
            nextBestAction = if (asksForSensitiveData) {
                "Nu trimite parole, coduri OTP sau date de card."
            } else {
                "Deschide manual site-ul oficial, nu linkul primit."
            }
        )
        "Suspect" -> UserActionDecision(
            headline = "Suspect",
            supportText = "Am găsit semnale neclare. Verifică direct în aplicația sau pe site-ul oficial.",
            nextBestAction = "Intră manual în aplicația sau site-ul oficial, fără să apeși linkul primit."
        )
        else -> UserActionDecision(
            headline = "Sigur",
            supportText = "Scanarea a verificat destinația și nu a găsit semnale clare de risc.",
            nextBestAction = "Poți continua."
        )
    }
}

internal fun buildTopReasons(assessment: OfflineAssessment, decision: UserActionDecision): List<String> {
    val gateReason = assessment.gateResult?.let {
        GateResultPresentation.reasonText(it, assessment.evidenceSnapshot)
    }
    return (listOfNotNull(gateReason) + assessment.reasons + assessment.keyDangers)
        .map { it.trim() }
        .filter { it.isNotBlank() }
        .distinct()
        .take(2)
        .ifEmpty { listOf(decision.supportText) }
}

internal fun buildNextActions(assessment: OfflineAssessment, decision: UserActionDecision): List<String> {
    val gateActions = assessment.gateResult?.let {
        listOf(GateResultPresentation.primaryAction(it)) + GateResultPresentation.recommendedActions(it)
    } ?: listOf(decision.nextBestAction)
    return (gateActions + assessment.safeActions)
        .map { it.trim() }
        .filter { it.isNotBlank() }
        .distinct()
        .take(3)
}

internal fun displayDomainFrom(url: String?): String? {
    if (url.isNullOrBlank()) return null
    val normalizedUrl = if (url.startsWith("http://", true) || url.startsWith("https://", true)) {
        url
    } else {
        "https://$url"
    }
    return runCatching { Uri.parse(normalizedUrl).host?.removePrefix("www.") }
        .getOrNull()
        ?.takeIf { it.isNotBlank() }
        ?: url.take(64)
}

internal fun containsAny(input: String, needles: List<String>): Boolean {
    return needles.any { input.contains(it) }
}

internal data class RiskDisplayState(val level: String, val label: String, val color: Color)

internal fun mapRiskDisplayState(assessment: OfflineAssessment): RiskDisplayState {
    return assessment.gateResult?.let { mapGateDisplayState(it) }
        ?: mapRiskDisplayState(assessment.riskLevel)
}

internal fun mapGateDisplayState(result: GateResult): RiskDisplayState {
    if (GateResultPresentation.isScanInProgress(result)) {
        return RiskDisplayState(
            level = "Se verifică...",
            label = "Se verifică...",
            color = SigurColors.Pending
        )
    }
    if (GateResultPresentation.isFinalUnverified(result) || GateResultPresentation.isVerificationUnavailable(result)) {
        return RiskDisplayState(
            level = "Neverificat",
            label = "Neverificat",
            color = SigurColors.Pending
        )
    }
    return mapGateDisplayState(result.action)
}

internal fun mapGateDisplayState(action: GateAction): RiskDisplayState = when (action) {
    GateAction.DO_NOT_CONTINUE,
    GateAction.NO_ENTER_DATA,
    GateAction.NO_REPLY -> RiskDisplayState(
        level = "Periculos",
        label = "Periculos",
        color = SigurColors.Dangerous
    )
    GateAction.VERIFY_OFFICIAL -> RiskDisplayState(
        level = "Suspect",
        label = "Suspect",
        color = SigurColors.Suspect
    )
    GateAction.CONTINUE_WITH_CAUTION -> RiskDisplayState(
        level = "Sigur",
        label = "Sigur",
        color = SigurColors.Safe
    )
    GateAction.UNVERIFIED -> RiskDisplayState(
        level = "Neverificat",
        label = "Neverificat",
        color = SigurColors.Pending
    )
    GateAction.INSUFFICIENT_EVIDENCE -> RiskDisplayState(
        level = "Suspect",
        label = "Suspect",
        color = SigurColors.Suspect
    )
}

internal fun mapRiskDisplayState(level: String): RiskDisplayState {
    return when (level.lowercase(Locale.getDefault())) {
        "high", "critical", "dangerous", "high_risk" -> RiskDisplayState(
            level = "Periculos",
            label = "Periculos",
            color = SigurColors.Dangerous
        )
        "medium", "suspicious", "warn", "warning" -> RiskDisplayState(
            level = "Suspect",
            label = "Suspect",
            color = SigurColors.Suspect
        )
        "error" -> RiskDisplayState(
            level = "Suspect",
            label = "Suspect",
            color = SigurColors.Suspect
        )
        "info", "unknown", "unverified" -> RiskDisplayState(
            level = "Neverificat",
            label = "Neverificat",
            color = SigurColors.Pending
        )
        "low", "safe", "none" -> RiskDisplayState(
            level = "Sigur",
            label = "Sigur",
            color = SigurColors.Safe
        )
        else -> RiskDisplayState(
            level = "Suspect",
            label = "Suspect",
            color = SigurColors.Suspect
        )
    }
}

internal fun gateStatusText(result: GateResult?): String {
    return when {
        result == null -> "Scanare pregătită"
        result.asyncExpected || result.finality == GateFinality.PROVISIONAL -> "Se verifică..."
        else -> "Verdict finalizat"
    }
}

internal fun resultIconFor(action: GateAction?, level: String): ImageVector {
    if (level == "Se verifică...") return Icons.Default.HourglassEmpty
    return when (action) {
        GateAction.DO_NOT_CONTINUE,
        GateAction.NO_ENTER_DATA,
        GateAction.NO_REPLY -> Icons.Default.Warning
        GateAction.VERIFY_OFFICIAL -> Icons.Default.Info
        GateAction.CONTINUE_WITH_CAUTION -> Icons.Default.CheckCircle
        GateAction.UNVERIFIED -> Icons.Default.Info
        GateAction.INSUFFICIENT_EVIDENCE -> Icons.Default.ReportProblem
        null -> when (level) {
            "Periculos" -> Icons.Default.Warning
            "Sigur" -> Icons.Default.CheckCircle
            else -> Icons.Default.Info
        }
    }
}
