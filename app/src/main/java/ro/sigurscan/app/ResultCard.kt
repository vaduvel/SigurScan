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

@Preview(showBackground = true, backgroundColor = 0xFF0B0F19)
@Composable
fun EvidenceSectionPreview() {
    SigurScanTheme {
        Column(modifier = Modifier.padding(16.dp)) {
            EvidenceSection(
                screenshotUrl = null,
                serverInfo = "Preview disponibil pentru pagina finală.",
                finalUrl = "https://exemplu.invalid"
            )
        }
    }
}

@Composable
fun ResultCard(
    assessment: OfflineAssessment,
    onBack: () -> Unit,
    onRescan: () -> Unit,
    onReport: () -> Unit,
    officialReportPackage: OneTapReportPackage? = null,
    officialReportLoading: Boolean = false,
    officialReportStatus: String? = null,
    onOfficialReport: () -> Unit = {},
    onFeedback: (String) -> Unit,
    onFamilyAlert: () -> Unit = {},
    actionPlanLoading: Boolean = false,
    actionPlanStatus: String? = null,
    onActionPlanImpacts: (List<String>) -> Unit = {}
) {
    val riskUi = mapRiskDisplayState(assessment)
    val decision = mapUserActionDecision(assessment, riskUi)
    val finalDomain = displayDomainFrom(assessment.finalUrl)
    val topReasons = buildTopReasons(assessment, decision)
    val nextActions = buildNextActions(assessment, decision)
    val hasTechnicalDetails = assessment.threatIntel.isNotEmpty() ||
            assessment.emailAuth != null ||
            assessment.detectedButtons.isNotEmpty() ||
            assessment.redirectChain.isNotEmpty() ||
            assessment.finalUrl != null ||
            assessment.sandboxReportUrl != null

    var feedbackSent by remember { mutableStateOf(false) }
    var showTechnicalDetails by remember { mutableStateOf(false) }

    val hasRiskVerdict = riskUi.level == "Suspect" || riskUi.level == "Periculos"
    val verdictLightBg = when (riskUi.level) {
        "Sigur" -> SigurColors.SafeLight
        "Periculos" -> SigurColors.DangerousLight
        "Suspect" -> SigurColors.SuspectLight
        else -> SigurColors.PendingLight
    }
    val verdictBorder = when (riskUi.level) {
        "Sigur" -> SigurColors.SafeBorder
        "Periculos" -> SigurColors.DangerousBorder
        "Suspect" -> SigurColors.SuspectBorder
        else -> SigurColors.Pending.copy(alpha = 0.32f)
    }
    val isCheckingFurther = assessment.gateResult?.asyncExpected == true ||
        assessment.gateResult?.finality == GateFinality.PROVISIONAL

    Column(modifier = Modifier.fillMaxWidth()) {
        // VerdictCard — DS hero block (icon circle + title + subtitle + message)
        Card(
            colors = CardDefaults.cardColors(containerColor = verdictLightBg),
            shape = RoundedCornerShape(16.dp),
            modifier = Modifier
                .fillMaxWidth()
                .border(1.5.dp, verdictBorder, RoundedCornerShape(16.dp))
        ) {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier.fillMaxWidth().padding(20.dp)
            ) {
                Box(
                    modifier = Modifier
                        .size(56.dp)
                        .background(riskUi.color, CircleShape),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = resultIconFor(assessment.gateResult?.action, riskUi.level),
                        contentDescription = null,
                        tint = Color.White,
                        modifier = Modifier.size(30.dp)
                    )
                }
                Spacer(modifier = Modifier.height(14.dp))
                Text(
                    text = decision.headline.uppercase(Locale.getDefault()),
                    fontSize = 24.sp,
                    fontWeight = FontWeight.Bold,
                    letterSpacing = 0.04.em,
                    color = riskUi.color,
                    textAlign = TextAlign.Center
                )
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = decision.supportText,
                    color = SigurColors.TextSecondary,
                    fontSize = 16.sp,
                    lineHeight = 24.sp,
                    textAlign = TextAlign.Center
                )
                if (isCheckingFurther) {
                    Spacer(modifier = Modifier.height(12.dp))
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        modifier = Modifier
                            .background(SigurColors.BackgroundCard, RoundedCornerShape(12.dp))
                            .padding(horizontal = 16.dp, vertical = 8.dp)
                    ) {
                        CircularProgressIndicator(
                            color = SigurColors.Pending,
                            strokeWidth = 2.dp,
                            modifier = Modifier.size(16.dp)
                        )
                        Text(
                            text = "Verificare suplimentară în curs",
                            color = SigurColors.Pending,
                            fontSize = 14.sp,
                            fontWeight = FontWeight.SemiBold
                        )
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

    Card(
        colors = CardDefaults.cardColors(containerColor = SigurColors.BackgroundCard),
        shape = RoundedCornerShape(16.dp),
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, SigurColors.GlassBorder, RoundedCornerShape(16.dp))
    ) {
        Column(modifier = Modifier.padding(20.dp)) {

            GateEvidenceSummary(assessment, riskUi)

            EvidenceSection(assessment.screenshotUrl, assessment.serverInfo, assessment.finalUrl)

            finalDomain?.let { domain ->
                Card(
                    colors = CardDefaults.cardColors(containerColor = SigurColors.BackgroundSurface),
                    border = BorderStroke(1.dp, SigurColors.GlassBorder),
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp)
                ) {
                    Row(
                        modifier = Modifier.padding(12.dp).fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(Icons.Default.Link, contentDescription = null, tint = SigurColors.Brand, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(8.dp))
                        Column {
                            Text("Te duce către", color = SigurColors.TextMuted, fontSize = 11.sp)
                            Text(domain, color = SigurColors.TextPrimary, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                        }
                    }
                }
            }

            Text(
                text = "Clasificare: ${assessment.family}",
                color = SigurColors.TextMuted,
                fontSize = 11.sp,
                modifier = Modifier.padding(bottom = 4.dp)
            )

            assessment.offerEvidence?.let { offer ->
                OfferEvidenceSection(offer)
                Spacer(modifier = Modifier.height(12.dp))
            }

            ResultSection(title = "De ce spunem asta", items = topReasons, icon = Icons.AutoMirrored.Filled.List)

            if (assessment.offerAnalysis != null) {
                OfferAnalysisSection(assessment.offerAnalysis)
            }

            if (assessment.keyDangers.isNotEmpty() && hasRiskVerdict) {
                ResultSection(title = "Riscuri principale", items = assessment.keyDangers.take(3), icon = Icons.Default.Warning)
            }

            ResultSection(title = "Ce să faci acum", items = nextActions, icon = Icons.Default.CheckCircle)

            assessment.actionPlan?.let { plan ->
                ActionPlanSection(plan)
            }

            if (hasRiskVerdict) {
                PostIncidentImpactControls(
                    loading = actionPlanLoading,
                    status = actionPlanStatus,
                    onSubmit = onActionPlanImpacts
                )
            }

            officialReportPackage?.let { report ->
                OfficialReportPackageSection(report)
            }

            assessment.legal?.let { legal ->
                LegalEducationSection(legal)
            }

            Text(
                text = "SigurScan oferă o estimare automată de risc. Scamurile noi sau personalizate pot să nu fie detectate. Verifică datele importante direct pe site-ul sau în aplicația oficială.",
                color = SigurColors.TextMuted,
                fontSize = 10.sp,
                lineHeight = 14.sp,
                modifier = Modifier.padding(top = 8.dp)
            )

            if (hasTechnicalDetails) {
                TextButton(
                    onClick = { showTechnicalDetails = !showTechnicalDetails },
                    modifier = Modifier.fillMaxWidth().padding(top = 8.dp)
                ) {
                    Text(
                        text = if (showTechnicalDetails) "Ascunde detalii tehnice" else "Arată detalii tehnice",
                        color = SigurColors.Brand,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold
                    )
                }

                if (showTechnicalDetails) {
                    SincerityPillarsSection(assessment)

                    if (assessment.threatIntel.isNotEmpty()) {
                        ThreatIntelSection(assessment.threatIntel, assessment.sandboxReportUrl)
                    }

                    if (assessment.emailAuth != null) {
                        ComplianceSection(assessment.emailAuth)
                    }

                    if (assessment.detectedButtons.isNotEmpty()) {
                        ButtonsSection(assessment.detectedButtons)
                    }

                    RedirectChainSection(assessment.redirectChain, assessment.finalUrl)
                }
            }

            Spacer(modifier = Modifier.height(20.dp))

            // Feedback Section
            if (!feedbackSent) {
                Text(
                    "A fost util acest verdict?",
                    color = SigurColors.TextPrimary,
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.padding(bottom = 8.dp)
                )
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(
                        onClick = { onFeedback("correct"); feedbackSent = true },
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(containerColor = SigurColors.SafeLight),
                        border = BorderStroke(1.dp, SigurColors.SafeBorder)
                    ) {
                        Text("DA", color = SigurColors.Safe)
                    }
                    Button(
                        onClick = { onFeedback("false_positive"); feedbackSent = true },
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(containerColor = SigurColors.DangerousLight),
                        border = BorderStroke(1.dp, SigurColors.DangerousBorder)
                    ) {
                        Text("NU", color = SigurColors.Dangerous)
                    }
                }
                Spacer(modifier = Modifier.height(16.dp))
            } else {
                Text(
                    "Mulțumim pentru feedback! Împreună facem România mai sigură.",
                    color = SigurColors.Safe,
                    fontSize = 12.sp,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.fillMaxWidth().padding(bottom = 16.dp)
                )
            }

            Button(
                onClick = onFamilyAlert,
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = SigurColors.BrandTint),
                shape = RoundedCornerShape(10.dp),
                border = BorderStroke(1.dp, SigurColors.Brand)
            ) {
                Icon(Icons.Default.People, contentDescription = null, tint = SigurColors.Brand, modifier = Modifier.size(16.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text("Trimite alertă Familie", color = SigurColors.Brand, fontSize = 12.sp)
            }
            Spacer(modifier = Modifier.height(12.dp))

            if (hasRiskVerdict) {
                Button(
                    onClick = onOfficialReport,
                    enabled = !officialReportLoading,
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = SigurColors.SuspectLight),
                    shape = RoundedCornerShape(10.dp),
                    border = BorderStroke(1.dp, SigurColors.SuspectBorder)
                ) {
                    Icon(Icons.Default.AssignmentTurnedIn, contentDescription = null, tint = SigurColors.Suspect, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(if (officialReportLoading) "Se pregătește..." else "Pregătește raport oficial", color = SigurColors.Suspect, fontSize = 12.sp)
                }
                officialReportStatus?.takeIf { it.isNotBlank() }?.let {
                    Text(it, color = SigurColors.TextMuted, fontSize = 11.sp, modifier = Modifier.padding(top = 6.dp, bottom = 8.dp))
                }
                Spacer(modifier = Modifier.height(12.dp))
            }

            if (riskUi.level == "Periculos") {
                Button(
                    onClick = onReport,
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = SigurColors.SafeLight),
                    shape = RoundedCornerShape(10.dp),
                    border = BorderStroke(1.dp, SigurColors.SafeBorder)
                ) {
                    Icon(Icons.Default.Share, contentDescription = null, tint = SigurColors.Safe, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Raportează către comunitatea SigurScan", color = SigurColors.Safe, fontSize = 12.sp)
                }
                Spacer(modifier = Modifier.height(12.dp))
            }

            if (assessment.cacheStatus != null) {
                Button(
                    onClick = onRescan,
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = SigurColors.BrandTint),
                    shape = RoundedCornerShape(10.dp),
                    border = BorderStroke(1.dp, SigurColors.Brand)
                ) {
                    Icon(Icons.Default.Refresh, contentDescription = null, tint = SigurColors.Brand, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Rescanează acum", color = SigurColors.Brand, fontSize = 12.sp)
                }
                Spacer(modifier = Modifier.height(12.dp))
            }

            Button(
                onClick = onBack,
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = SigurColors.BackgroundSurface),
                shape = RoundedCornerShape(10.dp)
            ) {
                Text("Înapoi la scanare", color = SigurColors.TextPrimary)
            }
        }
    }
    }
}

@Composable
internal fun GateEvidenceSummary(assessment: OfflineAssessment, riskUi: RiskDisplayState) {
    val gateResult = assessment.gateResult ?: return
    val invoiceContext = GateResultPresentation.isInvoiceFamily(assessment.family)
    val snapshot = assessment.evidenceSnapshot
    val inProgress = GateResultPresentation.isScanInProgress(gateResult)
    val hasLocalPreview = assessment.screenshotUrl
        ?.trim()
        ?.startsWith("file://", ignoreCase = true) == true &&
        sandboxScreenshotModel(assessment.screenshotUrl) != null
    val hasUrlEvidence = GateResultPresentation.hasUrlEvidence(snapshot)
    val finalWithPreviewPending = !inProgress &&
        hasUrlEvidence &&
        snapshot?.completeness == EvidenceCompleteness.PARTIAL_ONLINE &&
        !hasLocalPreview
    val chips = listOfNotNull(
        if (inProgress) "Scanare în curs" else "Verdict final",
        if (assessment.cacheStatus != null) "Verificat anterior" else null,
        snapshot?.completeness?.let {
            when (it) {
                EvidenceCompleteness.FULL -> "Verificări complete"
                EvidenceCompleteness.PARTIAL_ONLINE -> when {
                    finalWithPreviewPending -> "Preview în curs"
                    hasUrlEvidence && !inProgress && hasLocalPreview -> "Preview disponibil"
                    !hasUrlEvidence -> "Verificări parțiale"
                    else -> "Se verifică linkul"
                }
                EvidenceCompleteness.LOCAL_ONLY -> "Mai trebuie informații"
            }
        }
    ).distinct()

    Card(
        colors = CardDefaults.cardColors(containerColor = riskUi.color.copy(alpha = 0.08f)),
        border = BorderStroke(1.dp, riskUi.color.copy(alpha = 0.22f)),
        shape = RoundedCornerShape(12.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Text(
                text = GateResultPresentation.primaryAction(gateResult, invoiceContext),
                color = SigurColors.TextPrimary,
                fontSize = 13.sp,
                fontWeight = FontWeight.SemiBold,
                lineHeight = 18.sp
            )
            if (chips.isNotEmpty()) {
                Spacer(modifier = Modifier.height(8.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    chips.take(3).forEach { chip ->
                        Surface(
                            color = SigurColors.BackgroundCard,
                            border = BorderStroke(1.dp, riskUi.color.copy(alpha = 0.18f)),
                            shape = RoundedCornerShape(999.dp)
                        ) {
                            Text(
                                text = chip,
                                color = SigurColors.TextSecondary,
                                fontSize = 10.sp,
                                fontWeight = FontWeight.SemiBold,
                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                            )
                        }
                    }
                }
            }
        }
    }
}
