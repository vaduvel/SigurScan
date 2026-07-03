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

private fun verdictToneFor(level: String): ro.sigurscan.app.ui.v2.theme.VerdictTone = when (level) {
    "Sigur" -> ro.sigurscan.app.ui.v2.theme.VerdictTone.SIGUR
    "Suspect" -> ro.sigurscan.app.ui.v2.theme.VerdictTone.SUSPECT
    "Periculos" -> ro.sigurscan.app.ui.v2.theme.VerdictTone.PERICULOS
    else -> ro.sigurscan.app.ui.v2.theme.VerdictTone.NEVERIFICAT // "Neverificat" and the transient "Se verifică..." state
}

private fun verdictReasonSeverityFor(level: String): ro.sigurscan.app.ui.v2.components.ReasonSeverity = when (level) {
    "Sigur" -> ro.sigurscan.app.ui.v2.components.ReasonSeverity.GOOD
    "Suspect", "Periculos" -> ro.sigurscan.app.ui.v2.components.ReasonSeverity.ALERT
    else -> ro.sigurscan.app.ui.v2.components.ReasonSeverity.NEUTRAL
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
    val tone = verdictToneFor(riskUi.level)
    val reasonSeverity = verdictReasonSeverityFor(riskUi.level)
    val isCheckingFurther = assessment.gateResult?.asyncExpected == true ||
        assessment.gateResult?.finality == GateFinality.PROVISIONAL

    Column(modifier = Modifier.fillMaxWidth()) {
        ro.sigurscan.app.ui.v2.components.VerdictCardV2(
            tone = tone,
            badgeLabel = riskUi.label.uppercase(Locale.getDefault()),
            title = decision.headline,
            subtitle = decision.supportText,
            headerIcon = resultIconFor(assessment.gateResult?.action, riskUi.level),
            reasons = topReasons.map { ro.sigurscan.app.ui.v2.components.VerdictReason(it, reasonSeverity) },
            extraHeaderContent = if (isCheckingFurther) {
                {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        modifier = Modifier
                            .fillMaxWidth()
                            .background(SigurColors.BackgroundCard)
                            .padding(horizontal = 17.dp, vertical = 10.dp)
                    ) {
                        CircularProgressIndicator(
                            color = SigurColors.Pending,
                            strokeWidth = 2.dp,
                            modifier = Modifier.size(14.dp)
                        )
                        Text(
                            text = "Verificare suplimentară în curs",
                            color = SigurColors.Pending,
                            fontSize = 12.5.sp,
                            fontWeight = FontWeight.SemiBold
                        )
                    }
                }
            } else null
        )

        Spacer(modifier = Modifier.height(12.dp))

        finalDomain?.let { domain ->
            ro.sigurscan.app.ui.v2.components.DestinationRowV2(
                icon = Icons.Default.Link,
                accent = riskUi.color,
                label = "Te duce către",
                value = domain
            )
            Spacer(modifier = Modifier.height(12.dp))
        }

    Card(
        colors = CardDefaults.cardColors(containerColor = SigurColors.BackgroundCard),
        shape = RoundedCornerShape(SigurColors.RadiusCard.dp),
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, SigurColors.GlassBorder, RoundedCornerShape(SigurColors.RadiusCard.dp))
    ) {
        Column(modifier = Modifier.padding(18.dp)) {

            GateEvidenceSummary(assessment, riskUi)

            EvidenceSection(assessment.screenshotUrl, assessment.serverInfo, assessment.finalUrl)

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

            if (assessment.offerAnalysis != null) {
                OfferAnalysisSection(assessment.offerAnalysis)
            }

            val keyDangersDeduped = assessment.keyDangers.filter {
                !it.trim().equals(decision.supportText.trim(), ignoreCase = true)
            }
            if (keyDangersDeduped.isNotEmpty() && hasRiskVerdict) {
                ResultSection(title = "Riscuri principale", items = keyDangersDeduped.take(3), icon = Icons.Default.Warning, accent = riskUi.color)
            }

            // The gate's primaryAction is already shown prominently in GateEvidenceSummary
            // above; don't repeat it verbatim as the first "next action" bullet too.
            val gatePrimaryAction = assessment.gateResult?.let { GateResultPresentation.primaryAction(it) }
            val nextActionsDeduped = if (gatePrimaryAction != null) {
                nextActions.filterIndexed { index, action -> index != 0 || !action.trim().equals(gatePrimaryAction.trim(), ignoreCase = true) }
            } else {
                nextActions
            }
            ResultSection(title = "Ce să faci acum", items = nextActionsDeduped, icon = Icons.Default.CheckCircle, accent = riskUi.color)

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
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.padding(bottom = 10.dp)
                )
                ro.sigurscan.app.ui.v2.components.FeedbackRowV2(
                    onYes = { onFeedback("correct"); feedbackSent = true },
                    onNo = { onFeedback("false_positive"); feedbackSent = true }
                )
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

            ro.sigurscan.app.ui.v2.components.SecondaryButtonV2(
                label = "Trimite alertă Familie",
                icon = Icons.Default.People,
                accent = SigurColors.Brand,
                onClick = onFamilyAlert
            )
            Spacer(modifier = Modifier.height(10.dp))

            if (hasRiskVerdict) {
                ro.sigurscan.app.ui.v2.components.SecondaryButtonV2(
                    label = if (officialReportLoading) "Se pregătește..." else "Pregătește raport oficial",
                    icon = Icons.Default.AssignmentTurnedIn,
                    accent = SigurColors.Suspect,
                    onClick = onOfficialReport
                )
                officialReportStatus?.takeIf { it.isNotBlank() }?.let {
                    Text(it, color = SigurColors.TextMuted, fontSize = 11.sp, modifier = Modifier.padding(top = 6.dp, bottom = 8.dp))
                }
                Spacer(modifier = Modifier.height(10.dp))
            }

            if (riskUi.level == "Periculos") {
                ro.sigurscan.app.ui.v2.components.SecondaryButtonV2(
                    label = "Raportează către comunitatea SigurScan",
                    icon = Icons.Default.Share,
                    accent = SigurColors.Safe,
                    onClick = onReport
                )
                Spacer(modifier = Modifier.height(10.dp))
            }

            if (assessment.cacheStatus != null) {
                ro.sigurscan.app.ui.v2.components.SecondaryButtonV2(
                    label = "Rescanează acum",
                    icon = Icons.Default.Refresh,
                    accent = SigurColors.Brand,
                    onClick = onRescan
                )
                Spacer(modifier = Modifier.height(10.dp))
            }

            ro.sigurscan.app.ui.v2.components.SubtleButtonV2(
                label = "Înapoi la scanare",
                onClick = onBack
            )
        }
    }
    }
}

@Composable
internal fun GateEvidenceSummary(assessment: OfflineAssessment, riskUi: RiskDisplayState) {
    val gateResult = assessment.gateResult ?: return
    val snapshot = assessment.evidenceSnapshot
    val inProgress = GateResultPresentation.isScanInProgress(gateResult)
    val hasLocalPreview = assessment.screenshotUrl
        ?.trim()
        ?.startsWith("file://", ignoreCase = true) == true &&
        sandboxScreenshotModel(assessment.screenshotUrl) != null
    val hasUrlEvidence = GateResultPresentation.hasUrlEvidence(snapshot)
    // Must match EvidenceSection's own "still generating" condition below — otherwise this
    // chip can say "Preview în curs" while the preview card itself says "indisponibil".
    val serverSuggestsPreviewGenerating = assessment.screenshotUrl == null &&
        assessment.serverInfo?.contains("genere", ignoreCase = true) == true
    val finalWithPreviewPending = !inProgress &&
        hasUrlEvidence &&
        snapshot?.completeness == EvidenceCompleteness.PARTIAL_ONLINE &&
        !hasLocalPreview &&
        serverSuggestsPreviewGenerating
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
                    !inProgress -> "Preview indisponibil"
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
                text = GateResultPresentation.primaryAction(gateResult),
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
