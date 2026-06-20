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

// Result detail sections extracted from ResultCard.kt for cohesion.

@Composable
fun ResultSection(title: String, items: List<String>, icon: ImageVector) {
    Column(modifier = Modifier.padding(vertical = 8.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(icon, contentDescription = null, tint = SigurColors.TextMuted, modifier = Modifier.size(16.dp))
            Spacer(modifier = Modifier.width(6.dp))
            Text(title, fontWeight = FontWeight.Bold, color = SigurColors.TextPrimary, fontSize = 14.sp)
        }
        items.forEach { item ->
            Text(
                text = "• $item",
                color = SigurColors.TextSecondary,
                fontSize = 13.sp,
                modifier = Modifier.padding(start = 22.dp, top = 2.dp)
            )
        }
    }
}

@Composable
fun OfferEvidenceSection(offer: OfferEvidenceSummary) {
    val entity = offer.entity
    val entityTone = when {
        entity?.brandImpersonation == true -> DSChipTone.Danger
        entity?.cuiChecked == false || entity?.cuiChecked == null -> DSChipTone.Pending
        entity.cuiExists == true && entity.cuiActive == true -> DSChipTone.Safe
        entity.cuiExists == false -> DSChipTone.Suspect
        else -> DSChipTone.Pending
    }
    val entityLabel = when {
        entity?.brandImpersonation == true -> "posibilă impersonare"
        entity?.cuiChecked == false || entity?.cuiChecked == null -> "ANAF neverificat"
        entity.cuiExists == true && entity.cuiActive == true -> "CUI activ"
        entity.cuiExists == false -> "CUI negăsit"
        else -> "ANAF incert"
    }

    Card(
        colors = CardDefaults.cardColors(containerColor = SigurColors.BackgroundCard),
        border = BorderStroke(1.dp, SigurColors.GlassBorder),
        shape = DSCardShape,
        modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    modifier = Modifier
                        .size(38.dp)
                        .background(SigurColors.BrandTint, RoundedCornerShape(14.dp)),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(Icons.Default.LocalOffer, contentDescription = null, tint = SigurColors.Brand, modifier = Modifier.size(20.dp))
                }
                Spacer(modifier = Modifier.width(10.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text("Date citite din ofertă", fontWeight = FontWeight.Bold, color = SigurColors.TextPrimary, fontSize = 15.sp)
                    Text("Confirmate din document și comparate cu dovezile scanării", color = SigurColors.TextMuted, fontSize = 11.sp)
                }
                DSChip(entityLabel, tone = entityTone)
            }

            Spacer(modifier = Modifier.height(10.dp))

            val fields = offer.fields
            InvoiceFieldRow("Emitent", fields.issuerName ?: entity?.denumire ?: "—")
            InvoiceFieldRow("CUI", fields.issuerCui ?: "—")
            InvoiceFieldRow("IBAN", fields.iban ?: "—")
            InvoiceFieldRow("Beneficiar plată", fields.paymentBeneficiary ?: "—")
            InvoiceFieldRow("Suma", formatOfferAmount(fields.totalAmount, fields.currency ?: "RON"))
            InvoiceFieldRow("Metodă plată", fields.paymentMethod ?: "—")
            InvoiceFieldRow("Tip document", fields.documentType ?: "ofertă")
            fields.familyCode?.takeIf { it.isNotBlank() }?.let {
                InvoiceFieldRow("Familie ofertă", it, DSChipTone.Brand)
            }

            if (offer.coherenceOk != null) {
                InvoiceFieldRow("Coerență sumă/date", if (offer.coherenceOk) "ok" else "neclar")
            }

            val readableSignals = offer.signals
                .map(::offerSignalLabel)
                .distinct()
                .take(5)
            if (readableSignals.isNotEmpty()) {
                Spacer(modifier = Modifier.height(10.dp))
                Text("Semnale observate", fontWeight = FontWeight.Bold, fontSize = 13.sp, color = SigurColors.TextPrimary)
                readableSignals.forEach { signal ->
                    Text("• $signal", fontSize = 12.sp, color = SigurColors.TextSecondary, modifier = Modifier.padding(start = 8.dp, top = 3.dp))
                }
            }

            if (offer.warnings.isNotEmpty()) {
                Spacer(modifier = Modifier.height(10.dp))
                Text("Atenționări", fontWeight = FontWeight.Bold, fontSize = 13.sp, color = SigurColors.Suspect)
                offer.warnings.take(4).forEach { warning ->
                    Text("• $warning", fontSize = 12.sp, color = SigurColors.TextSecondary, modifier = Modifier.padding(start = 8.dp, top = 3.dp))
                }
            }

            Text(
                text = "Notă: lipsa verificării ANAF sau un CUI neclar nu înseamnă automat fraudă; verdictul final folosește combinația de dovezi.",
                fontSize = 10.sp,
                lineHeight = 14.sp,
                color = SigurColors.TextMuted,
                modifier = Modifier.padding(top = 10.dp)
            )
        }
    }
}

@Composable
fun LegalEducationSection(legal: LegalSection) {
    // Strat educativ: randează DOAR ce întoarce backend-ul, verbatim. Nu atinge
    // verdictul. 0 carduri sau label lipsă => secțiunea nu apare deloc.
    val cards = legal.cards.orEmpty().filter { !it.title.isNullOrBlank() || !it.summary.isNullOrBlank() }
    val label = legal.label
    if (cards.isEmpty() || label.isNullOrBlank()) return

    Spacer(modifier = Modifier.height(12.dp))
    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(bottom = 8.dp)) {
        Icon(Icons.Default.Info, contentDescription = null, tint = SigurColors.Brand, modifier = Modifier.size(16.dp))
        Spacer(modifier = Modifier.width(8.dp))
        Text(label, color = SigurColors.TextPrimary, fontWeight = FontWeight.Bold, fontSize = 14.sp)
    }
    cards.forEach { card ->
        Card(
            colors = CardDefaults.cardColors(containerColor = SigurColors.BackgroundCard),
            shape = DSCardShape,
            border = DSCardBorder,
            modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp)
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                card.title?.takeIf { it.isNotBlank() }?.let {
                    Text(it, color = SigurColors.TextPrimary, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                }
                card.summary?.takeIf { it.isNotBlank() }?.let {
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(it, color = SigurColors.TextSecondary, fontSize = 12.sp, lineHeight = 18.sp)
                }
                val actions = card.actions.orEmpty().filter { it.isNotBlank() }
                if (actions.isNotEmpty()) {
                    Spacer(modifier = Modifier.height(8.dp))
                    actions.forEach { action ->
                        Text("\u2022 $action", color = SigurColors.TextPrimary, fontSize = 12.sp, lineHeight = 18.sp)
                    }
                }
                val refs = card.sourceRefs.orEmpty().filter { it.isNotBlank() }
                if (refs.isNotEmpty()) {
                    Spacer(modifier = Modifier.height(8.dp))
                    refs.forEach { ref ->
                        Text(ref, color = SigurColors.TextMuted, fontSize = 10.sp)
                    }
                }
            }
        }
    }
    legal.disclaimer?.takeIf { it.isNotBlank() }?.let { disclaimer ->
        Row(modifier = Modifier.fillMaxWidth().padding(top = 2.dp, bottom = 8.dp)) {
            Icon(Icons.Default.Info, contentDescription = null, tint = SigurColors.TextMuted, modifier = Modifier.size(12.dp))
            Spacer(modifier = Modifier.width(6.dp))
            Text(disclaimer, color = SigurColors.TextMuted, fontSize = 10.sp, lineHeight = 14.sp, fontStyle = FontStyle.Italic)
        }
    }
}

@Composable
fun OfficialReportPackageSection(report: OneTapReportPackage) {
    val channels = report.channels.orEmpty()
        .filter { !it.name.isNullOrBlank() || !it.contact.isNullOrBlank() }
    if (channels.isEmpty()) return

    Spacer(modifier = Modifier.height(12.dp))
    Card(
        colors = CardDefaults.cardColors(containerColor = SigurColors.BackgroundCard),
        shape = DSCardShape,
        border = DSCardBorder,
        modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.AssignmentTurnedIn, contentDescription = null, tint = SigurColors.Suspect, modifier = Modifier.size(16.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text("Raport oficial pregătit", color = SigurColors.TextPrimary, fontWeight = FontWeight.Bold, fontSize = 14.sp)
            }
            Spacer(modifier = Modifier.height(10.dp))
            channels.take(4).forEachIndexed { index, channel ->
                if (index > 0) {
                    HorizontalDivider(color = SigurColors.GlassBorder, modifier = Modifier.padding(vertical = 10.dp))
                }
                channel.name?.takeIf { it.isNotBlank() }?.let {
                    Text(it, color = SigurColors.TextPrimary, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                }
                channel.contact?.takeIf { it.isNotBlank() }?.let {
                    Text(it, color = SigurColors.TextSecondary, fontSize = 12.sp, lineHeight = 17.sp)
                }
                channel.prefilledSubject?.takeIf { it.isNotBlank() }?.let {
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(it, color = SigurColors.TextMuted, fontSize = 11.sp, fontWeight = FontWeight.SemiBold)
                }
                channel.prefilledBody?.takeIf { it.isNotBlank() }?.let {
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(it.take(220), color = SigurColors.TextMuted, fontSize = 10.sp, lineHeight = 14.sp)
                }
            }
            report.disclaimer?.takeIf { it.isNotBlank() }?.let {
                Spacer(modifier = Modifier.height(10.dp))
                Text(it, color = SigurColors.TextMuted, fontSize = 10.sp, lineHeight = 14.sp, fontStyle = FontStyle.Italic)
            }
        }
    }
}

@Composable
fun ActionPlanSection(plan: ActionPlan) {
    val steps = plan.steps.orEmpty()
        .filter { !it.title.isNullOrBlank() || !it.detail.isNullOrBlank() }
        .sortedWith(compareBy<ActionPlanStep> { it.order ?: Int.MAX_VALUE })
    if (steps.isEmpty()) return

    Spacer(modifier = Modifier.height(12.dp))
    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(bottom = 8.dp)) {
        Icon(Icons.Default.AssignmentTurnedIn, contentDescription = null, tint = SigurColors.Brand, modifier = Modifier.size(16.dp))
        Spacer(modifier = Modifier.width(8.dp))
        Text(
            text = plan.label?.takeIf { it.isNotBlank() } ?: "Plan de acțiune",
            color = SigurColors.TextPrimary,
            fontWeight = FontWeight.Bold,
            fontSize = 14.sp
        )
    }

    Card(
        colors = CardDefaults.cardColors(containerColor = SigurColors.BackgroundCard),
        shape = DSCardShape,
        border = DSCardBorder,
        modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            steps.take(6).forEachIndexed { index, step ->
                if (index > 0) {
                    HorizontalDivider(color = SigurColors.GlassBorder, modifier = Modifier.padding(vertical = 10.dp))
                }
                Row(verticalAlignment = Alignment.Top) {
                    Surface(
                        color = actionPlanUrgencyColor(step.urgency).copy(alpha = 0.12f),
                        border = BorderStroke(1.dp, actionPlanUrgencyColor(step.urgency).copy(alpha = 0.35f)),
                        shape = RoundedCornerShape(999.dp)
                    ) {
                        Text(
                            text = actionPlanUrgencyLabel(step.urgency),
                            color = actionPlanUrgencyColor(step.urgency),
                            fontSize = 10.sp,
                            fontWeight = FontWeight.Bold,
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                        )
                    }
                    Spacer(modifier = Modifier.width(10.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        step.title?.takeIf { it.isNotBlank() }?.let {
                            Text(it, color = SigurColors.TextPrimary, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                        }
                        step.detail?.takeIf { it.isNotBlank() }?.let {
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(it, color = SigurColors.TextSecondary, fontSize = 12.sp, lineHeight = 18.sp)
                        }
                        step.channel?.takeIf { it.isNotBlank() }?.let {
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(it, color = SigurColors.TextMuted, fontSize = 11.sp, fontWeight = FontWeight.SemiBold)
                        }
                    }
                }
            }

            val channels = plan.reportPackage?.channels.orEmpty()
                .mapNotNull { it.name?.takeIf(String::isNotBlank) }
                .distinct()
                .take(3)
            if (channels.isNotEmpty()) {
                Spacer(modifier = Modifier.height(12.dp))
                Text(
                    text = "Raportare: ${channels.joinToString(", ")}",
                    color = SigurColors.TextMuted,
                    fontSize = 11.sp,
                    lineHeight = 16.sp
                )
            }
            plan.disclaimer?.takeIf { it.isNotBlank() }?.let {
                Spacer(modifier = Modifier.height(8.dp))
                Text(it, color = SigurColors.TextMuted, fontSize = 10.sp, lineHeight = 14.sp, fontStyle = FontStyle.Italic)
            }
        }
    }
}

@Composable
fun PostIncidentImpactControls(
    loading: Boolean,
    status: String?,
    onSubmit: (List<String>) -> Unit
) {
    var selected by remember { mutableStateOf<Set<String>>(emptySet()) }
    val options = listOf(
        "shared_card" to "Am introdus cardul",
        "shared_otp" to "Am dat cod OTP",
        "shared_credentials" to "Am dat parola",
        "paid_transfer" to "Am trimis bani",
        "installed_remote_access" to "Am instalat remote"
    )

    Card(
        colors = CardDefaults.cardColors(containerColor = SigurColors.BackgroundCard),
        shape = DSCardShape,
        border = DSCardBorder,
        modifier = Modifier.fillMaxWidth().padding(top = 8.dp, bottom = 8.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.HealthAndSafety, contentDescription = null, tint = SigurColors.Suspect, modifier = Modifier.size(16.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text("Ce s-a întâmplat deja?", color = SigurColors.TextPrimary, fontWeight = FontWeight.Bold, fontSize = 14.sp)
            }
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                "Selectează doar ce ai făcut, ca planul să fie ordonat corect.",
                color = SigurColors.TextMuted,
                fontSize = 11.sp,
                lineHeight = 15.sp
            )
            Spacer(modifier = Modifier.height(10.dp))
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                options.forEach { (impact, label) ->
                    FilterChip(
                        selected = selected.contains(impact),
                        onClick = {
                            selected = if (selected.contains(impact)) selected - impact else selected + impact
                        },
                        label = { Text(label, fontSize = 11.sp) },
                        enabled = !loading
                    )
                }
            }
            status?.takeIf { it.isNotBlank() }?.let {
                Spacer(modifier = Modifier.height(8.dp))
                Text(it, color = SigurColors.TextSecondary, fontSize = 11.sp, lineHeight = 15.sp)
            }
            Spacer(modifier = Modifier.height(10.dp))
            Button(
                onClick = { onSubmit(selected.toList()) },
                enabled = selected.isNotEmpty() && !loading,
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = SigurColors.SuspectLight),
                border = BorderStroke(1.dp, SigurColors.SuspectBorder),
                shape = DSPillShape
            ) {
                Icon(Icons.Default.AssignmentTurnedIn, contentDescription = null, tint = SigurColors.Suspect, modifier = Modifier.size(14.dp))
                Spacer(modifier = Modifier.width(6.dp))
                Text(if (loading) "Se actualizează..." else "Actualizează planul", color = SigurColors.Suspect, fontSize = 11.sp)
            }
        }
    }
}

internal fun actionPlanUrgencyLabel(urgency: String?): String = when (urgency?.lowercase(Locale.US)) {
    "now" -> "Acum"
    "today" -> "Azi"
    "soon" -> "Curând"
    else -> "Pas"
}

internal fun actionPlanUrgencyColor(urgency: String?): Color = when (urgency?.lowercase(Locale.US)) {
    "now" -> SigurColors.Dangerous
    "today" -> SigurColors.Suspect
    "soon" -> SigurColors.Brand
    else -> SigurColors.TextMuted
}

@Composable
fun OfferAnalysisSection(analysis: String) {
    Column(modifier = Modifier.padding(vertical = 12.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Default.AutoAwesome, contentDescription = null, tint = SigurColors.Suspect, modifier = Modifier.size(16.dp))
            Spacer(modifier = Modifier.width(6.dp))
            Text("🔍 Verificare Ofertă / Campanie (AI)", fontWeight = FontWeight.Bold, color = SigurColors.TextPrimary, fontSize = 14.sp)
        }
        
        Spacer(modifier = Modifier.height(8.dp))
        
        Card(
            colors = CardDefaults.cardColors(containerColor = SigurColors.SuspectLight),
            border = BorderStroke(1.dp, SigurColors.SuspectBorder),
            shape = RoundedCornerShape(12.dp)
        ) {
            Text(
                text = analysis,
                color = SigurColors.TextSecondary,
                fontSize = 13.sp,
                lineHeight = 20.sp,
                modifier = Modifier.padding(12.dp)
            )
        }
    }
}

@Composable
fun ComplianceSection(authSummary: String) {
    Column(modifier = Modifier.padding(vertical = 12.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Default.CheckCircle, contentDescription = null, tint = SigurColors.Safe, modifier = Modifier.size(16.dp))
            Spacer(modifier = Modifier.width(6.dp))
            Text("Autentificare email (DKIM/SPF/DMARC)", fontWeight = FontWeight.Bold, color = SigurColors.TextPrimary, fontSize = 14.sp)
        }

        Spacer(modifier = Modifier.height(8.dp))

        Card(
            colors = CardDefaults.cardColors(containerColor = SigurColors.SafeLight),
            border = BorderStroke(1.dp, SigurColors.SafeBorder),
            shape = RoundedCornerShape(12.dp)
        ) {
            Text(
                text = authSummary,
                color = SigurColors.TextSecondary,
                fontSize = 12.sp,
                modifier = Modifier.padding(12.dp)
            )
        }
    }
}

@Composable
fun ButtonsSection(buttons: List<String>) {
    Column(modifier = Modifier.padding(vertical = 12.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Default.TouchApp, contentDescription = null, tint = SigurColors.Suspect, modifier = Modifier.size(16.dp))
            Spacer(modifier = Modifier.width(6.dp))
            Text("Butoane Detectate În E-mail", fontWeight = FontWeight.Bold, color = SigurColors.TextPrimary, fontSize = 14.sp)
        }

        Spacer(modifier = Modifier.height(8.dp))

        Card(
            colors = CardDefaults.cardColors(containerColor = SigurColors.SuspectLight),
            border = BorderStroke(1.dp, SigurColors.SuspectBorder),
            shape = RoundedCornerShape(12.dp)
        ) {
            Column(modifier = Modifier.padding(12.dp)) {
                buttons.forEach { button ->
                    Text("• $button", color = SigurColors.TextSecondary, fontSize = 12.sp)
                }
            }
        }
    }
}

@Composable
fun SincerityPillarsSection(assessment: OfflineAssessment) {
    Column(modifier = Modifier.padding(vertical = 12.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Default.Verified, contentDescription = null, tint = SigurColors.Safe, modifier = Modifier.size(16.dp))
            Spacer(modifier = Modifier.width(6.dp))
            Text("Detalii de verificare", fontWeight = FontWeight.Bold, color = SigurColors.TextPrimary, fontSize = 14.sp)
        }
        
        Spacer(modifier = Modifier.height(8.dp))
        
        Card(
            colors = CardDefaults.cardColors(containerColor = SigurColors.BackgroundSurface),
            border = BorderStroke(1.dp, SigurColors.GlassBorder),
            shape = RoundedCornerShape(12.dp)
        ) {
            Column(modifier = Modifier.padding(12.dp)) {
                PillarRow("1. Cazier Global", assessment.reputationVerdict, Icons.Default.Public)
                PillarRow("2. Vârsta Domeniului", assessment.domainAgeText, Icons.Default.History)
                PillarRow("3. Infrastructură (SSL)", assessment.sslStatus, Icons.Default.Lock)
                PillarRow("4. Analiză de Conținut", assessment.aiConfidence, Icons.Default.AutoAwesome)
            }
        }
    }
}

@Composable
fun PillarRow(label: String, value: String, icon: ImageVector) {
    Row(
        modifier = Modifier.padding(vertical = 6.dp).fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(icon, contentDescription = null, tint = SigurColors.TextMuted, modifier = Modifier.size(14.dp))
            Spacer(modifier = Modifier.width(8.dp))
            Text(label, color = SigurColors.TextSecondary, fontSize = 12.sp)
        }
        Text(value, color = SigurColors.TextPrimary, fontSize = 12.sp, fontWeight = FontWeight.Bold)
    }
}
