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
import androidx.compose.ui.graphics.Brush
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
import kotlinx.coroutines.delay
import kotlin.math.max
import kotlin.math.min
import kotlin.math.pow

// Radar feature cards / map extracted from RadarScreen.kt for cohesion.

@Composable
internal fun BtrOnDeviceCard(
    snapshot: BtrSyncSnapshot?,
    verdict: InboxProvenanceVerdict?,
    loading: Boolean,
    status: String?,
    provenanceStatus: String?,
    onSync: () -> Unit,
    onLocalCheck: () -> Unit
) {
    val cacheText = snapshot?.let {
        "${it.manifests.size} manifeste oficiale • ${it.version}"
    } ?: "Registru oficial local indisponibil"

    Card(
        colors = CardDefaults.cardColors(containerColor = SigurColors.BackgroundCard),
        border = DSCardBorder,
        shape = DSCardShape,
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.VerifiedUser, contentDescription = null, tint = SigurColors.Safe, modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text("BTR on-device", color = SigurColors.TextPrimary, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                    Text(cacheText, color = SigurColors.TextMuted, fontSize = 11.sp, lineHeight = 15.sp)
                }
                DSChip(if (snapshot == null) "necesită sync" else "local", tone = if (snapshot == null) DSChipTone.Pending else DSChipTone.Safe)
            }
            Text(
                "Manifestele coboară pe telefon; conținutul SMS nu este trimis la server.",
                color = SigurColors.TextSecondary,
                fontSize = 11.sp,
                lineHeight = 15.sp,
                modifier = Modifier.padding(top = 8.dp)
            )
            status?.takeIf { it.isNotBlank() }?.let {
                Spacer(modifier = Modifier.height(8.dp))
                Text(it, color = SigurColors.TextSecondary, fontSize = 11.sp, lineHeight = 15.sp)
            }
            verdict?.let {
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    "Ultima verificare locală: ${it.verdict.name.lowercase(Locale.getDefault())} · ${it.reasonCodes.joinToString(", ")}",
                    color = SigurColors.TextMuted,
                    fontSize = 11.sp,
                    lineHeight = 15.sp
                )
            }
            provenanceStatus?.takeIf { it.isNotBlank() }?.let {
                Spacer(modifier = Modifier.height(6.dp))
                Text(it, color = SigurColors.TextSecondary, fontSize = 11.sp, lineHeight = 15.sp)
            }
            Spacer(modifier = Modifier.height(12.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                Button(
                    onClick = onSync,
                    enabled = !loading,
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.buttonColors(containerColor = SigurColors.SafeLight),
                    border = BorderStroke(1.dp, SigurColors.SafeBorder),
                    shape = DSPillShape
                ) {
                    Icon(Icons.Default.Download, contentDescription = null, tint = SigurColors.Safe, modifier = Modifier.size(14.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(if (loading) "Sync..." else "Sincronizează", color = SigurColors.Safe, fontSize = 11.sp)
                }
                Button(
                    onClick = onLocalCheck,
                    enabled = snapshot != null,
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.buttonColors(containerColor = SigurColors.BackgroundSurface),
                    border = BorderStroke(1.dp, SigurColors.GlassBorder),
                    shape = DSPillShape
                ) {
                    Icon(Icons.Default.Verified, contentDescription = null, tint = SigurColors.TextPrimary, modifier = Modifier.size(14.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Verifică local", color = SigurColors.TextPrimary, fontSize = 11.sp)
                }
            }
        }
    }
}

@Composable
internal fun CircleGuardianCard(
    members: List<FamilyMember>,
    selectedMember: FamilyMember?,
    onSelectedMember: (FamilyMember) -> Unit,
    snapshot: CircleProtectionSnapshot,
    circleLoading: Boolean,
    circleStatus: String?,
    guardianLoading: Boolean,
    guardianStatus: String?,
    hasAssessment: Boolean,
    onPair: () -> Unit,
    onPing: () -> Unit,
    onResolve: (String) -> Unit,
    onRevoke: () -> Unit,
    onGuardian: (String, Boolean) -> Unit
) {
    var memberMenuExpanded by remember { mutableStateOf(false) }
    var guardianShareLevel by remember { mutableStateOf("metadata_only") }
    var fullConsent by remember { mutableStateOf(false) }
    val link = snapshot.link
    val ping = snapshot.ping
    val outcome = snapshot.outcome
    val guardian = snapshot.guardianOpinion
    val activeLink = link?.active == true

    Card(
        colors = CardDefaults.cardColors(containerColor = SigurColors.BackgroundCard),
        border = DSCardBorder,
        shape = DSCardShape,
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Group, contentDescription = null, tint = SigurColors.Brand, modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text("Cercul + Guardian", color = SigurColors.TextPrimary, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                    Text(
                        "Verificare out-of-band; fără acces la conținut brut.",
                        color = SigurColors.TextMuted,
                        fontSize = 11.sp,
                        lineHeight = 15.sp
                    )
                }
                DSChip(
                    text = if (activeLink) "activ" else "neconfigurat",
                    tone = if (activeLink) DSChipTone.Safe else DSChipTone.Pending
                )
            }

            Spacer(modifier = Modifier.height(12.dp))

            if (members.isEmpty()) {
                Text(
                    "Adaugă întâi o persoană de încredere în Mai mult > Securitate și Familie.",
                    color = SigurColors.TextSecondary,
                    fontSize = 11.sp,
                    lineHeight = 15.sp
                )
            } else {
                Box {
                    Button(
                        onClick = { memberMenuExpanded = true },
                        modifier = Modifier.fillMaxWidth(),
                        colors = ButtonDefaults.buttonColors(containerColor = SigurColors.BackgroundSurface),
                        border = BorderStroke(1.dp, SigurColors.GlassBorder),
                        shape = DSPillShape
                    ) {
                        Icon(Icons.Default.Person, contentDescription = null, tint = SigurColors.TextPrimary, modifier = Modifier.size(14.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            selectedMember?.name ?: "Alege persoana",
                            color = SigurColors.TextPrimary,
                            fontSize = 12.sp
                        )
                    }
                    DropdownMenu(expanded = memberMenuExpanded, onDismissRequest = { memberMenuExpanded = false }) {
                        members.forEach { member ->
                            DropdownMenuItem(
                                text = {
                                    Column {
                                        Text(member.name)
                                        Text(member.contact, fontSize = 11.sp, color = SigurColors.TextMuted)
                                    }
                                },
                                onClick = {
                                    onSelectedMember(member)
                                    memberMenuExpanded = false
                                }
                            )
                        }
                    }
                }
            }

            circleStatus?.takeIf { it.isNotBlank() }?.let {
                Spacer(modifier = Modifier.height(8.dp))
                Text(it, color = SigurColors.TextSecondary, fontSize = 11.sp, lineHeight = 15.sp)
            }

            link?.let {
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    "Link: ${it.linkId} • citire conținut: ${if (it.verifierCanReadContent) "da" else "nu"} • supraveghere: ${if (it.verifierCanSurveil) "da" else "nu"}",
                    color = SigurColors.TextMuted,
                    fontSize = 10.sp,
                    lineHeight = 14.sp
                )
            }

            ping?.let {
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    "Ping: ${it.pingId} • ${it.payloadClass ?: "metadata_only"} • timeout=${it.defaultOnTimeout ?: "PRECAUTIE"}",
                    color = SigurColors.TextMuted,
                    fontSize = 10.sp,
                    lineHeight = 14.sp
                )
            }

            outcome?.let {
                Spacer(modifier = Modifier.height(8.dp))
                val tone = when (it.status) {
                    "CONFIRMED" -> DSChipTone.Safe
                    "REJECTED" -> DSChipTone.Danger
                    else -> DSChipTone.Suspect
                }
                DSChip(text = (it.status ?: "PRECAUTIE"), tone = tone)
            }

            Spacer(modifier = Modifier.height(12.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                Button(
                    onClick = onPair,
                    enabled = !circleLoading && selectedMember != null,
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.buttonColors(containerColor = SigurColors.BrandTint),
                    border = BorderStroke(1.dp, SigurColors.Brand),
                    shape = DSPillShape
                ) {
                    Icon(Icons.Default.Link, contentDescription = null, tint = SigurColors.Brand, modifier = Modifier.size(14.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(if (circleLoading) "..." else "Leagă", color = SigurColors.Brand, fontSize = 11.sp)
                }
                Button(
                    onClick = onPing,
                    enabled = !circleLoading && activeLink,
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.buttonColors(containerColor = SigurColors.SafeLight),
                    border = BorderStroke(1.dp, SigurColors.SafeBorder),
                    shape = DSPillShape
                ) {
                    Icon(Icons.Default.Send, contentDescription = null, tint = SigurColors.Safe, modifier = Modifier.size(14.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Ping", color = SigurColors.Safe, fontSize = 11.sp)
                }
            }

            Spacer(modifier = Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                Button(
                    onClick = { onResolve("its_me") },
                    enabled = !circleLoading && ping != null,
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.buttonColors(containerColor = SigurColors.SafeLight),
                    border = BorderStroke(1.dp, SigurColors.SafeBorder),
                    shape = DSPillShape
                ) {
                    Text("Confirmă", color = SigurColors.Safe, fontSize = 11.sp)
                }
                Button(
                    onClick = { onResolve("not_me") },
                    enabled = !circleLoading && ping != null,
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.buttonColors(containerColor = SigurColors.DangerousLight),
                    border = BorderStroke(1.dp, SigurColors.DangerousBorder),
                    shape = DSPillShape
                ) {
                    Text("Respinge", color = SigurColors.Dangerous, fontSize = 11.sp)
                }
                Button(
                    onClick = { onResolve("timeout") },
                    enabled = !circleLoading && ping != null,
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.buttonColors(containerColor = SigurColors.SuspectLight),
                    border = BorderStroke(1.dp, SigurColors.SuspectBorder),
                    shape = DSPillShape
                ) {
                    Text("Timeout", color = SigurColors.Suspect, fontSize = 11.sp)
                }
            }

            Spacer(modifier = Modifier.height(14.dp))
            HorizontalDivider(color = SigurColors.GlassBorder)
            Spacer(modifier = Modifier.height(12.dp))

            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.VerifiedUser, contentDescription = null, tint = SigurColors.Safe, modifier = Modifier.size(16.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text("Guardian second opinion", color = SigurColors.TextPrimary, fontWeight = FontWeight.SemiBold, fontSize = 13.sp)
            }
            Text(
                if (hasAssessment) "Trimite doar rezumat redactat al scanării curente." else "Poți cere o opinie metadata-only chiar fără scanare curentă.",
                color = SigurColors.TextSecondary,
                fontSize = 11.sp,
                lineHeight = 15.sp,
                modifier = Modifier.padding(top = 6.dp)
            )

            Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(top = 8.dp)) {
                Checkbox(
                    checked = guardianShareLevel == "redacted_excerpt",
                    onCheckedChange = { checked ->
                        guardianShareLevel = if (checked) "redacted_excerpt" else "metadata_only"
                    }
                )
                Text("Include extras redactat", color = SigurColors.TextSecondary, fontSize = 11.sp)
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                Checkbox(
                    checked = fullConsent,
                    onCheckedChange = { fullConsent = it }
                )
                Text("Consimțământ explicit pentru full_with_consent", color = SigurColors.TextSecondary, fontSize = 11.sp)
            }

            guardianStatus?.takeIf { it.isNotBlank() }?.let {
                Spacer(modifier = Modifier.height(8.dp))
                Text(it, color = SigurColors.TextSecondary, fontSize = 11.sp, lineHeight = 15.sp)
            }
            guardian?.let {
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    "Request: ${it.requestId} • share=${it.shareLevel ?: "metadata_only"} • downgraded=${it.shareDowngraded}",
                    color = SigurColors.TextMuted,
                    fontSize = 10.sp,
                    lineHeight = 14.sp
                )
            }

            Spacer(modifier = Modifier.height(10.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                Button(
                    onClick = {
                        val level = if (fullConsent) "full_with_consent" else guardianShareLevel
                        onGuardian(level, fullConsent)
                    },
                    enabled = !guardianLoading && selectedMember != null,
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.buttonColors(containerColor = SigurColors.SafeLight),
                    border = BorderStroke(1.dp, SigurColors.SafeBorder),
                    shape = DSPillShape
                ) {
                    Icon(Icons.Default.PrivacyTip, contentDescription = null, tint = SigurColors.Safe, modifier = Modifier.size(14.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(if (guardianLoading) "..." else "Cere opinie", color = SigurColors.Safe, fontSize = 11.sp)
                }
                Button(
                    onClick = onRevoke,
                    enabled = !circleLoading && link != null && activeLink,
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.buttonColors(containerColor = SigurColors.BackgroundSurface),
                    border = BorderStroke(1.dp, SigurColors.GlassBorder),
                    shape = DSPillShape
                ) {
                    Icon(Icons.Default.Delete, contentDescription = null, tint = SigurColors.TextMuted, modifier = Modifier.size(14.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Revocă", color = SigurColors.TextPrimary, fontSize = 11.sp)
                }
            }
        }
    }
}

@Composable
internal fun AudioAsrReadinessCard(
    snapshot: AudioReadinessSnapshot,
    status: String?,
    evidenceResult: AudioEvidenceResult?,
    hasAssessment: Boolean,
    onConsentChanged: (Boolean) -> Unit,
    onDisclosureChanged: (Boolean) -> Unit,
    onRefresh: () -> Unit,
    onAnalyzeTranscript: () -> Unit,
    speakerGuard: SpeakerGuardSnapshot,
    callPrompt: SpeakerGuardCallPromptPresentation?,
    hasMicrophonePermission: Boolean,
    onStartSpeakerGuard: () -> Unit,
    onStopSpeakerGuard: () -> Unit
) {
    val blocked = !snapshot.decision.allowed
    var nowMillis by remember { mutableStateOf(System.currentTimeMillis()) }
    var showLocalSetup by remember(blocked) { mutableStateOf(blocked) }
    LaunchedEffect(speakerGuard.active, speakerGuard.startedAtEpochMillis) {
        nowMillis = System.currentTimeMillis()
        while (speakerGuard.active) {
            delay(1000L)
            nowMillis = System.currentTimeMillis()
        }
    }
    val presentation = speakerGuardPresentation(speakerGuard, evidenceResult, nowMillis)
    Card(
        colors = CardDefaults.cardColors(containerColor = SigurColors.BackgroundCard),
        border = DSCardBorder,
        shape = DSCardShape,
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Security, contentDescription = null, tint = SigurColors.Brand, modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text("Urechea SigurScan", color = SigurColors.TextPrimary, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                    Text("Pentru apeluri nesigure: pui pe difuzor, apeși start, iar analiza rămâne pe telefon.", color = SigurColors.TextMuted, fontSize = 11.sp, lineHeight = 15.sp)
                }
                DSChip(if (speakerGuard.active) "live" else if (blocked) "nepregătit" else "pregătit", tone = if (speakerGuard.active) DSChipTone.Brand else if (blocked) DSChipTone.Suspect else DSChipTone.Safe)
            }

            Spacer(modifier = Modifier.height(10.dp))
            callPrompt?.let { prompt ->
                SpeakerGuardCallPromptCard(prompt = prompt, onStartSpeakerGuard = onStartSpeakerGuard)
                Spacer(modifier = Modifier.height(10.dp))
            }

            status?.takeIf { it.isNotBlank() }?.let {
                Spacer(modifier = Modifier.height(8.dp))
                Text(it, color = SigurColors.TextSecondary, fontSize = 11.sp, lineHeight = 15.sp)
            }

            SpeakerGuardStatusBlock(presentation, speakerGuard.latestVerdict ?: evidenceResult?.verdict)

            Spacer(modifier = Modifier.height(12.dp))
            Button(
                onClick = if (speakerGuard.active) onStopSpeakerGuard else onStartSpeakerGuard,
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(
                    containerColor = if (speakerGuard.active) SigurColors.DangerousLight else SigurColors.SafeLight
                ),
                border = BorderStroke(
                    1.dp,
                    if (speakerGuard.active) SigurColors.DangerousBorder else SigurColors.SafeBorder
                ),
                shape = DSPillShape
            ) {
                Icon(
                    if (speakerGuard.active) Icons.Default.Stop else Icons.Default.Mic,
                    contentDescription = null,
                    tint = if (speakerGuard.active) SigurColors.Dangerous else SigurColors.Safe,
                    modifier = Modifier.size(14.dp)
                )
                Spacer(modifier = Modifier.width(6.dp))
                Text(
                    if (speakerGuard.active) "Oprește Urechea" else "Ascultă pe difuzor",
                    color = if (speakerGuard.active) SigurColors.Dangerous else SigurColors.Safe,
                    fontSize = 11.sp
                )
            }
            Spacer(modifier = Modifier.height(8.dp))
            Button(
                onClick = onAnalyzeTranscript,
                enabled = hasAssessment,
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = SigurColors.BackgroundSurface),
                border = BorderStroke(1.dp, SigurColors.GlassBorder),
                shape = DSPillShape
            ) {
                Icon(Icons.Default.Security, contentDescription = null, tint = SigurColors.TextPrimary, modifier = Modifier.size(14.dp))
                Spacer(modifier = Modifier.width(6.dp))
                Text("Analizează transcrierea lipită", color = SigurColors.TextPrimary, fontSize = 11.sp)
            }

            TextButton(onClick = { showLocalSetup = !showLocalSetup }, modifier = Modifier.fillMaxWidth()) {
                Icon(Icons.Default.Info, contentDescription = null, tint = SigurColors.TextMuted, modifier = Modifier.size(14.dp))
                Spacer(modifier = Modifier.width(6.dp))
                Text(if (showLocalSetup) "Ascunde pregătirea locală" else "Arată pregătirea locală", color = SigurColors.TextMuted, fontSize = 11.sp)
            }

            if (showLocalSetup) {
                Spacer(modifier = Modifier.height(4.dp))
                ReadinessRow("Feature flag", snapshot.featureFlagEnabled)
                ReadinessRow("Model audio local", snapshot.modelAvailable)
                ReadinessRow("Runtime audio local", snapshot.nativeRuntimeAvailable)
                ReadinessRow("Permisiune microfon", snapshot.microphonePermissionGranted || hasMicrophonePermission)
                ReadinessRow("Consimțământ explicit", snapshot.explicitConsent)
                ReadinessRow("Privacy acceptat", snapshot.privacyDisclosureAccepted)
                Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(top = 8.dp)) {
                    Checkbox(checked = snapshot.explicitConsent, onCheckedChange = onConsentChanged)
                    Text("Accept pornirea ascultării locale", color = SigurColors.TextSecondary, fontSize = 11.sp)
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(checked = snapshot.privacyDisclosureAccepted, onCheckedChange = onDisclosureChanged)
                    Text("Am citit că audio-ul nu părăsește telefonul", color = SigurColors.TextSecondary, fontSize = 11.sp)
                }
                Button(
                    onClick = onRefresh,
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = SigurColors.BackgroundSurface),
                    border = BorderStroke(1.dp, SigurColors.GlassBorder),
                    shape = DSPillShape
                ) {
                    Icon(Icons.Default.Security, contentDescription = null, tint = SigurColors.TextPrimary, modifier = Modifier.size(14.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Verifică pregătirea", color = SigurColors.TextPrimary, fontSize = 11.sp)
                }
            }
        }
    }
}

@Composable
internal fun SpeakerGuardCallPromptCard(
    prompt: SpeakerGuardCallPromptPresentation,
    onStartSpeakerGuard: () -> Unit
) {
    Card(
        colors = CardDefaults.cardColors(containerColor = SigurColors.BrandTint),
        border = BorderStroke(1.dp, SigurColors.Brand.copy(alpha = 0.30f)),
        shape = DSCardShape,
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Phone, contentDescription = null, tint = SigurColors.Brand, modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.width(6.dp))
                Text(prompt.title, color = SigurColors.TextPrimary, fontWeight = FontWeight.Bold, fontSize = 13.sp)
            }
            Spacer(modifier = Modifier.height(6.dp))
            Text(prompt.body, color = SigurColors.TextSecondary, fontSize = 11.sp, lineHeight = 15.sp)
            Spacer(modifier = Modifier.height(6.dp))
            Text(prompt.privacyLine, color = SigurColors.TextMuted, fontSize = 10.sp, lineHeight = 14.sp)
            Spacer(modifier = Modifier.height(10.dp))
            Button(
                onClick = onStartSpeakerGuard,
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = SigurColors.SafeLight),
                border = BorderStroke(1.dp, SigurColors.SafeBorder),
                shape = DSPillShape
            ) {
                Icon(Icons.Default.Mic, contentDescription = null, tint = SigurColors.Safe, modifier = Modifier.size(14.dp))
                Spacer(modifier = Modifier.width(6.dp))
                Text(prompt.primaryCta, color = SigurColors.Safe, fontSize = 11.sp)
            }
        }
    }
}

@Composable
internal fun SpeakerGuardStatusBlock(
    presentation: SpeakerGuardPresentation,
    verdict: AudioEvidenceVerdict?
) {
    val tone = speakerGuardTone(verdict)
    val accent = speakerGuardAccent(verdict)
    val light = speakerGuardLight(verdict)
    Card(
        colors = CardDefaults.cardColors(containerColor = SigurColors.BackgroundSurface),
        border = BorderStroke(1.dp, speakerGuardBorder(verdict)),
        shape = DSCardShape,
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Box(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(
                        Brush.horizontalGradient(
                            listOf(light, SigurColors.BackgroundCard)
                        ),
                        RoundedCornerShape(16.dp)
                    )
                    .padding(12.dp)
            ) {
                Column {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.GraphicEq, contentDescription = null, tint = accent, modifier = Modifier.size(20.dp))
                        Spacer(modifier = Modifier.width(8.dp))
                        Column(modifier = Modifier.weight(1f)) {
                            Text(presentation.title, color = SigurColors.TextPrimary, fontWeight = FontWeight.Bold, fontSize = 15.sp)
                            Text(presentation.privacyLine, color = SigurColors.TextMuted, fontSize = 10.sp, lineHeight = 14.sp)
                        }
                        DSChip(presentation.listeningLabel, tone = tone)
                    }
                    Spacer(modifier = Modifier.height(12.dp))
                    Row(verticalAlignment = Alignment.Bottom) {
                        Text(presentation.verdictTitle, color = accent, fontWeight = FontWeight.Bold, fontSize = 20.sp)
                        Spacer(modifier = Modifier.weight(1f))
                        Text(presentation.elapsedLabel, color = SigurColors.TextPrimary, fontWeight = FontWeight.Bold, fontSize = 18.sp)
                    }
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(presentation.primaryAction, color = SigurColors.TextSecondary, fontSize = 12.sp, lineHeight = 16.sp)
                }
            }

            Spacer(modifier = Modifier.height(10.dp))
            Text(presentation.status, color = SigurColors.TextSecondary, fontSize = 11.sp, lineHeight = 15.sp)
            presentation.diagnosticLine?.let {
                Spacer(modifier = Modifier.height(4.dp))
                Text(it, color = SigurColors.TextMuted, fontSize = 10.sp, lineHeight = 14.sp)
            }

            if (presentation.reasons.isNotEmpty()) {
                Spacer(modifier = Modifier.height(10.dp))
                Text("Ce am auzit suspect", color = SigurColors.TextPrimary, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                Spacer(modifier = Modifier.height(6.dp))
                presentation.reasons.forEach { reason ->
                    Row(modifier = Modifier.padding(vertical = 4.dp), verticalAlignment = Alignment.Top) {
                        Icon(Icons.Default.Warning, contentDescription = null, tint = accent, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(8.dp))
                        Column {
                            Text(reason.title, color = SigurColors.TextPrimary, fontWeight = FontWeight.SemiBold, fontSize = 11.sp)
                            Text(reason.body, color = SigurColors.TextMuted, fontSize = 10.sp, lineHeight = 14.sp)
                        }
                    }
                }
            }
        }
    }
}

private fun speakerGuardTone(verdict: AudioEvidenceVerdict?): DSChipTone = when (verdict) {
    AudioEvidenceVerdict.DANGEROUS -> DSChipTone.Danger
    AudioEvidenceVerdict.SUSPECT -> DSChipTone.Suspect
    AudioEvidenceVerdict.UNVERIFIED -> DSChipTone.Pending
    null -> DSChipTone.Brand
}

private fun speakerGuardAccent(verdict: AudioEvidenceVerdict?): Color = when (verdict) {
    AudioEvidenceVerdict.DANGEROUS -> SigurColors.Dangerous
    AudioEvidenceVerdict.SUSPECT -> SigurColors.Suspect
    AudioEvidenceVerdict.UNVERIFIED -> SigurColors.Pending
    null -> SigurColors.Brand
}

private fun speakerGuardLight(verdict: AudioEvidenceVerdict?): Color = when (verdict) {
    AudioEvidenceVerdict.DANGEROUS -> SigurColors.DangerousLight
    AudioEvidenceVerdict.SUSPECT -> SigurColors.SuspectLight
    AudioEvidenceVerdict.UNVERIFIED -> SigurColors.PendingLight
    null -> SigurColors.BrandTint
}

private fun speakerGuardBorder(verdict: AudioEvidenceVerdict?): Color = when (verdict) {
    AudioEvidenceVerdict.DANGEROUS -> SigurColors.DangerousBorder
    AudioEvidenceVerdict.SUSPECT -> SigurColors.SuspectBorder
    AudioEvidenceVerdict.UNVERIFIED -> SigurColors.BrandLight.copy(alpha = 0.35f)
    null -> SigurColors.Brand.copy(alpha = 0.25f)
}

@Composable
internal fun ReadinessRow(label: String, ok: Boolean) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(label, color = SigurColors.TextSecondary, fontSize = 11.sp)
        DSChip(if (ok) "OK" else "LIPSĂ", tone = if (ok) DSChipTone.Safe else DSChipTone.Pending)
    }
}

@Composable
internal fun RadarCallProtectionCard(
    cache: RadarHotCacheSnapshot?,
    audit: RadarScreeningAudit?,
    loading: Boolean,
    status: String?,
    hasCallPromptNotificationPermission: Boolean,
    reportPhoneInput: String,
    reportPhoneLoading: Boolean,
    reportPhoneStatus: String?,
    onSync: () -> Unit,
    onRefreshAudit: () -> Unit,
    onEnableRole: () -> Unit,
    onEnableCallPromptNotification: () -> Unit,
    onReportPhoneInputChange: (String) -> Unit,
    onReportPhone: () -> Unit
) {
    val expired = cache?.isExpired() ?: true
    val cacheText = when {
        cache == null -> "Cache apeluri indisponibil"
        expired -> "Cache apeluri expirat"
        else -> "${cache.hotCampaigns.size} campanii, ${cache.numberReputation.size} numere raportate"
    }

    Card(
        colors = CardDefaults.cardColors(containerColor = SigurColors.BackgroundCard),
        border = DSCardBorder,
        shape = DSCardShape,
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Phone, contentDescription = null, tint = SigurColors.Brand, modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text("Protecție apeluri", color = SigurColors.TextPrimary, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                    Text(cacheText, color = SigurColors.TextMuted, fontSize = 11.sp, lineHeight = 15.sp)
                }
                DSChip(if (expired) "necesită sync" else "offline ready", tone = if (expired) DSChipTone.Pending else DSChipTone.Safe)
            }
            status?.takeIf { it.isNotBlank() }?.let {
                Spacer(modifier = Modifier.height(8.dp))
                Text(it, color = SigurColors.TextSecondary, fontSize = 11.sp, lineHeight = 15.sp)
            }
            audit?.let {
                Spacer(modifier = Modifier.height(8.dp))
                val checkedAt = remember(it.checkedAtEpochMillis) {
                    SimpleDateFormat("HH:mm", Locale.getDefault()).format(Date(it.checkedAtEpochMillis))
                }
                Text(
                    "Ultimul apel verificat local: ${it.action.name.lowercase(Locale.getDefault())} · ${it.reason} · $checkedAt",
                    color = SigurColors.TextMuted,
                    fontSize = 11.sp,
                    lineHeight = 15.sp
                )
            }
            Spacer(modifier = Modifier.height(12.dp))
            OutlinedTextField(
                value = reportPhoneInput,
                onValueChange = onReportPhoneInputChange,
                enabled = !reportPhoneLoading,
                singleLine = true,
                label = { Text("Număr primit") },
                supportingText = {
                    Text(
                        "Raportăm doar amprenta numărului; nu trimitem contacte sau jurnalul de apeluri.",
                        color = SigurColors.TextMuted,
                        fontSize = 10.sp,
                        lineHeight = 13.sp
                    )
                },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Phone),
                colors = OutlinedTextFieldDefaults.colors(
                    focusedBorderColor = SigurColors.Brand,
                    unfocusedBorderColor = SigurColors.GlassBorder,
                    focusedTextColor = SigurColors.TextPrimary,
                    unfocusedTextColor = SigurColors.TextPrimary,
                    focusedLabelColor = SigurColors.Brand,
                    unfocusedLabelColor = SigurColors.TextSecondary,
                    cursorColor = SigurColors.Brand
                ),
                modifier = Modifier.fillMaxWidth()
            )
            reportPhoneStatus?.takeIf { it.isNotBlank() }?.let {
                Spacer(modifier = Modifier.height(6.dp))
                Text(it, color = SigurColors.TextSecondary, fontSize = 11.sp, lineHeight = 15.sp)
            }
            if (!hasCallPromptNotificationPermission) {
                Spacer(modifier = Modifier.height(8.dp))
                Card(
                    colors = CardDefaults.cardColors(containerColor = SigurColors.BrandTint),
                    border = BorderStroke(1.dp, SigurColors.Brand.copy(alpha = 0.25f)),
                    shape = DSCardShape
                ) {
                    Column(modifier = Modifier.padding(10.dp)) {
                        Text(
                            "Permite alerta Urechea ca să apară în timpul unui apel semnalat.",
                            color = SigurColors.TextSecondary,
                            fontSize = 11.sp,
                            lineHeight = 15.sp
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        Button(
                            onClick = onEnableCallPromptNotification,
                            modifier = Modifier.fillMaxWidth(),
                            colors = ButtonDefaults.buttonColors(containerColor = SigurColors.SafeLight),
                            border = BorderStroke(1.dp, SigurColors.SafeBorder),
                            shape = DSPillShape
                        ) {
                            Icon(Icons.Default.Notifications, contentDescription = null, tint = SigurColors.Safe, modifier = Modifier.size(14.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("Permite alerta", color = SigurColors.Safe, fontSize = 11.sp)
                        }
                    }
                }
            }
            Spacer(modifier = Modifier.height(8.dp))
            Button(
                onClick = onReportPhone,
                enabled = !reportPhoneLoading && reportPhoneInput.isNotBlank(),
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = SigurColors.BackgroundSurface),
                border = BorderStroke(1.dp, SigurColors.Brand),
                shape = DSPillShape
            ) {
                Icon(Icons.Default.Report, contentDescription = null, tint = SigurColors.Brand, modifier = Modifier.size(14.dp))
                Spacer(modifier = Modifier.width(6.dp))
                Text(if (reportPhoneLoading) "Se raportează..." else "Raportează număr suspect", color = SigurColors.Brand, fontSize = 11.sp)
            }
            Spacer(modifier = Modifier.height(12.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                Button(
                    onClick = onSync,
                    enabled = !loading,
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.buttonColors(containerColor = SigurColors.BrandTint),
                    border = BorderStroke(1.dp, SigurColors.Brand),
                    shape = DSPillShape
                ) {
                    Icon(Icons.Default.Refresh, contentDescription = null, tint = SigurColors.Brand, modifier = Modifier.size(14.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(if (loading) "Sync..." else "Sync", color = SigurColors.Brand, fontSize = 11.sp, maxLines = 1)
                }
                Button(
                    onClick = onRefreshAudit,
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.buttonColors(containerColor = SigurColors.BackgroundSurface),
                    border = BorderStroke(1.dp, SigurColors.GlassBorder),
                    shape = DSPillShape
                ) {
                    Icon(Icons.Default.History, contentDescription = null, tint = SigurColors.TextPrimary, modifier = Modifier.size(14.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Ultim", color = SigurColors.TextPrimary, fontSize = 11.sp, maxLines = 1)
                }
                Button(
                    onClick = onEnableRole,
                    modifier = Modifier.weight(1f),
                    colors = ButtonDefaults.buttonColors(containerColor = SigurColors.BackgroundSurface),
                    border = BorderStroke(1.dp, SigurColors.GlassBorder),
                    shape = DSPillShape
                ) {
                    Icon(Icons.Default.SettingsPhone, contentDescription = null, tint = SigurColors.TextPrimary, modifier = Modifier.size(14.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text("Rol", color = SigurColors.TextPrimary, fontSize = 11.sp, maxLines = 1)
                }
            }
        }
    }
}

internal fun requestCallScreeningRole(context: Context) {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
        val roleManager = context.getSystemService(RoleManager::class.java)
        val intent = roleManager?.createRequestRoleIntent(RoleManager.ROLE_CALL_SCREENING)
        if (intent != null) {
            context.startActivity(intent)
            return
        }
    }
    val fallback = Intent(ACTION_APPLICATION_DETAILS_SETTINGS).apply {
        data = Uri.parse("package:${context.packageName}")
        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    }
    context.startActivity(fallback)
}

@Composable
internal fun CampaignBottomCard(campaign: ScamCampaign, onOpenMap: () -> Unit) {
    Card(
        colors = CardDefaults.cardColors(containerColor = SigurColors.BackgroundCard),
        border = DSCardBorder,
        shape = DSCardShape
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Info, contentDescription = null, tint = SigurColors.Brand)
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = campaign.title,
                    color = SigurColors.TextPrimary,
                    fontWeight = FontWeight.Bold,
                    fontSize = 14.sp
                )
            }
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                "Brand: ${campaign.brand}",
                color = SigurColors.TextSecondary,
                fontSize = 12.sp
            )
            Text(
                "Risc: ${campaign.risk.uppercase()} • Scanări: ${campaign.count}",
                color = SigurColors.TextSecondary,
                fontSize = 12.sp
            )
            Text(
                "Mesaj: ${campaign.safeActionText}",
                color = SigurColors.TextPrimary,
                fontSize = 12.sp,
                modifier = Modifier.padding(top = 8.dp)
            )
            Spacer(modifier = Modifier.height(12.dp))
            Button(
                onClick = onOpenMap,
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = SigurColors.BrandTint),
                border = BorderStroke(1.dp, SigurColors.Brand),
                shape = DSPillShape
            ) {
                Icon(Icons.Default.Place, contentDescription = null, tint = SigurColors.Brand, modifier = Modifier.size(14.dp))
                Spacer(modifier = Modifier.width(6.dp))
                Text("Vezi locația exactă", color = SigurColors.Brand, fontSize = 11.sp)
            }
        }
    }
}
