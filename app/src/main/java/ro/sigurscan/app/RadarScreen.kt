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
import ro.sigurscan.app.ui.v2.components.AppHeaderV2
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

/**
 * Radar — the "what's circulating now" scam feed (v2 · 10 · Radar):
 * green hero, live scam map, active-campaign feed (real viewModel.campaigns),
 * verified-brands entry. Protection controls live under the Protecție tab.
 */
@Composable
fun RadarTab(viewModel: ScannerViewModel) {
    val context = LocalContext.current
    LaunchedEffect(Unit) {
        if (viewModel.campaignsLoadState == CampaignLoadState.NOT_LOADED) {
            viewModel.loadCampaigns()
        }
    }
    LaunchedEffect(BuildConfig.SIGURSCAN_ENABLE_AUDIO_ASR) {
        if (BuildConfig.SIGURSCAN_ENABLE_AUDIO_ASR) {
            viewModel.refreshAudioReadiness()
        }
    }
    var hasMicrophonePermission by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.RECORD_AUDIO
            ) == PackageManager.PERMISSION_GRANTED
        )
    }
    var hasCallPromptNotificationPermission by remember {
        mutableStateOf(
            Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
                ContextCompat.checkSelfPermission(
                    context,
                    Manifest.permission.POST_NOTIFICATIONS
                ) == PackageManager.PERMISSION_GRANTED
        )
    }
    val microphonePermissionLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        hasMicrophonePermission = granted
        viewModel.refreshAudioReadiness()
        if (granted) {
            viewModel.startSpeakerGuard()
        } else {
            viewModel.audioReadinessStatus = "Permisiunea microfonului este necesară pentru Urechea."
        }
    }
    val callPromptNotificationPermissionLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        hasCallPromptNotificationPermission = granted
        viewModel.radarHotCacheStatus = if (granted) {
            "Alerta Urechea poate apărea când Radar semnalează un apel."
        } else {
            "Fără notificări, deschide manual Urechea din Radar în timpul apelului."
        }
    }
    var selectedCampaign by remember { mutableStateOf<ScamCampaign?>(null) }
    val campaignPins = remember(viewModel.campaigns.toList()) {
        viewModel.campaigns.filter { it.lat != null && it.lon != null }
    }
    val campaignPresentation = campaignFeedPresentation(
        loadState = viewModel.campaignsLoadState,
        hasCampaigns = viewModel.campaigns.isNotEmpty(),
    )
    val heroGradient = androidx.compose.ui.graphics.Brush.linearGradient(
        colors = listOf(Color(0xFF14BE86), SigurColors.Brand, Color(0xFF06875A))
    )

    Column(modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(start = 20.dp, end = 20.dp, top = 20.dp, bottom = 120.dp)) {
        AppHeaderV2()

        // Green hero — "Ce circulă acum în România"
        Box(modifier = Modifier.fillMaxWidth().clip(RoundedCornerShape(22.dp)).background(heroGradient).padding(18.dp)) {
            Column {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Radar, contentDescription = null, tint = Color.White, modifier = Modifier.size(22.dp))
                    Spacer(modifier = Modifier.width(9.dp))
                    Text("Ce circulă acum în România", color = Color.White, fontSize = 18.5.sp, fontWeight = FontWeight.ExtraBold)
                }
                Text(
                    "Înșelăciunile semnalate în ultimele zile, ca să le recunoști înainte să te prindă.",
                    color = Color.White.copy(alpha = 0.9f),
                    fontSize = 13.5.sp,
                    lineHeight = 19.sp,
                    modifier = Modifier.padding(top = 6.dp)
                )
                Row(
                    modifier = Modifier
                        .padding(top = 12.dp)
                        .clip(RoundedCornerShape(999.dp))
                        .background(Color.White.copy(alpha = 0.18f))
                        .padding(horizontal = 11.dp, vertical = 5.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(Icons.Default.Sync, contentDescription = null, tint = Color.White, modifier = Modifier.size(14.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        campaignPresentation.statusLabel,
                        color = Color.White,
                        fontSize = 11.5.sp,
                        fontWeight = FontWeight.Bold
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        if (BuildConfig.SIGURSCAN_ENABLE_LIVE_CALL) {
            RadarCallProtectionCard(
                cache = viewModel.radarHotCache,
                audit = viewModel.radarScreeningAudit,
                loading = viewModel.radarHotCacheLoading,
                status = viewModel.radarHotCacheStatus,
                hasCallPromptNotificationPermission = hasCallPromptNotificationPermission,
                reportPhoneInput = viewModel.radarReportPhoneInput,
                reportPhoneLoading = viewModel.radarReportPhoneLoading,
                reportPhoneStatus = viewModel.radarReportPhoneStatus,
                onSync = { viewModel.syncRadarHotCache() },
                onRefreshAudit = { viewModel.refreshRadarScreeningAudit() },
                onEnableRole = { requestCallScreeningRole(context) },
                onEnableCallPromptNotification = {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        callPromptNotificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                    } else {
                        hasCallPromptNotificationPermission = true
                    }
                },
                onReportPhoneInputChange = { viewModel.radarReportPhoneInput = it },
                onReportPhone = { viewModel.reportRadarPhoneNumber() }
            )
            Spacer(modifier = Modifier.height(12.dp))
        }

        if (BuildConfig.SIGURSCAN_ENABLE_AUDIO_ASR) {
            val speakerGuardPrompt = if (BuildConfig.SIGURSCAN_ENABLE_LIVE_CALL) {
                viewModel.radarScreeningAudit
                    ?.let {
                        RadarCallDecision(
                            action = it.action,
                            reason = it.reason,
                            family = it.family,
                            isKnownContact = it.isKnownContact
                        )
                    }
                    ?.takeIf { SpeakerGuardCallPromptPolicy.shouldOffer(it) && !viewModel.speakerGuardSnapshot.active }
                    ?.let { speakerGuardCallPrompt(it) }
            } else {
                null
            }
            val startSpeakerGuardWithConsent = {
                viewModel.acceptSpeakerGuardConsent()
                if (!hasMicrophonePermission) {
                    microphonePermissionLauncher.launch(Manifest.permission.RECORD_AUDIO)
                } else {
                    viewModel.startSpeakerGuard()
                }
            }
            AudioAsrReadinessCard(
                snapshot = viewModel.audioReadiness,
                status = viewModel.audioReadinessStatus,
                evidenceResult = viewModel.audioEvidenceResult,
                hasAssessment = viewModel.assessment != null,
                onConsentChanged = { viewModel.setAudioConsent(it) },
                onDisclosureChanged = { viewModel.setAudioPrivacyDisclosureAccepted(it) },
                onRefresh = { viewModel.refreshAudioReadiness() },
                onAnalyzeTranscript = { viewModel.analyzeCurrentTextAsAudioTranscript() },
                speakerGuard = viewModel.speakerGuardSnapshot,
                callPrompt = speakerGuardPrompt,
                hasMicrophonePermission = hasMicrophonePermission,
                onStartSpeakerGuard = startSpeakerGuardWithConsent,
                onStopSpeakerGuard = { viewModel.stopSpeakerGuard() }
            )
            Spacer(modifier = Modifier.height(12.dp))
        }

        // Live scam map (real pins)
        if (campaignPins.isNotEmpty()) {
            RadarMapCard(campaigns = campaignPins, onCampaignSelected = { selectedCampaign = it })
            Spacer(modifier = Modifier.height(4.dp))
            Text("Harta înșelăciunilor · azi", color = SigurColors.TextMuted, fontSize = 11.sp, modifier = Modifier.padding(start = 4.dp))
            Spacer(modifier = Modifier.height(14.dp))
        }

        // Campanii active — real feed
        Text("Campanii active", color = SigurColors.TextPrimary, fontSize = 13.sp, fontWeight = FontWeight.ExtraBold, modifier = Modifier.padding(start = 4.dp))
        Spacer(modifier = Modifier.height(10.dp))

        if (viewModel.campaignsLoading && viewModel.campaigns.isEmpty()) {
            Box(modifier = Modifier.fillMaxWidth().height(72.dp), contentAlignment = Alignment.Center) {
                CircularProgressIndicator(color = SigurColors.Brand)
            }
        } else if (viewModel.campaigns.isEmpty()) {
            Text(
                campaignPresentation.emptyLabel.orEmpty(),
                color = SigurColors.TextMuted,
                fontSize = 13.sp,
                modifier = Modifier.padding(start = 4.dp, bottom = 4.dp),
            )
        } else {
            campaignPresentation.supportingLabel?.let { label ->
                Text(
                    label,
                    color = SigurColors.Suspect,
                    fontSize = 12.sp,
                    modifier = Modifier.padding(start = 4.dp, bottom = 8.dp),
                )
            }
            viewModel.campaigns.forEach { campaign ->
                CampaignRowV2(campaign = campaign, onClick = { selectedCampaign = campaign })
                Spacer(modifier = Modifier.height(10.dp))
            }
        }

        Spacer(modifier = Modifier.height(2.dp))

        // Branduri verificate
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(16.dp))
                .background(SigurColors.BackgroundCard)
                .border(1.dp, SigurColors.GlassBorder, RoundedCornerShape(16.dp))
                .padding(horizontal = 15.dp, vertical = 14.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier.size(42.dp).clip(RoundedCornerShape(12.dp)).background(SigurColors.Brand.copy(alpha = 0.14f)),
                contentAlignment = Alignment.Center
            ) { Icon(Icons.Default.Verified, contentDescription = null, tint = SigurColors.Brand, modifier = Modifier.size(21.dp)) }
            Spacer(modifier = Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text("Branduri verificate", color = SigurColors.TextPrimary, fontSize = 14.sp, fontWeight = FontWeight.ExtraBold)
                Text("Domeniile și IBAN-urile oficiale ale firmelor cunoscute, ca să le deosebești de imitații.", color = SigurColors.TextMuted, fontSize = 12.sp, lineHeight = 17.sp)
                Text(
                    "Folosit automat în scanări",
                    color = SigurColors.Safe,
                    fontSize = 11.5.sp,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.padding(top = 5.dp),
                )
            }
        }

        Spacer(modifier = Modifier.height(8.dp))
        TextButton(onClick = { viewModel.loadCampaigns() }, modifier = Modifier.align(Alignment.CenterHorizontally)) {
            Icon(Icons.Default.Refresh, contentDescription = null, tint = SigurColors.Brand, modifier = Modifier.size(16.dp))
            Spacer(modifier = Modifier.width(8.dp))
            Text("Reîncarcă campanii", color = SigurColors.Brand)
        }

        selectedCampaign?.let { campaign ->
            Spacer(modifier = Modifier.height(12.dp))
            CampaignBottomCard(campaign = campaign) {
                openCampaignOnMap(context, campaign.lat, campaign.lon, campaign.title)
            }
        }
    }
}

/** One active-campaign card — icon chip + title + severity badge + description (v2). */
@Composable
private fun CampaignRowV2(campaign: ScamCampaign, onClick: () -> Unit) {
    val accent = when (campaign.risk.lowercase()) {
        "high", "critical", "dangerous", "danger", "red" -> Color(0xFFE5392B)
        "medium", "suspect", "warn", "warning", "yellow", "orange" -> Color(0xFFF2900B)
        else -> Color(0xFF2563EB)
    }
    val badgeLabel = campaign.status?.takeIf { it.isNotBlank() } ?: when (campaign.risk.lowercase()) {
        "high", "critical", "dangerous", "danger", "red" -> "În creștere"
        "medium", "suspect", "warn", "warning", "yellow", "orange" -> "Activ"
        else -> "De urmărit"
    }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(16.dp))
            .background(SigurColors.BackgroundCard)
            .border(1.dp, SigurColors.GlassBorder, RoundedCornerShape(16.dp))
            .clickable(onClick = onClick)
            .padding(horizontal = 15.dp, vertical = 14.dp),
        verticalAlignment = Alignment.Top
    ) {
        Box(
            modifier = Modifier.size(42.dp).clip(RoundedCornerShape(12.dp)).background(accent.copy(alpha = 0.14f)),
            contentAlignment = Alignment.Center
        ) { Icon(Icons.Default.Campaign, contentDescription = null, tint = accent, modifier = Modifier.size(21.dp)) }
        Spacer(modifier = Modifier.width(12.dp))
        Column(modifier = Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    campaign.title,
                    color = SigurColors.TextPrimary,
                    fontSize = 14.5.sp,
                    fontWeight = FontWeight.ExtraBold,
                    modifier = Modifier.weight(1f, fill = false),
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis
                )
                Spacer(modifier = Modifier.width(8.dp))
                Box(
                    modifier = Modifier.clip(RoundedCornerShape(999.dp)).background(accent.copy(alpha = 0.15f)).padding(horizontal = 9.dp, vertical = 3.dp)
                ) { Text(badgeLabel, color = accent, fontSize = 11.sp, fontWeight = FontWeight.ExtraBold) }
            }
            Text(
                campaign.description,
                color = SigurColors.TextMuted,
                fontSize = 12.5.sp,
                lineHeight = 17.sp,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.padding(top = 4.dp)
            )
        }
    }
}
