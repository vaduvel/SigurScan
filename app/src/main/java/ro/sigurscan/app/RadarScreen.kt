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

@Composable
fun RadarTab(viewModel: ScannerViewModel) {
    val context = LocalContext.current
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
    val locatedCampaigns = remember(viewModel.campaigns) {
        viewModel.campaigns.count { it.lat != null && it.lon != null }
    }
    var selectedCampaign by remember { mutableStateOf<ScamCampaign?>(null) }
    val onMapCampaignSelected: (ScamCampaign?) -> Unit = { selectedCampaign = it }

    val campaignPins = remember(viewModel.campaigns) {
        viewModel.campaigns.filter { it.lat != null && it.lon != null }
    }
    var selectedCircleMemberId by remember { mutableStateOf<String?>(null) }
    val selectedCircleMember = remember(viewModel.familyMembers.toList(), selectedCircleMemberId) {
        viewModel.familyMembers.firstOrNull { it.id == selectedCircleMemberId }
            ?: viewModel.familyMembers.firstOrNull { it.isProtected }
            ?: viewModel.familyMembers.firstOrNull()
    }

    Column(modifier = Modifier.fillMaxSize().padding(20.dp).verticalScroll(rememberScrollState())) {
        Text("Radar Scam", fontSize = 20.sp, fontWeight = FontWeight.Bold, color = SigurColors.TextPrimary)
        Spacer(modifier = Modifier.height(16.dp))

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
            Spacer(modifier = Modifier.height(16.dp))
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
            Spacer(modifier = Modifier.height(16.dp))
        }

        BtrOnDeviceCard(
            snapshot = viewModel.btrSyncSnapshot,
            verdict = viewModel.inboxProvenanceVerdict,
            loading = viewModel.btrSyncLoading,
            status = viewModel.btrSyncStatus,
            provenanceStatus = viewModel.inboxProvenanceStatus,
            onSync = { viewModel.syncBtrManifests() },
            onLocalCheck = { viewModel.runLocalInboxProvenanceCheck() }
        )
        Spacer(modifier = Modifier.height(16.dp))

        CircleGuardianCard(
            members = viewModel.familyMembers,
            selectedMember = selectedCircleMember,
            onSelectedMember = { selectedCircleMemberId = it.id },
            snapshot = viewModel.circleSnapshot,
            circleLoading = viewModel.circleLoading,
            circleStatus = viewModel.circleStatus,
            guardianLoading = viewModel.guardianLoading,
            guardianStatus = viewModel.guardianStatus,
            hasAssessment = viewModel.assessment != null,
            onPair = { viewModel.createCirclePair(selectedCircleMember) },
            onPing = { viewModel.createCirclePing() },
            onResolve = { viewModel.resolveCirclePing(it) },
            onRevoke = { viewModel.revokeCirclePair() },
            onGuardian = { shareLevel, consent ->
                viewModel.requestGuardianSecondOpinion(selectedCircleMember, shareLevel, consent)
            }
        )
        Spacer(modifier = Modifier.height(16.dp))

        viewModel.liveCampaignEvent?.let { liveCampaignEvent ->
            ActiveCampaignBanner(liveCampaignEvent) {
                viewModel.clearLiveCampaignEvent()
            }
            Spacer(modifier = Modifier.height(12.dp))
        }

        viewModel.activeCampaignAlert?.let { activeCampaignAlert ->
            Card(
                colors = CardDefaults.cardColors(containerColor = SigurColors.DangerousLight),
                border = BorderStroke(1.dp, SigurColors.DangerousBorder),
                shape = DSCardShape
            ) {
                Text(
                    text = activeCampaignAlert,
                    color = SigurColors.Dangerous,
                    fontSize = 12.sp,
                    modifier = Modifier.padding(10.dp)
                )
            }
            Spacer(modifier = Modifier.height(16.dp))
        }

        if (locatedCampaigns > 0) {
            Card(
                colors = CardDefaults.cardColors(containerColor = SigurColors.BrandTint),
                border = BorderStroke(1.dp, SigurColors.Brand.copy(alpha = 0.20f)),
                shape = DSCardShape
            ) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(Icons.Default.Place, contentDescription = null, tint = SigurColors.Brand)
                        Spacer(modifier = Modifier.width(8.dp))
                        Text("Radar Geographic", color = SigurColors.TextPrimary, fontWeight = FontWeight.Bold)
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    Text("Am mapat $locatedCampaigns campanii pe hartă. Atinge un marker pentru detalii.", color = SigurColors.TextSecondary, fontSize = 12.sp)
                }
            }
            Spacer(modifier = Modifier.height(16.dp))
    RadarMapCard(
                campaigns = campaignPins,
                onCampaignSelected = onMapCampaignSelected
            )
            Spacer(modifier = Modifier.height(16.dp))
        }

        ActiveCampaignsSection(viewModel.campaigns, viewModel.campaignsLoading)
        Spacer(modifier = Modifier.height(8.dp))
        TextButton(
            onClick = { viewModel.loadCampaigns() },
            modifier = Modifier.align(Alignment.CenterHorizontally)
        ) {
            Icon(Icons.Default.Refresh, contentDescription = null, tint = SigurColors.Brand, modifier = Modifier.size(16.dp))
            Spacer(modifier = Modifier.width(8.dp))
            Text("Reîncarcă campanii", color = SigurColors.Brand)
        }

        selectedCampaign?.let { campaign ->
            Spacer(modifier = Modifier.height(12.dp))
            CampaignBottomCard(campaign = campaign) {
                openCampaignOnMap(
                    context,
                    campaign.lat,
                    campaign.lon,
                    campaign.title
                )
            }
        }
    }
}
