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

internal fun handleIncomingIntent(context: Context, intent: Intent?, viewModel: ScannerViewModel) {
    val plan = buildSharedIntentIntakePlan(intent)
    val streamCount = (plan as? SharedIntentIntakePlan.SharedContent)?.streams?.size ?: 0
    val autoScan = (plan as? SharedIntentIntakePlan.SharedContent)?.autoScan?.name ?: "not_applicable"
    Log.i(
        "SharedIntentIntake",
        "Incoming intent: action=${intent?.action ?: "none"}, type=${intent?.type ?: "none"}, " +
            "plan=${plan.javaClass.simpleName}, streamCount=$streamCount, autoScan=$autoScan"
    )
    executeSharedIntentIntakePlan(
        plan = plan,
        sink = object : SharedIntentIntakeSink {
            override fun clear() {
                viewModel.clearAllPendingShared()
            }

            override fun showDeepLink(text: String?) {
                if (!text.isNullOrBlank()) {
                    viewModel.text = text
                }
                viewModel.currentTab = "scan"
            }

            override fun navigate(destination: SharedIntentDestination, autoStartSpeakerGuard: Boolean) {
                when (destination) {
                    SharedIntentDestination.RADAR -> {
                        viewModel.currentTab = "radar"
                    }
                    SharedIntentDestination.SPEAKER_GUARD -> {
                        viewModel.currentTab = "radar"
                        if (
                            autoStartSpeakerGuard &&
                            BuildConfig.SIGURSCAN_ENABLE_LIVE_CALL &&
                            BuildConfig.SIGURSCAN_ENABLE_AUDIO_ASR
                        ) {
                            viewModel.acceptSpeakerGuardConsent()
                            val microphoneGranted = ContextCompat.checkSelfPermission(
                                context,
                                Manifest.permission.RECORD_AUDIO
                            ) == PackageManager.PERMISSION_GRANTED
                            if (microphoneGranted) {
                                viewModel.startSpeakerGuard()
                            } else {
                                viewModel.audioReadinessStatus = "Permite microfonul, pune celălalt telefon pe difuzor, apoi pornește Urechea aici."
                            }
                        } else {
                            viewModel.audioReadinessStatus = "Pune celălalt telefon pe difuzor, apoi apasă Pornește ascultarea."
                        }
                    }
                }
            }

            override fun stageText(payload: ResolvedSharedTextPayload, preservePendingFiles: Boolean) {
                viewModel.stageSharedTextPayload(
                    payload = payload.text,
                    sourceLabel = payload.sourceLabel,
                    preserveHtml = payload.preserveHtml,
                    autoScan = false,
                    fidelity = payload.fidelity,
                    preservePendingFiles = preservePendingFiles
                )
            }

            override fun stageFile(uri: Uri, fallbackMime: String, preserveSharedTextState: Boolean) {
                viewModel.stageSharedFile(
                    uri = uri,
                    context = context,
                    sourceLabel = sourceLabelForSharedUri(context, uri, fallbackMime),
                    fallbackMime = fallbackMime,
                    preserveSharedTextState = preserveSharedTextState
                )
            }

            override fun scanText() {
                viewModel.scanPendingSharedText()
            }

            override fun scanSingleFile() {
                Log.i(
                    "SharedIntentIntake",
                    "Auto-scanning single shared file: pendingCount=${viewModel.pendingSharedFiles.size}"
                )
                viewModel.scanPendingSharedFile(
                    viewModel.pendingSharedFiles.singleOrNull()?.id.orEmpty(),
                    context
                )
            }
        }
    )
}

internal fun resolveSharedTextPayload(intent: Intent): ResolvedSharedTextPayload? {
    return SharedTextPayloadResolver.resolve(collectSharedTextCandidates(intent))
}

internal fun resolveDeepLinkScanText(intent: Intent?): String? {
    if (!isDeepLinkScanIntent(intent)) return null
    return intent?.data?.getQueryParameter("text")?.takeIf { it.isNotBlank() }
}

internal fun collectSharedTextCandidates(intent: Intent): List<SharedTextCandidate> {
    val candidates = mutableListOf<SharedTextCandidate>()
    val intentTypeIsHtml = intent.type?.equals("text/html", ignoreCase = true) == true

    intent.getCharSequenceExtra(Intent.EXTRA_PROCESS_TEXT)
        ?.let(::sharedCharSequenceCandidate)
        ?.let { candidate ->
            candidates += SharedTextCandidate(
                text = candidate.text,
                kind = candidate.kind,
                sourceLabel = "Text selectat"
            )
        }

    intent.getStringExtra(Intent.EXTRA_HTML_TEXT)
        ?.takeIf { it.isNotBlank() }
        ?.let { html ->
            candidates += SharedTextCandidate(
                text = html,
                kind = SharedTextCandidateKind.HTML,
                sourceLabel = "Conținut HTML partajat"
            )
        }

    intent.getCharSequenceExtra(Intent.EXTRA_TEXT)
        ?.let(::sharedCharSequenceCandidate)
        ?.let { candidate ->
            candidates += SharedTextCandidate(
                text = candidate.text,
                kind = if (candidate.kind == SharedTextCandidateKind.HTML || intentTypeIsHtml) {
                    SharedTextCandidateKind.HTML
                } else {
                    SharedTextCandidateKind.PLAIN_TEXT
                },
                sourceLabel = if (candidate.kind == SharedTextCandidateKind.HTML || intentTypeIsHtml) {
                    "Conținut HTML partajat"
                } else {
                    "Conținut text partajat"
                }
            )
        }

    val clipData = intent.clipData ?: return candidates
    val clipDescriptionIsHtml = clipData.description?.hasMimeType("text/html") == true
    for (index in 0 until clipData.itemCount) {
        val item = clipData.getItemAt(index)
        item.htmlText
            ?.takeIf { it.isNotBlank() }
            ?.let { html ->
                candidates += SharedTextCandidate(
                    text = html,
                    kind = SharedTextCandidateKind.HTML,
                    sourceLabel = "Conținut HTML din ClipData"
                )
            }

        item.text
            ?.let(::sharedCharSequenceCandidate)
            ?.let { candidate ->
                val isHtml = candidate.kind == SharedTextCandidateKind.HTML || clipDescriptionIsHtml
                candidates += SharedTextCandidate(
                    text = candidate.text,
                    kind = if (isHtml) SharedTextCandidateKind.HTML else SharedTextCandidateKind.PLAIN_TEXT,
                    sourceLabel = if (isHtml) "Conținut HTML din ClipData" else "Conținut text din ClipData"
                )
            }
    }

    return candidates
}

internal fun sharedCharSequenceCandidate(value: CharSequence): SharedTextCandidate? {
    val text = when (value) {
        is Spanned -> Html.toHtml(value, Html.TO_HTML_PARAGRAPH_LINES_CONSECUTIVE)
        else -> value.toString()
    }.takeIf { it.isNotBlank() } ?: return null

    return SharedTextCandidate(
        text = text,
        kind = if (value is Spanned) SharedTextCandidateKind.HTML else SharedTextCandidateKind.PLAIN_TEXT,
        sourceLabel = if (value is Spanned) "Conținut HTML partajat" else "Conținut text partajat"
    )
}

internal fun collectSharedStreamUris(intent: Intent): List<Uri> {
    val streams = linkedMapOf<String, Uri>()
    val rawStreamExtra = intent.extras?.get(Intent.EXTRA_STREAM)

    when (intent.action) {
        Intent.ACTION_SEND_MULTIPLE -> {
            when (rawStreamExtra) {
                is ArrayList<*> -> {
                    rawStreamExtra.forEach { item ->
                        when (item) {
                            is Uri -> streams[item.toString()] = item
                            is String -> runCatching { Uri.parse(item) }
                                .getOrNull()
                                ?.let { streams[it.toString()] = it }
                        }
                    }
                }
                is String -> {
                    runCatching { Uri.parse(rawStreamExtra) }
                        .getOrNull()
                        ?.let { streams[it.toString()] = it }
                }
                is Uri -> streams[rawStreamExtra.toString()] = rawStreamExtra
                else -> Unit
            }
        }
        else -> {
            when (rawStreamExtra) {
                is Uri -> streams[rawStreamExtra.toString()] = rawStreamExtra
                is String -> {
                    runCatching { Uri.parse(rawStreamExtra) }
                        .getOrNull()
                        ?.let { streams[it.toString()] = it }
                }
                else -> Unit
            }
        }
    }

    val clipData = intent.clipData
    if (clipData != null) {
        for (index in 0 until clipData.itemCount) {
            clipData.getItemAt(index).uri?.let { uri ->
                streams[uri.toString()] = uri
            }
        }
    }

    if (streams.isEmpty()) {
        intent.data?.let { dataUri ->
            streams[dataUri.toString()] = dataUri
        }
    }

    return streams.values.toList()
}

internal fun sourceLabelForSharedUri(context: Context, uri: Uri, fallbackMime: String): String {
    val mime = runCatching {
        context.contentResolver.getType(uri)?.lowercase(Locale.getDefault())
    }.getOrNull().orEmpty().ifBlank { fallbackMime }
    return sourceLabelForMime(mime)
}

internal fun sourceLabelForMime(mime: String): String {
    return when {
        mime.startsWith("image/") -> "Imagine partajată"
        mime.startsWith("audio/") -> "Audio partajat"
        mime.startsWith("application/pdf") || mime.contains("pdf") -> "PDF partajat"
        mime == "message/rfc822" || mime.contains("eml") -> "Email partajat"
        mime.contains("text/html") -> "HTML partajat"
        mime.contains("text/") -> "Fișier text partajat"
        else -> "Fișier partajat"
    }
}

internal fun isDeepLinkScanIntent(intent: Intent?): Boolean {
    val data = intent?.data ?: return false
    if (!"sigurscan".equals(data.scheme, ignoreCase = true)) return false
    val host = data.host?.lowercase(Locale.getDefault())
    return host == "scan" || data.path?.trim('/')?.lowercase(Locale.getDefault()) == "scan"
}

internal fun isDeepLinkRadarIntent(intent: Intent?): Boolean {
    val data = intent?.data ?: return false
    if (!"sigurscan".equals(data.scheme, ignoreCase = true)) return false
    val target = data.host?.lowercase(Locale.getDefault())
        ?: data.path?.trim('/')?.lowercase(Locale.getDefault())
        ?: return false
    return target == "radar" || target == "speaker-guard"
}

internal fun resolveDeepLinkDestination(intent: Intent?): SharedIntentDestination {
    val data = intent?.data
    val target = data?.host?.lowercase(Locale.getDefault())
        ?: data?.path?.trim('/')?.lowercase(Locale.getDefault())
    return if (target == "speaker-guard") {
        SharedIntentDestination.SPEAKER_GUARD
    } else {
        SharedIntentDestination.RADAR
    }
}
