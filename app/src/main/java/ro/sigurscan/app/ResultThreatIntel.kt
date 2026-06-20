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
fun ThreatIntelSection(items: List<ThreatIntelSourceResult>, sandboxReportUrl: String?) {
    val context = LocalContext.current

    Column(modifier = Modifier.padding(vertical = 12.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Default.Security, contentDescription = null, tint = SigurColors.Brand, modifier = Modifier.size(16.dp))
            Spacer(modifier = Modifier.width(6.dp))
            Text("Surse de verificare", fontWeight = FontWeight.Bold, color = SigurColors.TextPrimary, fontSize = 14.sp)
        }

        Spacer(modifier = Modifier.height(8.dp))

        Card(
            colors = CardDefaults.cardColors(containerColor = SigurColors.BackgroundSurface),
            border = BorderStroke(1.dp, SigurColors.GlassBorder),
            shape = RoundedCornerShape(12.dp)
        ) {
            Column(modifier = Modifier.padding(12.dp)) {
                items.forEach { item ->
                    val statusColor = when (item.severity.lowercase(Locale.getDefault())) {
                        "high", "critical" -> SigurColors.Dangerous
                        "medium", "warning", "suspicious" -> SigurColors.Suspect
                        "low", "safe", "clean" -> SigurColors.Safe
                        else -> SigurColors.TextMuted
                    }
                    Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.Top) {
                        Box(
                            modifier = Modifier
                                .padding(top = 5.dp)
                                .size(8.dp)
                                .border(1.dp, statusColor, RoundedCornerShape(99.dp))
                        )
                        Spacer(modifier = Modifier.width(10.dp))
                        Column(modifier = Modifier.weight(1f)) {
                            Row(horizontalArrangement = Arrangement.SpaceBetween, modifier = Modifier.fillMaxWidth()) {
                                Text(publicThreatSource(item.source), color = SigurColors.TextPrimary, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                                Text(publicThreatVerdict(item.verdict), color = statusColor, fontWeight = FontWeight.Bold, fontSize = 11.sp)
                            }
                            publicThreatDetails(item.details)?.let { details ->
                                Text(details, color = SigurColors.TextSecondary, fontSize = 11.sp, lineHeight = 16.sp)
                            }
                        }
                    }
                    Spacer(modifier = Modifier.height(10.dp))
                }

                sandboxReportUrl?.takeIf { BuildConfig.DEBUG }?.let { url ->
                    TextButton(
                        onClick = {
                            runCatching {
                                context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
                            }
                        },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Icon(Icons.Default.OpenInNew, contentDescription = null, tint = SigurColors.Brand, modifier = Modifier.size(14.dp))
                        Spacer(modifier = Modifier.width(6.dp))
                        Text("Deschide detalii tehnice", color = SigurColors.Brand, fontSize = 12.sp)
                    }
                }
            }
        }
    }
}

internal fun publicThreatSource(source: String): String {
    val normalized = source.lowercase(Locale.getDefault())
    return when {
        normalized.contains("urlscan") -> "Analiză izolată"
        normalized.contains("web risk") || normalized.contains("webrisk") || normalized.contains("google") -> "Reputație globală"
        normalized.contains("phishing.database") || normalized.contains("phishing_database") -> "Listă phishing activ"
        normalized.contains("backend") -> "Analiză SigurScan"
        else -> "Sursă de verificare"
    }
}

internal fun publicThreatVerdict(verdict: String): String {
    val normalized = verdict.lowercase(Locale.getDefault())
    return when {
        normalized.contains("pending") || normalized.contains("queued") || normalized.contains("processing") -> "În verificare"
        normalized.contains("malware") || normalized.contains("phish") || normalized.contains("malicious") || normalized.contains("threat") -> "Periculos"
        normalized.contains("clean") || normalized.contains("no malicious") || normalized.contains("no threat") || normalized.contains("no classification") -> "Sigur"
        normalized.isBlank() -> "În verificare"
        else -> "Suspect"
    }
}

internal fun publicThreatDetails(details: String?): String? {
    val value = details?.trim()?.takeIf { it.isNotBlank() } ?: return null
    val normalized = value.lowercase(Locale.getDefault())
    return when {
        normalized.contains("http ") ||
            normalized.contains("exception") ||
            normalized.contains("api key") ||
            normalized.contains("backend") ||
            normalized.contains("urlscan") ||
            normalized.contains("phishing.database") ||
            normalized.contains("phishing_database") ||
            normalized.contains("web risk") ||
            normalized.contains("engines:") ||
            normalized.contains("sandbox") ->
            "Verificarea online nu a returnat suficiente detalii publice. Folosește și canalul oficial."
        normalized.contains("queued") || normalized.contains("processing") || normalized.contains("attempt") ->
            "Verificarea online este încă în curs."
        normalized.contains("not configured") || normalized.contains("unavailable") || normalized.contains("timeout") ->
            "Unele surse online nu sunt disponibile momentan."
        else -> value.take(180)
    }
}

@Composable
fun RedirectChainSection(chain: List<String>, finalUrl: String?) {
    if (chain.isNotEmpty() || finalUrl != null) {
        Column(modifier = Modifier.padding(vertical = 12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Link, contentDescription = null, tint = SigurColors.Brand, modifier = Modifier.size(16.dp))
                Spacer(modifier = Modifier.width(6.dp))
                Text("Analiză linkuri și redirecționări", fontWeight = FontWeight.Bold, color = SigurColors.TextPrimary, fontSize = 14.sp)
            }

            Spacer(modifier = Modifier.height(8.dp))

            Card(
                colors = CardDefaults.cardColors(containerColor = SigurColors.BackgroundSurface),
                border = BorderStroke(1.dp, SigurColors.GlassBorder),
                shape = RoundedCornerShape(10.dp)
            ) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Text("Urmărirea redirecționărilor a arătat următoarele:", color = SigurColors.TextSecondary, fontSize = 11.sp)
                    Spacer(modifier = Modifier.height(8.dp))

                    chain.forEachIndexed { index, url ->
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Text(
                                text = "${index + 1}. ",
                                color = SigurColors.Brand,
                                fontWeight = FontWeight.Bold,
                                fontSize = 11.sp
                            )
                            Text(
                                text = url,
                                color = SigurColors.TextPrimary,
                                fontSize = 11.sp,
                                maxLines = 1,
                                modifier = Modifier.weight(1f)
                            )
                        }
                        if (index < chain.size - 1) {
                            Icon(Icons.Default.ArrowDownward, contentDescription = null, tint = SigurColors.TextMuted, modifier = Modifier.size(12.dp).padding(start = 12.dp))
                        }
                    }

                    if (finalUrl != null && !chain.contains(finalUrl)) {
                        Spacer(modifier = Modifier.height(4.dp))
                        Icon(Icons.Default.ArrowDownward, contentDescription = null, tint = SigurColors.TextMuted, modifier = Modifier.size(12.dp).padding(start = 12.dp))
                        Text(
                            text = "DESTINAȚIE FINALĂ: $finalUrl",
                            color = SigurColors.Safe,
                            fontWeight = FontWeight.Bold,
                            fontSize = 11.sp,
                            modifier = Modifier.padding(top = 4.dp)
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun EvidenceSection(screenshotUrl: String?, serverInfo: String?, finalUrl: String?) {
    if (screenshotUrl != null || finalUrl != null) {
        val screenshotModel = sandboxScreenshotModel(screenshotUrl)
        val previewPending = screenshotUrl == null && serverInfo?.contains("genere", ignoreCase = true) == true

        Column(modifier = Modifier.padding(vertical = 12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Visibility, contentDescription = null, tint = SigurColors.Brand, modifier = Modifier.size(16.dp))
                Spacer(modifier = Modifier.width(6.dp))
                Text("Preview securizat", fontWeight = FontWeight.Bold, color = SigurColors.TextPrimary, fontSize = 14.sp)
            }

            Spacer(modifier = Modifier.height(8.dp))

            Card(
                shape = RoundedCornerShape(12.dp),
                border = BorderStroke(1.dp, SigurColors.GlassBorder),
                modifier = Modifier
                    .fillMaxWidth()
                    .height(220.dp),
                colors = CardDefaults.cardColors(containerColor = SigurColors.BackgroundSurface)
            ) {
                Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    if (screenshotModel == null) {
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            if (previewPending) {
                                CircularProgressIndicator(color = SigurColors.Brand, modifier = Modifier.size(30.dp))
                            } else if (screenshotUrl == null) {
                                Icon(Icons.Default.Visibility, contentDescription = null, tint = SigurColors.TextMuted, modifier = Modifier.size(30.dp))
                            } else {
                                CircularProgressIndicator(color = SigurColors.Brand, modifier = Modifier.size(30.dp))
                            }
                            Spacer(modifier = Modifier.height(8.dp))
                            Text(
                                text = if (previewPending || screenshotUrl != null) {
                                    "Se generează captura paginii finale..."
                                } else {
                                    "Preview indisponibil momentan"
                                },
                                color = SigurColors.TextPrimary,
                                fontSize = 10.sp
                            )
                            finalUrl?.let {
                                Text(
                                    text = "Destinație verificată: ${it.take(72)}",
                                    color = SigurColors.TextMuted,
                                    fontSize = 9.sp,
                                    textAlign = TextAlign.Center,
                                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 4.dp)
                                )
                            }
                        }
	                    } else {
	                        val localBitmap = remember(screenshotModel) {
	                            screenshotModel
	                                ?.takeIf { it.startsWith("file://", ignoreCase = true) }
	                                ?.let { Uri.parse(it).path }
	                                ?.let { path -> runCatching { BitmapFactory.decodeFile(path) }.getOrNull() }
	                        }
	                        if (localBitmap != null) {
	                            androidx.compose.foundation.Image(
	                                bitmap = localBitmap.asImageBitmap(),
                                contentDescription = "Captură izolată a paginii finale",
	                                modifier = Modifier.fillMaxSize(),
	                                contentScale = androidx.compose.ui.layout.ContentScale.Fit
	                            )
	                        } else {
	                            SubcomposeAsyncImage(
	                                model = screenshotModel,
	                                contentDescription = "Captură izolată a paginii finale",
	                                modifier = Modifier.fillMaxSize(),
	                                contentScale = androidx.compose.ui.layout.ContentScale.Fit,
	                                loading = {
	                                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
	                                        CircularProgressIndicator(color = SigurColors.Brand, modifier = Modifier.size(30.dp))
	                                        Spacer(modifier = Modifier.height(8.dp))
	                                        Text("Se încarcă preview-ul securizat...", color = SigurColors.TextPrimary, fontSize = 10.sp)
	                                    }
	                                },
	                                error = {
	                                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
	                                        Icon(Icons.Default.HourglassEmpty, contentDescription = null, tint = SigurColors.TextMuted)
	                                        Text("Captura încă se procesează...", color = SigurColors.TextMuted, fontSize = 10.sp)
	                                        Text("(reîncercare automată)", color = Color(0xFF4B5563), fontSize = 9.sp)
	                                    }
	                                }
	                            )
	                        }
	                    }

                    // Overlay for info
                    Surface(
                        color = SigurColors.TextPrimary.copy(alpha = 0.72f),
                        modifier = Modifier
                            .align(Alignment.BottomCenter)
                            .fillMaxWidth()
                    ) {
                        Text(
                            text = publicServerInfo(serverInfo),
                            color = SigurColors.TextInverse,
                            fontSize = 11.sp,
                            modifier = Modifier.padding(8.dp),
                            textAlign = TextAlign.Center
                        )
                    }
                }
            }
            Text(
                "Aceasta este o imagine izolată a paginii finale, nu site-ul real. Nu interacționezi cu pagina.",
                color = SigurColors.TextSecondary,
                fontSize = 10.sp,
                modifier = Modifier.padding(top = 4.dp, start = 4.dp)
            )
        }
    }
}

internal fun sandboxScreenshotModel(screenshotUrl: String?): String? =
    screenshotUrl
        ?.takeIf { it.isNotBlank() }
        ?.takeIf {
            it.startsWith("file://", ignoreCase = true) ||
                !it.contains("/v1/sandbox/urlscan/", ignoreCase = true)
        }

internal fun publicServerInfo(serverInfo: String?): String {
    val value = serverInfo?.trim()?.takeIf { it.isNotBlank() } ?: return "Preview securizat al paginii finale"
    val normalized = value.lowercase(Locale.getDefault())
    return when {
        normalized.contains("server:") || normalized.contains("backend") || normalized.contains("http ") || normalized.contains("sandbox") ->
            "Preview securizat al paginii finale"
        normalized.contains("pilon") || normalized.contains("pillar") || normalized.contains("provider") ->
            "Se verifică destinația și sursele de risc."
        normalized.contains("genere") || normalized.contains("processing") || normalized.contains("pending") ->
            "Preview-ul securizat se generează."
        else -> value.take(140)
    }
}
