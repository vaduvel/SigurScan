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

// Radar feature cards / map extracted from RadarScreen.kt for cohesion.

@Composable
internal fun RadarMapCard(
    campaigns: List<ScamCampaign>,
    onCampaignSelected: (ScamCampaign?) -> Unit
) {
    val campaignLookup = remember(campaigns) { campaigns.associateBy { it.id } }
    val mapHtml = remember(campaigns) { buildRadarMapHtml(campaigns) }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .height(280.dp),
        colors = CardDefaults.cardColors(containerColor = SigurColors.BackgroundSurface),
        border = DSCardBorder,
        shape = DSCardShape
    ) {
        Column(modifier = Modifier.fillMaxSize()) {
            if (campaigns.isEmpty()) {
                Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Text("Nu sunt campanii geografice valide în acest moment.", color = SigurColors.TextMuted, fontSize = 12.sp)
                }
            } else {
                AndroidView(
                    modifier = Modifier.fillMaxSize(),
	                    factory = { context ->
	                        WebView(context).apply {
	                            settings.apply {
	                                javaScriptEnabled = false
	                                domStorageEnabled = false
	                                cacheMode = WebSettings.LOAD_NO_CACHE
	                                blockNetworkLoads = true
	                                allowFileAccess = false
	                                allowContentAccess = false
	                                mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
	                            }
	                            webViewClient = RadarWebViewClient(campaignLookup, onCampaignSelected)
	                            loadDataWithBaseURL(
	                                "https://sigurscan-radar.local/",
	                                mapHtml,
                                "text/html",
                                "UTF-8",
                                null
                            )
                        }
                    },
                    update = { webView ->
                        webView.loadDataWithBaseURL(
                            "https://sigurscan-radar.local/",
                            mapHtml,
                            "text/html",
                            "UTF-8",
                            null
                        )
                    }
                )
            }
        }
	}
}

internal class RadarWebViewClient(
    private val campaignLookup: Map<String, ScamCampaign>,
    private val onCampaignSelected: (ScamCampaign?) -> Unit
) : WebViewClient() {
    override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest?): Boolean {
        return handleRadarUri(request?.url)
    }

    @Suppress("OVERRIDE_DEPRECATION")
    override fun shouldOverrideUrlLoading(view: WebView?, url: String?): Boolean {
        return handleRadarUri(url?.let(Uri::parse))
    }

    private fun handleRadarUri(uri: Uri?): Boolean {
        if (uri?.scheme != "sigurscan-radar" || uri.host != "campaign") return true
        val campaignId = uri.lastPathSegment.orEmpty()
        onCampaignSelected(campaignLookup[campaignId])
        return true
    }
}

internal fun buildRadarMapHtml(campaigns: List<ScamCampaign>): String {
    val payload = JSONArray()
    for (campaign in campaigns) {
        val lat = campaign.lat
        val lon = campaign.lon
        if (lat == null || lon == null) continue

        val item = JSONObject()
        item.put("id", campaign.id)
        item.put("title", campaign.title)
        item.put("brand", campaign.brand)
        item.put("risk", campaign.risk)
        item.put("lat", lat)
        item.put("lon", lon)
        item.put("scanCount", campaign.count)
        item.put("safeActionText", campaign.safeActionText)
        item.put("lastSeenText", campaign.lastSeenText)
        payload.put(item)
    }

    return """
	        <!doctype html>
	        <html>
	            <head>
	                <meta name="viewport" content="width=device-width, initial-scale=1.0">
	                <style>
	                    html, body, .radar {
	                        margin: 0;
	                        width: 100%;
	                        height: 100%;
	                        background:
	                            radial-gradient(circle at 48% 48%, rgba(6, 182, 212, 0.24), transparent 28%),
	                            linear-gradient(145deg, #07111f 0%, #111827 58%, #172554 100%);
	                    }
	                    body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; overflow: hidden; }
	                    .radar {
	                        position: relative;
	                        border-radius: 0;
	                    }
	                    .grid {
	                        position: absolute;
	                        inset: 0;
	                        opacity: 0.28;
	                        background-image:
	                            linear-gradient(rgba(148, 163, 184, 0.18) 1px, transparent 1px),
	                            linear-gradient(90deg, rgba(148, 163, 184, 0.18) 1px, transparent 1px);
	                        background-size: 32px 32px;
	                    }
	                    .label {
	                        position: absolute;
	                        left: 14px;
	                        top: 12px;
	                        color: #e2e8f0;
	                        font-size: 12px;
	                        letter-spacing: 0.06em;
	                        text-transform: uppercase;
	                    }
	                    .hint {
	                        position: absolute;
	                        left: 14px;
	                        right: 14px;
	                        bottom: 12px;
	                        color: #94a3b8;
	                        font-size: 11px;
	                    }
	                    .marker {
	                        position: absolute;
	                        width: 18px;
	                        height: 18px;
	                        margin: -9px 0 0 -9px;
	                        border: 2px solid #ffffff;
	                        border-radius: 999px;
	                        box-shadow: 0 0 0 8px rgba(255, 255, 255, 0.08), 0 10px 24px rgba(0, 0, 0, 0.35);
	                        text-decoration: none;
	                    }
	                    .marker.dangerous, .marker.high { background: #ef4444; }
	                    .marker.medium { background: #f59e0b; }
	                    .marker.low { background: #22c55e; }
	                    .marker span {
	                        position: absolute;
	                        left: 22px;
	                        top: -5px;
	                        min-width: 110px;
	                        color: #f8fafc;
	                        background: rgba(15, 23, 42, 0.86);
	                        border: 1px solid rgba(148, 163, 184, 0.28);
	                        border-radius: 8px;
	                        padding: 4px 6px;
	                        font-size: 10px;
	                        pointer-events: none;
	                    }
	                </style>
	            </head>
	            <body>
	                <div class="radar">
	                    <div class="grid"></div>
	                    <div class="label">Radar Romania</div>
	                    ${buildStaticRadarMarkers(payload)}
	                    <div class="hint">Punctele sunt aproximative si nu incarca resurse externe.</div>
	                </div>
	            </body>
	        </html>
	    """.trimIndent()
}

internal fun buildStaticRadarMarkers(payload: JSONArray): String {
    if (payload.length() == 0) {
        return """<div class="hint">Nu exista campanii valide pe harta.</div>"""
    }
    return (0 until payload.length()).joinToString("\n") { index ->
        val item = payload.getJSONObject(index)
        val id = item.optString("id")
        val title = item.optString("title", "Campanie")
        val risk = item.optString("risk", "medium").lowercase(Locale.US)
        val lat = item.optDouble("lat")
        val lon = item.optDouble("lon")
        val left = romanianMapX(lon)
        val top = romanianMapY(lat)
        val safeTitle = title.htmlEscape()
        """<a class="marker $risk" href="sigurscan-radar://campaign/${Uri.encode(id)}" style="left:${left}%;top:${top}%"><span>$safeTitle</span></a>"""
    }
}

internal fun romanianMapX(lon: Double): Int {
    val minLon = 20.2
    val maxLon = 29.8
    return (((lon - minLon) / (maxLon - minLon)) * 78.0 + 11.0).toInt().coerceIn(8, 92)
}

internal fun romanianMapY(lat: Double): Int {
    val minLat = 43.6
    val maxLat = 48.3
    return ((1.0 - ((lat - minLat) / (maxLat - minLat))) * 72.0 + 14.0).toInt().coerceIn(8, 92)
}

internal fun String.htmlEscape(): String {
    return replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\"", "&quot;")
        .replace("'", "&#39;")
}
