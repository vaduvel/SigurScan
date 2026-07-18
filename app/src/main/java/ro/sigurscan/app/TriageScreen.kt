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
import androidx.compose.material.icons.automirrored.filled.ArrowForward
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

@Composable
fun TriageTab(viewModel: ScannerViewModel) {
    val context = LocalContext.current
    val dangerHero = androidx.compose.ui.graphics.Brush.linearGradient(
        colors = listOf(Color(0xFFF0594B), Color(0xFFD32C1F))
    )

    Column(modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(start = 20.dp, end = 20.dp, top = 20.dp, bottom = 120.dp)) {
        AppHeaderV2()

        // Red emergency hero + inner "Sună la 1911" call card (v2 · Urgență)
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(22.dp))
                .background(dangerHero)
                .padding(18.dp)
        ) {
            Column {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Emergency, contentDescription = null, tint = Color.White, modifier = Modifier.size(24.dp))
                    Spacer(modifier = Modifier.width(9.dp))
                    Text(
                        "Ai pățit ceva? Acționează acum",
                        color = Color.White,
                        fontSize = 20.sp,
                        fontWeight = FontWeight.ExtraBold,
                        lineHeight = 24.sp
                    )
                }
                Text(
                    "Dacă ai dat bani, date de card sau parole, contează fiecare minut.",
                    color = Color.White.copy(alpha = 0.92f),
                    fontSize = 13.5.sp,
                    lineHeight = 19.sp,
                    modifier = Modifier.padding(top = 7.dp)
                )
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 15.dp)
                        .clip(RoundedCornerShape(15.dp))
                        .background(Color.White)
                        .clickable { context.startActivity(Intent(Intent.ACTION_DIAL, Uri.parse("tel:1911"))) }
                        .padding(14.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Box(
                        modifier = Modifier.size(44.dp).clip(RoundedCornerShape(12.dp)).background(SigurColors.Dangerous.copy(alpha = 0.13f)),
                        contentAlignment = Alignment.Center
                    ) { Icon(Icons.Default.Call, contentDescription = null, tint = SigurColors.Dangerous, modifier = Modifier.size(23.dp)) }
                    Spacer(modifier = Modifier.width(12.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text("Sună la 1911", color = SigurColors.TextPrimary, fontSize = 16.sp, fontWeight = FontWeight.ExtraBold)
                        Text("Linia DNSC pentru fraude online", color = SigurColors.TextMuted, fontSize = 12.sp)
                    }
                    Icon(Icons.AutoMirrored.Filled.ArrowForward, contentDescription = null, tint = SigurColors.Dangerous, modifier = Modifier.size(22.dp))
                }
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        // Raportează oficial → DNSC
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(14.dp))
                .background(SigurColors.BackgroundCard)
                .border(1.dp, SigurColors.GlassBorder, RoundedCornerShape(14.dp))
                .clickable { context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://pnrisc.dnsc.ro"))) }
                .padding(horizontal = 15.dp, vertical = 14.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier.size(42.dp).clip(RoundedCornerShape(12.dp)).background(SigurColors.Pending.copy(alpha = 0.13f)),
                contentAlignment = Alignment.Center
            ) { Icon(Icons.Default.Gavel, contentDescription = null, tint = SigurColors.Pending, modifier = Modifier.size(21.dp)) }
            Spacer(modifier = Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text("Raportează oficial", color = SigurColors.TextPrimary, fontSize = 14.5.sp, fontWeight = FontWeight.ExtraBold)
                Text("Deschide canalul oficial DNSC pentru raportare. Dacă ai pierdut bani sau ești amenințat, contactează și poliția.", color = SigurColors.TextMuted, fontSize = 12.sp, lineHeight = 17.sp)
            }
            Icon(Icons.Default.ChevronRight, contentDescription = null, tint = SigurColors.TextMuted, modifier = Modifier.size(22.dp))
        }

        Spacer(modifier = Modifier.height(11.dp))

        // Plan de acțiune — numbered steps, tap to mark done (tracked in viewModel)
        val planSteps = listOf(
            Triple("Blochează cardul", "Sună banca sau blochează din aplicație, dacă ai dat datele cardului.", 0),
            Triple("Schimbă parolele", "Începe cu emailul și banca, dacă ai introdus parole.", 1),
            Triple("Păstrează dovezile", "Fă capturi cu mesajul, linkul și orice plată.", 2)
        )
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(18.dp))
                .background(SigurColors.BackgroundCard)
                .border(1.dp, SigurColors.GlassBorder, RoundedCornerShape(18.dp))
                .padding(16.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Checklist, contentDescription = null, tint = SigurColors.Pending, modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text("Plan de acțiune", color = SigurColors.TextPrimary, fontSize = 15.sp, fontWeight = FontWeight.ExtraBold)
            }
            planSteps.forEach { (title, desc, idx) ->
                val done = viewModel.isTriageStepDone("urgent", idx)
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 12.dp)
                        .clickable { viewModel.setTriageStep("urgent", idx, !done) },
                    verticalAlignment = Alignment.Top
                ) {
                    Box(
                        modifier = Modifier.size(30.dp).clip(CircleShape).background(
                            if (done) SigurColors.Safe.copy(alpha = 0.16f) else SigurColors.Pending.copy(alpha = 0.13f)
                        ),
                        contentAlignment = Alignment.Center
                    ) {
                        if (done) Icon(Icons.Default.Check, contentDescription = null, tint = SigurColors.Safe, modifier = Modifier.size(17.dp))
                        else Text("${idx + 1}", color = Color(0xFF475569), fontWeight = FontWeight.ExtraBold, fontSize = 14.sp)
                    }
                    Spacer(modifier = Modifier.width(12.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            title,
                            color = SigurColors.TextPrimary,
                            fontSize = 14.5.sp,
                            fontWeight = FontWeight.ExtraBold,
                            textDecoration = if (done) TextDecoration.LineThrough else null
                        )
                        Text(desc, color = SigurColors.TextMuted, fontSize = 12.5.sp, lineHeight = 17.sp)
                    }
                }
            }
        }

        // Așteaptă decizia ta — pending invoice SANB confirmation (v2 mockup 12).
        viewModel.invoiceResult?.beneficiaryNameCheck?.takeIf { it.recommended }?.let { _ ->
            val supplier = viewModel.invoiceResult?.fields?.emitent?.takeIf { it.isNotBlank() }
            Spacer(modifier = Modifier.height(18.dp))
            Text("Așteaptă decizia ta", fontSize = 13.sp, fontWeight = FontWeight.ExtraBold, color = SigurColors.TextPrimary, modifier = Modifier.padding(start = 4.dp))
            Spacer(modifier = Modifier.height(9.dp))
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(14.dp))
                    .background(SigurColors.Suspect.copy(alpha = 0.10f))
                    .clickable { viewModel.currentTab = "scan" }
                    .padding(horizontal = 14.dp, vertical = 13.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(
                    modifier = Modifier.size(40.dp).clip(RoundedCornerShape(11.dp)).background(SigurColors.Suspect.copy(alpha = 0.16f)),
                    contentAlignment = Alignment.Center
                ) { Icon(Icons.Default.AccountBalance, contentDescription = null, tint = Color(0xFFB26B00), modifier = Modifier.size(20.dp)) }
                Spacer(modifier = Modifier.width(12.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text("Confirmă în SANB", color = SigurColors.TextPrimary, fontSize = 13.5.sp, fontWeight = FontWeight.ExtraBold)
                    Text(
                        if (supplier != null) "Factură $supplier — verifică numele beneficiarului înainte să plătești." else "Verifică numele beneficiarului înainte să plătești.",
                        color = SigurColors.TextMuted, fontSize = 12.sp, lineHeight = 17.sp
                    )
                }
                Icon(Icons.Default.ChevronRight, contentDescription = null, tint = Color(0xFFB26B00), modifier = Modifier.size(22.dp))
            }
        }
    }
}
