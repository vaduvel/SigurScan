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

@Composable
fun MoreTab(viewModel: ScannerViewModel) {
    Column(modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(start = 20.dp, end = 20.dp, top = 20.dp, bottom = 120.dp)) {
        AppHeaderV2()

        Text("Securitate și familie", fontSize = 13.sp, fontWeight = FontWeight.ExtraBold, color = SigurColors.TextPrimary, modifier = Modifier.padding(start = 4.dp, bottom = 10.dp))
        SecurityFamilySection(viewModel)

        Spacer(modifier = Modifier.height(22.dp))

        Text("Educație anti-fraudă", fontSize = 13.sp, fontWeight = FontWeight.ExtraBold, color = SigurColors.TextPrimary, modifier = Modifier.padding(start = 4.dp, bottom = 10.dp))
        LessonsSection(viewModel)

        Spacer(modifier = Modifier.height(22.dp))

        Text("Registru amenințări (pe telefon)", fontSize = 13.sp, fontWeight = FontWeight.ExtraBold, color = SigurColors.TextPrimary, modifier = Modifier.padding(start = 4.dp, bottom = 10.dp))
        BtrOnDeviceCard(
            snapshot = viewModel.btrSyncSnapshot,
            verdict = viewModel.inboxProvenanceVerdict,
            loading = viewModel.btrSyncLoading,
            status = viewModel.btrSyncStatus,
            provenanceStatus = viewModel.inboxProvenanceStatus,
            onSync = { viewModel.syncBtrManifests() },
            onLocalCheck = { viewModel.runLocalInboxProvenanceCheck() }
        )

        Spacer(modifier = Modifier.height(22.dp))

        if (BuildConfig.DEBUG) {
            ReportsTab(viewModel)

            Spacer(modifier = Modifier.height(16.dp))

            ContrastSection()

            Spacer(modifier = Modifier.height(16.dp))
        }

        Card(
            colors = CardDefaults.cardColors(containerColor = SigurColors.BackgroundCard),
            shape = DSCardShape,
            border = DSCardBorder
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.History, contentDescription = null, tint = SigurColors.Brand)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Istoric Scanări", color = SigurColors.TextPrimary, fontWeight = FontWeight.Bold)
                }
                Spacer(modifier = Modifier.height(8.dp))

                if (viewModel.historyItems.isEmpty()) {
                    Text("Nicio scanare salvată încă.", color = SigurColors.TextSecondary, fontSize = 12.sp)
                } else {
                    viewModel.historyItems.forEach { item ->
                        HistoryItemCard(
                            item = item,
                            onClick = {
                                viewModel.assessment = item
                                viewModel.currentTab = "scan"
                            },
                            onDelete = { viewModel.deleteHistoryItem(item) }
                        )
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))
        AboutTab()
    }
}

@Composable
fun SecurityFamilySection(viewModel: ScannerViewModel) {
    var showAddDialog by remember { mutableStateOf(false) }
    var memberName by remember { mutableStateOf("") }
    var memberContact by remember { mutableStateOf("") }
    var showClearConfirm by remember { mutableStateOf(false) }

    if (showAddDialog) {
        AlertDialog(
            onDismissRequest = { showAddDialog = false },
            title = { Text("Adaugă membru în familie") },
            text = {
                Column {
                    OutlinedTextField(
                        value = memberName,
                        onValueChange = { memberName = it },
                        label = { Text("Nume") },
                        modifier = Modifier.fillMaxWidth()
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedTextField(
                        value = memberContact,
                        onValueChange = { memberContact = it },
                        label = { Text("Telefon / Email") },
                        modifier = Modifier.fillMaxWidth()
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        viewModel.addFamilyMember(memberName, memberContact)
                        memberName = ""
                        memberContact = ""
                        showAddDialog = false
                    },
                    enabled = memberName.isNotBlank() && memberContact.isNotBlank()
                ) {
                    Text("Salvează")
                }
            },
            dismissButton = {
                TextButton(
                    onClick = {
                        memberName = ""
                        memberContact = ""
                        showAddDialog = false
                    }
                ) {
                    Text("Anulează")
                }
            }
        )
    }

    if (showClearConfirm) {
        AlertDialog(
            onDismissRequest = { showClearConfirm = false },
            title = { Text("Ștergi alertele de familie?") },
            text = { Text("Această acțiune șterge istoricul local de alerte.") },
            confirmButton = {
                Button(
                    onClick = {
                        viewModel.clearFamilyAlerts()
                        showClearConfirm = false
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = SigurColors.DangerousLight),
                    border = BorderStroke(1.dp, SigurColors.DangerousBorder)
                ) {
                    Text("Șterge", color = SigurColors.Dangerous)
                }
            },
            dismissButton = {
                TextButton(onClick = { showClearConfirm = false }) {
                    Text("Anulează")
                }
            }
        )
    }

    Card(
        colors = CardDefaults.cardColors(containerColor = SigurColors.BackgroundCard),
        shape = DSCardShape,
        border = DSCardBorder
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text("Securitate și Familie", color = SigurColors.TextPrimary, fontWeight = FontWeight.Bold)
            Spacer(modifier = Modifier.height(12.dp))

            Text(
                "Scor protecție: ${viewModel.familyResilienceScore}/100",
                color = SigurColors.TextSecondary,
                fontSize = 12.sp,
                fontWeight = FontWeight.Bold
            )
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                "Membrii protejați: ${viewModel.familyMembers.count { it.isProtected }} / ${viewModel.familyMembers.size}",
                color = SigurColors.TextSecondary,
                fontSize = 11.sp
            )

            Spacer(modifier = Modifier.height(12.dp))

            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(
                    modifier = Modifier.weight(1f),
                    onClick = { showAddDialog = true },
                    shape = DSPillShape,
                    colors = ButtonDefaults.buttonColors(containerColor = SigurColors.BrandTint),
                    border = BorderStroke(1.dp, SigurColors.Brand)
                ) {
                    Text("Adaugă membru", color = SigurColors.Brand, fontSize = 12.sp)
                }
                Button(
                    modifier = Modifier.weight(1f),
                    onClick = { viewModel.notifyFamilyForCurrentScan() },
                    enabled = viewModel.assessment != null && viewModel.familyMembers.any { it.isProtected },
                    shape = DSPillShape,
                    colors = ButtonDefaults.buttonColors(containerColor = SigurColors.SafeLight),
                    border = BorderStroke(1.dp, SigurColors.SafeBorder)
                ) {
                    Icon(Icons.Default.Notifications, contentDescription = null, tint = SigurColors.Safe, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Trimite alertă", color = SigurColors.Safe, fontSize = 12.sp)
                }
            }

            Spacer(modifier = Modifier.height(12.dp))
            if (viewModel.familyMembers.isEmpty()) {
                Text(
                    "Nu există membri Family adăugați. Adaugă cel puțin o persoană de încredere.",
                    color = SigurColors.TextSecondary,
                    fontSize = 11.sp
                )
            } else {
                viewModel.familyMembers.forEach { member ->
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(member.name, color = SigurColors.TextPrimary, fontWeight = FontWeight.Bold)
                            Text(member.contact, color = SigurColors.TextSecondary, fontSize = 11.sp)
                        }

                        Switch(
                            checked = member.isProtected,
                            onCheckedChange = { isProtected -> viewModel.toggleFamilyProtection(member.id, isProtected) }
                        )
                        IconButton(onClick = { viewModel.removeFamilyMember(member.id) }) {
                            Icon(Icons.Default.Delete, contentDescription = "Șterge", tint = SigurColors.Dangerous)
                        }
                    }
                }
            }

            if (viewModel.familyAlerts.isNotEmpty()) {
                Spacer(modifier = Modifier.height(12.dp))
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                    Text("Alerte recente", color = SigurColors.TextPrimary, fontWeight = FontWeight.SemiBold, fontSize = 13.sp)
                    TextButton(onClick = { showClearConfirm = true }) {
                        Text("șterge", color = SigurColors.TextMuted, fontSize = 10.sp)
                    }
                }

                viewModel.familyAlerts.forEach { alert ->
                    Card(
                        colors = CardDefaults.cardColors(containerColor = SigurColors.BackgroundSurface),
                        shape = DSCardShape,
                        border = DSCardBorder,
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(bottom = 8.dp)
                    ) {
                        Column(modifier = Modifier.padding(10.dp)) {
                            Text(
                                "${alert.memberName} • ${alert.triggerLabel}",
                                color = SigurColors.TextSecondary,
                                fontSize = 11.sp
                            )
                            Text(
                                "${alert.family} (${alert.riskLevel.uppercase()})",
                                color = SigurColors.TextPrimary,
                                fontWeight = FontWeight.Bold,
                                fontSize = 12.sp
                            )
                            Text(
                                alert.snapshot,
                                color = SigurColors.TextSecondary,
                                fontSize = 10.sp
                            )
                            Text(
                                SimpleDateFormat("dd MMM HH:mm", Locale.getDefault()).format(Date(alert.timestamp)),
                                color = SigurColors.TextMuted,
                                fontSize = 10.sp
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun ContrastSection() {
    val foregroundColors = listOf(
        SigurColors.TextPrimary to "Text Primary",
        SigurColors.TextSecondary to "Text Secondary",
        SigurColors.TextMuted to "Text Muted",
        SigurColors.TextInverse to "Text Inverse"
    )
    val backgroundOptions = listOf(
        Pair(SigurColors.BackgroundCard, "Card"),
        Pair(SigurColors.Canvas, "Canvas"),
        Pair(SigurColors.Brand, "Brand"),
        Pair(SigurColors.BackgroundSurface, "Surface")
    )

    val checks = mutableListOf<Pair<String, Float>>()
    foregroundColors.forEach { fg ->
        backgroundOptions.forEach { bg ->
            val ratio = contrastRatio(fg.first, bg.first)
            checks.add("${fg.second} / ${bg.second}" to ratio)
        }
    }

    Card(
        colors = CardDefaults.cardColors(containerColor = SigurColors.BackgroundCard),
        shape = DSCardShape,
        border = DSCardBorder
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text("Contrast Checker", color = SigurColors.TextPrimary, fontWeight = FontWeight.Bold)
            Spacer(modifier = Modifier.height(12.dp))

            checks.take(6).forEach { item ->
                val wcagLevel = when {
                    item.second >= 7f -> "AAA"
                    item.second >= 4.5f -> "AA"
                    item.second >= 3f -> "AA Large"
                    else -> "FAIL"
                }
                val labelColor = if (item.second >= 4.5f) SigurColors.Safe else SigurColors.Suspect

                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text(item.first, color = SigurColors.TextSecondary, fontSize = 11.sp, modifier = Modifier.weight(1f))
                    Text(
                        "${String.format("%.2f", item.second)} ($wcagLevel)",
                        color = labelColor,
                        fontSize = 11.sp,
                        fontWeight = FontWeight.Bold
                    )
                }
                Spacer(modifier = Modifier.height(8.dp))
            }

            Text(
                "Scor minim recomandat AA: 4.5 (text normal).",
                color = SigurColors.TextMuted,
                fontSize = 10.sp
            )
        }
    }
}

@Composable
fun AboutTab() {
    val uriHandler = LocalUriHandler.current

    Column(modifier = Modifier.fillMaxWidth().padding(20.dp), horizontalAlignment = Alignment.CenterHorizontally) {
        Header()
        Spacer(modifier = Modifier.height(20.dp))

        Text(
            "SigurScan este proiectat special pentru contextul cibernetic din România, oferind protecție împotriva celor mai frecvente tipuri de fraude locale.",
            color = SigurColors.TextPrimary,
            textAlign = TextAlign.Center,
            fontSize = 14.sp,
            lineHeight = 20.sp
        )

        Spacer(modifier = Modifier.height(20.dp))

        Card(
            colors = CardDefaults.cardColors(containerColor = SigurColors.BackgroundCard),
            shape = DSCardShape,
            border = DSCardBorder
        ) {
            Column(modifier = Modifier.padding(20.dp)) {
                Text("De ce SigurScan?", color = SigurColors.Brand, fontWeight = FontWeight.Bold)
                Spacer(modifier = Modifier.height(8.dp))
                Text("• Detecție localizată (FAN, Poșta Română, ANAF)\n• Scanare fără a deschide linkurile în browserul tău\n• Ghiduri de urgență pas-cu-pas\n• Nu monitorizează automat notificări, inbox sau clipboard", color = SigurColors.TextSecondary, fontSize = 13.sp, lineHeight = 22.sp)
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        BuildConfig.SIGURSCAN_PRIVACY_URL.takeIf { it.isNotBlank() }?.let { privacyUrl ->
            OutlinedButton(
                onClick = { uriHandler.openUri(privacyUrl) },
                border = BorderStroke(1.dp, SigurColors.Brand),
                shape = DSPillShape
            ) {
                Icon(Icons.Default.PrivacyTip, contentDescription = null, tint = SigurColors.Brand)
                Spacer(modifier = Modifier.width(8.dp))
                Text("Politica de confidențialitate", color = SigurColors.Brand)
            }
        }

        Spacer(modifier = Modifier.height(40.dp))
        Text("Versiune 1.0.0 (Kotlin Native Edition)", color = SigurColors.TextMuted, fontSize = 12.sp)
    }
}

@Composable
fun NoticeSection() {
    Card(
        colors = CardDefaults.cardColors(containerColor = SigurColors.BrandTint),
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, SigurColors.Brand.copy(alpha = 0.15f), RoundedCornerShape(8.dp))
    ) {
        Text(
            text = "🛡️ Promisiune: SigurScan nu va deschide niciodată paginile suspecte în browserul tău și nu îți va accesa datele personale.",
            color = SigurColors.TextSecondary,
            fontSize = 11.sp,
            modifier = Modifier.padding(10.dp),
            lineHeight = 16.sp
        )
    }
}

internal fun contrastChannel(channel: Float): Float {
    return if (channel <= 0.03928f) channel / 12.92f else ((channel + 0.055f) / 1.055f).pow(2.4f)
}

internal fun contrastRatio(foreground: Color, background: Color): Float {
    val fgR = contrastChannel(foreground.red)
    val fgG = contrastChannel(foreground.green)
    val fgB = contrastChannel(foreground.blue)
    val bgR = contrastChannel(background.red)
    val bgG = contrastChannel(background.green)
    val bgB = contrastChannel(background.blue)

    val fgLuminance = 0.2126f * fgR + 0.7152f * fgG + 0.0722f * fgB
    val bgLuminance = 0.2126f * bgR + 0.7152f * bgG + 0.0722f * bgB

    val lighter = max(fgLuminance, bgLuminance)
    val darker = min(fgLuminance, bgLuminance)

    return (lighter + 0.05f) / (darker + 0.05f)
}
