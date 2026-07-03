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
fun TriageTab(viewModel: ScannerViewModel) {
    val context = LocalContext.current
    var selectedCategory by remember { mutableStateOf("card") }

    val guides = mapOf(
        "card" to Triple("Compromitere date card", Icons.Outlined.CreditCard, SigurColors.Dangerous),
        "whatsapp" to Triple("Cont WhatsApp compromis", Icons.Outlined.Smartphone, SigurColors.Safe),
        "anydesk" to Triple("Aplicație control distanță", Icons.Outlined.Download, SigurColors.Brand),
        "personal" to Triple("Date personale trimise", Icons.Outlined.AccountBox, SigurColors.Suspect)
    )

    Column(modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(start = 20.dp, end = 20.dp, top = 20.dp, bottom = 120.dp)) {
        Text("Centrul de Urgență", fontSize = 20.sp, fontWeight = FontWeight.Bold, color = SigurColors.TextPrimary)
        Spacer(modifier = Modifier.height(16.dp))

        Card(
            colors = CardDefaults.cardColors(containerColor = SigurColors.BackgroundCard),
            shape = DSCardShape,
            border = DSCardBorder,
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(20.dp)) {
                Icon(Icons.Default.Warning, contentDescription = null, tint = SigurColors.Dangerous, modifier = Modifier.size(28.dp))
                Text("Ghiduri Interactive Anti-Fraudă", color = SigurColors.TextPrimary, fontWeight = FontWeight.Bold, modifier = Modifier.padding(top = 8.dp))
                Text("Alegeți mai jos scenariul potrivit pentru a genera un plan de măsuri.", color = SigurColors.TextSecondary, fontSize = 13.sp)
            }
        }

        Spacer(modifier = Modifier.height(20.dp))

        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            guides.forEach { (key, value) ->
                val isSelected = selectedCategory == key
                Card(
                    modifier = Modifier.weight(1f).clickable { selectedCategory = key },
                    colors = CardDefaults.cardColors(containerColor = if (isSelected) value.third.copy(alpha = 0.15f) else SigurColors.BackgroundCard),
                    shape = DSCardShape,
                    border = BorderStroke(1.dp, if (isSelected) value.third else SigurColors.GlassBorder)
                ) {
                    Column(modifier = Modifier.padding(8.dp).fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
                        Icon(value.second, contentDescription = null, tint = if (isSelected) value.third else SigurColors.TextMuted, modifier = Modifier.size(20.dp))
                        Text(value.first.split(" ")[0], color = if (isSelected) SigurColors.TextPrimary else SigurColors.TextMuted, fontSize = 10.sp, textAlign = TextAlign.Center)
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(20.dp))

        TriageDetail(
            category = selectedCategory,
            viewModel = viewModel
        )

        Spacer(modifier = Modifier.height(20.dp))

        Card(
            colors = CardDefaults.cardColors(containerColor = SigurColors.BrandTint),
            shape = DSCardShape,
            border = BorderStroke(1.dp, SigurColors.Brand.copy(alpha = 0.15f))
        ) {
            Column(modifier = Modifier.padding(20.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Phone, contentDescription = null, tint = SigurColors.Brand)
                    Text("Asistență Telefonică (DNSC)", color = SigurColors.TextPrimary, fontWeight = FontWeight.Bold, modifier = Modifier.padding(start = 8.dp))
                }
                Text("Dacă ați fost victima unei fraude, contactați DNSC la numărul unic gratuit: 1911", color = SigurColors.TextSecondary, fontSize = 12.sp, modifier = Modifier.padding(vertical = 12.dp))
                Button(
                    onClick = {
                        val intent = Intent(Intent.ACTION_DIAL, Uri.parse("tel:1911"))
                        context.startActivity(intent)
                    },
                    modifier = Modifier.fillMaxWidth(),
                    shape = DSPillShape,
                    colors = ButtonDefaults.buttonColors(containerColor = SigurColors.Brand)
                ) {
                    Text("Sunați la 1911")
                }
            }
        }
    }
}

@Composable
fun TriageDetail(category: String, viewModel: ScannerViewModel) {
    val steps = when(category) {
        "card" -> listOf(
            "Blocați imediat cardul din aplicația bancară" to "Folosiți opțiunea de înghețare (Freeze/Block) a cardului.",
            "Sunați la asistența clienți a băncii dvs." to "Raportați tranzacțiile neautorizate rapid.",
            "Depuneți plângere la Poliție și DNSC (1911)" to "Salvați screenshot-uri cu mesajul și site-ul clonat."
        )
        "whatsapp" -> listOf(
            "Verificați dispozitivele conectate" to "În WhatsApp: Setări -> Dispozitive asociate. Deconectați tot.",
            "Activați verificarea în doi pași" to "Configurați un cod PIN personal în Setări -> Cont.",
            "Avertizați-vă contactele de urgență" to "Anunțați-i că cineva ar putea cere bani în numele dvs."
        )
        "anydesk" -> listOf(
            "Deconectați telefonul de la internet" to "Activați Modul Avion imediat.",
            "Dezinstalați aplicația suspectă" to "Ștergeți AnyDesk, TeamViewer sau fișierele .APK.",
            "Schimbați parolele bancare" to "Faceți acest lucru de pe un alt dispozitiv sigur."
        )
        else -> listOf(
            "Alertați DNSC la numărul 1911" to "Raportați incidentul pe site-ul dnsc.ro.",
            "Monitorizați încercările de credite" to "Verificați Biroul de Credit periodic.",
            "Înlocuiți actul de identitate" to "Dacă poza buletinului a ajuns la atacatori, declarați-l pierdut."
        )
    }

    Card(
        colors = CardDefaults.cardColors(containerColor = SigurColors.BackgroundCard),
        shape = DSCardShape,
        border = DSCardBorder
    ) {
        Column(modifier = Modifier.padding(20.dp)) {
            steps.forEachIndexed { index, (title, detail) ->
                val checked = viewModel.isTriageStepDone(category, index)
                Row(
                    modifier = Modifier
                        .padding(vertical = 8.dp)
                        .clickable { viewModel.setTriageStep(category, index, !checked) }
                ) {
                    Icon(
                        imageVector = if (checked) Icons.Default.CheckBox else Icons.Default.CheckBoxOutlineBlank,
                        contentDescription = null,
                        tint = if (checked) SigurColors.Safe else SigurColors.TextMuted
                    )
                    Spacer(modifier = Modifier.width(12.dp))
                    Column {
                        Text(title, color = SigurColors.TextPrimary, fontWeight = FontWeight.Bold, fontSize = 14.sp, textDecoration = if (checked) TextDecoration.LineThrough else null)
                        Text(detail, color = SigurColors.TextSecondary, fontSize = 12.sp)
                    }
                }
            }
        }
    }
}
