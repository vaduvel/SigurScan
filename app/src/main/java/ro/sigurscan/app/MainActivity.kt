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

class MainActivity : ComponentActivity() {
    private lateinit var viewModel: ScannerViewModel

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            SigurScanTheme {
                val viewModel: ScannerViewModel = viewModel()
                this@MainActivity.viewModel = viewModel
                val startupIntent = remember { intent }
                LaunchedEffect(startupIntent) {
                    handleIncomingIntent(this@MainActivity, startupIntent, viewModel)
                }

                MainScreen(viewModel)
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        if (::viewModel.isInitialized) {
            handleIncomingIntent(this, intent, viewModel)
        }
    }
}

@Composable
fun MainScreen(viewModel: ScannerViewModel) {
    val context = LocalContext.current
    var pendingInvoicePhotoUri by remember { mutableStateOf<Uri?>(null) }
    val imagePickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri ->
        uri?.let { viewModel.onImagePicked(it, context) }
    }

    val filePickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri ->
        uri?.let { viewModel.onFilePicked(it, context) }
    }

    val qrPickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri ->
        uri?.let { viewModel.onQrPicked(it, context) }
    }
    val invoicePickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri ->
        uri?.let { viewModel.scanInvoiceFromDocument(it, context) }
    }
    val invoiceOfficialXmlPickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { xmlUri ->
        xmlUri?.let { selectedXmlUri ->
            val invoiceUri = viewModel.lastInvoiceScanSource?.uri
            if (invoiceUri != null) {
                viewModel.scanInvoiceFromDocument(invoiceUri, context, officialXmlUri = selectedXmlUri)
            } else {
                Toast.makeText(context, "Reîncarcă factura înainte să atașezi XML-ul oficial.", Toast.LENGTH_SHORT).show()
            }
        }
    }
    val invoicePhotoLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.TakePicture()
    ) { captured ->
        val capturedUri = pendingInvoicePhotoUri
        if (captured && capturedUri != null) {
            viewModel.scanInvoiceFromDocument(capturedUri, context)
        }
        pendingInvoicePhotoUri = null
    }
    fun launchInvoiceCameraCapture() {
        val uri = createInvoiceCaptureUri(context)
        pendingInvoicePhotoUri = uri
        invoicePhotoLauncher.launch(uri)
    }
    val invoiceCameraPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (granted) {
            launchInvoiceCameraCapture()
        } else {
            pendingInvoicePhotoUri = null
            Toast.makeText(context, "Permite camera ca să fotografiezi factura.", Toast.LENGTH_SHORT).show()
        }
    }
    val offerPickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri ->
        uri?.let { viewModel.scanOfferFromDocument(it, context) }
    }
    val captureInvoicePhoto = {
        if (ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) {
            launchInvoiceCameraCapture()
        } else {
            invoiceCameraPermissionLauncher.launch(Manifest.permission.CAMERA)
        }
    }
    var hasQrCameraPermission by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED
        )
    }
    val qrCameraPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission()
    ) { granted ->
        hasQrCameraPermission = granted
        if (!granted) {
            Toast.makeText(context, "Permite camera ca să scanezi codul QR.", Toast.LENGTH_SHORT).show()
        }
    }
    var showQrScanner by remember { mutableStateOf(false) }
    val closeQrScanner = { showQrScanner = false }

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        containerColor = SigurColors.Canvas,
        bottomBar = {
            BottomNavigationBar(viewModel.currentTab) { viewModel.currentTab = it }
        }
    ) { innerPadding ->
        Box(modifier = Modifier.padding(innerPadding)) {
            when (viewModel.currentTab) {
                "scan" -> ScanTab(
                    viewModel, 
                    onPickImage = { imagePickerLauncher.launch("image/*") },
                    onPickFile = { filePickerLauncher.launch("*/*") },
                    onScanQr = { showQrScanner = true },
                    onCaptureInvoicePhoto = captureInvoicePhoto,
                    onScanInvoice = { invoicePickerLauncher.launch(arrayOf("image/*", "application/pdf")) },
                    onInvoiceOfficialXmlCheck = {
                        invoiceOfficialXmlPickerLauncher.launch(arrayOf("application/xml", "text/xml", "text/*"))
                    },
                    onScanOffer = { offerPickerLauncher.launch(arrayOf("image/*", "application/pdf", "text/*", "text/html", "message/rfc822")) }
                )
                "radar" -> RadarTab(viewModel)
                "triage" -> TriageTab(viewModel)
                "education" -> EducationTab(viewModel)
                "more" -> {
                    if (BuildConfig.DEBUG) {
                        LaunchedEffect(Unit) { viewModel.loadReports() }
                    }
                    MoreTab(viewModel)
                }
                else -> ScanTab(
                    viewModel,
                    onPickImage = { imagePickerLauncher.launch("image/*") },
                    onPickFile = { filePickerLauncher.launch("*/*") },
                    onScanQr = { showQrScanner = true },
                    onCaptureInvoicePhoto = captureInvoicePhoto,
                    onScanInvoice = { invoicePickerLauncher.launch(arrayOf("image/*", "application/pdf")) },
                    onScanOffer = { offerPickerLauncher.launch(arrayOf("image/*", "application/pdf", "text/*", "text/html", "message/rfc822")) }
                )
            }

            if (showQrScanner) {
                hasQrCameraPermission =
                    ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED
                QrScannerScreen(
                    hasCameraPermission = hasQrCameraPermission,
                    onRequestCameraPermission = {
                        qrCameraPermissionLauncher.launch(Manifest.permission.CAMERA)
                    },
                    onClose = { closeQrScanner() },
                    onQrCodeScanned = { value ->
                        viewModel.text = value
                        viewModel.onScanClick()
                        closeQrScanner()
                    },
                    onPickImageFallback = {
                        closeQrScanner()
                        qrPickerLauncher.launch("image/*")
                    }
                )
            }
        }
    }
}
