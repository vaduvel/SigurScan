package ro.sigurscan.app

import android.Manifest
import android.content.Intent
import android.content.Context
import android.graphics.BitmapFactory
import android.net.Uri
import android.content.pm.PackageManager
import android.os.Bundle
import android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS
import android.text.Html
import android.text.Spanned
import android.view.ViewGroup.LayoutParams
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.em
import androidx.compose.ui.unit.sp
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.viewinterop.AndroidView
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.core.content.ContextCompat
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
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.common.InputImage
import java.text.SimpleDateFormat
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

private fun handleIncomingIntent(context: Context, intent: Intent?, viewModel: ScannerViewModel) {
    val plan = buildSharedIntentIntakePlan(intent)
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
                    preserveSharedTextState = preserveSharedTextState
                )
            }

            override fun scanText() {
                viewModel.scanPendingSharedText()
            }

            override fun scanSingleFile() {
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

private fun sharedCharSequenceCandidate(value: CharSequence): SharedTextCandidate? {
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

    when (intent.action) {
        Intent.ACTION_SEND_MULTIPLE -> {
            @Suppress("DEPRECATION")
            runCatching { intent.getParcelableArrayListExtra<Uri>(Intent.EXTRA_STREAM) }
                .getOrNull()
                ?.forEach { stream -> streams[stream.toString()] = stream }
        }
        else -> {
            val singleStream = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
                intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
            } else {
                @Suppress("DEPRECATION")
                intent.getParcelableExtra<Uri>(Intent.EXTRA_STREAM)
            }
            singleStream?.let { streams[it.toString()] = it }
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

    return streams.values.toList()
}

private fun sourceLabelForSharedUri(context: Context, uri: Uri, fallbackMime: String): String {
    val mime = runCatching {
        context.contentResolver.getType(uri)?.lowercase(Locale.getDefault())
    }.getOrNull().orEmpty().ifBlank { fallbackMime }
    return sourceLabelForMime(mime)
}

private fun sourceLabelForMime(mime: String): String {
    return when {
        mime.startsWith("image/") -> "Imagine partajată"
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

@Composable
fun MainScreen(viewModel: ScannerViewModel) {
    val context = LocalContext.current
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
                    onScanInvoice = { invoicePickerLauncher.launch(arrayOf("image/*", "application/pdf")) }
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
                    onScanInvoice = { invoicePickerLauncher.launch(arrayOf("image/*", "application/pdf")) }
                )
            }

            if (showQrScanner) {
                QrScannerScreen(
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

@Composable
fun ScanTab(viewModel: ScannerViewModel, onPickImage: () -> Unit, onPickFile: () -> Unit, onScanQr: () -> Unit, onScanInvoice: () -> Unit = {}) {
    val hasActiveScanContext = viewModel.loading ||
        viewModel.assessment != null ||
        viewModel.invoiceResult != null ||
        viewModel.pendingSharedInput != null ||
        viewModel.pendingSharedFiles.isNotEmpty() ||
        viewModel.sharedContentFidelity != null

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(20.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Header()
        
        Spacer(modifier = Modifier.height(20.dp))

        if (hasActiveScanContext) {
            viewModel.sharedContentFidelity?.let { fidelity ->
                SharedContentFidelityCard(
                    fidelity = fidelity,
                    sourceLabel = viewModel.sharedContentSourceLabel
                )
                Spacer(modifier = Modifier.height(16.dp))
            }

            when {
                viewModel.invoiceResult != null -> InvoiceResultCard(
                    result = viewModel.invoiceResult!!,
                    onBack = { viewModel.reset() }
                )
                viewModel.assessment != null -> ResultCard(
                    assessment = viewModel.assessment!!,
                    onBack = { viewModel.reset() },
                    onRescan = { viewModel.onScanClick(forceRefresh = true) },
                    onReport = { viewModel.onCommunityReport() },
                    onFeedback = { viewModel.submitFeedback(it) },
                    onFamilyAlert = { viewModel.notifyFamilyForCurrentScan() }
                )
                else -> ScanInputCard(viewModel, onPickImage, onPickFile, onScanQr, onScanInvoice)
            }

            Spacer(modifier = Modifier.height(20.dp))
        }

        if (!hasActiveScanContext) {
            ScanInputCard(viewModel, onPickImage, onPickFile, onScanQr, onScanInvoice)
        }
        
        Spacer(modifier = Modifier.height(20.dp))

        if (viewModel.activeCampaignAlert != null) {
            ActiveCampaignBanner(viewModel.activeCampaignAlert!!) {
                viewModel.activeCampaignAlert = null
            }
            Spacer(modifier = Modifier.height(16.dp))
        }

        ActiveCampaignsSection(viewModel.campaigns, viewModel.campaignsLoading)

        Spacer(modifier = Modifier.height(20.dp))
        
        NoticeSection()
    }
}

@AndroidxOptIn(ExperimentalGetImage::class)
@Composable
fun QrScannerScreen(
    onClose: () -> Unit,
    onQrCodeScanned: (String) -> Unit,
    onPickImageFallback: () -> Unit
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    var hasCameraPermission by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.CAMERA
            ) == PackageManager.PERMISSION_GRANTED
        )
    }
    var requestingPermission by remember { mutableStateOf(false) }
    var statusMessage by remember { mutableStateOf("Poziționează codul QR în zona verde.") }
    var errorMessage by remember { mutableStateOf<String?>(null) }
    var showTorchUnavailable by remember { mutableStateOf(false) }
    var isTorchOn by remember { mutableStateOf(false) }
    var camera by remember { mutableStateOf<Camera?>(null) }
    val permissionLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        hasCameraPermission = granted
        requestingPermission = false
        if (!granted) {
            errorMessage = "Permisiunea camerei este necesară pentru scanare."
        }
    }

    val previewView = remember {
        PreviewView(context).apply {
            layoutParams = LayoutParams(
                LayoutParams.MATCH_PARENT,
                LayoutParams.MATCH_PARENT
            )
            scaleType = PreviewView.ScaleType.FILL_CENTER
        }
    }
    val executor = remember { Executors.newSingleThreadExecutor() }
    val barcodeScanner = remember { BarcodeScanning.getClient() }
    val hasScanned = remember { AtomicBoolean(false) }
    var cameraProvider by remember { mutableStateOf<ProcessCameraProvider?>(null) }

    fun stopCamera() {
        cameraProvider?.unbindAll()
    }

    LaunchedEffect(Unit) {
        if (!hasCameraPermission && !requestingPermission) {
            requestingPermission = true
            permissionLauncher.launch(Manifest.permission.CAMERA)
        }
    }

    DisposableEffect(hasCameraPermission) {
        if (!hasCameraPermission) {
            return@DisposableEffect onDispose {}
        }

        var imageAnalysis: ImageAnalysis? = null
        val providerFuture = ProcessCameraProvider.getInstance(context)

        val startCamera = Runnable {
            runCatching {
                val provider = providerFuture.get()
                cameraProvider = provider

                val preview = CameraPreview.Builder().build().apply {
                    setSurfaceProvider(previewView.surfaceProvider)
                }

                imageAnalysis = ImageAnalysis.Builder()
                    .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                    .build()

                imageAnalysis?.setAnalyzer(executor) { imageProxy ->
                    if (hasScanned.get()) {
                        imageProxy.close()
                        return@setAnalyzer
                    }

                    val mediaImage = imageProxy.image
                    if (mediaImage == null) {
                        imageProxy.close()
                        return@setAnalyzer
                    }

                    val inputImage = InputImage.fromMediaImage(mediaImage, imageProxy.imageInfo.rotationDegrees)
                    barcodeScanner.process(inputImage)
                        .addOnSuccessListener { barcodes ->
                            val qrValue = barcodes.firstOrNull()?.rawValue?.trim()
                            if (!qrValue.isNullOrBlank() && hasScanned.compareAndSet(false, true)) {
                                stopCamera()
                                onQrCodeScanned(qrValue)
                                onClose()
                            }
                        }
                        .addOnFailureListener {
                            statusMessage = "Nu am reușit să citesc QR-ul, încearcă din nou."
                        }
                        .addOnCompleteListener {
                            imageProxy.close()
                        }
                }

                provider.unbindAll()
                camera = provider.bindToLifecycle(
                    lifecycleOwner,
                    CameraSelector.DEFAULT_BACK_CAMERA,
                    preview,
                    imageAnalysis
                )
            }.onFailure { throwable ->
                errorMessage = throwable.message ?: "Nu pot porni camera."
            }
        }

        providerFuture.addListener(startCamera, ContextCompat.getMainExecutor(context))

        onDispose {
            stopCamera()
            camera?.cameraControl?.enableTorch(false)
            camera = null
            imageAnalysis?.clearAnalyzer()
            executor.shutdown()
            barcodeScanner.close()
        }
    }

    Box(
        modifier = Modifier.fillMaxSize()
    ) {
        if (!hasCameraPermission) {
            Surface(
                modifier = Modifier.fillMaxSize(),
                color = SigurColors.Canvas
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(20.dp),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center
                ) {
                    Text(
                        text = "Ai nevoie de acces la cameră pentru scanare live",
                        style = MaterialTheme.typography.titleMedium,
                        color = SigurColors.TextPrimary,
                        textAlign = TextAlign.Center
                    )
                    Spacer(modifier = Modifier.height(16.dp))
                    Text(
                        text = errorMessage ?: "Apasă „Permite camera” și încearcă din nou.",
                        color = SigurColors.TextSecondary,
                        textAlign = TextAlign.Center
                    )
                    Spacer(modifier = Modifier.height(24.dp))
                    Button(
                        onClick = {
                            permissionLauncher.launch(Manifest.permission.CAMERA)
                        },
                        colors = ButtonDefaults.buttonColors(containerColor = SigurColors.Brand)
                    ) {
                        Text("Permite camera")
                    }
                    Spacer(modifier = Modifier.height(12.dp))
                    OutlinedButton(onClick = onPickImageFallback) {
                        Text("Scanează din poză")
                    }
                    Spacer(modifier = Modifier.height(12.dp))
                    TextButton(onClick = {
                        val uri = android.net.Uri.parse("package:${context.packageName}")
                        val intent = Intent(ACTION_APPLICATION_DETAILS_SETTINGS, uri)
                        context.startActivity(intent)
                    }) {
                        Text("Deschide setări")
                    }
                }
            }
        } else {
            AndroidView(
                factory = { previewView },
                modifier = Modifier.fillMaxSize()
            )

            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(24.dp)
            ) {
                Card(
                    modifier = Modifier
                        .align(Alignment.TopCenter)
                        .fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = SigurColors.Canvas.copy(alpha = 0.92f))
                ) {
                    Column(modifier = Modifier.padding(10.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                        Text("Scanează codul QR", color = SigurColors.TextPrimary, fontWeight = FontWeight.Bold)
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(statusMessage, color = SigurColors.TextSecondary, fontSize = 12.sp, textAlign = TextAlign.Center)
                    }
                }

                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(4.dp)
                ) {
                    val hasTorch = camera?.cameraInfo?.hasFlashUnit() == true

                    Row(
                        modifier = Modifier
                            .align(Alignment.TopEnd),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        if (camera != null) {
                            Surface(
                                shape = CircleShape,
                                color = SigurColors.BackgroundCard,
                                modifier = Modifier.size(38.dp)
                            ) {
                                IconButton(
                                    onClick = {
                                        if (!hasTorch) {
                                            showTorchUnavailable = true
                                            return@IconButton
                                        }
                                        isTorchOn = !isTorchOn
                                        camera?.cameraControl?.enableTorch(isTorchOn)
                                    }
                                ) {
                                    Icon(
                                        if (isTorchOn) Icons.Default.FlashOn else Icons.Default.FlashOff,
                                        contentDescription = if (isTorchOn) "Oprește lanternă" else "Pornește lanternă",
                                        tint = SigurColors.TextPrimary
                                    )
                                }
                            }
                        }

                        Surface(
                            shape = CircleShape,
                            color = SigurColors.BackgroundCard,
                            modifier = Modifier
                                .size(38.dp)
                        ) {
                            IconButton(onClick = onClose) {
                                Icon(Icons.Default.Close, contentDescription = "Închide", tint = SigurColors.TextPrimary)
                            }
                        }
                    }

                    if (showTorchUnavailable) {
                        AssistChip(
                            onClick = { showTorchUnavailable = false },
                            label = { Text("Camera nu are lanternă", color = SigurColors.Dangerous) },
                            colors = AssistChipDefaults.assistChipColors(
                                labelColor = SigurColors.Dangerous,
                                containerColor = SigurColors.BackgroundCard
                            ),
                            modifier = Modifier
                                .align(Alignment.TopCenter)
                                .padding(top = 48.dp)
                        )
                    }

                    Box(
                        modifier = Modifier
                            .size(220.dp)
                            .align(Alignment.Center)
                            .border(3.dp, SigurColors.Brand, RoundedCornerShape(12.dp))
                    )
                }

                Surface(
                    modifier = Modifier
                        .align(Alignment.BottomCenter)
                        .fillMaxWidth(0.9f),
                    color = SigurColors.BackgroundCard.copy(alpha = 0.9f)
                ) {
                    Row(
                        modifier = Modifier.padding(12.dp),
                        horizontalArrangement = Arrangement.Center
                    ) {
                        Text(
                            text = "Nu pleca app-ul în fundal pe durata scanării",
                            color = SigurColors.TextSecondary,
                            fontSize = 12.sp,
                            textAlign = TextAlign.Center
                        )
                    }
                }
            }
        }

        errorMessage?.let { message ->
            if (errorMessage != null) {
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(24.dp),
                    verticalArrangement = Arrangement.Bottom,
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    AssistChip(
                        onClick = { errorMessage = null },
                        label = { Text(message) },
                        colors = AssistChipDefaults.assistChipColors(
                            labelColor = SigurColors.Dangerous,
                            containerColor = SigurColors.BackgroundCard
                        )
                    )
                }
            }
        }
    }
}

@Composable
fun RadarTab(viewModel: ScannerViewModel) {
    val context = LocalContext.current
    val locatedCampaigns = remember(viewModel.campaigns) {
        viewModel.campaigns.count { it.lat != null && it.lon != null }
    }
    var selectedCampaign by remember { mutableStateOf<ScamCampaign?>(null) }
    val onMapCampaignSelected: (ScamCampaign?) -> Unit = { selectedCampaign = it }

    val campaignPins = remember(viewModel.campaigns) {
        viewModel.campaigns.filter { it.lat != null && it.lon != null }
    }

    Column(modifier = Modifier.fillMaxSize().padding(20.dp).verticalScroll(rememberScrollState())) {
        Text("Radar Scam", fontSize = 20.sp, fontWeight = FontWeight.Bold, color = SigurColors.TextPrimary)
        Spacer(modifier = Modifier.height(16.dp))

        if (viewModel.liveCampaignEvent != null) {
            ActiveCampaignBanner(viewModel.liveCampaignEvent!!) {
                viewModel.clearLiveCampaignEvent()
            }
            Spacer(modifier = Modifier.height(12.dp))
        }

        if (viewModel.activeCampaignAlert != null) {
            Card(
                colors = CardDefaults.cardColors(containerColor = SigurColors.DangerousLight),
                border = BorderStroke(1.dp, SigurColors.DangerousBorder),
                shape = DSCardShape
            ) {
                Text(
                    text = viewModel.activeCampaignAlert!!,
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

@Composable
private fun CampaignBottomCard(campaign: ScamCampaign, onOpenMap: () -> Unit) {
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

@Composable
private fun RadarMapCard(
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

private class RadarWebViewClient(
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

private fun buildRadarMapHtml(campaigns: List<ScamCampaign>): String {
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

private fun buildStaticRadarMarkers(payload: JSONArray): String {
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

private fun romanianMapX(lon: Double): Int {
    val minLon = 20.2
    val maxLon = 29.8
    return (((lon - minLon) / (maxLon - minLon)) * 78.0 + 11.0).toInt().coerceIn(8, 92)
}

private fun romanianMapY(lat: Double): Int {
    val minLat = 43.6
    val maxLat = 48.3
    return ((1.0 - ((lat - minLat) / (maxLat - minLat))) * 72.0 + 14.0).toInt().coerceIn(8, 92)
}

private fun String.htmlEscape(): String {
    return replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\"", "&quot;")
        .replace("'", "&#39;")
}

private data class LessonContent(
    val id: String,
    val title: String,
    val summary: String,
    val question: String,
    val options: List<String>,
    val correctIndex: Int
)

@Composable
fun EducationTab(viewModel: ScannerViewModel) {
    val lessons = listOf(
        LessonContent(
            id = "lesson_phishing_sms",
            title = "Cum identifici un link din SMS",
            summary = "Nu apăsa pe linkul din mesaj înainte să verifici sursa.",
            question = "Ce faci dacă mesajul conține un link cu urgență, dar nu recunoști expeditorul?",
            options = listOf(
                "Ceri pe cineva să-l verifice și nu deschizi linkul",
                "Deschizi imediat, poate e urgent",
                "Ceri 2FA prin SMS pentru siguranță"
            ),
            correctIndex = 0
        ),
        LessonContent(
            id = "lesson_mail_links",
            title = "Mesaj email + butoane suspecte",
            summary = "Butonul afișat poate ascunde un link către alt domeniu.",
            question = "Ce e corect când vezi un buton „Click aici”?",
            options = listOf(
                "Verifici adresa reală din atributul link-ului înainte de apăsare",
                "Dai click doar pe textul clar de pe buton",
                "Copiezi adresa din semnătura emailului"
            ),
            correctIndex = 0
        ),
        LessonContent(
            id = "lesson_qr_security",
            title = "QR în phishing",
            summary = "Codurile QR pot duce la aceeași pagină rău intenționată ca și linkurile text.",
            question = "Ce faci dacă ți se cere scanare QR de la un mesaj nediagnosticat?",
            options = listOf(
                "Nu-l scanezi și anunți emitentul pe canal oficial",
                "Scanezi, dar cu Wi-Fi oprit",
                "Scanezi doar dacă mesajul pare urgent"
            ),
            correctIndex = 0
        ),
        LessonContent(
            id = "lesson_courier_alert",
            title = "Pachete reținute sau AWB incorect",
            summary = "Frauda de tip curier cere adesea o taxă de eliberare prin link-uri neoficiale.",
            question = "Ce faci când primești mesaj că livrarea e blocată și ți se cere plată urgentă?",
            options = listOf(
                "Verifici AWB-ul direct pe site-ul oficial al curierului",
                "Deschizi linkul din mesajul primit",
                "Confirmezi datele cardului în formularul din SMS"
            ),
            correctIndex = 0
        ),
        LessonContent(
            id = "lesson_anaf_scam",
            title = "Mesaje cu ANAF/TVA fals",
            summary = "ANAF nu cere plăți directe prin linkuri din SMS sau emailuri improvizate.",
            question = "Dacă vezi o notificare cu rambursare/penalizare fiscală care cere acces la cont, ce faci?",
            options = listOf(
                "Verifici direct în portalul oficial ANAF, nu din linkul primit",
                "Intrii pe link și confirmi datele persoanele",
                "Descarci toate atașamentele ca să te asiguri"
            ),
            correctIndex = 0
        ),
        LessonContent(
            id = "lesson_olx_card",
            title = "Oferte OLX/card și vouchere",
            summary = "Cererea de date bancare prin link rapid este frecventă pe platforme de falsă ofertă.",
            question = "Care e regula sigură la o ofertă mare 'gratuită' primită prin mesaj?",
            options = listOf(
                "Verifici oferta în aplicația oficială a platformei fără a da date sensibile",
                "Folosești linkul imediat și apoi schimbi parola dacă e nevoie",
                "Scanezi eventualele atașamente PDF ca să confirmi autentificitatea"
            ),
            correctIndex = 0
        ),
        LessonContent(
            id = "lesson_crypto_deepfake",
            title = "Crypto/Deepfake și promisiuni false",
            summary = "Promisiunile de profit rapid sau investiții instant vizează panicarea rapidă.",
            question = "Cum reduci riscul la astfel de mesaje?",
            options = listOf(
                "Ignori promisiunile, verifici sursa oficială și eviți orice achiziție prin link",
                "Cerzi un credit mic ca test înainte de a da datele",
                "Te uiți pe link dintr-un browser privat fără alt control"
            ),
            correctIndex = 0
        ),
        LessonContent(
            id = "lesson_parental_protection",
            title = "Protecția părinților online",
            summary = "Persoanele mai puțin tehnice sunt ținta preferată a mesajelor de phishing.",
            question = "Ce faci dacă părintelui i se cere verificarea contului printr-un link nou?",
            options = listOf(
                "Discuți împreună pe un apel separat și nu acționezi pe acel link",
                "Îl ajuți să dea click dacă nu ai timp să verifici",
                "Îi setezi parole noi pe acel site imediat"
            ),
            correctIndex = 0
        )
    )

    var selectedLesson by remember { mutableStateOf(lessons.first()) }

    Column(modifier = Modifier.fillMaxSize().padding(20.dp).verticalScroll(rememberScrollState())) {
        Text("Educație", fontSize = 20.sp, fontWeight = FontWeight.Bold, color = SigurColors.TextPrimary)
        Spacer(modifier = Modifier.height(8.dp))
        Text("Alege o lecție, vezi regula și apoi verifici cu un mini test.", color = SigurColors.TextSecondary, fontSize = 12.sp)

        Spacer(modifier = Modifier.height(16.dp))

        lessons.forEach { lesson ->
            val isSelected = selectedLesson.id == lesson.id
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 4.dp)
                    .clickable { selectedLesson = lesson },
                shape = DSCardShape,
                colors = CardDefaults.cardColors(containerColor = if (isSelected) SigurColors.BrandTint else SigurColors.BackgroundCard),
                border = BorderStroke(1.dp, if (isSelected) SigurColors.Brand else SigurColors.GlassBorder)
            ) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        if (viewModel.completedLessons.contains(lesson.id)) {
                            Icon(Icons.Default.CheckCircle, contentDescription = null, tint = SigurColors.Safe, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(6.dp))
                        }
                        Text(lesson.title, color = SigurColors.TextPrimary, fontWeight = FontWeight.Bold)
                    }
                    Text(lesson.summary, color = SigurColors.TextSecondary, fontSize = 12.sp)
                }
            }
        }

        Spacer(modifier = Modifier.height(20.dp))

        Card(
            shape = DSCardShape,
            colors = CardDefaults.cardColors(containerColor = SigurColors.BackgroundCard),
            border = DSCardBorder
        ) {
            var answerFeedback by remember(selectedLesson.id) { mutableStateOf<String?>(null) }

            Column(modifier = Modifier.padding(16.dp)) {
                Text("Quiz: ${selectedLesson.title}", color = SigurColors.TextPrimary, fontWeight = FontWeight.Bold)
                Spacer(modifier = Modifier.height(12.dp))
                Text(selectedLesson.question, color = SigurColors.TextSecondary)
                Spacer(modifier = Modifier.height(10.dp))

                selectedLesson.options.forEachIndexed { index, option ->
                    val isCorrect = answerFeedback != null && index == selectedLesson.correctIndex
                    val isWrong = answerFeedback == option && !isCorrect

                    Button(
                        onClick = {
                            answerFeedback = option
                            if (index == selectedLesson.correctIndex) {
                                viewModel.setLessonCompleted(selectedLesson.id)
                            }
                        },
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 4.dp),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = when {
                                isCorrect -> SigurColors.SafeLight
                                isWrong -> SigurColors.DangerousLight
                                else -> SigurColors.BackgroundSurface
                            }
                        ),
                        shape = DSCardShape,
                        border = BorderStroke(1.dp, when {
                            isCorrect -> SigurColors.SafeBorder
                            isWrong -> SigurColors.DangerousBorder
                            else -> SigurColors.GlassBorder
                        })
                    ) {
                        Text(option, color = SigurColors.TextPrimary, fontSize = 12.sp, textAlign = TextAlign.Start)
                    }
                }

                if (answerFeedback != null) {
                    val selectedIndex = selectedLesson.options.indexOfFirst { it == answerFeedback }
                    if (selectedIndex == selectedLesson.correctIndex) {
                        Text("Corect. Ai înțeles pasul de bază.", color = SigurColors.Safe, modifier = Modifier.padding(top = 8.dp))
                    } else {
                        Text("Incorect. Răspunsul corect: ${selectedLesson.options[selectedLesson.correctIndex]}", color = SigurColors.Dangerous, modifier = Modifier.padding(top = 8.dp))
                    }
                }
            }
        }
    }
}

@Composable
fun MoreTab(viewModel: ScannerViewModel) {
    Column(modifier = Modifier.fillMaxSize().padding(20.dp).verticalScroll(rememberScrollState())) {
        Text("Mai Mult", fontSize = 20.sp, fontWeight = FontWeight.Bold, color = SigurColors.TextPrimary)
        Spacer(modifier = Modifier.height(16.dp))

                SecurityFamilySection(viewModel)

        Spacer(modifier = Modifier.height(16.dp))

        if (BuildConfig.DEBUG) {
            ReportsTab(viewModel)

            Spacer(modifier = Modifier.height(16.dp))
        }

        ContrastSection()

        Spacer(modifier = Modifier.height(16.dp))

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
fun ActiveCampaignBanner(message: String, onDismiss: () -> Unit) {
    Card(
        colors = CardDefaults.cardColors(containerColor = SigurColors.Dangerous),
        shape = DSCardShape,
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier.padding(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(Icons.Default.Campaign, contentDescription = null, tint = Color.White, modifier = Modifier.size(24.dp))
            Spacer(modifier = Modifier.width(12.dp))
            Text(
                text = message,
                color = SigurColors.TextInverse,
                fontSize = 13.sp,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.weight(1f)
            )
            IconButton(onClick = onDismiss, modifier = Modifier.size(24.dp)) {
                Icon(Icons.Default.Close, contentDescription = "Închide", tint = Color.White, modifier = Modifier.size(16.dp))
            }
        }
    }
}

@Composable
fun ActiveCampaignsSection(campaigns: List<ScamCampaign>, isLoading: Boolean) {
    Column(modifier = Modifier.fillMaxWidth()) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Default.Radar, contentDescription = null, tint = SigurColors.Brand, modifier = Modifier.size(18.dp))
            Spacer(modifier = Modifier.width(8.dp))
            Text("Alerte Active în România", color = SigurColors.TextPrimary, fontWeight = FontWeight.Bold, fontSize = 16.sp)
        }
        
        Spacer(modifier = Modifier.height(12.dp))

        if (isLoading) {
            LinearProgressIndicator(modifier = Modifier.fillMaxWidth(), color = SigurColors.Brand)
        } else if (campaigns.isEmpty()) {
            Text("Nicio alertă majoră în ultimele 24h.", color = SigurColors.TextMuted, fontSize = 12.sp)
        } else {
            campaigns.forEach { campaign ->
                CampaignItem(campaign)
                Spacer(modifier = Modifier.height(8.dp))
            }
        }
    }
}

@Composable
fun CampaignItem(campaign: ScamCampaign) {
    val context = LocalContext.current

    Card(
        colors = CardDefaults.cardColors(containerColor = SigurColors.BackgroundCard),
        border = DSCardBorder,
        shape = DSCardShape
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                DSChip(
                    text = campaign.risk.uppercase(),
                    tone = if (campaign.risk == "dangerous") DSChipTone.Danger else DSChipTone.Suspect
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(campaign.title, color = SigurColors.TextPrimary, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                }
            Text(campaign.description, color = SigurColors.TextSecondary, fontSize = 11.sp, maxLines = 2, modifier = Modifier.padding(top = 4.dp))

                campaign.count.takeIf { it > 0 }?.let { scanCount ->
                Spacer(modifier = Modifier.height(10.dp))
                Text(
                    text = "Număr scanări: $scanCount",
                    color = SigurColors.TextSecondary,
                    fontSize = 10.sp
                )
            }

            campaign.lastSeenText.takeIf { it.isNotBlank() }?.let { lastSeen ->
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = "Ultima activitate: $lastSeen",
                    color = SigurColors.TextMuted,
                    fontSize = 10.sp
                )
            }

            campaign.region?.takeIf { it.isNotBlank() }?.let { region ->
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "Regiune: $region",
                    color = SigurColors.TextMuted,
                    fontSize = 10.sp
                )
            }

            if (campaign.lat != null && campaign.lon != null) {
                Spacer(modifier = Modifier.height(10.dp))
                Button(
                    onClick = {
                        openCampaignOnMap(context, campaign.lat, campaign.lon, campaign.title)
                    },
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = SigurColors.BrandTint),
                    border = BorderStroke(1.dp, SigurColors.Brand),
                    shape = DSPillShape
                ) {
                    Icon(Icons.Default.Place, contentDescription = null, tint = SigurColors.Brand, modifier = Modifier.size(14.dp))
                    Spacer(modifier = Modifier.width(6.dp))
                    Text(
                        "Vezi pe hartă",
                        color = SigurColors.Brand,
                        fontSize = 11.sp
                    )
                }
            }
        }
    }
}

private fun openCampaignOnMap(context: android.content.Context, lat: Double?, lon: Double?, title: String) {
    if (lat == null || lon == null) return
    val uri = Uri.parse("geo:$lat,$lon?q=$lat,$lon(${Uri.encode(title)})")
    try {
        val mapIntent = Intent(Intent.ACTION_VIEW, uri)
        context.startActivity(mapIntent)
    } catch (_: Exception) {
        try {
            val browserUri = Uri.parse("https://www.google.com/maps/search/?api=1&query=${lat},${lon}")
            val browserIntent = Intent(Intent.ACTION_VIEW, browserUri)
            context.startActivity(browserIntent)
        } catch (_: Exception) {
            // no-op; action unavailable in this environment
        }
    }
}

@Preview(showBackground = true, backgroundColor = 0xFF0B0F19)
@Composable
fun EvidenceSectionPreview() {
    SigurScanTheme {
        Column(modifier = Modifier.padding(16.dp)) {
            EvidenceSection(
                screenshotUrl = null,
                serverInfo = "Preview disponibil pentru pagina finală.",
                finalUrl = "https://exemplu.invalid"
            )
        }
    }
}

@Composable
fun Header() {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 4.dp)
    ) {
        Box(
            modifier = Modifier
                .size(44.dp)
                .background(
                    brush = androidx.compose.ui.graphics.Brush.linearGradient(
                        colors = listOf(Color(0xFF5B86FF), SigurColors.Brand, Color(0xFF3552D6))
                    ),
                    shape = RoundedCornerShape(14.dp)
                ),
            contentAlignment = Alignment.Center
        ) {
            Icon(
                imageVector = Icons.Default.Shield,
                contentDescription = null,
                tint = Color.White,
                modifier = Modifier.size(24.dp)
            )
        }
        Spacer(modifier = Modifier.width(12.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = "SigurScan",
                style = MaterialTheme.typography.titleLarge.copy(fontSize = 22.sp),
                color = SigurColors.TextPrimary
            )
            Text(
                text = "Verifici doar ce alegi tu",
                style = MaterialTheme.typography.bodyMedium,
                color = SigurColors.TextMuted
            )
        }
    }
}

@Composable
fun ScanInputCard(viewModel: ScannerViewModel, onPickImage: () -> Unit, onPickFile: () -> Unit, onScanQr: () -> Unit, onScanInvoice: () -> Unit = {}) {
    val clipboard = LocalClipboardManager.current
    val context = LocalContext.current

    val heroShape = RoundedCornerShape(24.dp)
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .clip(heroShape)
            .background(
                brush = androidx.compose.ui.graphics.Brush.linearGradient(
                    colors = listOf(Color(0xFF5B86FF), SigurColors.Brand, Color(0xFF2F50D4))
                )
            )
    ) {
        Column(modifier = Modifier.padding(20.dp)) {
            val sharedText = viewModel.pendingSharedInput
            val pendingFiles = viewModel.pendingSharedFiles
            Text(
                text = "Introdu textul sau linkul suspect",
                fontSize = 18.sp,
                fontWeight = FontWeight.Bold,
                color = Color.White
            )
            Text(
                text = "Îți spunem în câteva secunde dacă e o capcană.",
                fontSize = 14.sp,
                color = Color.White.copy(alpha = 0.78f),
                modifier = Modifier.padding(top = 4.dp, bottom = 14.dp)
            )

            if (viewModel.loading) {
                Box(modifier = Modifier.fillMaxWidth().height(150.dp), contentAlignment = Alignment.Center) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        CircularProgressIndicator(color = Color.White)
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(viewModel.loadingMsg, color = Color.White, fontSize = 12.sp)
                    }
                }
            } else {
                OutlinedTextField(
                    value = viewModel.text,
                    onValueChange = { value ->
                        if ((viewModel.pendingSharedInput != null && value != viewModel.pendingSharedInput) ||
                            viewModel.pendingSharedFiles.isNotEmpty()
                        ) {
                            viewModel.clearAllPendingShared()
                        }
                        viewModel.text = value
                    },
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(150.dp),
                    placeholder = {
                        Text(
                            "Lipește textul sau URL-ul aici",
                            color = SigurColors.TextMuted
                        )
                    },
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedContainerColor = Color.White.copy(alpha = 0.94f),
                        unfocusedContainerColor = Color.White.copy(alpha = 0.90f),
                        focusedBorderColor = Color.White,
                        unfocusedBorderColor = Color.White.copy(alpha = 0.70f),
                        focusedTextColor = SigurColors.TextPrimary,
                        unfocusedTextColor = SigurColors.TextPrimary,
                        cursorColor = SigurColors.BrandDeep
                    ),
                    shape = RoundedCornerShape(16.dp)
                )
                        
                if (sharedText != null) {
                    Spacer(modifier = Modifier.height(12.dp))
                    Card(
                        colors = CardDefaults.cardColors(containerColor = Color.White.copy(alpha = 0.16f)),
                        border = BorderStroke(1.dp, Color.White.copy(alpha = 0.35f)),
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        Column(modifier = Modifier.padding(12.dp)) {
                            Text(
                                "Ai primit conținut partajat (${viewModel.pendingSharedSourceLabel})",
                                color = Color.White,
                                fontWeight = FontWeight.Bold,
                                fontSize = 12.sp
                            )
                            Spacer(modifier = Modifier.height(6.dp))
                            Text(
                                "Verifică mai întâi textul, apoi apasă scanare.",
                                color = Color.White.copy(alpha = 0.85f),
                                fontSize = 11.sp
                            )
                            Spacer(modifier = Modifier.height(10.dp))
                            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                Button(
                                    onClick = { viewModel.scanPendingSharedText() },
                                    colors = ButtonDefaults.buttonColors(containerColor = Color.White),
                                    shape = RoundedCornerShape(8.dp),
                                    modifier = Modifier.weight(1f)
                                ) {
                                    Text("Scanează", color = SigurColors.BrandDeep)
                                }
                                OutlinedButton(
                                    onClick = { viewModel.clearAllPendingShared() },
                                    border = BorderStroke(1.dp, Color.White.copy(alpha = 0.6f)),
                                    shape = RoundedCornerShape(8.dp),
                                    modifier = Modifier.weight(1f)
                                ) {
                                    Text("Anulează", color = Color.White)
                                }
                            }
                        }
                    }
                }

                if (pendingFiles.isNotEmpty()) {
                    Spacer(modifier = Modifier.height(12.dp))
                    Card(
                        colors = CardDefaults.cardColors(containerColor = Color.White.copy(alpha = 0.16f)),
                        border = BorderStroke(1.dp, Color.White.copy(alpha = 0.35f)),
                        shape = RoundedCornerShape(12.dp)
                    ) {
                        Column(modifier = Modifier.padding(12.dp)) {
                            Text(
                                "Ai primit ${pendingFiles.size} fișier(e) partajat(e)",
                                color = Color.White,
                                fontWeight = FontWeight.Bold,
                                fontSize = 12.sp
                            )
                            Spacer(modifier = Modifier.height(8.dp))
                            pendingFiles.forEach { fileItem ->
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(bottom = 8.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Column(modifier = Modifier.weight(1f)) {
                                        Text(
                                            fileItem.fileName,
                                            fontWeight = FontWeight.Medium,
                                            color = Color.White,
                                            maxLines = 1
                                        )
                                        val mime = fileItem.mimeType.ifBlank { fileItem.sourceLabel }
                                        Text(
                                            mime,
                                            fontSize = 11.sp,
                                            color = Color.White.copy(alpha = 0.75f)
                                        )
                                    }
                                    OutlinedButton(
                                        onClick = { viewModel.removePendingSharedFile(fileItem.id) },
                                        border = BorderStroke(1.dp, Color.White.copy(alpha = 0.6f)),
                                        shape = RoundedCornerShape(8.dp)
                                    ) {
                                        Text("Anulează", fontSize = 10.sp, color = Color.White)
                                    }
                                    Spacer(modifier = Modifier.width(8.dp))
                                    Button(
                                        onClick = { viewModel.scanPendingSharedFile(fileItem.id, context) },
                                        colors = ButtonDefaults.buttonColors(containerColor = Color.White),
                                        shape = RoundedCornerShape(8.dp)
                                    ) {
                                        Text("Scanează", fontSize = 10.sp, color = SigurColors.BrandDeep)
                                    }
                                }
                            }
                        }
                    }
                }

                Spacer(modifier = Modifier.height(8.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        "${viewModel.text.length} caractere",
                        color = Color.White.copy(alpha = 0.75f),
                        fontSize = 11.sp,
                        modifier = Modifier.weight(1f)
                    )
                    TextButton(onClick = {
                        clipboard.getText()?.text?.let { pasted ->
                            if (pasted.isNotBlank()) {
                                viewModel.clearAllPendingShared()
                                viewModel.text = pasted
                            }
                        }
                    }) {
                        Icon(Icons.Default.ContentPaste, contentDescription = null, tint = Color.White, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("Lipește", fontSize = 12.sp, color = Color.White)
                    }
                    if (viewModel.text.isNotBlank()) {
                        TextButton(onClick = {
                            viewModel.clearAllPendingShared()
                            viewModel.text = ""
                        }) {
                            Icon(Icons.Default.Clear, contentDescription = null, tint = Color.White, modifier = Modifier.size(16.dp))
                            Spacer(modifier = Modifier.width(4.dp))
                            Text("Șterge", fontSize = 12.sp, color = Color.White)
                        }
                    }
                }
            }

            Spacer(modifier = Modifier.height(12.dp))

            Button(
                onClick = {
                    when {
                        viewModel.pendingSharedInput != null -> viewModel.scanPendingSharedText()
                        viewModel.pendingSharedFiles.isNotEmpty() -> viewModel.scanPendingSharedFile(
                            viewModel.pendingSharedFiles.first().id,
                            context
                        )
                        else -> viewModel.onScanClick()
                    }
                },
                modifier = Modifier.fillMaxWidth().height(48.dp),
                colors = ButtonDefaults.buttonColors(containerColor = Color.White),
                shape = RoundedCornerShape(100),
                contentPadding = PaddingValues(14.dp),
                enabled = !viewModel.loading
            ) {
                Icon(Icons.Default.Bolt, contentDescription = null, tint = SigurColors.BrandDeep, modifier = Modifier.size(20.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text("Scanează acum", fontSize = 16.sp, fontWeight = FontWeight.Bold, color = SigurColors.BrandDeep)
            }

        }
    }

    Spacer(modifier = Modifier.height(16.dp))

    Card(
        colors = CardDefaults.cardColors(containerColor = SigurColors.BackgroundCard),
        shape = RoundedCornerShape(16.dp),
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, SigurColors.GlassBorder, RoundedCornerShape(16.dp))
    ) {
        Column(modifier = Modifier.padding(20.dp)) {
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                GridButton(
                    title = "Încarcă Screenshot",
                    desc = "Analiză text & OCR",
                    icon = Icons.Default.Image,
                    color = SigurColors.Brand,
                    onClick = onPickImage,
                    modifier = Modifier.weight(1f)
                )
                GridButton(
                    title = "Email / PDF",
                    desc = "Analiză fișiere",
                    icon = Icons.Default.Description,
                    color = SigurColors.Suspect,
                    onClick = onPickFile,
                    modifier = Modifier.weight(1f)
                )
            }

            Spacer(modifier = Modifier.height(12.dp))

            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                GridButton(
                    title = "Scanează Cod QR",
                    desc = "Scanare live direct din cameră",
                    icon = Icons.Default.QrCodeScanner,
                    color = SigurColors.Safe,
                    onClick = onScanQr,
                    modifier = Modifier.weight(1f)
                )
                GridButton(
                    title = "Scanează Factură",
                    desc = "CUI, IBAN, brand, ANAF",
                    icon = Icons.Default.Receipt,
                    color = Color(0xFF7C4DFF),
                    onClick = onScanInvoice,
                    modifier = Modifier.weight(1f)
                )
            }
        }
    }
}

@Composable
private fun SharedContentFidelityCard(fidelity: SharedContentFidelity, sourceLabel: String) {
    val accent = when (fidelity) {
        SharedContentFidelity.FULL_HTML -> SigurColors.Safe
        SharedContentFidelity.PLAIN_TEXT_ONLY -> SigurColors.Suspect
        SharedContentFidelity.FILE_OR_EMAIL -> SigurColors.Brand
    }
    val background = when (fidelity) {
        SharedContentFidelity.FULL_HTML -> SigurColors.SafeLight
        SharedContentFidelity.PLAIN_TEXT_ONLY -> SigurColors.SuspectLight
        SharedContentFidelity.FILE_OR_EMAIL -> SigurColors.BrandTint
    }
    val border = when (fidelity) {
        SharedContentFidelity.FULL_HTML -> SigurColors.SafeBorder
        SharedContentFidelity.PLAIN_TEXT_ONLY -> SigurColors.SuspectBorder
        SharedContentFidelity.FILE_OR_EMAIL -> SigurColors.Brand.copy(alpha = 0.30f)
    }
    val icon = when (fidelity) {
        SharedContentFidelity.FULL_HTML -> Icons.Default.MarkEmailRead
        SharedContentFidelity.PLAIN_TEXT_ONLY -> Icons.Default.Visibility
        SharedContentFidelity.FILE_OR_EMAIL -> Icons.Default.AttachFile
    }

    Card(
        colors = CardDefaults.cardColors(containerColor = background),
        border = BorderStroke(1.dp, border),
        shape = RoundedCornerShape(12.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier.padding(12.dp),
            verticalAlignment = Alignment.Top
        ) {
            Icon(
                icon,
                contentDescription = null,
                tint = accent,
                modifier = Modifier.size(22.dp)
            )
            Spacer(modifier = Modifier.width(10.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    fidelity.title,
                    color = accent,
                    fontWeight = FontWeight.Bold,
                    fontSize = 13.sp
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    fidelity.description,
                    color = SigurColors.TextSecondary,
                    fontSize = 11.sp,
                    lineHeight = 15.sp
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    "Sursa: $sourceLabel",
                    color = SigurColors.TextMuted,
                    fontSize = 10.sp
                )
            }
        }
    }
}

@Composable
fun GridButton(title: String, desc: String, icon: ImageVector, color: Color, onClick: () -> Unit, modifier: Modifier = Modifier) {
    Card(
        modifier = modifier.clickable { onClick() },
        colors = CardDefaults.cardColors(containerColor = SigurColors.BackgroundSurface),
        border = BorderStroke(1.dp, SigurColors.GlassBorder),
        shape = RoundedCornerShape(12.dp)
    ) {
        Column(
            modifier = Modifier.padding(12.dp).fillMaxWidth(),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Icon(icon, contentDescription = null, tint = color, modifier = Modifier.size(24.dp))
            Text(title, color = SigurColors.TextPrimary, fontSize = 12.sp, fontWeight = FontWeight.Bold, textAlign = TextAlign.Center, modifier = Modifier.padding(top = 8.dp))
            Text(desc, color = SigurColors.TextMuted, fontSize = 10.sp, textAlign = TextAlign.Center)
        }
    }
}

@Composable
fun ResultCard(
    assessment: OfflineAssessment,
    onBack: () -> Unit,
    onRescan: () -> Unit,
    onReport: () -> Unit,
    onFeedback: (String) -> Unit,
    onFamilyAlert: () -> Unit = {}
) {
    val riskUi = mapRiskDisplayState(assessment)
    val decision = mapUserActionDecision(assessment, riskUi)
    val finalDomain = displayDomainFrom(assessment.finalUrl)
    val topReasons = buildTopReasons(assessment, decision)
    val nextActions = buildNextActions(assessment, decision)
    val hasTechnicalDetails = assessment.threatIntel.isNotEmpty() ||
            assessment.emailAuth != null ||
            assessment.detectedButtons.isNotEmpty() ||
            assessment.redirectChain.isNotEmpty() ||
            assessment.finalUrl != null ||
            assessment.sandboxReportUrl != null

    var feedbackSent by remember { mutableStateOf(false) }
    var showTechnicalDetails by remember { mutableStateOf(false) }

    val verdictLightBg = when (riskUi.level) {
        "Sigur" -> SigurColors.SafeLight
        "Periculos" -> SigurColors.DangerousLight
        else -> SigurColors.SuspectLight
    }
    val verdictBorder = when (riskUi.level) {
        "Sigur" -> SigurColors.SafeBorder
        "Periculos" -> SigurColors.DangerousBorder
        else -> SigurColors.SuspectBorder
    }
    val isCheckingFurther = assessment.gateResult?.asyncExpected == true ||
        assessment.gateResult?.finality == GateFinality.PROVISIONAL

    Column(modifier = Modifier.fillMaxWidth()) {
        // VerdictCard — DS hero block (icon circle + title + subtitle + message)
        Card(
            colors = CardDefaults.cardColors(containerColor = verdictLightBg),
            shape = RoundedCornerShape(16.dp),
            modifier = Modifier
                .fillMaxWidth()
                .border(1.5.dp, verdictBorder, RoundedCornerShape(16.dp))
        ) {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                modifier = Modifier.fillMaxWidth().padding(20.dp)
            ) {
                Box(
                    modifier = Modifier
                        .size(56.dp)
                        .background(riskUi.color, CircleShape),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = resultIconFor(assessment.gateResult?.action, riskUi.level),
                        contentDescription = null,
                        tint = Color.White,
                        modifier = Modifier.size(30.dp)
                    )
                }
                Spacer(modifier = Modifier.height(14.dp))
                Text(
                    text = decision.headline.uppercase(Locale.getDefault()),
                    fontSize = 24.sp,
                    fontWeight = FontWeight.Bold,
                    letterSpacing = 0.04.em,
                    color = riskUi.color,
                    textAlign = TextAlign.Center
                )
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = decision.supportText,
                    color = SigurColors.TextSecondary,
                    fontSize = 16.sp,
                    lineHeight = 24.sp,
                    textAlign = TextAlign.Center
                )
                if (isCheckingFurther) {
                    Spacer(modifier = Modifier.height(12.dp))
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        modifier = Modifier
                            .background(SigurColors.BackgroundCard, RoundedCornerShape(12.dp))
                            .padding(horizontal = 16.dp, vertical = 8.dp)
                    ) {
                        CircularProgressIndicator(
                            color = SigurColors.Pending,
                            strokeWidth = 2.dp,
                            modifier = Modifier.size(16.dp)
                        )
                        Text(
                            text = "Verificare suplimentară în curs",
                            color = SigurColors.Pending,
                            fontSize = 14.sp,
                            fontWeight = FontWeight.SemiBold
                        )
                    }
                }
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

    Card(
        colors = CardDefaults.cardColors(containerColor = SigurColors.BackgroundCard),
        shape = RoundedCornerShape(16.dp),
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, SigurColors.GlassBorder, RoundedCornerShape(16.dp))
    ) {
        Column(modifier = Modifier.padding(20.dp)) {

            GateEvidenceSummary(assessment, riskUi)

            EvidenceSection(assessment.screenshotUrl, assessment.serverInfo, assessment.finalUrl)

            finalDomain?.let { domain ->
                Card(
                    colors = CardDefaults.cardColors(containerColor = SigurColors.BackgroundSurface),
                    border = BorderStroke(1.dp, SigurColors.GlassBorder),
                    shape = RoundedCornerShape(12.dp),
                    modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp)
                ) {
                    Row(
                        modifier = Modifier.padding(12.dp).fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(Icons.Default.Link, contentDescription = null, tint = SigurColors.Brand, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(8.dp))
                        Column {
                            Text("Te duce către", color = SigurColors.TextMuted, fontSize = 11.sp)
                            Text(domain, color = SigurColors.TextPrimary, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                        }
                    }
                }
            }

            Text(
                text = "Clasificare: ${assessment.family}",
                color = SigurColors.TextMuted,
                fontSize = 11.sp,
                modifier = Modifier.padding(bottom = 4.dp)
            )

            ResultSection(title = "De ce spunem asta", items = topReasons, icon = Icons.AutoMirrored.Filled.List)
            
            if (assessment.offerAnalysis != null) {
                OfferAnalysisSection(assessment.offerAnalysis)
            }

            if (assessment.keyDangers.isNotEmpty() && riskUi.level != "Sigur") {
                ResultSection(title = "Riscuri principale", items = assessment.keyDangers.take(3), icon = Icons.Default.Warning)
            }

            ResultSection(title = "Ce să faci acum", items = nextActions, icon = Icons.Default.CheckCircle)

            Text(
                text = "SigurScan oferă o estimare automată de risc. Scamurile noi sau personalizate pot să nu fie detectate. Verifică datele importante direct pe site-ul sau în aplicația oficială.",
                color = SigurColors.TextMuted,
                fontSize = 10.sp,
                lineHeight = 14.sp,
                modifier = Modifier.padding(top = 8.dp)
            )

            if (hasTechnicalDetails) {
                TextButton(
                    onClick = { showTechnicalDetails = !showTechnicalDetails },
                    modifier = Modifier.fillMaxWidth().padding(top = 8.dp)
                ) {
                    Text(
                        text = if (showTechnicalDetails) "Ascunde detalii tehnice" else "Arată detalii tehnice",
                        color = SigurColors.Brand,
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold
                    )
                }

                if (showTechnicalDetails) {
                    SincerityPillarsSection(assessment)

                    if (assessment.threatIntel.isNotEmpty()) {
                        ThreatIntelSection(assessment.threatIntel, assessment.sandboxReportUrl)
                    }

                    if (assessment.emailAuth != null) {
                        ComplianceSection(assessment.emailAuth)
                    }

                    if (assessment.detectedButtons.isNotEmpty()) {
                        ButtonsSection(assessment.detectedButtons)
                    }

                    RedirectChainSection(assessment.redirectChain, assessment.finalUrl)
                }
            }

            Spacer(modifier = Modifier.height(20.dp))

            // Feedback Section
            if (!feedbackSent) {
                Text(
                    "A fost util acest verdict?",
                    color = SigurColors.TextPrimary,
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.padding(bottom = 8.dp)
                )
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(
                        onClick = { onFeedback("correct"); feedbackSent = true },
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(containerColor = SigurColors.SafeLight),
                        border = BorderStroke(1.dp, SigurColors.SafeBorder)
                    ) {
                        Text("DA", color = SigurColors.Safe)
                    }
                    Button(
                        onClick = { onFeedback("false_positive"); feedbackSent = true },
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(containerColor = SigurColors.DangerousLight),
                        border = BorderStroke(1.dp, SigurColors.DangerousBorder)
                    ) {
                        Text("NU", color = SigurColors.Dangerous)
                    }
                }
                Spacer(modifier = Modifier.height(16.dp))
            } else {
                Text(
                    "Mulțumim pentru feedback! Împreună facem România mai sigură.",
                    color = SigurColors.Safe,
                    fontSize = 12.sp,
                    textAlign = TextAlign.Center,
                    modifier = Modifier.fillMaxWidth().padding(bottom = 16.dp)
                )
            }

            Button(
                onClick = onFamilyAlert,
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = SigurColors.BrandTint),
                shape = RoundedCornerShape(10.dp),
                border = BorderStroke(1.dp, SigurColors.Brand)
            ) {
                Icon(Icons.Default.People, contentDescription = null, tint = SigurColors.Brand, modifier = Modifier.size(16.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text("Trimite alertă Familie", color = SigurColors.Brand, fontSize = 12.sp)
            }
            Spacer(modifier = Modifier.height(12.dp))

            if (riskUi.level == "Periculos") {
                Button(
                    onClick = onReport,
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = SigurColors.SafeLight),
                    shape = RoundedCornerShape(10.dp),
                    border = BorderStroke(1.dp, SigurColors.SafeBorder)
                ) {
                    Icon(Icons.Default.Share, contentDescription = null, tint = SigurColors.Safe, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Raportează către comunitatea SigurScan", color = SigurColors.Safe, fontSize = 12.sp)
                }
                Spacer(modifier = Modifier.height(12.dp))
            }

            if (assessment.cacheStatus != null) {
                Button(
                    onClick = onRescan,
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = SigurColors.BrandTint),
                    shape = RoundedCornerShape(10.dp),
                    border = BorderStroke(1.dp, SigurColors.Brand)
                ) {
                    Icon(Icons.Default.Refresh, contentDescription = null, tint = SigurColors.Brand, modifier = Modifier.size(16.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Rescanează acum", color = SigurColors.Brand, fontSize = 12.sp)
                }
                Spacer(modifier = Modifier.height(12.dp))
            }

            Button(
                onClick = onBack,
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = SigurColors.BackgroundSurface),
                shape = RoundedCornerShape(10.dp)
            ) {
                Text("Înapoi la scanare", color = SigurColors.TextPrimary)
            }
        }
    }
    }
}

@Composable
private fun GateEvidenceSummary(assessment: OfflineAssessment, riskUi: RiskDisplayState) {
    val gateResult = assessment.gateResult ?: return
    val snapshot = assessment.evidenceSnapshot
    val inProgress = GateResultPresentation.isScanInProgress(gateResult)
    val chips = listOfNotNull(
        if (inProgress) "Scanare în curs" else "Verdict final",
        if (assessment.cacheStatus != null) "Verificat anterior" else null,
        snapshot?.completeness?.let {
            when (it) {
                EvidenceCompleteness.FULL -> "Verificări complete"
                EvidenceCompleteness.PARTIAL_ONLINE -> "Se verifică linkul"
                EvidenceCompleteness.LOCAL_ONLY -> "Mai trebuie informații"
            }
        }
    ).distinct()

    Card(
        colors = CardDefaults.cardColors(containerColor = riskUi.color.copy(alpha = 0.08f)),
        border = BorderStroke(1.dp, riskUi.color.copy(alpha = 0.22f)),
        shape = RoundedCornerShape(12.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Text(
                text = GateResultPresentation.primaryAction(gateResult),
                color = SigurColors.TextPrimary,
                fontSize = 13.sp,
                fontWeight = FontWeight.SemiBold,
                lineHeight = 18.sp
            )
            if (chips.isNotEmpty()) {
                Spacer(modifier = Modifier.height(8.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    chips.take(3).forEach { chip ->
                        Surface(
                            color = SigurColors.BackgroundCard,
                            border = BorderStroke(1.dp, riskUi.color.copy(alpha = 0.18f)),
                            shape = RoundedCornerShape(999.dp)
                        ) {
                            Text(
                                text = chip,
                                color = SigurColors.TextSecondary,
                                fontSize = 10.sp,
                                fontWeight = FontWeight.SemiBold,
                                modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun ResultSection(title: String, items: List<String>, icon: ImageVector) {
    Column(modifier = Modifier.padding(vertical = 8.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(icon, contentDescription = null, tint = SigurColors.TextMuted, modifier = Modifier.size(16.dp))
            Spacer(modifier = Modifier.width(6.dp))
            Text(title, fontWeight = FontWeight.Bold, color = SigurColors.TextPrimary, fontSize = 14.sp)
        }
        items.forEach { item ->
            Text(
                text = "• $item",
                color = SigurColors.TextSecondary,
                fontSize = 13.sp,
                modifier = Modifier.padding(start = 22.dp, top = 2.dp)
            )
        }
    }
}

@Composable
fun OfferAnalysisSection(analysis: String) {
    Column(modifier = Modifier.padding(vertical = 12.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Default.AutoAwesome, contentDescription = null, tint = SigurColors.Suspect, modifier = Modifier.size(16.dp))
            Spacer(modifier = Modifier.width(6.dp))
            Text("🔍 Verificare Ofertă / Campanie (AI)", fontWeight = FontWeight.Bold, color = SigurColors.TextPrimary, fontSize = 14.sp)
        }
        
        Spacer(modifier = Modifier.height(8.dp))
        
        Card(
            colors = CardDefaults.cardColors(containerColor = SigurColors.SuspectLight),
            border = BorderStroke(1.dp, SigurColors.SuspectBorder),
            shape = RoundedCornerShape(12.dp)
        ) {
            Text(
                text = analysis,
                color = SigurColors.TextSecondary,
                fontSize = 13.sp,
                lineHeight = 20.sp,
                modifier = Modifier.padding(12.dp)
            )
        }
    }
}

@Composable
fun ComplianceSection(authSummary: String) {
    Column(modifier = Modifier.padding(vertical = 12.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Default.CheckCircle, contentDescription = null, tint = SigurColors.Safe, modifier = Modifier.size(16.dp))
            Spacer(modifier = Modifier.width(6.dp))
            Text("Autentificare email (DKIM/SPF/DMARC)", fontWeight = FontWeight.Bold, color = SigurColors.TextPrimary, fontSize = 14.sp)
        }

        Spacer(modifier = Modifier.height(8.dp))

        Card(
            colors = CardDefaults.cardColors(containerColor = SigurColors.SafeLight),
            border = BorderStroke(1.dp, SigurColors.SafeBorder),
            shape = RoundedCornerShape(12.dp)
        ) {
            Text(
                text = authSummary,
                color = SigurColors.TextSecondary,
                fontSize = 12.sp,
                modifier = Modifier.padding(12.dp)
            )
        }
    }
}

@Composable
fun ButtonsSection(buttons: List<String>) {
    Column(modifier = Modifier.padding(vertical = 12.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Default.TouchApp, contentDescription = null, tint = SigurColors.Suspect, modifier = Modifier.size(16.dp))
            Spacer(modifier = Modifier.width(6.dp))
            Text("Butoane Detectate În E-mail", fontWeight = FontWeight.Bold, color = SigurColors.TextPrimary, fontSize = 14.sp)
        }

        Spacer(modifier = Modifier.height(8.dp))

        Card(
            colors = CardDefaults.cardColors(containerColor = SigurColors.SuspectLight),
            border = BorderStroke(1.dp, SigurColors.SuspectBorder),
            shape = RoundedCornerShape(12.dp)
        ) {
            Column(modifier = Modifier.padding(12.dp)) {
                buttons.forEach { button ->
                    Text("• $button", color = SigurColors.TextSecondary, fontSize = 12.sp)
                }
            }
        }
    }
}

@Composable
fun SincerityPillarsSection(assessment: OfflineAssessment) {
    Column(modifier = Modifier.padding(vertical = 12.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Default.Verified, contentDescription = null, tint = SigurColors.Safe, modifier = Modifier.size(16.dp))
            Spacer(modifier = Modifier.width(6.dp))
            Text("Detalii de verificare", fontWeight = FontWeight.Bold, color = SigurColors.TextPrimary, fontSize = 14.sp)
        }
        
        Spacer(modifier = Modifier.height(8.dp))
        
        Card(
            colors = CardDefaults.cardColors(containerColor = SigurColors.BackgroundSurface),
            border = BorderStroke(1.dp, SigurColors.GlassBorder),
            shape = RoundedCornerShape(12.dp)
        ) {
            Column(modifier = Modifier.padding(12.dp)) {
                PillarRow("1. Cazier Global", assessment.reputationVerdict, Icons.Default.Public)
                PillarRow("2. Vârsta Domeniului", assessment.domainAgeText, Icons.Default.History)
                PillarRow("3. Infrastructură (SSL)", assessment.sslStatus, Icons.Default.Lock)
                PillarRow("4. Analiză de Conținut", assessment.aiConfidence, Icons.Default.AutoAwesome)
            }
        }
    }
}

@Composable
fun PillarRow(label: String, value: String, icon: ImageVector) {
    Row(
        modifier = Modifier.padding(vertical = 6.dp).fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(icon, contentDescription = null, tint = SigurColors.TextMuted, modifier = Modifier.size(14.dp))
            Spacer(modifier = Modifier.width(8.dp))
            Text(label, color = SigurColors.TextSecondary, fontSize = 12.sp)
        }
        Text(value, color = SigurColors.TextPrimary, fontSize = 12.sp, fontWeight = FontWeight.Bold)
    }
}

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

private fun publicThreatSource(source: String): String {
    val normalized = source.lowercase(Locale.getDefault())
    return when {
        normalized.contains("urlscan") -> "Analiză izolată"
        normalized.contains("web risk") || normalized.contains("webrisk") || normalized.contains("google") -> "Reputație globală"
        normalized.contains("phishing.database") || normalized.contains("phishing_database") -> "Listă phishing activ"
        normalized.contains("backend") -> "Analiză SigurScan"
        else -> "Sursă de verificare"
    }
}

private fun publicThreatVerdict(verdict: String): String {
    val normalized = verdict.lowercase(Locale.getDefault())
    return when {
        normalized.contains("pending") || normalized.contains("queued") || normalized.contains("processing") -> "În verificare"
        normalized.contains("malware") || normalized.contains("phish") || normalized.contains("malicious") || normalized.contains("threat") -> "Periculos"
        normalized.contains("clean") || normalized.contains("no malicious") || normalized.contains("no threat") || normalized.contains("no classification") -> "Sigur"
        normalized.isBlank() -> "În verificare"
        else -> "Suspect"
    }
}

private fun publicThreatDetails(details: String?): String? {
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

private fun publicServerInfo(serverInfo: String?): String {
    val value = serverInfo?.trim()?.takeIf { it.isNotBlank() } ?: return "Preview securizat al paginii finale"
    val normalized = value.lowercase(Locale.getDefault())
    return when {
        normalized.contains("server:") || normalized.contains("backend") || normalized.contains("http ") || normalized.contains("sandbox") ->
            "Preview securizat al paginii finale"
        normalized.contains("genere") || normalized.contains("processing") || normalized.contains("pending") ->
            "Preview-ul securizat se generează."
        else -> value.take(140)
    }
}

private data class UserActionDecision(
    val headline: String,
    val supportText: String,
    val nextBestAction: String
)

private fun mapUserActionDecision(assessment: OfflineAssessment, riskUi: RiskDisplayState): UserActionDecision {
    assessment.gateResult?.let { gateResult ->
        return UserActionDecision(
            headline = GateResultPresentation.userHeadline(gateResult),
            supportText = GateResultPresentation.supportText(gateResult),
            nextBestAction = GateResultPresentation.primaryAction(gateResult)
        )
    }

    val normalizedText = assessment.originalText.lowercase(Locale.getDefault())
    val asksForSensitiveData = containsAny(
        normalizedText,
        listOf("card", "cvv", "cvc", "otp", "parola", "pin", "iban", "cod")
    )
    val looksLikeEmail = assessment.emailAuth != null || containsAny(
        normalizedText,
        listOf("from:", "subject:", "reply-to:", "expeditor", "subiect")
    )

    return when (riskUi.level) {
        "Periculos" -> UserActionDecision(
            headline = when {
                asksForSensitiveData -> "Nu introduce date"
                looksLikeEmail -> "Nu răspunde"
                else -> "Nu continua"
            },
            supportText = "Am găsit semnale puternice de risc. Verifică direct în aplicația sau pe site-ul oficial.",
            nextBestAction = if (asksForSensitiveData) {
                "Nu trimite parole, coduri OTP sau date de card."
            } else {
                "Deschide manual site-ul oficial, nu linkul primit."
            }
        )
        "Suspect" -> UserActionDecision(
            headline = "Suspect",
            supportText = "Am găsit semnale neclare. Verifică direct în aplicația sau pe site-ul oficial.",
            nextBestAction = "Intră manual în aplicația sau site-ul oficial, fără să apeși linkul primit."
        )
        else -> UserActionDecision(
            headline = "Sigur",
            supportText = "Scanarea a verificat destinația și nu a găsit semnale clare de risc.",
            nextBestAction = "Poți continua."
        )
    }
}

private fun buildTopReasons(assessment: OfflineAssessment, decision: UserActionDecision): List<String> {
    val gateReason = assessment.gateResult?.let {
        GateResultPresentation.reasonText(it, assessment.evidenceSnapshot)
    }
    return (listOfNotNull(gateReason) + assessment.reasons + assessment.keyDangers)
        .map { it.trim() }
        .filter { it.isNotBlank() }
        .distinct()
        .take(2)
        .ifEmpty { listOf(decision.supportText) }
}

private fun buildNextActions(assessment: OfflineAssessment, decision: UserActionDecision): List<String> {
    val gateActions = assessment.gateResult?.let {
        listOf(GateResultPresentation.primaryAction(it)) + GateResultPresentation.recommendedActions(it)
    } ?: listOf(decision.nextBestAction)
    return (gateActions + assessment.safeActions)
        .map { it.trim() }
        .filter { it.isNotBlank() }
        .distinct()
        .take(3)
}

private fun displayDomainFrom(url: String?): String? {
    if (url.isNullOrBlank()) return null
    val normalizedUrl = if (url.startsWith("http://", true) || url.startsWith("https://", true)) {
        url
    } else {
        "https://$url"
    }
    return runCatching { Uri.parse(normalizedUrl).host?.removePrefix("www.") }
        .getOrNull()
        ?.takeIf { it.isNotBlank() }
        ?: url.take(64)
}

private fun containsAny(input: String, needles: List<String>): Boolean {
    return needles.any { input.contains(it) }
}

private data class RiskDisplayState(val level: String, val label: String, val color: Color)

private fun mapRiskDisplayState(assessment: OfflineAssessment): RiskDisplayState {
    return assessment.gateResult?.let { mapGateDisplayState(it) }
        ?: mapRiskDisplayState(assessment.riskLevel)
}

private fun mapGateDisplayState(result: GateResult): RiskDisplayState {
    if (GateResultPresentation.isScanInProgress(result)) {
        return RiskDisplayState(
            level = "Scanare în curs",
            label = "Scanare în curs",
            color = SigurColors.Brand
        )
    }
    return mapGateDisplayState(result.action)
}

private fun mapGateDisplayState(action: GateAction): RiskDisplayState = when (action) {
    GateAction.DO_NOT_CONTINUE,
    GateAction.NO_ENTER_DATA,
    GateAction.NO_REPLY -> RiskDisplayState(
        level = "Periculos",
        label = "Periculos",
        color = SigurColors.Dangerous
    )
    GateAction.VERIFY_OFFICIAL -> RiskDisplayState(
        level = "Suspect",
        label = "Suspect",
        color = SigurColors.Suspect
    )
    GateAction.CONTINUE_WITH_CAUTION -> RiskDisplayState(
        level = "Sigur",
        label = "Sigur",
        color = SigurColors.Safe
    )
    GateAction.INSUFFICIENT_EVIDENCE -> RiskDisplayState(
        level = "Suspect",
        label = "Suspect",
        color = SigurColors.Suspect
    )
}

private fun mapRiskDisplayState(level: String): RiskDisplayState {
    return when (level.lowercase(Locale.getDefault())) {
        "high", "critical", "dangerous", "high_risk" -> RiskDisplayState(
            level = "Periculos",
            label = "Periculos",
            color = SigurColors.Dangerous
        )
        "medium", "suspicious", "warn", "warning" -> RiskDisplayState(
            level = "Suspect",
            label = "Suspect",
            color = SigurColors.Suspect
        )
        "error" -> RiskDisplayState(
            level = "Suspect",
            label = "Suspect",
            color = SigurColors.Suspect
        )
        "low", "safe", "none" -> RiskDisplayState(
            level = "Sigur",
            label = "Sigur",
            color = SigurColors.Safe
        )
        else -> RiskDisplayState(
            level = "Suspect",
            label = "Suspect",
            color = SigurColors.Suspect
        )
    }
}

private fun gateStatusText(result: GateResult?): String {
    return when {
        result == null -> "Scanare pregătită"
        result.asyncExpected || result.finality == GateFinality.PROVISIONAL -> "Scanare în curs"
        else -> "Verdict finalizat"
    }
}

private fun resultIconFor(action: GateAction?, level: String): ImageVector {
    if (level == "Scanare în curs") return Icons.Default.HourglassEmpty
    return when (action) {
        GateAction.DO_NOT_CONTINUE,
        GateAction.NO_ENTER_DATA,
        GateAction.NO_REPLY -> Icons.Default.Warning
        GateAction.VERIFY_OFFICIAL -> Icons.Default.Info
        GateAction.CONTINUE_WITH_CAUTION -> Icons.Default.CheckCircle
        GateAction.INSUFFICIENT_EVIDENCE -> Icons.Default.ReportProblem
        null -> when (level) {
            "Periculos" -> Icons.Default.Warning
            "Sigur" -> Icons.Default.CheckCircle
            else -> Icons.Default.Info
        }
    }
}

@Composable
fun HistoryTab(viewModel: ScannerViewModel) {
    Column(modifier = Modifier.fillMaxSize().padding(20.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(bottom = 20.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.History, contentDescription = null, tint = SigurColors.Brand)
                Spacer(modifier = Modifier.width(8.dp))
                Text("Istoric Scanări", fontSize = 20.sp, fontWeight = FontWeight.Bold, color = SigurColors.TextPrimary)
            }
            if (viewModel.historyItems.isNotEmpty()) {
                Text(
                    "Șterge tot",
                    color = SigurColors.Dangerous,
                    fontSize = 12.sp,
                    modifier = Modifier.clickable { viewModel.clearHistory() }
                )
            }
        }

        if (viewModel.historyItems.isEmpty()) {
            Card(
                modifier = Modifier.fillMaxSize(),
                colors = CardDefaults.cardColors(containerColor = SigurColors.BackgroundCard),
                shape = DSCardShape,
                border = DSCardBorder
            ) {
                Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        Icon(Icons.Default.History, contentDescription = null, modifier = Modifier.size(64.dp), tint = SigurColors.TextSubtle)
                        Spacer(modifier = Modifier.height(16.dp))
                        Text("Nicio scanare efectuată", color = SigurColors.TextPrimary, fontWeight = FontWeight.Bold)
                        Text(
                            "Istoricul scanărilor tale va fi salvat local, în siguranță pe dispozitiv.",
                            color = SigurColors.TextSecondary,
                            fontSize = 13.sp,
                            textAlign = TextAlign.Center,
                            modifier = Modifier.padding(horizontal = 40.dp)
                        )
                    }
                }
            }
        } else {
            LazyColumn {
                items(viewModel.historyItems) { item ->
                    HistoryItemCard(item, onClick = { viewModel.assessment = item; viewModel.currentTab = "scan" }, onDelete = { viewModel.deleteHistoryItem(item) })
                }
            }
        }
    }
}

@Composable
fun HistoryItemCard(item: OfflineAssessment, onClick: () -> Unit, onDelete: () -> Unit) {
    val risk = mapRiskDisplayState(item)
    val chipTone = when (risk.color) {
        SigurColors.Dangerous -> DSChipTone.Danger
        SigurColors.Safe -> DSChipTone.Safe
        SigurColors.Brand -> DSChipTone.Pending
        else -> DSChipTone.Suspect
    }

    Card(
        modifier = Modifier.fillMaxWidth().padding(vertical = 6.dp).clickable { onClick() },
        colors = CardDefaults.cardColors(containerColor = SigurColors.BackgroundCard),
        shape = DSCardShape,
        border = DSCardBorder
    ) {
        Row(modifier = Modifier.padding(16.dp)) {
            Column(modifier = Modifier.weight(1f)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    DSChip(text = risk.label.uppercase(Locale.getDefault()), tone = chipTone)
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = SimpleDateFormat("dd.MM.yyyy HH:mm", Locale.getDefault()).format(Date(item.timestamp)),
                        color = SigurColors.TextMuted,
                        fontSize = 11.sp
                    )
                }
                Spacer(modifier = Modifier.height(8.dp))
                Text("Clasificare: ${item.family}", color = SigurColors.TextPrimary, fontWeight = FontWeight.Bold, fontSize = 14.sp)
                Text(publicHistorySummary(item), color = SigurColors.TextSecondary, fontSize = 12.sp, maxLines = 1)
            }
            IconButton(onClick = onDelete) {
                Icon(Icons.Default.Delete, contentDescription = null, tint = SigurColors.Dangerous.copy(alpha = 0.70f), modifier = Modifier.size(18.dp))
            }
        }
    }
}

private fun publicHistorySummary(item: OfflineAssessment): String {
    item.finalUrl?.let { return "Link analizat: ${it.take(72)}" }
    return when {
        item.originalText.startsWith("scan=", ignoreCase = true) -> "Conținut analizat local, detalii redactate"
        item.originalText.contains("Scanare imagine", ignoreCase = true) -> "Imagine analizată"
        item.originalText.contains("Scanare PDF", ignoreCase = true) -> "PDF analizat"
        item.originalText.contains("Scanare email", ignoreCase = true) -> "E-mail analizat"
        item.originalText.contains("Fișier", ignoreCase = true) -> "Fișier analizat"
        else -> "Mesaj analizat, conținut redactat"
    }
}

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

    Column(modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(20.dp)) {
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

@Composable
fun ReportsTab(viewModel: ScannerViewModel) {
    val readiness = viewModel.readiness
    val quality = viewModel.quality
    val summary = quality?.summary as? Map<String, Any>
    val falsePositiveCount = viewModel.feedbackSamples?.topFalsePositive?.size ?: 0
    val falseNegativeCount = viewModel.feedbackSamples?.topFalseNegative?.size ?: 0

    fun asFloat(value: Any?): Float {
        return when (value) {
            is Number -> value.toFloat()
            is String -> value.toFloatOrNull() ?: 0f
            else -> 0f
        }
    }

    fun percent(value: Any?): Float {
        val normalized = asFloat(value)
        return if (normalized > 1f) normalized / 100f else normalized
    }

    Column(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text("Rapoarte Detective", fontSize = 20.sp, fontWeight = FontWeight.Bold, color = SigurColors.TextPrimary)
            if (viewModel.reportsLoading) {
                CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp, color = SigurColors.Brand)
            }
        }
        Spacer(modifier = Modifier.height(16.dp))
        
        Card(
            colors = CardDefaults.cardColors(containerColor = SigurColors.BackgroundCard),
            shape = DSCardShape,
            border = DSCardBorder
        ) {
            Column(modifier = Modifier.padding(20.dp)) {
                Row(horizontalArrangement = Arrangement.SpaceBetween, modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Text("Maturitate Detectiv", color = SigurColors.TextPrimary, fontWeight = FontWeight.Bold)
                    val readinessTone = when (readiness?.status) {
                        "healthy" -> DSChipTone.Safe
                        "watch" -> DSChipTone.Suspect
                        else -> DSChipTone.Danger
                    }
                    val readinessLabel = when (readiness?.status) {
                        "healthy" -> "Sănătos"
                        "watch" -> "Atenție"
                        "degraded" -> "Degradat"
                        else -> "Încărcare..."
                    }
                    DSChip(text = readinessLabel.uppercase(Locale.getDefault()), tone = readinessTone)
                }
                Text(
                    text = String.format("%.2f", readiness?.readinessScore ?: 0f),
                    color = SigurColors.Safe,
                    fontSize = 40.sp,
                    fontWeight = FontWeight.Black
                )
                Text("readiness_score (0..1)", color = SigurColors.TextSecondary, fontSize = 12.sp)
                
                Spacer(modifier = Modifier.height(16.dp))
                
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    val qualityScore = readiness?.readinessComponents?.get("quality_score") ?: 0f
                    val coverageScore = readiness?.readinessComponents?.get("coverage_score") ?: 0f
                    Text("Calitate: ${String.format("%.0f%%", qualityScore * 100)}", color = SigurColors.TextPrimary, fontSize = 12.sp)
                    Text("Acoperire: ${String.format("%.0f%%", coverageScore * 100)}", color = SigurColors.TextPrimary, fontSize = 12.sp)
                }
            }
        }
        
        Spacer(modifier = Modifier.height(16.dp))
        
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            val metrics = listOf(
                "Precision" to percent(summary?.get("precision")),
                "Recall" to percent(summary?.get("recall")),
                "F1" to percent(summary?.get("f1"))
            )
            
            metrics.forEach { (label, value) ->
                Card(
                    modifier = Modifier.weight(1f),
                    colors = CardDefaults.cardColors(containerColor = SigurColors.BackgroundCard),
                    shape = DSCardShape,
                    border = DSCardBorder
                ) {
                    Column(modifier = Modifier.padding(12.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                        Text(label, color = SigurColors.TextSecondary, fontSize = 11.sp)
                        Text(String.format("%.0f%%", value * 100), color = SigurColors.TextPrimary, fontWeight = FontWeight.Bold)
                    }
                }
            }
        }
        
        Spacer(modifier = Modifier.height(16.dp))
        
        Card(
            colors = CardDefaults.cardColors(containerColor = SigurColors.BackgroundCard),
            shape = DSCardShape,
            border = DSCardBorder
        ) {
            Column(modifier = Modifier.padding(20.dp)) {
                Text("Bucăți evaluate: ${quality?.itemsEvaluated ?: 0}", color = SigurColors.TextPrimary, fontWeight = FontWeight.Bold)
                Spacer(modifier = Modifier.height(12.dp))
                MetricRow("Reputație URL", String.format("%.0f%%", (readiness?.readinessComponents?.get("reputation_score") ?: 0f) * 100))
                MetricRow("Rate Corecte", "${quality?.itemsEvaluated ?: 0}")
                MetricRow("False positive / False negative", "$falsePositiveCount / $falseNegativeCount")
            }
        }

        if (viewModel.feedbackSamples != null) {
            Spacer(modifier = Modifier.height(16.dp))
            Card(
                colors = CardDefaults.cardColors(containerColor = SigurColors.BackgroundCard),
                shape = DSCardShape,
                border = DSCardBorder
            ) {
                Column(modifier = Modifier.padding(20.dp)) {
                    Text("Monitorizare feedback comunitate", color = SigurColors.TextPrimary, fontWeight = FontWeight.Bold)
                    Spacer(modifier = Modifier.height(12.dp))
                    Text(
                        "False Positive (cele mai frecvente): ${viewModel.feedbackSamples?.topFalsePositive?.joinToString(", ") ?: "N/A"}",
                        color = SigurColors.TextSecondary,
                        fontSize = 12.sp
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        "False Negative (cele mai frecvente): ${viewModel.feedbackSamples?.topFalseNegative?.joinToString(", ") ?: "N/A"}",
                        color = SigurColors.TextSecondary,
                        fontSize = 12.sp
                    )
                }
            }
        }

        viewModel.reputationStats?.let { stats ->
            Spacer(modifier = Modifier.height(16.dp))
            Card(
                colors = CardDefaults.cardColors(containerColor = SigurColors.BackgroundCard),
                shape = DSCardShape,
                border = DSCardBorder
            ) {
                Column(modifier = Modifier.padding(20.dp)) {
                    Text("Statistici cache reputație", color = SigurColors.TextPrimary, fontWeight = FontWeight.Bold)
                    Spacer(modifier = Modifier.height(12.dp))
                    MetricRow("Rata de hit cache", String.format("%.0f%%", (stats.cacheHitRatio ?: 0f) * 100))
                    MetricRow("În cache", "${stats.cachedDomains ?: 0}")
                    MetricRow("Înregistrări", "${stats.entries ?: 0}")
                    MetricRow("Ultima sincronizare", stats.lastUpdated ?: "N/A")
                }
            }
        }
    }
}

@Composable
fun MetricRow(label: String, value: String) {
    Row(modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(label, color = SigurColors.TextSecondary, fontSize = 12.sp)
        Text(value, color = SigurColors.TextPrimary, fontSize = 12.sp, fontWeight = FontWeight.Bold)
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

private fun contrastChannel(channel: Float): Float {
    return if (channel <= 0.03928f) channel / 12.92f else ((channel + 0.055f) / 1.055f).pow(2.4f)
}

private fun contrastRatio(foreground: Color, background: Color): Float {
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

@Composable
private fun BottomNavItem(
    icon: ImageVector,
    label: String,
    isActive: Boolean,
    activeColor: Color = SigurColors.Brand,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
        modifier = modifier
            .fillMaxHeight()
            .clickable(onClick = onClick)
            .padding(top = 12.dp),
    ) {
        Icon(
            imageVector = icon,
            contentDescription = label,
            tint = if (isActive) activeColor else SigurColors.TextMuted,
            modifier = Modifier.size(24.dp)
        )
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = label,
            fontSize = 12.sp,
            fontWeight = if (isActive) FontWeight.Bold else FontWeight.Medium,
            color = if (isActive) activeColor else SigurColors.TextMuted
        )
    }
}

@Composable
fun BottomNavigationBar(activeTab: String, onTabClick: (String) -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .height(80.dp)
            .background(SigurColors.BackgroundCard)
            .border(BorderStroke(1.dp, SigurColors.BorderSubtle)),
        verticalAlignment = Alignment.Top
    ) {
        BottomNavItem(
            icon = Icons.Default.Radar,
            label = "Radar",
            isActive = activeTab == "radar",
            onClick = { onTabClick("radar") },
            modifier = Modifier.weight(1f)
        )
        BottomNavItem(
            icon = Icons.Default.Warning,
            label = "Urgență",
            isActive = activeTab == "triage",
            activeColor = SigurColors.Dangerous,
            onClick = { onTabClick("triage") },
            modifier = Modifier.weight(1f)
        )

        // Central FAB — scan action, raised above the bar (DS BottomNav)
        Box(
            modifier = Modifier
                .weight(1f)
                .fillMaxHeight(),
            contentAlignment = Alignment.TopCenter
        ) {
            Box(
                modifier = Modifier
                    .offset(y = (-28).dp)
                    .size(56.dp)
                    .border(4.dp, SigurColors.Canvas, CircleShape)
                    .clip(CircleShape)
                    .background(
                        brush = androidx.compose.ui.graphics.Brush.linearGradient(
                            colors = listOf(Color(0xFF5B86FF), SigurColors.Brand, Color(0xFF3552D6))
                        )
                    )
                    .clickable { onTabClick("scan") },
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = Icons.Default.QrCodeScanner,
                    contentDescription = "Scanează",
                    tint = Color.White,
                    modifier = Modifier.size(24.dp)
                )
            }
            Text(
                text = "Scanează",
                fontSize = 12.sp,
                fontWeight = if (activeTab == "scan") FontWeight.Bold else FontWeight.Medium,
                color = if (activeTab == "scan") SigurColors.Brand else SigurColors.TextMuted,
                modifier = Modifier
                    .align(Alignment.BottomCenter)
                    .padding(bottom = 12.dp)
            )
        }

        BottomNavItem(
            icon = Icons.Default.School,
            label = "Educație",
            isActive = activeTab == "education",
            onClick = { onTabClick("education") },
            modifier = Modifier.weight(1f)
        )
        BottomNavItem(
            icon = Icons.Default.MoreHoriz,
            label = "Mai mult",
            isActive = activeTab == "more",
            onClick = { onTabClick("more") },
            modifier = Modifier.weight(1f)
        )
    }
}

// ─────────────────────────────────────────────────────────────
// DS shared primitives (design-system/ds-full: .ss-card, .ss-chip)
// ─────────────────────────────────────────────────────────────
val DSCardShape = RoundedCornerShape(SigurColors.RadiusCard.dp)
val DSPillShape = RoundedCornerShape(SigurColors.RadiusPill.dp)
val DSCardBorder = BorderStroke(1.dp, SigurColors.GlassBorder)

enum class DSChipTone { Safe, Suspect, Danger, Pending, Brand, Neutral }

@Composable
fun DSChip(text: String, tone: DSChipTone = DSChipTone.Neutral, modifier: Modifier = Modifier) {
    val (bg, fg) = when (tone) {
        DSChipTone.Safe -> SigurColors.SafeLight to SigurColors.Safe
        DSChipTone.Suspect -> SigurColors.SuspectLight to SigurColors.Suspect
        DSChipTone.Danger -> SigurColors.DangerousLight to SigurColors.Dangerous
        DSChipTone.Pending -> SigurColors.PendingLight to SigurColors.Pending
        DSChipTone.Brand -> SigurColors.BrandTint to SigurColors.Brand
        DSChipTone.Neutral -> SigurColors.BackgroundSurface to SigurColors.TextSecondary
    }
    Box(
        modifier = modifier
            .background(bg, DSPillShape)
            .then(
                if (tone == DSChipTone.Neutral)
                    Modifier.border(1.dp, SigurColors.BorderSubtle, DSPillShape)
                else Modifier
            )
            .padding(horizontal = 12.dp, vertical = 6.dp),
        contentAlignment = Alignment.Center
    ) {
        Text(text, fontSize = 12.sp, fontWeight = FontWeight.SemiBold, color = fg, maxLines = 1)
    }
}

@Composable
fun InvoiceResultCard(result: InvoiceScanResponse, onBack: () -> Unit) {
    val readinessState = result.readiness?.state ?: "unknown"
    val isReady = readinessState == "ready_for_analysis"
    val isError = result.error != null
    val hasWarnings = result.warnings?.isNotEmpty() == true
    val impersonation = result.brandMatch?.impersonationRisk == true

    val tone = when {
        isError -> DSChipTone.Danger
        impersonation -> DSChipTone.Danger
        hasWarnings -> DSChipTone.Suspect
        isReady -> DSChipTone.Safe
        else -> DSChipTone.Pending
    }

    Card(
        colors = CardDefaults.cardColors(containerColor = SigurColors.BackgroundCard),
        shape = RoundedCornerShape(16.dp),
        modifier = Modifier.fillMaxWidth().border(1.dp, SigurColors.GlassBorder, RoundedCornerShape(16.dp))
    ) {
        Column(modifier = Modifier.padding(20.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Receipt, contentDescription = null, tint = SigurColors.Brand, modifier = Modifier.size(24.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text("Scanare Factură", fontWeight = FontWeight.Bold, fontSize = 18.sp, color = SigurColors.TextPrimary)
                Spacer(modifier = Modifier.weight(1f))
                DSChip(
                    when {
                        isError -> "Eroare"
                        impersonation -> "Pericol"
                        hasWarnings -> "Atenție"
                        isReady -> "Verificat"
                        else -> "Incert"
                    },
                    tone = tone
                )
            }

            Spacer(modifier = Modifier.height(16.dp))

            result.error?.let { err ->
                Text(err, color = SigurColors.Dangerous, fontSize = 14.sp)
                Spacer(modifier = Modifier.height(12.dp))
            }

            result.fields?.let { f ->
                val currency = f.currency ?: "RON"
                val profileLabel = when (f.invoiceProfile) {
                    "international" -> "Internațională / SaaS"
                    "ro" -> "România"
                    else -> f.invoiceProfile ?: "—"
                }
                InvoiceFieldRow("Emitent", f.emitent ?: "—")
                InvoiceFieldRow("Tip factură", profileLabel)
                InvoiceFieldRow("CUI", f.cui ?: "—")
                InvoiceFieldRow("IBAN", f.iban ?: "—")
                InvoiceFieldRow("Nr. Factură", f.nrFactura ?: "—")
                InvoiceFieldRow("Data", f.dataEmitere ?: "—")
                InvoiceFieldRow("Scadența", f.scadenta ?: "—")
                InvoiceFieldRow("Total", formatInvoiceAmount(f.total, currency))
                InvoiceFieldRow("Subtotal", formatInvoiceAmount(f.subtotal, currency))
                InvoiceFieldRow("Taxă / TVA", formatInvoiceAmount(f.tva, currency))
            }

            result.brand?.let { brand ->
                Spacer(modifier = Modifier.height(8.dp))
                InvoiceFieldRow("Brand detectat", brand, DSChipTone.Brand)
            }

            result.iban?.let { iban ->
                if (iban.valid != null) {
                    Spacer(modifier = Modifier.height(8.dp))
                    InvoiceFieldRow("IBAN valid", if (iban.valid) "Da" else "Nu")
                    iban.bank?.let { InvoiceFieldRow("Bancă", it) }
                }
            }

            result.warnings?.takeIf { it.isNotEmpty() }?.let { warnings ->
                Spacer(modifier = Modifier.height(12.dp))
                Text("Avertismente:", fontWeight = FontWeight.Bold, fontSize = 13.sp, color = SigurColors.Suspect)
                warnings.forEach { w ->
                    Text("• $w", fontSize = 12.sp, color = SigurColors.TextSecondary, modifier = Modifier.padding(start = 8.dp, top = 4.dp))
                }
            }

            Spacer(modifier = Modifier.height(16.dp))
            Button(
                onClick = onBack,
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = SigurColors.Brand),
                shape = RoundedCornerShape(12.dp)
            ) {
                Text("Scanează altă factură", color = Color.White)
            }
        }
    }
}

private fun formatInvoiceAmount(value: Double?, currency: String): String {
    return value?.let { "%.2f %s".format(it, currency) } ?: "—"
}

@Composable
private fun InvoiceFieldRow(label: String, value: String, valueTone: DSChipTone = DSChipTone.Neutral) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(label, fontSize = 13.sp, color = SigurColors.TextSecondary)
        if (valueTone == DSChipTone.Brand) {
            DSChip(value, tone = valueTone)
        } else {
            Text(value, fontSize = 13.sp, fontWeight = FontWeight.Medium, color = SigurColors.TextPrimary)
        }
    }
    HorizontalDivider(color = SigurColors.BorderSubtle, thickness = 0.5.dp)
}
