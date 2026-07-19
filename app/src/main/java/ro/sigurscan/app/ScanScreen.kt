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

internal fun createInvoiceCaptureUri(context: Context): Uri {
    val dir = File(context.cacheDir, "invoice_photos").apply { mkdirs() }
    val stamp = SimpleDateFormat("yyyyMMdd_HHmmss_SSS", Locale.US).format(Date())
    val photo = File.createTempFile("sigurscan_invoice_$stamp", ".jpg", dir)
    return FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", photo)
}

@Composable
fun ScanTab(
    viewModel: ScannerViewModel,
    onPickImage: () -> Unit,
    onPickFile: () -> Unit,
    onScanQr: () -> Unit,
    onCaptureInvoicePhoto: () -> Unit = {},
    onScanInvoice: () -> Unit = {},
    onInvoiceOfficialXmlCheck: () -> Unit = {},
    onScanOffer: () -> Unit = {}
) {
    val context = LocalContext.current
    val hasActiveScanContext = viewModel.loading ||
        viewModel.paymentCaseActive ||
        viewModel.assessment != null ||
        viewModel.invoiceResult != null ||
        viewModel.pendingOfferConfirmation != null ||
        viewModel.pendingSharedInput != null ||
        viewModel.pendingSharedFiles.isNotEmpty() ||
        viewModel.sharedContentFidelity != null

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(start = 20.dp, end = 20.dp, top = 20.dp, bottom = 120.dp),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        AppHeaderV2()

        Spacer(modifier = Modifier.height(14.dp))

        if (hasActiveScanContext) {
            viewModel.sharedContentFidelity?.let { fidelity ->
                SharedContentFidelityCard(
                    fidelity = fidelity,
                    sourceLabel = viewModel.sharedContentSourceLabel
                )
                Spacer(modifier = Modifier.height(16.dp))
            }

            val pendingOfferConfirmation = viewModel.pendingOfferConfirmation
            val invoiceResult = viewModel.invoiceResult
            val assessment = viewModel.assessment
            val paymentCaseResult = viewModel.paymentCaseResult
            when {
                pendingOfferConfirmation != null -> OfferConfirmationCard(
                    draft = pendingOfferConfirmation,
                    onConfirm = { viewModel.confirmOfferAndScan(it) },
                    onCancel = { viewModel.cancelOfferConfirmation() }
                )
                viewModel.paymentCaseActive && paymentCaseResult != null -> PaymentCaseResultCard(
                    result = paymentCaseResult,
                    loading = viewModel.paymentCaseLoading || viewModel.loading,
                    status = viewModel.paymentCaseStatus ?: viewModel.loadingMsg.takeIf { viewModel.loading },
                    onAddOffer = onScanOffer,
                    onAddFile = onPickFile,
                    onClose = { viewModel.discardPaymentCase() },
                )
                viewModel.paymentCaseActive -> PaymentCaseSetupCard(
                    status = viewModel.paymentCaseStatus,
                    loading = viewModel.loading || viewModel.paymentCaseLoading,
                    canRetry = nextPaymentCaseRetryRef(
                        viewModel.pendingPaymentCaseArtifactRefs,
                        viewModel.attachedPaymentCaseArtifactRefs,
                    ) != null,
                    onRetry = { viewModel.retryPaymentCaseAttach() },
                    onCaptureInvoice = onCaptureInvoicePhoto,
                    onPickInvoice = onScanInvoice,
                    onClose = { viewModel.discardPaymentCase() },
                )
                invoiceResult != null -> InvoiceResultCard(
                    result = invoiceResult,
                    sanbStatus = viewModel.invoiceSanbStatus,
                    onSanbAttestation = { attestation ->
                        viewModel.submitInvoiceBeneficiaryAttestation(attestation, context)
                    },
                    onOfficialXmlCheck = onInvoiceOfficialXmlCheck,
                    onBack = {
                        if (viewModel.paymentCaseActive) viewModel.discardPaymentCase() else viewModel.reset()
                    }
                )
                assessment != null -> ResultCard(
                    assessment = assessment,
                    onBack = {
                        if (viewModel.paymentCaseActive) viewModel.discardPaymentCase() else viewModel.reset()
                    },
                    onRescan = { viewModel.onScanClick(forceRefresh = true) },
                    onReport = { viewModel.onCommunityReport() },
                    officialReportPackage = viewModel.officialReportPackage,
                    officialReportLoading = viewModel.officialReportLoading,
                    officialReportStatus = viewModel.officialReportStatus,
                    onOfficialReport = { viewModel.requestOfficialReportPackage() },
                    onFeedback = { viewModel.submitFeedback(it) },
                    onFamilyAlert = { viewModel.notifyFamilyForCurrentScan() },
                    actionPlanLoading = viewModel.actionPlanLoading,
                    actionPlanStatus = viewModel.actionPlanStatus,
                    onActionPlanImpacts = { viewModel.requestPostIncidentActionPlan(it) }
                )
                else -> ScanInputCard(viewModel, onPickImage, onPickFile, onScanQr, onCaptureInvoicePhoto, onScanInvoice, onScanOffer)
            }

            Spacer(modifier = Modifier.height(20.dp))
        }

        if (!hasActiveScanContext) {
            ScanInputCard(viewModel, onPickImage, onPickFile, onScanQr, onCaptureInvoicePhoto, onScanInvoice, onScanOffer)
        }

        Spacer(modifier = Modifier.height(20.dp))

        viewModel.activeCampaignAlert?.let { activeCampaignAlert ->
            ActiveCampaignBanner(activeCampaignAlert) {
                viewModel.activeCampaignAlert = null
            }
            Spacer(modifier = Modifier.height(16.dp))
        }

        ActiveCampaignsSection(viewModel.campaigns, viewModel.campaignsLoading)

        Spacer(modifier = Modifier.height(20.dp))

        NoticeSection()
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
                        colors = listOf(Color(0xFF14BE86), SigurColors.Brand, Color(0xFF06875A))
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
fun ScanInputCard(
    viewModel: ScannerViewModel,
    onPickImage: () -> Unit,
    onPickFile: () -> Unit,
    onScanQr: () -> Unit,
    onCaptureInvoicePhoto: () -> Unit = {},
    onScanInvoice: () -> Unit = {},
    onScanOffer: () -> Unit = {}
) {
    val clipboard = LocalClipboardManager.current
    val context = LocalContext.current
    var showInvoiceSourceChooser by remember { mutableStateOf(false) }
    var showPaymentCaseSourceChooser by remember { mutableStateOf(false) }

    if (showInvoiceSourceChooser) {
        InvoiceSourceChooserDialog(
            onDismiss = { showInvoiceSourceChooser = false },
            onCapturePhoto = {
                showInvoiceSourceChooser = false
                onCaptureInvoicePhoto()
            },
            onPickDocument = {
                showInvoiceSourceChooser = false
                onScanInvoice()
            }
        )
    }

    if (showPaymentCaseSourceChooser) {
        InvoiceSourceChooserDialog(
            title = "Verifică o plată",
            onDismiss = { showPaymentCaseSourceChooser = false },
            onCapturePhoto = {
                showPaymentCaseSourceChooser = false
                viewModel.beginPaymentCase()
                onCaptureInvoicePhoto()
            },
            onPickDocument = {
                showPaymentCaseSourceChooser = false
                viewModel.beginPaymentCase()
                onScanInvoice()
            },
        )
    }

    val heroShape = RoundedCornerShape(24.dp)
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .clip(heroShape)
            .background(
                brush = androidx.compose.ui.graphics.Brush.linearGradient(
                    colors = listOf(Color(0xFF14BE86), SigurColors.Brand, Color(0xFF06875A))
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
                Box(modifier = Modifier.fillMaxWidth().height(120.dp), contentAlignment = Alignment.Center) {
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
                        .height(120.dp),
                    placeholder = {
                        Text(
                            "Lipește textul sau URL-ul aici",
                            color = SigurColors.TextMuted
                        )
                    },
                    label = {
                        Text(
                            "Text sau link de verificat",
                            color = SigurColors.TextSecondary,
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

            // v2: button disabled + "Scrie sau lipește ceva" until there is input to scan.
            val hasScanInput = viewModel.text.isNotBlank() ||
                viewModel.pendingSharedInput != null ||
                viewModel.pendingSharedFiles.isNotEmpty()
            val btnContent = if (hasScanInput) SigurColors.BrandDeep else Color.White.copy(alpha = 0.78f)
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
                colors = ButtonDefaults.buttonColors(
                    containerColor = Color.White,
                    disabledContainerColor = Color.White.copy(alpha = 0.20f)
                ),
                shape = RoundedCornerShape(100),
                contentPadding = PaddingValues(14.dp),
                enabled = hasScanInput && !viewModel.loading
            ) {
                Icon(Icons.Default.Bolt, contentDescription = null, tint = btnContent, modifier = Modifier.size(20.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    if (hasScanInput) "Scanează acum" else "Scrie sau lipește ceva",
                    fontSize = 16.sp,
                    fontWeight = FontWeight.Bold,
                    color = btnContent
                )
            }

        }
    }

    Spacer(modifier = Modifier.height(14.dp))

    Text(
        "Sau alege tipul de scanare",
        color = SigurColors.TextPrimary,
        fontSize = 13.sp,
        fontWeight = FontWeight.ExtraBold,
        modifier = Modifier.padding(start = 4.dp)
    )

    Spacer(modifier = Modifier.height(10.dp))

    Card(
        colors = CardDefaults.cardColors(containerColor = SigurColors.BackgroundCard),
        shape = RoundedCornerShape(16.dp),
        modifier = Modifier
            .fillMaxWidth()
            .border(1.dp, SigurColors.GlassBorder, RoundedCornerShape(16.dp))
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
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

            Spacer(modifier = Modifier.height(10.dp))

            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                GridButton(
                    title = "Scanează Cod QR",
                    desc = "Scanare live din cameră",
                    icon = Icons.Default.QrCodeScanner,
                    color = SigurColors.Safe,
                    onClick = onScanQr,
                    modifier = Modifier.weight(1f)
                )
                GridButton(
                    title = "Scanează Factură",
                    desc = "Poză sau fișier",
                    icon = Icons.Default.Receipt,
                    color = Color(0xFF7C4DFF),
                    onClick = { showInvoiceSourceChooser = true },
                    modifier = Modifier.weight(1f)
                )
            }

            Spacer(modifier = Modifier.height(12.dp))

            OfferScanEntryCard(
                onClick = onScanOffer,
                modifier = Modifier.fillMaxWidth()
            )

            Spacer(modifier = Modifier.height(10.dp))

            PaymentCaseEntryRow(
                onClick = { showPaymentCaseSourceChooser = true },
                modifier = Modifier.fillMaxWidth(),
            )
        }
    }
}

@Composable
internal fun SharedContentFidelityCard(fidelity: SharedContentFidelity, sourceLabel: String) {
    val accent = when (fidelity) {
        SharedContentFidelity.FULL_HTML -> SigurColors.Safe
        SharedContentFidelity.PLAIN_TEXT_ONLY -> SigurColors.Suspect
        SharedContentFidelity.FILE_OR_EMAIL -> SigurColors.Brand
        SharedContentFidelity.AUDIO_FILE -> SigurColors.Brand
    }
    val background = when (fidelity) {
        SharedContentFidelity.FULL_HTML -> SigurColors.SafeLight
        SharedContentFidelity.PLAIN_TEXT_ONLY -> SigurColors.SuspectLight
        SharedContentFidelity.FILE_OR_EMAIL -> SigurColors.BrandTint
        SharedContentFidelity.AUDIO_FILE -> SigurColors.BrandTint
    }
    val border = when (fidelity) {
        SharedContentFidelity.FULL_HTML -> SigurColors.SafeBorder
        SharedContentFidelity.PLAIN_TEXT_ONLY -> SigurColors.SuspectBorder
        SharedContentFidelity.FILE_OR_EMAIL -> SigurColors.Brand.copy(alpha = 0.30f)
        SharedContentFidelity.AUDIO_FILE -> SigurColors.Brand.copy(alpha = 0.30f)
    }
    val icon = when (fidelity) {
        SharedContentFidelity.FULL_HTML -> Icons.Default.MarkEmailRead
        SharedContentFidelity.PLAIN_TEXT_ONLY -> Icons.Default.Visibility
        SharedContentFidelity.FILE_OR_EMAIL -> Icons.Default.AttachFile
        SharedContentFidelity.AUDIO_FILE -> Icons.Default.GraphicEq
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
fun InvoiceSourceChooserDialog(
    title: String = "Scanează factura",
    onDismiss: () -> Unit,
    onCapturePhoto: () -> Unit,
    onPickDocument: () -> Unit
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                text = title,
                color = SigurColors.TextPrimary,
                fontWeight = FontWeight.Bold
            )
        },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                InvoiceSourceAction(
                    title = "Fă poză",
                    desc = "Fotografiază factura acum",
                    icon = Icons.Default.PhotoCamera,
                    onClick = onCapturePhoto
                )
                InvoiceSourceAction(
                    title = "Încarcă imagine/PDF",
                    desc = "Alege o factură salvată",
                    icon = Icons.Default.UploadFile,
                    onClick = onPickDocument
                )
            }
        },
        confirmButton = {},
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Închide")
            }
        },
        containerColor = SigurColors.BackgroundCard,
        shape = DSCardShape
    )
}

@Composable
internal fun InvoiceSourceAction(
    title: String,
    desc: String,
    icon: ImageVector,
    onClick: () -> Unit
) {
    Card(
        onClick = onClick,
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = SigurColors.Canvas),
        border = BorderStroke(1.dp, SigurColors.GlassBorder),
        shape = DSCardShape
    ) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(14.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(44.dp)
                    .background(Color(0xFF7C4DFF).copy(alpha = 0.12f), RoundedCornerShape(14.dp)),
                contentAlignment = Alignment.Center
            ) {
                Icon(icon, contentDescription = null, tint = Color(0xFF7C4DFF), modifier = Modifier.size(22.dp))
            }
            Spacer(modifier = Modifier.width(12.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(title, color = SigurColors.TextPrimary, fontSize = 15.sp, fontWeight = FontWeight.Bold)
                Text(desc, color = SigurColors.TextMuted, fontSize = 12.sp)
            }
        }
    }
}

@Composable
fun OfferScanEntryCard(onClick: () -> Unit, modifier: Modifier = Modifier) {
    Card(
        modifier = modifier.clickable { onClick() },
        colors = CardDefaults.cardColors(containerColor = SigurColors.BackgroundCard),
        border = BorderStroke(1.dp, SigurColors.GlassBorder),
        shape = DSCardShape
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(48.dp)
                    .background(SigurColors.BrandTint, RoundedCornerShape(16.dp)),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    imageVector = Icons.Default.LocalOffer,
                    contentDescription = null,
                    tint = SigurColors.Brand,
                    modifier = Modifier.size(24.dp)
                )
            }
            Spacer(modifier = Modifier.width(14.dp))
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = "Verifică o ofertă",
                    color = SigurColors.TextPrimary,
                    fontSize = 17.sp,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    text = "Avansuri, bilete, chirii, contracte sau plăți cerute rapid",
                    color = SigurColors.TextMuted,
                    fontSize = 13.sp,
                    lineHeight = 18.sp
                )
            }
            Icon(
                imageVector = Icons.Default.ChevronRight,
                contentDescription = null,
                tint = SigurColors.TextSubtle,
                modifier = Modifier.size(26.dp)
            )
        }
    }
}
