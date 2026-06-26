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
fun InvoiceResultCard(
    result: InvoiceScanResponse,
    sanbStatus: String? = null,
    onSanbAttestation: (String) -> Unit = {},
    onOfficialXmlCheck: (() -> Unit)? = null,
    onBack: () -> Unit
) {
    val isError = result.error != null
    val fraudFlags = result.fraudFlags.orEmpty()
    val reasonCodes = result.verdictGate?.reasonCodes.orEmpty()
    val invoiceTruth = result.invoiceTruth

    // FIX-10: one verdict in the app's vocabulary (Sigur / Neverificat / Suspect / Periculos),
    // derived from the engine signals — not the uniform verdict_gate label.
    val presentation = if (isError) null else invoiceVerdictPresentation(invoiceVerdict(result))
    val tone = if (isError) DSChipTone.Danger else presentation?.tone ?: DSChipTone.Pending
    val verdictText = if (isError) "Eroare" else presentation?.headline ?: "Verifică"

    Card(
        colors = CardDefaults.cardColors(containerColor = SigurColors.BackgroundCard),
        shape = RoundedCornerShape(16.dp),
        modifier = Modifier.fillMaxWidth().border(1.dp, SigurColors.GlassBorder, RoundedCornerShape(16.dp))
    ) {
        Column(modifier = Modifier.padding(20.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Receipt, contentDescription = null, tint = SigurColors.Brand, modifier = Modifier.size(24.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    "Scanare Factură",
                    fontWeight = FontWeight.Bold,
                    fontSize = 18.sp,
                    color = SigurColors.TextPrimary,
                    modifier = Modifier.weight(1f),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Spacer(modifier = Modifier.width(8.dp))
                DSChip(
                    verdictText,
                    tone = tone,
                    modifier = Modifier.widthIn(max = 210.dp)
                )
            }

            Spacer(modifier = Modifier.height(16.dp))

            Text(
                invoiceSourceLabel(result.officialDocumentCheck),
                fontSize = 12.sp,
                color = SigurColors.TextSecondary,
                lineHeight = 16.sp
            )
            result.officialDocumentCheck?.takeIf { it.provided && it.status == "mismatch" }?.let { check ->
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    "XML-ul oficial nu se potrivește cu factura scanată.",
                    fontWeight = FontWeight.Bold,
                    fontSize = 13.sp,
                    color = SigurColors.Dangerous
                )
                check.mismatches.take(2).forEach { mismatch ->
                    Text(
                        "• ${invoiceOfficialFieldLabel(mismatch.field)} diferă între factură și XML",
                        fontSize = 12.sp,
                        color = SigurColors.TextSecondary,
                        modifier = Modifier.padding(start = 8.dp, top = 3.dp)
                    )
                }
            }
            if (result.officialDocumentCheck?.provided != true && onOfficialXmlCheck != null && !isError) {
                Spacer(modifier = Modifier.height(10.dp))
                OutlinedButton(
                    onClick = onOfficialXmlCheck,
                    shape = RoundedCornerShape(10.dp),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Icon(Icons.Default.UploadFile, contentDescription = null, modifier = Modifier.size(18.dp))
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Ai XML-ul oficial de la ANAF? Verifică-l")
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            result.error?.let { err ->
                Text(err, color = SigurColors.Dangerous, fontSize = 14.sp)
                Spacer(modifier = Modifier.height(12.dp))
            }

            presentation?.let { p ->
                val accent = when (p.tone) {
                    DSChipTone.Danger -> SigurColors.Dangerous
                    DSChipTone.Suspect -> SigurColors.Suspect
                    DSChipTone.Safe -> SigurColors.Safe
                    else -> SigurColors.Pending
                }
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(12.dp))
                        .background(accent.copy(alpha = 0.12f))
                        .padding(14.dp)
                ) {
                    Text(p.headline, fontWeight = FontWeight.Bold, fontSize = 20.sp, color = accent)
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(p.action, color = SigurColors.TextPrimary, fontSize = 14.sp, lineHeight = 20.sp)
                }
                Spacer(modifier = Modifier.height(14.dp))
            }

            invoiceTruth?.hardConflicts?.takeIf { it.isNotEmpty() }?.let { items ->
                Text("Problemă găsită", fontWeight = FontWeight.Bold, fontSize = 13.sp, color = SigurColors.Dangerous)
                items.take(4).forEach { item ->
                    item.label?.takeIf { it.isNotBlank() }?.let { label ->
                        Text("• $label", fontSize = 12.sp, color = SigurColors.TextSecondary, modifier = Modifier.padding(start = 8.dp, top = 3.dp))
                    }
                }
                Spacer(modifier = Modifier.height(10.dp))
            }

            invoiceTruth?.verifiedItems?.takeIf { it.isNotEmpty() }?.let { items ->
                Text("Am verificat", fontWeight = FontWeight.Bold, fontSize = 13.sp, color = SigurColors.Safe)
                items.take(4).forEach { item ->
                    item.label?.takeIf { it.isNotBlank() }?.let { label ->
                        Text("• $label", fontSize = 12.sp, color = SigurColors.TextSecondary, modifier = Modifier.padding(start = 8.dp, top = 3.dp))
                    }
                }
                Spacer(modifier = Modifier.height(10.dp))
            }

            invoiceTruth?.unconfirmedItems?.takeIf { it.isNotEmpty() }?.let { items ->
                Text("Mai verifică", fontWeight = FontWeight.Bold, fontSize = 13.sp, color = SigurColors.Pending)
                items.take(4).forEach { item ->
                    item.label?.takeIf { it.isNotBlank() }?.let { label ->
                        Text("• $label", fontSize = 12.sp, color = SigurColors.TextSecondary, modifier = Modifier.padding(start = 8.dp, top = 3.dp))
                    }
                }
                Spacer(modifier = Modifier.height(10.dp))
            }

            invoiceTruth?.nextAction?.title?.takeIf { it.isNotBlank() }?.let { action ->
                InvoiceFieldRow("Următorul pas", action, tone)
                Spacer(modifier = Modifier.height(8.dp))
            }

            // SANB beneficiary check stays visible — it is the user's actionable next step.
            result.beneficiaryNameCheck?.takeIf { it.recommended }?.let { check ->
                InvoiceBeneficiaryNameCheck(check = check, onAttestation = onSanbAttestation)
            }
            sanbStatus?.takeIf { it.isNotBlank() }?.let { status ->
                Spacer(modifier = Modifier.height(10.dp))
                Text(status, fontSize = 12.sp, color = SigurColors.TextSecondary, lineHeight = 16.sp)
            }

            // Technical fields (IBAN, CUI, totals, raw signals) collapse under one toggle —
            // the verdict + decision above is all a non-technical user needs.
            var detailsExpanded by remember { mutableStateOf(false) }
            Spacer(modifier = Modifier.height(8.dp))
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clip(RoundedCornerShape(8.dp))
                    .clickable { detailsExpanded = !detailsExpanded }
                    .padding(vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    if (detailsExpanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore,
                    contentDescription = null,
                    tint = SigurColors.TextSecondary,
                    modifier = Modifier.size(20.dp)
                )
                Spacer(modifier = Modifier.width(4.dp))
                Text("Detalii tehnice (CUI, IBAN, sume)", fontSize = 13.sp, color = SigurColors.TextSecondary)
            }

            if (detailsExpanded) {
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
                f.paymentBeneficiary?.takeIf { it.isNotBlank() }?.let {
                    InvoiceFieldRow("Beneficiar plată", it)
                }
                f.allIbans
                    .filter { it.isNotBlank() }
                    .distinct()
                    .filter { it != f.iban }
                    .takeIf { it.isNotEmpty() }
                    ?.let { ibans ->
                        InvoiceFieldRow("Alte IBAN-uri", ibans.joinToString(" · "))
                    }
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

            result.verdictGate?.let { gate ->
                Spacer(modifier = Modifier.height(8.dp))
                InvoiceFieldRow(
                    "Verdict final",
                    listOfNotNull(verdictText, gate.riskScore?.let { "$it/100" }).joinToString(" · "),
                    tone
                )
            }

            result.paymentDestination?.let { destination ->
                Spacer(modifier = Modifier.height(8.dp))
                val destinationTone = when {
                    destination.canContributeToSafe == true -> DSChipTone.Safe
                    destination.brandMatches == false || destination.ibanMatches == false -> DSChipTone.Danger
                    destination.matched == false -> DSChipTone.Pending
                    else -> DSChipTone.Neutral
                }
                val destinationLabel = when {
                    !destination.display.isNullOrBlank() -> destination.display
                    destination.canContributeToSafe == true -> "confirmată"
                    destination.brandMatches == false -> "nu corespunde brandului"
                    destination.ibanMatches == false -> "IBAN diferit"
                    destination.matched == false -> "neconfirmată public"
                    else -> destination.matchReason ?: "verificată parțial"
                }
                InvoiceFieldRow("Destinație plată", destinationLabel, destinationTone)
                destination.trustTier?.takeIf { it.isNotBlank() }?.let {
                    InvoiceFieldRow("Nivel dovadă", invoicePaymentTrustTierLabel(it))
                }
                destination.ibanMaskedForClient?.takeIf { it.isNotBlank() }?.let {
                    InvoiceFieldRow("IBAN verificat", it)
                }
                destination.matchedEntity?.takeIf { it.isNotBlank() }?.let {
                    InvoiceFieldRow("Entitate găsită", it)
                }
                destination.brandId?.takeIf { it.isNotBlank() && destination.matchedEntity.isNullOrBlank() }?.let {
                    InvoiceFieldRow("Entitate găsită", it.replace("_", " "))
                }
                destination.reasons.take(2).forEach { reason ->
                    Text("• $reason", fontSize = 12.sp, color = SigurColors.TextSecondary, modifier = Modifier.padding(start = 8.dp, top = 4.dp))
                }
            }

            result.iban?.let { iban ->
                if (iban.valid != null) {
                    Spacer(modifier = Modifier.height(8.dp))
                    InvoiceFieldRow("IBAN valid", if (iban.valid) "Da" else "Nu")
                    iban.bank?.let { InvoiceFieldRow("Bancă", it) }
                }
            }

            result.officialDocumentCheck?.takeIf { it.provided }?.let { check ->
                Spacer(modifier = Modifier.height(12.dp))
                val xmlTone = when (check.status) {
                    "match" -> DSChipTone.Safe
                    "mismatch" -> DSChipTone.Danger
                    "parse_error" -> DSChipTone.Suspect
                    else -> DSChipTone.Pending
                }
                val xmlLabel = when (check.status) {
                    "match" -> "se potrivește"
                    "mismatch" -> "contrazice factura"
                    "parse_error" -> "XML invalid"
                    else -> "neverificat"
                }
                InvoiceFieldRow("Document oficial", xmlLabel, xmlTone)
                check.mismatches.take(3).forEach { mismatch ->
                    val fieldLabel = invoiceOfficialFieldLabel(mismatch.field)
                    Text(
                        "• $fieldLabel diferă între factură și XML",
                        fontSize = 12.sp,
                        color = SigurColors.TextSecondary,
                        modifier = Modifier.padding(start = 8.dp, top = 4.dp)
                    )
                }
                check.error?.takeIf { it.isNotBlank() }?.let { error ->
                    Text("• $error", fontSize = 12.sp, color = SigurColors.TextSecondary, modifier = Modifier.padding(start = 8.dp, top = 4.dp))
                }
            }

            fraudFlags.takeIf { it.isNotEmpty() }?.let { flags ->
                Spacer(modifier = Modifier.height(12.dp))
                Text("Semnale detectate:", fontWeight = FontWeight.Bold, fontSize = 13.sp, color = SigurColors.Suspect)
                flags.take(5).forEach { flag ->
                    Text("• ${invoiceSignalLabel(flag)}", fontSize = 12.sp, color = SigurColors.TextSecondary, modifier = Modifier.padding(start = 8.dp, top = 4.dp))
                }
            }

            reasonCodes.takeIf { it.isNotEmpty() }?.let { reasons ->
                Spacer(modifier = Modifier.height(12.dp))
                Text("Motive verdict:", fontWeight = FontWeight.Bold, fontSize = 13.sp, color = SigurColors.TextSecondary)
                reasons.take(3).forEach { reason ->
                    Text("• ${invoiceReasonLabel(reason)}", fontSize = 12.sp, color = SigurColors.TextSecondary, modifier = Modifier.padding(start = 8.dp, top = 4.dp))
                }
            }

            result.warnings?.takeIf { it.isNotEmpty() }?.let { warnings ->
                Spacer(modifier = Modifier.height(12.dp))
                Text("Avertismente:", fontWeight = FontWeight.Bold, fontSize = 13.sp, color = SigurColors.Suspect)
                warnings.forEach { w ->
                    Text("• $w", fontSize = 12.sp, color = SigurColors.TextSecondary, modifier = Modifier.padding(start = 8.dp, top = 4.dp))
                }
            }
            } // end Detalii tehnice (collapsible)

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

internal fun invoiceSignalLabel(code: String): String = when (code) {
    "REPORTED_FRAUD_IBAN" -> "IBAN raportat în fraude"
    "PAYMENT_DESTINATION_BRAND_MISMATCH" -> "Destinația plății nu corespunde brandului"
    "UNKNOWN_PAYMENT_DESTINATION" -> "IBAN-ul nu este confirmat ca destinație oficială"
    "BENEFICIARY_PERSON_MISMATCH" -> "Beneficiar persoană fizică pentru emitent firmă"
    "FOREIGN_IBAN" -> "IBAN străin pentru o factură locală"
    "ACCOUNT_CHANGE_LANGUAGE" -> "Text de schimbare cont bancar"
    "PAYMENT_PRESSURE" -> "Presiune de plată rapidă"
    "MULTIPLE_IBANS" -> "Mai multe IBAN-uri în document"
    "OSIM_TRADEMARK_FEE_UNOFFICIAL_SENDER" -> "Taxă marcă/OSIM de la expeditor neoficial"
    "OFFICIAL_REGISTRY_CLAIM_BUT_NO_PROVENANCE" -> "Pretinde registru oficial fără proveniență"
    "URGENT_PAYMENT_OVERRIDE_NO_TICKET" -> "Plată urgentă fără comandă/tichet intern"
    "LEGAL_DEMAND_PAYMENT_TO_NEW_IBAN" -> "Cerere legală/plată către IBAN nou"
    "DOMAIN_RENEWAL_INVOICE_NO_EXISTING_VENDOR" -> "Factură domeniu/hosting de la furnizor necunoscut"
    "SAAS_LICENSE_AUDIT_URGENT_PAYMENT" -> "Audit licențe/SaaS cu plată urgentă"
    "PO_OR_OVERPAYMENT_RETURN_REQUEST" -> "PO/supraplată cu cerere de returnare"
    "PAYROLL_OR_EMPLOYEE_DATA_REQUEST_VIA_INVOICE_THREAD" -> "Cerere date angajați în fir de factură"
    "NEW_VENDOR_PUBLIC_PROCUREMENT_FEE" -> "Taxă achiziție publică/furnizor nou"
    "EFACTURA_OFFICIAL_DOCUMENT_MISMATCH" -> "Factura diferă de XML-ul oficial atașat"
    else -> code.replace('_', ' ').lowercase(Locale.getDefault()).replaceFirstChar { it.titlecase(Locale.getDefault()) }
}

internal fun invoiceOfficialFieldLabel(code: String?): String = when (code) {
    "cui" -> "CUI-ul"
    "iban" -> "IBAN-ul"
    "total" -> "Totalul"
    "nr_factura" -> "Numărul facturii"
    "data_emitere" -> "Data emiterii"
    "scadenta" -> "Scadența"
    else -> code?.replace('_', ' ') ?: "Câmpul"
}

internal fun invoicePaymentTrustTierLabel(code: String): String = when (code) {
    "T0_PARTNER_SIGNED" -> "partener confirmat"
    "T1_PUBLIC_OFFICIAL" -> "sursă oficială publică"
    "T2_OFFICIAL_DOCUMENT_CHAIN" -> "document oficial atașat"
    "T3_LOCAL_VENDOR_MEMORY" -> "istoric furnizor confirmat"
    "T4_STRUCTURALLY_VALID_UNKNOWN" -> "valid structural, neconfirmat"
    "ambiguous_shared_destination" -> "destinație ambiguă"
    else -> code.replace('_', ' ').lowercase(Locale.getDefault()).replaceFirstChar { it.titlecase(Locale.getDefault()) }
}

internal fun invoiceReasonLabel(code: String): String = when (code) {
    "value_request_needs_verification" -> "Plata trebuie verificată înainte de transfer"
    "semantic_high_risk_match" -> "Textul seamănă cu un tipar cunoscut de fraudă"
    "positive_provenance_clean" -> "Proveniență pozitivă și semnale curate"
    "provider_malicious" -> "Provider extern a raportat risc"
    "provider_suspicious" -> "Provider extern a raportat suspiciuni"
    else -> code.replace('_', ' ').lowercase(Locale.getDefault()).replaceFirstChar { it.titlecase(Locale.getDefault()) }
}
