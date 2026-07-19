package ro.sigurscan.app

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ReceiptLong
import androidx.compose.material.icons.automirrored.rounded.Rule
import androidx.compose.material.icons.rounded.Add
import androidx.compose.material.icons.rounded.AttachFile
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.Description
import androidx.compose.material.icons.rounded.Error
import androidx.compose.material.icons.rounded.HourglassTop
import androidx.compose.material.icons.rounded.Payments
import androidx.compose.material.icons.rounded.Warning
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import ro.sigurscan.app.ui.v2.components.CardOutlinedV2
import ro.sigurscan.app.ui.v2.components.PrimaryButtonV2
import ro.sigurscan.app.ui.v2.components.ReasonSeverity
import ro.sigurscan.app.ui.v2.components.SecondaryButtonV2
import ro.sigurscan.app.ui.v2.components.SubtleButtonV2
import ro.sigurscan.app.ui.v2.components.VerdictCardV2
import ro.sigurscan.app.ui.v2.components.VerdictReason
import ro.sigurscan.app.ui.v2.theme.SigurTokensV2
import ro.sigurscan.app.ui.v2.theme.TypeV2
import ro.sigurscan.app.ui.v2.theme.VerdictTone

@Composable
fun PaymentCaseResultCard(
    result: PaymentCaseResponse,
    loading: Boolean,
    status: String?,
    onAddOffer: () -> Unit,
    onAddFile: () -> Unit,
    onClose: () -> Unit,
) {
    val presentation = paymentCasePresentation(result)
    val palette = SigurTokensV2.palette(presentation.tone)
    val reasonSeverity = paymentCaseReasonSeverity(presentation.tone)
    val reasons = result.contradictions.mapNotNull { contradiction ->
        contradiction.message?.takeIf(String::isNotBlank)?.let {
            VerdictReason(it, ReasonSeverity.ALERT)
        }
    }.ifEmpty {
        listOf(
            VerdictReason(
                "Am verificat împreună ${paymentCaseEvidenceLabel(result).lowercase()}.",
                reasonSeverity,
            )
        )
    }

    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
        VerdictCardV2(
            tone = presentation.tone,
            badgeLabel = presentation.badge,
            title = presentation.title,
            subtitle = presentation.message,
            headerIcon = paymentCaseVerdictIcon(presentation.tone),
            reasons = reasons,
        )

        CardOutlinedV2(modifier = Modifier.fillMaxWidth()) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.AutoMirrored.Rounded.Rule, contentDescription = null, tint = palette.accent)
                Column(modifier = Modifier.padding(start = 10.dp)) {
                    Text("Dovezi verificate împreună", style = TypeV2.CardTitle, color = SigurTokensV2.Ink)
                    Text(
                        paymentCaseEvidenceLabel(result),
                        style = TypeV2.Body,
                        color = SigurTokensV2.Body,
                    )
                }
            }
            if (result.artifactTypes.isNotEmpty()) {
                Text(
                    result.artifactTypes.joinToString(" · ") { paymentCaseArtifactLabel(it) },
                    style = TypeV2.Body,
                    color = SigurTokensV2.Muted,
                    modifier = Modifier.padding(top = 10.dp),
                )
            }
            if (loading) {
                Row(
                    modifier = Modifier.padding(top = 12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(18.dp),
                        strokeWidth = 2.dp,
                        color = palette.accent,
                    )
                    Text(
                        status ?: "Actualizăm cazul...",
                        style = TypeV2.Body,
                        color = SigurTokensV2.Body,
                        modifier = Modifier.padding(start = 10.dp),
                    )
                }
            } else if (!status.isNullOrBlank()) {
                Text(status, style = TypeV2.Body, color = SigurTokensV2.Muted, modifier = Modifier.padding(top = 10.dp))
            }
        }

        if (shouldPromptForMorePaymentEvidence(result)) {
            CardOutlinedV2(modifier = Modifier.fillMaxWidth()) {
                Text("Mai ai și oferta, mesajul sau comanda?", style = TypeV2.CardTitle, color = SigurTokensV2.Ink)
                Text(
                    "Adaug-o ca să comparăm firma, suma, linkurile și destinația plății.",
                    style = TypeV2.Body,
                    color = SigurTokensV2.Body,
                    modifier = Modifier.padding(top = 5.dp),
                )
                Spacer(Modifier.height(12.dp))
                PrimaryButtonV2(
                    label = "Adaugă oferta sau comanda",
                    icon = Icons.Rounded.Description,
                    onClick = onAddOffer,
                )
                Spacer(Modifier.height(8.dp))
                SecondaryButtonV2(
                    label = "Adaugă email, PDF sau captură",
                    icon = Icons.Rounded.AttachFile,
                    accent = palette.accent,
                    onClick = onAddFile,
                )
            }
        } else {
            SecondaryButtonV2(
                label = "Adaugă altă dovadă",
                icon = Icons.Rounded.Add,
                accent = palette.accent,
                onClick = onAddFile,
            )
        }

        SubtleButtonV2(label = "Închide cazul", onClick = onClose)
    }
}

@Composable
fun PaymentCaseSetupCard(
    status: String?,
    loading: Boolean,
    canRetry: Boolean,
    onRetry: () -> Unit,
    onCaptureInvoice: () -> Unit,
    onPickInvoice: () -> Unit,
    onClose: () -> Unit,
) {
    CardOutlinedV2(modifier = Modifier.fillMaxWidth()) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(
                Icons.AutoMirrored.Rounded.ReceiptLong,
                contentDescription = null,
                tint = SigurTokensV2.FunctionSecondOpinion,
            )
            Text(
                "Verifică o plată",
                style = TypeV2.CardTitle,
                color = SigurTokensV2.Ink,
                modifier = Modifier.padding(start = 10.dp),
            )
        }
        Text(
            status ?: "Începe cu factura sau documentul care cere plata.",
            style = TypeV2.Body,
            color = SigurTokensV2.Body,
            modifier = Modifier.padding(top = 8.dp),
        )
        if (loading) {
            Row(modifier = Modifier.padding(top = 14.dp), verticalAlignment = Alignment.CenterVertically) {
                CircularProgressIndicator(modifier = Modifier.size(20.dp), strokeWidth = 2.dp)
                Text("Analizăm dovada...", style = TypeV2.Body, modifier = Modifier.padding(start = 10.dp))
            }
        } else if (canRetry) {
            Spacer(Modifier.height(14.dp))
            PrimaryButtonV2(
                label = "Reîncearcă actualizarea",
                icon = Icons.AutoMirrored.Rounded.Rule,
                onClick = onRetry,
            )
            Spacer(Modifier.height(8.dp))
            SecondaryButtonV2(
                label = "Alege alt document",
                icon = Icons.Rounded.AttachFile,
                accent = SigurTokensV2.FunctionSecondOpinion,
                onClick = onPickInvoice,
            )
        } else {
            Spacer(Modifier.height(14.dp))
            PrimaryButtonV2(
                label = "Fotografiază factura",
                icon = Icons.AutoMirrored.Rounded.ReceiptLong,
                onClick = onCaptureInvoice,
            )
            Spacer(Modifier.height(8.dp))
            SecondaryButtonV2(
                label = "Încarcă imagine sau PDF",
                icon = Icons.Rounded.AttachFile,
                accent = SigurTokensV2.FunctionSecondOpinion,
                onClick = onPickInvoice,
            )
        }
        Spacer(Modifier.height(8.dp))
        SubtleButtonV2(label = "Renunță", onClick = onClose)
    }
}

@Composable
fun PaymentCaseEntryRow(
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Row(
        modifier = modifier
            .clip(RoundedCornerShape(14.dp))
            .background(SigurTokensV2.FunctionSecondOpinion.copy(alpha = 0.10f))
            .clickable(role = Role.Button, onClick = onClick)
            .padding(horizontal = 14.dp, vertical = 13.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(
            Icons.Rounded.Payments,
            contentDescription = null,
            tint = SigurTokensV2.FunctionSecondOpinion,
            modifier = Modifier.size(24.dp),
        )
        Column(modifier = Modifier.padding(start = 12.dp).weight(1f)) {
            Text("Verifică o plată", style = TypeV2.CardTitle, color = SigurTokensV2.Ink)
            Text(
                "Compară factura cu oferta, emailul sau comanda",
                style = TypeV2.Body,
                color = SigurTokensV2.Body,
            )
        }
    }
}

private fun paymentCaseVerdictIcon(tone: VerdictTone): ImageVector = when (tone) {
    VerdictTone.SIGUR -> Icons.Rounded.CheckCircle
    VerdictTone.NEVERIFICAT -> Icons.Rounded.HourglassTop
    VerdictTone.SUSPECT -> Icons.Rounded.Warning
    VerdictTone.PERICULOS -> Icons.Rounded.Error
}

private fun paymentCaseArtifactLabel(type: String): String = when (type.trim().lowercase()) {
    "invoice" -> "factură"
    "email", "email_html", "eml" -> "email"
    "offer" -> "ofertă"
    "pdf", "pdf_ocr" -> "PDF"
    "image", "image_ocr" -> "captură"
    "url", "qr" -> "link/QR"
    "text" -> "mesaj"
    else -> "document"
}
