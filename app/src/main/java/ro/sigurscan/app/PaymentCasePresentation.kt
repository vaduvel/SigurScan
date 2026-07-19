package ro.sigurscan.app

import ro.sigurscan.app.ui.v2.components.ReasonSeverity
import ro.sigurscan.app.ui.v2.theme.VerdictTone

data class PaymentCasePresentation(
    val tone: VerdictTone,
    val badge: String,
    val title: String,
    val message: String,
)

fun paymentCasePresentation(response: PaymentCaseResponse): PaymentCasePresentation {
    val fallbackMessage = "Nu avem încă suficiente dovezi finale pentru această plată."
    return when (response.verdict.trim().uppercase()) {
        "SAFE" -> PaymentCasePresentation(
            tone = VerdictTone.SIGUR,
            badge = "SIGUR",
            title = if (response.artifactCount == 1) {
                "Documentul este în regulă"
            } else {
                "Documentele sunt coerente"
            },
            message = response.message?.takeIf(String::isNotBlank)
                ?: "Dovezile verificate nu se contrazic.",
        )
        "SUSPECT" -> PaymentCasePresentation(
            tone = VerdictTone.SUSPECT,
            badge = "SUSPECT",
            title = "Verifică înainte să plătești",
            message = response.message?.takeIf(String::isNotBlank)
                ?: "Am găsit informații care trebuie confirmate înainte de plată.",
        )
        "DANGEROUS" -> PaymentCasePresentation(
            tone = VerdictTone.PERICULOS,
            badge = "PERICULOS",
            title = "Nu continua plata",
            message = response.message?.takeIf(String::isNotBlank)
                ?: "Cel puțin o dovadă indică fraudă.",
        )
        else -> PaymentCasePresentation(
            tone = VerdictTone.NEVERIFICAT,
            badge = "NEVERIFICAT",
            title = "Nu avem destule dovezi",
            message = response.message?.takeIf(String::isNotBlank) ?: fallbackMessage,
        )
    }
}

internal fun paymentCaseReasonSeverity(tone: VerdictTone): ReasonSeverity = when (tone) {
    VerdictTone.SIGUR -> ReasonSeverity.GOOD
    VerdictTone.NEVERIFICAT -> ReasonSeverity.NEUTRAL
    VerdictTone.SUSPECT, VerdictTone.PERICULOS -> ReasonSeverity.ALERT
}

fun shouldPromptForMorePaymentEvidence(response: PaymentCaseResponse): Boolean =
    response.artifactCount == 1 && response.verdict.trim().uppercase() != "DANGEROUS"

fun paymentCaseEvidenceLabel(response: PaymentCaseResponse): String = when (response.artifactCount) {
    1 -> "1 dovadă verificată"
    else -> "${response.artifactCount} dovezi verificate"
}

internal fun paymentCaseArtifactRef(response: OrchestratedScanResponse): String? =
    response.result?.paymentCaseArtifactRef ?: response.paymentCaseArtifactRef

internal fun isCurrentPaymentCaseSession(
    capturedGeneration: Long,
    currentGeneration: Long,
    active: Boolean,
): Boolean = active && capturedGeneration == currentGeneration

internal fun nextPaymentCaseRetryRef(
    pendingRefs: Set<String>,
    attachedRefs: Set<String>,
): String? = pendingRefs.firstOrNull { it.isNotBlank() && it !in attachedRefs }

internal fun shouldUseCachedScanResult(forceRefresh: Boolean, paymentCaseActive: Boolean): Boolean =
    !forceRefresh && !paymentCaseActive
