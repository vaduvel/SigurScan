package ro.sigurscan.app

import java.util.Locale

/**
 * FIX-10 — invoice signals -> one of the app's four verdicts, for the result card.
 *
 * The invoice card answers one question: should the user pay or not? It speaks the
 * same four words as every other scan — Sigur / Neverificat / Suspect / Periculos —
 * so the verdict is consistent across the app.
 *
 * Display-layer only: this never re-judges the engine, it transposes the signals the
 * engine already produced (invoice_truth + fraud collapse + brand_match + coherence +
 * beneficiary) into the verdict + a single decision instruction.
 *
 * Periculos keys on the engine's *collapsed* fraud signals (hard_conflicts +
 * primary_reason_code + impersonation_risk), not on a hardcoded subset of fraud_flags —
 * so a newly added fraud-grade flag escalates automatically via the engine.
 *
 * IBAN principle: not being able to confirm the IBAN owner is NOT a bad signal. When
 * everything verifiable is clean and only the IBAN is unconfirmed, the verdict is
 * Neverificat — it must never drop to Suspect on that account alone.
 */
enum class InvoiceVerdict { SIGUR, NEVERIFICAT, SUSPECT, PERICULOS }

data class InvoiceVerdictResult(
    val verdict: InvoiceVerdict,
    /** Periculos was (also) reached because payment beneficiary != issuer — copy adds the cession caveat. */
    val beneficiaryMismatch: Boolean,
)

/** primary_reason_code values the engine uses for the two fraud-grade pattern families. */
private val STOP_REASON_CODES = setOf(
    "CHANGED_IBAN_OR_CHANNEL",
    "HIGH_RISK_PAYMENT_PATTERN_REQUIRES_VERIFICATION",
)

private fun normalizeEntity(value: String?): String =
    value?.uppercase(Locale.ROOT)?.replace(Regex("[^A-Z0-9]"), "").orEmpty()

/**
 * True only when the payment beneficiary is a genuinely different entity than the issuer.
 * Tolerates punctuation and omitted legal-form suffixes ("ALFA" vs "ALFA S.R.L.") so a clean
 * invoice is never flagged on cosmetics alone.
 */
internal fun invoiceBeneficiaryMismatch(fields: InvoiceFieldsResponse?): Boolean {
    val emitent = normalizeEntity(fields?.emitent)
    val beneficiary = normalizeEntity(fields?.paymentBeneficiary)
    if (emitent.isBlank() || beneficiary.isBlank()) return false
    if (emitent == beneficiary) return false
    if (emitent.contains(beneficiary) || beneficiary.contains(emitent)) return false
    return true
}

private fun anafCheckedNotFound(anaf: Map<String, Any>?): Boolean {
    if (anaf == null) return false
    val checked = anaf["checked"] as? Boolean ?: false
    val exists = anaf["exists"] as? Boolean ?: true
    return checked && !exists
}

private fun ibanMissingOrInvalid(result: InvoiceScanResponse): Boolean {
    if (result.fields?.iban?.trim().isNullOrBlank()) return true
    return result.iban?.valid == false
}

fun invoiceVerdict(result: InvoiceScanResponse): InvoiceVerdictResult {
    val truth = result.invoiceTruth
    val beneficiaryMismatch = invoiceBeneficiaryMismatch(result.fields)

    // 1) Periculos (hard) — fraud-grade triggers win over everything, even a confirmed safe_to_pay.
    val hardPericulos = (truth?.hardConflicts?.isNotEmpty() == true) ||
        ((truth?.primaryReasonCode ?: "") in STOP_REASON_CODES) ||
        (result.brandMatch?.impersonationRisk == true)
    if (hardPericulos) {
        return InvoiceVerdictResult(InvoiceVerdict.PERICULOS, beneficiaryMismatch = beneficiaryMismatch)
    }

    // 2) Sigur — the engine confirmed the destination (atlas/SANB + name match). A confirmed
    //    safe_to_pay wins over a bare beneficiary name mismatch (e.g. legit factoring in atlas).
    if (truth?.safeToPay == true) {
        return InvoiceVerdictResult(InvoiceVerdict.SIGUR, beneficiaryMismatch = false)
    }

    // 3) Periculos (beneficiary) — beneficiary != issuer escalates only when not confirmed safe.
    if (beneficiaryMismatch) {
        return InvoiceVerdictResult(InvoiceVerdict.PERICULOS, beneficiaryMismatch = true)
    }

    // 4) Suspect — a real bad verifiable signal, not merely an unconfirmed IBAN.
    val suspect = (result.coherence?.allOk == false) ||
        ibanMissingOrInvalid(result) ||
        anafCheckedNotFound(result.anaf)
    if (suspect) {
        return InvoiceVerdictResult(InvoiceVerdict.SUSPECT, beneficiaryMismatch = false)
    }

    // 5) Neverificat — everything verifiable is clean; only the IBAN owner is unconfirmed.
    return InvoiceVerdictResult(InvoiceVerdict.NEVERIFICAT, beneficiaryMismatch = false)
}

/** App verdict word as headline + the single pay/don't-pay instruction + chip tone. */
data class InvoiceVerdictPresentation(
    val headline: String,
    val action: String,
    val tone: DSChipTone,
)

private const val CESSION_DOOR =
    " Dacă ai un acord de cesiune/factoring, confirmă-l cu furnizorul pe un număr cunoscut."

fun invoiceVerdictPresentation(result: InvoiceVerdictResult): InvoiceVerdictPresentation = when (result.verdict) {
    InvoiceVerdict.SIGUR -> InvoiceVerdictPresentation(
        headline = "Sigur",
        action = "Poți plăti. Pentru siguranță, confirmă și în SANB.",
        tone = DSChipTone.Safe,
    )
    InvoiceVerdict.NEVERIFICAT -> InvoiceVerdictPresentation(
        headline = "Neverificat",
        action = "Firma e reală, dar n-am putut confirma contul — verifică IBAN-ul în SANB înainte să plătești.",
        tone = DSChipTone.Pending,
    )
    InvoiceVerdict.SUSPECT -> InvoiceVerdictPresentation(
        headline = "Suspect",
        action = "Nu plăti încă — verifică în SANB înainte să plătești.",
        tone = DSChipTone.Suspect,
    )
    InvoiceVerdict.PERICULOS -> {
        val base = "Nu plăti — sună furnizorul pe un număr cunoscut."
        InvoiceVerdictPresentation(
            headline = "Periculos",
            action = if (result.beneficiaryMismatch) base + CESSION_DOOR else base,
            tone = DSChipTone.Danger,
        )
    }
}

fun invoiceSourceLabel(check: OfficialDocumentCheckResponse?): String = when {
    check?.provided != true -> "Sursă: document scanat"
    check.status == "match" -> "Sursă: document scanat + XML oficial verificat"
    check.status == "mismatch" -> "Sursă: document scanat + XML oficial nu se potrivește"
    check.status == "parse_error" -> "Sursă: document scanat + XML oficial ilizibil"
    else -> "Sursă: document scanat + XML oficial primit"
}
