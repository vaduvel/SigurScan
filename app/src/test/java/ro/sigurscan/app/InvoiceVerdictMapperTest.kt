package ro.sigurscan.app

import com.google.gson.Gson
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Golden test for FIX-10: invoice signals -> one of the app's four verdicts
 * (Sigur / Neverificat / Suspect / Periculos) — same vocabulary as every other scan.
 *
 * F1..F5 fixtures are REAL responses captured in-process from the production invoice
 * engine (origin/main ed1445d) on the gauntlet PDFs — not hand-authored. The two
 * synthetic boundary cases (atlas-confirmed Sigur, legit-cession Periculos boundary)
 * are contract-sanctioned.
 *
 * Display-layer only: never re-judges the engine, only transposes its signals.
 */
class InvoiceVerdictMapperTest {

    private fun fixture(name: String): InvoiceScanResponse {
        val path = "fixtures/invoice/$name"
        val stream = requireNotNull(javaClass.classLoader?.getResourceAsStream(path)) {
            "Missing test fixture: $path"
        }
        return stream.bufferedReader().use {
            Gson().fromJson(it.readText(), InvoiceScanResponse::class.java)
        }
    }

    private fun fromJson(json: String): InvoiceScanResponse =
        Gson().fromJson(json.trimIndent(), InvoiceScanResponse::class.java)

    // ---- Real captures, labeled by ground truth ----

    @Test
    fun f1LegitInvoiceMapsToNeverificat() {
        // Everything verifiable is clean; only the IBAN owner is unconfirmed.
        // IBAN principle: this stays Neverificat — it must NOT drop to Suspect.
        assertEquals(InvoiceVerdict.NEVERIFICAT, invoiceVerdict(fixture("F1_real.json")).verdict)
    }

    @Test
    fun f2BecIbanSwapMapsToPericulos() {
        // primary_reason_code = CHANGED_IBAN_OR_CHANNEL, beneficiary TECH SOLUTIONS != emitent MGH
        assertEquals(InvoiceVerdict.PERICULOS, invoiceVerdict(fixture("F2_real.json")).verdict)
    }

    @Test
    fun f3BrandImpersonationMapsToPericulos() {
        // impersonation_risk = true, primary_reason_code = HIGH_RISK_PAYMENT_PATTERN_REQUIRES_VERIFICATION
        assertEquals(InvoiceVerdict.PERICULOS, invoiceVerdict(fixture("F3_real.json")).verdict)
    }

    @Test
    fun f4IncoherentTotalsMapsToSuspect() {
        // coherence.all_ok = false — a real bad verifiable signal, no fraud-grade flag
        assertEquals(InvoiceVerdict.SUSPECT, invoiceVerdict(fixture("F4_real.json")).verdict)
    }

    @Test
    fun f5MissingIbanMapsToSuspect() {
        // no IBAN + CUI not found in ANAF — a real bad verifiable signal, no fraud-grade flag
        assertEquals(InvoiceVerdict.SUSPECT, invoiceVerdict(fixture("F5_real.json")).verdict)
    }

    // ---- Anti-false-positive boundaries ----

    @Test
    fun f1SoftHighValueFlagAndLegalFormPunctuationDoNotEscalate() {
        // F1 carries HIGH_VALUE_UNCONFIRMED_PAYMENT_DESTINATION (soft) and the beneficiary
        // "...S.R.L" differs from emitent "...S.R.L." only by a trailing period.
        // Neither may push a clean legit invoice to Suspect or Periculos.
        assertEquals(InvoiceVerdict.NEVERIFICAT, invoiceVerdict(fixture("F1_real.json")).verdict)
    }

    // ---- Synthetic boundary cases (contract-sanctioned) ----

    @Test
    fun atlasConfirmedSafeToPayMapsToSigur() {
        val r = invoiceVerdict(
            fromJson(
                """
                {
                  "fields": {"emitent": "GROUPAMA ASIGURARI SA", "payment_beneficiary": "GROUPAMA ASIGURARI SA",
                             "iban": "RO49AAAA1B31007593840000"},
                  "coherence": {"totals_match": true, "tva_rate_plausible": true, "dates_plausible": true, "all_ok": true},
                  "payment_destination": {"matched": true, "trust_tier": "T1_PUBLIC_OFFICIAL", "can_contribute_to_safe": true},
                  "invoice_truth": {"verdict": "VERIFY_BEFORE_PAYING", "safe_to_pay": true,
                                    "primary_reason_code": "DESTINATION_CONFIRMED", "hard_conflicts": []}
                }
                """
            )
        )
        assertEquals(InvoiceVerdict.SIGUR, r.verdict)
    }

    @Test
    fun legitCessionBeneficiaryMismatchStaysPericulos() {
        // Rare-but-legal factoring: payment beneficiary (factoring house) != issuer.
        // Stays Periculos; the cession escape hatch lives in copy, not in the verdict.
        val r = invoiceVerdict(
            fromJson(
                """
                {
                  "fields": {"emitent": "ALFA PRODUCTION SRL", "payment_beneficiary": "OMRO IFN SA",
                             "iban": "RO12BTRL0000111122223333"},
                  "coherence": {"totals_match": true, "tva_rate_plausible": true, "dates_plausible": true, "all_ok": true},
                  "invoice_truth": {"verdict": "VERIFY_BEFORE_PAYING", "safe_to_pay": false,
                                    "primary_reason_code": "UNCONFIRMED_DESTINATION", "hard_conflicts": []}
                }
                """
            )
        )
        assertEquals(InvoiceVerdict.PERICULOS, r.verdict)
        assertTrue(r.beneficiaryMismatch)
    }

    @Test
    fun safeToPayTrueWithBeneficiaryMismatchStaysSigur() {
        // Engine confirmed the destination (e.g. legit factoring in atlas): beneficiary != issuer,
        // BUT safe_to_pay=true and no hard trigger. The display layer must not override the engine —
        // only a hard fraud trigger may win over a confirmed safe_to_pay.
        val r = invoiceVerdict(
            fromJson(
                """
                {
                  "fields": {"emitent": "ALFA DISTRIB SRL", "payment_beneficiary": "OMEGA FACTORING IFN SA",
                             "iban": "RO17BTRL0000456789012345"},
                  "coherence": {"totals_match": true, "tva_rate_plausible": true, "dates_plausible": true, "all_ok": true},
                  "invoice_truth": {"verdict": "VERIFY_BEFORE_PAYING", "safe_to_pay": true,
                                    "primary_reason_code": "UNCONFIRMED_DESTINATION", "hard_conflicts": []}
                }
                """
            )
        )
        assertEquals(InvoiceVerdict.SIGUR, r.verdict)
        assertEquals(
            "Poți plăti. Pentru siguranță, confirmă și în SANB.",
            invoiceVerdictPresentation(r).action,
        )
    }

    @Test
    fun beneficiaryWithoutLegalFormSuffixIsNotAMismatch() {
        // "ALFA DISTRIB" (beneficiary) vs "ALFA DISTRIB SRL" (emitent): same entity, legal form omitted.
        // Must not be read as beneficiary != emitent -> stays Neverificat, not Periculos.
        val r = invoiceVerdict(
            fromJson(
                """
                {
                  "fields": {"emitent": "ALFA DISTRIB SRL", "payment_beneficiary": "ALFA DISTRIB",
                             "iban": "RO17BTRL0000456789012345"},
                  "coherence": {"totals_match": true, "tva_rate_plausible": true, "dates_plausible": true, "all_ok": true},
                  "invoice_truth": {"verdict": "VERIFY_BEFORE_PAYING", "safe_to_pay": false,
                                    "primary_reason_code": "UNCONFIRMED_DESTINATION", "hard_conflicts": []}
                }
                """
            )
        )
        assertEquals(InvoiceVerdict.NEVERIFICAT, r.verdict)
    }

    @Test
    fun beneficiaryWithoutLegalFormSuffixAndPunctuationIsNotAMismatch() {
        val r = invoiceVerdict(
            fromJson(
                """
                {
                  "fields": {"emitent": "Electrica S.A.", "payment_beneficiary": "Electrica",
                             "iban": "RO17BTRL0000456789012345"},
                  "coherence": {"totals_match": true, "tva_rate_plausible": true, "dates_plausible": true, "all_ok": true},
                  "invoice_truth": {"verdict": "VERIFY_BEFORE_PAYING", "safe_to_pay": false,
                                    "primary_reason_code": "UNCONFIRMED_DESTINATION", "hard_conflicts": []}
                }
                """
            )
        )
        assertEquals(InvoiceVerdict.NEVERIFICAT, r.verdict)
        assertFalse(r.beneficiaryMismatch)
    }

    @Test
    fun beneficiaryWithExtraSignificantWordsIsAMismatch() {
        val r = invoiceVerdict(
            fromJson(
                """
                {
                  "fields": {"emitent": "Electrica SA", "payment_beneficiary": "Global Electrica Trading SRL",
                             "iban": "RO17BTRL0000456789012345"},
                  "coherence": {"totals_match": true, "tva_rate_plausible": true, "dates_plausible": true, "all_ok": true},
                  "invoice_truth": {"verdict": "VERIFY_BEFORE_PAYING", "safe_to_pay": false,
                                    "primary_reason_code": "UNCONFIRMED_DESTINATION", "hard_conflicts": []}
                }
                """
            )
        )
        assertEquals(InvoiceVerdict.PERICULOS, r.verdict)
        assertTrue(r.beneficiaryMismatch)

        val p = invoiceVerdictPresentation(r)
        assertEquals("Periculos", p.headline)
        assertTrue(p.action.lowercase().contains("cesiune"))
    }

    @Test
    fun beneficiaryContainingShortIssuerNameWithExtraSignificantWordsIsAMismatch() {
        val r = invoiceVerdict(
            fromJson(
                """
                {
                  "fields": {"emitent": "Electrica", "payment_beneficiary": "Global Electrica Trading SRL",
                             "iban": "RO17BTRL0000456789012345"},
                  "coherence": {"totals_match": true, "tva_rate_plausible": true, "dates_plausible": true, "all_ok": true},
                  "invoice_truth": {"verdict": "VERIFY_BEFORE_PAYING", "safe_to_pay": false,
                                    "primary_reason_code": "UNCONFIRMED_DESTINATION", "hard_conflicts": []}
                }
                """
            )
        )
        assertEquals(InvoiceVerdict.PERICULOS, r.verdict)
        assertTrue(r.beneficiaryMismatch)
    }

    // ---- Presentation: app verdict word as headline + locked decision copy ----

    @Test
    fun sigurPresentsSigurHeadlineAndCanPayCopyInSafeTone() {
        val p = invoiceVerdictPresentation(
            InvoiceVerdictResult(InvoiceVerdict.SIGUR, beneficiaryMismatch = false)
        )
        assertEquals("Sigur", p.headline)
        assertEquals(DSChipTone.Safe, p.tone)
        assertTrue(p.action.contains("Poți plăti"))
    }

    @Test
    fun neverificatPresentsNeverificatHeadlineAndConfirmIbanCopyInPendingTone() {
        val p = invoiceVerdictPresentation(
            InvoiceVerdictResult(InvoiceVerdict.NEVERIFICAT, beneficiaryMismatch = false)
        )
        assertEquals("Neverificat", p.headline)
        assertEquals(DSChipTone.Pending, p.tone)
        assertTrue(p.action.contains("SANB"))
    }

    @Test
    fun suspectPresentsSuspectHeadlineAndDoNotPayYetCopyInSuspectTone() {
        val p = invoiceVerdictPresentation(
            InvoiceVerdictResult(InvoiceVerdict.SUSPECT, beneficiaryMismatch = false)
        )
        assertEquals("Suspect", p.headline)
        assertEquals(DSChipTone.Suspect, p.tone)
        assertTrue(p.action.contains("Nu plăti încă"))
    }

    @Test
    fun periculosPresentsPericulosHeadlineAndCallSupplierCopyInDangerTone() {
        val p = invoiceVerdictPresentation(
            InvoiceVerdictResult(InvoiceVerdict.PERICULOS, beneficiaryMismatch = false)
        )
        assertEquals("Periculos", p.headline)
        assertEquals(DSChipTone.Danger, p.tone)
        assertTrue(p.action.contains("sună furnizorul"))
    }

    @Test
    fun periculosFromBeneficiaryMismatchAddsCessionDoorToCopyOnly() {
        val p = invoiceVerdictPresentation(
            InvoiceVerdictResult(InvoiceVerdict.PERICULOS, beneficiaryMismatch = true)
        )
        assertEquals("Periculos", p.headline) // cession never changes the verdict word
        assertTrue(p.action.lowercase().contains("cesiune"))
    }

    // ---- FIX-9a: XML-ul oficial devine opt-in post-result, nu dialog forțat pre-scan ----

    @Test
    fun sourceLabelWithoutOfficialXmlSaysScannedDocument() {
        assertEquals("Sursă: document scanat", invoiceSourceLabel(null))
        assertEquals(
            "Sursă: document scanat",
            invoiceSourceLabel(OfficialDocumentCheckResponse(provided = false)),
        )
    }

    @Test
    fun sourceLabelWithMatchingOfficialXmlSaysVerified() {
        assertEquals(
            "Sursă: document scanat + XML oficial verificat",
            invoiceSourceLabel(OfficialDocumentCheckResponse(provided = true, status = "match")),
        )
    }

    @Test
    fun sourceLabelWithMismatchOfficialXmlFlagsDivergence() {
        val label = invoiceSourceLabel(OfficialDocumentCheckResponse(provided = true, status = "mismatch"))
        assertTrue(label.lowercase().contains("nu se potrivește"))
    }
}
