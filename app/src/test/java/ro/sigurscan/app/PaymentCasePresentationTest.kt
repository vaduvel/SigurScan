package ro.sigurscan.app

import com.google.gson.Gson
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import ro.sigurscan.app.ui.v2.components.ReasonSeverity
import ro.sigurscan.app.ui.v2.theme.VerdictTone

class PaymentCasePresentationTest {
    @Test
    fun backendDangerousVerdictIsRenderedAsStopPaymentWithoutLocalReclassification() {
        val response = PaymentCaseResponse(
            caseId = "pc-1",
            artifactCount = 2,
            artifactTypes = listOf("invoice", "email"),
            verdict = "DANGEROUS",
            reasonCodes = listOf("cross_artifact_payment_destination_changed"),
            message = "Mesajul schimbă contul de plată față de document.",
        )

        val presentation = paymentCasePresentation(response)

        assertEquals(VerdictTone.PERICULOS, presentation.tone)
        assertEquals("Nu continua plata", presentation.title)
        assertEquals(response.message, presentation.message)
    }

    @Test
    fun oneFinalArtifactPromptsForTheCompanionMessageOrOffer() {
        val response = PaymentCaseResponse(
            caseId = "pc-2",
            artifactCount = 1,
            artifactTypes = listOf("invoice"),
            verdict = "UNVERIFIED",
            message = "Nu avem încă suficiente dovezi.",
        )

        assertTrue(shouldPromptForMorePaymentEvidence(response))
        assertEquals("1 dovadă verificată", paymentCaseEvidenceLabel(response))
    }

    @Test
    fun dangerousArtifactKeepsStopPaymentAsThePrimaryAction() {
        val response = PaymentCaseResponse(
            caseId = "pc-danger-one",
            artifactCount = 1,
            artifactTypes = listOf("email"),
            verdict = "DANGEROUS",
        )

        assertFalse(shouldPromptForMorePaymentEvidence(response))
    }

    @Test
    fun oneSafeArtifactUsesClearSingularCopy() {
        val response = PaymentCaseResponse(
            caseId = "pc-safe-one",
            artifactCount = 1,
            artifactTypes = listOf("invoice"),
            verdict = "SAFE",
        )

        assertEquals("Documentul este în regulă", paymentCasePresentation(response).title)
    }

    @Test
    fun neverificatEvidenceIsPresentedNeutrallyInsteadOfAsAnAlert() {
        assertEquals(ReasonSeverity.NEUTRAL, paymentCaseReasonSeverity(VerdictTone.NEVERIFICAT))
        assertEquals(ReasonSeverity.ALERT, paymentCaseReasonSeverity(VerdictTone.SUSPECT))
        assertEquals(ReasonSeverity.ALERT, paymentCaseReasonSeverity(VerdictTone.PERICULOS))
    }

    @Test
    fun multipleArtifactsProduceOneCaseResultAndNoFurtherMandatoryPrompt() {
        val response = PaymentCaseResponse(
            caseId = "pc-3",
            artifactCount = 2,
            artifactTypes = listOf("invoice", "email"),
            verdict = "SAFE",
            message = "Documentele verificate sunt coerente.",
        )

        assertFalse(shouldPromptForMorePaymentEvidence(response))
        assertEquals("2 dovezi verificate", paymentCaseEvidenceLabel(response))
        assertEquals(VerdictTone.SIGUR, paymentCasePresentation(response).tone)
    }

    @Test
    fun unknownBackendLabelFailsClosedAsNeverificat() {
        val response = PaymentCaseResponse(
            caseId = "pc-4",
            artifactCount = 1,
            verdict = "NEW_BACKEND_LABEL",
            message = "Rezultat nou.",
        )

        val presentation = paymentCasePresentation(response)

        assertEquals(VerdictTone.NEVERIFICAT, presentation.tone)
        assertEquals("Nu avem destule dovezi", presentation.title)
    }

    @Test
    fun orchestratedArtifactReferenceIsReadFromTheFinalResultPayload() {
        val response = Gson().fromJson(
            """
            {
              "scan_id": "orch-1",
              "status": "complete",
              "result": {
                "scan_id": "orch-1",
                "risk_score": 55,
                "risk_level": "medium",
                "is_final": true,
                "payment_case_artifact_ref": "pc-art-final"
              }
            }
            """.trimIndent(),
            OrchestratedScanResponse::class.java,
        )

        assertEquals("pc-art-final", paymentCaseArtifactRef(response))
    }

    @Test
    fun legacyTopLevelArtifactReferenceRemainsCompatible() {
        val response = OrchestratedScanResponse(
            scanId = "orch-2",
            status = "complete",
            paymentCaseArtifactRef = "pc-art-legacy",
        )

        assertEquals("pc-art-legacy", paymentCaseArtifactRef(response))
    }

    @Test
    fun orchestratedRequestExplicitlyScopesPaymentCasePersistence() {
        val json = Gson().toJson(
            OrchestratedScanRequest(
                inputType = "offer",
                text = "Cerere de plată",
                paymentCaseActive = true,
            )
        )

        assertTrue(json.contains("\"payment_case_active\":true"))
    }

    @Test
    fun stalePaymentCaseResponseCannotReplaceTheCurrentSession() {
        assertFalse(isCurrentPaymentCaseSession(4, 5, active = true))
        assertFalse(isCurrentPaymentCaseSession(5, 5, active = false))
        assertTrue(isCurrentPaymentCaseSession(5, 5, active = true))
    }

    @Test
    fun retrySelectsOnlyAnUnattachedServerArtifact() {
        val pending = linkedSetOf("pc-art-done", "pc-art-retry")
        val attached = setOf("pc-art-done")

        assertEquals("pc-art-retry", nextPaymentCaseRetryRef(pending, attached))
        assertEquals(null, nextPaymentCaseRetryRef(setOf("pc-art-done"), attached))
    }

    @Test
    fun activePaymentCaseNeverReusesAResultWithoutANewServerArtifact() {
        assertFalse(shouldUseCachedScanResult(forceRefresh = false, paymentCaseActive = true))
        assertFalse(shouldUseCachedScanResult(forceRefresh = true, paymentCaseActive = false))
        assertTrue(shouldUseCachedScanResult(forceRefresh = false, paymentCaseActive = false))
    }
}
