package ro.sigurscan.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AudioSemanticReviewFusionTest {
    @Test
    fun mistralHighEscalatesUnverifiedLocalEvidenceToDangerous() {
        val local = AudioEvidenceEngine.evaluate(AudioEvidenceInput())

        val fused = AudioSemanticReviewFusion.fuse(
            local = local,
            review = AudioSemanticReviewResponse(
                status = "done",
                semanticReview = AudioSemanticReviewPayload(
                    riskClass = "high",
                    reasonCodes = listOf("semantic:false_authority", "semantic:safe_account"),
                    matchedFamily = "CONV_BANK_SAFE_ACCOUNT",
                    source = "mistral_semantic_pillar"
                ),
                escalates = true,
                reasonCodes = listOf("semantic:false_authority", "semantic:safe_account")
            )
        )

        assertEquals(AudioEvidenceVerdict.DANGEROUS, fused.verdict)
        assertTrue(fused.reasonCodes.contains("semantic:false_authority"))
        assertTrue(fused.reasonCodes.contains("semantic:mistral_escalation"))
        assertEquals("CONV_BANK_SAFE_ACCOUNT", fused.arcFamily)
    }

    @Test
    fun mistralBenignCannotDowngradeDangerousLocalEvidence() {
        val local = AudioTranscriptEvidence.analyze(
            "Sunt de la banca si trebuie sa imi dai codul OTP ca sa blocam creditul fraudulos"
        )

        val fused = AudioSemanticReviewFusion.fuse(
            local = local,
            review = AudioSemanticReviewResponse(
                status = "done",
                semanticReview = AudioSemanticReviewPayload(
                    riskClass = "benign",
                    reasonCodes = listOf("semantic:benign"),
                    source = "mistral_semantic_pillar"
                ),
                escalates = false,
                reasonCodes = listOf("semantic:benign")
            )
        )

        assertEquals(AudioEvidenceVerdict.DANGEROUS, fused.verdict)
        assertFalse(fused.reasonCodes.contains("semantic:benign"))
        assertTrue(fused.reasonCodes.isNotEmpty())
    }
}
