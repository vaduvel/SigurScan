package ro.sigurscan.app

import com.google.gson.Gson
import kotlinx.coroutines.runBlocking
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory

class AudioSemanticReviewFusionTest {
    @Test
    fun backendReviewerReportsNetworkFailureInsteadOfSilentlyReturningNull() = runBlocking {
        val server = MockWebServer()
        server.enqueue(MockResponse().setResponseCode(503).setBody("unavailable"))
        server.start()
        try {
            val api = Retrofit.Builder()
                .baseUrl(server.url("/"))
                .addConverterFactory(GsonConverterFactory.create(Gson()))
                .build()
                .create(SigurScanApi::class.java)

            val outcome = BackendAudioSemanticReviewer(api, "audio_share").review(
                redactedTranscript = "Sunt de la banca si cer [cod]",
                localEvidence = AudioEvidenceEngine.evaluate(AudioEvidenceInput())
            )

            assertEquals(VerificationPillarStatus.ERROR, outcome.status)
            assertEquals("semantic:http_503", outcome.reasonCode)
            assertEquals(null, outcome.response)
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun backendFallbackIsExposedAsProviderErrorWithLocalResponsePreserved() = runBlocking {
        val server = MockWebServer()
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody(
                    """{"status":"fallback","semantic_review":{"risk_class":"medium","reason_codes":["semantic:mistral_unavailable"],"source":"audio_local_fallback"},"reason_codes":["semantic:mistral_unavailable"],"escalates":false}"""
                )
        )
        server.start()
        try {
            val api = Retrofit.Builder()
                .baseUrl(server.url("/"))
                .addConverterFactory(GsonConverterFactory.create(Gson()))
                .build()
                .create(SigurScanApi::class.java)

            val outcome = BackendAudioSemanticReviewer(api, "audio_share").review(
                redactedTranscript = "Sunt de la banca si cer [cod]",
                localEvidence = AudioEvidenceEngine.evaluate(AudioEvidenceInput())
            )

            assertEquals(VerificationPillarStatus.ERROR, outcome.status)
            assertEquals("semantic:mistral_unavailable", outcome.reasonCode)
            assertEquals("fallback", outcome.response?.status)
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun malformedDoneResponseIsNotPresentedAsSuccessfulSemanticReview() = runBlocking {
        val server = MockWebServer()
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody("""{"status":"done","semantic_review":null,"reason_codes":[],"escalates":false}""")
        )
        server.start()
        try {
            val api = Retrofit.Builder()
                .baseUrl(server.url("/"))
                .addConverterFactory(GsonConverterFactory.create(Gson()))
                .build()
                .create(SigurScanApi::class.java)

            val outcome = BackendAudioSemanticReviewer(api, "audio_share").review(
                redactedTranscript = "Sunt de la banca si cer [cod]",
                localEvidence = AudioEvidenceEngine.evaluate(AudioEvidenceInput())
            )

            assertEquals(VerificationPillarStatus.ERROR, outcome.status)
            assertEquals("semantic:invalid_response", outcome.reasonCode)
        } finally {
            server.shutdown()
        }
    }

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
