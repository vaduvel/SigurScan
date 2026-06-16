package ro.sigurscan.app

import com.google.gson.Gson
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CircleGuardianContractTest {
    @Test
    fun guardianSummaryNeverSharesRawScanText() {
        val assessment = OfflineAssessment(
            scanId = "scan_1",
            family = "CONV_BANK_SAFE_ACCOUNT",
            riskScore = 82,
            riskLevel = "high",
            reasons = listOf("Cerere transfer urgent"),
            safeActions = listOf("Sună banca oficial"),
            keyDangers = listOf("Cont sigur fals"),
            originalText = "codul meu secret este 123456",
            finalUrl = "https://example.test/login"
        )

        val summary = guardianRedactedSummaryFromAssessment(assessment)
        val json = Gson().toJson(summary)

        assertTrue(json.contains("\"raw_text_shared\":false"))
        assertTrue(json.contains("\"final_host\":\"example.test\""))
        assertFalse(json.contains("codul meu secret"))
        assertFalse(json.contains("123456"))
    }

    @Test
    fun circleRequestsSerializeBackendContract() {
        val pair = Gson().toJson(
            CirclePairRequest(
                protectedId = "protected_local",
                verifierId = "verifier_local"
            )
        )
        val ping = Gson().toJson(CirclePingRequest(linkId = "cl_123"))
        val guardian = Gson().toJson(
            GuardianSecondOpinionRequest(
                caseId = "scan_1",
                protectedId = "protected_local",
                guardianId = "verifier_local",
                redactedSummary = mapOf("raw_text_shared" to false),
                shareLevel = "metadata_only",
                consent = false
            )
        )

        assertTrue(pair.contains("\"protected_id\":\"protected_local\""))
        assertTrue(pair.contains("\"verifier_id\":\"verifier_local\""))
        assertTrue(pair.contains("\"consent\":\"explicit\""))
        assertTrue(ping.contains("\"link_id\":\"cl_123\""))
        assertTrue(guardian.contains("\"share_level\":\"metadata_only\""))
        assertTrue(guardian.contains("\"raw_text_shared\":false"))
    }

    @Test
    fun verificationPingParsesMetadataOnlyDeliveryIntent() {
        val json = """
            {
              "ping_id": "vp_123",
              "link_id": "cl_123",
              "payload_class": "metadata_only",
              "default_on_timeout": "PRECAUTIE",
              "raw_stored": false,
              "delivery": {
                "type": "push_deeplink",
                "target_user_id": "verifier_local",
                "deeplink": "sigurscan://radar?ping_id=vp_123",
                "payload_class": "metadata_only",
                "raw_content_shared": false
              }
            }
        """.trimIndent()

        val ping = Gson().fromJson(json, VerificationPingResponse::class.java)

        assertTrue(ping.delivery?.get("deeplink").toString().contains("ping_id=vp_123"))
        assertTrue(ping.delivery?.get("payload_class") == "metadata_only")
        assertFalse(ping.delivery?.get("raw_content_shared") as Boolean)
    }
}
