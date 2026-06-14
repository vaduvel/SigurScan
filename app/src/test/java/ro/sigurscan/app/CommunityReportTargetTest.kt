package ro.sigurscan.app

import org.junit.Assert.assertEquals
import org.junit.Test

class CommunityReportTargetTest {
    @Test
    fun phoneOnlyAssessmentUsesNormalizedPhoneHash() {
        val target = communityReportTarget(
            OfflineAssessment(
                family = "phone",
                riskScore = 70,
                riskLevel = "high",
                reasons = emptyList(),
                safeActions = emptyList(),
                keyDangers = emptyList(),
                originalText = "0721 123 456"
            )
        )

        assertEquals("phone", target.targetType)
        assertEquals(PhoneNumberHasher.hashPhone("+40721123456"), target.hash)
    }

    @Test
    fun urlAndMessageReportsNeverMasqueradeAsPhoneReputation() {
        val url = communityReportTarget(
            OfflineAssessment(
                family = "url",
                riskScore = 70,
                riskLevel = "high",
                reasons = emptyList(),
                safeActions = emptyList(),
                keyDangers = emptyList(),
                originalText = "https://example.com",
                finalUrl = "https://example.com"
            )
        )
        val text = communityReportTarget(
            OfflineAssessment(
                family = "text",
                riskScore = 70,
                riskLevel = "high",
                reasons = emptyList(),
                safeActions = emptyList(),
                keyDangers = emptyList(),
                originalText = "Banca cere OTP la telefon"
            )
        )

        assertEquals("url", url.targetType)
        assertEquals("text", text.targetType)
    }
}
