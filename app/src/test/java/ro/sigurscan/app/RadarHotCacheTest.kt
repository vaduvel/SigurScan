package ro.sigurscan.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RadarHotCacheTest {
    @Test
    fun romanianPhoneNumbersNormalizeToStableE164() {
        assertEquals("+40721123456", PhoneNumberHasher.normalizePhoneNumber("0721 123 456"))
        assertEquals("+40721123456", PhoneNumberHasher.normalizePhoneNumber("0040 721 123 456"))
        assertEquals("+40721123456", PhoneNumberHasher.normalizePhoneNumber("+40 721 123 456"))
    }

    @Test
    fun phoneHashIsSha256OfNormalizedPhone() {
        val expected = "6299727319d94b437bb345a7fff98237cf41973f182d2beb4ceed789feb03586"
        assertEquals(expected, PhoneNumberHasher.hashPhone("+40 721 123 456"))
    }

    @Test
    fun freshCacheRemainsUsableWithinTtl() {
        val cache = RadarHotCacheSnapshot(
            generatedAtEpochMillis = 1_000L,
            ttlMinutes = 60,
            hotCampaigns = emptyList(),
            numberReputation = emptyList()
        )

        assertFalse(cache.isExpired(nowMillis = 1_000L + 59 * 60 * 1000))
        assertTrue(cache.isExpired(nowMillis = 1_000L + 61 * 60 * 1000))
    }

    @Test
    fun exactReportedPhoneHashWarnsButDoesNotReject() {
        val phoneHash = PhoneNumberHasher.hashPhone("0721 123 456")
        val cache = RadarHotCacheSnapshot(
            generatedAtEpochMillis = 1_000L,
            ttlMinutes = 60,
            hotCampaigns = emptyList(),
            numberReputation = listOf(
                RadarNumberReputation(phoneHash = phoneHash, status = "reported", family = "whatsapp", bucketCount = "5-24")
            )
        )

        val decision = RadarCallDecider.decide("+40 721 123 456", cache, nowMillis = 2_000L)

        assertEquals(RadarCallAction.WARN, decision.action)
        assertFalse(decision.rejectCall)
        assertTrue(decision.reason.contains("reported"))
    }

    @Test
    fun blockedPhoneReputationWarnsAndRejects() {
        val phoneHash = PhoneNumberHasher.hashPhone("0721 123 456")
        val cache = RadarHotCacheSnapshot(
            generatedAtEpochMillis = 1_000L,
            ttlMinutes = 60,
            hotCampaigns = emptyList(),
            numberReputation = listOf(
                RadarNumberReputation(phoneHash = phoneHash, status = "blocked", family = "bank_safe_account", bucketCount = "25+")
            )
        )

        val decision = RadarCallDecider.decide("+40 721 123 456", cache, nowMillis = 2_000L)

        assertEquals(RadarCallAction.WARN, decision.action)
        assertTrue(decision.rejectCall)
        assertTrue(decision.silenceCall)
        assertTrue(decision.reason.contains("blocked"))
    }

    @Test
    fun callScreeningServiceHonorsRejectDecisions() {
        val serviceSource = java.io.File("src/main/java/ro/sigurscan/app/SigurScanCallScreeningService.kt").readText()

        assertTrue(
            "CallScreeningService must wire reject decisions into CallResponse instead of only logging them.",
            serviceSource.contains(".setDisallowCall(decision.rejectCall)") &&
                serviceSource.contains(".setRejectCall(decision.rejectCall)")
        )
    }

    @Test
    fun callScreeningWarnsWithSpeakerGuardPrompt() {
        val serviceSource = java.io.File("src/main/java/ro/sigurscan/app/SigurScanCallScreeningService.kt").readText()
        val notifierSource = java.io.File("src/main/java/ro/sigurscan/app/SpeakerGuardCallPromptNotifier.kt").takeIf { it.exists() }?.readText().orEmpty()

        assertTrue(
            "CallScreeningService must surface a user-controlled Speaker Guard prompt for WARN decisions.",
            serviceSource.contains("SpeakerGuardCallPromptNotifier.fromContext(applicationContext).showIfNeeded(decision)")
        )
        assertTrue(
            "The call-time prompt must deep-link to Speaker Guard with autostart, not to a generic Radar page.",
            notifierSource.contains("sigurscan://speaker-guard") &&
                notifierSource.contains("autostart=1") &&
                notifierSource.contains("source=call_screening")
        )
        assertTrue(
            "The prompt must be gated behind the reviewed local ASR feature flag.",
            notifierSource.contains("BuildConfig.SIGURSCAN_ENABLE_AUDIO_ASR")
        )
    }

    @Test
    fun campaignHashPrefixWarnsOffline() {
        val phoneHash = PhoneNumberHasher.hashPhone("+40 721 123 456")
        val cache = RadarHotCacheSnapshot(
            generatedAtEpochMillis = 1_000L,
            ttlMinutes = 60,
            hotCampaigns = listOf(
                RadarHotCampaign(
                    campaignId = "c1",
                    family = "CONV_BANK_SAFE_ACCOUNT",
                    warningTitle = "Apeluri false banca",
                    warningBody = "Inchide si suna banca.",
                    regions = listOf("RO"),
                    phoneHashPrefixes = listOf(phoneHash.take(10)),
                    confidence = "high"
                )
            ),
            numberReputation = emptyList()
        )

        val decision = RadarCallDecider.decide("0721123456", cache, nowMillis = 2_000L)

        assertEquals(RadarCallAction.WARN, decision.action)
        assertEquals("CONV_BANK_SAFE_ACCOUNT", decision.family)
        assertFalse(decision.rejectCall)
    }

    @Test
    fun expiredOrMissingCacheAllowsCall() {
        val expired = RadarHotCacheSnapshot(
            generatedAtEpochMillis = 1_000L,
            ttlMinutes = 1,
            hotCampaigns = emptyList(),
            numberReputation = listOf(
                RadarNumberReputation(phoneHash = PhoneNumberHasher.hashPhone("0721 123 456"), status = "reported")
            )
        )

        assertEquals(RadarCallAction.ALLOW, RadarCallDecider.decide("0721123456", expired, nowMillis = 180_000L).action)
        assertEquals(RadarCallAction.ALLOW, RadarCallDecider.decide("0721123456", null, nowMillis = 2_000L).action)
    }

    @Test
    fun screeningAuditKeepsDecisionButNoRawPhoneNumber() {
        val decision = RadarCallDecision(
            action = RadarCallAction.WARN,
            reason = "campaign_hash_prefix_match",
            family = "CONV_BANK_SAFE_ACCOUNT",
            silenceCall = true
        )

        val audit = RadarScreeningAudit.fromDecision(decision, checkedAtEpochMillis = 42L)

        assertEquals(42L, audit.checkedAtEpochMillis)
        assertEquals(RadarCallAction.WARN, audit.action)
        assertEquals("campaign_hash_prefix_match", audit.reason)
        assertEquals("CONV_BANK_SAFE_ACCOUNT", audit.family)
        assertNull(RadarScreeningAudit::class.java.declaredFields.firstOrNull { it.name.contains("phone", ignoreCase = true) })
    }
}
