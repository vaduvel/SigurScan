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
        val promptServiceSource = java.io.File("src/main/java/ro/sigurscan/app/SpeakerGuardPromptForegroundService.kt").takeIf { it.exists() }?.readText().orEmpty()
        val promptActivitySource = java.io.File("src/main/java/ro/sigurscan/app/SpeakerGuardPromptActivity.kt").takeIf { it.exists() }?.readText().orEmpty()
        val foregroundServiceSource = java.io.File("src/main/java/ro/sigurscan/app/SpeakerGuardForegroundService.kt").takeIf { it.exists() }?.readText().orEmpty()

        assertTrue(
            "CallScreeningService must hand call-time Speaker Guard prompts to a foreground service so the app-closed case is covered.",
            serviceSource.contains("SpeakerGuardPromptForegroundService.startForCallPrompt(applicationContext, decision)")
        )
        assertTrue(
            "The call-time prompt must open a dedicated lower-screen consent activity, which then deep-links to Speaker Guard with autostart.",
            notifierSource.contains("SpeakerGuardPromptActivity.startIntent(context)") &&
                promptActivitySource.contains("sigurscan://speaker-guard") &&
                promptActivitySource.contains("autostart=1") &&
                promptActivitySource.contains("source=call_screening")
        )
        assertTrue(
            "The call-time prompt should be allowed to surface as a full-screen/high-priority call prompt when the app is closed.",
            notifierSource.contains(".setFullScreenIntent(pendingIntent, true)") &&
                notifierSource.contains("NotificationCompat.PRIORITY_MAX") &&
                notifierSource.contains("NotificationCompat.VISIBILITY_PUBLIC") &&
                notifierSource.contains(".setTimeoutAfter(")
        )
        assertTrue(
            "When the unlocked incoming-call UI covers the heads-up card, the prompt service must also point the user to the lower-screen card.",
            promptServiceSource.contains("Toast.makeText") &&
                promptServiceSource.contains("cardul de jos")
        )
        assertTrue(
            "The dedicated prompt activity must anchor the CTA at the bottom so the system incoming-call popup cannot cover it.",
            promptActivitySource.contains("contentAlignment = Alignment.BottomCenter") &&
                promptActivitySource.contains("Cardul stă jos") &&
                promptActivitySource.contains("Am răspuns. Ascultă pe difuzor")
        )
        assertTrue(
            "The prompt must be gated behind the reviewed local ASR feature flag.",
            notifierSource.contains("BuildConfig.SIGURSCAN_ENABLE_AUDIO_ASR")
        )
        assertTrue(
            "Speaker Guard call prompt eligibility must use the unknown-contact policy, not only Radar WARN.",
            notifierSource.contains("SpeakerGuardCallPromptPolicy.shouldOffer(decision)") &&
                promptServiceSource.contains("SpeakerGuardCallPromptPolicy.shouldOffer(decision)")
        )
        assertFalse(
            "The old WARN-only gate would miss fresh unsaved-number scams.",
            notifierSource.contains("decision.action != RadarCallAction.WARN") ||
                promptServiceSource.contains("decision.action != RadarCallAction.WARN")
        )
        assertTrue(
            "CallScreeningService must propagate the system contact-display signal without requiring READ_CONTACTS.",
            serviceSource.contains("callDetails.contactDisplayName") &&
                serviceSource.contains("isKnownContact")
        )
        assertTrue(
            "SpeakerGuardPromptForegroundService must show a prompt-only foreground notification before delegating to the explicit-consent prompt.",
            promptServiceSource.contains("startForeground(") &&
                promptServiceSource.contains("SpeakerGuardCallPromptNotifier.fromContext(applicationContext).showIfNeeded(decision)")
        )
        val promptHandler = Regex(
            """private fun handleCallPrompt[\s\S]*?return START_NOT_STICKY"""
        ).find(promptServiceSource)?.value.orEmpty()
        assertFalse(
            "The call prompt branch must not start microphone capture before the user taps the prompt.",
            promptHandler.contains("SpeakerGuardSession(") ||
                promptHandler.contains("ACTION_START_CAPTURE")
        )
        assertFalse(
            "The microphone capture service must not carry the background call-screening prompt action; Android treats the class as microphone-sensitive.",
            foregroundServiceSource.contains("ACTION_SHOW_CALL_PROMPT") ||
                foregroundServiceSource.contains("startForCallPrompt")
        )
        assertTrue(
            "After explicit consent, live-call microphone capture must be owned by the foreground service.",
            foregroundServiceSource.contains("ACTION_START_CAPTURE") &&
                foregroundServiceSource.contains("SpeakerGuardSession(")
        )
    }

    @Test
    fun speakerGuardPromptPolicyOffersForUnsavedNumberWithoutRadarHit() {
        val decision = RadarCallDecision(
            action = RadarCallAction.ALLOW,
            reason = "no_radar_hit",
            isKnownContact = false
        )

        assertTrue(SpeakerGuardCallPromptPolicy.shouldOffer(decision))
    }

    @Test
    fun speakerGuardPromptPolicyExcludesSavedContactsEvenWhenRadarWarns() {
        val decision = RadarCallDecision(
            action = RadarCallAction.WARN,
            reason = "reported_number_bucket_5-24",
            family = "CONV_BANK_SAFE_ACCOUNT",
            isKnownContact = true
        )

        assertFalse(SpeakerGuardCallPromptPolicy.shouldOffer(decision))
    }

    @Test
    fun speakerGuardPromptPolicyKeepsWarnForUnsavedRadarHits() {
        val decision = RadarCallDecision(
            action = RadarCallAction.WARN,
            reason = "campaign_hash_prefix_match",
            family = "CONV_BANK_SAFE_ACCOUNT",
            isKnownContact = false
        )

        assertTrue(SpeakerGuardCallPromptPolicy.shouldOffer(decision))
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
