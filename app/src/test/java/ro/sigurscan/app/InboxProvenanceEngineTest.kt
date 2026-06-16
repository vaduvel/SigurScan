package ro.sigurscan.app

import org.junit.Assert.assertEquals
import org.junit.Test

class InboxProvenanceEngineTest {
    private val snapshot = BtrSyncSnapshot(
        version = "btr-ro-test",
        generatedAt = "2026-06-13T00:00:00Z",
        manifests = listOf(
            BtrManifest(
                manifestId = "yoxo",
                displayName = "YOXO",
                officialDomains = listOf("yoxo.ro", "reconditionate.yoxo.ro"),
                officialEmailDomains = listOf("yoxo.ro"),
                officialShortcodes = listOf("1872"),
                officialPhonesE164 = listOf("+40211234567"),
                neverAsks = listOf("otp", "card_number", "password")
            )
        )
    )

    @Test
    fun officialDomainWithoutSensitiveAskIsSafeOnDevice() {
        val verdict = InboxProvenanceEngine.evaluate(
            InboxSignalBundle(
                messageHash = "hash1",
                claimedBrand = "YOXO",
                observedDomain = "www.yoxo.ro",
                sensitiveAsks = emptyList(),
                hasUrl = true
            ),
            snapshot
        )

        assertEquals(OnDeviceInboxVerdict.SAFE, verdict.verdict)
        assertEquals("yoxo", verdict.manifestId)
    }

    @Test
    fun officialBrandNeverAskViolationIsDangerous() {
        val verdict = InboxProvenanceEngine.evaluate(
            InboxSignalBundle(
                messageHash = "hash2",
                claimedBrand = "YOXO",
                observedDomain = "www.yoxo.ro",
                sensitiveAsks = listOf("otp"),
                hasUrl = true
            ),
            snapshot
        )

        assertEquals(OnDeviceInboxVerdict.DANGEROUS, verdict.verdict)
        assertEquals(listOf("never_ask_violation:otp"), verdict.reasonCodes)
    }

    @Test
    fun unknownBrandStaysUnverified() {
        val verdict = InboxProvenanceEngine.evaluate(
            InboxSignalBundle(
                messageHash = "hash3",
                claimedBrand = "Brand Nou",
                observedDomain = "brand-nou.example",
                sensitiveAsks = emptyList(),
                hasUrl = true
            ),
            snapshot
        )

        assertEquals(OnDeviceInboxVerdict.UNVERIFIED, verdict.verdict)
    }

    @Test
    fun localTextOfficialDomainWithoutSensitiveAskIsSafe() {
        val verdict = InboxProvenanceEngine.evaluateLocalText(
            rawText = "Upgrade fara regrete in YOXO Shop. Vezi ofertele pe https://www.yoxo.ro/",
            observedDomain = "www.yoxo.ro",
            btr = snapshot
        )

        assertEquals(OnDeviceInboxVerdict.SAFE, verdict.verdict)
        assertEquals("yoxo", verdict.manifestId)
        assertEquals(false, verdict.rawStored)
        assertEquals("on_device_only", verdict.processing)
    }

    @Test
    fun localTextOfficialBrandAskingOtpIsDangerous() {
        val verdict = InboxProvenanceEngine.evaluateLocalText(
            rawText = "YOXO: trimite codul de verificare primit prin SMS pentru activare.",
            observedDomain = "www.yoxo.ro",
            btr = snapshot
        )

        assertEquals(OnDeviceInboxVerdict.DANGEROUS, verdict.verdict)
        assertEquals(listOf("never_ask_violation:otp"), verdict.reasonCodes)
    }

    @Test
    fun localTextMentioningSmsWithoutCodeDoesNotBecomeDangerous() {
        val verdict = InboxProvenanceEngine.evaluateLocalText(
            rawText = "YOXO: informare SMS despre oferta ta din aplicatie.",
            observedDomain = "www.yoxo.ro",
            btr = snapshot
        )

        assertEquals(OnDeviceInboxVerdict.SAFE, verdict.verdict)
    }

    @Test
    fun officialShortcodeWithoutSensitiveAskIsSafeOnDevice() {
        val verdict = InboxProvenanceEngine.evaluate(
            InboxSignalBundle(
                messageHash = "hash4",
                claimedBrand = "YOXO",
                observedShortcode = "1872",
                sensitiveAsks = emptyList(),
                hasUrl = false
            ),
            snapshot
        )

        assertEquals(OnDeviceInboxVerdict.SAFE, verdict.verdict)
        assertEquals(listOf("official_shortcode_match"), verdict.reasonCodes)
    }

    @Test
    fun officialPhoneAskingOtpIsDangerousOnDevice() {
        val verdict = InboxProvenanceEngine.evaluate(
            InboxSignalBundle(
                messageHash = "hash5",
                claimedBrand = "YOXO",
                observedPhoneE164 = "021 123 4567",
                sensitiveAsks = listOf("otp"),
                hasUrl = false
            ),
            snapshot
        )

        assertEquals(OnDeviceInboxVerdict.DANGEROUS, verdict.verdict)
        assertEquals(listOf("never_ask_violation:otp"), verdict.reasonCodes)
    }
}
