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
}
