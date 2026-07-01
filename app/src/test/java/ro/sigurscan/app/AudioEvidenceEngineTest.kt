package ro.sigurscan.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AudioEvidenceEngineTest {
    @Test
    fun audioEvidenceResultNeverContainsRawTranscript() {
        val verdict = AudioEvidenceEngine.evaluate(
            AudioEvidenceInput(transcriptRedacted = "suna banca acum cont sigur")
        )

        assertFalse(verdict.rawAudioStored)
        assertEquals("on_device_only", verdict.processing)
        assertTrue(verdict.transcriptRedacted)
        assertFalse(verdict.toString().contains("cont sigur"))
    }

    @Test
    fun safeAccountOtpBankComboIsDangerous() {
        val verdict = AudioEvidenceEngine.evaluate(
            AudioEvidenceInput(
                claimedIdentity = "banca",
                identityProvenance = AudioIdentityProvenance.MISMATCH,
                sensitiveAsks = listOf("otp"),
                arcFamily = "CONV_BANK_SAFE_ACCOUNT"
            )
        )

        assertEquals(AudioEvidenceVerdict.DANGEROUS, verdict.verdict)
        assertTrue(verdict.reasonCodes.contains("identity_spoof"))
    }

    @Test
    fun transferWithClaimedPoliceIdentityIsDangerous() {
        val verdict = AudioEvidenceEngine.evaluate(
            AudioEvidenceInput(
                claimedIdentity = "politie",
                identityProvenance = AudioIdentityProvenance.MISMATCH,
                sensitiveAsks = listOf("transfer"),
                arcFamily = "CONV_BANK_SAFE_ACCOUNT"
            )
        )

        assertEquals(AudioEvidenceVerdict.DANGEROUS, verdict.verdict)
    }

    @Test
    fun hardSensitiveSignalsWinOverCampaignMatch() {
        val verdict = AudioEvidenceEngine.evaluate(
            AudioEvidenceInput(
                sensitiveAsks = listOf("otp"),
                arcFamily = "CONV_BANK_SAFE_ACCOUNT",
                campaignMatch = "cf_bank_safe",
                campaignConfidence = 0.93
            )
        )

        assertEquals(AudioEvidenceVerdict.DANGEROUS, verdict.verdict)
        assertTrue(verdict.reasonCodes.contains("sensitive_wrong_channel"))
        assertFalse(verdict.reasonCodes.contains("campaign_match_only"))
    }

    @Test
    fun identitySpoofSignalsWinOverCampaignMatch() {
        val verdict = AudioEvidenceEngine.evaluate(
            AudioEvidenceInput(
                claimedIdentity = "banca",
                identityProvenance = AudioIdentityProvenance.MISMATCH,
                sensitiveAsks = listOf("transfer"),
                arcFamily = "CONV_BANK_SAFE_ACCOUNT",
                campaignMatch = "cf_bank_safe",
                campaignConfidence = 0.93
            )
        )

        assertEquals(AudioEvidenceVerdict.DANGEROUS, verdict.verdict)
        assertTrue(verdict.reasonCodes.contains("identity_spoof"))
        assertFalse(verdict.reasonCodes.contains("campaign_match_only"))
    }

    @Test
    fun criticalClaimedIdentityCampaignIsDangerousEvenWhenTinyAsrMissesTheExactAsk() {
        val verdict = AudioEvidenceEngine.evaluate(
            AudioEvidenceInput(
                claimedIdentity = "banca",
                arcFamily = "CONV_BANK_ANTI_FRAUD_CALL",
                campaignMatch = "conv_bank_anti_fraud_call",
                campaignConfidence = 0.84
            )
        )

        assertEquals(AudioEvidenceVerdict.DANGEROUS, verdict.verdict)
        assertTrue(verdict.reasonCodes.contains("critical_campaign_identity"))
        assertFalse(verdict.reasonCodes.contains("campaign_match_only"))
    }

    @Test
    fun sttOnlyCampaignMatchIsCappedAtSuspect() {
        val verdict = AudioEvidenceEngine.evaluate(
            AudioEvidenceInput(
                arcFamily = "CONV_BANK_SAFE_ACCOUNT",
                campaignMatch = "cf_bank_safe",
                campaignConfidence = 0.91
            )
        )

        assertEquals(AudioEvidenceVerdict.SUSPECT, verdict.verdict)
        assertTrue(verdict.sttOnly)
        assertFalse(verdict.verdict == AudioEvidenceVerdict.DANGEROUS)
    }

    @Test
    fun unknownCallerWithoutSensitiveAskIsNotDangerous() {
        val verdict = AudioEvidenceEngine.evaluate(
            AudioEvidenceInput(transcriptRedacted = "[redactat]")
        )

        assertTrue(
            verdict.verdict == AudioEvidenceVerdict.UNVERIFIED ||
                verdict.verdict == AudioEvidenceVerdict.SUSPECT
        )
        assertFalse(verdict.verdict == AudioEvidenceVerdict.DANGEROUS)
    }

    @Test
    fun deterministicForSameSignals() {
        val input = AudioEvidenceInput(
            claimedIdentity = "banca",
            identityProvenance = AudioIdentityProvenance.MISMATCH,
            sensitiveAsks = listOf("otp"),
            arcFamily = "CONV_BANK_SAFE_ACCOUNT"
        )

        assertEquals(AudioEvidenceEngine.evaluate(input), AudioEvidenceEngine.evaluate(input))
    }
}
