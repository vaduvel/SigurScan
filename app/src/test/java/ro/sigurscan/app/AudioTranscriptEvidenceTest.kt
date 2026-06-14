package ro.sigurscan.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class AudioTranscriptEvidenceTest {
    @Test
    fun bankSafeAccountTranscriptProducesDangerousWithoutRetainingRawText() {
        val raw = "Sunt inspector de la Politie. BNR cere sa muti economiile intr-un cont sigur."

        val result = AudioTranscriptEvidence.analyze(raw)

        assertEquals(AudioEvidenceVerdict.DANGEROUS, result.verdict)
        assertEquals("CONV_BANK_SAFE_ACCOUNT", result.arcFamily)
        assertTrue(result.transcriptRedacted)
        assertFalse(result.toString().contains("economiile"))
    }

    @Test
    fun remoteAccessInvestmentTranscriptProducesDangerous() {
        val result = AudioTranscriptEvidence.analyze(
            "Consultantul promite profit garantat si cere sa instalez AnyDesk pentru acces la distanta."
        )

        assertEquals(AudioEvidenceVerdict.DANGEROUS, result.verdict)
        assertEquals("CONV_INVESTMENT_REMOTE_ACCESS", result.arcFamily)
        assertTrue(result.reasonCodes.contains("sensitive_wrong_channel"))
    }

    @Test
    fun familyEmergencyMoneyTranscriptProducesDangerous() {
        val result = AudioTranscriptEvidence.analyze(
            "Sunt nepotul tau, am facut accident. Avocatul cere 12000 lei cash si sa nu suni politia."
        )

        assertEquals(AudioEvidenceVerdict.DANGEROUS, result.verdict)
        assertEquals("CONV_FAMILY_EMERGENCY", result.arcFamily)
    }

    @Test
    fun ordinaryUnknownCallWithoutSensitiveAskIsNotDangerous() {
        val result = AudioTranscriptEvidence.analyze(
            "Buna ziua, confirmam programarea de maine la ora zece."
        )

        assertTrue(result.verdict in setOf(AudioEvidenceVerdict.UNVERIFIED, AudioEvidenceVerdict.SUSPECT))
        assertFalse(result.verdict == AudioEvidenceVerdict.DANGEROUS)
    }

    @Test
    fun blankTranscriptStaysUnverified() {
        val result = AudioTranscriptEvidence.analyze("   ")

        assertEquals(AudioEvidenceVerdict.UNVERIFIED, result.verdict)
        assertFalse(result.transcriptRedacted)
    }

    @Test
    fun realisticCallTranscriptFixturePackProducesActionableLocalEvidence() {
        val fixtureDir = File("../e2e_fixtures/sigurscan_e2e_fixtures_v2_realistic/fixtures/call_transcripts")
        val fixtures = fixtureDir.listFiles { file -> file.extension == "txt" }.orEmpty().sortedBy(File::getName)

        assertEquals(34, fixtures.size)
        val results = fixtures.map { fixture -> fixture.name to AudioTranscriptEvidence.analyze(fixture.readText()) }
        val unverified = results.filter { (_, result) -> result.verdict == AudioEvidenceVerdict.UNVERIFIED }

        assertTrue("Scam call fixtures left unverified: ${unverified.map { it.first }}", unverified.isEmpty())
        assertTrue(results.all { (_, result) -> result.transcriptRedacted && !result.rawAudioStored })
    }
}
