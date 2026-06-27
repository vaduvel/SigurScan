package ro.sigurscan.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AudioEvidenceSessionAggregatorTest {
    @Test
    fun splitBankSafeAccountSignalsEscalateWithoutRetainingTranscript() {
        val aggregator = AudioEvidenceSessionAggregator()

        aggregator.absorb(AudioTranscriptEvidence.analyze("Sunt de la banca."))
        aggregator.absorb(AudioTranscriptEvidence.analyze("Trebuie sa muti banii acum."))
        val aggregated = aggregator.absorb(AudioTranscriptEvidence.analyze("Intr-un cont sigur."))

        assertEquals(AudioEvidenceVerdict.DANGEROUS, aggregated.verdict)
        assertEquals("CONV_BANK_SAFE_ACCOUNT", aggregated.arcFamily)
        assertTrue(aggregated.reasonCodes.contains("identity_spoof"))
        assertTrue(aggregated.transcriptRedacted)
        assertFalse(aggregated.rawAudioStored)
        assertFalse(aggregator.toString().contains("Trebuie sa muti banii"))
        assertFalse(aggregator.toString().contains("cont sigur"))
    }

    @Test
    fun ordinaryFragmentsStayUnverifiedOrSuspectButNeverDangerous() {
        val aggregator = AudioEvidenceSessionAggregator()

        aggregator.absorb(AudioTranscriptEvidence.analyze("Buna ziua."))
        val aggregated = aggregator.absorb(AudioTranscriptEvidence.analyze("Confirmam programarea de maine."))

        assertTrue(aggregated.verdict != AudioEvidenceVerdict.DANGEROUS)
        assertFalse(aggregated.rawAudioStored)
    }
}
