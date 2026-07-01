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
    fun bankAntiFraudIntroThenMoneyRequestEscalatesWithoutRetainingTranscript() {
        val aggregator = AudioEvidenceSessionAggregator()

        aggregator.absorb(
            AudioTranscriptEvidence.analyze(
                "Bu nezioa, văsun din partea bănsin, departamentul anti-fraude."
            )
        )
        val aggregated = aggregator.absorb(
            AudioTranscriptEvidence.analyze(
                "Trebuie sa mutati fondurile acum intr-un cont temporar de siguranta."
            )
        )

        assertEquals(AudioEvidenceVerdict.DANGEROUS, aggregated.verdict)
        assertTrue(aggregated.reasonCodes.contains("identity_spoof"))
        assertTrue(aggregated.transcriptRedacted)
        assertFalse(aggregator.toString().contains("fondurile"))
        assertFalse(aggregator.toString().contains("anti-fraude"))
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
