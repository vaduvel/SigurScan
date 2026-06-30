package ro.sigurscan.app

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LocalExtractionPresentationTest {
    @Test
    fun localExtractionFailuresAreNeutralNeverificatNotSuspect() {
        val result = GateResult(
            action = GateAction.UNVERIFIED,
            finality = GateFinality.FINAL,
            reasonCodes = listOf("LOCAL_IMAGE_OCR_INCOMPLETE"),
            decisiveSignalIds = emptyList(),
            unknownReason = "LOCAL_IMAGE_OCR_INCOMPLETE"
        )
        val copy = listOf(
            GateResultPresentation.familyLabel(result, "fallback"),
            GateResultPresentation.legacyRiskLevel(result),
            GateResultPresentation.userHeadline(result),
            GateResultPresentation.supportText(result),
            GateResultPresentation.reasonText(result, null),
            GateResultPresentation.primaryAction(result)
        )
            .plus(GateResultPresentation.recommendedActions(result))
            .joinToString(" ")
            .lowercase()

        assertTrue(GateResultPresentation.familyLabel(result, "fallback") == "Neverificat")
        assertTrue(GateResultPresentation.legacyRiskLevel(result) == "info")
        assertTrue(GateResultPresentation.legacyRiskScore(result) == 0)
        assertTrue(GateResultPresentation.userHeadline(result) == "Neverificat")
        assertTrue(copy.contains("nu am putut"))
        assertTrue(copy.contains("reîncearcă") || copy.contains("reincearcă") || copy.contains("reincearca"))
        assertFalse(copy.contains("suspect"))
        assertFalse(copy.contains("periculos"))
        assertFalse(copy.contains("scanarea nu este completa"))
        assertFalse(copy.contains("scanarea nu este completă"))
    }

    @Test
    fun localAudioTranscriptionUnavailableIsNeutralNeverificatNotSuspect() {
        val result = GateResult(
            action = GateAction.UNVERIFIED,
            finality = GateFinality.FINAL,
            reasonCodes = listOf("LOCAL_AUDIO_TRANSCRIPTION_UNAVAILABLE"),
            decisiveSignalIds = emptyList(),
            unknownReason = "LOCAL_AUDIO_TRANSCRIPTION_UNAVAILABLE"
        )
        val copy = listOf(
            GateResultPresentation.familyLabel(result, "fallback"),
            GateResultPresentation.legacyRiskLevel(result),
            GateResultPresentation.userHeadline(result),
            GateResultPresentation.supportText(result),
            GateResultPresentation.reasonText(result, null),
            GateResultPresentation.primaryAction(result)
        )
            .plus(GateResultPresentation.recommendedActions(result))
            .joinToString(" ")
            .lowercase()

        assertTrue(GateResultPresentation.familyLabel(result, "fallback") == "Neverificat")
        assertTrue(GateResultPresentation.legacyRiskLevel(result) == "info")
        assertTrue(GateResultPresentation.legacyRiskScore(result) == 0)
        assertTrue(copy.contains("audio") || copy.contains("transcriere"))
        assertFalse(copy.contains("suspect"))
        assertFalse(copy.contains("periculos"))
    }
}
