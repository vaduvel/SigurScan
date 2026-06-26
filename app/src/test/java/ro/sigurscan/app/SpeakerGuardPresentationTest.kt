package ro.sigurscan.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SpeakerGuardPresentationTest {
    @Test
    fun activeListeningPresentationMatchesSpeakerGuardProductPromise() {
        val snapshot = SpeakerGuardSnapshot(
            active = true,
            phase = SpeakerGuardPhase.LISTENING,
            latestVerdict = null,
            status = "Ascultă prin microfon. Ține apelul pe difuzor.",
            startedAtEpochMillis = 1_000L
        )

        val presentation = speakerGuardPresentation(snapshot, evidence = null, nowMillis = 43_000L)

        assertEquals("Urechea ascultă", presentation.title)
        assertEquals("Ascult pe difuzor", presentation.listeningLabel)
        assertEquals("0:42", presentation.elapsedLabel)
        assertEquals("Analizez pe telefonul tău. Nimic nu pleacă de pe el.", presentation.privacyLine)
        assertEquals("Ascultă prin microfon. Ține apelul pe difuzor.", presentation.status)
        assertFalse(presentation.showHangUpCta)
    }

    @Test
    fun dangerousPresentationTellsUserToHangUpAndExplainsSuspiciousSignals() {
        val evidence = AudioEvidenceResult(
            verdict = AudioEvidenceVerdict.DANGEROUS,
            reasonCodes = listOf("identity_spoof", "sensitive_wrong_channel"),
            sttOnly = false,
            arcFamily = "CONV_BANK_SAFE_ACCOUNT"
        )
        val snapshot = SpeakerGuardSnapshot(
            active = true,
            phase = SpeakerGuardPhase.LISTENING,
            latestVerdict = AudioEvidenceVerdict.DANGEROUS,
            latestArcFamily = "CONV_BANK_SAFE_ACCOUNT",
            status = "Semnale puternice de fraudă în conversație.",
            startedAtEpochMillis = 1_000L
        )

        val presentation = speakerGuardPresentation(snapshot, evidence, nowMillis = 2_000L)

        assertEquals("Pare o țeapă", presentation.verdictTitle)
        assertEquals("Închide apelul. Nu da date și nu transfera bani.", presentation.primaryAction)
        assertTrue(presentation.showHangUpCta)
        assertTrue(presentation.reasons.any { it.title == "Se dă drept bancă sau autoritate" })
        assertTrue(presentation.reasons.any { it.title == "Îți cere coduri sau date sensibile" })
        assertTrue(presentation.reasons.any { it.title == "Cere transfer într-un cont sigur" })
        assertFalse(presentation.toString().contains("cont sigur acum"))
    }

    @Test
    fun callPromptCopyIsConsentFirstAndOnDeviceOnly() {
        val decision = RadarCallDecision(
            action = RadarCallAction.WARN,
            reason = "reported_number_bucket_5-24",
            family = "CONV_BANK_SAFE_ACCOUNT",
            warningTitle = "Număr semnalat în Radar",
            warningBody = "Numărul apare în rapoarte recente."
        )

        val prompt = speakerGuardCallPrompt(decision)

        assertEquals("Te sună un număr suspect", prompt.title)
        assertEquals("Ascultă pe difuzor", prompt.primaryCta)
        assertEquals("Nu acum", prompt.secondaryCta)
        assertTrue(prompt.body.contains("pui pe difuzor"))
        assertTrue(prompt.privacyLine.contains("Pornește doar dacă apeși"))
        assertTrue(prompt.privacyLine.contains("telefonul tău"))
    }
}
