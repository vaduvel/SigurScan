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

    @Test
    fun stoppedUnverifiedListeningShowsFinalNeverificatVerdict() {
        val snapshot = SpeakerGuardSnapshot(
            active = false,
            phase = SpeakerGuardPhase.STOPPED,
            latestVerdict = AudioEvidenceVerdict.UNVERIFIED,
            latestReasonCode = "call_ended_no_clear_audio",
            status = "Apelul s-a încheiat. Nu am prins suficientă voce clară."
        )

        val presentation = speakerGuardPresentation(snapshot, evidence = null, nowMillis = 10_000L)

        assertEquals("Urechea este oprită", presentation.title)
        assertEquals("Oprit", presentation.listeningLabel)
        assertEquals("Neverificat", presentation.verdictTitle)
        assertEquals("Nu am prins suficient audio clar. Verifică pe canal oficial înainte să dai bani sau date.", presentation.primaryAction)
        assertFalse(presentation.showHangUpCta)
    }

    @Test
    fun stoppedCallEndedWithoutAudioExplainsNoFragmentWasAnalyzed() {
        val snapshot = SpeakerGuardSnapshot(
            active = false,
            phase = SpeakerGuardPhase.STOPPED,
            chunksAnalyzed = 0,
            chunksDropped = 0,
            latestVerdict = AudioEvidenceVerdict.UNVERIFIED,
            latestReasonCode = "call_ended_no_capture",
            status = "Apelul s-a încheiat. Nu am putut confirma captura audio."
        )

        val presentation = speakerGuardPresentation(snapshot, evidence = null, nowMillis = 10_000L)

        assertEquals("Neverificat", presentation.verdictTitle)
        assertTrue(presentation.diagnosticLine!!.contains("nu am analizat fragmente audio clare"))
        assertTrue(presentation.diagnosticLine.contains("captură neconfirmată"))
    }

    @Test
    fun stoppedCallWithAndroidSilencedRecordingExplainsSystemBlockedMicrophone() {
        val snapshot = SpeakerGuardSnapshot(
            active = false,
            phase = SpeakerGuardPhase.STOPPED,
            chunksAnalyzed = 0,
            chunksDropped = 0,
            latestVerdict = AudioEvidenceVerdict.UNVERIFIED,
            latestReasonCode = "call_ended_recording_silenced",
            status = "Apelul s-a încheiat. Android a blocat microfonul în timpul apelului."
        )

        val presentation = speakerGuardPresentation(snapshot, evidence = null, nowMillis = 10_000L)

        assertEquals("Neverificat", presentation.verdictTitle)
        assertEquals(
            "Android nu ne-a lăsat să ascultăm apelul live pe acest telefon. Nu da bani sau date; verifică pe canal oficial.",
            presentation.primaryAction
        )
        assertTrue(presentation.diagnosticLine!!.contains("nu am analizat fragmente audio clare"))
        assertTrue(presentation.diagnosticLine.contains("microfon blocat de Android în apel"))
    }

    @Test
    fun activePresentationShowsPrivacySafeProgressWithoutTranscript() {
        val snapshot = SpeakerGuardSnapshot(
            active = true,
            phase = SpeakerGuardPhase.LISTENING,
            chunksAnalyzed = 3,
            chunksDropped = 1,
            latestReasonCode = "empty_transcript",
            status = "Nu am prins voce clară în ultimul fragment.",
            startedAtEpochMillis = 1_000L
        )

        val presentation = speakerGuardPresentation(snapshot, evidence = null, nowMillis = 10_000L)

        assertTrue(presentation.diagnosticLine!!.contains("3 fragmente"))
        assertTrue(presentation.diagnosticLine.contains("voce neclară"))
        assertTrue(presentation.diagnosticLine.contains("1 sărit"))
        assertFalse(presentation.diagnosticLine.contains("cont sigur"))
    }

    @Test
    fun activeUnverifiedEvidenceExplainsThatNoClearSignalsWereFound() {
        val snapshot = SpeakerGuardSnapshot(
            active = true,
            phase = SpeakerGuardPhase.LISTENING,
            chunksAnalyzed = 2,
            latestVerdict = AudioEvidenceVerdict.UNVERIFIED,
            status = "Am analizat vocea, dar încă nu sunt suficiente dovezi.",
            startedAtEpochMillis = 1_000L
        )

        val presentation = speakerGuardPresentation(snapshot, evidence = null, nowMillis = 10_000L)

        assertTrue(presentation.diagnosticLine!!.contains("2 fragmente"))
        assertTrue(presentation.diagnosticLine.contains("fără semnale clare"))
    }
}
