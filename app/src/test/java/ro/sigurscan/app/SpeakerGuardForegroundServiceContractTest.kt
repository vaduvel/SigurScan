package ro.sigurscan.app

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class SpeakerGuardForegroundServiceContractTest {
    @Test
    fun viewModelDelegatesLiveCaptureToMicrophoneForegroundService() {
        val viewModelAudioSource = File("src/main/java/ro/sigurscan/app/ScannerViewModelAudio.kt").readText()

        assertTrue(
            "Starting live-call Speaker Guard must enter the microphone foreground service after consent.",
            viewModelAudioSource.contains("SpeakerGuardForegroundService.startCapture(")
        )
        assertTrue(
            "Stopping live-call Speaker Guard must explicitly stop the microphone foreground service.",
            viewModelAudioSource.contains("SpeakerGuardForegroundService.stopCapture(")
        )
        assertFalse(
            "The ViewModel must not own AudioRecord capture in viewModelScope; Android can background-limit it behind the dialer.",
            viewModelAudioSource.contains("SpeakerGuardSession(")
        )
    }

    @Test
    fun foregroundServiceOwnsCaptureSessionOnlyAfterExplicitStartAction() {
        val serviceSource = File("src/main/java/ro/sigurscan/app/SpeakerGuardForegroundService.kt").readText()

        assertTrue(serviceSource.contains("ACTION_START_CAPTURE"))
        assertTrue(serviceSource.contains("ACTION_STOP_CAPTURE"))
        assertTrue(serviceSource.contains("SpeakerGuardSession("))
        assertTrue(
            "The service must start foreground capture with microphone type, not just a prompt notification.",
            serviceSource.contains("FOREGROUND_SERVICE_TYPE_MICROPHONE") ||
                serviceSource.contains("ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE")
        )
        assertTrue(
            "Prompt action must stay separated from capture action so call screening cannot start the mic before consent.",
            serviceSource.contains("ACTION_SHOW_CALL_PROMPT") &&
                serviceSource.contains("ACTION_START_CAPTURE")
        )
    }

    @Test
    fun foregroundServiceEventsReplayLatestUpdateForActivityRebind() {
        val serviceSource = File("src/main/java/ro/sigurscan/app/SpeakerGuardForegroundService.kt").readText()

        assertTrue(
            "Live-call updates must replay the latest state so Activity recreation behind the dialer does not lose the current verdict.",
            serviceSource.contains("MutableSharedFlow<SpeakerGuardUpdate>(replay = 1")
        )
        assertTrue(
            "Fresh sessions must clear replayed STOPPED/error states before starting capture.",
            serviceSource.contains("fun clear()")
        )
    }

    @Test
    fun speakerGuardSessionDoesNotBlockAsrLoopOnSemanticReview() {
        val sessionSource = File("src/main/java/ro/sigurscan/app/SpeakerGuardSession.kt").readText()

        assertFalse(
            "The ASR loop must not await semantic review before publishing the local result.",
            sessionSource.contains("val semanticResult = rawResult.withSemanticReview()")
        )
        assertFalse(
            "Semantic review must not be called inside LocalAsrResult.withSemanticReview() as an awaited step in the ASR loop.",
            sessionSource.contains("private suspend fun LocalAsrResult.withSemanticReview()")
        )
        assertTrue(
            "Semantic review should be launched as a fire-and-update path after the local ASR verdict is emitted.",
            sessionSource.contains("launchSemanticReview(")
        )
    }

    @Test
    fun speakerGuardSessionEmitsHeardVoicePhaseFromLocalAudioLevel() {
        val sessionSource = File("src/main/java/ro/sigurscan/app/SpeakerGuardSession.kt").readText()

        assertTrue(
            "The user needs immediate proof that Urechea hears voice before Whisper finishes.",
            sessionSource.contains("HEARD_VOICE")
        )
        assertTrue(
            "Voice feedback must be based on local audio energy/RMS, not on a completed ASR transcript.",
            sessionSource.contains("hasVoiceEnergy(")
        )
    }
}
