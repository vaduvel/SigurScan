package ro.sigurscan.app

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class SpeakerGuardForegroundServiceContractTest {
    @Test
    fun viewModelDelegatesManualListenerCaptureToMicrophoneForegroundService() {
        val viewModelAudioSource = File("src/main/java/ro/sigurscan/app/ScannerViewModelAudio.kt").readText()

        assertTrue(
            "Starting the manual Urechea listener must enter the microphone foreground service after consent.",
            viewModelAudioSource.contains("SpeakerGuardForegroundService.startCapture(")
        )
        assertTrue(
            "Stopping the manual Urechea listener must explicitly stop the microphone foreground service.",
            viewModelAudioSource.contains("SpeakerGuardForegroundService.stopCapture(")
        )
        assertFalse(
            "The ViewModel must not own AudioRecord capture in viewModelScope; Activity recreation must not kill the listener.",
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
    fun callPromptEntryIsSeparatelyGatedFromManualListenerCapture() {
        val serviceSource = File("src/main/java/ro/sigurscan/app/SpeakerGuardForegroundService.kt").readText()
        val sharedIntentSource = File("src/main/java/ro/sigurscan/app/SharedIntentHandling.kt").readText()

        assertTrue(
            "Automatic call prompts must require the dedicated live-call feature flag.",
            serviceSource.contains("BuildConfig.SIGURSCAN_ENABLE_LIVE_CALL")
        )
        assertTrue(
            "The call-screening autostart deep link must not start the microphone in V1.",
            sharedIntentSource.contains("autoStartSpeakerGuard") &&
                sharedIntentSource.contains("BuildConfig.SIGURSCAN_ENABLE_LIVE_CALL")
        )
        assertTrue(
            "Manual listener capture must remain available independently through ACTION_START_CAPTURE.",
            serviceSource.contains("ACTION_START_CAPTURE") &&
                serviceSource.contains("fun startCapture(")
        )
    }

    @Test
    fun v1ListenerCopyRequiresASecondPhoneAndUsesItsOwnSemanticChannel() {
        val cardSource = File("src/main/java/ro/sigurscan/app/RadarCards.kt").readText()
        val sessionSource = File("src/main/java/ro/sigurscan/app/SpeakerGuardSession.kt").readText()
        val serviceSource = File("src/main/java/ro/sigurscan/app/SpeakerGuardForegroundService.kt").readText()

        assertTrue(
            "V1 must explain that Urechea listens to a conversation played from another phone.",
            cardSource.contains("Pe alt telefon") &&
                sessionSource.contains("celălalt telefon")
        )
        assertTrue(
            "Manual listener telemetry must not be mislabeled as same-phone live-call traffic.",
            serviceSource.contains("channel = \"speaker_listener\"")
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
    fun foregroundServiceAudioSemanticClientUsesFullBackendAuth() {
        val serviceSource = File("src/main/java/ro/sigurscan/app/SpeakerGuardForegroundService.kt").readText()

        assertTrue(
            "Live-call Mistral must use the same backend client path as normal scans so Play Integrity enforcement does not kill Urechea.",
            serviceSource.contains("buildSigurScanApiClient(")
        )
        assertTrue(
            "Live-call semantic review must send a stable client instance id.",
            serviceSource.contains("clientInstanceId = clientInstanceId")
        )
        assertTrue(
            "Live-call semantic review must attach Play Integrity tokens when enabled.",
            serviceSource.contains("integrityTokenProvider = { playIntegrityTokenProvider.currentToken() }")
        )
    }

    @Test
    fun viewModelClearDoesNotStopLiveCaptureOwnedByForegroundService() {
        val viewModelSource = File("src/main/java/ro/sigurscan/app/ScannerViewModel.kt").readText()
        val onClearedBody = Regex(
            """override fun onCleared\(\) \{([\s\S]*?)\n    \}"""
        ).find(viewModelSource)?.groupValues?.get(1).orEmpty()

        assertFalse(
            "Activity/ViewModel recycling behind the dialer must not stop the microphone foreground service.",
            onClearedBody.contains("SpeakerGuardForegroundService.stopCapture(")
        )
        assertTrue(
            "onCleared should only detach update collection; explicit UI/call-end paths own stopCapture.",
            onClearedBody.contains("speakerGuardServiceUpdatesJob?.cancel()")
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

    @Test
    fun audioSemanticReviewerDoesNotSilentlySwallowBackendFailures() {
        val reviewerSource = File("src/main/java/ro/sigurscan/app/AudioSemanticReviewFusion.kt").readText()
        val sessionSource = File("src/main/java/ro/sigurscan/app/SpeakerGuardSession.kt").readText()

        assertTrue(
            "Audio semantic review must return a diagnostic outcome, not just null, when backend calls fail.",
            reviewerSource.contains("AudioSemanticReviewOutcome")
        )
        assertFalse(
            "BackendAudioSemanticReviewer must not hide timeout/HTTP failures behind runCatching().getOrNull().",
            reviewerSource.contains("}.getOrNull()")
        )
        assertTrue(
            "Listener session must use diagnostic semantic review so provider failures have a reason code.",
            sessionSource.contains("semanticReviewer.review(")
        )
    }

    @Test
    fun sharedAudioIntakeUsesSemanticDiagnosticsAndPrivacySafeTelemetry() {
        val sharedIntakeSource = File("src/main/java/ro/sigurscan/app/ScannerViewModelSharedIntake.kt").readText()

        assertTrue(
            "Shared audio files must use diagnostic semantic review so a Neverificat result has a concrete backend/Mistral reason.",
            sharedIntakeSource.contains("val semanticOutcome") &&
                sharedIntakeSource.contains(".review(") &&
                sharedIntakeSource.contains("semanticOutcome.reasonCode")
        )
        assertTrue(
            "Shared audio telemetry must record whether semantic review was received without logging raw transcript or audio.",
            sharedIntakeSource.contains("semanticReceived=")
        )
        assertTrue(
            "Shared audio telemetry must record semantic failure reason codes for real-device triage.",
            sharedIntakeSource.contains("semanticReason=")
        )
        assertTrue(
            "Shared audio telemetry must record transcript length only, never transcript content.",
            sharedIntakeSource.contains("transcriptChars=")
        )
    }

    @Test
    fun sharedAudioDebugPreviewIsDebugOnlyRedactedAndBounded() {
        val sharedIntakeSource = File("src/main/java/ro/sigurscan/app/ScannerViewModelSharedIntake.kt").readText()

        assertTrue(
            "Device-grade ASR triage may log a redacted transcript preview only in debug builds.",
            sharedIntakeSource.contains("BuildConfig.DEBUG") &&
                sharedIntakeSource.contains("debugRedactedPreview=")
        )
        assertTrue(
            "The debug preview must use the already-redacted semantic transcript, not raw ASR text.",
            sharedIntakeSource.contains("result.redactedTranscriptForSemanticReview")
        )
        assertTrue(
            "The debug preview must be bounded so device logs cannot contain full conversations.",
            sharedIntakeSource.contains(".take(240)")
        )
        assertFalse(
            "Shared audio debug logs must never preview raw ASR transcript text.",
            sharedIntakeSource.contains("debugRedactedPreview=${'$'}{result.transcript")
        )
    }

    @Test
    fun speakerGuardDebugPreviewIsDebugOnlyRedactedAndBounded() {
        val sessionSource = File("src/main/java/ro/sigurscan/app/SpeakerGuardSession.kt").readText()

        assertTrue(
            "Listener triage may log a redacted ASR preview only in debug builds.",
            sessionSource.contains("BuildConfig.DEBUG") &&
                sessionSource.contains("asr_debug_redacted_preview")
        )
        assertTrue(
            "Live-call debug preview must redact ASR text before logging.",
            sessionSource.contains("AudioTranscriptRedactor.redact(result.transcript)")
        )
        assertTrue(
            "Live-call debug preview must be bounded so logs cannot contain full conversations.",
            sessionSource.contains(".take(160)")
        )
    }

    @Test
    fun sharedIntentIntakeLogsPlanForRealDeviceTriage() {
        val sharedIntentSource = File("src/main/java/ro/sigurscan/app/SharedIntentHandling.kt").readText()

        assertTrue(
            "Shared intent intake must log action/type and resolved plan so share-sheet failures are not silent on real devices.",
            sharedIntentSource.contains("SharedIntentIntake")
        )
        assertTrue(
            "Shared intent intake logs must include stream count for audio/file shares.",
            sharedIntentSource.contains("streamCount=")
        )
        assertTrue(
            "Shared intent intake logs must include autoScan so we know whether audio should start immediately.",
            sharedIntentSource.contains("autoScan=")
        )
    }
}
