package ro.sigurscan.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AudioFileScanPipelineTest {
    @Test
    fun sharedAudioPcmFeedsWhisperAndLocalEvidenceWithoutRetainingRawAudio() {
        val pipeline = AudioFileScanPipeline(
            asrEngine = WhisperCppAsrEngine(
                nativeRuntime = FakeWhisperRuntime(
                    transcript = "BNR spune ca s-a facut un credit pe numele tau si trebuie sa muti banii in RO49AAAA1B31007593840000. Codul este 123456."
                )
            )
        )

        val result = pipeline.scan(
            decodedAudio = DecodedAudioFile(
                pcm16Mono = ShortArray(16_000),
                sampleRateHz = 16_000
            ),
            modelPath = "/local/ggml-model.bin"
        )

        assertTrue(result.success)
        assertEquals("import_audio_file", result.inputKind)
        assertEquals("audio_share", result.channel)
        assertEquals(AudioEvidenceVerdict.DANGEROUS, result.evidence?.verdict)
        assertEquals(0, result.rawAudioBytesRetained)
        assertFalse(result.transcriptForTelemetry.contains("BNR"))
        assertTrue(result.redactedTranscriptForSemanticReview.contains("[iban]"))
        assertTrue(result.redactedTranscriptForSemanticReview.contains("[cod]"))
        assertFalse(result.redactedTranscriptForSemanticReview.contains("RO49AAAA1B31007593840000"))
        assertFalse(result.redactedTranscriptForSemanticReview.contains("123456"))
    }

    @Test
    fun sharedAudioPipelineFailsClosedWhenWhisperCannotTranscribe() {
        val pipeline = AudioFileScanPipeline(
            asrEngine = WhisperCppAsrEngine(
                nativeRuntime = FakeWhisperRuntime(available = false)
            )
        )

        val result = pipeline.scan(
            decodedAudio = DecodedAudioFile(
                pcm16Mono = ShortArray(16_000),
                sampleRateHz = 16_000
            ),
            modelPath = "/local/ggml-model.bin"
        )

        assertFalse(result.success)
        assertEquals("whisper_native_unavailable", result.reasonCode)
        assertEquals(AudioEvidenceVerdict.UNVERIFIED, result.evidence?.verdict)
        assertEquals(0, result.rawAudioBytesRetained)

        val assessment = result.toOfflineAssessment("voice-note.m4a")
        assertEquals("Neverificat", assessment.family)
        assertEquals("unknown", assessment.riskLevel)
        assertEquals("Neverificat", assessment.reputationVerdict)
        assertEquals(0, assessment.riskScore)
    }

    @Test
    fun scamInFinalSampledWindowEscalatesAndIsIncludedInSemanticContext() {
        val runtime = SequenceWhisperRuntime(
            listOf(
                "Discutie generala despre program.",
                "Confirmam detaliile neutre ale conversatiei.",
                "BNR spune ca s-a facut un credit pe numele tau si trebuie sa muti banii in RO49AAAA1B31007593840000. Codul este 123456."
            )
        )
        val pipeline = AudioFileScanPipeline(
            asrEngine = WhisperCppAsrEngine(nativeRuntime = runtime)
        )
        val windows = listOf(
            decodedWindow(0L, 30_000L),
            decodedWindow(285_000L, 315_000L),
            decodedWindow(570_000L, 600_000L)
        )

        val result = pipeline.scan(
            decodedAudio = DecodedAudioFile(
                pcm16Mono = ShortArray(0),
                sampleRateHz = 16_000,
                durationMs = 90_000L,
                sourceDurationMs = 600_000L,
                windows = windows,
                plannedCoverage = AudioCoverageMetadata(
                    sourceDurationMs = 600_000L,
                    plannedDurationMs = 90_000L,
                    decodedDurationMs = 90_000L,
                    sourceCoverageRatio = 0.15,
                    status = AudioCoverageStatus.PARTIAL,
                    windowsPlanned = 3,
                    windowsDecoded = 3
                )
            ),
            modelPath = "/local/ggml-model.bin"
        )

        assertTrue(result.success)
        assertEquals(3, runtime.calls)
        assertEquals(AudioEvidenceVerdict.DANGEROUS, result.evidence?.verdict)
        assertTrue(result.redactedTranscriptForSemanticReview.contains("BNR"))
        assertTrue(result.redactedTranscriptForSemanticReview.contains("[iban]"))
        assertTrue(result.coverage.reasonCodes.contains("audio_partial_coverage"))
        assertEquals(3, result.coverage.windowsTranscribed)
    }

    @Test
    fun silentWindowsAreSkippedWithoutHidingAllAudioBehindVad() {
        val runtime = SequenceWhisperRuntime(listOf("mesaj neutru"))
        val pipeline = AudioFileScanPipeline(
            asrEngine = WhisperCppAsrEngine(nativeRuntime = runtime)
        )

        val result = pipeline.scan(
            decodedAudio = DecodedAudioFile(
                pcm16Mono = ShortArray(0),
                sampleRateHz = 16_000,
                sourceDurationMs = 60_000L,
                windows = listOf(
                    DecodedAudioWindow(ShortArray(16_000), 0L, 30_000L),
                    decodedWindow(30_000L, 60_000L)
                ),
                plannedCoverage = AudioCoverageMetadata(
                    sourceDurationMs = 60_000L,
                    plannedDurationMs = 60_000L,
                    decodedDurationMs = 60_000L,
                    sourceCoverageRatio = 1.0,
                    status = AudioCoverageStatus.COMPLETE,
                    windowsPlanned = 2,
                    windowsDecoded = 2
                )
            ),
            modelPath = "/local/ggml-model.bin"
        )

        assertTrue(result.success)
        assertEquals(1, runtime.calls)
        assertEquals(1, result.coverage.windowsSkippedByVad)
        assertEquals(1, result.coverage.windowsTranscribed)
        assertEquals(0.5, result.coverage.sourceCoverageRatio ?: 0.0, 0.0001)
        assertEquals(AudioCoverageStatus.PARTIAL, result.coverage.status)
        assertTrue(result.coverage.reasonCodes.contains("audio_partial_coverage"))
    }

    @Test
    fun allLowEnergyWindowsStillGetOneRecallSafeTranscription() {
        val runtime = SequenceWhisperRuntime(
            listOf("Sunt de la banca. Spune codul primit prin SMS.")
        )
        val pipeline = AudioFileScanPipeline(
            asrEngine = WhisperCppAsrEngine(nativeRuntime = runtime)
        )

        val result = pipeline.scan(
            decodedAudio = DecodedAudioFile(
                pcm16Mono = ShortArray(0),
                sampleRateHz = 16_000,
                sourceDurationMs = 60_000L,
                windows = listOf(
                    DecodedAudioWindow(ShortArray(16_000), 0L, 30_000L),
                    DecodedAudioWindow(ShortArray(16_000), 30_000L, 60_000L)
                ),
                plannedCoverage = AudioCoverageMetadata(
                    sourceDurationMs = 60_000L,
                    plannedDurationMs = 60_000L,
                    decodedDurationMs = 60_000L,
                    sourceCoverageRatio = 1.0,
                    status = AudioCoverageStatus.COMPLETE,
                    windowsPlanned = 2,
                    windowsDecoded = 2
                )
            ),
            modelPath = "/local/ggml-model.bin"
        )

        assertTrue(result.success)
        assertEquals(1, runtime.calls)
        assertTrue(result.coverage.vadFallbackUsed)
        assertEquals(0.5, result.coverage.sourceCoverageRatio ?: 0.0, 0.0001)
        assertTrue(result.coverage.reasonCodes.contains("audio_vad_recall_fallback"))
        assertEquals(AudioEvidenceVerdict.DANGEROUS, result.evidence?.verdict)
    }

    private class FakeWhisperRuntime(
        override val available: Boolean = true,
        private val transcript: String = "salut"
    ) : WhisperCppNativeRuntime {
        override fun transcribe(request: LocalAsrRequest): String = transcript
    }

    private class SequenceWhisperRuntime(
        private val transcripts: List<String>
    ) : WhisperCppNativeRuntime {
        override val available: Boolean = true
        var calls: Int = 0
            private set

        override fun transcribe(request: LocalAsrRequest): String {
            val index = calls.coerceAtMost(transcripts.lastIndex)
            calls += 1
            return transcripts[index]
        }
    }

    private fun decodedWindow(startMs: Long, endMs: Long): DecodedAudioWindow {
        return DecodedAudioWindow(
            pcm16Mono = ShortArray(16_000) { index -> if (index % 80 == 0) 1_200 else 220 },
            startMs = startMs,
            endMs = endMs
        )
    }
}
