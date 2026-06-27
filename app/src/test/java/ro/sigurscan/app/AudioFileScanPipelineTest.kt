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
                    transcript = "BNR spune ca s-a facut un credit pe numele tau si trebuie sa muti banii intr-un cont sigur"
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

    private class FakeWhisperRuntime(
        override val available: Boolean = true,
        private val transcript: String = "salut"
    ) : WhisperCppNativeRuntime {
        override fun transcribe(request: LocalAsrRequest): String = transcript
    }
}
