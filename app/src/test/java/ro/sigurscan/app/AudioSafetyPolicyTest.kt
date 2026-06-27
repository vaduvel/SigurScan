package ro.sigurscan.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class AudioSafetyPolicyTest {
    @Test
    fun audioCaptureIsBlockedByDefault() {
        val decision = AudioSafetyPolicy.canStartCapture(
            explicitConsent = false,
            modelAvailable = false,
            privacyDisclosureAccepted = false,
            featureFlagEnabled = false,
            microphonePermissionGranted = false
        )

        assertFalse(decision.allowed)
        assertTrue(decision.reasonCodes.contains("feature_flag_disabled"))
    }

    @Test
    fun audioCaptureRequiresAllSafetyPreconditions() {
        val decision = AudioSafetyPolicy.canStartCapture(
            explicitConsent = true,
            modelAvailable = true,
            nativeRuntimeAvailable = true,
            privacyDisclosureAccepted = true,
            featureFlagEnabled = true,
            microphonePermissionGranted = true
        )

        assertTrue(decision.allowed)
    }

    @Test
    fun modelWithoutWhisperNativeRuntimeStillBlocksCapture() {
        val decision = AudioSafetyPolicy.canStartCapture(
            explicitConsent = true,
            modelAvailable = true,
            nativeRuntimeAvailable = false,
            privacyDisclosureAccepted = true,
            featureFlagEnabled = true,
            microphonePermissionGranted = true
        )

        assertFalse(decision.allowed)
        assertTrue(decision.reasonCodes.contains("asr_native_runtime_missing"))
    }

    @Test
    fun explicitConsentAloneIsNotEnough() {
        val decision = AudioSafetyPolicy.canStartCapture(
            explicitConsent = true,
            modelAvailable = false,
            privacyDisclosureAccepted = true,
            featureFlagEnabled = true,
            microphonePermissionGranted = true
        )

        assertFalse(decision.allowed)
        assertTrue(decision.reasonCodes.contains("asr_model_missing"))
    }

    @Test
    fun offlineModelWithoutDisclosureStillBlocksCapture() {
        val decision = AudioSafetyPolicy.canStartCapture(
            explicitConsent = true,
            modelAvailable = true,
            privacyDisclosureAccepted = false,
            featureFlagEnabled = true,
            microphonePermissionGranted = true
        )

        assertFalse(decision.allowed)
        assertTrue(decision.reasonCodes.contains("privacy_disclosure_missing"))
    }

    @Test
    fun microphonePermissionIsRequiredForSpeakerGuardCapture() {
        val decision = AudioSafetyPolicy.canStartCapture(
            explicitConsent = true,
            modelAvailable = true,
            nativeRuntimeAvailable = true,
            privacyDisclosureAccepted = true,
            featureFlagEnabled = true,
            microphonePermissionGranted = false
        )

        assertFalse(decision.allowed)
        assertTrue(decision.reasonCodes.contains("microphone_permission_missing"))
    }

    @Test
    fun randomAssetDirectoryCannotMasqueradeAsAnAsrModel() {
        val modelReady = AudioModelPackagePolicy.isComplete(
            existingFiles = setOf("README.txt", "placeholder.bin")
        )

        assertFalse(modelReady)
    }

    @Test
    fun whisperModelPackageRequiresManifestAndModelBinary() {
        val modelReady = AudioModelPackagePolicy.isComplete(
            existingFiles = setOf(
                "model-manifest.json",
                "ggml-model.bin"
            )
        )

        assertTrue(modelReady)
    }

    @Test
    fun voskDirectoryCannotMasqueradeAsWhisperModel() {
        val modelReady = AudioModelPackagePolicy.isComplete(
            existingFiles = setOf(
                "model-manifest.json",
                "am/final.mdl",
                "conf/mfcc.conf",
                "conf/model.conf",
                "graph/HCLG.fst",
                "graph/words.txt"
            )
        )

        assertFalse(modelReady)
    }

    @Test
    fun whisperManifestMustDeclareRomanianWhisperCppRuntime() {
        val manifest = AudioModelPackagePolicy.parseManifest(
            """
            {
              "engine": "whisper.cpp",
              "model_id": "ggml-base-q5_0",
              "language": "ro",
              "sample_rate_hz": 16000,
              "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }
            """.trimIndent()
        )

        assertTrue(manifest.valid)
        assertEquals("ggml-base-q5_0", manifest.modelId)
    }

    @Test
    fun whisperManifestRejectsWrongLanguageOrMissingChecksum() {
        val manifest = AudioModelPackagePolicy.parseManifest(
            """
            {
              "engine": "whisper.cpp",
              "model_id": "ggml-tiny-en",
              "language": "en",
              "sample_rate_hz": 16000
            }
            """.trimIndent()
        )

        assertFalse(manifest.valid)
        assertTrue(manifest.reasonCodes.contains("language_not_romanian"))
        assertTrue(manifest.reasonCodes.contains("sha256_missing_or_invalid"))
    }

    @Test
    fun instrumentedWhisperRuntimeTestDoesNotLogRawTranscript() {
        val source = File("src/androidTest/java/ro/sigurscan/app/WhisperNativeRuntimeInstrumentedTest.kt")
            .readText()

        assertFalse(source.contains("transcript=${'$'}{result.transcript}"))
        assertFalse(source.contains("assertTrue(result.transcript,"))
    }

    @Test
    fun nativeWhisperBridgeDoesNotReturnTranscriptWithNewStringUtf() {
        val source = File("src/main/cpp/sigurscan_whisper_jni.cpp").readText()

        assertFalse(source.contains("NewStringUTF(transcript.c_str())"))
    }
}
