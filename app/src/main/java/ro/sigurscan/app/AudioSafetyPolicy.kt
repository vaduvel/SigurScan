package ro.sigurscan.app

import com.google.gson.JsonParser

data class AudioCaptureDecision(
    val allowed: Boolean,
    val reasonCodes: List<String>
)

data class AudioModelManifestValidation(
    val valid: Boolean,
    val modelId: String?,
    val reasonCodes: List<String>
)

object AudioSafetyPolicy {
    fun canStartCapture(
        explicitConsent: Boolean,
        modelAvailable: Boolean,
        nativeRuntimeAvailable: Boolean = false,
        privacyDisclosureAccepted: Boolean,
        featureFlagEnabled: Boolean,
        microphonePermissionGranted: Boolean
    ): AudioCaptureDecision {
        val reasons = mutableListOf<String>()
        if (!featureFlagEnabled) reasons += "feature_flag_disabled"
        if (!explicitConsent) reasons += "explicit_consent_missing"
        if (!privacyDisclosureAccepted) reasons += "privacy_disclosure_missing"
        if (!microphonePermissionGranted) reasons += "microphone_permission_missing"
        if (!modelAvailable) reasons += "asr_model_missing"
        if (!nativeRuntimeAvailable) reasons += "asr_native_runtime_missing"
        return AudioCaptureDecision(
            allowed = reasons.isEmpty(),
            reasonCodes = reasons
        )
    }
}

object AudioModelPackagePolicy {
    const val assetRoot = "asr/whispercpp"
    private const val requiredEngine = "whisper.cpp"
    private const val requiredLanguage = "ro"
    private const val requiredSampleRateHz = 16_000
    private val sha256Pattern = Regex("^[a-fA-F0-9]{64}$")

    val requiredFiles = setOf(
        "model-manifest.json",
        "ggml-model.bin"
    )

    fun isComplete(existingFiles: Set<String>): Boolean {
        return requiredFiles.all(existingFiles::contains)
    }

    fun parseManifest(rawJson: String): AudioModelManifestValidation {
        val reasons = mutableListOf<String>()
        val obj = runCatching {
            JsonParser.parseString(rawJson).asJsonObject
        }.getOrElse {
            return AudioModelManifestValidation(
                valid = false,
                modelId = null,
                reasonCodes = listOf("manifest_json_invalid")
            )
        }

        val engine = obj.string("engine")
        val modelId = obj.string("model_id")
        val language = obj.string("language")
        val sampleRateHz = obj.int("sample_rate_hz")
        val sha256 = obj.string("sha256")

        if (engine != requiredEngine) reasons += "engine_not_whisper_cpp"
        if (modelId.isNullOrBlank()) reasons += "model_id_missing"
        if (language != requiredLanguage) reasons += "language_not_romanian"
        if (sampleRateHz != requiredSampleRateHz) reasons += "sample_rate_not_16000"
        if (sha256 == null || !sha256Pattern.matches(sha256)) {
            reasons += "sha256_missing_or_invalid"
        }

        return AudioModelManifestValidation(
            valid = reasons.isEmpty(),
            modelId = modelId,
            reasonCodes = reasons
        )
    }

    private fun com.google.gson.JsonObject.string(name: String): String? {
        return get(name)?.takeUnless { it.isJsonNull }?.asString?.trim()
    }

    private fun com.google.gson.JsonObject.int(name: String): Int? {
        return runCatching {
            get(name)?.takeUnless { it.isJsonNull }?.asInt
        }.getOrNull()
    }
}
