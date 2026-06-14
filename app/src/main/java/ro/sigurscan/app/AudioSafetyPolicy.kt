package ro.sigurscan.app

data class AudioCaptureDecision(
    val allowed: Boolean,
    val reasonCodes: List<String>
)

object AudioSafetyPolicy {
    fun canStartCapture(
        explicitConsent: Boolean,
        modelAvailable: Boolean,
        privacyDisclosureAccepted: Boolean,
        featureFlagEnabled: Boolean
    ): AudioCaptureDecision {
        val reasons = mutableListOf<String>()
        if (!featureFlagEnabled) reasons += "feature_flag_disabled"
        if (!explicitConsent) reasons += "explicit_consent_missing"
        if (!privacyDisclosureAccepted) reasons += "privacy_disclosure_missing"
        if (!modelAvailable) reasons += "asr_model_missing"
        return AudioCaptureDecision(
            allowed = reasons.isEmpty(),
            reasonCodes = reasons
        )
    }
}

object AudioModelPackagePolicy {
    val requiredFiles = setOf(
        "model-manifest.json",
        "am/final.mdl",
        "conf/mfcc.conf",
        "conf/model.conf",
        "graph/HCLG.fst",
        "graph/words.txt"
    )

    fun isComplete(existingFiles: Set<String>): Boolean {
        return requiredFiles.all(existingFiles::contains)
    }
}
