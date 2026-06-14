package ro.sigurscan.app

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AudioSafetyPolicyTest {
    @Test
    fun audioCaptureIsBlockedByDefault() {
        val decision = AudioSafetyPolicy.canStartCapture(
            explicitConsent = false,
            modelAvailable = false,
            privacyDisclosureAccepted = false,
            featureFlagEnabled = false
        )

        assertFalse(decision.allowed)
        assertTrue(decision.reasonCodes.contains("feature_flag_disabled"))
    }

    @Test
    fun audioCaptureRequiresAllSafetyPreconditions() {
        val decision = AudioSafetyPolicy.canStartCapture(
            explicitConsent = true,
            modelAvailable = true,
            privacyDisclosureAccepted = true,
            featureFlagEnabled = true
        )

        assertTrue(decision.allowed)
    }

    @Test
    fun explicitConsentAloneIsNotEnough() {
        val decision = AudioSafetyPolicy.canStartCapture(
            explicitConsent = true,
            modelAvailable = false,
            privacyDisclosureAccepted = true,
            featureFlagEnabled = true
        )

        assertFalse(decision.allowed)
        assertTrue(decision.reasonCodes.contains("asr_model_missing"))
    }
}
