package ro.sigurscan.app

import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class SpeakerGuardCallPromptActivityContractTest {
    private val source = File("src/main/java/ro/sigurscan/app/SpeakerGuardCallPromptActivity.kt")
        .takeIf { it.exists() }
        ?.readText()
        .orEmpty()

    @Test
    fun callPromptActivityCanSurfaceWhilePhoneIsLockedOrRinging() {
        assertTrue(
            "Call prompt Activity must opt into lock-screen/ringing visibility without SYSTEM_ALERT_WINDOW.",
            source.contains("setShowWhenLocked(true)") &&
                source.contains("setTurnScreenOn(true)") &&
                source.contains("WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON")
        )
    }

    @Test
    fun callPromptActivityKeepsPrimaryPromptAwayFromIncomingCallBanner() {
        assertTrue(
            "The prompt card must be anchored low so the system incoming-call banner remains visible/tappable.",
            source.contains("Alignment.BottomCenter") &&
                source.contains("statusBarsPadding()") &&
                source.contains("navigationBarsPadding()")
        )
    }

    @Test
    fun callPromptActivityStartsSpeakerGuardOnlyAfterExplicitConsent() {
        assertTrue(
            "The call prompt must route to the existing explicit-consent autostart path only after the user taps.",
            source.contains("sigurscan://speaker-guard?autostart=1&source=call_prompt_activity") &&
                source.contains("onClick = { startSpeakerGuard() }")
        )
    }
}
