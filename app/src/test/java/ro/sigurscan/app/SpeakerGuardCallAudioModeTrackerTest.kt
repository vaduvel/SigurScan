package ro.sigurscan.app

import android.media.AudioManager
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SpeakerGuardCallAudioModeTrackerTest {
    @Test
    fun normalAudioBeforeAnyCallDoesNotStopCapture() {
        val tracker = SpeakerGuardCallAudioModeTracker(idleConfirmationsRequired = 2)

        assertFalse(tracker.shouldStopForMode(AudioManager.MODE_NORMAL))
        assertFalse(tracker.shouldStopForMode(AudioManager.MODE_NORMAL))
    }

    @Test
    fun callAudioReturningToNormalStopsAfterConfirmation() {
        val tracker = SpeakerGuardCallAudioModeTracker(idleConfirmationsRequired = 2)

        assertFalse(tracker.shouldStopForMode(AudioManager.MODE_IN_CALL))
        assertFalse(tracker.shouldStopForMode(AudioManager.MODE_NORMAL))
        assertTrue(tracker.shouldStopForMode(AudioManager.MODE_NORMAL))
    }

    @Test
    fun callAudioFlapResetsIdleConfirmation() {
        val tracker = SpeakerGuardCallAudioModeTracker(idleConfirmationsRequired = 2)

        assertFalse(tracker.shouldStopForMode(AudioManager.MODE_IN_COMMUNICATION))
        assertFalse(tracker.shouldStopForMode(AudioManager.MODE_NORMAL))
        assertFalse(tracker.shouldStopForMode(AudioManager.MODE_IN_CALL))
        assertFalse(tracker.shouldStopForMode(AudioManager.MODE_NORMAL))
        assertTrue(tracker.shouldStopForMode(AudioManager.MODE_NORMAL))
    }
}
