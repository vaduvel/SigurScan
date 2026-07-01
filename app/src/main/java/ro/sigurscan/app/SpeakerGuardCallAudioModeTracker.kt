package ro.sigurscan.app

import android.media.AudioManager

internal class SpeakerGuardCallAudioModeTracker(
    private val idleConfirmationsRequired: Int = DEFAULT_IDLE_CONFIRMATIONS_REQUIRED
) {
    private var observedCallAudio = false
    private var idleConfirmations = 0

    fun shouldStopForMode(mode: Int): Boolean {
        if (isCallAudioMode(mode)) {
            observedCallAudio = true
            idleConfirmations = 0
            return false
        }
        if (!observedCallAudio) return false

        idleConfirmations += 1
        return idleConfirmations >= idleConfirmationsRequired
    }

    companion object {
        private const val DEFAULT_IDLE_CONFIRMATIONS_REQUIRED = 2

        fun isCallAudioMode(mode: Int): Boolean {
            return mode == AudioManager.MODE_IN_CALL ||
                mode == AudioManager.MODE_IN_COMMUNICATION
        }
    }
}
