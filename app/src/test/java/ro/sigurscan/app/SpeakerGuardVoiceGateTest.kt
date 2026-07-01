package ro.sigurscan.app

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.assertEquals
import org.junit.Test

class SpeakerGuardVoiceGateTest {
    @Test
    fun liveCallAsrUsesShorterWindowsForFasterFirstVerdict() {
        assertEquals(3, SpeakerGuardSession.CHUNK_SECONDS)
    }

    @Test
    fun silentChunksAreNotSentToWhisper() {
        assertFalse(SpeakerGuardVoiceGate.shouldProcessChunk(ShortArray(16_000 * 3) { 0 }))
    }

    @Test
    fun voicedChunksAreSentToWhisper() {
        val voiced = ShortArray(16_000 * 3) { index ->
            if (index % 80 < 40) 1400 else (-1400)
        }

        assertTrue(SpeakerGuardVoiceGate.shouldProcessChunk(voiced))
    }

    @Test
    fun sparseButAudibleSpeakerVoiceIsStillSentToWhisper() {
        val speakerLeak = ShortArray(16_000 * 3) { index ->
            if (index % 1200 < 120) 2600 else 0
        }

        assertTrue(SpeakerGuardVoiceGate.shouldProcessChunk(speakerLeak))
    }

    @Test
    fun lowVolumeSpeakerVoiceIsStillSentToWhisper() {
        val quietSpeaker = ShortArray(16_000 * 3) { index ->
            when (index % 160) {
                in 0..79 -> 420
                else -> -420
            }
        }

        assertTrue(SpeakerGuardVoiceGate.shouldProcessChunk(quietSpeaker))
    }

    @Test
    fun lowLevelRoomNoiseIsIgnored() {
        val roomNoise = ShortArray(16_000 * 3) { index ->
            ((index * 37) % 120 - 60).toShort()
        }

        assertFalse(SpeakerGuardVoiceGate.shouldProcessChunk(roomNoise))
    }
}
