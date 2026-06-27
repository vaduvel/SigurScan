package ro.sigurscan.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.math.abs

class AudioFileDecoderTest {
    @Test
    fun resamplerDownmixesStereoBeforeWhisper() {
        val source = shortArrayOf(
            100, 300,
            200, 400,
            300, 500
        )

        val mono = Pcm16Resampler.toMono16k(
            interleavedPcm16 = source,
            sourceSampleRateHz = 16_000,
            sourceChannelCount = 2
        )

        assertEquals(listOf(200, 300, 400), mono.map { it.toInt() })
    }

    @Test
    fun resamplerUsesLinearInterpolationForNonIntegerVoiceNoteRates() {
        val source = ShortArray(10) { (it * 1_000).toShort() }

        val mono = Pcm16Resampler.toMono16k(
            interleavedPcm16 = source,
            sourceSampleRateHz = 44_100,
            sourceChannelCount = 1
        )

        assertTrue("Expected at least four output frames for this fixture.", mono.size >= 4)
        assertTrue(
            "44.1kHz to 16kHz must interpolate between frames, not snap to the lower sample.",
            abs(mono[1].toInt() - 2_756) <= 3
        )
    }
}
