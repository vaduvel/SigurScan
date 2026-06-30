package ro.sigurscan.app

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.math.abs

class AudioFileDecoderTest {
    @Test
    fun decoderKeepsAssetDescriptorOpenAndUsesOffsetLength() {
        val source = File("src/main/java/ro/sigurscan/app/AudioFileDecoder.kt").readText()

        assertTrue(
            "Shared audio content URIs can be backed by a file slice; MediaExtractor must receive offset/length.",
            source.contains("openAssetFileDescriptor(uri, \"r\")") &&
                source.contains("extractor.setDataSource(") &&
                source.contains("assetDescriptor.startOffset") &&
                source.contains("assetDescriptor.length")
        )
        assertFalse(
            "Do not close the descriptor immediately after setDataSource; keep it open while MediaExtractor decodes.",
            source.contains("openFileDescriptor(uri, \"r\")?.use")
        )
    }

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
