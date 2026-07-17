package ro.sigurscan.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AudioWindowingTest {
    @Test
    fun shortAudioIsCoveredCompletelyWithContiguousWindows() {
        val plan = AudioWindowPlanner.plan(sourceDurationMs = 75_000L)

        assertEquals(
            listOf(0L to 30_000L, 30_000L to 60_000L, 60_000L to 75_000L),
            plan.windows.map { it.startMs to it.endMs }
        )
        assertEquals(AudioCoverageStatus.COMPLETE, plan.status)
        assertEquals(1.0, plan.sourceCoverageRatio ?: 0.0, 0.0001)
    }

    @Test
    fun longAudioSamplesBeginningMiddleAndEndWithinBudget() {
        val plan = AudioWindowPlanner.plan(sourceDurationMs = 600_000L)

        assertEquals(6, plan.windows.size)
        assertEquals(0L, plan.windows.first().startMs)
        assertEquals(600_000L, plan.windows.last().endMs)
        assertEquals(180_000L, plan.plannedDurationMs)
        assertEquals(AudioCoverageStatus.PARTIAL, plan.status)
        assertEquals(0.30, plan.sourceCoverageRatio ?: 0.0, 0.0001)
        assertTrue(plan.windows.zipWithNext().all { (left, right) -> left.endMs <= right.startMs })
    }

    @Test
    fun voiceGateRejectsSilenceButKeepsQuietSpeakerVoice() {
        val silence = ShortArray(16_000)
        val quietSpeakerVoice = ShortArray(16_000).also { samples ->
            for (index in samples.indices step 160) {
                samples[index] = 1_100
                if (index + 1 < samples.size) samples[index + 1] = (-1_100).toShort()
            }
        }

        assertFalse(AudioVoiceActivityDetector.hasVoice(silence))
        assertTrue(AudioVoiceActivityDetector.hasVoice(quietSpeakerVoice))
    }

    @Test
    fun voiceWindowPolicyPeriodicallySamplesLowEnergyWindowsForRecall() {
        val silence = AudioVoiceActivity(
            activeFrames = 0,
            totalFrames = 50,
            meanAbsoluteAmplitude = 0.0,
            peak = 0,
            hasVoice = false
        )
        var consecutiveSkips = 0

        repeat(3) {
            val decision = AudioVoiceWindowPolicy.decide(silence, consecutiveSkips)
            assertFalse(decision.shouldTranscribe)
            assertFalse(decision.usedRecallProbe)
            consecutiveSkips = decision.nextConsecutiveSkips
        }

        val recallProbe = AudioVoiceWindowPolicy.decide(silence, consecutiveSkips)

        assertTrue(recallProbe.shouldTranscribe)
        assertTrue(recallProbe.usedRecallProbe)
        assertEquals(0, recallProbe.nextConsecutiveSkips)
    }

    @Test
    fun semanticSamplerKeepsSignalsFromBeginningMiddleAndEnd() {
        val windows = listOf(
            AudioTranscriptWindow(0L, 30_000L, "START_MARKER " + "a".repeat(1_200)),
            AudioTranscriptWindow(285_000L, 315_000L, "MIDDLE_MARKER " + "b".repeat(1_200)),
            AudioTranscriptWindow(570_000L, 600_000L, "END_MARKER muta banii in contul sigur " + "c".repeat(1_200))
        )

        val sampled = AudioSemanticContextSampler.sample(windows, maxChars = 2_500)

        assertTrue(sampled.text.length <= 2_500)
        assertTrue(sampled.text.contains("START_MARKER"))
        assertTrue(sampled.text.contains("MIDDLE_MARKER"))
        assertTrue(sampled.text.contains("END_MARKER"))
        assertTrue(sampled.truncated)
        assertEquals(windows.sumOf { it.transcript.length }, sampled.totalChars)
    }
}
