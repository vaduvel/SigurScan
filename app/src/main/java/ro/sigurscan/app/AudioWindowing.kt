package ro.sigurscan.app

import kotlin.math.abs
import kotlin.math.roundToLong

enum class AudioCoverageStatus(val wireValue: String) {
    COMPLETE("complete"),
    PARTIAL("partial"),
    UNKNOWN("unknown")
}

data class AudioWindowPlan(
    val startMs: Long,
    val endMs: Long
) {
    val durationMs: Long
        get() = (endMs - startMs).coerceAtLeast(0L)
}

data class AudioWindowPlanSet(
    val sourceDurationMs: Long?,
    val windows: List<AudioWindowPlan>,
    val plannedDurationMs: Long,
    val sourceCoverageRatio: Double?,
    val status: AudioCoverageStatus
)

object AudioWindowPlanner {
    const val WINDOW_DURATION_MS = 30_000L
    const val MAX_ANALYSIS_DURATION_MS = 180_000L

    fun plan(sourceDurationMs: Long?): AudioWindowPlanSet {
        val knownDuration = sourceDurationMs?.takeIf { it > 0L }
        if (knownDuration == null) {
            val fallback = AudioWindowPlan(0L, MAX_ANALYSIS_DURATION_MS)
            return AudioWindowPlanSet(
                sourceDurationMs = null,
                windows = listOf(fallback),
                plannedDurationMs = fallback.durationMs,
                sourceCoverageRatio = null,
                status = AudioCoverageStatus.UNKNOWN
            )
        }

        val windows = if (knownDuration <= MAX_ANALYSIS_DURATION_MS) {
            buildList {
                var start = 0L
                while (start < knownDuration) {
                    val end = (start + WINDOW_DURATION_MS).coerceAtMost(knownDuration)
                    add(AudioWindowPlan(start, end))
                    start = end
                }
            }
        } else {
            val count = (MAX_ANALYSIS_DURATION_MS / WINDOW_DURATION_MS).toInt()
            val lastStart = knownDuration - WINDOW_DURATION_MS
            (0 until count).map { index ->
                val fraction = index.toDouble() / (count - 1).toDouble()
                val start = (lastStart * fraction).roundToLong()
                AudioWindowPlan(start, start + WINDOW_DURATION_MS)
            }
        }
        val plannedDuration = windows.sumOf { it.durationMs }
        val ratio = (plannedDuration.toDouble() / knownDuration.toDouble()).coerceIn(0.0, 1.0)
        return AudioWindowPlanSet(
            sourceDurationMs = knownDuration,
            windows = windows,
            plannedDurationMs = plannedDuration,
            sourceCoverageRatio = ratio,
            status = if (plannedDuration >= knownDuration) AudioCoverageStatus.COMPLETE else AudioCoverageStatus.PARTIAL
        )
    }
}

data class DecodedAudioWindow(
    val pcm16Mono: ShortArray,
    val startMs: Long,
    val endMs: Long
) {
    val durationMs: Long
        get() = (endMs - startMs).coerceAtLeast(0L)
}

data class AudioCoverageMetadata(
    val sourceDurationMs: Long? = null,
    val plannedDurationMs: Long = 0L,
    val decodedDurationMs: Long = 0L,
    val transcribedDurationMs: Long = 0L,
    val sourceCoverageRatio: Double? = null,
    val status: AudioCoverageStatus = AudioCoverageStatus.UNKNOWN,
    val windowsPlanned: Int = 0,
    val windowsDecoded: Int = 0,
    val windowsSkippedByVad: Int = 0,
    val windowsTranscribed: Int = 0,
    val windowsFailed: Int = 0,
    val transcriptCharsTotal: Int = 0,
    val transcriptCharsSent: Int = 0,
    val transcriptTruncated: Boolean = false,
    val vadFallbackUsed: Boolean = false
) {
    val reasonCodes: List<String>
        get() = buildList {
            when (status) {
                AudioCoverageStatus.PARTIAL -> add("audio_partial_coverage")
                AudioCoverageStatus.UNKNOWN -> add("audio_unknown_coverage")
                AudioCoverageStatus.COMPLETE -> Unit
            }
            if (windowsFailed > 0) add("audio_window_transcription_failed")
            if (transcriptTruncated) add("audio_semantic_context_sampled")
            if (vadFallbackUsed) add("audio_vad_recall_fallback")
        }
}

data class AudioTranscriptWindow(
    val startMs: Long,
    val endMs: Long,
    val transcript: String
)

data class AudioSemanticContextSample(
    val text: String,
    val totalChars: Int,
    val sentChars: Int,
    val truncated: Boolean
)

object AudioSemanticContextSampler {
    fun sample(
        windows: List<AudioTranscriptWindow>,
        maxChars: Int
    ): AudioSemanticContextSample {
        val clean = windows
            .map { it.copy(transcript = it.transcript.trim()) }
            .filter { it.transcript.isNotBlank() }
        val totalChars = clean.sumOf { it.transcript.length }
        if (clean.isEmpty() || maxChars <= 0) {
            return AudioSemanticContextSample("", totalChars, 0, totalChars > 0)
        }

        val joined = clean.joinToString("\n\n") { it.transcript }
        if (joined.length <= maxChars) {
            return AudioSemanticContextSample(joined, totalChars, joined.length, false)
        }

        val selected = selectStratified(clean, maxChars)
        val separatorCost = ((selected.size - 1).coerceAtLeast(0) * 2)
        val textBudget = (maxChars - separatorCost).coerceAtLeast(selected.size)
        var remaining = textBudget
        val fragments = selected.mapIndexed { index, window ->
            val windowsLeft = selected.size - index
            val budget = (remaining / windowsLeft).coerceAtLeast(1)
            val fragment = clipBothEnds(window.transcript, budget)
            remaining -= fragment.length
            fragment
        }
        val sampled = fragments.joinToString("\n\n").take(maxChars)
        return AudioSemanticContextSample(sampled, totalChars, sampled.length, true)
    }

    private fun selectStratified(
        windows: List<AudioTranscriptWindow>,
        maxChars: Int
    ): List<AudioTranscriptWindow> {
        val maxWindows = (maxChars / 64).coerceAtLeast(1)
        if (windows.size <= maxWindows) return windows
        if (maxWindows == 1) return listOf(windows.first())
        return (0 until maxWindows)
            .map { index ->
                val sourceIndex = ((windows.lastIndex.toDouble() * index) / (maxWindows - 1)).roundToLong().toInt()
                windows[sourceIndex]
            }
            .distinctBy { it.startMs to it.endMs }
    }

    private fun clipBothEnds(text: String, budget: Int): String {
        if (text.length <= budget) return text
        if (budget < 12) return text.take(budget)
        val separator = " ... "
        val remaining = budget - separator.length
        val prefix = (remaining + 1) / 2
        val suffix = remaining - prefix
        return text.take(prefix) + separator + text.takeLast(suffix)
    }
}

data class AudioVoiceActivity(
    val activeFrames: Int,
    val totalFrames: Int,
    val meanAbsoluteAmplitude: Double,
    val peak: Int,
    val hasVoice: Boolean
)

object AudioVoiceActivityDetector {
    private const val FRAME_MILLIS = 20
    private const val MEAN_ABSOLUTE_THRESHOLD = 180.0
    private const val PEAK_THRESHOLD = 900

    fun analyze(
        pcm16Mono: ShortArray,
        sampleRateHz: Int = WhisperCppAsrEngine.REQUIRED_SAMPLE_RATE_HZ
    ): AudioVoiceActivity {
        if (pcm16Mono.isEmpty() || sampleRateHz <= 0) {
            return AudioVoiceActivity(0, 0, 0.0, 0, false)
        }
        val frameSamples = ((sampleRateHz * FRAME_MILLIS) / 1_000).coerceAtLeast(1)
        var activeFrames = 0
        var totalFrames = 0
        var totalAbsolute = 0L
        var peak = 0
        var frameStart = 0
        while (frameStart < pcm16Mono.size) {
            val frameEnd = (frameStart + frameSamples).coerceAtMost(pcm16Mono.size)
            var frameAbsolute = 0L
            var framePeak = 0
            for (index in frameStart until frameEnd) {
                val absolute = abs(pcm16Mono[index].toInt())
                frameAbsolute += absolute
                totalAbsolute += absolute
                if (absolute > framePeak) framePeak = absolute
                if (absolute > peak) peak = absolute
            }
            val frameMean = frameAbsolute.toDouble() / (frameEnd - frameStart).coerceAtLeast(1).toDouble()
            if (frameMean >= MEAN_ABSOLUTE_THRESHOLD || framePeak >= PEAK_THRESHOLD) {
                activeFrames += 1
            }
            totalFrames += 1
            frameStart = frameEnd
        }
        val minimumActiveFrames = (totalFrames / 20).coerceAtLeast(1)
        return AudioVoiceActivity(
            activeFrames = activeFrames,
            totalFrames = totalFrames,
            meanAbsoluteAmplitude = totalAbsolute.toDouble() / pcm16Mono.size.toDouble(),
            peak = peak,
            hasVoice = activeFrames >= minimumActiveFrames
        )
    }

    fun hasVoice(
        pcm16Mono: ShortArray,
        sampleRateHz: Int = WhisperCppAsrEngine.REQUIRED_SAMPLE_RATE_HZ
    ): Boolean = analyze(pcm16Mono, sampleRateHz).hasVoice
}

data class AudioVoiceWindowDecision(
    val shouldTranscribe: Boolean,
    val usedRecallProbe: Boolean,
    val nextConsecutiveSkips: Int
)

object AudioVoiceWindowPolicy {
    private const val MAX_CONSECUTIVE_SKIPS = 3

    fun decide(
        activity: AudioVoiceActivity,
        consecutiveSkips: Int
    ): AudioVoiceWindowDecision {
        if (activity.hasVoice) {
            return AudioVoiceWindowDecision(
                shouldTranscribe = true,
                usedRecallProbe = false,
                nextConsecutiveSkips = 0
            )
        }
        val updatedSkips = consecutiveSkips.coerceAtLeast(0) + 1
        if (updatedSkips > MAX_CONSECUTIVE_SKIPS) {
            return AudioVoiceWindowDecision(
                shouldTranscribe = true,
                usedRecallProbe = true,
                nextConsecutiveSkips = 0
            )
        }
        return AudioVoiceWindowDecision(
            shouldTranscribe = false,
            usedRecallProbe = false,
            nextConsecutiveSkips = updatedSkips
        )
    }
}
