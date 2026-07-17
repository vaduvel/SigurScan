package ro.sigurscan.app

import android.content.Context
import android.media.AudioFormat
import android.media.MediaCodec
import android.media.MediaExtractor
import android.media.MediaFormat
import android.net.Uri
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.math.roundToInt

class AudioDecodeException(message: String, cause: Throwable? = null) : Exception(message, cause)

object AudioFileDecoder {
    private const val TIMEOUT_US = 10_000L

    fun decodeToWhisperPcm(
        context: Context,
        uri: Uri
    ): DecodedAudioFile {
        val sourceDurationMs = probeSourceDurationMs(context, uri)
        val plan = AudioWindowPlanner.plan(sourceDurationMs)
        var firstFailure: Throwable? = null
        val decodedWindows = plan.windows.mapNotNull { window ->
            try {
                val decoded = decodePcmWindow(context, uri, window)
                val mono16k = Pcm16Resampler.toMono16k(
                    interleavedPcm16 = decoded.pcm16Interleaved,
                    sourceSampleRateHz = decoded.sampleRateHz,
                    sourceChannelCount = decoded.channelCount
                )
                if (mono16k.isEmpty()) {
                    null
                } else {
                    val actualDurationMs = (mono16k.size * 1_000L) / WhisperCppAsrEngine.REQUIRED_SAMPLE_RATE_HZ
                    DecodedAudioWindow(
                        pcm16Mono = mono16k,
                        startMs = window.startMs,
                        endMs = (window.startMs + actualDurationMs).coerceAtMost(window.endMs)
                    )
                }
            } catch (error: Exception) {
                if (firstFailure == null) firstFailure = error
                null
            }
        }
        if (decodedWindows.isEmpty()) {
            val failure = firstFailure
            if (failure is AudioDecodeException) throw failure
            throw AudioDecodeException("audio_decode_empty_pcm")
        }
        val combined = decodedWindows.map { it.pcm16Mono }.concatShortArrays()
        val decodedDurationMs = decodedWindows.sumOf { it.durationMs }
        val coverageStatus = when {
            plan.status == AudioCoverageStatus.UNKNOWN -> AudioCoverageStatus.UNKNOWN
            decodedWindows.size < plan.windows.size -> AudioCoverageStatus.PARTIAL
            else -> plan.status
        }
        return DecodedAudioFile(
            pcm16Mono = combined,
            sampleRateHz = WhisperCppAsrEngine.REQUIRED_SAMPLE_RATE_HZ,
            durationMs = decodedDurationMs,
            sourceDurationMs = sourceDurationMs,
            windows = decodedWindows,
            plannedCoverage = AudioCoverageMetadata(
                sourceDurationMs = sourceDurationMs,
                plannedDurationMs = plan.plannedDurationMs,
                decodedDurationMs = decodedDurationMs,
                sourceCoverageRatio = plan.sourceCoverageRatio,
                status = coverageStatus,
                windowsPlanned = plan.windows.size,
                windowsDecoded = decodedWindows.size
            )
        )
    }

    private fun probeSourceDurationMs(context: Context, uri: Uri): Long? {
        val extractor = MediaExtractor()
        try {
            return context.contentResolver.openAssetFileDescriptor(uri, "r")?.use { descriptor ->
                if (descriptor.length >= 0L) {
                    extractor.setDataSource(descriptor.fileDescriptor, descriptor.startOffset, descriptor.length)
                } else {
                    extractor.setDataSource(descriptor.fileDescriptor)
                }
                val trackIndex = findAudioTrack(extractor)
                extractor.getTrackFormat(trackIndex)
                    .safeLong(MediaFormat.KEY_DURATION, -1L)
                    .takeIf { it > 0L }
                    ?.div(1_000L)
            }
        } catch (_: Exception) {
            return null
        } finally {
            runCatching { extractor.release() }
        }
    }

    private fun decodePcmWindow(
        context: Context,
        uri: Uri,
        window: AudioWindowPlan
    ): DecodedPcm {
        val extractor = MediaExtractor()
        var codec: MediaCodec? = null
        try {
            context.contentResolver.openAssetFileDescriptor(uri, "r")?.use { descriptor ->
                if (descriptor.length >= 0L) {
                    extractor.setDataSource(descriptor.fileDescriptor, descriptor.startOffset, descriptor.length)
                } else {
                    extractor.setDataSource(descriptor.fileDescriptor)
                }
            } ?: throw AudioDecodeException("audio_file_open_failed")

            val trackIndex = findAudioTrack(extractor)

            extractor.selectTrack(trackIndex)
            val startUs = window.startMs * 1_000L
            val endUs = window.endMs * 1_000L
            if (startUs > 0L) {
                extractor.seekTo(startUs, MediaExtractor.SEEK_TO_CLOSEST_SYNC)
            }
            val inputFormat = extractor.getTrackFormat(trackIndex)
            val mime = inputFormat.getString(MediaFormat.KEY_MIME)
                ?: throw AudioDecodeException("audio_mime_missing")
            codec = MediaCodec.createDecoderByType(mime)
            codec.configure(inputFormat, null, null, 0)
            codec.start()

            val output = ArrayList<ShortArray>()
            val info = MediaCodec.BufferInfo()
            var inputDone = false
            var outputDone = false
            var sampleRate = inputFormat.safeInteger(MediaFormat.KEY_SAMPLE_RATE, WhisperCppAsrEngine.REQUIRED_SAMPLE_RATE_HZ)
            var channelCount = inputFormat.safeInteger(MediaFormat.KEY_CHANNEL_COUNT, 1).coerceAtLeast(1)
            var pcmEncoding = AudioFormat.ENCODING_PCM_16BIT
            var decodedSamples = 0

            while (!outputDone) {
                if (!inputDone) {
                    val inputIndex = codec.dequeueInputBuffer(TIMEOUT_US)
                    if (inputIndex >= 0) {
                        val inputBuffer = codec.getInputBuffer(inputIndex)
                        inputBuffer?.clear()
                        val sampleSize = if (inputBuffer != null) {
                            extractor.readSampleData(inputBuffer, 0)
                        } else {
                            -1
                        }
                        val sampleTime = extractor.sampleTime
                        if (sampleSize < 0 || sampleTime < 0L || sampleTime >= endUs) {
                            codec.queueInputBuffer(
                                inputIndex,
                                0,
                                0,
                                0L,
                                MediaCodec.BUFFER_FLAG_END_OF_STREAM
                            )
                            inputDone = true
                        } else {
                            codec.queueInputBuffer(
                                inputIndex,
                                0,
                                sampleSize,
                                sampleTime.coerceAtLeast(0L),
                                0
                            )
                            extractor.advance()
                        }
                    }
                }

                when (val outputIndex = codec.dequeueOutputBuffer(info, TIMEOUT_US)) {
                    MediaCodec.INFO_OUTPUT_FORMAT_CHANGED -> {
                        val outputFormat = codec.outputFormat
                        sampleRate = outputFormat.safeInteger(MediaFormat.KEY_SAMPLE_RATE, sampleRate)
                        channelCount = outputFormat.safeInteger(MediaFormat.KEY_CHANNEL_COUNT, channelCount).coerceAtLeast(1)
                        pcmEncoding = outputFormat.safeInteger(MediaFormat.KEY_PCM_ENCODING, AudioFormat.ENCODING_PCM_16BIT)
                    }
                    MediaCodec.INFO_TRY_AGAIN_LATER -> Unit
                    else -> if (outputIndex >= 0) {
                        val buffer = codec.getOutputBuffer(outputIndex)
                        if (buffer != null && info.size > 0 && info.presentationTimeUs >= startUs) {
                            buffer.position(info.offset)
                            buffer.limit(info.offset + info.size)
                            val chunk = buffer.toShortArray(pcmEncoding)
                            val maxSamples = (
                                (sampleRate.toLong() * channelCount.toLong() * window.durationMs) / 1_000L
                                ).coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
                            val remaining = (maxSamples - decodedSamples).coerceAtLeast(0)
                            val stored = if (chunk.size > remaining) chunk.copyOf(remaining) else chunk
                            if (stored.isNotEmpty()) {
                                output += stored
                                decodedSamples += stored.size
                            }
                        }
                        outputDone = outputDone ||
                            info.flags and MediaCodec.BUFFER_FLAG_END_OF_STREAM != 0
                        codec.releaseOutputBuffer(outputIndex, false)
                    }
                }
            }

            return DecodedPcm(
                pcm16Interleaved = output.concatShortArrays(),
                sampleRateHz = sampleRate,
                channelCount = channelCount
            )
        } catch (e: AudioDecodeException) {
            throw e
        } catch (e: Exception) {
            throw AudioDecodeException("audio_decode_failed", e)
        } finally {
            runCatching { codec?.stop() }
            runCatching { codec?.release() }
            runCatching { extractor.release() }
        }
    }

    private data class DecodedPcm(
        val pcm16Interleaved: ShortArray,
        val sampleRateHz: Int,
        val channelCount: Int
    )

    private fun findAudioTrack(extractor: MediaExtractor): Int {
        return (0 until extractor.trackCount).firstOrNull { index ->
            extractor.getTrackFormat(index)
                .getString(MediaFormat.KEY_MIME)
                ?.startsWith("audio/") == true
        } ?: throw AudioDecodeException("audio_track_missing")
    }
}

object Pcm16Resampler {
    fun toMono16k(
        interleavedPcm16: ShortArray,
        sourceSampleRateHz: Int,
        sourceChannelCount: Int
    ): ShortArray {
        if (interleavedPcm16.isEmpty() || sourceSampleRateHz <= 0 || sourceChannelCount <= 0) {
            return ShortArray(0)
        }
        val frameCount = interleavedPcm16.size / sourceChannelCount
        if (frameCount <= 0) return ShortArray(0)
        val mono = ShortArray(frameCount)
        for (frame in 0 until frameCount) {
            var sum = 0
            for (channel in 0 until sourceChannelCount) {
                sum += interleavedPcm16[frame * sourceChannelCount + channel].toInt()
            }
            mono[frame] = (sum / sourceChannelCount).toShort()
        }
        if (sourceSampleRateHz == WhisperCppAsrEngine.REQUIRED_SAMPLE_RATE_HZ) {
            return mono
        }
        val outFrames = ((mono.size.toDouble() * WhisperCppAsrEngine.REQUIRED_SAMPLE_RATE_HZ) / sourceSampleRateHz)
            .roundToInt()
            .coerceAtLeast(1)
        return ShortArray(outFrames) { index ->
            val sourcePosition = (index.toDouble() * sourceSampleRateHz) / WhisperCppAsrEngine.REQUIRED_SAMPLE_RATE_HZ
            val left = sourcePosition.toInt().coerceIn(0, mono.lastIndex)
            val right = (left + 1).coerceAtMost(mono.lastIndex)
            val fraction = sourcePosition - left
            val interpolated = mono[left] + ((mono[right] - mono[left]) * fraction)
            interpolated.roundToInt()
                .coerceIn(Short.MIN_VALUE.toInt(), Short.MAX_VALUE.toInt())
                .toShort()
        }
    }
}

private fun MediaFormat.safeInteger(key: String, fallback: Int): Int {
    return runCatching {
        if (containsKey(key)) getInteger(key) else fallback
    }.getOrDefault(fallback)
}

private fun MediaFormat.safeLong(key: String, fallback: Long): Long {
    return runCatching {
        if (containsKey(key)) getLong(key) else fallback
    }.getOrDefault(fallback)
}

private fun ByteBuffer.toShortArray(pcmEncoding: Int): ShortArray {
    val slice = slice().order(ByteOrder.LITTLE_ENDIAN)
    return when (pcmEncoding) {
        AudioFormat.ENCODING_PCM_FLOAT -> {
            val count = slice.remaining() / 4
            ShortArray(count) {
                val value = slice.float.coerceIn(-1f, 1f)
                (value * Short.MAX_VALUE).roundToInt().toShort()
            }
        }
        else -> {
            val count = slice.remaining() / 2
            ShortArray(count) { slice.short }
        }
    }
}

private fun List<ShortArray>.concatShortArrays(): ShortArray {
    val total = sumOf { it.size }
    val out = ShortArray(total)
    var offset = 0
    for (chunk in this) {
        chunk.copyInto(out, offset)
        offset += chunk.size
    }
    return out
}
