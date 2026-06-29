package ro.sigurscan.app

import android.Manifest
import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import android.media.AudioFormat
import android.media.AudioRecord
import android.media.MediaRecorder
import android.util.Log
import androidx.core.content.ContextCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.ClosedReceiveChannelException
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlin.math.max

enum class SpeakerGuardPhase {
    IDLE,
    LISTENING,
    HEARD_VOICE,
    PROCESSING,
    STOPPED,
    ERROR
}

data class SpeakerGuardUpdate(
    val phase: SpeakerGuardPhase,
    val active: Boolean,
    val chunksAnalyzed: Int = 0,
    val chunksDropped: Int = 0,
    val result: LocalAsrResult? = null,
    val latencyMs: Long? = null,
    val reasonCode: String? = null,
    val status: String
)

internal class SpeakerGuardChunkQueue(
    capacity: Int
) {
    private val capacity = max(1, capacity)
    private val lock = Any()
    private val pending = ArrayDeque<ShortArray>()
    private val available = Channel<Unit>(Channel.UNLIMITED)
    private var closed = false
    private var droppedCount = 0

    val chunksDropped: Int
        get() = synchronized(lock) { droppedCount }

    suspend fun send(chunk: ShortArray) {
        var accepted = false
        synchronized(lock) {
            if (!closed) {
                if (pending.size >= capacity) {
                    pending.removeFirst()
                    droppedCount += 1
                }
                pending.addLast(chunk)
                accepted = true
            }
        }
        if (accepted) {
            available.trySend(Unit)
        }
    }

    suspend fun receive(): ShortArray {
        while (true) {
            synchronized(lock) {
                if (pending.isNotEmpty()) {
                    return pending.removeFirst()
                }
                if (closed) {
                    throw ClosedReceiveChannelException("speaker guard chunk queue closed")
                }
            }
            available.receive()
        }
    }

    fun close() {
        synchronized(lock) {
            closed = true
        }
        available.close()
    }
}

internal object SpeakerGuardVoiceGate {
    private const val VOICE_MEAN_ABS_THRESHOLD = 180.0
    private const val VOICE_PEAK_ABS_THRESHOLD = 900

    fun hasVoiceEnergy(buffer: ShortArray, sampleCount: Int = buffer.size): Boolean {
        if (sampleCount <= 0) return false
        val safeCount = sampleCount.coerceAtMost(buffer.size)
        var sum = 0L
        var peak = 0
        for (index in 0 until safeCount) {
            val sample = buffer[index].toInt()
            val absolute = if (sample < 0) -sample else sample
            sum += absolute
            if (absolute > peak) {
                peak = absolute
            }
        }
        val meanAbsoluteAmplitude = sum.toDouble() / safeCount.toDouble()
        return meanAbsoluteAmplitude >= VOICE_MEAN_ABS_THRESHOLD || peak >= VOICE_PEAK_ABS_THRESHOLD
    }

    fun shouldProcessChunk(pcm16Mono: ShortArray): Boolean {
        return hasVoiceEnergy(pcm16Mono, pcm16Mono.size)
    }
}

class SpeakerGuardSession(
    private val context: Context,
    private val asrEngine: WhisperCppAsrEngine = WhisperCppAsrEngine(),
    private val semanticReviewer: AudioSemanticReviewer = NoopAudioSemanticReviewer
) {
    private var job: Job? = null
    @Volatile
    private var activeAudioRecord: AudioRecord? = null
    @Volatile
    private var stopRequested: Boolean = false

    val active: Boolean
        get() = job?.isActive == true

    fun start(
        scope: CoroutineScope,
        modelPath: String,
        onUpdate: (SpeakerGuardUpdate) -> Unit
    ) {
        if (active) return
        stopRequested = false
        job = scope.launch(Dispatchers.Default) {
            runCatching {
                runCaptureLoop(modelPath, onUpdate)
            }.onFailure { throwable ->
                if (stopRequested || throwable is CancellationException) {
                    return@onFailure
                }
                onUpdate(
                    SpeakerGuardUpdate(
                        phase = SpeakerGuardPhase.ERROR,
                        active = false,
                        reasonCode = throwable.javaClass.simpleName,
                        status = "Urechea s-a oprit: ${throwable.message ?: "eroare audio"}."
                    )
                )
            }
        }
    }

    fun stop() {
        stopRequested = true
        job?.cancel()
        releaseActiveAudioRecord()
        job = null
    }

    @SuppressLint("MissingPermission")
    private suspend fun runCaptureLoop(
        modelPath: String,
        onUpdate: (SpeakerGuardUpdate) -> Unit
    ) = coroutineScope {
        if (ContextCompat.checkSelfPermission(context, Manifest.permission.RECORD_AUDIO) != PackageManager.PERMISSION_GRANTED) {
            onUpdate(
                SpeakerGuardUpdate(
                    phase = SpeakerGuardPhase.ERROR,
                    active = false,
                    reasonCode = "microphone_permission_missing",
                    status = "Permisiunea microfonului lipsește."
                )
            )
            return@coroutineScope
        }

        val minBufferBytes = AudioRecord.getMinBufferSize(
            SAMPLE_RATE_HZ,
            AudioFormat.CHANNEL_IN_MONO,
            AudioFormat.ENCODING_PCM_16BIT
        )
        if (minBufferBytes <= 0) {
            onUpdate(
                SpeakerGuardUpdate(
                    phase = SpeakerGuardPhase.ERROR,
                    active = false,
                    reasonCode = "audio_record_unavailable",
                    status = "Microfonul nu poate porni pe acest dispozitiv."
                )
            )
            return@coroutineScope
        }

        val chunkSamples = SAMPLE_RATE_HZ * CHUNK_SECONDS
        val recordBufferSamples = max(minBufferBytes / BYTES_PER_SAMPLE, SAMPLE_RATE_HZ)
        val audioRecord = AudioRecord.Builder()
            .setAudioSource(MediaRecorder.AudioSource.VOICE_RECOGNITION)
            .setAudioFormat(
                AudioFormat.Builder()
                    .setEncoding(AudioFormat.ENCODING_PCM_16BIT)
                    .setSampleRate(SAMPLE_RATE_HZ)
                    .setChannelMask(AudioFormat.CHANNEL_IN_MONO)
                    .build()
            )
            .setBufferSizeInBytes(max(minBufferBytes, recordBufferSamples * BYTES_PER_SAMPLE * 2))
            .build()

        if (audioRecord.state != AudioRecord.STATE_INITIALIZED) {
            audioRecord.release()
            onUpdate(
                SpeakerGuardUpdate(
                    phase = SpeakerGuardPhase.ERROR,
                    active = false,
                    reasonCode = "audio_record_init_failed",
                    status = "Microfonul nu s-a inițializat corect."
                )
            )
            return@coroutineScope
        }

        val chunks = SpeakerGuardChunkQueue(capacity = CHUNK_QUEUE_CAPACITY)
        var chunksAnalyzed = 0
        var chunksQueued = 0
        var chunksSkippedByVoiceGate = 0
        val evidenceAggregator = AudioEvidenceSessionAggregator()
        val semanticCoordinator = SpeakerGuardSemanticReviewCoordinator()
        var heardVoice = false

        try {
            activeAudioRecord = audioRecord
            audioRecord.startRecording()
            Log.i(
                TAG,
                "capture_started sampleRate=$SAMPLE_RATE_HZ chunkSeconds=$CHUNK_SECONDS " +
                    "recordBufferSamples=$recordBufferSamples minBufferBytes=$minBufferBytes"
            )
            onUpdate(
                SpeakerGuardUpdate(
                    phase = SpeakerGuardPhase.LISTENING,
                    active = true,
                    status = "Ascultă prin microfon. Ține apelul pe difuzor."
                )
            )

            val recorder = launch(Dispatchers.IO) {
                val readBuffer = ShortArray(recordBufferSamples)
                var chunk = ShortArray(chunkSamples)
                var offset = 0

                while (isActive) {
                    val read = audioRecord.read(readBuffer, 0, readBuffer.size)
                    if (read <= 0) continue
                    if (!heardVoice && hasVoiceEnergy(readBuffer, read)) {
                        heardVoice = true
                        onUpdate(
                            SpeakerGuardUpdate(
                                phase = SpeakerGuardPhase.HEARD_VOICE,
                                active = true,
                                chunksAnalyzed = chunksAnalyzed,
                                chunksDropped = chunks.chunksDropped,
                                status = "Am prins voce. Analizez local conversația."
                            )
                        )
                    }

                    var consumed = 0
                    while (consumed < read) {
                        val copyCount = minOf(read - consumed, chunk.size - offset)
                        readBuffer.copyInto(
                            destination = chunk,
                            destinationOffset = offset,
                            startIndex = consumed,
                            endIndex = consumed + copyCount
                        )
                        offset += copyCount
                        consumed += copyCount

                        if (offset == chunk.size) {
                            if (SpeakerGuardVoiceGate.shouldProcessChunk(chunk)) {
                                chunks.send(chunk)
                                chunksQueued += 1
                                Log.i(
                                    TAG,
                                    "chunk_queued queued=$chunksQueued analyzed=$chunksAnalyzed " +
                                        "dropped=${chunks.chunksDropped} skipped=$chunksSkippedByVoiceGate"
                                )
                            } else {
                                chunksSkippedByVoiceGate += 1
                                Log.i(
                                    TAG,
                                    "chunk_skipped_voice_gate skipped=$chunksSkippedByVoiceGate " +
                                        "queued=$chunksQueued analyzed=$chunksAnalyzed"
                                )
                            }
                            chunk = ShortArray(chunkSamples)
                            offset = 0
                        }
                    }
                }
            }

            val processor = launch(Dispatchers.Default) {
                while (isActive) {
                    val chunk = try {
                        chunks.receive()
                    } catch (_: ClosedReceiveChannelException) {
                        break
                    }
                    onUpdate(
                        SpeakerGuardUpdate(
                            phase = SpeakerGuardPhase.PROCESSING,
                            active = true,
                            chunksAnalyzed = chunksAnalyzed,
                            chunksDropped = chunks.chunksDropped,
                            status = "Analizează local ultimul fragment audio."
                        )
                    )
                    val started = System.currentTimeMillis()
                    Log.i(
                        TAG,
                        "asr_started nextChunk=${chunksAnalyzed + 1} queued=$chunksQueued " +
                            "dropped=${chunks.chunksDropped}"
                    )
                    val rawResult = withContext(Dispatchers.Default) {
                        asrEngine.transcribe(
                            LocalAsrRequest(
                                pcm16Mono = chunk,
                                sampleRateHz = SAMPLE_RATE_HZ,
                                language = "ro",
                                modelPath = modelPath
                            )
                        )
                    }
                    val result = rawResult.withSessionEvidence(evidenceAggregator)
                    chunksAnalyzed += 1
                    val latency = System.currentTimeMillis() - started
                    val redactedTranscript = AudioTranscriptRedactor.redact(result.transcript)
                    if (BuildConfig.DEBUG && redactedTranscript.isNotBlank()) {
                        Log.i(
                            TAG,
                            "asr_debug_redacted_preview chunk=$chunksAnalyzed " +
                                "preview=${redactedTranscript.take(160)}"
                        )
                    }
                    Log.i(
                        TAG,
                        "asr_finished chunk=$chunksAnalyzed success=${result.success} " +
                            "reason=${result.reasonCode ?: "none"} transcriptChars=${result.transcript.length} " +
                            "redactedChars=${redactedTranscript.length} " +
                            "verdict=${result.evidence?.verdict ?: "none"} latencyMs=$latency " +
                            "dropped=${chunks.chunksDropped}"
                    )
                    onUpdate(
                        SpeakerGuardUpdate(
                            phase = SpeakerGuardPhase.LISTENING,
                            active = true,
                            chunksAnalyzed = chunksAnalyzed,
                            chunksDropped = chunks.chunksDropped,
                            result = result,
                            latencyMs = latency,
                            reasonCode = result.reasonCode,
                            status = statusFor(result)
                        )
                    )
                    launchSemanticReview(
                        result = result,
                        evidenceAggregator = evidenceAggregator,
                        semanticCoordinator = semanticCoordinator,
                        chunksAnalyzed = chunksAnalyzed,
                        chunksDropped = chunks.chunksDropped,
                        latencyMs = latency,
                        onUpdate = onUpdate
                    )
                }
            }

            recorder.join()
            processor.cancel()
        } finally {
            chunks.close()
            if (activeAudioRecord === audioRecord) {
                activeAudioRecord = null
            }
            releaseAudioRecord(audioRecord)
            onUpdate(
                SpeakerGuardUpdate(
                    phase = SpeakerGuardPhase.STOPPED,
                    active = false,
                    chunksAnalyzed = chunksAnalyzed,
                    chunksDropped = chunks.chunksDropped,
                    status = "Urechea este oprită."
                )
            )
        }
    }

    private fun hasVoiceEnergy(buffer: ShortArray, sampleCount: Int): Boolean {
        return SpeakerGuardVoiceGate.hasVoiceEnergy(buffer, sampleCount)
    }

    private fun releaseActiveAudioRecord() {
        activeAudioRecord?.let { audioRecord ->
            activeAudioRecord = null
            releaseAudioRecord(audioRecord)
        }
    }

    private fun releaseAudioRecord(audioRecord: AudioRecord) {
        runCatching { audioRecord.stop() }
        runCatching { audioRecord.release() }
    }

    private fun statusFor(result: LocalAsrResult): String {
        val evidence = result.evidence
        return when {
            !result.success && result.reasonCode == "empty_transcript" -> "Nu am prins voce clară în ultimul fragment. Ține telefonul aproape de difuzor."
            !result.success -> "Nu am putut transcrie fragmentul: ${result.reasonCode ?: "eroare ASR"}."
            evidence?.verdict == AudioEvidenceVerdict.DANGEROUS -> "Semnale puternice de fraudă în conversație."
            evidence?.verdict == AudioEvidenceVerdict.SUSPECT -> "Semnale suspecte în conversație. Verifică înainte să continui."
            else -> "Am analizat vocea, dar încă nu sunt suficiente dovezi."
        }
    }

    private fun LocalAsrResult.withSessionEvidence(
        aggregator: AudioEvidenceSessionAggregator
    ): LocalAsrResult {
        val currentEvidence = evidence ?: return this
        val aggregatedEvidence = synchronized(aggregator) {
            aggregator.absorb(currentEvidence)
        }
        return if (aggregatedEvidence == currentEvidence) {
            this
        } else {
            copy(evidence = aggregatedEvidence)
        }
    }

    private fun CoroutineScope.launchSemanticReview(
        result: LocalAsrResult,
        evidenceAggregator: AudioEvidenceSessionAggregator,
        semanticCoordinator: SpeakerGuardSemanticReviewCoordinator,
        chunksAnalyzed: Int,
        chunksDropped: Int,
        latencyMs: Long,
        onUpdate: (SpeakerGuardUpdate) -> Unit
    ): Job {
        val semanticRequest = synchronized(semanticCoordinator) {
            semanticCoordinator.offer(result)
        } ?: return launch {
            Log.i(
                TAG,
                "semantic_skipped reason=no_recall_trigger transcriptChars=${AudioTranscriptRedactor.redact(result.transcript).length} " +
                    "localVerdict=${result.evidence?.verdict ?: "none"}"
            )
        }
        return launch(Dispatchers.IO) {
            val semanticStarted = System.currentTimeMillis()
            Log.i(
                TAG,
                "semantic_started transcriptChars=${semanticRequest.redactedTranscript.length} " +
                    "localVerdict=${semanticRequest.localEvidence?.verdict ?: "none"} " +
                    "family=${semanticRequest.localEvidence?.arcFamily ?: "none"}"
            )
            val attempt = semanticReviewer.reviewWithDiagnostics(
                redactedTranscript = semanticRequest.redactedTranscript,
                localEvidence = semanticRequest.localEvidence
            )
            if (attempt.response == null) {
                val reasonCode = attempt.reasonCode ?: "semantic_unavailable"
                Log.i(
                    TAG,
                    "semantic_finished received=false reason=$reasonCode " +
                        "elapsedMs=${System.currentTimeMillis() - semanticStarted}"
                )
                onUpdate(
                    SpeakerGuardUpdate(
                        phase = SpeakerGuardPhase.LISTENING,
                        active = true,
                        chunksAnalyzed = chunksAnalyzed,
                        chunksDropped = chunksDropped,
                        result = result,
                        latencyMs = latencyMs,
                        reasonCode = reasonCode,
                        status = "Verificarea semantică nu a răspuns încă: $reasonCode."
                    )
                )
                return@launch
            }

            val fusedEvidence = AudioSemanticReviewFusion.fuse(result.evidence, attempt.response)
            Log.i(
                TAG,
                "semantic_finished received=true escalates=${attempt.response.escalates} " +
                    "riskClass=${attempt.response.semanticReview?.riskClass ?: "none"} fusedVerdict=${fusedEvidence.verdict} " +
                    "elapsedMs=${System.currentTimeMillis() - semanticStarted}"
            )
            if (fusedEvidence == result.evidence) return@launch
            val aggregatedEvidence = synchronized(evidenceAggregator) {
                evidenceAggregator.absorb(fusedEvidence)
            }
            val semanticResult = result.copy(evidence = aggregatedEvidence)
            onUpdate(
                SpeakerGuardUpdate(
                    phase = SpeakerGuardPhase.LISTENING,
                    active = true,
                    chunksAnalyzed = chunksAnalyzed,
                    chunksDropped = chunksDropped,
                    result = semanticResult,
                    latencyMs = latencyMs,
                    reasonCode = semanticResult.reasonCode,
                    status = statusFor(semanticResult)
                )
            )
        }
    }

    companion object {
        private const val TAG = "SpeakerGuardLive"
        const val SAMPLE_RATE_HZ = 16_000
        const val CHUNK_SECONDS = 3
        private const val CHUNK_QUEUE_CAPACITY = 4
        private const val BYTES_PER_SAMPLE = 2
    }
}
