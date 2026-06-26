package ro.sigurscan.app

import android.Manifest
import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import android.media.AudioFormat
import android.media.AudioRecord
import android.media.MediaRecorder
import androidx.core.content.ContextCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlin.math.max

enum class SpeakerGuardPhase {
    IDLE,
    LISTENING,
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

class SpeakerGuardSession(
    private val context: Context,
    private val asrEngine: WhisperCppAsrEngine = WhisperCppAsrEngine()
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

        val chunks = Channel<ShortArray>(
            capacity = 1,
            onBufferOverflow = BufferOverflow.DROP_OLDEST
        )
        var chunksAnalyzed = 0
        var chunksDropped = 0

        try {
            activeAudioRecord = audioRecord
            audioRecord.startRecording()
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
                            val sent = chunks.trySend(chunk).isSuccess
                            if (!sent) chunksDropped += 1
                            chunk = ShortArray(chunkSamples)
                            offset = 0
                        }
                    }
                }
            }

            val processor = launch(Dispatchers.Default) {
                for (chunk in chunks) {
                    onUpdate(
                        SpeakerGuardUpdate(
                            phase = SpeakerGuardPhase.PROCESSING,
                            active = true,
                            chunksAnalyzed = chunksAnalyzed,
                            chunksDropped = chunksDropped,
                            status = "Analizează local ultimul fragment audio."
                        )
                    )
                    val started = System.currentTimeMillis()
                    val result = withContext(Dispatchers.Default) {
                        asrEngine.transcribe(
                            LocalAsrRequest(
                                pcm16Mono = chunk,
                                sampleRateHz = SAMPLE_RATE_HZ,
                                language = "ro",
                                modelPath = modelPath
                            )
                        )
                    }
                    chunksAnalyzed += 1
                    val latency = System.currentTimeMillis() - started
                    onUpdate(
                        SpeakerGuardUpdate(
                            phase = SpeakerGuardPhase.LISTENING,
                            active = true,
                            chunksAnalyzed = chunksAnalyzed,
                            chunksDropped = chunksDropped,
                            result = result,
                            latencyMs = latency,
                            reasonCode = result.reasonCode,
                            status = statusFor(result)
                        )
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
                    chunksDropped = chunksDropped,
                    status = "Urechea este oprită."
                )
            )
        }
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
            !result.success -> "Nu am putut transcrie fragmentul: ${result.reasonCode ?: "eroare ASR"}."
            evidence?.verdict == AudioEvidenceVerdict.DANGEROUS -> "Semnale puternice de fraudă în conversație."
            evidence?.verdict == AudioEvidenceVerdict.SUSPECT -> "Semnale suspecte în conversație. Verifică înainte să continui."
            else -> "Nu sunt suficiente dovezi în fragmentul analizat."
        }
    }

    companion object {
        const val SAMPLE_RATE_HZ = 16_000
        const val CHUNK_SECONDS = 6
        private const val BYTES_PER_SAMPLE = 2
    }
}
