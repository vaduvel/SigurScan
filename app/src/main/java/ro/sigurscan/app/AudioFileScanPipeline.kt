package ro.sigurscan.app

data class DecodedAudioFile(
    val pcm16Mono: ShortArray,
    val sampleRateHz: Int,
    val durationMs: Long? = null,
    val sourceDurationMs: Long? = durationMs,
    val windows: List<DecodedAudioWindow> = emptyList(),
    val plannedCoverage: AudioCoverageMetadata = AudioCoverageMetadata(
        sourceDurationMs = sourceDurationMs,
        plannedDurationMs = durationMs ?: 0L,
        decodedDurationMs = durationMs ?: 0L,
        sourceCoverageRatio = sourceDurationMs?.takeIf { it > 0L }?.let { source ->
            ((durationMs ?: 0L).toDouble() / source.toDouble()).coerceIn(0.0, 1.0)
        },
        status = when {
            sourceDurationMs == null -> AudioCoverageStatus.UNKNOWN
            durationMs != null && durationMs >= sourceDurationMs -> AudioCoverageStatus.COMPLETE
            else -> AudioCoverageStatus.PARTIAL
        },
        windowsPlanned = if (pcm16Mono.isNotEmpty()) 1 else 0,
        windowsDecoded = if (pcm16Mono.isNotEmpty()) 1 else 0
    )
)

data class AudioFileScanResult(
    val success: Boolean,
    val inputKind: String = "import_audio_file",
    val channel: String = "audio_share",
    val engine: String = WhisperCppAsrEngine.ENGINE_NAME,
    val evidence: AudioEvidenceResult?,
    val reasonCode: String?,
    val transcriptForTelemetry: String,
    val redactedTranscriptForSemanticReview: String = "",
    val rawAudioBytesRetained: Int = 0,
    val coverage: AudioCoverageMetadata = AudioCoverageMetadata()
)

class AudioFileScanPipeline(
    private val asrEngine: WhisperCppAsrEngine = WhisperCppAsrEngine()
) {
    fun scan(
        decodedAudio: DecodedAudioFile,
        modelPath: String
    ): AudioFileScanResult {
        val decodedWindows = decodedAudio.effectiveWindows()
        val voiceWindows = decodedWindows.filter { window ->
            AudioVoiceActivityDetector.hasVoice(window.pcm16Mono, decodedAudio.sampleRateHz)
        }
        val vadFallbackUsed = decodedWindows.isNotEmpty() && voiceWindows.isEmpty()
        val selectedWindows = if (voiceWindows.isNotEmpty()) voiceWindows else decodedWindows.take(1)
        val transcripts = mutableListOf<AudioTranscriptWindow>()
        var windowsFailed = 0
        var firstFailureReason: String? = null
        var rawAudioBytesRetained = 0
        for (window in selectedWindows) {
            val asr = asrEngine.transcribe(
                LocalAsrRequest(
                    pcm16Mono = window.pcm16Mono,
                    sampleRateHz = decodedAudio.sampleRateHz,
                    language = "ro",
                    modelPath = modelPath
                )
            )
            rawAudioBytesRetained += asr.rawAudioBytesRetained
            if (asr.success && asr.transcript.isNotBlank()) {
                transcripts += AudioTranscriptWindow(window.startMs, window.endMs, asr.transcript)
            } else {
                windowsFailed += 1
                if (firstFailureReason == null) firstFailureReason = asr.reasonCode
            }
        }

        val redactedWindows = transcripts.map { window ->
            window.copy(transcript = AudioTranscriptRedactor.redact(window.transcript))
        }
        val semanticSample = AudioSemanticContextSampler.sample(redactedWindows, MAX_SEMANTIC_CONTEXT_CHARS)
        val baseCoverage = decodedAudio.plannedCoverage
        val successfulWindowKeys = transcripts.map { it.startMs to it.endMs }.toSet()
        val transcribedDuration = selectedWindows
            .filter { (it.startMs to it.endMs) in successfulWindowKeys }
            .sumOf { it.durationMs }
        val transcribedSourceCoverageRatio = baseCoverage.sourceDurationMs
            ?.takeIf { it > 0L }
            ?.let { sourceDuration ->
                (transcribedDuration.toDouble() / sourceDuration.toDouble()).coerceIn(0.0, 1.0)
            }
        val effectiveStatus = when {
            baseCoverage.status == AudioCoverageStatus.UNKNOWN -> AudioCoverageStatus.UNKNOWN
            windowsFailed > 0 ||
                baseCoverage.windowsDecoded < baseCoverage.windowsPlanned ||
                selectedWindows.size < decodedWindows.size -> AudioCoverageStatus.PARTIAL
            else -> baseCoverage.status
        }
        val coverage = baseCoverage.copy(
            transcribedDurationMs = transcribedDuration,
            sourceCoverageRatio = transcribedSourceCoverageRatio ?: baseCoverage.sourceCoverageRatio,
            status = effectiveStatus,
            windowsSkippedByVad = (decodedWindows.size - selectedWindows.size).coerceAtLeast(0),
            windowsTranscribed = transcripts.size,
            windowsFailed = windowsFailed,
            transcriptCharsTotal = semanticSample.totalChars,
            transcriptCharsSent = semanticSample.sentChars,
            transcriptTruncated = semanticSample.truncated,
            vadFallbackUsed = vadFallbackUsed
        )

        if (transcripts.isEmpty()) {
            return AudioFileScanResult(
                success = false,
                evidence = AudioEvidenceEngine.evaluate(AudioEvidenceInput()),
                reasonCode = firstFailureReason
                    ?: if (selectedWindows.isEmpty()) "audio_decode_empty_pcm" else "empty_transcript",
                transcriptForTelemetry = "",
                redactedTranscriptForSemanticReview = "",
                rawAudioBytesRetained = rawAudioBytesRetained,
                coverage = coverage
            )
        }
        val combinedTranscript = transcripts.joinToString(" ") { it.transcript }
        return AudioFileScanResult(
            success = true,
            evidence = AudioTranscriptEvidence.analyze(combinedTranscript),
            reasonCode = null,
            transcriptForTelemetry = "[redactat]",
            redactedTranscriptForSemanticReview = semanticSample.text,
            rawAudioBytesRetained = rawAudioBytesRetained,
            coverage = coverage
        )
    }

    private fun DecodedAudioFile.effectiveWindows(): List<DecodedAudioWindow> {
        if (windows.isNotEmpty()) return windows
        if (pcm16Mono.isEmpty()) return emptyList()
        val effectiveDuration = durationMs ?: ((pcm16Mono.size * 1_000L) / sampleRateHz.coerceAtLeast(1))
        return listOf(DecodedAudioWindow(pcm16Mono, 0L, effectiveDuration))
    }

    private companion object {
        const val MAX_SEMANTIC_CONTEXT_CHARS = 2_500
    }
}

internal fun AudioFileScanResult.toOfflineAssessment(fileName: String): OfflineAssessment {
    val evidence = evidence
    val verdict = evidence?.verdict ?: AudioEvidenceVerdict.UNVERIFIED
    val reasonCodes = (evidence?.reasonCodes.orEmpty() + coverage.reasonCodes).distinct().ifEmpty {
        listOf(reasonCode ?: "audio_asr_unavailable")
    }
    val family = evidence?.arcFamily ?: when (verdict) {
        AudioEvidenceVerdict.DANGEROUS -> "Periculos"
        AudioEvidenceVerdict.SUSPECT -> "Suspect"
        AudioEvidenceVerdict.UNVERIFIED -> "Neverificat"
    }
    val riskLevel = when (verdict) {
        AudioEvidenceVerdict.DANGEROUS -> "high"
        AudioEvidenceVerdict.SUSPECT -> "medium"
        AudioEvidenceVerdict.UNVERIFIED -> "unknown"
    }
    val riskScore = when (verdict) {
        AudioEvidenceVerdict.DANGEROUS -> 92
        AudioEvidenceVerdict.SUSPECT -> 58
        AudioEvidenceVerdict.UNVERIFIED -> 0
    }
    val primaryReason = when (verdict) {
        AudioEvidenceVerdict.DANGEROUS -> "Audio-ul partajat conține semnale puternice de fraudă telefonică."
        AudioEvidenceVerdict.SUSPECT -> "Audio-ul partajat conține semnale care cer verificare pe canal oficial."
        AudioEvidenceVerdict.UNVERIFIED -> "Audio-ul partajat a fost procesat local, dar nu avem suficiente dovezi pentru un verdict de risc."
    }
    val actions = when (verdict) {
        AudioEvidenceVerdict.DANGEROUS -> listOf(
            "Nu continua conversația și nu trimite bani, coduri sau date personale.",
            "Sună instituția sau persoana pe un număr găsit manual, nu pe cel primit în mesaj.",
            "Dacă ai trimis deja date sau bani, contactează banca imediat."
        )
        AudioEvidenceVerdict.SUSPECT -> listOf(
            "Verifică pe canal oficial înainte să răspunzi sau să plătești.",
            "Nu instala aplicații remote și nu comunica OTP, PIN sau date de card.",
            "Cere timp de gândire; presiunea în apel este semnal de risc."
        )
        AudioEvidenceVerdict.UNVERIFIED -> listOf(
            "Dacă ai dubii, verifică separat cu persoana sau instituția pretinsă.",
            "Nu trimite coduri, date de card sau bani doar pe baza unui mesaj vocal.",
            "Poți lipi transcriptul manual dacă transcrierea audio nu a fost clară."
        )
    }
    val coverageReason = when (coverage.status) {
        AudioCoverageStatus.COMPLETE -> "Am verificat toată înregistrarea disponibilă."
        AudioCoverageStatus.PARTIAL -> {
            val percent = coverage.sourceCoverageRatio?.let { (it * 100).toInt().coerceIn(1, 99) }
            if (percent != null) {
                "Am verificat fragmente distribuite în toată înregistrarea ($percent% din durată)."
            } else {
                "Am verificat fragmente distribuite în înregistrare; acoperirea este parțială."
            }
        }
        AudioCoverageStatus.UNKNOWN -> "Durata completă nu a putut fi confirmată; verdictul folosește partea analizată."
    }
    return OfflineAssessment(
        family = family,
        riskScore = riskScore,
        riskLevel = riskLevel,
        reasons = (listOf(primaryReason, coverageReason) + reasonCodes.map { "Semnal audio: $it" }).distinct(),
        safeActions = actions,
        keyDangers = if (verdict == AudioEvidenceVerdict.DANGEROUS) {
            listOf("Cerere riscantă detectată în conversația audio.")
        } else {
            emptyList()
        },
        originalText = "Audio analizat local, fără stocare raw: $fileName.",
        reputationVerdict = "Neverificat",
        domainAgeText = "Nu se aplică",
        sslStatus = "Nu se aplică",
        aiConfidence = "Analiză audio locală"
    )
}
