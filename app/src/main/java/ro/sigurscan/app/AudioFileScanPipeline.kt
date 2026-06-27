package ro.sigurscan.app

data class DecodedAudioFile(
    val pcm16Mono: ShortArray,
    val sampleRateHz: Int,
    val durationMs: Long? = null
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
    val rawAudioBytesRetained: Int = 0
)

class AudioFileScanPipeline(
    private val asrEngine: WhisperCppAsrEngine = WhisperCppAsrEngine()
) {
    fun scan(
        decodedAudio: DecodedAudioFile,
        modelPath: String
    ): AudioFileScanResult {
        val asr = asrEngine.transcribe(
            LocalAsrRequest(
                pcm16Mono = decodedAudio.pcm16Mono,
                sampleRateHz = decodedAudio.sampleRateHz,
                language = "ro",
                modelPath = modelPath
            )
        )
        if (!asr.success) {
            return AudioFileScanResult(
                success = false,
                evidence = AudioEvidenceEngine.evaluate(AudioEvidenceInput()),
                reasonCode = asr.reasonCode,
                transcriptForTelemetry = "",
                redactedTranscriptForSemanticReview = "",
                rawAudioBytesRetained = asr.rawAudioBytesRetained
            )
        }
        val redactedTranscript = AudioTranscriptRedactor.redact(asr.transcript)
        return AudioFileScanResult(
            success = true,
            evidence = asr.evidence ?: AudioTranscriptEvidence.analyze(asr.transcript),
            reasonCode = null,
            transcriptForTelemetry = "[redactat]",
            redactedTranscriptForSemanticReview = redactedTranscript,
            rawAudioBytesRetained = asr.rawAudioBytesRetained
        )
    }
}

internal fun AudioFileScanResult.toOfflineAssessment(fileName: String): OfflineAssessment {
    val evidence = evidence
    val verdict = evidence?.verdict ?: AudioEvidenceVerdict.UNVERIFIED
    val reasonCodes = evidence?.reasonCodes.orEmpty().ifEmpty {
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
    return OfflineAssessment(
        family = family,
        riskScore = riskScore,
        riskLevel = riskLevel,
        reasons = (listOf(primaryReason) + reasonCodes.map { "Semnal audio: $it" }).distinct(),
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
