package ro.sigurscan.app

internal data class SpeakerGuardSemanticReviewRequest(
    val redactedTranscript: String,
    val localEvidence: AudioEvidenceResult?
)

internal class SpeakerGuardSemanticReviewCoordinator(
    private val minNewChars: Int = DEFAULT_MIN_NEW_CHARS,
    private val maxReviews: Int = DEFAULT_MAX_REVIEWS
) {
    private val transcriptWindow = StringBuilder()
    private var lastSentChars = 0
    var reviewsStarted: Int = 0
        private set

    fun offer(result: LocalAsrResult): SpeakerGuardSemanticReviewRequest? {
        if (!result.success || result.transcript.isBlank()) return null

        val redacted = AudioTranscriptRedactor.redact(result.transcript)
        if (redacted.isBlank()) return null

        if (transcriptWindow.isNotEmpty()) {
            transcriptWindow.append(' ')
        }
        transcriptWindow.append(redacted)
        trimWindow()

        if (reviewsStarted >= maxReviews) return null
        if (!shouldAskSemanticReview(result.evidence, transcriptWindow.toString())) return null

        val newChars = transcriptWindow.length - lastSentChars
        if (newChars < minNewChars) return null

        reviewsStarted += 1
        lastSentChars = transcriptWindow.length
        return SpeakerGuardSemanticReviewRequest(
            redactedTranscript = transcriptWindow.toString(),
            localEvidence = result.evidence
        )
    }

    private fun trimWindow() {
        if (transcriptWindow.length <= MAX_WINDOW_CHARS) return
        val removeCount = transcriptWindow.length - MAX_WINDOW_CHARS
        transcriptWindow.delete(0, removeCount)
        lastSentChars = (lastSentChars - removeCount).coerceAtLeast(0)
    }

    private fun shouldAskSemanticReview(evidence: AudioEvidenceResult?, redactedTranscriptWindow: String): Boolean {
        if (isEscalable(evidence)) return true
        return looksLikeSocialEngineeringForRecall(redactedTranscriptWindow)
    }

    private fun isEscalable(evidence: AudioEvidenceResult?): Boolean {
        if (evidence == null) return false
        if (evidence.verdict != AudioEvidenceVerdict.UNVERIFIED) return true
        if (!evidence.arcFamily.isNullOrBlank()) return true
        return evidence.reasonCodes.any { reason ->
            reason == "value_request_needs_verification" ||
                reason == "campaign_match_only" ||
                reason == "sensitive_wrong_channel" ||
                reason == "identity_spoof"
        }
    }

    private fun looksLikeSocialEngineeringForRecall(value: String): Boolean {
        val text = value.lowercase()
        val hasTrustedOrAuthority = listOf(
            "coleg",
            "colega",
            "prieten",
            "prietena",
            "sef",
            "sefa",
            "numar nou",
            "banca",
            "politie",
            "procuror",
            "suport",
            "curier"
        ).any(text::contains)
        val hasPressure = listOf(
            "urgent",
            "repede",
            "imediat",
            "azi",
            "nu spune",
            "nu zice",
            "ramane intre noi",
            "confidential"
        ).any(text::contains)
        val hasAction = listOf(
            "bani",
            "transfer",
            "imprumut",
            "cod",
            "otp",
            "card",
            "parola",
            "anydesk",
            "teamviewer"
        ).any(text::contains)
        return (hasTrustedOrAuthority && hasPressure) || (hasPressure && hasAction) || (hasTrustedOrAuthority && hasAction)
    }

    companion object {
        private const val DEFAULT_MIN_NEW_CHARS = 80
        private const val DEFAULT_MAX_REVIEWS = 4
        private const val MAX_WINDOW_CHARS = 2_500
    }
}
