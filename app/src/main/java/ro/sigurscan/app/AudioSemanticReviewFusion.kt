package ro.sigurscan.app

import java.io.IOException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import retrofit2.HttpException

data class AudioSemanticReviewAttempt(
    val response: AudioSemanticReviewResponse?,
    val reasonCode: String? = null
)

interface AudioSemanticReviewer {
    suspend fun review(
        redactedTranscript: String,
        localEvidence: AudioEvidenceResult?
    ): AudioSemanticReviewResponse? = reviewWithDiagnostics(redactedTranscript, localEvidence).response

    suspend fun reviewWithDiagnostics(
        redactedTranscript: String,
        localEvidence: AudioEvidenceResult?
    ): AudioSemanticReviewAttempt
}

class BackendAudioSemanticReviewer(
    private val api: SigurScanApi,
    private val channel: String
) : AudioSemanticReviewer {
    override suspend fun review(
        redactedTranscript: String,
        localEvidence: AudioEvidenceResult?
    ): AudioSemanticReviewResponse? = reviewWithDiagnostics(redactedTranscript, localEvidence).response

    override suspend fun reviewWithDiagnostics(
        redactedTranscript: String,
        localEvidence: AudioEvidenceResult?
    ): AudioSemanticReviewAttempt {
        if (redactedTranscript.isBlank()) {
            return AudioSemanticReviewAttempt(response = null, reasonCode = "semantic_blank_transcript")
        }
        return try {
            AudioSemanticReviewAttempt(
                response = api.reviewAudioTranscript(
                    AudioSemanticReviewRequest(
                        transcriptRedacted = redactedTranscript,
                        channel = channel,
                        localVerdict = localEvidence?.verdict?.name ?: AudioEvidenceVerdict.UNVERIFIED.name,
                        localReasonCodes = localEvidence?.reasonCodes.orEmpty(),
                        claimedIdentity = localEvidence?.claimedIdentity,
                        arcFamily = localEvidence?.arcFamily
                    )
                )
            )
        } catch (throwable: Throwable) {
            AudioSemanticReviewAttempt(response = null, reasonCode = reasonCodeFor(throwable))
        }
    }

    private fun reasonCodeFor(throwable: Throwable): String {
        return when (throwable) {
            is SocketTimeoutException -> "semantic_timeout"
            is UnknownHostException -> "semantic_network_unavailable"
            is HttpException -> "semantic_http_${throwable.code()}"
            is IOException -> "semantic_io_error"
            else -> "semantic_error_${throwable.javaClass.simpleName}"
        }
    }
}

object NoopAudioSemanticReviewer : AudioSemanticReviewer {
    override suspend fun reviewWithDiagnostics(
        redactedTranscript: String,
        localEvidence: AudioEvidenceResult?
    ): AudioSemanticReviewAttempt = AudioSemanticReviewAttempt(response = null, reasonCode = "semantic_noop")
}

object AudioSemanticReviewFusion {
    private fun rank(verdict: AudioEvidenceVerdict): Int = when (verdict) {
        AudioEvidenceVerdict.UNVERIFIED -> 0
        AudioEvidenceVerdict.SUSPECT -> 1
        AudioEvidenceVerdict.DANGEROUS -> 2
    }

    private fun verdictForRiskClass(value: String?): AudioEvidenceVerdict? {
        return when (value?.trim()?.lowercase()) {
            "high" -> AudioEvidenceVerdict.DANGEROUS
            "medium" -> AudioEvidenceVerdict.SUSPECT
            else -> null
        }
    }

    fun fuse(
        local: AudioEvidenceResult?,
        review: AudioSemanticReviewResponse?
    ): AudioEvidenceResult {
        val base = local ?: AudioEvidenceEngine.evaluate(AudioEvidenceInput())
        val semantic = review?.semanticReview ?: return base
        val semanticVerdict = verdictForRiskClass(semantic.riskClass) ?: return base
        if (rank(semanticVerdict) <= rank(base.verdict)) return base

        val reasonCodes = (
            base.reasonCodes +
                semantic.reasonCodes +
                review.reasonCodes +
                "semantic:mistral_escalation"
            )
            .map { it.trim() }
            .filter { it.isNotBlank() }
            .distinct()

        return base.copy(
            verdict = semanticVerdict,
            reasonCodes = reasonCodes,
            sttOnly = false,
            processing = "on_device_plus_mistral_semantic",
            transcriptRedacted = true,
            arcFamily = semantic.matchedFamily ?: base.arcFamily,
            campaignMatch = semantic.matchedFamily ?: base.campaignMatch
        )
    }
}
