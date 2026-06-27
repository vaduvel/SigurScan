package ro.sigurscan.app

interface AudioSemanticReviewer {
    suspend fun review(
        redactedTranscript: String,
        localEvidence: AudioEvidenceResult?
    ): AudioSemanticReviewResponse?
}

class BackendAudioSemanticReviewer(
    private val api: SigurScanApi,
    private val channel: String
) : AudioSemanticReviewer {
    override suspend fun review(
        redactedTranscript: String,
        localEvidence: AudioEvidenceResult?
    ): AudioSemanticReviewResponse? {
        if (redactedTranscript.isBlank()) return null
        return runCatching {
            api.reviewAudioTranscript(
                AudioSemanticReviewRequest(
                    transcriptRedacted = redactedTranscript,
                    channel = channel,
                    localVerdict = localEvidence?.verdict?.name ?: AudioEvidenceVerdict.UNVERIFIED.name,
                    localReasonCodes = localEvidence?.reasonCodes.orEmpty(),
                    claimedIdentity = localEvidence?.claimedIdentity,
                    arcFamily = localEvidence?.arcFamily
                )
            )
        }.getOrNull()
    }
}

object NoopAudioSemanticReviewer : AudioSemanticReviewer {
    override suspend fun review(
        redactedTranscript: String,
        localEvidence: AudioEvidenceResult?
    ): AudioSemanticReviewResponse? = null
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
