package ro.sigurscan.app

private val AUDIO_VERDICT_RANK = mapOf(
    AudioEvidenceVerdict.UNVERIFIED to 0,
    AudioEvidenceVerdict.SUSPECT to 1,
    AudioEvidenceVerdict.DANGEROUS to 2
)

class AudioEvidenceSessionAggregator {
    private var transcriptSeen: Boolean = false
    private var claimedIdentity: String? = null
    private var arcFamily: String? = null
    private var campaignMatch: String? = null
    private var valueRequestSeen: Boolean = false
    private var strongest: AudioEvidenceResult? = null

    fun absorb(evidence: AudioEvidenceResult): AudioEvidenceResult {
        transcriptSeen = transcriptSeen || evidence.transcriptRedacted
        claimedIdentity = claimedIdentity ?: evidence.claimedIdentity?.takeIf { it.isNotBlank() }
        arcFamily = arcFamily ?: evidence.arcFamily?.takeIf { it.isNotBlank() }
        campaignMatch = campaignMatch ?: evidence.campaignMatch?.takeIf { it.isNotBlank() }
        valueRequestSeen = valueRequestSeen ||
            "value_request_needs_verification" in evidence.reasonCodes ||
            evidence.arcFamily == "CONV_BANK_SAFE_ACCOUNT"

        val aggregated = aggregate()
        strongest = listOfNotNull(strongest, evidence, aggregated)
            .maxWith(
                compareBy<AudioEvidenceResult> { AUDIO_VERDICT_RANK[it.verdict] ?: 0 }
                    .thenBy { decisiveReasonRank(it) }
                    .thenBy { it.reasonCodes.size }
            )
        return strongest ?: aggregated
    }

    private fun decisiveReasonRank(result: AudioEvidenceResult): Int {
        return when {
            "sensitive_wrong_channel" in result.reasonCodes -> 4
            "identity_spoof" in result.reasonCodes -> 3
            "critical_campaign_identity" in result.reasonCodes -> 2
            "campaign_match_only" in result.reasonCodes -> 1
            else -> 0
        }
    }

    private fun aggregate(): AudioEvidenceResult {
        val effectiveArcFamily = arcFamily ?: inferredArcFamily()
        return AudioEvidenceEngine.evaluate(
            AudioEvidenceInput(
                transcriptRedacted = "[redactat]".takeIf { transcriptSeen },
                claimedIdentity = claimedIdentity,
                sensitiveAsks = listOf("transfer").takeIf { valueRequestSeen }.orEmpty(),
                arcFamily = effectiveArcFamily,
                identityProvenance = if (claimedIdentity.isNullOrBlank()) {
                    AudioIdentityProvenance.UNKNOWN
                } else {
                    AudioIdentityProvenance.MISMATCH
                },
                campaignMatch = campaignMatch ?: effectiveArcFamily?.lowercase(),
                campaignConfidence = campaignConfidenceFor(effectiveArcFamily)
            )
        )
    }

    private fun inferredArcFamily(): String? {
        return if (!claimedIdentity.isNullOrBlank() && valueRequestSeen) {
            "CONV_BANK_SAFE_ACCOUNT"
        } else {
            null
        }
    }

    private fun campaignConfidenceFor(family: String?): Double {
        return when (family) {
            "CONV_BANK_SAFE_ACCOUNT" -> 0.96
            "CONV_BANK_FRAUDULENT_CREDIT" -> 0.92
            "CONV_INVESTMENT_REMOTE_ACCESS" -> 0.90
            "CONV_FAMILY_EMERGENCY" -> 0.88
            else -> 0.0
        }
    }
}
