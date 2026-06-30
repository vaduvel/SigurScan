package ro.sigurscan.app

import java.util.Locale

enum class AudioEvidenceVerdict {
    DANGEROUS,
    SUSPECT,
    UNVERIFIED
}

enum class AudioIdentityProvenance {
    MATCH,
    MISMATCH,
    UNKNOWN
}

data class AudioEvidenceInput(
    val transcriptRedacted: String? = null,
    val claimedIdentity: String? = null,
    val sensitiveAsks: List<String> = emptyList(),
    val arcFamily: String? = null,
    val identityProvenance: AudioIdentityProvenance = AudioIdentityProvenance.UNKNOWN,
    val campaignMatch: String? = null,
    val campaignConfidence: Double = 0.0
)

data class AudioEvidenceResult(
    val verdict: AudioEvidenceVerdict,
    val reasonCodes: List<String>,
    val sttOnly: Boolean,
    val processing: String = "on_device_only",
    val rawAudioStored: Boolean = false,
    val transcriptRedacted: Boolean = false,
    val claimedIdentity: String? = null,
    val arcFamily: String? = null,
    val campaignMatch: String? = null
)

object AudioEvidenceEngine {
    private val hardSensitive = setOf("card", "otp", "password", "pin", "crypto", "remote", "id_document", "gift_card")
    private val valueSensitive = setOf("transfer")
    private val hardPriority = listOf("card", "otp", "password", "pin", "crypto", "remote", "id_document", "gift_card")
    private val criticalIdentityCampaigns = setOf(
        "CONV_BANK_SAFE_ACCOUNT",
        "CONV_BANK_FRAUDULENT_CREDIT",
        "CONV_BANK_ANTI_FRAUD_CALL",
        "CONV_TECH_SUPPORT_REMOTE_ACCESS",
        "CONV_AUTHORITY_IMPERSONATION_LEGAL_THREAT",
        "CONV_RECOVERY_SCAM",
        "CONV_VOICE_CLONE_EMERGENCY_IMPERSONATION",
        "CONV_MARKETPLACE_RECEIVE_MONEY"
    )

    fun evaluate(input: AudioEvidenceInput): AudioEvidenceResult {
        val sensitive = primarySensitive(input.sensitiveAsks)
        val identityStatus = identityStatus(input.identityProvenance, input.claimedIdentity)
        val sttOnly = sensitive == "none" && identityStatus != "lookalike"
        val campaignHigh = !input.campaignMatch.isNullOrBlank() && input.campaignConfidence >= 0.82

        val verdict = when {
            identityStatus == "lookalike" && (sensitive in hardSensitive || sensitive in valueSensitive) ->
                AudioEvidenceVerdict.DANGEROUS to listOf("identity_spoof")

            sensitive in hardSensitive ->
                AudioEvidenceVerdict.DANGEROUS to listOf("sensitive_wrong_channel")

            campaignHigh && identityStatus == "lookalike" && input.arcFamily in criticalIdentityCampaigns ->
                AudioEvidenceVerdict.DANGEROUS to listOf("critical_campaign_identity")

            campaignHigh ->
                AudioEvidenceVerdict.SUSPECT to listOf("campaign_match_only")

            sensitive in valueSensitive ->
                AudioEvidenceVerdict.SUSPECT to listOf("value_request_needs_verification")

            else ->
                AudioEvidenceVerdict.UNVERIFIED to listOf("residual")
        }.capSttOnly(sttOnly)

        return AudioEvidenceResult(
            verdict = verdict.first,
            reasonCodes = verdict.second,
            sttOnly = sttOnly,
            transcriptRedacted = !input.transcriptRedacted.isNullOrBlank(),
            claimedIdentity = input.claimedIdentity?.takeIf { it.isNotBlank() },
            arcFamily = input.arcFamily?.takeIf { it.isNotBlank() },
            campaignMatch = input.campaignMatch?.takeIf { it.isNotBlank() }
        )
    }

    private fun Pair<AudioEvidenceVerdict, List<String>>.capSttOnly(sttOnly: Boolean): Pair<AudioEvidenceVerdict, List<String>> {
        return if (sttOnly && first == AudioEvidenceVerdict.DANGEROUS) {
            AudioEvidenceVerdict.SUSPECT to listOf("stt_only_capped_suspect")
        } else {
            this
        }
    }

    private fun primarySensitive(values: List<String>): String {
        val normalized = values
            .mapNotNull { raw ->
                raw.trim()
                    .lowercase(Locale.US)
                    .replace("cvv", "card")
                    .takeIf { it.isNotBlank() }
            }
            .toSet()
        hardPriority.firstOrNull { it in normalized }?.let { return it }
        return valueSensitive.firstOrNull { it in normalized } ?: "none"
    }

    private fun identityStatus(provenance: AudioIdentityProvenance, claimedIdentity: String?): String {
        return when {
            provenance == AudioIdentityProvenance.MATCH -> "official_match"
            provenance == AudioIdentityProvenance.MISMATCH -> "lookalike"
            !claimedIdentity.isNullOrBlank() -> "lookalike"
            else -> "unknown"
        }
    }
}
