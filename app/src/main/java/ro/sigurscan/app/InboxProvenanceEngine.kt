package ro.sigurscan.app

import java.util.Locale

data class InboxSignalBundle(
    val messageHash: String,
    val claimedBrand: String? = null,
    val observedDomain: String? = null,
    val sensitiveAsks: List<String> = emptyList(),
    val hasUrl: Boolean = false
)

data class InboxProvenanceVerdict(
    val verdict: OnDeviceInboxVerdict,
    val manifestId: String? = null,
    val reasonCodes: List<String> = emptyList(),
    val processing: String = "on_device_only",
    val rawStored: Boolean = false
)

enum class OnDeviceInboxVerdict {
    SAFE,
    SUSPECT,
    DANGEROUS,
    UNVERIFIED
}

object InboxProvenanceEngine {
    fun evaluate(bundle: InboxSignalBundle, btr: BtrSyncSnapshot?): InboxProvenanceVerdict {
        if (btr == null || btr.manifests.isEmpty()) {
            return InboxProvenanceVerdict(
                verdict = OnDeviceInboxVerdict.UNVERIFIED,
                reasonCodes = listOf("btr_missing")
            )
        }

        val manifest = findManifest(bundle, btr)
            ?: return InboxProvenanceVerdict(
                verdict = OnDeviceInboxVerdict.UNVERIFIED,
                reasonCodes = listOf("no_manifest_match")
            )

        val normalizedAsks = bundle.sensitiveAsks.map { normalizeToken(it) }.filter { it.isNotBlank() }
        val neverAskViolations = normalizedAsks.filter { ask ->
            manifest.neverAsks.map(::normalizeToken).contains(ask)
        }.distinct()
        if (neverAskViolations.isNotEmpty()) {
            return InboxProvenanceVerdict(
                verdict = OnDeviceInboxVerdict.DANGEROUS,
                manifestId = manifest.manifestId,
                reasonCodes = neverAskViolations.map { "never_ask_violation:$it" }
            )
        }

        val officialDomainMatch = domainMatches(bundle.observedDomain, manifest.officialDomains)
        if (officialDomainMatch && normalizedAsks.isEmpty()) {
            return InboxProvenanceVerdict(
                verdict = OnDeviceInboxVerdict.SAFE,
                manifestId = manifest.manifestId,
                reasonCodes = listOf("official_domain_match")
            )
        }

        return InboxProvenanceVerdict(
            verdict = if (officialDomainMatch) OnDeviceInboxVerdict.SUSPECT else OnDeviceInboxVerdict.UNVERIFIED,
            manifestId = manifest.manifestId,
            reasonCodes = if (officialDomainMatch) listOf("official_domain_requires_review") else listOf("brand_match_without_domain")
        )
    }

    private fun findManifest(bundle: InboxSignalBundle, btr: BtrSyncSnapshot): BtrManifest? {
        val claimed = normalizeName(bundle.claimedBrand)
        return btr.manifests.firstOrNull { manifest ->
            claimed.isNotBlank() && (
                normalizeName(manifest.displayName).contains(claimed) ||
                    claimed.contains(normalizeName(manifest.displayName)) ||
                    normalizeName(manifest.manifestId) == claimed
                )
        } ?: btr.manifests.firstOrNull { manifest ->
            domainMatches(bundle.observedDomain, manifest.officialDomains)
        }
    }

    private fun domainMatches(observedDomain: String?, officialDomains: List<String>): Boolean {
        val observed = observedDomain.orEmpty()
            .trim()
            .removePrefix("http://")
            .removePrefix("https://")
            .substringBefore("/")
            .substringBefore(":")
            .lowercase(Locale.US)
            .removePrefix("www.")
        if (observed.isBlank()) return false
        return officialDomains.any { raw ->
            val official = raw.trim().lowercase(Locale.US).removePrefix("www.")
            official.isNotBlank() && (observed == official || observed.endsWith(".$official"))
        }
    }

    private fun normalizeToken(value: String?): String {
        return value.orEmpty().trim().lowercase(Locale.US)
            .replace("card_number", "card")
            .replace("cvv", "card")
    }

    private fun normalizeName(value: String?): String {
        return value.orEmpty().trim().lowercase(Locale.US)
            .replace(Regex("[^a-z0-9ăâîșţț ]"), "")
            .replace(Regex("\\s+"), " ")
    }
}
