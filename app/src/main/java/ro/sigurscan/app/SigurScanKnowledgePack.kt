package ro.sigurscan.app

import android.content.Context
import com.google.gson.Gson
import com.google.gson.annotations.SerializedName
import java.security.MessageDigest
import java.util.Locale

data class KnowledgeSourceUrl(
    @SerializedName("source_id")
    val sourceId: String? = null,
    val url: String? = null,
    val published: String? = null,
    val accessed: String? = null
)

data class OfficialRegistryUpdate(
    @SerializedName("brand_id")
    val brandId: String,
    @SerializedName("display_name")
    val displayName: String,
    @SerializedName("official_domains")
    val officialDomains: List<String> = emptyList(),
    @SerializedName("official_apps_or_channels")
    val officialAppsOrChannels: List<String> = emptyList(),
    @SerializedName("approved_tracking_or_partner_domains")
    val approvedTrackingOrPartnerDomains: List<String> = emptyList(),
    @SerializedName("source_urls")
    val sourceUrls: List<KnowledgeSourceUrl> = emptyList(),
    val confidence: String = "medium",
    val notes: String? = null
)

data class BrandWarningPackEntry(
    @SerializedName("brand_id")
    val brandId: String,
    @SerializedName("never_ask_for")
    val neverAskFor: Map<String, Boolean> = emptyMap(),
    @SerializedName("exact_official_statement_summary")
    val exactOfficialStatementSummary: String? = null,
    @SerializedName("source_url")
    val sourceUrl: String? = null,
    val published: String? = null,
    val accessed: String? = null,
    val confidence: String = "medium",
    @SerializedName("evidence_gate_signal_suggested")
    val evidenceGateSignalSuggested: String? = null
)

data class ClaimVerifierTarget(
    @SerializedName("claim_type")
    val claimType: String,
    @SerializedName("cum_verificam_pe_web_oficial")
    val verifyHow: String? = null,
    @SerializedName("surse_oficiale_folosim")
    val officialSources: List<KnowledgeSourceUrl> = emptyList(),
    @SerializedName("claim_confirmed")
    val claimConfirmed: String? = null,
    @SerializedName("claim_not_found")
    val claimNotFound: String? = null,
    @SerializedName("de_ce_not_found_nu_e_automat_periculos")
    val notFoundReason: String? = null,
    @SerializedName("exemple_legitime")
    val legitimateExamples: List<String> = emptyList(),
    @SerializedName("exemple_fake")
    val fakeExamples: List<String> = emptyList()
)

data class ScenarioCorpusEntry(
    @SerializedName("scenario_id")
    val scenarioId: String,
    val title: String? = null,
    val family: String,
    @SerializedName("claimed_brand_or_role")
    val claimedBrandOrRole: String,
    @SerializedName("typical_text_patterns")
    val typicalTextPatterns: List<String> = emptyList(),
    @SerializedName("requested_asset")
    val requestedAsset: List<String> = emptyList(),
    val signals: List<String> = emptyList(),
    val examples: List<Any> = emptyList(),
    @SerializedName("acceptance_test_idea")
    val acceptanceTestIdea: String? = null
)

data class RomaniaKnowledgeLayerFile(
    @SerializedName("official_registry_updates")
    val officialRegistryUpdates: List<OfficialRegistryUpdate> = emptyList(),
    @SerializedName("brand_warnings")
    val brandWarnings: List<BrandWarningPackEntry> = emptyList(),
    @SerializedName("claim_verifier_targets")
    val claimVerifierTargets: List<ClaimVerifierTarget> = emptyList(),
    @SerializedName("scenario_corpus")
    val scenarioCorpus: List<ScenarioCorpusEntry> = emptyList(),
    @SerializedName("signal_mapping")
    val signalMapping: List<Map<String, Any>> = emptyList()
)

object SigurScanKnowledgePack {
    private const val ASSET_PATH = "knowledge/romania_knowledge_layer_compact.json"
    private val gson = Gson()

    @Volatile
    private var loaded: RomaniaKnowledgeLayerFile = RomaniaKnowledgeLayerFile()

    @Volatile
    private var registryVersion: String = "fallback-local"

    @Volatile
    private var corpusVersion: String = "fallback-local"

    fun initialize(context: Context?) {
        if (context == null) return
        runCatching {
            val json = context.assets.open(ASSET_PATH).use { stream ->
                stream.bufferedReader().readText()
            }
            initializeFromJson(json)
        }
    }

    fun initializeFromJson(json: String) {
        loaded = (gson.fromJson(json, RomaniaKnowledgeLayerFile::class.java) ?: RomaniaKnowledgeLayerFile()).normalized()
        registryVersion = fingerprint(loaded.officialRegistryUpdates, loaded.brandWarnings)
        corpusVersion = fingerprint(loaded.scenarioCorpus, loaded.claimVerifierTargets, loaded.signalMapping)
    }

    fun resetForTests() {
        loaded = RomaniaKnowledgeLayerFile()
        registryVersion = "fallback-local"
        corpusVersion = "fallback-local"
    }

    fun entries(staticEntries: List<BrandKnowledgeEntry>): List<BrandKnowledgeEntry> {
        val byId = LinkedHashMap<String, BrandKnowledgeEntry>()
        staticEntries.forEach { entry -> byId[canonicalBrandId(entry.id, entry.id)] = entry }

        loaded.officialRegistryUpdates.forEach { update ->
            val canonicalId = canonicalBrandId(update.brandId, update.displayName)
            val existing = byId[canonicalId]
            val warnings = loaded.brandWarnings
                .filter { canonicalBrandId(it.brandId, it.brandId) == canonicalId }
                .flatMap { warning -> warning.neverAskFor.toNeverAskForSet() }
                .toSet()
            val sourceRefs = update.sourceUrls.mapNotNull { it.url } + loaded.brandWarnings
                .filter { canonicalBrandId(it.brandId, it.brandId) == canonicalId }
                .mapNotNull { it.sourceUrl }

            byId[canonicalId] = BrandKnowledgeEntry(
                id = canonicalId,
                aliases = (existing?.aliases.orEmpty() + update.brandId + update.displayName)
                    .map { it.trim().lowercase(Locale.getDefault()) }
                    .filter { it.isNotBlank() }
                    .distinct(),
                officialDomains = (existing?.officialDomains.orEmpty() + update.officialDomains)
                    .map(::normalizeDomain)
                    .filter { it.isNotBlank() }
                    .distinct(),
                approvedTrackerDomains = (existing?.approvedTrackerDomains.orEmpty() + update.approvedTrackingOrPartnerDomains)
                    .map(::normalizeDomain)
                    .filter { it.isNotBlank() }
                    .toSet(),
                neverAskFor = existing?.neverAskFor.orEmpty() + warnings,
                sourceRefs = (existing?.sourceRefs.orEmpty() + sourceRefs).distinct()
            )
        }

        return byId.values.toList()
    }

    fun scenarioCorpus(): List<ScenarioCorpusEntry> = loaded.scenarioCorpus

    fun claimVerifierTargets(): List<ClaimVerifierTarget> = loaded.claimVerifierTargets

    fun registryVersion(): String = registryVersion

    fun corpusVersion(): String = corpusVersion

    private fun Map<String, Boolean>.toNeverAskForSet(): Set<NeverAskFor> {
        return entries.filter { it.value }.flatMap { (key, _) ->
            when (key.lowercase(Locale.US)) {
                "card_number" -> listOf(NeverAskFor.CARD_DATA)
                "cvv" -> listOf(NeverAskFor.CVV)
                "otp", "whatsapp_code" -> listOf(NeverAskFor.OTP_CODE)
                "banking_pin" -> listOf(NeverAskFor.PIN_CODE)
                "password" -> listOf(NeverAskFor.PASSWORD)
                "cnp" -> listOf(NeverAskFor.CNP)
                "iban" -> listOf(NeverAskFor.IBAN)
                "remote_access" -> listOf(NeverAskFor.REMOTE_ACCESS)
                "apk_install" -> listOf(NeverAskFor.APK_INSTALL)
                "safe_account_transfer", "crypto_atm_deposit" -> listOf(NeverAskFor.SAFE_ACCOUNT_TRANSFER)
                else -> emptyList()
            }
        }.toSet()
    }

    private fun canonicalBrandId(brandId: String, displayName: String): String {
        return when (normalizeBrandId(brandId)) {
            "fancourier", "fancourierro" -> "fanCourier"
            "postaromana", "posta_romana" -> "postaRomana"
            "orange_yoxo", "orangeyoxo", "yoxo" -> "yoxo"
            "ministerulfinantelor", "mfinante", "anaf" -> "anaf"
            "bt", "bancar", "bancatransilvania" -> "cardAndBanks"
            "olx" -> "marketplace"
            "ghiseul" -> "paymentsGovernment"
            "sameday", "cargus" -> "couriers"
            "hidroelectrica", "ppc", "eon", "digi", "vodafone" -> "utilities"
            else -> normalizeBrandId(brandId).takeIf { it.isNotBlank() } ?: normalizeBrandId(displayName)
        }
    }

    private fun normalizeBrandId(value: String): String {
        return value.lowercase(Locale.US).replace(Regex("[^a-z0-9]"), "")
    }

    private fun normalizeDomain(value: String): String {
        return value
            .trim()
            .removePrefix("http://")
            .removePrefix("https://")
            .substringBefore("/")
            .substringBefore("?")
            .lowercase(Locale.US)
            .removePrefix("www.")
            .trimEnd('.')
    }

    private fun RomaniaKnowledgeLayerFile.normalized(): RomaniaKnowledgeLayerFile {
        return copy(
            officialRegistryUpdates = officialRegistryUpdates.orEmpty().map { it.normalized() },
            brandWarnings = brandWarnings.orEmpty().map { it.normalized() },
            claimVerifierTargets = claimVerifierTargets.orEmpty().map { it.normalized() },
            scenarioCorpus = scenarioCorpus.orEmpty().map { it.normalized() },
            signalMapping = signalMapping.orEmpty()
        )
    }

    private fun OfficialRegistryUpdate.normalized(): OfficialRegistryUpdate {
        return copy(
            officialDomains = officialDomains.orEmpty(),
            officialAppsOrChannels = officialAppsOrChannels.orEmpty(),
            approvedTrackingOrPartnerDomains = approvedTrackingOrPartnerDomains.orEmpty(),
            sourceUrls = sourceUrls.orEmpty()
        )
    }

    private fun BrandWarningPackEntry.normalized(): BrandWarningPackEntry {
        return copy(neverAskFor = neverAskFor.orEmpty())
    }

    private fun ClaimVerifierTarget.normalized(): ClaimVerifierTarget {
        return copy(
            officialSources = officialSources.orEmpty(),
            legitimateExamples = legitimateExamples.orEmpty(),
            fakeExamples = fakeExamples.orEmpty()
        )
    }

    private fun ScenarioCorpusEntry.normalized(): ScenarioCorpusEntry {
        val patterns = typicalTextPatterns.orEmpty()
        val fallbackPatterns = if (patterns.isEmpty()) {
            (examples.orEmpty().map(::exampleToText) + signals.orEmpty() + listOfNotNull(title, claimedBrandOrRole))
        } else {
            patterns
        }
        return copy(
            scenarioId = scenarioId.orEmpty(),
            title = title,
            family = family.orEmpty(),
            claimedBrandOrRole = claimedBrandOrRole.orEmpty(),
            typicalTextPatterns = fallbackPatterns.filter { it.isNotBlank() },
            requestedAsset = requestedAsset.orEmpty(),
            signals = signals.orEmpty(),
            examples = examples.orEmpty().map(::exampleToText)
        )
    }

    private fun exampleToText(value: Any?): String {
        if (value == null) return ""
        if (value is String) return value
        if (value is Map<*, *>) {
            return listOfNotNull(
                value["sample_text"],
                value["text"],
                value["example"],
                value["expected_targets"]
            ).joinToString(" ")
        }
        return value.toString()
    }

    private fun fingerprint(vararg payloads: Any?): String {
        val digest = MessageDigest.getInstance("SHA-256")
        payloads.forEach { digest.update(it?.hashCode().toString().toByteArray()) }
        return digest.digest().joinToString("") { "%02x".format(it) }.take(10)
    }
}
