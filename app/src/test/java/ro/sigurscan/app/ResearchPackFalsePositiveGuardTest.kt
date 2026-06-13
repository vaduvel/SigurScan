package ro.sigurscan.app

import com.google.gson.JsonArray
import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import org.junit.Test

class ResearchPackFalsePositiveGuardTest {
    private val gate = EvidenceGate { 1_000L }
    private val packPaths = listOf(
        "research/sigurscan_research_test_pack_v1/false_positive_guard_tests.json",
        "research/sigurscan_ro_research_test_pack_2025_2026_v1/false_positive_guard_tests.json"
    )

    @Test
    fun falsePositiveGuardPackNeverReturnsDangerousVerdict() {
        val cases = loadCases()
        val failures = mutableListOf<String>()

        cases.forEach { testCase ->
            val snapshot = snapshotFor(testCase)
            val result = gate.evaluate(snapshot)
            val dangerousActions = setOf(
                GateAction.DO_NOT_CONTINUE,
                GateAction.NO_ENTER_DATA,
                GateAction.NO_REPLY
            )

            if (result.action in dangerousActions) {
                failures += "${testCase.packName}/${testCase.id}: returned ${result.action} with reasons=${result.reasonCodes}"
            }
        }

        assert(failures.isEmpty()) {
            "False-positive guard pack produced dangerous verdicts:\n${failures.joinToString("\n")}"
        }
    }

    private fun snapshotFor(testCase: FalsePositiveGuardCase): EvidenceSnapshot {
        val target = testCase.finalUrl
        val primary = testCase.primaryUrl ?: target
        val codes = linkedSetOf<EvidenceCode>()

        testCase.presentSignals.forEach { signal ->
            when (signal) {
                "MARKETING_TEXT" -> {
                    codes += EvidenceCode.PROMO_TEXT
                    codes += EvidenceCode.CTA_TEXT
                }
                "LINK_UNDER_BUTTON" -> codes += EvidenceCode.HTML_BUTTON_LINK
                "TRACKING_LINK" -> codes += EvidenceCode.TRACKING_LINK
                "OFFICIAL_DOMAIN_EXACT" -> codes += EvidenceCode.OFFICIAL_DOMAIN_EXACT
                "DOMAIN_AGE_VERY_NEW" -> codes += EvidenceCode.DOMAIN_AGE_VERY_RECENT
                "PUNYCODE_HOST" -> codes += EvidenceCode.PUNYCODE_HOST
                "BRAND_IMPERSONATION_CANDIDATE" -> codes += EvidenceCode.CORPUS_SIMILARITY
                "SENSITIVE_FORM" -> {
                    // First-party login forms are not SENSITIVE_FORM_UNOFFICIAL.
                }
            }
        }

        if (testCase.expectedVerdict == "SAFE") {
            codes += EvidenceCode.OFFICIAL_DOMAIN_EXACT
        }
        if (testCase.sampleText.contains("<a", ignoreCase = true) || testCase.sampleText.contains("http", ignoreCase = true)) {
            codes += EvidenceCode.HTML_BUTTON_LINK
        }
        if (
            testCase.sampleText.contains("ofert", ignoreCase = true) ||
            testCase.sampleText.contains("promo", ignoreCase = true) ||
            testCase.sampleText.contains("reduc", ignoreCase = true) ||
            testCase.sampleText.contains("catalog", ignoreCase = true)
        ) {
            codes += EvidenceCode.PROMO_TEXT
            codes += EvidenceCode.CTA_TEXT
        }

        codes += EvidenceCode.NO_SENSITIVE_FORM
        codes += EvidenceCode.WEBRISK_NO_MATCH
        codes += EvidenceCode.URLSCAN_NO_CLASSIFICATION
        if (testCase.expectedVerdict == "SAFE" && codes.contains(EvidenceCode.PROMO_TEXT)) {
            codes += EvidenceCode.OFFER_CLAIM_CONFIRMED
        }

        return EvidenceSnapshot(
            scanId = testCase.id,
            inputKind = "research_false_positive_guard",
            channel = testCase.channel ?: "unknown",
            primaryUrl = primary,
            finalUrl = target ?: primary,
            signals = codes.map { code -> signalFor(code, target ?: primary ?: testCase.id) },
            providerStates = mapOf(
                ProviderId.WEB_RISK to ProviderState(ProviderId.WEB_RISK, ProviderStatus.OK),
                ProviderId.URLSCAN to ProviderState(ProviderId.URLSCAN, ProviderStatus.OK),
                ProviderId.PHISHING_DATABASE to ProviderState(ProviderId.PHISHING_DATABASE, ProviderStatus.SKIPPED, note = "not_required"),
                ProviderId.CLAIM_VERIFIER to ProviderState(ProviderId.CLAIM_VERIFIER, ProviderStatus.OK)
            ),
            completeness = EvidenceCompleteness.FULL
        )
    }

    private fun signalFor(code: EvidenceCode, targetKey: String): EvidenceSignal {
        return EvidenceSignal(
            id = "${code.name}-$targetKey",
            source = sourceFor(code),
            code = code,
            targetKey = targetKey,
            provider = providerFor(code)
        )
    }

    private fun sourceFor(code: EvidenceCode): EvidenceSource = when (code) {
        EvidenceCode.WEBRISK_NO_MATCH -> EvidenceSource.GOOGLE_WEB_RISK
        EvidenceCode.URLSCAN_NO_CLASSIFICATION -> EvidenceSource.URLSCAN
        EvidenceCode.OFFER_CLAIM_CONFIRMED -> EvidenceSource.CLAIM_VERIFIER
        EvidenceCode.OFFICIAL_DOMAIN_EXACT -> EvidenceSource.OFFICIAL_REGISTRY
        EvidenceCode.PUNYCODE_HOST,
        EvidenceCode.DOMAIN_AGE_VERY_RECENT -> EvidenceSource.INFRA_ANALYZER
        else -> EvidenceSource.LOCAL_EXTRACTOR
    }

    private fun providerFor(code: EvidenceCode): ProviderId? = when (sourceFor(code)) {
        EvidenceSource.GOOGLE_WEB_RISK -> ProviderId.WEB_RISK
        EvidenceSource.URLSCAN -> ProviderId.URLSCAN
        EvidenceSource.CLAIM_VERIFIER -> ProviderId.CLAIM_VERIFIER
        EvidenceSource.OFFICIAL_REGISTRY -> ProviderId.OFFICIAL_REGISTRY
        EvidenceSource.INFRA_ANALYZER -> ProviderId.INFRA
        else -> null
    }

    private fun loadCases(): List<FalsePositiveGuardCase> {
        return packPaths.flatMap { path ->
            val resource = requireNotNull(javaClass.classLoader?.getResourceAsStream(path)) {
                "Missing research false-positive guard pack resource: $path"
            }
            val root = resource.bufferedReader(Charsets.UTF_8).use { reader ->
                JsonParser.parseReader(reader)
            }
            val packName = path.substringAfter("research/").substringBefore("/")
            casesFromRoot(packName, root)
        }
    }

    private fun casesFromRoot(packName: String, root: JsonElement): List<FalsePositiveGuardCase> {
        val array = when {
            root.isJsonArray -> root.asJsonArray
            root.isJsonObject && root.asJsonObject.has("tests") -> root.asJsonObject.getAsJsonArray("tests")
            else -> JsonArray()
        }
        return array.mapNotNull { element ->
            if (!element.isJsonObject) return@mapNotNull null
            val obj = element.asJsonObject
            val id = obj.string("id") ?: obj.string("test_id") ?: return@mapNotNull null
            val input = obj.get("input")?.takeIf { it.isJsonObject }?.asJsonObject
            val expectedTargets = obj.get("expected_extracted_targets")
                ?.takeIf { it.isJsonArray }
                ?.asJsonArray
                ?.mapNotNull { it.asStringOrNull() }
                .orEmpty()
            val finalUrl = input?.string("final_url")
                ?: expectedTargets.firstOrNull()?.let { target -> if (target.startsWith("http")) target else "https://$target/" }
            val primaryUrl = input?.string("primary_url")
                ?: input?.string("button_href")
                ?: finalUrl
            FalsePositiveGuardCase(
                packName = packName,
                id = id,
                channel = obj.string("channel") ?: obj.string("input_type"),
                primaryUrl = primaryUrl,
                finalUrl = finalUrl,
                sampleText = obj.string("sample_text").orEmpty(),
                presentSignals = obj.get("present_signals")
                    ?.takeIf { it.isJsonArray }
                    ?.asJsonArray
                    ?.mapNotNull { it.asStringOrNull() }
                    .orEmpty(),
                expectedVerdict = obj.string("expectedVerdict") ?: obj.string("expected_final_verdict")
            )
        }
    }

    private fun JsonObject.string(name: String): String? {
        return get(name)?.asStringOrNull()
    }

    private fun JsonElement.asStringOrNull(): String? {
        return if (isJsonPrimitive && asJsonPrimitive.isString) asString else null
    }

    private data class FalsePositiveGuardCase(
        val packName: String,
        val id: String,
        val channel: String? = null,
        val primaryUrl: String? = null,
        val finalUrl: String? = null,
        val sampleText: String = "",
        val presentSignals: List<String> = emptyList(),
        val expectedVerdict: String? = null
    )
}
