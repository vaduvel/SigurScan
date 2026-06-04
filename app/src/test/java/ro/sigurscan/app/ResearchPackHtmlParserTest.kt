package ro.sigurscan.app

import com.google.gson.JsonArray
import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import org.junit.Assert.assertTrue
import org.junit.Test

class ResearchPackHtmlParserTest {
    private val packPaths = listOf(
        "research/sigurscan_research_test_pack_v1/html_email_parser_torture_tests.json",
        "research/sigurscan_ro_research_test_pack_2025_2026_v1/html_email_parser_torture_tests.json"
    )

    @Test
    fun htmlTorturePackExtractsExpectedActionableUrls() {
        val cases = loadCases()
        val failures = mutableListOf<String>()

        cases.forEach { testCase ->
            val extracted = HtmlLinkExtractor.extractHtmlLinks(testCase.html)

            testCase.expectedTargets.forEach { expectedTarget ->
                if (!matchesExpectedTarget(extracted, expectedTarget)) {
                    failures += "${testCase.packName}/${testCase.id}: missing $expectedTarget; extracted=$extracted"
                }
            }
        }

        assertTrue(
            "HTML parser failed research torture pack:\n${failures.joinToString("\n")}",
            failures.isEmpty()
        )
    }

    private fun matchesExpectedTarget(extracted: List<String>, expectedTarget: String): Boolean {
        val expected = expectedTarget.trim()
        return extracted.any { candidate ->
            candidate == expected ||
                candidate.contains(expected, ignoreCase = true) ||
                candidateHost(candidate).equals(expected, ignoreCase = true)
        }
    }

    private fun candidateHost(candidate: String): String {
        val withoutScheme = candidate.substringAfter("://", candidate)
        return withoutScheme.substringBefore("/").substringBefore("?").substringBefore("#")
    }

    private fun loadCases(): List<HtmlTortureCase> {
        return packPaths.flatMap { path ->
            val resource = requireNotNull(javaClass.classLoader?.getResourceAsStream(path)) {
                "Missing research HTML torture pack resource: $path"
            }
            val root = resource.bufferedReader(Charsets.UTF_8).use { reader ->
                JsonParser.parseReader(reader)
            }
            val packName = path.substringAfter("research/").substringBefore("/")
            casesFromRoot(packName, root)
        }
    }

    private fun casesFromRoot(packName: String, root: JsonElement): List<HtmlTortureCase> {
        val array = when {
            root.isJsonArray -> root.asJsonArray
            root.isJsonObject && root.asJsonObject.has("tests") -> root.asJsonObject.getAsJsonArray("tests")
            else -> JsonArray()
        }
        return array.mapNotNull { element ->
            if (!element.isJsonObject) return@mapNotNull null
            val obj = element.asJsonObject
            val id = obj.string("id") ?: obj.string("test_id") ?: return@mapNotNull null
            val html = obj.string("html") ?: obj.string("html_mime_fragment") ?: return@mapNotNull null
            val expectedTargets = expectedTargetsFor(id, obj)
            HtmlTortureCase(packName, id, html, expectedTargets)
        }
    }

    private fun expectedTargetsFor(id: String, obj: JsonObject): List<String> {
        val expectedFromList = obj.get("expected_extracted_targets")
            ?.takeIf { it.isJsonArray }
            ?.asJsonArray
            ?.mapNotNull { it.asStringOrNull() }
            .orEmpty()
        if (expectedFromList.isNotEmpty()) return expectedFromList

        val expected = obj.get("expected")?.takeIf { it.isJsonObject }?.asJsonObject
        val explicit = expected?.string("final_url")?.takeIf { it.isNotBlank() }
        if (explicit != null) return listOf(explicit)

        return when (id) {
            "ht_zero_width_in_host" -> listOf("https://fancourier-update.test/awb")
            "ht_data_uri" -> listOf("https://evil.test")
            "ht_hidden_prefilled_form" -> listOf("https://collect.test/card")
            "ht_nested_redirect_param" -> listOf("https://phish.test/pay")
            "ht_rtl_override" -> listOf("https://drive.test/facturagpj.exe")
            "ht_multiple_anchors_pick_action" -> listOf("https://fancourier-awb.test/track")
            "ht_encoded_entities_host" -> listOf("https://phish.test/login")
            "ht_ip_literal_host" -> listOf("http://192.0.2.10/bcr/login")
            else -> emptyList()
        }
    }

    private fun JsonObject.string(name: String): String? {
        return get(name)?.asStringOrNull()
    }

    private fun JsonElement.asStringOrNull(): String? {
        return if (isJsonPrimitive && asJsonPrimitive.isString) asString else null
    }

    private data class HtmlTortureCase(
        val packName: String,
        val id: String,
        val html: String,
        val expectedTargets: List<String>
    )
}
