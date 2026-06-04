package ro.sigurscan.app

import java.io.File
import org.junit.After
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class KnowledgePackIntegrationTest {
    @After
    fun tearDown() {
        SigurScanKnowledgePack.resetForTests()
    }

    @Test
    fun loadsRomaniaKnowledgePackAndExtendsRegistry() {
        SigurScanKnowledgePack.initializeFromJson(knowledgePackJson())

        assertNotEquals("fallback-local", BrandKnowledgeRegistry.registryVersion())
        assertNotEquals("fallback-local", BrandKnowledgeRegistry.corpusVersion())
        assertTrue(BrandKnowledgeRegistry.entries.any { it.id == "yoxo" && it.officialDomains.contains("newsroom.orange.ro") })
        assertTrue(BrandKnowledgeRegistry.entries.any { it.id == "postaRomana" && it.officialDomains.contains("ropost.ro") })
        assertTrue(SigurScanKnowledgePack.claimVerifierTargets().any { it.claimType.contains("YOXO", ignoreCase = true) })
        assertTrue(SigurScanKnowledgePack.scenarioCorpus().any { it.scenarioId.contains("FAN", ignoreCase = true) })
    }

    @Test
    fun knowledgeLayerEmitsClaimVerifierSignalForYoxoBuyback() {
        SigurScanKnowledgePack.initializeFromJson(knowledgePackJson())

        val signals = ScamKnowledgeLayer.evaluate(
            ScamKnowledgeInput(
                rawText = "Ai un telefon vechi? Foloseste serviciul buyback YOXO si primesti plata in cont.",
                claimedBrandIds = setOf("yoxo"),
                targetHost = "buyback.yoxo.ro",
                targetIsOfficial = true,
                hasTarget = true
            )
        )

        assertTrue(signals.any {
            it.source == EvidenceSource.CORPUS &&
                it.code == EvidenceCode.CORPUS_SIMILARITY &&
                it.attrs["claimContextOnly"] == "true"
        })
    }

    @Test
    fun normalizerUsesPackCorpusAndRegistryVersions() {
        SigurScanKnowledgePack.initializeFromJson(knowledgePackJson())

        val snapshot = EvidenceSignalNormalizer.buildSnapshot(
            EvidenceNormalizerInput(
                inputKind = "sms",
                channel = "text_with_url",
                rawText = "FAN Courier: colet blocat. Alege locker si trimite cod WhatsApp pentru verificare: https://fanbox-help.example.test",
                primaryUrl = "https://fanbox-help.example.test",
                finalUrl = "https://fanbox-help.example.test",
                threatIntel = listOf(
                    ThreatIntelSourceResult("Google Web Risk", "No Threats", "low", "NO_MATCH"),
                    ThreatIntelSourceResult("urlscan.io", "No malicious classification", "low", "NO_VISIBLE_RISK"),
                    ThreatIntelSourceResult("VirusTotal", "Clean", "low", "malicious=0")
                ),
                virusTotalConfigured = true
            )
        )

        assertNotEquals("local", snapshot.registryVersion)
        assertNotEquals("local", snapshot.corpusVersion)
        assertTrue(snapshot.signals.any { it.code == EvidenceCode.CORPUS_SIMILARITY })
        assertTrue(snapshot.signals.any { it.code == EvidenceCode.CORPUS_BRAND_WARNING && it.brandId == "fanCourier" })
    }

    private fun knowledgePackJson(): String {
        val candidates = listOf(
            File("src/main/assets/knowledge/romania_knowledge_layer_compact.json"),
            File("app/src/main/assets/knowledge/romania_knowledge_layer_compact.json")
        )
        return candidates.first { it.exists() }.readText()
    }
}
