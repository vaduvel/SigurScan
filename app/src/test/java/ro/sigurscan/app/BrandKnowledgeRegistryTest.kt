package ro.sigurscan.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class BrandKnowledgeRegistryTest {
    @Test
    fun trustedOfficialDomainsAreDerivedFromRuntimeKnowledgeRegistry() {
        assertEquals(
            BrandKnowledgeRegistry.trustedOfficialDomains,
            ScamRules.TRUSTED_OFFICIAL_DOMAINS
        )
        assertTrue(ScamRules.TRUSTED_OFFICIAL_DOMAINS["yoxo"].orEmpty().contains("buyback.yoxo.ro"))
        assertTrue(ScamRules.TRUSTED_OFFICIAL_DOMAINS["idroid"].orEmpty().contains("idroid.ro"))
        assertTrue(ScamRules.TRUSTED_OFFICIAL_DOMAINS["dnsc"].orEmpty().contains("sigurantaonline.ro"))
    }

    @Test
    fun anafAndBankingNeverAskForRulesAreAvailableToTheKnowledgeLayer() {
        val anaf = BrandKnowledgeRegistry.findById("anaf")
        val banks = BrandKnowledgeRegistry.findById("cardAndBanks")
        val couriers = BrandKnowledgeRegistry.findById("fanCourier")
        val retail = BrandKnowledgeRegistry.findById("retail")
        val utilities = BrandKnowledgeRegistry.findById("utilities")

        assertTrue(anaf?.neverAskFor.orEmpty().contains(NeverAskFor.CARD_DATA))
        assertTrue(anaf?.neverAskFor.orEmpty().contains(NeverAskFor.OTP_CODE))
        assertTrue(banks?.neverAskFor.orEmpty().contains(NeverAskFor.SAFE_ACCOUNT_TRANSFER))
        assertTrue(couriers?.neverAskFor.orEmpty().contains(NeverAskFor.CVV))
        assertTrue(banks?.officialDomains.orEmpty().contains("raiffeisen.ro"))
        assertTrue(retail?.officialDomains.orEmpty().contains("dedeman.ro"))
        assertTrue(retail?.officialDomains.orEmpty().contains("kaufland.ro"))
        assertTrue(utilities?.officialDomains.orEmpty().contains("engie.ro"))
    }
}
