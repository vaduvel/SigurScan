package ro.sigurscan.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ResultMappingTest {
    @Test
    fun unverifiedSharedAudioDoesNotPresentAsSafe() {
        val assessment = OfflineAssessment(
            family = "Neverificat",
            riskScore = 0,
            riskLevel = "unknown",
            reasons = listOf("Audio-ul partajat a fost procesat local, dar nu avem suficiente dovezi."),
            safeActions = listOf("Verifică separat persoana sau instituția pretinsă."),
            keyDangers = emptyList(),
            originalText = "Audio analizat local, fără stocare raw: profi_go_4.m4a.",
            reputationVerdict = "Neverificat"
        )

        val riskUi = mapRiskDisplayState(assessment)
        val decision = mapUserActionDecision(assessment, riskUi)
        val actions = buildNextActions(assessment, decision).joinToString(" ").lowercase()

        assertEquals("Neverificat", riskUi.level)
        assertEquals("Neverificat", decision.headline)
        assertTrue(decision.supportText.contains("nu avem suficiente", ignoreCase = true))
        assertTrue(actions.contains("verific"))
        assertFalse(actions.contains("poți continua"))
        assertFalse(actions.contains("poti continua"))
    }
}
