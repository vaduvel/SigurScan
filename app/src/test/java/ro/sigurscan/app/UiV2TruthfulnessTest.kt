package ro.sigurscan.app

import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class UiV2TruthfulnessTest {
    @Test
    fun campaignFailureNeverClaimsTheFeedWasUpdatedOrEmpty() {
        val presentation = campaignFeedPresentation(
            loadState = CampaignLoadState.ERROR,
            hasCampaigns = false,
        )

        assertEquals("Actualizare indisponibilă", presentation.statusLabel)
        assertEquals("Nu am putut verifica acum campaniile active. Reîncearcă.", presentation.emptyLabel)
        assertFalse(presentation.statusLabel.contains("Actualizat"))
        assertFalse(presentation.emptyLabel.orEmpty().contains("Nicio campanie"))
    }

    @Test
    fun successfulEmptyCampaignFeedCanSayNoMajorCampaigns() {
        val presentation = campaignFeedPresentation(
            loadState = CampaignLoadState.READY,
            hasCampaigns = false,
        )

        assertEquals("Actualizat acum", presentation.statusLabel)
        assertEquals("Nicio campanie majoră semnalată acum.", presentation.emptyLabel)
    }

    @Test
    fun familyProtectionSummaryUsesOnlyConfiguredMembers() {
        assertEquals(
            "Protecția familiei nu este configurată.",
            familyProtectionSummary(emptyList()),
        )
        assertEquals(
            "Protecție activă pentru 1 din 2 membri.",
            familyProtectionSummary(
                listOf(
                    FamilyMember(name = "Ana", contact = "0700000000", isProtected = true),
                    FamilyMember(name = "Mihai", contact = "0711111111", isProtected = false),
                )
            ),
        )
    }

    @Test
    fun v2CopyDoesNotPromiseActionsTheAppDoesNotPerform() {
        val radarSource = File("src/main/java/ro/sigurscan/app/RadarScreen.kt").readText()
        val triageSource = File("src/main/java/ro/sigurscan/app/TriageScreen.kt").readText()

        assertFalse(radarSource.contains(".clickable { viewModel.loadCampaigns() }"))
        assertTrue(radarSource.contains("Folosit automat în scanări"))
        assertFalse(triageSource.contains("completăm noi datele"))
        assertTrue(triageSource.contains("Deschide canalul oficial DNSC"))
        assertTrue(triageSource.contains("https://pnrisc.dnsc.ro"))
    }

    @Test
    fun primaryScanInputHasAnAccessibleLabel() {
        val scanSource = File("src/main/java/ro/sigurscan/app/ScanScreen.kt").readText()

        assertTrue(scanSource.contains("Text sau link de verificat"))
    }
}
