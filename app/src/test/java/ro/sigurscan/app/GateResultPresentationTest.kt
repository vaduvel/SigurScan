package ro.sigurscan.app

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class GateResultPresentationTest {

    @Test
    fun everyGateActionHasPlainLanguageCopyAndRecommendedActions() {
        GateAction.entries.forEach { action ->
            val result = gateResult(action)

            assertTrue(result.userLabel.isNotBlank())
            assertTrue(GateResultPresentation.supportText(result).isNotBlank())
            assertTrue(GateResultPresentation.primaryAction(result).isNotBlank())
            assertTrue(GateResultPresentation.reasonText(result, null).isNotBlank())
            assertTrue(GateResultPresentation.recommendedActions(result).size >= 2)
        }
    }

    @Test
    fun verifiedCleanOfficialDestinationUsesThreeStatusSafeCopyWithoutGuarantees() {
        val result = gateResult(GateAction.CONTINUE_WITH_CAUTION)
        val copy = listOf(
            result.userLabel,
            GateResultPresentation.supportText(result),
            GateResultPresentation.primaryAction(result)
        )
            .plus(GateResultPresentation.recommendedActions(result))
            .joinToString(" ")
            .lowercase()

        assertTrue(result.userLabel == "Sigur")
        assertFalse(copy.contains("100%"))
        assertFalse(copy.contains("garantat"))
        assertFalse(copy.contains("safe"))
        assertFalse(copy.contains("prudenta"))
        assertFalse(copy.contains("prudență"))
    }

    @Test
    fun insufficientEvidenceCopyDoesNotSoundLikeAThreatVerdict() {
        val result = gateResult(GateAction.INSUFFICIENT_EVIDENCE, unknownReason = "PROVIDERS_UNAVAILABLE")
        val copy = listOf(
            result.userLabel,
            GateResultPresentation.supportText(result),
            GateResultPresentation.reasonText(result, null),
            GateResultPresentation.primaryAction(result)
        )
            .plus(GateResultPresentation.recommendedActions(result))
            .joinToString(" ")
            .lowercase()

        assertTrue(copy.contains("scan"))
        assertTrue(copy.contains("asteapta") || copy.contains("așteaptă") || copy.contains("reincearca") || copy.contains("reîncearcă"))
        assertFalse(copy.contains("phishing confirmat"))
        assertFalse(copy.contains("malware confirmat"))
        assertFalse(copy.contains("nu continua"))
    }

    @Test
    fun providerUnavailableFinalUsesNeutralNeverificatPresentation() {
        val result = gateResult(
            GateAction.INSUFFICIENT_EVIDENCE,
            reasonCodes = listOf("PROVIDER_REVIEW_REQUIRED"),
            unknownReason = "PROVIDERS_UNAVAILABLE",
            finality = GateFinality.FINAL
        )
        val display = mapGateDisplayState(result)
        val copy = listOf(
            GateResultPresentation.familyLabel(result, "fallback"),
            GateResultPresentation.legacyRiskLevel(result),
            GateResultPresentation.userHeadline(result),
            GateResultPresentation.supportText(result),
            GateResultPresentation.reasonText(result, null),
            GateResultPresentation.primaryAction(result)
        )
            .plus(GateResultPresentation.recommendedActions(result))
            .joinToString(" ")
            .lowercase()

        assertTrue(GateResultPresentation.familyLabel(result, "fallback") == "Neverificat")
        assertTrue(GateResultPresentation.legacyRiskLevel(result) == "info")
        assertTrue(GateResultPresentation.legacyRiskScore(result) == 0)
        assertTrue(GateResultPresentation.userHeadline(result) == "Neverificat")
        assertTrue(display.level == "Neverificat")
        assertTrue(display.label == "Neverificat")
        assertFalse(copy.contains("suspect"))
        assertFalse(copy.contains("periculos"))
        assertFalse(copy.contains("scanarea nu este completa"))
        assertFalse(copy.contains("scanarea nu este completă"))
    }

    @Test
    fun finalUnverifiedBackendCopyDoesNotSayTheScanIsStillIncomplete() {
        val result = gateResult(
            GateAction.UNVERIFIED,
            reasonCodes = listOf("BACKEND_UNVERIFIED"),
            unknownReason = "BACKEND_UNVERIFIED",
            finality = GateFinality.FINAL
        )
        val copy = listOf(
            result.userLabel,
            GateResultPresentation.supportText(result),
            GateResultPresentation.reasonText(result, null),
            GateResultPresentation.primaryAction(result)
        )
            .plus(GateResultPresentation.recommendedActions(result))
            .joinToString(" ")
            .lowercase()

        assertTrue(result.userLabel == "Neverificat")
        assertTrue(GateResultPresentation.familyLabel(result.action, "fallback") == "Neverificat")
        assertTrue(GateResultPresentation.legacyRiskLevel(result.action) == "info")
        assertTrue(copy.contains("nu am găsit") || copy.contains("nu am gasit"))
        assertTrue(copy.contains("confirm"))
        assertFalse(copy.contains("suspect"))
        assertFalse(copy.contains("incomplet"))
        assertFalse(copy.contains("incompletă"))
        assertFalse(copy.contains("inca"))
        assertFalse(copy.contains("încă"))
        assertFalse(copy.contains("asteapta scanarea"))
        assertFalse(copy.contains("așteaptă scanarea"))
    }

    @Test
    fun dangerousCopyTellsTheUserWhatToDoWithoutTechnicalRawDetails() {
        val result = gateResult(
            GateAction.DO_NOT_CONTINUE,
            reasonCodes = listOf("SANDBOX_VERDICT")
        )
        val copy = listOf(
            result.userLabel,
            GateResultPresentation.reasonText(result, null),
            GateResultPresentation.primaryAction(result)
        )
            .plus(GateResultPresentation.recommendedActions(result))
            .joinToString(" ")
            .lowercase()

        assertTrue(copy.contains("nu"))
        assertTrue(copy.contains("apasa") || copy.contains("continua"))
        assertFalse(copy.contains("json"))
        assertFalse(copy.contains("http 200"))
        assertFalse(copy.contains("asn"))
    }

    @Test
    fun backendVerdictCopyDoesNotInventUrlEvidenceForTextOnlyScans() {
        val result = gateResult(
            GateAction.DO_NOT_CONTINUE,
            reasonCodes = listOf("BACKEND_ORCHESTRATED_VERDICT")
        )
        val textOnlySnapshot = EvidenceSnapshot(
            scanId = "text-only",
            inputKind = "share_text",
            channel = "visible_text"
        )
        val urlSnapshot = textOnlySnapshot.copy(
            primaryUrl = "https://example.com"
        )

        val textOnlyReason = GateResultPresentation.reasonText(result, textOnlySnapshot).lowercase()
        val urlReason = GateResultPresentation.reasonText(result, urlSnapshot).lowercase()

        assertTrue(textOnlyReason.contains("mesaj"))
        assertFalse(textOnlyReason.contains("linkul final"))
        assertFalse(textOnlyReason.contains("captura"))
        assertTrue(urlReason.contains("linkul final"))
        assertTrue(urlReason.contains("captura"))
    }

    @Test
    fun pendingScanCopyHidesProviderAndPillarJargonFromUsers() {
        val result = gateResult(
            GateAction.INSUFFICIENT_EVIDENCE,
            reasonCodes = listOf("PROVIDER_REVIEW_REQUIRED"),
            unknownReason = "PROVIDERS_PENDING_FOR_TARGET",
            finality = GateFinality.PROVISIONAL,
            asyncExpected = true
        )
        val copy = listOf(
            GateResultPresentation.userHeadline(result),
            GateResultPresentation.supportText(result),
            GateResultPresentation.reasonText(result, null),
            GateResultPresentation.primaryAction(result)
        )
            .plus(GateResultPresentation.recommendedActions(result))
            .joinToString(" ")
            .lowercase()

        assertTrue(copy.contains("scan"))
        assertTrue(GateResultPresentation.userHeadline(result) == "Se verifică...")
        assertFalse(copy.contains("suspect"))
        listOf("web risk", "virustotal", "urlscan", "sandbox", "provider", "pilon", "tehnic").forEach { jargon ->
            assertFalse("User-facing copy leaked '$jargon': $copy", copy.contains(jargon))
        }
    }

    @Test
    fun previewOverlayCopyHidesPillarJargon() {
        val copy = publicServerInfo("Scanarea continua pana cand pilonii necesari returneaza date.").lowercase()
        assertTrue(copy.contains("verific"))
        assertFalse(copy.contains("pilon"))
        assertFalse(copy.contains("provider"))
    }

    @Test
    fun screenshotProxyUrlWaitsForLocalCachedFileBeforeImageRendering() {
        val proxyUrl = "https://api.sigurscan.com/v1/sandbox/urlscan/urlscan-123/screenshot"
        val missingLocalUrl = "file:///tmp/urlscan-123.png"
        val cachedFile = File.createTempFile("sigurscan-urlscan", ".png").apply {
            writeBytes(byteArrayOf(0x01, 0x02, 0x03))
            deleteOnExit()
        }
        val localUrl = cachedFile.toURI().toString()

        assertTrue(sandboxScreenshotModel(proxyUrl) == null)
        assertTrue(sandboxScreenshotModel(missingLocalUrl) == null)
        assertTrue(sandboxScreenshotModel(localUrl) == localUrl)
    }

    @Test
    fun provisionalBackendResultUsesNeutralPendingCopyInsteadOfRiskVerdict() {
        val result = backendScanInProgressGateResult()
        val copy = listOf(
            GateResultPresentation.familyLabel(result, "fallback"),
            GateResultPresentation.legacyRiskLevel(result),
            GateResultPresentation.userHeadline(result),
            GateResultPresentation.supportText(result),
            GateResultPresentation.reasonText(result, null),
            GateResultPresentation.primaryAction(result)
        )
            .plus(GateResultPresentation.recommendedActions(result))
            .joinToString(" ")
            .lowercase()

        assertTrue(GateResultPresentation.isScanInProgress(result))
        assertTrue(GateResultPresentation.familyLabel(result, "fallback") == "Se verifică")
        assertTrue(GateResultPresentation.legacyRiskLevel(result) == "info")
        assertTrue(GateResultPresentation.userHeadline(result) == "Se verifică...")
        assertTrue(copy.contains("mesaj"))
        assertFalse(copy.contains("suspect"))
        assertFalse(copy.contains("periculos"))
        assertFalse(copy.contains("preview"))
    }

    private fun gateResult(
        action: GateAction,
        reasonCodes: List<String> = listOf("UNIT_TEST_REASON"),
        unknownReason: String? = null,
        finality: GateFinality = GateFinality.FINAL,
        asyncExpected: Boolean = false
    ): GateResult {
        return GateResult(
            action = action,
            finality = finality,
            reasonCodes = reasonCodes,
            decisiveSignalIds = listOf("sig-test"),
            asyncExpected = asyncExpected,
            unknownReason = unknownReason
        )
    }
}
