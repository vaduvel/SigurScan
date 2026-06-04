package ro.sigurscan.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class LaunchAcceptanceRomaniaTest {
    private val gate = EvidenceGate { 1_000L }

    @Test
    fun uberRealPromoButtonWithOfficialFinalUrlCanContinueWithCaution() {
        val html = """
            <a href="https://rides.sng.link/Aw5zn/hw3r?_fallback_redirect=https%3A%2F%2Fwww.uber.com">
              Comanda o cursa
            </a>
        """.trimIndent()

        val snapshot = snapshot(
            rawText = "Uber: nu rata reducerea. Comanda o cursa.",
            htmlContent = html,
            primaryUrl = "https://rides.sng.link/Aw5zn/hw3r?_fallback_redirect=https%3A%2F%2Fwww.uber.com",
            finalUrl = "https://www.uber.com/ro/ride/",
            threatIntel = confirmedClaimThreatIntel("uber.com"),
            redirectChain = listOf(
                "https://rides.sng.link/Aw5zn/hw3r?_fallback_redirect=https%3A%2F%2Fwww.uber.com",
                "https://www.uber.com/ro/ride/"
            )
        )

        assertCodes(snapshot, EvidenceCode.HTML_BUTTON_LINK, EvidenceCode.OFFICIAL_DOMAIN_EXACT, EvidenceCode.NO_SENSITIVE_FORM)
        assertEquals(GateAction.CONTINUE_WITH_CAUTION, gate.evaluate(snapshot).action)
        assertNoHardVerdictFromMarketing(snapshot)
    }

    @Test
    fun uberFakeCardFlowIsDoNotContinue() {
        val snapshot = snapshot(
            rawText = "Uber: oferta ta expira azi. Confirma cardul pentru activare.",
            primaryUrl = "https://uber-promo-login.example.net/card/verify",
            finalUrl = "https://uber-promo-login.example.net/card/verify"
        )

        assertCodes(snapshot, EvidenceCode.BRAND_IMPERSONATION, EvidenceCode.OFFICIAL_DOMAIN_MISMATCH, EvidenceCode.CARD_REQUEST)
        assertEquals(GateAction.DO_NOT_CONTINUE, gate.evaluate(snapshot).action)
    }

    @Test
    fun fanCourierFakeTaxAndCardFlowIsDoNotContinue() {
        val snapshot = snapshot(
            rawText = "FAN Courier: colet blocat. Plateste taxa mica pentru livrare cu cardul.",
            primaryUrl = "https://fan-colet-plata.example.net/card",
            finalUrl = "https://fan-colet-plata.example.net/card"
        )

        assertCodes(snapshot, EvidenceCode.COURIER_UNOFFICIAL_DOMAIN, EvidenceCode.PARCEL_TAX, EvidenceCode.CARD_REQUEST)
        assertEquals(GateAction.DO_NOT_CONTINUE, gate.evaluate(snapshot).action)
    }

    @Test
    fun fanCourierOfficialTrackingDoesNotBecomeScamBecauseOfAwbWords() {
        val snapshot = snapshot(
            rawText = "FAN Courier: verifica AWB si statusul livrarii.",
            primaryUrl = "https://www.fancourier.ro/awb-tracking/",
            finalUrl = "https://www.fancourier.ro/awb-tracking/"
        )

        assertCodes(snapshot, EvidenceCode.OFFICIAL_DOMAIN_EXACT, EvidenceCode.NO_SENSITIVE_FORM)
        assertEquals(GateAction.CONTINUE_WITH_CAUTION, gate.evaluate(snapshot).action)
    }

    @Test
    fun anafFakeSpvPasswordAndCardFlowIsDoNotContinue() {
        val snapshot = snapshot(
            rawText = "ANAF SPV: plata restanta. Introdu parola si cardul pentru deblocare.",
            primaryUrl = "https://anaf-spv-plata.example.net/login/card",
            finalUrl = "https://anaf-spv-plata.example.net/login/card"
        )

        assertCodes(
            snapshot,
            EvidenceCode.TAX_NOTICE,
            EvidenceCode.BRAND_IMPERSONATION,
            EvidenceCode.OFFICIAL_DOMAIN_MISMATCH,
            EvidenceCode.PASSWORD_REQUEST,
            EvidenceCode.CARD_REQUEST
        )
        assertEquals(GateAction.DO_NOT_CONTINUE, gate.evaluate(snapshot).action)
    }

    @Test
    fun emagRealNewsletterWithMarketingLanguageCanContinueWithCaution() {
        val snapshot = snapshot(
            rawText = "eMAG: nu rata oferta de weekend si voucherul tau.",
            primaryUrl = "https://marketing.sng.link/click/emag",
            finalUrl = "https://www.emag.ro/oferta",
            threatIntel = confirmedClaimThreatIntel("emag.ro"),
            redirectChain = listOf("https://marketing.sng.link/click/emag", "https://www.emag.ro/oferta")
        )

        assertCodes(snapshot, EvidenceCode.PROMO_TEXT, EvidenceCode.MARKETING_URGENCY, EvidenceCode.OFFICIAL_DOMAIN_EXACT)
        assertEquals(GateAction.CONTINUE_WITH_CAUTION, gate.evaluate(snapshot).action)
        assertNoHardVerdictFromMarketing(snapshot)
    }

    @Test
    fun emagFakePrizeWithCardPaymentIsDoNotContinue() {
        val snapshot = snapshot(
            rawText = "eMAG: ai castigat un premiu. Plateste taxa de transport cu cardul.",
            primaryUrl = "https://emag-premiu-transport.example.net/card",
            finalUrl = "https://emag-premiu-transport.example.net/card"
        )

        assertCodes(snapshot, EvidenceCode.BRAND_IMPERSONATION, EvidenceCode.OFFICIAL_DOMAIN_MISMATCH, EvidenceCode.CARD_REQUEST)
        assertEquals(GateAction.DO_NOT_CONTINUE, gate.evaluate(snapshot).action)
    }

    @Test
    fun googleWebRiskMalwareProviderCanStopTheFlowAlone() {
        val snapshot = snapshot(
            rawText = "Verifica linkul primit.",
            primaryUrl = "https://malware.example.net",
            finalUrl = "https://malware.example.net",
            threatIntel = listOf(
                ThreatIntelSourceResult(
                    source = "Google Web Risk",
                    verdict = "Threats Detected",
                    severity = "high",
                    details = "MALWARE"
                )
            )
        )

        assertCodes(snapshot, EvidenceCode.WEBRISK_MATCH_MALWARE)
        assertEquals(GateAction.DO_NOT_CONTINUE, gate.evaluate(snapshot).action)
    }

    @Test
    fun neutralExampleUrlDoesNotBecomeSafeOrDangerousWithoutEvidence() {
        val snapshot = snapshot(
            rawText = "https://example.com",
            primaryUrl = "https://example.com",
            finalUrl = "https://example.com",
            autoCompleteProviders = false
        )

        val result = gate.evaluate(snapshot)
        assertEquals(GateAction.INSUFFICIENT_EVIDENCE, result.action)
        assertNotEquals(GateAction.CONTINUE_WITH_CAUTION, result.action)
        assertNotEquals(GateAction.DO_NOT_CONTINUE, result.action)
    }

    @Test
    fun webmailShellWithoutBodyIsInsufficientEvidence() {
        val snapshot = EvidenceSignalNormalizer.buildSnapshot(
            EvidenceNormalizerInput(
                inputKind = "share_text",
                channel = "webmail_shell",
                rawText = "<html><body><div id=\"mail-app-container\"></div></body></html>"
            )
        )

        assertCodes(snapshot, EvidenceCode.WEBMAIL_SHELL_ONLY)
        assertEquals(GateAction.INSUFFICIENT_EVIDENCE, gate.evaluate(snapshot).action)
    }

    @Test
    fun visibleOfficialLinkWithUnofficialHrefAndOtpIsDoNotContinue() {
        val html = """
            <a href="https://revolut-login-check.example.net/otp">https://www.revolut.com</a>
            <p>Introdu parola si codul OTP pentru reactivare.</p>
        """.trimIndent()

        val snapshot = snapshot(
            rawText = html,
            htmlContent = html,
            primaryUrl = "https://revolut-login-check.example.net/otp",
            finalUrl = "https://revolut-login-check.example.net/otp"
        )

        assertCodes(snapshot, EvidenceCode.HIDDEN_LINK_OFFICIAL_TO_UNOFFICIAL, EvidenceCode.PASSWORD_REQUEST, EvidenceCode.OTP_REQUEST)
        assertEquals(GateAction.DO_NOT_CONTINUE, gate.evaluate(snapshot).action)
    }

    @Test
    fun trackingRedirectToOfficialBrandDoesNotBecomeDangerousJustBecauseItIsTracking() {
        val snapshot = snapshot(
            rawText = "Uber promo: vezi oferta in aplicatie.",
            primaryUrl = "https://rides.sng.link/Aw5zn/hw3r",
            finalUrl = "https://www.uber.com/ro/ride/",
            threatIntel = confirmedClaimThreatIntel("uber.com"),
            redirectChain = listOf("https://rides.sng.link/Aw5zn/hw3r", "https://www.uber.com/ro/ride/")
        )

        assertCodes(snapshot, EvidenceCode.APPROVED_TRACKER_DOMAIN, EvidenceCode.OFFICIAL_DOMAIN_EXACT, EvidenceCode.NO_SENSITIVE_FORM)
        assertEquals(GateAction.CONTINUE_WITH_CAUTION, gate.evaluate(snapshot).action)
    }

    @Test
    fun urlscanUnavailableDoesNotCreateSafeOrDangerousVerdict() {
        val snapshot = snapshot(
            rawText = "https://example.com",
            primaryUrl = "https://example.com",
            providerStates = mapOf(
                ProviderId.WEB_RISK to ProviderState(ProviderId.WEB_RISK, ProviderStatus.ERROR),
                ProviderId.URLSCAN to ProviderState(ProviderId.URLSCAN, ProviderStatus.TIMEOUT),
                ProviderId.VIRUSTOTAL to ProviderState(ProviderId.VIRUSTOTAL, ProviderStatus.SKIPPED)
            )
        )

        val result = gate.evaluate(snapshot)
        assertEquals(GateAction.INSUFFICIENT_EVIDENCE, result.action)
        assertEquals("PROVIDERS_UNAVAILABLE", result.unknownReason)
    }

    @Test
    fun virusTotalFallbackMaliciousConsensusCanStopTheFlow() {
        val snapshot = snapshot(
            rawText = "Domeniu necunoscut cu plata card.",
            primaryUrl = "https://unknown-pay.example.net/card",
            finalUrl = "https://unknown-pay.example.net/card",
            threatIntel = listOf(
                ThreatIntelSourceResult(
                    source = "VirusTotal",
                    verdict = "Malicious",
                    severity = "high",
                    details = "Engines: total=70, malicious=4, suspicious=2"
                )
            ),
            virusTotalConfigured = true
        )

        assertCodes(snapshot, EvidenceCode.VIRUSTOTAL_MALICIOUS_CONSENSUS)
        assertEquals(GateAction.DO_NOT_CONTINUE, gate.evaluate(snapshot).action)
    }

    @Test
    fun marketingUrgencyOnlyIsCappedAtVerifyOfficial() {
        val snapshot = snapshot(
            rawText = "Nu rata oferta, ultima sansa, voucher gratuit doar azi!"
        )

        val result = gate.evaluate(snapshot)
        assertEquals(GateAction.INSUFFICIENT_EVIDENCE, result.action)
        assertFalse(result.decisiveSignalIds.any { id ->
            snapshot.signals.firstOrNull { it.id == id }?.maxSoloAction == GateAction.DO_NOT_CONTINUE
        })
    }

    private fun snapshot(
        rawText: String,
        htmlContent: String? = null,
        primaryUrl: String? = null,
        finalUrl: String? = null,
        redirectChain: List<String> = emptyList(),
        threatIntel: List<ThreatIntelSourceResult> = emptyList(),
        providerStates: Map<ProviderId, ProviderState> = emptyMap(),
        virusTotalConfigured: Boolean = false,
        autoCompleteProviders: Boolean = true
    ): EvidenceSnapshot {
        val effectiveProviderStates = if (
            autoCompleteProviders &&
            providerStates.isEmpty() &&
            (!primaryUrl.isNullOrBlank() || !finalUrl.isNullOrBlank())
        ) completedUrlProviderStates() else providerStates
        return EvidenceSignalNormalizer.buildSnapshot(
            EvidenceNormalizerInput(
                inputKind = "acceptance_test",
                channel = if (htmlContent != null) "email_html" else "text",
                rawText = rawText,
                htmlContent = htmlContent,
                primaryUrl = primaryUrl,
                finalUrl = finalUrl,
                redirectChain = redirectChain,
                threatIntel = threatIntel,
                providerStates = effectiveProviderStates,
                completeness = if (effectiveProviderStates.isNotEmpty()) EvidenceCompleteness.PARTIAL_ONLINE else null,
                virusTotalConfigured = virusTotalConfigured
            )
        )
    }

    private fun completedUrlProviderStates(): Map<ProviderId, ProviderState> = mapOf(
        ProviderId.WEB_RISK to ProviderState(ProviderId.WEB_RISK, ProviderStatus.OK),
        ProviderId.URLSCAN to ProviderState(ProviderId.URLSCAN, ProviderStatus.OK),
        ProviderId.VIRUSTOTAL to ProviderState(ProviderId.VIRUSTOTAL, ProviderStatus.OK),
        ProviderId.CLAIM_VERIFIER to ProviderState(ProviderId.CLAIM_VERIFIER, ProviderStatus.OK)
    )

    private fun confirmedClaimThreatIntel(officialDomain: String): List<ThreatIntelSourceResult> = listOf(
        ThreatIntelSourceResult(
            source = "ai_offer_web_check",
            verdict = "confirmed",
            severity = "low",
            details = "official_source_found=true; official_domains=$officialDomain; campaign confirmed on official destination."
        )
    )

    private fun assertCodes(snapshot: EvidenceSnapshot, vararg expected: EvidenceCode) {
        val actual = snapshot.signals.map { it.code }.toSet()
        expected.forEach { code ->
            assertTrue("Missing $code in $actual", actual.contains(code))
        }
    }

    private fun assertNoHardVerdictFromMarketing(snapshot: EvidenceSnapshot) {
        val result = gate.evaluate(snapshot)
        val decisiveCodes = result.decisiveSignalIds.mapNotNull { id ->
            snapshot.signals.firstOrNull { it.id == id }?.code
        }.toSet()
        assertFalse(decisiveCodes.contains(EvidenceCode.MARKETING_URGENCY))
        assertFalse(decisiveCodes.contains(EvidenceCode.PROMO_TEXT))
        assertFalse(decisiveCodes.contains(EvidenceCode.VOUCHER_TEXT))
    }
}
