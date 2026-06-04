package ro.sigurscan.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class EvidenceGateTest {
    private val gate = EvidenceGate { 1_000L }

    @Test
    fun uberRealPromoVerifiedByEvidenceIsShownAsSafe() {
        val result = evaluate(
            EvidenceCode.OFFICIAL_DOMAIN_EXACT,
            EvidenceCode.NO_SENSITIVE_FORM,
            EvidenceCode.PROMO_TEXT,
            EvidenceCode.OFFER_CLAIM_CONFIRMED,
            finalUrl = "https://www.uber.com/ro/ride/"
        )

        assertAction(GateAction.CONTINUE_WITH_CAUTION, result)
        assertEquals("Sigur", result.userLabel)
    }

    @Test
    fun emagNewsletterWithApprovedTrackerCanContinueWithCaution() {
        val result = evaluate(
            EvidenceCode.APPROVED_TRACKER_DOMAIN,
            EvidenceCode.REDIRECT_CHAIN_APPROVED,
            EvidenceCode.NO_SENSITIVE_FORM,
            EvidenceCode.PROMO_TEXT,
            EvidenceCode.OFFER_CLAIM_CONFIRMED,
            primaryUrl = "https://tracking.example.com/click",
            finalUrl = "https://www.emag.ro/oferta"
        )

        assertAction(GateAction.CONTINUE_WITH_CAUTION, result)
    }

    @Test
    fun fanRealTrackingCanContinueWithCaution() {
        val result = evaluate(
            EvidenceCode.OFFICIAL_DOMAIN_EXACT,
            EvidenceCode.TRACKING_ONLY_NO_PAYMENT,
            EvidenceCode.NO_SENSITIVE_FORM,
            finalUrl = "https://www.fancourier.ro/awb-tracking/"
        )

        assertAction(GateAction.CONTINUE_WITH_CAUTION, result)
    }

    @Test
    fun marketingTextOnlyWithoutTargetIsInsufficient() {
        val result = evaluate(
            EvidenceCode.PROMO_TEXT,
            EvidenceCode.VOUCHER_TEXT,
            EvidenceCode.MARKETING_URGENCY
        )

        assertAction(GateAction.INSUFFICIENT_EVIDENCE, result)
        assertNotEquals(GateAction.DO_NOT_CONTINUE, result.action)
    }

    @Test
    fun marketingTextWithTargetIsCappedAtVerifyOfficial() {
        val result = evaluate(
            EvidenceCode.PROMO_TEXT,
            EvidenceCode.VOUCHER_TEXT,
            EvidenceCode.MARKETING_URGENCY,
            finalUrl = "https://promo.example.com/oferta"
        )

        assertAction(GateAction.VERIFY_OFFICIAL, result)
        assertNotEquals(GateAction.DO_NOT_CONTINUE, result.action)
    }

    @Test
    fun htmlButtonOnlyIsCappedAtVerifyOfficial() {
        val result = evaluate(
            EvidenceCode.HTML_BUTTON_LINK,
            EvidenceCode.HIDDEN_LINK_PRESENT,
            finalUrl = "https://newsletter.example.com/promo"
        )

        assertAction(GateAction.VERIFY_OFFICIAL, result)
    }

    @Test
    fun trackingLinkOnlyIsCappedAtVerifyOfficial() {
        val result = evaluate(
            EvidenceCode.TRACKING_LINK,
            finalUrl = "https://tracker.example.com/click"
        )

        assertAction(GateAction.VERIFY_OFFICIAL, result)
    }

    @Test
    fun ragOnlyCannotCreateHardVerdict() {
        val result = evaluate(EvidenceCode.RAG_EXPLANATION)

        assertAction(GateAction.INSUFFICIENT_EVIDENCE, result)
        assertTrue(result.decisiveSignalIds.isEmpty())
    }

    @Test
    fun corpusSimilarityOnlyIsNotDangerous() {
        val result = evaluate(EvidenceCode.CORPUS_SIMILARITY)

        assertAction(GateAction.INSUFFICIENT_EVIDENCE, result)
        assertNotEquals(GateAction.DO_NOT_CONTINUE, result.action)
    }

    @Test
    fun fanFakeCardFormIsDoNotContinue() {
        val result = evaluate(
            EvidenceCode.COURIER_UNOFFICIAL_DOMAIN,
            EvidenceCode.PARCEL_TAX,
            EvidenceCode.SENSITIVE_FORM_UNOFFICIAL,
            EvidenceCode.CARD_REQUEST,
            EvidenceCode.CVV_REQUEST,
            EvidenceCode.BRAND_IMPERSONATION,
            finalUrl = "https://fan-colet-plata.example.net/card"
        )

        assertAction(GateAction.DO_NOT_CONTINUE, result)
        assertEquals("SENSITIVE_FORM_ON_UNOFFICIAL_BRAND_DOMAIN", result.reasonCodes.single())
    }

    @Test
    fun anafFakeCardFormIsDoNotContinue() {
        val result = evaluate(
            EvidenceCode.TAX_NOTICE,
            EvidenceCode.SENSITIVE_FORM_UNOFFICIAL,
            EvidenceCode.CARD_REQUEST,
            EvidenceCode.BRAND_IMPERSONATION,
            finalUrl = "https://anaf-plata.example.net/spv/card"
        )

        assertAction(GateAction.DO_NOT_CONTINUE, result)
    }

    @Test
    fun revolutFakeOtpOnMismatchedDomainIsNoEnterData() {
        val result = evaluate(
            EvidenceCode.BRAND_IMPERSONATION,
            EvidenceCode.OFFICIAL_DOMAIN_MISMATCH,
            EvidenceCode.OTP_REQUEST,
            finalUrl = "https://revolut-login.example.net/verify"
        )

        assertAction(GateAction.NO_ENTER_DATA, result)
    }

    @Test
    fun textOnlyOtpReplyIsNoReply() {
        val result = evaluate(
            EvidenceCode.REPLY_WITH_CODE_REQUEST,
            EvidenceCode.OTP_REQUEST,
            providerStates = completedClaimProviderState()
        )

        assertAction(GateAction.NO_REPLY, result)
        assertEquals("Periculos", result.userLabel)
    }

    @Test
    fun brokenPhoneMoneyScenarioIsNoReply() {
        val result = evaluate(
            EvidenceCode.FAMILY_NEW_PHONE_MONEY,
            providerStates = completedClaimProviderState()
        )

        assertAction(GateAction.NO_REPLY, result)
    }

    @Test
    fun accidentNephewMoneyScenarioIsNoReply() {
        val result = evaluate(
            EvidenceCode.ACCIDENT_NEPHEW_MONEY,
            providerStates = completedClaimProviderState()
        )

        assertAction(GateAction.NO_REPLY, result)
    }

    @Test
    fun whatsappCodeScenarioIsNoReply() {
        val result = evaluate(
            EvidenceCode.WHATSAPP_CODE_REQUEST,
            providerStates = completedClaimProviderState()
        )

        assertAction(GateAction.NO_REPLY, result)
    }

    @Test
    fun whatsappDeviceLinkingScenarioIsNoReply() {
        val result = evaluate(
            EvidenceCode.WHATSAPP_DEVICE_LINKING_REQUEST,
            providerStates = completedClaimProviderState()
        )

        assertAction(GateAction.NO_REPLY, result)
    }

    @Test
    fun bnrSafeAccountScenarioIsNoReply() {
        val result = evaluate(
            EvidenceCode.BNR_SAFE_ACCOUNT,
            providerStates = completedClaimProviderState()
        )

        assertAction(GateAction.NO_REPLY, result)
    }

    @Test
    fun marketplaceReceiveMoneyCardRequestIsNoEnterData() {
        val result = evaluate(
            EvidenceCode.MARKETPLACE_RECEIVE_MONEY,
            EvidenceCode.CARD_REQUEST,
            providerStates = completedClaimProviderState()
        )

        assertAction(GateAction.NO_ENTER_DATA, result)
    }

    @Test
    fun webRiskNoMatchDoesNotCancelUnofficialSensitiveForm() {
        val result = evaluate(
            EvidenceCode.WEBRISK_NO_MATCH,
            EvidenceCode.SENSITIVE_FORM_UNOFFICIAL,
            finalUrl = "https://unknown-checkout.example.net/card"
        )

        assertAction(GateAction.NO_ENTER_DATA, result)
    }

    @Test
    fun urlscanPhishingIsDoNotContinue() {
        val result = evaluate(
            EvidenceCode.URLSCAN_VERDICT_PHISHING,
            finalUrl = "https://phish.example.net/login"
        )

        assertAction(GateAction.DO_NOT_CONTINUE, result)
        assertEquals("SANDBOX_VERDICT", result.reasonCodes.single())
    }

    @Test
    fun webRiskMalwareIsDoNotContinue() {
        val result = evaluate(
            EvidenceCode.WEBRISK_MATCH_MALWARE,
            finalUrl = "https://malware.example.net/"
        )

        assertAction(GateAction.DO_NOT_CONTINUE, result)
        assertEquals("HIGH_CONFIDENCE_REPUTATION", result.reasonCodes.single())
    }

    @Test
    fun vtConsensusIsDoNotContinue() {
        val result = evaluate(
            EvidenceCode.VIRUSTOTAL_MALICIOUS_CONSENSUS,
            finalUrl = "https://malicious.example.net/"
        )

        assertAction(GateAction.DO_NOT_CONTINUE, result)
    }

    @Test
    fun providerDownNeutralIsInsufficientEvidence() {
        val providerStates = mapOf(
            ProviderId.WEB_RISK to ProviderState(ProviderId.WEB_RISK, ProviderStatus.ERROR),
            ProviderId.URLSCAN to ProviderState(ProviderId.URLSCAN, ProviderStatus.TIMEOUT)
        )

        val result = evaluate(
            EvidenceCode.PROVIDERS_UNAVAILABLE,
            providerStates = providerStates
        )

        assertAction(GateAction.INSUFFICIENT_EVIDENCE, result)
        assertEquals("PROVIDERS_UNAVAILABLE", result.unknownReason)
    }

    @Test
    fun webmailShellOnlyIsInsufficientEvidence() {
        val result = evaluate(EvidenceCode.WEBMAIL_SHELL_ONLY)

        assertAction(GateAction.INSUFFICIENT_EVIDENCE, result)
        assertEquals("WEBMAIL_SHELL_ONLY", result.unknownReason)
    }

    @Test
    fun lowConfidenceOcrIsInsufficientEvidence() {
        val result = evaluate(EvidenceCode.OCR_LOW_CONFIDENCE)

        assertAction(GateAction.INSUFFICIENT_EVIDENCE, result)
        assertEquals("OCR_LOW_CONFIDENCE", result.unknownReason)
    }

    @Test
    fun unresolvedShortlinkWaitsForFinalUrlResolution() {
        val result = evaluate(
            EvidenceCode.UNRESOLVED_SHORTLINK,
            primaryUrl = "https://short.example/abc"
        )

        assertAction(GateAction.INSUFFICIENT_EVIDENCE, result)
        assertEquals(GateFinality.PROVISIONAL, result.finality)
        assertTrue(result.asyncExpected)
        assertEquals("FINAL_URL_NOT_RESOLVED", result.unknownReason)
    }

    @Test
    fun officialDomainDoesNotOverrideHardMaliciousProviderSignal() {
        val result = evaluate(
            EvidenceCode.OFFICIAL_DOMAIN_EXACT,
            EvidenceCode.NO_SENSITIVE_FORM,
            EvidenceCode.URLSCAN_VERDICT_PHISHING,
            primaryUrl = "https://brand.example.com/start",
            finalUrl = "https://brand.example.com/start"
        )

        assertAction(GateAction.DO_NOT_CONTINUE, result)
    }

    @Test
    fun officialDomainWithLocalOnlyCompletenessDoesNotBecomeContinueWithCaution() {
        val result = evaluate(
            EvidenceCode.OFFICIAL_DOMAIN_EXACT,
            EvidenceCode.NO_SENSITIVE_FORM,
            finalUrl = "https://www.emag.ro/oferta",
            completeness = EvidenceCompleteness.LOCAL_ONLY
        )

        assertAction(GateAction.INSUFFICIENT_EVIDENCE, result)
    }

    @Test
    fun officialDomainWithPendingProviderIsProvisionalCaution() {
        val result = evaluate(
            EvidenceCode.OFFICIAL_DOMAIN_EXACT,
            EvidenceCode.NO_SENSITIVE_FORM,
            finalUrl = "https://www.emag.ro/oferta",
            providerStates = mapOf(
                ProviderId.URLSCAN to ProviderState(ProviderId.URLSCAN, ProviderStatus.PENDING)
            )
        )

        assertAction(GateAction.INSUFFICIENT_EVIDENCE, result)
        assertEquals(GateFinality.PROVISIONAL, result.finality)
        assertTrue(result.asyncExpected)
        assertEquals("PROVIDERS_PENDING_FOR_TARGET", result.unknownReason)
    }

    @Test
    fun targetWithPendingProvidersCannotReceiveFinalLocalVerdict() {
        val result = evaluate(
            EvidenceCode.MONEY_REQUEST,
            EvidenceCode.MARKETING_URGENCY,
            primaryUrl = "https://buyback.yoxo.ro",
            providerStates = mapOf(
                ProviderId.WEB_RISK to ProviderState(ProviderId.WEB_RISK, ProviderStatus.PENDING),
                ProviderId.URLSCAN to ProviderState(ProviderId.URLSCAN, ProviderStatus.PENDING)
            ),
            completeness = EvidenceCompleteness.PARTIAL_ONLINE
        )

        assertAction(GateAction.INSUFFICIENT_EVIDENCE, result)
        assertEquals(GateFinality.PROVISIONAL, result.finality)
        assertTrue(result.asyncExpected)
        assertEquals("PROVIDERS_PENDING_FOR_TARGET", result.unknownReason)
    }

    @Test
    fun officialYoxoWithCompletedCleanProvidersButInconclusiveClaimNeedsVerification() {
        val result = evaluate(
            EvidenceCode.OFFICIAL_DOMAIN_EXACT,
            EvidenceCode.NO_SENSITIVE_FORM,
            EvidenceCode.WEBRISK_NO_MATCH,
            EvidenceCode.URLSCAN_NO_CLASSIFICATION,
            EvidenceCode.VIRUSTOTAL_LOW_OR_NO_DETECTION,
            EvidenceCode.OFFER_CLAIM_INCONCLUSIVE,
            primaryUrl = "https://buyback.yoxo.ro",
            finalUrl = "https://buyback.yoxo.ro/?r=1#/yoxo-ro/ro"
        )

        assertAction(GateAction.VERIFY_OFFICIAL, result)
        assertEquals("Suspect", result.userLabel)
        assertEquals("CLAIM_NOT_CONFIRMED_ON_OFFICIAL_SOURCES", result.reasonCodes.single())
    }

    @Test
    fun officialPromoWithConfirmedClaimCanBeSafe() {
        val result = evaluate(
            EvidenceCode.OFFICIAL_DOMAIN_EXACT,
            EvidenceCode.NO_SENSITIVE_FORM,
            EvidenceCode.PROMO_TEXT,
            EvidenceCode.WEBRISK_NO_MATCH,
            EvidenceCode.URLSCAN_NO_CLASSIFICATION,
            EvidenceCode.OFFER_CLAIM_CONFIRMED,
            primaryUrl = "https://buyback.yoxo.ro",
            finalUrl = "https://buyback.yoxo.ro/?r=1#/yoxo-ro/ro"
        )

        assertAction(GateAction.CONTINUE_WITH_CAUTION, result)
        assertEquals("OFFICIAL_DESTINATION_AND_CLAIM_CONFIRMED", result.reasonCodes.single())
    }

    @Test
    fun officialDomainCanBeSafeWithoutVirusTotalWhenRequiredPillarsAreClean() {
        val result = evaluate(
            EvidenceCode.OFFICIAL_DOMAIN_EXACT,
            EvidenceCode.NO_SENSITIVE_FORM,
            EvidenceCode.WEBRISK_NO_MATCH,
            EvidenceCode.URLSCAN_NO_CLASSIFICATION,
            primaryUrl = "https://www.emag.ro/order/tracking",
            finalUrl = "https://www.emag.ro/order/tracking",
            providerStates = mapOf(
                ProviderId.WEB_RISK to ProviderState(ProviderId.WEB_RISK, ProviderStatus.OK),
                ProviderId.URLSCAN to ProviderState(ProviderId.URLSCAN, ProviderStatus.OK),
                ProviderId.VIRUSTOTAL to ProviderState(ProviderId.VIRUSTOTAL, ProviderStatus.SKIPPED)
            )
        )

        assertAction(GateAction.CONTINUE_WITH_CAUTION, result)
    }

    @Test
    fun skippedOptionalPillarsDoNotBlockOfficialCleanUrlWhenNoClaimIsRequired() {
        val result = evaluate(
            EvidenceCode.OFFICIAL_DOMAIN_EXACT,
            EvidenceCode.NO_SENSITIVE_FORM,
            EvidenceCode.WEBRISK_NO_MATCH,
            EvidenceCode.URLSCAN_NO_CLASSIFICATION,
            primaryUrl = "https://www.emag.ro/order/tracking",
            finalUrl = "https://www.emag.ro/order/tracking",
            providerStates = mapOf(
                ProviderId.WEB_RISK to ProviderState(ProviderId.WEB_RISK, ProviderStatus.OK),
                ProviderId.URLSCAN to ProviderState(ProviderId.URLSCAN, ProviderStatus.OK),
                ProviderId.VIRUSTOTAL to ProviderState(ProviderId.VIRUSTOTAL, ProviderStatus.SKIPPED, note = "not_required"),
                ProviderId.CLAIM_VERIFIER to ProviderState(ProviderId.CLAIM_VERIFIER, ProviderStatus.SKIPPED, note = "not_required")
            )
        )

        assertAction(GateAction.CONTINUE_WITH_CAUTION, result)
        assertEquals(GateFinality.FINAL, result.finality)
    }

    @Test
    fun localSensitiveSignalsWithUrlWaitForRequiredProviderPillars() {
        val result = evaluate(
            EvidenceCode.CARD_REQUEST,
            EvidenceCode.PAYMENT_REQUEST,
            EvidenceCode.MARKETING_URGENCY,
            primaryUrl = "https://promo.example.test/plata",
            providerStates = mapOf(
                ProviderId.WEB_RISK to ProviderState(ProviderId.WEB_RISK, ProviderStatus.PENDING),
                ProviderId.URLSCAN to ProviderState(ProviderId.URLSCAN, ProviderStatus.PENDING),
                ProviderId.CLAIM_VERIFIER to ProviderState(ProviderId.CLAIM_VERIFIER, ProviderStatus.PENDING)
            ),
            completeness = EvidenceCompleteness.PARTIAL_ONLINE
        )

        assertAction(GateAction.INSUFFICIENT_EVIDENCE, result)
        assertEquals(GateFinality.PROVISIONAL, result.finality)
        assertTrue(result.asyncExpected)
        assertEquals("PROVIDERS_PENDING_FOR_TARGET", result.unknownReason)
    }

    @Test
    fun homoglyphSensitiveRequestIsDoNotContinue() {
        val result = evaluate(
            EvidenceCode.HOMOGLYPH_DOMAIN,
            EvidenceCode.PUNYCODE_HOST,
            EvidenceCode.CARD_REQUEST,
            finalUrl = "https://xn--brand-login.example/card"
        )

        assertAction(GateAction.DO_NOT_CONTINUE, result)
        assertEquals("LOOKALIKE_DOMAIN_SENSITIVE_REQUEST", result.reasonCodes.single())
    }

    @Test
    fun officialPromoCannotBeSafeUntilClaimVerifierCompletes() {
        val result = evaluate(
            EvidenceCode.OFFICIAL_DOMAIN_EXACT,
            EvidenceCode.NO_SENSITIVE_FORM,
            EvidenceCode.PROMO_TEXT,
            EvidenceCode.WEBRISK_NO_MATCH,
            EvidenceCode.URLSCAN_NO_CLASSIFICATION,
            EvidenceCode.VIRUSTOTAL_LOW_OR_NO_DETECTION,
            primaryUrl = "https://smyk.ro/catalogul-ziua-copilului",
            finalUrl = "https://smyk.ro/catalogul-ziua-copilului",
            providerStates = mapOf(
                ProviderId.WEB_RISK to ProviderState(ProviderId.WEB_RISK, ProviderStatus.OK),
                ProviderId.URLSCAN to ProviderState(ProviderId.URLSCAN, ProviderStatus.OK),
                ProviderId.VIRUSTOTAL to ProviderState(ProviderId.VIRUSTOTAL, ProviderStatus.OK),
                ProviderId.CLAIM_VERIFIER to ProviderState(ProviderId.CLAIM_VERIFIER, ProviderStatus.PENDING)
            )
        )

        assertAction(GateAction.INSUFFICIENT_EVIDENCE, result)
        assertEquals(GateFinality.PROVISIONAL, result.finality)
        assertTrue(result.asyncExpected)
        assertEquals("PROVIDERS_PENDING_FOR_TARGET", result.unknownReason)
    }

    @Test
    fun officialDomainCannotBeSafeUntilUrlscanCompletes() {
        val result = evaluate(
            EvidenceCode.OFFICIAL_DOMAIN_EXACT,
            EvidenceCode.NO_SENSITIVE_FORM,
            EvidenceCode.WEBRISK_NO_MATCH,
            EvidenceCode.VIRUSTOTAL_LOW_OR_NO_DETECTION,
            primaryUrl = "https://smyk.ro/catalogul-ziua-copilului",
            finalUrl = "https://smyk.ro/catalogul-ziua-copilului",
            providerStates = mapOf(
                ProviderId.WEB_RISK to ProviderState(ProviderId.WEB_RISK, ProviderStatus.OK),
                ProviderId.URLSCAN to ProviderState(ProviderId.URLSCAN, ProviderStatus.PENDING),
                ProviderId.VIRUSTOTAL to ProviderState(ProviderId.VIRUSTOTAL, ProviderStatus.OK)
            )
        )

        assertAction(GateAction.INSUFFICIENT_EVIDENCE, result)
        assertEquals(GateFinality.PROVISIONAL, result.finality)
        assertTrue(result.asyncExpected)
        assertEquals("PROVIDERS_PENDING_FOR_TARGET", result.unknownReason)
    }

    @Test
    fun officialDomainCannotBeSafeUntilFinalUrlIsResolved() {
        val result = evaluate(
            EvidenceCode.OFFICIAL_DOMAIN_EXACT,
            EvidenceCode.NO_SENSITIVE_FORM,
            EvidenceCode.WEBRISK_NO_MATCH,
            EvidenceCode.URLSCAN_NO_CLASSIFICATION,
            EvidenceCode.VIRUSTOTAL_LOW_OR_NO_DETECTION,
            primaryUrl = "https://smyk.ro/catalogul-ziua-copilului"
        )

        assertAction(GateAction.INSUFFICIENT_EVIDENCE, result)
        assertEquals(GateFinality.PROVISIONAL, result.finality)
        assertTrue(result.asyncExpected)
        assertEquals("FINAL_URL_NOT_RESOLVED", result.unknownReason)
    }

    @Test
    fun expiredDangerousSignalIsIgnored() {
        val expired = signal(
            EvidenceCode.WEBRISK_MATCH_SOCIAL_ENGINEERING,
            id = "expired-webrisk",
            expiresAtMillis = 999L
        )
        val result = gate.evaluate(
            snapshot(
                signals = listOf(expired),
                finalUrl = "https://phish.example.net/"
            )
        )

        assertAction(GateAction.INSUFFICIENT_EVIDENCE, result)
    }

    @Test
    fun pendingProviderMakesWeakVerdictProvisional() {
        val result = evaluate(
            EvidenceCode.PROMO_TEXT,
            providerStates = mapOf(
                ProviderId.CLAIM_VERIFIER to ProviderState(ProviderId.CLAIM_VERIFIER, ProviderStatus.PENDING)
            )
        )

        assertAction(GateAction.INSUFFICIENT_EVIDENCE, result)
        assertEquals(GateFinality.PROVISIONAL, result.finality)
        assertTrue(result.asyncExpected)
    }

    private fun assertAction(expected: GateAction, result: GateResult) {
        assertEquals(expected, result.action)
    }

    private fun evaluate(
        vararg codes: EvidenceCode,
        primaryUrl: String? = null,
        finalUrl: String? = null,
        providerStates: Map<ProviderId, ProviderState> = emptyMap(),
        completeness: EvidenceCompleteness = EvidenceCompleteness.FULL
    ): GateResult {
        val effectiveProviderStates = if (
            providerStates.isEmpty() &&
            completeness == EvidenceCompleteness.FULL &&
            (!primaryUrl.isNullOrBlank() || !finalUrl.isNullOrBlank())
        ) completedUrlProviderStates() else providerStates
        return gate.evaluate(
            snapshot(
                signals = codes.map { signal(it) },
                primaryUrl = primaryUrl,
                finalUrl = finalUrl,
                providerStates = effectiveProviderStates,
                completeness = completeness
            )
        )
    }

    private fun completedUrlProviderStates(): Map<ProviderId, ProviderState> = mapOf(
        ProviderId.WEB_RISK to ProviderState(ProviderId.WEB_RISK, ProviderStatus.OK),
        ProviderId.URLSCAN to ProviderState(ProviderId.URLSCAN, ProviderStatus.OK),
        ProviderId.VIRUSTOTAL to ProviderState(ProviderId.VIRUSTOTAL, ProviderStatus.OK),
        ProviderId.CLAIM_VERIFIER to ProviderState(ProviderId.CLAIM_VERIFIER, ProviderStatus.OK)
    )

    private fun completedClaimProviderState(): Map<ProviderId, ProviderState> = mapOf(
        ProviderId.CLAIM_VERIFIER to ProviderState(ProviderId.CLAIM_VERIFIER, ProviderStatus.OK)
    )

    private fun snapshot(
        signals: List<EvidenceSignal>,
        primaryUrl: String? = null,
        finalUrl: String? = null,
        providerStates: Map<ProviderId, ProviderState> = emptyMap(),
        completeness: EvidenceCompleteness = EvidenceCompleteness.FULL
    ) = EvidenceSnapshot(
        scanId = "test-scan",
        inputKind = "unit_test",
        channel = "text",
        primaryUrl = primaryUrl,
        finalUrl = finalUrl,
        signals = signals,
        providerStates = providerStates,
        registryVersion = "test-registry",
        corpusVersion = "test-corpus",
        completeness = completeness
    )

    private fun signal(
        code: EvidenceCode,
        id: String = code.name,
        expiresAtMillis: Long? = null
    ) = EvidenceSignal(
        id = id,
        source = sourceFor(code),
        code = code,
        targetKey = "target:${code.name}",
        brandId = "brand",
        observedAtMillis = 1L,
        expiresAtMillis = expiresAtMillis,
        provider = providerFor(code)
    )

    private fun sourceFor(code: EvidenceCode): EvidenceSource = when (code) {
        EvidenceCode.WEBRISK_MATCH_MALWARE,
        EvidenceCode.WEBRISK_MATCH_SOCIAL_ENGINEERING,
        EvidenceCode.WEBRISK_MATCH_UNWANTED_SOFTWARE,
        EvidenceCode.WEBRISK_MATCH_SOCIAL_ENGINEERING_EXT,
        EvidenceCode.WEBRISK_NO_MATCH -> EvidenceSource.GOOGLE_WEB_RISK

        EvidenceCode.URLSCAN_VERDICT_PHISHING,
        EvidenceCode.URLSCAN_VERDICT_MALWARE,
        EvidenceCode.URLSCAN_NO_CLASSIFICATION -> EvidenceSource.URLSCAN

        EvidenceCode.VIRUSTOTAL_MALICIOUS_CONSENSUS,
        EvidenceCode.VIRUSTOTAL_LOW_OR_NO_DETECTION -> EvidenceSource.VIRUSTOTAL

        EvidenceCode.OFFER_CLAIM_CONFIRMED,
        EvidenceCode.OFFER_CLAIM_NOT_FOUND,
        EvidenceCode.OFFER_CLAIM_INCONCLUSIVE -> EvidenceSource.CLAIM_VERIFIER

        EvidenceCode.DOMAIN_AGE_SUSPICIOUS,
        EvidenceCode.DOMAIN_AGE_VERY_RECENT,
        EvidenceCode.TYPOSQUAT_LOOKALIKE,
        EvidenceCode.HOMOGLYPH_DOMAIN,
        EvidenceCode.PUNYCODE_HOST,
        EvidenceCode.DGA_ENTROPY_HIGH,
        EvidenceCode.URL_BEHAVIOUR_SUSPICIOUS,
        EvidenceCode.URL_TRANSPORT_RISK -> EvidenceSource.INFRA_ANALYZER

        EvidenceCode.OFFICIAL_DOMAIN_EXACT,
        EvidenceCode.DELEGATED_DOMAIN_EXACT,
        EvidenceCode.APPROVED_TRACKER_DOMAIN,
        EvidenceCode.REDIRECT_CHAIN_APPROVED -> EvidenceSource.OFFICIAL_REGISTRY

        EvidenceCode.FAMILY_NEW_PHONE_MONEY,
        EvidenceCode.FAMILY_EMERGENCY_MONEY,
        EvidenceCode.ACCIDENT_NEPHEW_MONEY,
        EvidenceCode.WHATSAPP_CODE_REQUEST,
        EvidenceCode.WHATSAPP_DEVICE_LINKING_REQUEST,
        EvidenceCode.BNR_SAFE_ACCOUNT,
        EvidenceCode.FRAUDULENT_CREDIT_AUTHORITY_CHAIN,
        EvidenceCode.MARKETPLACE_RECEIVE_MONEY,
        EvidenceCode.CORPUS_SIMILARITY,
        EvidenceCode.CORPUS_BRAND_WARNING -> EvidenceSource.ROMANIA_SCENARIO

        EvidenceCode.HIDDEN_LINK_OFFICIAL_TO_UNOFFICIAL,
        EvidenceCode.HIDDEN_LINK_PRESENT,
        EvidenceCode.HTML_BUTTON_LINK,
        EvidenceCode.TRACKING_LINK -> EvidenceSource.HTML_EXTRACTOR

        EvidenceCode.RAG_EXPLANATION -> EvidenceSource.RAG
        EvidenceCode.USER_REPORT_UNVERIFIED -> EvidenceSource.USER_FEEDBACK
        else -> EvidenceSource.LOCAL_EXTRACTOR
    }

    private fun providerFor(code: EvidenceCode): ProviderId? = when (sourceFor(code)) {
        EvidenceSource.GOOGLE_WEB_RISK -> ProviderId.WEB_RISK
        EvidenceSource.URLSCAN -> ProviderId.URLSCAN
        EvidenceSource.VIRUSTOTAL -> ProviderId.VIRUSTOTAL
        EvidenceSource.INFRA_ANALYZER -> ProviderId.INFRA
        EvidenceSource.CLAIM_VERIFIER -> ProviderId.CLAIM_VERIFIER
        EvidenceSource.OFFICIAL_REGISTRY -> ProviderId.OFFICIAL_REGISTRY
        EvidenceSource.ROMANIA_SCENARIO -> ProviderId.CORPUS
        EvidenceSource.RAG -> ProviderId.RAG
        else -> null
    }
}
