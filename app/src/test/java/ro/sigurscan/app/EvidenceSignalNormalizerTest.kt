package ro.sigurscan.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class EvidenceSignalNormalizerTest {
    private val gate = EvidenceGate { 1_000L }

    @Test
    fun uberPromoHtmlWithApprovedTrackerAndFinalOfficialCanContinueWithCaution() {
        val html = """
            <html>
              <body>
                <p>Uber promo: nu rata reducerea de azi.</p>
                <a href="https://rides.sng.link/Aw5zn/hw3r?campaign=crm">Comanda o cursa</a>
              </body>
            </html>
        """.trimIndent()

        val snapshot = normalize(
            rawText = html,
            htmlContent = html,
            primaryUrl = "https://rides.sng.link/Aw5zn/hw3r?campaign=crm",
            finalUrl = "https://www.uber.com/ro/ride/",
            redirectChain = listOf(
                "https://rides.sng.link/Aw5zn/hw3r?campaign=crm",
                "https://www.uber.com/ro/ride/"
            )
        )

        assertCodes(
            snapshot,
            EvidenceCode.HTML_BUTTON_LINK,
            EvidenceCode.HIDDEN_LINK_PRESENT,
            EvidenceCode.TRACKING_LINK,
            EvidenceCode.APPROVED_TRACKER_DOMAIN,
            EvidenceCode.REDIRECT_CHAIN_APPROVED,
            EvidenceCode.OFFICIAL_DOMAIN_EXACT,
            EvidenceCode.NO_SENSITIVE_FORM,
            EvidenceCode.PROMO_TEXT
        )
        assertEquals("https://www.uber.com/ro/ride/", snapshot.finalUrl)
        assertEquals(GateAction.CONTINUE_WITH_CAUTION, gate.evaluate(snapshot).action)
    }

    @Test
    fun emagPromoHtmlWithButtonAndFinalOfficialCanContinueWithCaution() {
        val html = """
            <html>
              <body>
                <p>eMAG: voucher de weekend si oferta limitata.</p>
                <a href="https://marketing.sng.link/click/emag">Vezi oferta</a>
              </body>
            </html>
        """.trimIndent()

        val snapshot = normalize(
            rawText = html,
            htmlContent = html,
            primaryUrl = "https://marketing.sng.link/click/emag",
            finalUrl = "https://www.emag.ro/oferta",
            redirectChain = listOf("https://marketing.sng.link/click/emag", "https://www.emag.ro/oferta")
        )

        assertCodes(snapshot, EvidenceCode.OFFICIAL_DOMAIN_EXACT, EvidenceCode.NO_SENSITIVE_FORM, EvidenceCode.VOUCHER_TEXT)
        assertEquals(GateAction.CONTINUE_WITH_CAUTION, gate.evaluate(snapshot).action)
    }

    @Test
    fun hiddenButtonOnlyWithoutOfficialFinalIsVerifyOfficial() {
        val html = """
            <html>
              <body>
                <button onclick="window.location.href='https://promo.example.net/landing'">Vezi oferta</button>
              </body>
            </html>
        """.trimIndent()

        val snapshot = normalize(rawText = html, htmlContent = html)

        assertCodes(snapshot, EvidenceCode.HTML_BUTTON_LINK, EvidenceCode.HIDDEN_LINK_PRESENT)
        assertEquals(GateAction.INSUFFICIENT_EVIDENCE, gate.evaluate(snapshot).action)
    }

    @Test
    fun telefonStricatMoneyTextMapsToNoReply() {
        val snapshot = normalize(
            rawText = "Mama, sunt eu. Mi s-a stricat telefonul si acesta e numar nou. Trimite bani urgent in cont."
        )

        assertCodes(snapshot, EvidenceCode.FAMILY_NEW_PHONE_MONEY, EvidenceCode.MONEY_REQUEST)
        assertEquals(GateAction.INSUFFICIENT_EVIDENCE, gate.evaluate(snapshot).action)
    }

    @Test
    fun whatsappCodeRequestMapsToNoReply() {
        val snapshot = normalize(
            rawText = "WhatsApp: trimite-mi codul de verificare primit prin SMS ca sa confirm dispozitivul."
        )

        assertCodes(snapshot, EvidenceCode.WHATSAPP_CODE_REQUEST, EvidenceCode.WHATSAPP_DEVICE_LINKING_REQUEST)
        assertEquals(GateAction.INSUFFICIENT_EVIDENCE, gate.evaluate(snapshot).action)
    }

    @Test
    fun fanFakeCardFormMapsToHardGateAction() {
        val html = """
            <html>
              <body>
                <p>FAN Courier: colet la locker. Plateste taxa de livrare.</p>
                <form action="https://fan-colet-plata.example.net/card">
                  <input name="card" />
                  <input name="cvv" />
                </form>
              </body>
            </html>
        """.trimIndent()

        val snapshot = normalize(rawText = html, htmlContent = html, providerStates = completedUrlProviderStates())

        assertCodes(
            snapshot,
            EvidenceCode.COURIER_UNOFFICIAL_DOMAIN,
            EvidenceCode.PARCEL_TAX,
            EvidenceCode.SENSITIVE_FORM_UNOFFICIAL,
            EvidenceCode.CARD_REQUEST,
            EvidenceCode.CVV_REQUEST,
            EvidenceCode.BRAND_IMPERSONATION
        )
        assertEquals(GateAction.DO_NOT_CONTINUE, gate.evaluate(snapshot).action)
    }

    @Test
    fun webRiskNoMatchDoesNotOverrideUnofficialCardForm() {
        val html = """
            <html>
              <body>
                <form action="https://checkout.example.net/pay-card">
                  <input name="card" />
                </form>
              </body>
            </html>
        """.trimIndent()

        val snapshot = normalize(
            rawText = html,
            htmlContent = html,
            threatIntel = listOf(
                ThreatIntelSourceResult(
                    source = "Google Web Risk",
                    verdict = "No Threats",
                    severity = "low",
                    details = "URL fara semnale in baza Google Web Risk."
                )
            ),
            providerStates = completedUrlProviderStates()
        )

        assertCodes(snapshot, EvidenceCode.WEBRISK_NO_MATCH, EvidenceCode.SENSITIVE_FORM_UNOFFICIAL)
        assertEquals(ProviderStatus.OK, snapshot.providerStates[ProviderId.WEB_RISK]?.status)
        assertEquals(GateAction.NO_ENTER_DATA, gate.evaluate(snapshot).action)
    }

    @Test
    fun backendGoogleWebRiskSourceNameMapsToHardProviderEvidence() {
        val snapshot = normalize(
            rawText = "Verifica linkul https://danger.example.net",
            finalUrl = "https://danger.example.net",
            threatIntel = listOf(
                ThreatIntelSourceResult(
                    source = "google_web_risk",
                    verdict = "Threats Detected",
                    severity = "high",
                    details = "SOCIAL_ENGINEERING"
                )
            ),
            providerStates = completedUrlProviderStates()
        )

        assertCodes(snapshot, EvidenceCode.WEBRISK_MATCH_SOCIAL_ENGINEERING)
        assertEquals(ProviderStatus.OK, snapshot.providerStates[ProviderId.WEB_RISK]?.status)
        assertEquals(GateAction.DO_NOT_CONTINUE, gate.evaluate(snapshot).action)
    }

    @Test
    fun formActionToUnofficialHostOverridesBrandTrustAndTriggersDoNotContinue() {
        val html = """
            <html>
              <body>
                <p>eMAG: confirmare comanda si plata securizata.</p>
                <form action="https://emag-pay.example.net/secure">
                  <input name="card" />
                  <input name="cvv" />
                  <button type="submit">Confirma plata</button>
                </form>
              </body>
            </html>
        """.trimIndent()

        val snapshot = normalize(rawText = html, htmlContent = html, providerStates = completedUrlProviderStates())

        assertCodes(
            snapshot,
            EvidenceCode.HTML_BUTTON_LINK,
            EvidenceCode.SENSITIVE_FORM_UNOFFICIAL,
            EvidenceCode.BRAND_IMPERSONATION,
            EvidenceCode.OFFICIAL_DOMAIN_MISMATCH,
            EvidenceCode.CARD_REQUEST,
            EvidenceCode.CVV_REQUEST
        )
        assertEquals(GateAction.DO_NOT_CONTINUE, gate.evaluate(snapshot).action)
    }

    @Test
    fun urlscanPhishingMapsToDoNotContinue() {
        val snapshot = normalize(
            rawText = "Verifica acest link: https://phish.example.net/login",
            finalUrl = "https://phish.example.net/login",
            threatIntel = listOf(
                ThreatIntelSourceResult(
                    source = "urlscan.io",
                    verdict = "Malicious phishing",
                    severity = "high",
                    details = "Sandbox verdict: phishing"
                )
            ),
            providerStates = completedUrlProviderStates()
        )

        assertCodes(snapshot, EvidenceCode.URLSCAN_VERDICT_PHISHING)
        assertEquals(ProviderStatus.OK, snapshot.providerStates[ProviderId.URLSCAN]?.status)
        assertEquals(GateAction.DO_NOT_CONTINUE, gate.evaluate(snapshot).action)
    }

    @Test
    fun urlscanNoMaliciousClassificationDoesNotBecomePhishingBecauseOfTheWordMalicious() {
        val snapshot = normalize(
            rawText = "https://example.com",
            finalUrl = "https://example.com",
            threatIntel = listOf(
                ThreatIntelSourceResult(
                    source = "urlscan.io",
                    verdict = "No malicious classification",
                    severity = "low",
                    details = "urlscan verdict=No malicious classification; score=0"
                )
            )
        )

        assertCodes(snapshot, EvidenceCode.URLSCAN_NO_CLASSIFICATION)
        assertFalse(snapshot.signals.any { it.code == EvidenceCode.URLSCAN_VERDICT_PHISHING })
        assertFalse(gate.evaluate(snapshot).action == GateAction.DO_NOT_CONTINUE)
    }

    @Test
    fun urlscanPendingIsProviderStateAndNotSafe() {
        val snapshot = normalize(
            rawText = "Verifica linkul https://pending.example.net",
            finalUrl = "https://pending.example.net",
            threatIntel = listOf(
                ThreatIntelSourceResult(
                    source = "urlscan.io",
                    verdict = "Pending",
                    severity = "unknown",
                    details = "Sandbox queued and processing."
                )
            )
        )

        assertEquals(ProviderStatus.PENDING, snapshot.providerStates[ProviderId.URLSCAN]?.status)
        val result = gate.evaluate(snapshot)
        assertTrue(result.action in listOf(GateAction.VERIFY_OFFICIAL, GateAction.INSUFFICIENT_EVIDENCE))
        assertFalse(result.action == GateAction.CONTINUE_WITH_CAUTION)
        assertFalse(result.action == GateAction.DO_NOT_CONTINUE)
        assertTrue(result.asyncExpected)
    }

    @Test
    fun urlscanTimeoutIsProviderStateAndNotSafe() {
        val snapshot = normalize(
            rawText = "Verifica linkul https://timeout.example.net",
            finalUrl = "https://timeout.example.net",
            threatIntel = listOf(
                ThreatIntelSourceResult(
                    source = "urlscan.io",
                    verdict = "Timeout",
                    severity = "unknown",
                    details = "urlscan.io sandbox timed out."
                )
            )
        )

        assertEquals(ProviderStatus.TIMEOUT, snapshot.providerStates[ProviderId.URLSCAN]?.status)
        val result = gate.evaluate(snapshot)
        assertTrue(result.action in listOf(GateAction.VERIFY_OFFICIAL, GateAction.INSUFFICIENT_EVIDENCE))
        assertFalse(result.action == GateAction.CONTINUE_WITH_CAUTION)
        assertFalse(result.action == GateAction.DO_NOT_CONTINUE)
    }

    @Test
    fun urlscanSkippedIsProviderStateAndNotSafe() {
        val snapshot = normalize(
            rawText = "Verifica linkul https://skipped.example.net",
            finalUrl = "https://skipped.example.net",
            threatIntel = listOf(
                ThreatIntelSourceResult(
                    source = "urlscan.io",
                    verdict = "Skipped",
                    severity = "unknown",
                    details = "urlscan.io API key not configured."
                )
            )
        )

        assertEquals(ProviderStatus.SKIPPED, snapshot.providerStates[ProviderId.URLSCAN]?.status)
        val result = gate.evaluate(snapshot)
        assertTrue(result.action in listOf(GateAction.VERIFY_OFFICIAL, GateAction.INSUFFICIENT_EVIDENCE))
        assertFalse(result.action == GateAction.CONTINUE_WITH_CAUTION)
        assertFalse(result.action == GateAction.DO_NOT_CONTINUE)
    }

    @Test
    fun webmailShellOnlyMapsToInsufficientEvidence() {
        val snapshot = EvidenceSignalNormalizer.buildSnapshot(
            EvidenceNormalizerInput(
                inputKind = "share_text",
                channel = "webmail_shell",
                rawText = "Yahoo Mail shell fara body util"
            )
        )

        assertCodes(snapshot, EvidenceCode.WEBMAIL_SHELL_ONLY)
        assertEquals(GateAction.INSUFFICIENT_EVIDENCE, gate.evaluate(snapshot).action)
    }

    @Test
    fun finalUrlDifferentFromPrimaryPreventsOfficialPrimaryFromBeingTrusted() {
        val rawText = "Uber: confirma cardul pentru oferta ta la https://www.uber.com"
        val snapshot = normalize(
            rawText = rawText,
            primaryUrl = "https://rides.sng.link/Aw5zn/hw3r",
            finalUrl = "https://uber-card-check.example.net/verify-card",
            redirectChain = listOf(
                "https://rides.sng.link/Aw5zn/hw3r",
                "https://uber-card-check.example.net/verify-card"
            )
        )

        assertCodes(
            snapshot,
            EvidenceCode.APPROVED_TRACKER_DOMAIN,
            EvidenceCode.BRAND_IMPERSONATION,
            EvidenceCode.OFFICIAL_DOMAIN_MISMATCH,
            EvidenceCode.CARD_REQUEST
        )
        assertFalse(snapshot.signals.any { it.code == EvidenceCode.OFFICIAL_DOMAIN_EXACT && it.targetKey.contains("sng.link") })
        assertEquals("https://uber-card-check.example.net/verify-card", snapshot.finalUrl)
        assertEquals(GateAction.DO_NOT_CONTINUE, gate.evaluate(snapshot).action)
    }

    @Test
    fun virusTotalCleanIsNonDecisiveButMapped() {
        val snapshot = normalize(
            rawText = "Verifica linkul https://example.com",
            finalUrl = "https://example.com",
            threatIntel = listOf(
                ThreatIntelSourceResult(
                    source = "VirusTotal",
                    verdict = "Clean",
                    severity = "low",
                    details = "Engines: malicious=0, suspicious=0, undetected=65"
                )
            ),
            virusTotalConfigured = true
        )

        assertCodes(snapshot, EvidenceCode.VIRUSTOTAL_LOW_OR_NO_DETECTION)
        assertEquals(ProviderStatus.OK, snapshot.providerStates[ProviderId.VIRUSTOTAL]?.status)
        assertEquals(GateAction.INSUFFICIENT_EVIDENCE, gate.evaluate(snapshot).action)
    }

    @Test
    fun virusTotalMaliciousConsensusIsMapped() {
        val snapshot = normalize(
            rawText = "Verifica linkul https://bad.example.net",
            finalUrl = "https://bad.example.net",
            threatIntel = listOf(
                ThreatIntelSourceResult(
                    source = "VirusTotal",
                    verdict = "Malicious",
                    severity = "high",
                    details = "Engines: total=70, malicious=4, suspicious=1"
                )
            ),
            virusTotalConfigured = true,
            providerStates = completedUrlProviderStates()
        )

        assertCodes(snapshot, EvidenceCode.VIRUSTOTAL_MALICIOUS_CONSENSUS)
        assertEquals(GateAction.DO_NOT_CONTINUE, gate.evaluate(snapshot).action)
    }

    @Test
    fun marketplaceReceiveMoneyWithOtpMapsToNoEnterData() {
        val snapshot = normalize(
            rawText = "OLX: ca sa primesti banii, introdu cardul si codul OTP primit prin SMS."
        )

        assertCodes(snapshot, EvidenceCode.MARKETPLACE_RECEIVE_MONEY, EvidenceCode.CARD_REQUEST, EvidenceCode.OTP_REQUEST)
        assertEquals(GateAction.INSUFFICIENT_EVIDENCE, gate.evaluate(snapshot).action)
    }

    @Test
    fun bareDomainInRealYoxoSmsIsExtractedAsScanTarget() {
        val snapshot = normalize(
            rawText = """
                Ai un telefon sau o tableta pe care nu le mai folosesti? Acum le poti transforma rapid in bani cu serviciul de buy-back YOXO. Beneficiezi de evaluare online in doar cateva minute, transport gratuit si plata in cont in maximum 48 de ore de la confirmarea dispozitivului. Simplu, sigur si fara batai de cap. Afla cat valoreaza dispozitivul tau si incepe procesul chiar acum: buyback.yoxo.ro
            """.trimIndent()
        )

        assertEquals("https://buyback.yoxo.ro", snapshot.primaryUrl)
        assertCodes(snapshot, EvidenceCode.OFFICIAL_DOMAIN_EXACT)
    }

    @Test
    fun yoxoBuybackSmsWithCleanProvidersOfficialDomainAndInconclusiveClaimIsSafe() {
        val snapshot = normalize(
            rawText = "Ai un telefon sau o tableta pe care nu le mai folosesti? Acum le poti transforma rapid in bani cu serviciul de buy-back YOXO. Afla cat valoreaza dispozitivul tau si incepe procesul chiar acum: buyback.yoxo.ro",
            primaryUrl = "https://buyback.yoxo.ro/",
            finalUrl = "https://buyback.yoxo.ro/?r=1",
            threatIntel = listOf(
                ThreatIntelSourceResult(
                    source = "google_web_risk",
                    verdict = "No Threats",
                    severity = "low"
                ),
                ThreatIntelSourceResult(
                    source = "urlscan.io",
                    verdict = "No malicious classification",
                    severity = "low"
                ),
                ThreatIntelSourceResult(
                    source = "VirusTotal",
                    verdict = "Clean",
                    severity = "low"
                ),
                ThreatIntelSourceResult(
                    source = "ai_offer_web_check",
                    verdict = "inconclusive",
                    severity = "unknown"
                )
            ),
            virusTotalConfigured = true
        )

        assertCodes(
            snapshot,
            EvidenceCode.WEBRISK_NO_MATCH,
            EvidenceCode.URLSCAN_NO_CLASSIFICATION,
            EvidenceCode.VIRUSTOTAL_LOW_OR_NO_DETECTION,
            EvidenceCode.OFFER_CLAIM_INCONCLUSIVE,
            EvidenceCode.OFFICIAL_DOMAIN_EXACT,
            EvidenceCode.NO_SENSITIVE_FORM
        )
        val result = gate.evaluate(snapshot)
        assertEquals(GateAction.CONTINUE_WITH_CAUTION, result.action)
        assertEquals("Sigur", result.userLabel)
    }

    @Test
    fun idroidServiceSmsWithCleanProvidersAndConfirmedOfficialClaimIsSafe() {
        val snapshot = normalize(
            rawText = "Dispozitivul dvs. (cod 8HXDX) nu a putut fi reparat. Informatii la 0371237475. https://idroid.ro/verificare-status Se percepe taxa de magazinaj la depasirea a 10 zile.",
            primaryUrl = "https://idroid.ro/verificare-status",
            finalUrl = "https://idroid.ro/verifica-status/",
            threatIntel = listOf(
                ThreatIntelSourceResult(
                    source = "google_web_risk",
                    verdict = "clean",
                    severity = "low"
                ),
                ThreatIntelSourceResult(
                    source = "urlscan.io",
                    verdict = "No malicious classification",
                    severity = "low"
                ),
                ThreatIntelSourceResult(
                    source = "VirusTotal",
                    verdict = "clean",
                    severity = "low"
                ),
                ThreatIntelSourceResult(
                    source = "ai_offer_web_check",
                    verdict = "confirmed",
                    severity = "low",
                    details = "official_source_found=true; official_domains=idroid.ro; Claim terms were found on an official destination/page."
                )
            ),
            virusTotalConfigured = true
        )

        assertCodes(
            snapshot,
            EvidenceCode.WEBRISK_NO_MATCH,
            EvidenceCode.URLSCAN_NO_CLASSIFICATION,
            EvidenceCode.VIRUSTOTAL_LOW_OR_NO_DETECTION,
            EvidenceCode.OFFER_CLAIM_CONFIRMED,
            EvidenceCode.OFFICIAL_DOMAIN_EXACT,
            EvidenceCode.NO_SENSITIVE_FORM
        )
        val result = gate.evaluate(snapshot)
        assertEquals(GateAction.CONTINUE_WITH_CAUTION, result.action)
        assertEquals("Sigur", result.userLabel)
    }

    @Test
    fun idroidServiceSmsWithCleanUrlProvidersButMissingClaimVerifierStaysSuspect() {
        val snapshot = normalize(
            rawText = "Dispozitivul dvs. (cod 8HXDX) nu a putut fi reparat. Informatii la 0371237475. https://idroid.ro/verificare-status Se percepe taxa de magazinaj la depasirea a 10 zile.",
            primaryUrl = "https://idroid.ro/verificare-status",
            finalUrl = "https://idroid.ro/verifica-status/",
            threatIntel = listOf(
                ThreatIntelSourceResult(
                    source = "google_web_risk",
                    verdict = "clean",
                    severity = "low"
                ),
                ThreatIntelSourceResult(
                    source = "urlscan.io",
                    verdict = "No malicious classification",
                    severity = "low"
                ),
                ThreatIntelSourceResult(
                    source = "VirusTotal",
                    verdict = "clean",
                    severity = "low"
                )
            ),
            virusTotalConfigured = true
        )

        assertCodes(
            snapshot,
            EvidenceCode.WEBRISK_NO_MATCH,
            EvidenceCode.URLSCAN_NO_CLASSIFICATION,
            EvidenceCode.VIRUSTOTAL_LOW_OR_NO_DETECTION,
            EvidenceCode.OFFICIAL_DOMAIN_EXACT,
            EvidenceCode.NO_SENSITIVE_FORM
        )
        val result = gate.evaluate(snapshot)
        assertEquals(GateAction.INSUFFICIENT_EVIDENCE, result.action)
        assertEquals("Suspect", result.userLabel)
        assertTrue(result.reasonCodes.contains("PROVIDER_REVIEW_REQUIRED"))
    }

    @Test
    fun fanCourierWhatsappCardScenarioIncludesRuntimeCorpusBrandWarning() {
        val snapshot = normalize(
            rawText = "FAN Courier: colet la locker. Pentru ridicare intra pe link si introdu codul WhatsApp, cardul si CVV.",
            primaryUrl = "https://fan-locker.example.test/card",
            finalUrl = "https://fan-locker.example.test/card",
            providerStates = completedUrlProviderStates()
        )

        assertCodes(
            snapshot,
            EvidenceCode.CORPUS_BRAND_WARNING,
            EvidenceCode.COURIER_UNOFFICIAL_DOMAIN,
            EvidenceCode.PARCEL_TAX,
            EvidenceCode.CARD_REQUEST,
            EvidenceCode.CVV_REQUEST,
            EvidenceCode.OTP_REQUEST
        )
        assertTrue(snapshot.signals.any { signal ->
            signal.code == EvidenceCode.CORPUS_BRAND_WARNING &&
                signal.brandId == "fanCourier" &&
                signal.attrs["neverAskFor"]?.contains("CARD_DATA") == true
        })
        assertEquals(GateAction.DO_NOT_CONTINUE, gate.evaluate(snapshot).action)
    }

    @Test
    fun corpusAndRagThreatIntelMapToControlledNonJudgingSignals() {
        val snapshot = normalize(
            rawText = "Voteaza pe Adeline si confirma cu codul primit pe WhatsApp.",
            threatIntel = listOf(
                ThreatIntelSourceResult(
                    source = "romania_corpus",
                    verdict = "similarity",
                    severity = "medium",
                    details = "scenario=whatsapp_voteaza_pe_adeline"
                ),
                ThreatIntelSourceResult(
                    source = "brand_warning_corpus",
                    verdict = "brand_warning",
                    severity = "medium",
                    details = "neverAskFor=OTP_CODE; brand=whatsapp"
                ),
                ThreatIntelSourceResult(
                    source = "rag_explainer",
                    verdict = "explanation",
                    severity = "low",
                    details = "RAG found similar WhatsApp takeover pattern."
                )
            ),
            providerStates = mapOf(
                ProviderId.CLAIM_VERIFIER to ProviderState(ProviderId.CLAIM_VERIFIER, ProviderStatus.OK)
            )
        )

        assertCodes(
            snapshot,
            EvidenceCode.CORPUS_SIMILARITY,
            EvidenceCode.CORPUS_BRAND_WARNING,
            EvidenceCode.RAG_EXPLANATION
        )
        assertEquals(ProviderStatus.OK, snapshot.providerStates[ProviderId.CORPUS]?.status)
        assertEquals(ProviderStatus.OK, snapshot.providerStates[ProviderId.RAG]?.status)
        assertTrue(snapshot.signals.none {
            it.code == EvidenceCode.RAG_EXPLANATION && EvidenceGatePolicy.isDecisionEligible(it)
        })
    }

    @Test
    fun backendEvidenceMapsInfrastructureSignals() {
        val snapshot = EvidenceSignalNormalizer.buildSnapshot(
            EvidenceNormalizerInput(
                inputKind = "unit_test",
                channel = "text_with_url",
                rawText = "Verifica https://brand-check.example/login",
                primaryUrl = "https://brand-check.example/login",
                finalUrl = "https://brand-check.example/login",
                backendEvidence = mapOf(
                    "extracted_urls" to listOf(
                        mapOf(
                            "final_url" to "https://brand-check.example/login",
                            "domain_age_days" to 5
                        )
                    ),
                    "url_behaviour" to mapOf(
                        "https://brand-check.example/login" to listOf("redirect", "login")
                    ),
                    "url_transport" to mapOf(
                        "https://brand-check.example/login" to mapOf("type" to "ip_hostname")
                    )
                )
            )
        )

        assertCodes(
            snapshot,
            EvidenceCode.DOMAIN_AGE_VERY_RECENT,
            EvidenceCode.URL_BEHAVIOUR_SUSPICIOUS,
            EvidenceCode.URL_TRANSPORT_RISK
        )
    }

    @Test
    fun infraThreatIntelMapsHomoglyphTyposquatAndPunycode() {
        val snapshot = normalize(
            rawText = "Actualizare cont https://xn--bcr-secure.example/login",
            finalUrl = "https://xn--bcr-secure.example/login",
            threatIntel = listOf(
                ThreatIntelSourceResult(
                    source = "sigurscan_lexical",
                    verdict = "typosquatting,punycode,homoglyph",
                    severity = "high",
                    details = "signals=typosquatting,punycode,homoglyph; domain_age_days=4"
                )
            )
        )

        assertCodes(
            snapshot,
            EvidenceCode.TYPOSQUAT_LOOKALIKE,
            EvidenceCode.PUNYCODE_HOST,
            EvidenceCode.HOMOGLYPH_DOMAIN,
            EvidenceCode.DOMAIN_AGE_VERY_RECENT
        )
    }

    @Test
    fun confusableBrandHostStillProducesBrandImpersonation() {
        val snapshot = normalize(
            rawText = "Verifica aici contul tau.",
            primaryUrl = "https://bсr-online.example/login",
            finalUrl = "https://bсr-online.example/login",
            threatIntel = listOf(
                ThreatIntelSourceResult(
                    source = "infra_homoglyph",
                    verdict = "homoglyph",
                    severity = "high",
                    details = "brand=bcr"
                )
            ),
            providerStates = completedUrlProviderStates()
        )

        assertCodes(
            snapshot,
            EvidenceCode.BRAND_IMPERSONATION,
            EvidenceCode.OFFICIAL_DOMAIN_MISMATCH,
            EvidenceCode.HOMOGLYPH_DOMAIN
        )
    }

    private fun normalize(
        rawText: String,
        htmlContent: String? = null,
        primaryUrl: String? = null,
        finalUrl: String? = null,
        redirectChain: List<String> = emptyList(),
        threatIntel: List<ThreatIntelSourceResult> = emptyList(),
        virusTotalConfigured: Boolean = false,
        providerStates: Map<ProviderId, ProviderState> = emptyMap(),
        backendEvidence: Map<String, Any>? = null
    ): EvidenceSnapshot {
        val effectiveProviderStates = providerStates.ifEmpty {
            if (
            threatIntel.isEmpty() &&
            (!primaryUrl.isNullOrBlank() || !finalUrl.isNullOrBlank())
            ) completedUrlProviderStates() else emptyMap()
        }
        return EvidenceSignalNormalizer.buildSnapshot(
            EvidenceNormalizerInput(
                inputKind = "unit_test",
                channel = if (htmlContent != null) "email_html" else "text",
                rawText = rawText,
                htmlContent = htmlContent,
                primaryUrl = primaryUrl,
                finalUrl = finalUrl,
                redirectChain = redirectChain,
                threatIntel = threatIntel,
                providerStates = effectiveProviderStates,
                backendEvidence = backendEvidence,
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

    private fun assertCodes(snapshot: EvidenceSnapshot, vararg expected: EvidenceCode) {
        val actual = snapshot.signals.map { it.code }.toSet()
        expected.forEach { code ->
            assertTrue("Missing $code in $actual", actual.contains(code))
        }
    }
}
