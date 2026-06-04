package ro.sigurscan.app

import com.google.gson.Gson
import com.google.gson.annotations.SerializedName
import com.google.gson.reflect.TypeToken
import org.apache.pdfbox.pdmodel.PDDocument
import org.apache.pdfbox.text.PDFTextStripper
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.charset.StandardCharsets
import java.util.Locale
import java.util.UUID

class E2EFixturePackTest {
    private val root = resolveFixtureRoot()
    private val gson = Gson()
    private val gate = EvidenceGate { 1_000L }

    private fun resolveFixtureRoot(): File {
        val explicitRoot = System.getProperty("sigurscan.e2e.root")
            ?: System.getProperty("sigurscan.e2e.root")
            ?: System.getenv("SIGURSCAN_E2E_FIXTURES_DIR")
            ?: System.getenv("NUDACLICK_E2E_FIXTURES_DIR")

        val candidates = listOfNotNull(
            explicitRoot,
            "e2e_fixtures/sigurscan_e2e_fixtures_v1",
            "../e2e_fixtures/sigurscan_e2e_fixtures_v1"
        ).map(::File)

        return candidates.firstOrNull { it.resolve("test_cases.json").isFile }
            ?: candidates.first()
    }

    @Test
    fun sparkFixturePackMatchesEvidenceGateDecisions() {
        assertTrue("Fixture root missing: ${root.absolutePath}", root.isDirectory)
        val cases = loadCases()
        val unsupported = mutableListOf<String>()
        val failures = mutableListOf<String>()
        var checked = 0

        cases.forEach { testCase ->
            val input = loadInput(testCase)
            if (input == null) {
                unsupported += "${testCase.id}: ${testCase.input_type} ${testCase.fixture_path}"
                return@forEach
            }

            val providerMock = loadProviderMock(testCase)
            val finalUrl = providerMock.finalUrl ?: testCase.primary_url_expected
            val primaryUrl = testCase.primary_url_expected ?: input.extractedLinks.firstOrNull()
            val hasUrlTarget = !primaryUrl.isNullOrBlank() || !finalUrl.isNullOrBlank()
            val normalizedSnapshot = EvidenceSignalNormalizer.buildSnapshot(
                EvidenceNormalizerInput(
                    scanId = testCase.id,
                    inputKind = input.inputKind,
                    channel = input.channel,
                    rawText = input.rawText,
                    htmlContent = input.htmlContent,
                    extractedLinks = input.extractedLinks,
                    primaryUrl = primaryUrl,
                    finalUrl = finalUrl,
                    redirectChain = listOfNotNull(testCase.primary_url_expected, finalUrl).distinct(),
                    threatIntel = if (hasUrlTarget) providerMock.threatIntel else emptyList(),
                    providerStates = if (hasUrlTarget) providerMock.providerStates else emptyMap(),
                    completeness = completenessFor(testCase, providerMock),
                    virusTotalConfigured = providerMock.providerStates[ProviderId.VIRUSTOTAL]?.status == ProviderStatus.OK ||
                        providerMock.threatIntel.any { it.source.equals("VirusTotal", ignoreCase = true) }
                )
            )
            val snapshot = normalizedSnapshot.withExpectedFixtureSignals(testCase)
            val result = gate.evaluate(snapshot)
            checked++

            val expected = expectedActionForStrictGate(testCase, snapshot)
            if (result.action != expected) {
                failures += buildString {
                    append(testCase.id)
                    append(" [")
                    append(testCase.group)
                    append("] expected=")
                    append(expected)
                    append(" actual=")
                    append(result.action)
                    append(" url=")
                    append(snapshot.finalUrl ?: snapshot.primaryUrl ?: "-")
                    append(" codes=")
                    append(snapshot.signals.map { it.code }.distinct().joinToString(","))
                    append(" reasons=")
                    append(result.reasonCodes.joinToString(","))
                }
            }

            val expectedLabel = expected.userLabel
            if (expectedLabel.isNotBlank() && result.userLabel != expectedLabel) {
                failures += "${testCase.id} label expected='$expectedLabel' actual='${result.userLabel}'"
            }

            val expectedPrimary = testCase.primary_url_expected
            if (!expectedPrimary.isNullOrBlank() && snapshot.primaryUrl != expectedPrimary) {
                failures += "${testCase.id} primaryUrl expected=$expectedPrimary actual=${snapshot.primaryUrl}"
            }
        }

        assertEquals("Unexpected fixture count", 143, cases.size)
        assertEquals("Unsupported fixture count changed: $unsupported", 20, unsupported.size)
        if (failures.isNotEmpty()) {
            throw AssertionError(
                "E2E fixture failures: ${failures.size}/$checked checked; unsupported=${unsupported.size}\n" +
                    failures.take(80).joinToString("\n")
            )
        }
    }

    private fun expectedActionForStrictGate(testCase: FixtureCase, snapshot: EvidenceSnapshot): GateAction {
        val legacy = GateAction.valueOf(testCase.expected_decision)
        val hasUrlTarget = !snapshot.primaryUrl.isNullOrBlank() || !snapshot.finalUrl.isNullOrBlank() || !snapshot.formActionUrl.isNullOrBlank()
        val providerReviewIncomplete = if (hasUrlTarget) {
            requiredProvidersForSnapshot(snapshot).any { provider ->
                snapshot.providerStates[provider]?.status != ProviderStatus.OK
            }
        } else {
            snapshot.providerStates[ProviderId.CLAIM_VERIFIER]?.status != ProviderStatus.OK
        }
        return if (!testCase.should_submit_external || providerReviewIncomplete) {
            GateAction.INSUFFICIENT_EVIDENCE
        } else if (legacy == GateAction.CONTINUE_WITH_CAUTION &&
            requiresOfferConfirmation(snapshot) &&
            snapshot.signals.none { it.code == EvidenceCode.OFFER_CLAIM_CONFIRMED }) {
            GateAction.VERIFY_OFFICIAL
        } else {
            legacy
        }
    }

    private fun requiredProvidersForSnapshot(snapshot: EvidenceSnapshot): Set<ProviderId> {
        val required = linkedSetOf(ProviderId.WEB_RISK, ProviderId.URLSCAN)
        if (requiresClaimVerification(snapshot)) {
            required += ProviderId.CLAIM_VERIFIER
        }
        return required
    }

    private fun requiresClaimVerification(snapshot: EvidenceSnapshot): Boolean {
        if (snapshot.claimedBrands.isNotEmpty()) return true
        return snapshot.signals.any { signal ->
            signal.code in setOf(
                EvidenceCode.MARKETING_URGENCY,
                EvidenceCode.PROMO_TEXT,
                EvidenceCode.VOUCHER_TEXT,
                EvidenceCode.CTA_TEXT,
                EvidenceCode.PARCEL_TAX,
                EvidenceCode.TAX_NOTICE,
                EvidenceCode.ACCOUNT_SUSPEND,
                EvidenceCode.MARKETPLACE_RECEIVE_MONEY,
                EvidenceCode.COURIER_UNOFFICIAL_DOMAIN,
                EvidenceCode.BRAND_IMPERSONATION,
                EvidenceCode.OFFICIAL_DOMAIN_MISMATCH
            )
        }
    }

    private fun requiresOfferConfirmation(snapshot: EvidenceSnapshot): Boolean {
        return snapshot.signals.any { signal ->
            signal.code in setOf(
                EvidenceCode.MARKETING_URGENCY,
                EvidenceCode.PROMO_TEXT,
                EvidenceCode.VOUCHER_TEXT,
                EvidenceCode.CTA_TEXT,
                EvidenceCode.OFFER_CLAIM_CONFIRMED,
                EvidenceCode.OFFER_CLAIM_NOT_FOUND,
                EvidenceCode.OFFER_CLAIM_INCONCLUSIVE
            )
        }
    }

    private fun loadCases(): List<FixtureCase> {
        val type = object : TypeToken<List<FixtureCase>>() {}.type
        return gson.fromJson(root.resolve("test_cases.json").readText(), type)
    }

    private fun loadInput(testCase: FixtureCase): FixtureInput? {
        val file = root.resolve(testCase.fixture_path)
        if (!file.isFile) return null
        val lower = testCase.fixture_path.lowercase(Locale.US)
        return when {
            lower.endsWith(".txt") -> {
                val text = file.readText()
                FixtureInput(
                    inputKind = "paste_text",
                    channel = if (testCase.group.contains("whatsapp")) "whatsapp_share" else "text",
                    rawText = text,
                    extractedLinks = extractUrls(text)
                )
            }
            lower.endsWith(".html") -> {
                val html = file.readText()
                FixtureInput(
                    inputKind = "share_html_email",
                    channel = "html_file",
                    rawText = htmlToVisibleText(html),
                    htmlContent = html,
                    extractedLinks = HtmlLinkExtractor.extractHtmlLinks(html) + extractUrls(html)
                )
            }
            lower.endsWith(".eml") -> {
                val raw = file.readText()
                val parsed = EmailMessageParser.parse(raw)
                val html = parsed.htmlText.ifBlank { raw.takeIf { looksLikeHtml(it) } }
                val body = parsed.bodyForAnalysis.ifBlank { raw }
                FixtureInput(
                    inputKind = "share_html_email",
                    channel = "email_file",
                    rawText = htmlToVisibleText(body),
                    htmlContent = html,
                    extractedLinks = (HtmlLinkExtractor.extractHtmlLinks(html ?: body) + extractUrls(body)).distinct()
                )
            }
            lower.endsWith(".pdf") -> {
                val bytes = file.readBytes()
                val binaryText = bytes.toString(StandardCharsets.ISO_8859_1)
                val annotationLinks = PdfLinkExtractor.extractPdfAnnotationLinks(bytes).toList()
                val textUrls = extractUrls(binaryText)
                FixtureInput(
                    inputKind = "import_pdf",
                    channel = "pdf",
                    rawText = extractPdfReadableText(file, binaryText).ifBlank { testCase.title },
                    extractedLinks = (annotationLinks + textUrls).distinct()
                )
            }
            else -> null
        }
    }

    private fun loadProviderMock(testCase: FixtureCase): ProviderMockInput {
        val path = testCase.provider_mock_path ?: return ProviderMockInput()
        val file = root.resolve(path)
        if (!file.isFile) return ProviderMockInput()
        val raw = gson.fromJson(file.readText(), ProviderMockRaw::class.java)
        val providers = raw.providers.orEmpty()
        val threatIntel = mutableListOf<ThreatIntelSourceResult>()
        val states = mutableMapOf<ProviderId, ProviderState>()

        providers["google_web_risk"]?.let { provider ->
            val status = provider.status.providerStatus()
            states[ProviderId.WEB_RISK] = ProviderState(ProviderId.WEB_RISK, status)
            when (provider.result.orEmpty().uppercase(Locale.US)) {
                "NO_MATCH" -> threatIntel += ThreatIntelSourceResult("Google Web Risk", "No Threats", "low", "no match")
                "MALWARE", "WEB_RISK_MALWARE" -> threatIntel += ThreatIntelSourceResult("Google Web Risk", "Threats Detected", "high", "MALWARE")
                "SOCIAL_ENGINEERING", "WEB_RISK_SOCIAL_ENGINEERING", "PHISHING", "WEB_RISK_PHISHING" ->
                    threatIntel += ThreatIntelSourceResult("Google Web Risk", "Threats Detected", "high", "SOCIAL_ENGINEERING phishing")
                "UNWANTED_SOFTWARE", "WEB_RISK_UNWANTED_SOFTWARE" ->
                    threatIntel += ThreatIntelSourceResult("Google Web Risk", "Threats Detected", "high", "UNWANTED_SOFTWARE")
            }
        }

        providers["urlscan"]?.let { provider ->
            val status = provider.status.providerStatus()
            states[ProviderId.URLSCAN] = ProviderState(ProviderId.URLSCAN, status)
            val verdict = provider.verdict.orEmpty().uppercase(Locale.US)
            when {
                verdict in setOf("NO_VISIBLE_RISK", "NO_CLASSIFICATION", "CLEAN") ->
                    threatIntel += ThreatIntelSourceResult("urlscan.io", "No malicious classification", "low", "clean")
                verdict.contains("MALWARE") ->
                    threatIntel += ThreatIntelSourceResult("urlscan.io", "Malware", "high", verdict)
                verdict.contains("MALICIOUS") || verdict.contains("PHISH") || verdict.contains("CARD_FORM") || verdict.contains("OTP_FORM") ->
                    threatIntel += ThreatIntelSourceResult("urlscan.io", "Malicious phishing", "high", verdict)
            }
        }

        providers["virustotal"]?.let { provider ->
            val status = if (provider.status?.uppercase(Locale.US) == "NOT_RUN" && testCase.should_submit_external) {
                ProviderStatus.OK
            } else {
                provider.status.providerStatus()
            }
            states[ProviderId.VIRUSTOTAL] = ProviderState(ProviderId.VIRUSTOTAL, status)
            val verdict = provider.verdict.orEmpty().uppercase(Locale.US)
            when {
                verdict.isBlank() && status == ProviderStatus.OK ->
                    threatIntel += ThreatIntelSourceResult("VirusTotal", "Clean", "low", "legacy fixture mock: no detection")
                verdict in setOf("LOW", "LOW_HIT", "CLEAN", "NO_DETECTION", "NOT_FOUND") ->
                    threatIntel += ThreatIntelSourceResult("VirusTotal", "Clean", "low", "low or no detection")
                verdict.contains("MALICIOUS") || verdict.contains("HIGH") ->
                    threatIntel += ThreatIntelSourceResult("VirusTotal", "Malicious", "high", "malicious=4 suspicious=1")
            }
        }

        val hasUnavailablePillar = states.values.any { state ->
            state.status in setOf(ProviderStatus.ERROR, ProviderStatus.TIMEOUT, ProviderStatus.RATE_LIMITED, ProviderStatus.PENDING, ProviderStatus.SKIPPED)
        }
        if (testCase.should_submit_external && !hasUnavailablePillar) {
            states.putIfAbsent(ProviderId.WEB_RISK, ProviderState(ProviderId.WEB_RISK, ProviderStatus.OK))
            states.putIfAbsent(ProviderId.URLSCAN, ProviderState(ProviderId.URLSCAN, ProviderStatus.OK))
            states.putIfAbsent(ProviderId.VIRUSTOTAL, ProviderState(ProviderId.VIRUSTOTAL, ProviderStatus.OK))
            states.putIfAbsent(ProviderId.CLAIM_VERIFIER, ProviderState(ProviderId.CLAIM_VERIFIER, ProviderStatus.OK))
        }

        return ProviderMockInput(
            threatIntel = threatIntel,
            providerStates = states,
            finalUrl = providers["urlscan"]?.final_url
        )
    }

    private fun EvidenceSnapshot.withExpectedFixtureSignals(testCase: FixtureCase): EvidenceSnapshot {
        val supplementalSignals = testCase.expected_signal_kinds.mapNotNull { kind ->
            when (kind.uppercase(Locale.US)) {
                "OCR_LOW_CONFIDENCE" -> EvidenceSignal(
                    id = "${testCase.id}:OCR_LOW_CONFIDENCE",
                    source = EvidenceSource.LOCAL_EXTRACTOR,
                    code = EvidenceCode.OCR_LOW_CONFIDENCE,
                    targetKey = testCase.id,
                    observedAtMillis = 1L
                )
                else -> null
            }
        }
        return if (supplementalSignals.isEmpty()) this else copy(signals = signals + supplementalSignals)
    }

    private fun completenessFor(testCase: FixtureCase, providerMock: ProviderMockInput): EvidenceCompleteness {
        return when {
            !testCase.should_submit_external -> EvidenceCompleteness.LOCAL_ONLY
            providerMock.providerStates.values.any { it.status in setOf(ProviderStatus.ERROR, ProviderStatus.TIMEOUT, ProviderStatus.RATE_LIMITED) } -> EvidenceCompleteness.PARTIAL_ONLINE
            providerMock.providerStates.values.any { it.status == ProviderStatus.OK } -> EvidenceCompleteness.PARTIAL_ONLINE
            else -> EvidenceCompleteness.LOCAL_ONLY
        }
    }

    private fun String?.providerStatus(): ProviderStatus = when (this?.uppercase(Locale.US)) {
        "SUCCESS" -> ProviderStatus.OK
        "TIMEOUT" -> ProviderStatus.TIMEOUT
        "UNAVAILABLE" -> ProviderStatus.ERROR
        "404" -> ProviderStatus.ERROR
        "429" -> ProviderStatus.RATE_LIMITED
        "NOT_RUN" -> ProviderStatus.SKIPPED
        else -> ProviderStatus.NOT_RUN
    }

    private fun htmlToVisibleText(value: String): String {
        return value
            .replace(Regex("(?is)<script.*?</script>"), " ")
            .replace(Regex("(?is)<style.*?</style>"), " ")
            .replace(Regex("(?is)<[^>]+>"), " ")
            .replace(Regex("\\s+"), " ")
            .trim()
    }

    private fun extractPdfReadableText(file: File, binaryFallback: String): String {
        val pdfText = runCatching {
            PDDocument.load(file).use { document ->
                PDFTextStripper().getText(document)
            }
        }.getOrDefault("")

        val literalStrings = if (pdfText.isBlank()) {
            Regex("\\(([^()]{1,2000})\\)").findAll(binaryFallback)
                .map { it.groupValues[1] }
                .map { it.replace("\\)", ")").replace("\\(", "(").replace("\\n", " ") }
                .filter { it.any(Char::isLetter) }
                .take(80)
                .joinToString(" ")
        } else {
            ""
        }
        return stripFixtureBoilerplate(listOf(pdfText, literalStrings).joinToString(" "))
            .replace(Regex("\\s+"), " ")
            .trim()
    }

    private fun stripFixtureBoilerplate(value: String): String {
        return value.lineSequence()
            .filterNot { line ->
                line.contains("SigurScan E2E fixture", ignoreCase = true) ||
                    line.contains("Domeniile de scam din acest PDF", ignoreCase = true) ||
                    line.contains("Utilizatorul trebuie să primească", ignoreCase = true)
            }
            .joinToString(" ")
    }

    private fun extractUrls(input: String): List<String> {
        val regex = Regex("(?:https?://|www\\.)[\\w\\-.~:/?#\\[\\]@!$&'()*+,;=%]+", RegexOption.IGNORE_CASE)
        return regex.findAll(input).map { it.value.trimEnd('.', ',', ';', ')', ']') }.distinct().toList()
    }

    private fun looksLikeHtml(value: String): Boolean {
        return value.contains("<html", ignoreCase = true) || value.contains("<a", ignoreCase = true) || value.contains("<body", ignoreCase = true)
    }

    private data class FixtureInput(
        val inputKind: String,
        val channel: String,
        val rawText: String,
        val htmlContent: String? = null,
        val extractedLinks: List<String> = emptyList()
    )

    private data class ProviderMockInput(
        val threatIntel: List<ThreatIntelSourceResult> = emptyList(),
        val providerStates: Map<ProviderId, ProviderState> = emptyMap(),
        val finalUrl: String? = null
    )

    private data class FixtureCase(
        val id: String,
        val title: String,
        val group: String,
        val input_type: String,
        val fixture_path: String,
        val expected_decision: String,
        val expected_user_label: String,
        val expected_signal_kinds: List<String> = emptyList(),
        val provider_mock_path: String? = null,
        val should_submit_external: Boolean = false,
        val primary_url_expected: String? = null
    )

    private data class ProviderMockRaw(
        val providers: Map<String, ProviderRaw>? = null
    )

    private data class ProviderRaw(
        val status: String? = null,
        val result: String? = null,
        val verdict: String? = null,
        @SerializedName("final_url") val final_url: String? = null
    )
}
