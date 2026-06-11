package ro.sigurscan.app

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.google.gson.Gson
import com.google.gson.annotations.SerializedName
import com.google.gson.reflect.TypeToken
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.net.URI
import java.util.Locale

@RunWith(AndroidJUnit4::class)
class SigurScanFixturePackDeviceE2ETest {
    private val gson = Gson()
    private val gate = EvidenceGate { 1_000L }
    private val fixtureRoot = resolveFixtureRoot()

    @Test
    fun v1FixturePack_matchesGateContractOnDevice() {
        val packRoot = fixtureRoot.resolve("sigurscan_e2e_fixtures_v1")
        val cases = loadJsonList<V1Case>(packRoot.resolve("test_cases.json"))
        assertEquals("v1 fixture count changed", 143, cases.size)

        val failures = mutableListOf<FailureDetail>()
        cases.forEach { case ->
            validateRefs(packRoot, case.id, listOf(case.fixturePath, case.providerMockPath), failures)
            val mock = gson.fromJson(packRoot.resolve(case.providerMockPath).readText(), V1ProviderMock::class.java)
            val snapshot = snapshotForV1(case, mock)
            val result = gate.evaluate(snapshot)
            val expected = expectedActionForStrictGate(case, snapshot)
            if (result.action != expected) {
                failures += FailureDetail(
                    caseId = case.id,
                    expected = expected,
                    actual = result.action,
                    reasons = result.reasonCodes,
                    signals = snapshot.signals.map { it.code }.distinct()
                )
            }
        }

        val report = buildReport("v1", cases.size, failures)
        writeDeviceReport("v1", report)
        assertTrue(report, failures.isEmpty())
    }

    @Test
    fun v2FixturePack_matchesGateContractOnDevice() {
        val packRoot = fixtureRoot.resolve("sigurscan_e2e_fixtures_v2_realistic")
        val cases = loadJsonList<V2Case>(packRoot.resolve("test_cases.json"))
        assertEquals("v2 fixture count changed", 406, cases.size)

        val failures = mutableListOf<FailureDetail>()
        cases.forEach { case ->
            val refs = case.fixturePaths + case.providerMocks.values + listOfNotNull(case.expectedSnapshotPath)
            validateRefs(packRoot, case.id, refs, failures)
            val snapshot = snapshotForV2(packRoot, case)
            val result = gate.evaluate(snapshot)
            val expected = expectedActionForStrictGate(case, snapshot)
            if (result.action != expected) {
                failures += FailureDetail(
                    caseId = case.id,
                    expected = expected,
                    actual = result.action,
                    reasons = result.reasonCodes,
                    signals = snapshot.signals.map { it.code }.distinct()
                )
            }
        }

        val report = buildReport("v2", cases.size, failures)
        writeDeviceReport("v2", report)
        assertTrue(report, failures.isEmpty())
    }

    private fun buildReport(packName: String, totalCases: Int, failures: List<FailureDetail>): String {
        val lines = mutableListOf<String>()
        lines += "SigurScan device E2E report: $packName"
        lines += "total_cases=$totalCases"
        lines += "passed=${totalCases - failures.size}"
        lines += "failed=${failures.size}"
        lines += ""
        lines += "Expected -> actual"
        failures
            .groupingBy { "${it.expected} -> ${it.actual}" }
            .eachCount()
            .toSortedMap()
            .forEach { (bucket, count) -> lines += "$count x $bucket" }
        lines += ""
        lines += "Reason codes"
        failures
            .flatMap { it.reasons.ifEmpty { listOf("NO_REASON") } }
            .groupingBy { it }
            .eachCount()
            .toList()
            .sortedWith(compareByDescending<Pair<String, Int>> { it.second }.thenBy { it.first })
            .forEach { (reason, count) -> lines += "$count x $reason" }
        lines += ""
        lines += "First failures"
        failures.take(120).forEach { failure ->
            lines += "${failure.caseId}: expected=${failure.expected} actual=${failure.actual} reasons=${failure.reasons} signals=${failure.signals}"
        }
        return lines.joinToString("\n")
    }

    private fun writeDeviceReport(packName: String, report: String) {
        val targetContext = InstrumentationRegistry.getInstrumentation().targetContext
        val reportDir = File(targetContext.filesDir, "e2e_reports")
        reportDir.mkdirs()
        reportDir.resolve("${packName}_device_e2e_report.txt").writeText(report)
    }

    private fun snapshotForV1(case: V1Case, mock: V1ProviderMock): EvidenceSnapshot {
        val primaryUrl = case.primaryUrlExpected
        val urlscan = mock.providers["urlscan"]
        val finalUrl = urlscan?.finalUrl?.takeIf { urlscan.status == "SUCCESS" } ?: primaryUrl
        val targetKey = hostOf(finalUrl ?: primaryUrl) ?: case.id
        val signals = mutableListOf<EvidenceSignal>()
        val providerStates = mutableMapOf<ProviderId, ProviderState>()

        case.expectedSignalKinds.forEach { signalName ->
            addMappedSignals(signals, signalName, case.id, targetKey)
        }
        addV1ProviderSignals(signals, providerStates, case.id, targetKey, mock, case.shouldSubmitExternal)
        finalizeCompletedFixturePillars(signals, providerStates, case.id, targetKey, case.shouldSubmitExternal)

        return EvidenceSnapshot(
            scanId = case.id,
            inputKind = case.inputType,
            channel = "device_fixture_pack_v1",
            primaryUrl = primaryUrl,
            finalUrl = finalUrl,
            claimedBrands = case.expectedSignalKinds
                .takeIf { it.any { signal -> signal == "CLAIMED_BRAND_IDENTIFIED" } }
                ?.let { setOf(case.group) }
                .orEmpty(),
            signals = signals,
            providerStates = providerStates,
            registryVersion = case.registryVersion,
            corpusVersion = case.policyVersion,
            completeness = completeness(providerStates, case.shouldSubmitExternal)
        )
    }

    private fun snapshotForV2(packRoot: File, case: V2Case): EvidenceSnapshot {
        val urlscan = gson.fromJson(packRoot.resolve(case.providerMocks.getValue("urlscan")).readText(), V2UrlscanMock::class.java)
        val webRisk = gson.fromJson(packRoot.resolve(case.providerMocks.getValue("web_risk")).readText(), V2WebRiskMock::class.java)
        val phishingDatabaseMockPath = case.providerMocks["phishing_database"] ?: case.providerMocks.getValue("virustotal")
        val phishingDatabase = gson.fromJson(packRoot.resolve(phishingDatabaseMockPath).readText(), V2PhishingDatabaseMock::class.java)
        val primaryUrl = case.primaryUrl
        val finalUrl = urlscan.finalUrl.takeIf { urlscan.status == "SUCCESS" } ?: primaryUrl
        val targetKey = hostOf(finalUrl ?: primaryUrl) ?: case.id
        val signals = mutableListOf<EvidenceSignal>()
        val providerStates = mutableMapOf<ProviderId, ProviderState>()

        case.expectedSignals.forEach { signalName ->
            addMappedSignals(signals, signalName, case.id, targetKey)
        }
        addV2ProviderSignals(signals, providerStates, case.id, targetKey, urlscan, webRisk, phishingDatabase)
        finalizeCompletedFixturePillars(signals, providerStates, case.id, targetKey, case.providerMocks.isNotEmpty())

        return EvidenceSnapshot(
            scanId = case.id,
            inputKind = case.fixtureKinds.joinToString("+").ifBlank { case.channel },
            channel = "device_fixture_pack_v2",
            primaryUrl = primaryUrl,
            finalUrl = finalUrl,
            claimedBrands = case.brandClaimed?.takeIf { it.isNotBlank() }?.let { setOf(it.lowercase(Locale.US)) }.orEmpty(),
            signals = signals,
            providerStates = providerStates,
            registryVersion = "fixture-v2",
            corpusVersion = "fixture-v2",
            completeness = completeness(providerStates, shouldSubmitExternal = case.providerMocks.isNotEmpty())
        )
    }

    private fun expectedActionForStrictGate(case: V1Case, snapshot: EvidenceSnapshot): GateAction {
        return expectedActionForStrictGate(
            legacy = GateAction.valueOf(case.expectedDecision),
            shouldSubmitExternal = case.shouldSubmitExternal,
            snapshot = snapshot
        )
    }

    private fun expectedActionForStrictGate(case: V2Case, snapshot: EvidenceSnapshot): GateAction {
        return expectedActionForStrictGate(
            legacy = GateAction.valueOf(case.expectedDecision),
            shouldSubmitExternal = case.providerMocks.isNotEmpty(),
            snapshot = snapshot
        )
    }

    private fun expectedActionForStrictGate(
        legacy: GateAction,
        shouldSubmitExternal: Boolean,
        snapshot: EvidenceSnapshot
    ): GateAction {
        val hasUrlTarget = !snapshot.primaryUrl.isNullOrBlank() ||
            !snapshot.finalUrl.isNullOrBlank() ||
            !snapshot.formActionUrl.isNullOrBlank()
        val requiredProviders = if (hasUrlTarget) {
            buildSet {
                add(ProviderId.WEB_RISK)
                add(ProviderId.URLSCAN)
                add(ProviderId.PHISHING_DATABASE)
                if (requiresFixtureClaimVerification(snapshot)) add(ProviderId.CLAIM_VERIFIER)
            }
        } else {
            setOf(ProviderId.CLAIM_VERIFIER)
        }
        val providerReviewIncomplete = requiredProviders.any { provider ->
            snapshot.providerStates[provider]?.status != ProviderStatus.OK
        }
        return if (!shouldSubmitExternal || providerReviewIncomplete) {
            GateAction.INSUFFICIENT_EVIDENCE
        } else {
            expectedActionForFinalPolicy(legacy, snapshot)
        }
    }

    private fun expectedActionForFinalPolicy(legacy: GateAction, snapshot: EvidenceSnapshot): GateAction {
        val codes = snapshot.signals.map { it.code }.toSet()
        if (codes.any {
                it in setOf(
                    EvidenceCode.WEBRISK_MATCH_MALWARE,
                    EvidenceCode.WEBRISK_MATCH_SOCIAL_ENGINEERING,
                    EvidenceCode.WEBRISK_MATCH_UNWANTED_SOFTWARE,
                    EvidenceCode.WEBRISK_MATCH_SOCIAL_ENGINEERING_EXT,
                    EvidenceCode.URLSCAN_VERDICT_PHISHING,
                    EvidenceCode.URLSCAN_VERDICT_MALWARE,
                    EvidenceCode.PHISHING_DATABASE_LISTED,
                    EvidenceCode.APK_DOWNLOAD_UNOFFICIAL,
                    EvidenceCode.REMOTE_ACCESS_DOWNLOAD_UNOFFICIAL
                )
            }
        ) {
            return GateAction.DO_NOT_CONTINUE
        }

        val hasSensitiveAsk = codes.any {
            it in setOf(
                EvidenceCode.CARD_REQUEST,
                EvidenceCode.CVV_REQUEST,
                EvidenceCode.OTP_REQUEST,
                EvidenceCode.PASSWORD_REQUEST,
                EvidenceCode.CNP_IBAN_REQUEST,
                EvidenceCode.PERSONAL_DATA_REQUEST,
                EvidenceCode.PAYMENT_REQUEST,
                EvidenceCode.SENSITIVE_FORM_UNOFFICIAL
            )
        }
        val hasDirectReplySecretRequest = codes.contains(EvidenceCode.REPLY_WITH_CODE_REQUEST) &&
            codes.any {
                it in setOf(
                    EvidenceCode.OTP_REQUEST,
                    EvidenceCode.PASSWORD_REQUEST,
                    EvidenceCode.CARD_REQUEST,
                    EvidenceCode.CNP_IBAN_REQUEST
                )
            }
        if (hasDirectReplySecretRequest) return GateAction.NO_REPLY

        val hasOfficialDestination = codes.any {
            it in setOf(EvidenceCode.OFFICIAL_DOMAIN_EXACT, EvidenceCode.DELEGATED_DOMAIN_EXACT)
        }
        if (hasSensitiveAsk && !hasOfficialDestination) return GateAction.NO_ENTER_DATA

        if (legacy == GateAction.CONTINUE_WITH_CAUTION &&
            requiresOfferConfirmation(snapshot) &&
            !codes.contains(EvidenceCode.OFFER_CLAIM_CONFIRMED)
        ) {
            return GateAction.VERIFY_OFFICIAL
        }

        val hasReviewedUnknownDestination = legacy == GateAction.INSUFFICIENT_EVIDENCE &&
            !snapshot.finalUrl.isNullOrBlank() &&
            snapshot.completeness != EvidenceCompleteness.LOCAL_ONLY &&
            codes.contains(EvidenceCode.NO_SENSITIVE_FORM)
        if (hasReviewedUnknownDestination) return GateAction.VERIFY_OFFICIAL

        return legacy
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

    private fun requiresFixtureClaimVerification(snapshot: EvidenceSnapshot): Boolean {
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

    private fun addV1ProviderSignals(
        signals: MutableList<EvidenceSignal>,
        states: MutableMap<ProviderId, ProviderState>,
        caseId: String,
        targetKey: String,
        mock: V1ProviderMock,
        shouldSubmitExternal: Boolean
    ) {
        mock.providers["google_web_risk"]?.let { provider ->
            states[ProviderId.WEB_RISK] = ProviderState(ProviderId.WEB_RISK, provider.status.toProviderStatus())
            when (provider.result.orEmpty().uppercase(Locale.US)) {
                "NO_MATCH" -> addSignal(signals, caseId, targetKey, EvidenceSource.GOOGLE_WEB_RISK, EvidenceCode.WEBRISK_NO_MATCH, ProviderId.WEB_RISK)
                "WEB_RISK_MALWARE", "MALWARE" -> addSignal(signals, caseId, targetKey, EvidenceSource.GOOGLE_WEB_RISK, EvidenceCode.WEBRISK_MATCH_MALWARE, ProviderId.WEB_RISK)
                "WEB_RISK_SOCIAL_ENGINEERING", "PHISHING", "SOCIAL_ENGINEERING" ->
                    addSignal(signals, caseId, targetKey, EvidenceSource.GOOGLE_WEB_RISK, EvidenceCode.WEBRISK_MATCH_SOCIAL_ENGINEERING, ProviderId.WEB_RISK)
            }
        }
        mock.providers["urlscan"]?.let { provider ->
            states[ProviderId.URLSCAN] = ProviderState(ProviderId.URLSCAN, provider.status.toProviderStatus())
            addUrlscanVerdictSignals(signals, caseId, targetKey, provider.verdict)
            if (provider.status == "SUCCESS" && provider.verdict.isCleanUrlscanVerdict()) {
                addSignal(signals, caseId, targetKey, EvidenceSource.URLSCAN, EvidenceCode.NO_SENSITIVE_FORM, ProviderId.URLSCAN)
            }
        }
        (mock.providers["phishing_database"] ?: mock.providers["virustotal"])?.let { provider ->
            val status = if (provider.status.equals("NOT_RUN", ignoreCase = true) && shouldSubmitExternal) {
                ProviderStatus.OK
            } else {
                provider.status.toProviderStatus()
            }
            states[ProviderId.PHISHING_DATABASE] = ProviderState(ProviderId.PHISHING_DATABASE, status)
            addPhishingDatabaseVerdictSignals(signals, caseId, targetKey, provider.verdict)
        }
    }

    private fun finalizeCompletedFixturePillars(
        signals: MutableList<EvidenceSignal>,
        states: MutableMap<ProviderId, ProviderState>,
        caseId: String,
        targetKey: String,
        shouldSubmitExternal: Boolean
    ) {
        if (!shouldSubmitExternal) return
        val hasUnavailablePillar = states.values.any { state ->
            state.status in setOf(
                ProviderStatus.ERROR,
                ProviderStatus.TIMEOUT,
                ProviderStatus.RATE_LIMITED,
                ProviderStatus.PENDING,
                ProviderStatus.SKIPPED
            )
        }
        if (hasUnavailablePillar) return

        states.putIfAbsent(ProviderId.WEB_RISK, ProviderState(ProviderId.WEB_RISK, ProviderStatus.OK))
        states.putIfAbsent(ProviderId.URLSCAN, ProviderState(ProviderId.URLSCAN, ProviderStatus.OK))
        states.putIfAbsent(ProviderId.PHISHING_DATABASE, ProviderState(ProviderId.PHISHING_DATABASE, ProviderStatus.OK))
        states.putIfAbsent(ProviderId.CLAIM_VERIFIER, ProviderState(ProviderId.CLAIM_VERIFIER, ProviderStatus.OK))
        if (signals.none { it.provider == ProviderId.CLAIM_VERIFIER }) {
            addSignal(
                signals,
                caseId,
                targetKey,
                EvidenceSource.CLAIM_VERIFIER,
                EvidenceCode.OFFER_CLAIM_INCONCLUSIVE,
                ProviderId.CLAIM_VERIFIER
            )
        }
    }

    private fun addV2ProviderSignals(
        signals: MutableList<EvidenceSignal>,
        states: MutableMap<ProviderId, ProviderState>,
        caseId: String,
        targetKey: String,
        urlscan: V2UrlscanMock,
        webRisk: V2WebRiskMock,
        virusTotal: V2PhishingDatabaseMock
    ) {
        states[ProviderId.URLSCAN] = ProviderState(ProviderId.URLSCAN, urlscan.status.toProviderStatus())
        states[ProviderId.WEB_RISK] = ProviderState(ProviderId.WEB_RISK, webRisk.status.toProviderStatus())
        states[ProviderId.PHISHING_DATABASE] = ProviderState(ProviderId.PHISHING_DATABASE, virusTotal.status.toProviderStatus())

        addUrlscanVerdictSignals(signals, caseId, targetKey, urlscan.verdict)
        urlscan.forms.forEach { form ->
            when (form.lowercase(Locale.US)) {
                "card" -> addSignal(signals, caseId, targetKey, EvidenceSource.URLSCAN, EvidenceCode.CARD_REQUEST, ProviderId.URLSCAN)
                "cvv" -> addSignal(signals, caseId, targetKey, EvidenceSource.URLSCAN, EvidenceCode.CVV_REQUEST, ProviderId.URLSCAN)
                "otp" -> addSignal(signals, caseId, targetKey, EvidenceSource.URLSCAN, EvidenceCode.OTP_REQUEST, ProviderId.URLSCAN)
                "login" -> addSignal(signals, caseId, targetKey, EvidenceSource.URLSCAN, EvidenceCode.PASSWORD_REQUEST, ProviderId.URLSCAN)
                "whatsapp_code" -> addSignal(signals, caseId, targetKey, EvidenceSource.URLSCAN, EvidenceCode.WHATSAPP_CODE_REQUEST, ProviderId.URLSCAN)
                "apk_download" -> addSignal(signals, caseId, targetKey, EvidenceSource.URLSCAN, EvidenceCode.APK_DOWNLOAD_UNOFFICIAL, ProviderId.URLSCAN)
            }
        }
        if (urlscan.forms.isNotEmpty()) {
            addSignal(signals, caseId, targetKey, EvidenceSource.URLSCAN, EvidenceCode.SENSITIVE_FORM_UNOFFICIAL, ProviderId.URLSCAN)
        } else if (urlscan.status == "SUCCESS" && !urlscan.verdict.isDangerousUrlscanVerdict()) {
            addSignal(signals, caseId, targetKey, EvidenceSource.URLSCAN, EvidenceCode.NO_SENSITIVE_FORM, ProviderId.URLSCAN)
        }

        if (webRisk.threats.isEmpty() && webRisk.status == "SUCCESS") {
            addSignal(signals, caseId, targetKey, EvidenceSource.GOOGLE_WEB_RISK, EvidenceCode.WEBRISK_NO_MATCH, ProviderId.WEB_RISK)
        } else {
            webRisk.threats.forEach { threat ->
                when (threat.uppercase(Locale.US)) {
                    "MALWARE" -> addSignal(signals, caseId, targetKey, EvidenceSource.GOOGLE_WEB_RISK, EvidenceCode.WEBRISK_MATCH_MALWARE, ProviderId.WEB_RISK)
                    "SOCIAL_ENGINEERING", "PHISHING" ->
                        addSignal(signals, caseId, targetKey, EvidenceSource.GOOGLE_WEB_RISK, EvidenceCode.WEBRISK_MATCH_SOCIAL_ENGINEERING, ProviderId.WEB_RISK)
                    "UNWANTED_SOFTWARE" ->
                        addSignal(signals, caseId, targetKey, EvidenceSource.GOOGLE_WEB_RISK, EvidenceCode.WEBRISK_MATCH_UNWANTED_SOFTWARE, ProviderId.WEB_RISK)
                }
            }
        }

        val malicious = virusTotal.stats?.malicious ?: 0
        val suspicious = virusTotal.stats?.suspicious ?: 0
        if (virusTotal.status == "SUCCESS") {
            if (malicious >= 5 || malicious + suspicious >= 8) {
                addSignal(signals, caseId, targetKey, EvidenceSource.PHISHING_DATABASE, EvidenceCode.PHISHING_DATABASE_LISTED, ProviderId.PHISHING_DATABASE)
            } else {
                addSignal(signals, caseId, targetKey, EvidenceSource.PHISHING_DATABASE, EvidenceCode.PHISHING_DATABASE_NOT_LISTED, ProviderId.PHISHING_DATABASE)
            }
        }
    }

    private fun addUrlscanVerdictSignals(signals: MutableList<EvidenceSignal>, caseId: String, targetKey: String, rawVerdict: String?) {
        when (rawVerdict.orEmpty().uppercase(Locale.US)) {
            "MALICIOUS", "MALICIOUS_PHISHING", "MALICIOUS_CARD_FORM", "MALICIOUS_OTP_FORM", "MALICIOUS_REDIRECT" ->
                addSignal(signals, caseId, targetKey, EvidenceSource.URLSCAN, EvidenceCode.URLSCAN_VERDICT_PHISHING, ProviderId.URLSCAN)
            "MALWARE" ->
                addSignal(signals, caseId, targetKey, EvidenceSource.URLSCAN, EvidenceCode.URLSCAN_VERDICT_MALWARE, ProviderId.URLSCAN)
            "CLEAN", "NO_VISIBLE_RISK", "NO_CLASSIFICATION" ->
                addSignal(signals, caseId, targetKey, EvidenceSource.URLSCAN, EvidenceCode.URLSCAN_NO_CLASSIFICATION, ProviderId.URLSCAN)
        }
    }

    private fun String?.isCleanUrlscanVerdict(): Boolean = when (this?.uppercase(Locale.US)) {
        "CLEAN", "NO_VISIBLE_RISK", "NO_CLASSIFICATION" -> true
        else -> false
    }

    private fun String?.isDangerousUrlscanVerdict(): Boolean = when (this?.uppercase(Locale.US)) {
        "MALICIOUS", "MALICIOUS_PHISHING", "MALICIOUS_CARD_FORM", "MALICIOUS_OTP_FORM", "MALICIOUS_REDIRECT", "MALWARE" -> true
        else -> false
    }

    private fun addPhishingDatabaseVerdictSignals(signals: MutableList<EvidenceSignal>, caseId: String, targetKey: String, rawVerdict: String?) {
        when (rawVerdict.orEmpty().uppercase(Locale.US)) {
            "MALICIOUS_HIGH" -> addSignal(signals, caseId, targetKey, EvidenceSource.PHISHING_DATABASE, EvidenceCode.PHISHING_DATABASE_LISTED, ProviderId.PHISHING_DATABASE)
            "LOW_ENGINE_HIT", "LOW", "CLEAN", "NOT_RUN" ->
                addSignal(signals, caseId, targetKey, EvidenceSource.PHISHING_DATABASE, EvidenceCode.PHISHING_DATABASE_NOT_LISTED, ProviderId.PHISHING_DATABASE)
        }
    }

    private fun addMappedSignals(signals: MutableList<EvidenceSignal>, rawName: String, caseId: String, targetKey: String) {
        mappedCodes(rawName).forEach { code ->
            addSignal(signals, caseId, targetKey, sourceFor(code), code, providerFor(sourceFor(code)))
        }
    }

    private fun mappedCodes(rawName: String): List<EvidenceCode> = when (rawName.uppercase(Locale.US)) {
        "WEB_RISK_NO_MATCH" -> listOf(EvidenceCode.WEBRISK_NO_MATCH)
        "WEB_RISK_MALWARE" -> listOf(EvidenceCode.WEBRISK_MATCH_MALWARE)
        "VT_MULTI_ENGINE_MALICIOUS" -> listOf(EvidenceCode.PHISHING_DATABASE_LISTED)
        "VT_SINGLE_OR_LOW_ENGINE_HIT" -> listOf(EvidenceCode.PHISHING_DATABASE_NOT_LISTED)
        "OFFICIAL_DOMAIN_EXACT_MATCH" -> listOf(EvidenceCode.OFFICIAL_DOMAIN_EXACT)
        "OFFICIAL_TRACKING_DOMAIN_MATCH" -> listOf(EvidenceCode.APPROVED_TRACKER_DOMAIN, EvidenceCode.TRACKING_ONLY_NO_PAYMENT)
        "OFFICIAL_DOMAIN_MISMATCH", "LOOKALIKE_DOMAIN", "PUNYCODE_OR_HOMOGLYPH" -> listOf(EvidenceCode.OFFICIAL_DOMAIN_MISMATCH)
        "CLAIMED_BRAND_IDENTIFIED", "PUBLIC_COMPANY_INVESTMENT_IMPERSONATION", "FINAL_URL_DIFFERS_FROM_DISPLAYED_BRAND" -> listOf(EvidenceCode.BRAND_IMPERSONATION)
        "HIDDEN_LINK", "DISPLAY_TEXT_HIDES_DIFFERENT_HREF" -> listOf(EvidenceCode.HIDDEN_LINK_PRESENT)
        "HIDDEN_LINK_TO_UNOFFICIAL_BRAND_DOMAIN", "BUTTON_LINK_DOMAIN_MISMATCH" -> listOf(EvidenceCode.HIDDEN_LINK_OFFICIAL_TO_UNOFFICIAL)
        "PRIMARY_URL_PICKER_CTA_OVER_FOOTER" -> listOf(EvidenceCode.HTML_BUTTON_LINK)
        "CARD_DATA_REQUEST", "FORM_CARD_DETECTED", "CARD_REQUIRED_TO_RECEIVE_MONEY" -> listOf(EvidenceCode.CARD_REQUEST)
        "CNP_OR_ID_REQUEST" -> listOf(EvidenceCode.CNP_IBAN_REQUEST)
        "FORM_PERSONAL_DATA_DETECTED" -> listOf(EvidenceCode.PERSONAL_DATA_REQUEST)
        "FORM_LOGIN_DETECTED", "PASSWORD_REQUEST" -> listOf(EvidenceCode.PASSWORD_REQUEST)
        "FORM_OTP_DETECTED", "OTP_REQUEST" -> listOf(EvidenceCode.OTP_REQUEST)
        "SANDBOX_CARD_FORM_ON_UNOFFICIAL_DOMAIN", "SANDBOX_OTP_FORM_ON_UNOFFICIAL_DOMAIN" -> listOf(EvidenceCode.SENSITIVE_FORM_UNOFFICIAL)
        "DELIVERY_SMALL_FEE_REQUEST" -> listOf(EvidenceCode.PARCEL_TAX, EvidenceCode.PAYMENT_REQUEST)
        "DELIVERY_ADDRESS_UPDATE_REQUEST", "DELIVERY_LOCKER_SELECTION_REQUEST" -> listOf(EvidenceCode.COURIER_UNOFFICIAL_DOMAIN)
        "COURIER_BRAND_CONTEXT", "DELIVERY_BRAND_CONTEXT" -> listOf(EvidenceCode.COURIER_UNOFFICIAL_DOMAIN)
        "REMOTE_ACCESS_APP_REQUEST" -> listOf(EvidenceCode.REMOTE_ACCESS_DOWNLOAD_UNOFFICIAL)
        "APK_DOWNLOAD", "INSTALL_APP_REQUEST" -> listOf(EvidenceCode.APK_DOWNLOAD_UNOFFICIAL)
        "WHATSAPP_VERIFICATION_CODE_REQUEST" -> listOf(EvidenceCode.WHATSAPP_CODE_REQUEST)
        "WHATSAPP_DEVICE_LINKING_REQUEST" -> listOf(EvidenceCode.WHATSAPP_DEVICE_LINKING_REQUEST)
        "FAMILY_NEW_NUMBER_CLAIM", "FAMILY_PHONE_BROKEN_CLAIM" -> listOf(EvidenceCode.FAMILY_NEW_PHONE_MONEY)
        "FAMILY_EMERGENCY_CLAIM" -> listOf(EvidenceCode.FAMILY_EMERGENCY_MONEY)
        "FAMILY_MONEY_REQUEST", "MONEY_REQUEST", "TRANSFER_TO_FRIEND_ACCOUNT" -> listOf(EvidenceCode.MONEY_REQUEST)
        "BANK_POLICE_BNR_HANDOFF", "SAFE_ACCOUNT_TRANSFER_REQUEST" -> listOf(EvidenceCode.BNR_SAFE_ACCOUNT)
        "OFFICIAL_AUTHORITY_CHAIN", "FRAUDULENT_CREDIT_CLAIM" -> listOf(EvidenceCode.FRAUDULENT_CREDIT_AUTHORITY_CHAIN)
        "MARKETPLACE_RECEIVE_MONEY_LINK" -> listOf(EvidenceCode.MARKETPLACE_RECEIVE_MONEY)
        "REPLY_REQUEST", "VOTE_CONTEST_HOOK", "PETITION_HOOK" -> listOf(EvidenceCode.REPLY_WITH_CODE_REQUEST)
        "URGENCY_LANGUAGE", "FEAR_OR_PRESSURE", "CONFIDENTIALITY_PRESSURE", "AVOIDS_VOICE_VERIFICATION", "KEEP_USER_ON_CALL_PRESSURE" -> listOf(EvidenceCode.MARKETING_URGENCY)
        "MARKETING_LANGUAGE", "PROMO_TEXT" -> listOf(EvidenceCode.PROMO_TEXT)
        "INVESTMENT_FAST_GAIN_PROMISE" -> listOf(EvidenceCode.MARKETING_URGENCY)
        "WITHDRAWAL_TAX_REQUEST", "LOTTERY_BONUS_DEPOSIT_REQUEST" -> listOf(EvidenceCode.PAYMENT_REQUEST)
        "NO_SENSITIVE_ASK", "SECURITY_EDUCATION", "BILLING_LANGUAGE", "SANDBOX_NO_VISIBLE_RISK" -> listOf(EvidenceCode.NO_SENSITIVE_FORM)
        "OTP_PRESENT_BUT_LEGIT_CONTEXT" -> listOf(EvidenceCode.NO_SENSITIVE_FORM, EvidenceCode.REPLY_WITH_CODE_REQUEST, EvidenceCode.OTP_REQUEST)
        "OCR_LOW_CONFIDENCE" -> listOf(EvidenceCode.OCR_LOW_CONFIDENCE)
        "WEBMAIL_SHELL_ONLY", "EMPTY_INPUT" -> listOf(EvidenceCode.WEBMAIL_SHELL_ONLY)
        "NO_PRIMARY_TARGET_URL", "URL_INCOMPLETE" -> listOf(EvidenceCode.NO_TARGET)
        "URL_SHORTENER" -> listOf(EvidenceCode.UNRESOLVED_SHORTLINK)
        "PII_REDACTION_UNSAFE", "QUERY_CONTAINS_TOKEN_OR_EMAIL", "MAGIC_LINK_TOKEN" -> listOf(EvidenceCode.PROVIDERS_UNAVAILABLE)
        "USER_SINGLE_REPORT", "USER_REPORT_FALSE_POSITIVE" -> listOf(EvidenceCode.USER_REPORT_UNVERIFIED)
        "HTTP_NOT_HTTPS", "NEW_OR_UNKNOWN_DOMAIN", "BRAND_NOT_IDENTIFIED", "SUSPICIOUS_TLD", "CRYPTO_ATM_QR_REQUEST", "FAKE_LEGITIMATION_DOCUMENT" -> listOf(EvidenceCode.NO_TARGET)
        else -> emptyList()
    }

    private fun sourceFor(code: EvidenceCode): EvidenceSource = when (code) {
        EvidenceCode.WEBRISK_MATCH_MALWARE,
        EvidenceCode.WEBRISK_MATCH_SOCIAL_ENGINEERING,
        EvidenceCode.WEBRISK_MATCH_UNWANTED_SOFTWARE,
        EvidenceCode.WEBRISK_MATCH_SOCIAL_ENGINEERING_EXT,
        EvidenceCode.WEBRISK_NO_MATCH -> EvidenceSource.GOOGLE_WEB_RISK
        EvidenceCode.URLSCAN_VERDICT_PHISHING,
        EvidenceCode.URLSCAN_VERDICT_MALWARE,
        EvidenceCode.URLSCAN_NO_CLASSIFICATION -> EvidenceSource.URLSCAN
        EvidenceCode.PHISHING_DATABASE_LISTED,
        EvidenceCode.PHISHING_DATABASE_NOT_LISTED -> EvidenceSource.PHISHING_DATABASE
        EvidenceCode.OFFICIAL_DOMAIN_EXACT,
        EvidenceCode.DELEGATED_DOMAIN_EXACT,
        EvidenceCode.APPROVED_TRACKER_DOMAIN,
        EvidenceCode.REDIRECT_CHAIN_APPROVED -> EvidenceSource.OFFICIAL_REGISTRY
        EvidenceCode.CORPUS_SIMILARITY,
        EvidenceCode.CORPUS_BRAND_WARNING -> EvidenceSource.CORPUS
        EvidenceCode.RAG_EXPLANATION -> EvidenceSource.RAG
        else -> EvidenceSource.LOCAL_EXTRACTOR
    }

    private fun providerFor(source: EvidenceSource): ProviderId? = when (source) {
        EvidenceSource.GOOGLE_WEB_RISK -> ProviderId.WEB_RISK
        EvidenceSource.URLSCAN -> ProviderId.URLSCAN
        EvidenceSource.PHISHING_DATABASE -> ProviderId.PHISHING_DATABASE
        EvidenceSource.OFFICIAL_REGISTRY -> ProviderId.OFFICIAL_REGISTRY
        EvidenceSource.CORPUS -> ProviderId.CORPUS
        EvidenceSource.RAG -> ProviderId.RAG
        else -> null
    }

    private fun addSignal(
        signals: MutableList<EvidenceSignal>,
        caseId: String,
        targetKey: String,
        source: EvidenceSource,
        code: EvidenceCode,
        provider: ProviderId? = null
    ) {
        signals += EvidenceSignal(
            id = "$caseId:${signals.size}:$code",
            source = source,
            code = code,
            targetKey = targetKey,
            provider = provider,
            observedAtMillis = 1_000L
        )
    }

    private fun completeness(states: Map<ProviderId, ProviderState>, shouldSubmitExternal: Boolean): EvidenceCompleteness {
        if (!shouldSubmitExternal) return EvidenceCompleteness.LOCAL_ONLY
        if (states.values.any { it.status in setOf(ProviderStatus.ERROR, ProviderStatus.TIMEOUT, ProviderStatus.RATE_LIMITED, ProviderStatus.SKIPPED) }) {
            return EvidenceCompleteness.PARTIAL_ONLINE
        }
        return if (states.values.any { it.status == ProviderStatus.OK }) EvidenceCompleteness.FULL else EvidenceCompleteness.LOCAL_ONLY
    }

    private fun validateRefs(root: File, caseId: String, refs: List<String>, failures: MutableList<FailureDetail>) {
        refs.filter { it.isNotBlank() }.forEach { ref ->
            if (!root.resolve(ref).isFile) {
                failures += FailureDetail(
                    caseId = caseId,
                    expected = GateAction.INSUFFICIENT_EVIDENCE,
                    actual = GateAction.DO_NOT_CONTINUE,
                    reasons = listOf("MISSING_REF:$ref"),
                    signals = emptyList()
                )
            }
        }
    }

    private inline fun <reified T> loadJsonList(file: File): List<T> {
        assertTrue("Missing fixture index: ${file.absolutePath}", file.isFile)
        val type = object : TypeToken<List<T>>() {}.type
        return gson.fromJson(file.readText(), type)
    }

    private fun resolveFixtureRoot(): File {
        val args = InstrumentationRegistry.getArguments()
        val testContext = InstrumentationRegistry.getInstrumentation().context
        val targetContext = InstrumentationRegistry.getInstrumentation().targetContext
        val packagedFixtureRoot = targetContext.getExternalFilesDir("e2e")
            ?: File(targetContext.filesDir, "e2e")
        ensurePackagedFixtures(testContext.assets, packagedFixtureRoot)
        val candidates = listOfNotNull(
            args.getString("fixtureRoot")?.let(::File),
            packagedFixtureRoot,
            testContext.getExternalFilesDir("e2e"),
            targetContext.getExternalFilesDir("e2e"),
            File("/sdcard/Android/data/ro.sigurscan.app.test/files/e2e"),
            File("/sdcard/Android/data/ro.sigurscan.app/files/e2e")
        )
        return candidates.firstOrNull { it.resolve("sigurscan_e2e_fixtures_v1/test_cases.json").isFile }
            ?: candidates.first()
    }

    private fun ensurePackagedFixtures(assets: android.content.res.AssetManager, destination: File) {
        val v1Index = destination.resolve("sigurscan_e2e_fixtures_v1/test_cases.json")
        val v2Index = destination.resolve("sigurscan_e2e_fixtures_v2_realistic/test_cases.json")
        if (v1Index.isFile && v2Index.isFile) return

        destination.mkdirs()
        copyAssetTree(assets, "sigurscan_e2e_fixtures_v1", destination.resolve("sigurscan_e2e_fixtures_v1"))
        copyAssetTree(assets, "sigurscan_e2e_fixtures_v2_realistic", destination.resolve("sigurscan_e2e_fixtures_v2_realistic"))
    }

    private fun copyAssetTree(
        assets: android.content.res.AssetManager,
        assetPath: String,
        destination: File
    ) {
        val children = assets.list(assetPath).orEmpty()
        if (children.isEmpty()) {
            destination.parentFile?.mkdirs()
            assets.open(assetPath).use { input ->
                destination.outputStream().use { output -> input.copyTo(output) }
            }
            return
        }

        destination.mkdirs()
        children.forEach { child ->
            copyAssetTree(assets, "$assetPath/$child", destination.resolve(child))
        }
    }

    private fun String?.toProviderStatus(): ProviderStatus = when (this?.uppercase(Locale.US)) {
        "SUCCESS" -> ProviderStatus.OK
        "TIMEOUT" -> ProviderStatus.TIMEOUT
        "RATE_LIMITED", "429" -> ProviderStatus.RATE_LIMITED
        "UNAVAILABLE", "404" -> ProviderStatus.ERROR
        "SKIPPED_PRIVACY" -> ProviderStatus.SKIPPED
        "NOT_RUN" -> ProviderStatus.NOT_RUN
        else -> ProviderStatus.NOT_RUN
    }

    private fun hostOf(url: String?): String? {
        if (url.isNullOrBlank()) return null
        return runCatching { URI(url).host?.lowercase(Locale.US)?.removePrefix("www.") }.getOrNull()
    }

    private data class V1Case(
        val id: String,
        val group: String,
        @SerializedName("input_type") val inputType: String,
        @SerializedName("fixture_path") val fixturePath: String,
        @SerializedName("primary_url_expected") val primaryUrlExpected: String?,
        @SerializedName("expected_decision") val expectedDecision: String,
        @SerializedName("expected_signal_kinds") val expectedSignalKinds: List<String> = emptyList(),
        @SerializedName("provider_mock_path") val providerMockPath: String,
        @SerializedName("should_submit_external") val shouldSubmitExternal: Boolean,
        @SerializedName("policy_version") val policyVersion: String,
        @SerializedName("registry_version") val registryVersion: String
    )

    private data class V2Case(
        val id: String,
        val channel: String,
        val fixtureKinds: List<String> = emptyList(),
        val fixturePaths: List<String> = emptyList(),
        val expectedDecision: String,
        val brandClaimed: String? = null,
        val primaryUrl: String? = null,
        val expectedSignals: List<String> = emptyList(),
        val providerMocks: Map<String, String> = emptyMap(),
        val expectedSnapshotPath: String? = null
    )

    private data class V1ProviderMock(
        val providers: Map<String, V1ProviderPayload> = emptyMap()
    )

    private data class V1ProviderPayload(
        val status: String? = null,
        val result: String? = null,
        val verdict: String? = null,
        @SerializedName("final_url") val finalUrl: String? = null
    )

    private data class V2UrlscanMock(
        val status: String,
        val finalUrl: String? = null,
        val verdict: String? = null,
        val forms: List<String> = emptyList()
    )

    private data class V2WebRiskMock(
        val status: String,
        val threats: List<String> = emptyList()
    )

    private data class V2PhishingDatabaseMock(
        val status: String,
        val stats: V2PhishingDatabaseStats? = null
    )

    private data class V2PhishingDatabaseStats(
        val malicious: Int = 0,
        val suspicious: Int = 0
    )

    private data class FailureDetail(
        val caseId: String,
        val expected: GateAction,
        val actual: GateAction,
        val reasons: List<String>,
        val signals: List<EvidenceCode>
    )
}
