package ro.sigurscan.app

import java.net.URI
import java.security.MessageDigest
import java.text.Normalizer
import java.util.Locale
import java.util.UUID

data class EvidenceNormalizerInput(
    val scanId: String = UUID.randomUUID().toString(),
    val inputKind: String,
    val channel: String,
    val rawText: String = "",
    val htmlContent: String? = null,
    val extractedLinks: List<String> = emptyList(),
    val primaryUrl: String? = null,
    val finalUrl: String? = null,
    val redirectChain: List<String> = emptyList(),
    val senderDomain: String? = null,
    val threatIntel: List<ThreatIntelSourceResult> = emptyList(),
    val providerStates: Map<ProviderId, ProviderState> = emptyMap(),
    val formActionUrl: String? = null,
    val backendEvidence: Map<String, Any>? = null,
    val backendReasons: List<String> = emptyList(),
    val completeness: EvidenceCompleteness? = null,
    val registryVersion: String = "local",
    val corpusVersion: String = "local",
    val virusTotalConfigured: Boolean = false
)

object EvidenceSignalNormalizer {
    private val brandPolicies: List<BrandPolicyLite>
        get() = BrandKnowledgeRegistry.entries.map { entry ->
            BrandPolicyLite(
                id = entry.id,
                aliases = entry.aliases,
                officialDomains = entry.officialDomains,
                approvedTrackerDomains = entry.approvedTrackerDomains
            )
        }

    private val allOfficialDomains: Set<String>
        get() = brandPolicies.flatMap { it.officialDomains }.map(::normalizeDomain).toSet()
    private val approvedTrackerDomains: Set<String>
        get() = BrandKnowledgeRegistry.approvedTrackerDomains
    private val shortenerDomains = setOf(
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "is.gd",
        "cutt.ly",
        "shorturl.at",
        "rebrand.ly"
    )

    fun buildSnapshot(input: EvidenceNormalizerInput): EvidenceSnapshot {
        val rawForAnalysis = listOfNotNull(input.rawText, input.htmlContent).joinToString("\n")
        val normalizedText = normalizeText(rawForAnalysis)
        val html = input.htmlContent ?: input.rawText.takeIf { looksLikeHtml(it) }
        val htmlLinks = html?.let { HtmlLinkExtractor.extractHtmlLinks(it) }.orEmpty()
        val textUrls = extractUrls(rawForAnalysis)
        val formActionUrls = html?.let { extractFormActionUrls(it) }.orEmpty()
        val allUrls = (input.extractedLinks + htmlLinks + textUrls + listOfNotNull(input.primaryUrl, input.finalUrl, input.formActionUrl))
            .mapNotNull(::normalizeUrl)
            .distinct()
        val normalizedRedirectChain = input.redirectChain.mapNotNull(::normalizeUrl)
        val normalizedFinal = normalizeUrl(input.finalUrl) ?: normalizedRedirectChain.lastOrNull()
        val normalizedPrimary = normalizeUrl(input.primaryUrl)
            ?: normalizedFinal?.takeIf { final -> allUrls.contains(final) }
            ?: PrimaryUrlPicker.pick(allUrls, rawForAnalysis).takeIf { it.isNotBlank() }
        val normalizedFormActionUrl = normalizeUrl(input.formActionUrl) ?: formActionUrls.firstOrNull()
        val normalizedFormActionHost = hostOf(normalizedFormActionUrl)
        val targetUrl = normalizedFinal ?: normalizedPrimary
        val primaryHost = hostOf(normalizedPrimary)
        val targetHost = hostOf(targetUrl)
        val claimedBrands = detectClaimedBrands(normalizedText, rawForAnalysis, allUrls)

        val builder = SignalBuilder(targetHost ?: textTargetKey(normalizedText))
        addLocalSignals(
            builder = builder,
            input = input,
            rawForAnalysis = rawForAnalysis,
            normalizedText = normalizedText,
            html = html,
            allUrls = allUrls,
            formActionUrl = normalizedFormActionUrl,
            formActionHost = normalizedFormActionHost,
            primaryHost = primaryHost,
            targetHost = targetHost,
            claimedBrands = claimedBrands
        )
        addBackendInfrastructureSignals(
            builder = builder,
            backendEvidence = input.backendEvidence,
            targetKey = targetHost ?: textTargetKey(normalizedText)
        )
        addScamKnowledgeSignals(
            builder = builder,
            rawForAnalysis = rawForAnalysis,
            normalizedText = normalizedText,
            allUrls = allUrls,
            formActionHost = normalizedFormActionHost,
            targetHost = targetHost,
            claimedBrands = claimedBrands
        )
        addThreatIntelSignals(builder, input.threatIntel, targetHost ?: textTargetKey(normalizedText))

        val providerStates = buildProviderStates(input, builder.signals)
        val completeness = input.completeness ?: inferCompleteness(
            finalUrl = normalizedFinal,
            providerStates = providerStates,
            signals = builder.signals
        )

        return EvidenceSnapshot(
            scanId = input.scanId,
            inputKind = input.inputKind,
            channel = input.channel,
            primaryUrl = normalizedPrimary,
            finalUrl = normalizedFinal,
            formActionUrl = normalizedFormActionUrl,
            formActionHost = normalizedFormActionHost,
            redirectChain = normalizedRedirectChain,
            senderDomain = input.senderDomain,
            claimedBrands = claimedBrands.map { it.id }.toSet(),
            signals = builder.signals,
            providerStates = providerStates,
            registryVersion = input.registryVersion.takeUnless { it == "local" } ?: BrandKnowledgeRegistry.registryVersion(),
            corpusVersion = input.corpusVersion.takeUnless { it == "local" } ?: BrandKnowledgeRegistry.corpusVersion(),
            completeness = completeness
        )
    }

    fun fromAssessment(
        inputKind: String,
        channel: String,
        assessment: OfflineAssessment,
        rawText: String = assessment.originalText,
        providerStates: Map<ProviderId, ProviderState> = emptyMap()
    ): EvidenceSnapshot {
        return buildSnapshot(
            EvidenceNormalizerInput(
                scanId = assessment.scanId,
                inputKind = inputKind,
                channel = channel,
                rawText = rawText,
                primaryUrl = assessment.redirectChain.firstOrNull() ?: assessment.finalUrl,
                finalUrl = assessment.finalUrl,
                redirectChain = assessment.redirectChain,
                threatIntel = assessment.threatIntel,
                providerStates = providerStates,
                completeness = if (assessment.finalUrl.isNullOrBlank()) null else EvidenceCompleteness.PARTIAL_ONLINE
            )
        )
    }

    private fun addLocalSignals(
        builder: SignalBuilder,
        input: EvidenceNormalizerInput,
        rawForAnalysis: String,
        normalizedText: String,
        html: String?,
        allUrls: List<String>,
        formActionUrl: String?,
        formActionHost: String?,
        primaryHost: String?,
        targetHost: String?,
        claimedBrands: List<BrandPolicyLite>
    ) {
        val effectiveTargetHost = formActionHost ?: targetHost
        val hasTarget = !effectiveTargetHost.isNullOrBlank()
        val targetIsOfficial = targetHost?.let(::isOfficialHost) == true
        val targetIsApprovedTracker = targetHost?.let(::isApprovedTrackerHost) == true
        val effectiveIsOfficial = effectiveTargetHost?.let(::isOfficialHost) == true
        val effectiveIsApprovedTracker = effectiveTargetHost?.let(::isApprovedTrackerHost) == true
        val primaryIsApprovedTracker = primaryHost?.let(::isApprovedTrackerHost) == true
        val sensitiveCodes = detectSensitiveCodes(normalizedText, allUrls)
        val hasCredentialOrIdentitySensitiveRisk = sensitiveCodes.any {
            it in setOf(
                EvidenceCode.CARD_REQUEST,
                EvidenceCode.CVV_REQUEST,
                EvidenceCode.OTP_REQUEST,
                EvidenceCode.PASSWORD_REQUEST,
                EvidenceCode.CNP_IBAN_REQUEST,
                EvidenceCode.PERSONAL_DATA_REQUEST
            )
        }
        if (!formActionUrl.isNullOrBlank()) {
            builder.add(
                source = EvidenceSource.HTML_EXTRACTOR,
                code = EvidenceCode.HTML_BUTTON_LINK,
                targetKey = formActionHost.orEmpty()
            )
        }

        if ((input.channel.contains("webmail", ignoreCase = true) || normalizedText.contains("webmail")) && allUrls.isEmpty()) {
            builder.add(EvidenceSource.LOCAL_EXTRACTOR, EvidenceCode.WEBMAIL_SHELL_ONLY)
        }

        if (!hasTarget && allUrls.isEmpty() && normalizedText.isBlank()) {
            builder.add(EvidenceSource.LOCAL_EXTRACTOR, EvidenceCode.NO_TARGET)
        }

        html?.takeIf { it.isNotBlank() }?.let { htmlContent ->
            if (looksLikeHtml(htmlContent)) {
                if (htmlContent.contains(Regex("(?is)<\\s*(a|button|form|input)\\b"))) {
                    builder.add(EvidenceSource.HTML_EXTRACTOR, EvidenceCode.HTML_BUTTON_LINK)
                }
                if (allUrls.isNotEmpty()) {
                    builder.add(EvidenceSource.HTML_EXTRACTOR, EvidenceCode.HIDDEN_LINK_PRESENT)
                }
                if (hasOfficialLookingTextToUnofficialHref(htmlContent, claimedBrands)) {
                    builder.add(EvidenceSource.HTML_EXTRACTOR, EvidenceCode.HIDDEN_LINK_OFFICIAL_TO_UNOFFICIAL)
                }
            }
        }

        if (allUrls.any { isTrackingUrl(it) }) {
            builder.add(EvidenceSource.HTML_EXTRACTOR, EvidenceCode.TRACKING_LINK)
        }

        if (primaryHost != null && isShortenerHost(primaryHost) && input.finalUrl.isNullOrBlank()) {
            builder.add(EvidenceSource.LOCAL_EXTRACTOR, EvidenceCode.UNRESOLVED_SHORTLINK, targetKey = primaryHost)
        }

        addMarketingSignals(builder, normalizedText)
        sensitiveCodes.forEach { builder.add(EvidenceSource.LOCAL_EXTRACTOR, it) }

        if (targetIsOfficial) {
            builder.add(EvidenceSource.OFFICIAL_REGISTRY, EvidenceCode.OFFICIAL_DOMAIN_EXACT, targetKey = targetHost.orEmpty())
        } else if (targetIsApprovedTracker) {
            builder.add(EvidenceSource.OFFICIAL_REGISTRY, EvidenceCode.APPROVED_TRACKER_DOMAIN, targetKey = targetHost.orEmpty())
        }

        if (primaryIsApprovedTracker) {
            builder.add(EvidenceSource.OFFICIAL_REGISTRY, EvidenceCode.APPROVED_TRACKER_DOMAIN, targetKey = primaryHost.orEmpty())
        }

        if (primaryIsApprovedTracker && targetIsOfficial) {
            builder.add(EvidenceSource.OFFICIAL_REGISTRY, EvidenceCode.REDIRECT_CHAIN_APPROVED, targetKey = targetHost.orEmpty())
        }

        addLocalDomainRiskSignals(
            builder = builder,
            targetHost = effectiveTargetHost,
            claimedBrands = claimedBrands,
            targetIsOfficial = effectiveIsOfficial,
            targetIsApprovedTracker = effectiveIsApprovedTracker
        )

        if (hasTarget && (!hasCredentialOrIdentitySensitiveRisk || targetIsOfficial || effectiveIsOfficial) && !hasSensitiveForm(rawForAnalysis)) {
            builder.add(EvidenceSource.LOCAL_EXTRACTOR, EvidenceCode.NO_SENSITIVE_FORM)
        }

        if (hasSensitiveForm(rawForAnalysis) && !effectiveIsOfficial && !effectiveIsApprovedTracker) {
            builder.add(EvidenceSource.LOCAL_EXTRACTOR, EvidenceCode.SENSITIVE_FORM_UNOFFICIAL)
            if (!formActionHost.isNullOrBlank() && claimedBrands.isNotEmpty()) {
                builder.add(
                    EvidenceSource.OFFICIAL_REGISTRY,
                    EvidenceCode.OFFICIAL_DOMAIN_MISMATCH,
                    targetKey = formActionHost
                )
            }
        }

        if (claimedBrands.isNotEmpty() && hasTarget) {
            val officialForClaim = claimedBrands.any { it.isOfficialHost(effectiveTargetHost.orEmpty()) }
            val delegatedForClaim = claimedBrands.any { it.isApprovedTrackerHost(effectiveTargetHost.orEmpty()) }
            if (officialForClaim) {
                builder.add(EvidenceSource.OFFICIAL_REGISTRY, EvidenceCode.OFFICIAL_DOMAIN_EXACT, targetKey = effectiveTargetHost.orEmpty())
            } else if (delegatedForClaim) {
                builder.add(EvidenceSource.OFFICIAL_REGISTRY, EvidenceCode.DELEGATED_DOMAIN_EXACT, targetKey = effectiveTargetHost.orEmpty())
            } else if (!effectiveIsApprovedTracker) {
                builder.add(EvidenceSource.LOCAL_EXTRACTOR, EvidenceCode.BRAND_IMPERSONATION)
                builder.add(EvidenceSource.LOCAL_EXTRACTOR, EvidenceCode.OFFICIAL_DOMAIN_MISMATCH, targetKey = effectiveTargetHost.orEmpty())
            }
        }

        if (isCourierClaim(normalizedText) && hasTarget && !effectiveIsOfficial && !effectiveIsApprovedTracker) {
            builder.add(EvidenceSource.ROMANIA_SCENARIO, EvidenceCode.COURIER_UNOFFICIAL_DOMAIN)
        }
        if (containsAny(normalizedText, "colet", "locker", "awb", "livrare", "curier") &&
            containsAny(normalizedText, "taxa", "taxă", "plata", "plată", "ramburs") &&
            hasTarget) {
            builder.add(EvidenceSource.ROMANIA_SCENARIO, EvidenceCode.PARCEL_TAX)
        }
        if (containsAny(normalizedText, "anaf", "spv", "impozit", "taxa", "taxă", "rambursare")) {
            builder.add(EvidenceSource.ROMANIA_SCENARIO, EvidenceCode.TAX_NOTICE)
        }
        if (containsAny(normalizedText, "cont suspendat", "contul suspendat", "deblocare cont", "account suspend")) {
            builder.add(EvidenceSource.LOCAL_EXTRACTOR, EvidenceCode.ACCOUNT_SUSPEND)
        }
    }

    private fun addThreatIntelSignals(
        builder: SignalBuilder,
        threatIntel: List<ThreatIntelSourceResult>,
        targetKey: String
    ) {
        threatIntel.forEach { item ->
            val source = item.source.lowercase(Locale.US)
            val text = listOf(item.source, item.verdict, item.severity, item.details.orEmpty())
                .joinToString(" ")
                .lowercase(Locale.US)
            val sourceKey = providerSourceKey(item.source)
            when {
                sourceKey.contains("webrisk") -> mapWebRisk(builder, item, text, targetKey)
                source.contains("urlscan") -> mapUrlscan(builder, item, text, targetKey)
                source.contains("virustotal") || source == "vt" -> mapVirusTotal(builder, item, text, targetKey)
                sourceKey.contains("aiofferwebcheck") || sourceKey.contains("offerclaim") -> mapOfferClaimVerifier(builder, item, text, targetKey)
                sourceKey.contains("infrahomoglyph") || sourceKey.contains("infratyposquat") ||
                    sourceKey.contains("infradomainage") || sourceKey.contains("infraentropy") ||
                    sourceKey.contains("infrapunycode") || sourceKey.contains("infraurlbehaviour") ||
                    sourceKey.contains("infraurltransport") || sourceKey.contains("sigurscanlexical") -> mapInfraThreatIntel(builder, text, targetKey)
                sourceKey.contains("brandwarning") || sourceKey.contains("corpus") -> mapCorpus(builder, item, text, targetKey)
                sourceKey.contains("rag") -> mapRag(builder, item, text, targetKey)
            }
        }
    }

    private fun mapInfraThreatIntel(builder: SignalBuilder, text: String, targetKey: String) {
        if (containsAny(text, "punycode", "idn")) {
            builder.add(EvidenceSource.INFRA_ANALYZER, EvidenceCode.PUNYCODE_HOST, targetKey = targetKey, provider = ProviderId.INFRA)
        }
        if (containsAny(text, "homoglyph", "homogl")) {
            builder.add(EvidenceSource.INFRA_ANALYZER, EvidenceCode.HOMOGLYPH_DOMAIN, targetKey = targetKey, provider = ProviderId.INFRA)
        }
        if (containsAny(text, "typosquatting", "lookalike", "mismatch critic")) {
            builder.add(EvidenceSource.INFRA_ANALYZER, EvidenceCode.TYPOSQUAT_LOOKALIKE, targetKey = targetKey, provider = ProviderId.INFRA)
        }
        if (containsAny(text, "domain_age_days", "domeniu recent", "vechime de doar")) {
            val ageDays = Regex("""(?:domain_age_days|vechime(?:\s+de)?(?:\s+doar)?)\D+(\d{1,5})""")
                .find(text)
                ?.groupValues
                ?.getOrNull(1)
                ?.toIntOrNull()
            when {
                ageDays != null && ageDays < 7 -> builder.add(EvidenceSource.INFRA_ANALYZER, EvidenceCode.DOMAIN_AGE_VERY_RECENT, targetKey = targetKey, provider = ProviderId.INFRA)
                ageDays != null && ageDays < 30 -> builder.add(EvidenceSource.INFRA_ANALYZER, EvidenceCode.DOMAIN_AGE_SUSPICIOUS, targetKey = targetKey, provider = ProviderId.INFRA)
            }
        }
        if (containsAny(text, "entropie", "entropy", "dga")) {
            builder.add(EvidenceSource.INFRA_ANALYZER, EvidenceCode.DGA_ENTROPY_HIGH, targetKey = targetKey, provider = ProviderId.INFRA)
        }
        if (containsAny(text, "url_behaviour", "url behaviour")) {
            builder.add(EvidenceSource.INFRA_ANALYZER, EvidenceCode.URL_BEHAVIOUR_SUSPICIOUS, targetKey = targetKey, provider = ProviderId.INFRA)
        }
        if (containsAny(text, "url_transport", "url transport", "ip_hostname", "http necriptat")) {
            builder.add(EvidenceSource.INFRA_ANALYZER, EvidenceCode.URL_TRANSPORT_RISK, targetKey = targetKey, provider = ProviderId.INFRA)
        }
    }

    private fun mapWebRisk(builder: SignalBuilder, item: ThreatIntelSourceResult, text: String, targetKey: String) {
        if (containsAny(text, "no threats", "no threat", "no-match", "no match", "clean")) {
            builder.add(EvidenceSource.GOOGLE_WEB_RISK, EvidenceCode.WEBRISK_NO_MATCH, targetKey = targetKey, provider = ProviderId.WEB_RISK)
            return
        }

        val high = item.severity.equals("high", ignoreCase = true) || containsAny(text, "threats detected", "malware", "phishing", "social_engineering", "unwanted_software")

        if (text.contains("malware")) {
            builder.add(EvidenceSource.GOOGLE_WEB_RISK, EvidenceCode.WEBRISK_MATCH_MALWARE, targetKey = targetKey, provider = ProviderId.WEB_RISK)
        }
        if (text.contains("unwanted_software") || text.contains("unwanted software")) {
            builder.add(EvidenceSource.GOOGLE_WEB_RISK, EvidenceCode.WEBRISK_MATCH_UNWANTED_SOFTWARE, targetKey = targetKey, provider = ProviderId.WEB_RISK)
        }
        if (text.contains("social_engineering_extended") || text.contains("extended_coverage")) {
            builder.add(EvidenceSource.GOOGLE_WEB_RISK, EvidenceCode.WEBRISK_MATCH_SOCIAL_ENGINEERING_EXT, targetKey = targetKey, provider = ProviderId.WEB_RISK)
        }
        if (text.contains("social_engineering") || text.contains("phishing") || (high && !text.contains("malware"))) {
            builder.add(EvidenceSource.GOOGLE_WEB_RISK, EvidenceCode.WEBRISK_MATCH_SOCIAL_ENGINEERING, targetKey = targetKey, provider = ProviderId.WEB_RISK)
        }
    }

    private fun mapUrlscan(builder: SignalBuilder, item: ThreatIntelSourceResult, text: String, targetKey: String) {
        val high = item.severity.equals("high", ignoreCase = true)
        when {
            containsAny(text, "no malicious", "no classification", "clean", "low", "no threats") -> builder.add(EvidenceSource.URLSCAN, EvidenceCode.URLSCAN_NO_CLASSIFICATION, targetKey = targetKey, provider = ProviderId.URLSCAN)
            text.contains("malware") -> builder.add(EvidenceSource.URLSCAN, EvidenceCode.URLSCAN_VERDICT_MALWARE, targetKey = targetKey, provider = ProviderId.URLSCAN)
            text.contains("phishing") || text.contains("malicious") || high -> builder.add(EvidenceSource.URLSCAN, EvidenceCode.URLSCAN_VERDICT_PHISHING, targetKey = targetKey, provider = ProviderId.URLSCAN)
        }
    }

    private fun mapVirusTotal(builder: SignalBuilder, item: ThreatIntelSourceResult, text: String, targetKey: String) {
        val high = item.severity.equals("high", ignoreCase = true)
        val maliciousCount = Regex("""malicious\s*[=:]\s*(\d+)""").find(text)?.groupValues?.getOrNull(1)?.toIntOrNull() ?: 0
        when {
            maliciousCount >= 3 || (high && containsAny(text, "malicious", "suspicious")) -> {
                builder.add(EvidenceSource.VIRUSTOTAL, EvidenceCode.VIRUSTOTAL_MALICIOUS_CONSENSUS, targetKey = targetKey, provider = ProviderId.VIRUSTOTAL)
            }
            containsAny(text, "clean", "harmless", "undetected", "not found", "low") -> {
                builder.add(EvidenceSource.VIRUSTOTAL, EvidenceCode.VIRUSTOTAL_LOW_OR_NO_DETECTION, targetKey = targetKey, provider = ProviderId.VIRUSTOTAL)
            }
        }
    }

    private fun mapOfferClaimVerifier(builder: SignalBuilder, item: ThreatIntelSourceResult, text: String, targetKey: String) {
        when {
            containsAny(text, "confirmed", "official_source_found=true") -> {
                builder.add(EvidenceSource.CLAIM_VERIFIER, EvidenceCode.OFFER_CLAIM_CONFIRMED, targetKey = targetKey, provider = ProviderId.CLAIM_VERIFIER)
                if (claimListsTargetAsOfficial(text, targetKey)) {
                    builder.add(EvidenceSource.CLAIM_VERIFIER, EvidenceCode.OFFICIAL_DOMAIN_EXACT, targetKey = targetKey, provider = ProviderId.CLAIM_VERIFIER)
                }
            }
            containsAny(text, "not_found", "not found", "unconfirmed") -> {
                builder.add(EvidenceSource.CLAIM_VERIFIER, EvidenceCode.OFFER_CLAIM_NOT_FOUND, targetKey = targetKey, provider = ProviderId.CLAIM_VERIFIER)
            }
            else -> {
                builder.add(EvidenceSource.CLAIM_VERIFIER, EvidenceCode.OFFER_CLAIM_INCONCLUSIVE, targetKey = targetKey, provider = ProviderId.CLAIM_VERIFIER)
            }
        }
    }

    private fun mapCorpus(builder: SignalBuilder, item: ThreatIntelSourceResult, text: String, targetKey: String) {
        val brandId = Regex("""(?:brand|brand_id)\s*[=:]\s*([a-zA-Z0-9_-]+)""")
            .find(text)
            ?.groupValues
            ?.getOrNull(1)
        val attrs = item.details
            ?.takeIf { it.isNotBlank() }
            ?.let { mapOf("details" to it.take(240)) }
            .orEmpty()
        val code = if (containsAny(text, "brand_warning", "brand warning", "neveraskfor", "never ask for")) {
            EvidenceCode.CORPUS_BRAND_WARNING
        } else {
            EvidenceCode.CORPUS_SIMILARITY
        }
        builder.add(
            source = EvidenceSource.CORPUS,
            code = code,
            targetKey = targetKey,
            brandId = brandId,
            provider = ProviderId.CORPUS,
            attrs = attrs
        )
    }

    private fun mapRag(builder: SignalBuilder, item: ThreatIntelSourceResult, text: String, targetKey: String) {
        val attrs = item.details
            ?.takeIf { it.isNotBlank() }
            ?.let { mapOf("details" to it.take(240)) }
            .orEmpty()
        builder.add(
            source = EvidenceSource.RAG,
            code = EvidenceCode.RAG_EXPLANATION,
            targetKey = targetKey,
            provider = ProviderId.RAG,
            attrs = attrs + ("verdict" to item.verdict)
        )
    }

    private fun addScamKnowledgeSignals(
        builder: SignalBuilder,
        rawForAnalysis: String,
        normalizedText: String,
        allUrls: List<String>,
        formActionHost: String?,
        targetHost: String?,
        claimedBrands: List<BrandPolicyLite>
    ) {
        val effectiveTargetHost = formActionHost ?: targetHost
        val knowledgeSignals = ScamKnowledgeLayer.evaluate(
            ScamKnowledgeInput(
                rawText = rawForAnalysis,
                claimedBrandIds = claimedBrands.map { it.id }.toSet(),
                targetHost = effectiveTargetHost,
                targetIsOfficial = effectiveTargetHost?.let(::isOfficialHost) == true,
                targetIsApprovedTracker = effectiveTargetHost?.let(::isApprovedTrackerHost) == true,
                sensitiveCodes = detectSensitiveCodes(normalizedText, allUrls),
                hasSensitiveForm = hasSensitiveForm(rawForAnalysis),
                hasTarget = !effectiveTargetHost.isNullOrBlank()
            )
        )

        knowledgeSignals.forEach { signal ->
            builder.add(
                source = signal.source,
                code = signal.code,
                targetKey = signal.targetKey ?: effectiveTargetHost ?: textTargetKey(normalizedText),
                brandId = signal.brandId,
                provider = when (signal.source) {
                    EvidenceSource.CORPUS -> ProviderId.CORPUS
                    EvidenceSource.RAG -> ProviderId.RAG
                    else -> null
                },
                attrs = signal.attrs
            )
        }
    }

    private fun addBackendInfrastructureSignals(
        builder: SignalBuilder,
        backendEvidence: Map<String, Any>?,
        targetKey: String
    ) {
        if (backendEvidence.isNullOrEmpty()) return

        val extractedUrls = (backendEvidence["extracted_urls"] as? List<*>)
            ?.filterIsInstance<Map<*, *>>()
            .orEmpty()
        val youngestDomainAge = extractedUrls
            .mapNotNull { (it["domain_age_days"] as? Number)?.toInt() }
            .minOrNull()

        when {
            youngestDomainAge != null && youngestDomainAge < 7 -> builder.add(
                EvidenceSource.INFRA_ANALYZER,
                EvidenceCode.DOMAIN_AGE_VERY_RECENT,
                targetKey = targetKey,
                provider = ProviderId.INFRA
            )
            youngestDomainAge != null && youngestDomainAge < 30 -> builder.add(
                EvidenceSource.INFRA_ANALYZER,
                EvidenceCode.DOMAIN_AGE_SUSPICIOUS,
                targetKey = targetKey,
                provider = ProviderId.INFRA
            )
        }

        val urlBehaviour = backendEvidence["url_behaviour"] as? Map<*, *>
        if (!urlBehaviour.isNullOrEmpty() && urlBehaviour.values.any { value ->
                (value as? List<*>)?.isNotEmpty() == true
            }
        ) {
            builder.add(
                EvidenceSource.INFRA_ANALYZER,
                EvidenceCode.URL_BEHAVIOUR_SUSPICIOUS,
                targetKey = targetKey,
                provider = ProviderId.INFRA
            )
        }

        val urlTransport = backendEvidence["url_transport"] as? Map<*, *>
        if (!urlTransport.isNullOrEmpty()) {
            builder.add(
                EvidenceSource.INFRA_ANALYZER,
                EvidenceCode.URL_TRANSPORT_RISK,
                targetKey = targetKey,
                provider = ProviderId.INFRA
            )
        }
    }

    private fun addLocalDomainRiskSignals(
        builder: SignalBuilder,
        targetHost: String?,
        claimedBrands: List<BrandPolicyLite>,
        targetIsOfficial: Boolean,
        targetIsApprovedTracker: Boolean
    ) {
        val normalizedHost = targetHost?.let(::normalizeDomain).orEmpty()
        if (normalizedHost.isBlank() || targetIsOfficial || targetIsApprovedTracker) return

        if (normalizedHost.contains("xn--")) {
            builder.add(
                EvidenceSource.INFRA_ANALYZER,
                EvidenceCode.PUNYCODE_HOST,
                targetKey = normalizedHost,
                provider = ProviderId.INFRA
            )
        }

        val lookalike = findLookalikeDomainMatch(normalizedHost, claimedBrands.ifEmpty { brandPolicies }) ?: return

        if (lookalike.isHomoglyph) {
            builder.add(
                EvidenceSource.INFRA_ANALYZER,
                EvidenceCode.HOMOGLYPH_DOMAIN,
                targetKey = normalizedHost,
                brandId = lookalike.brand.id,
                provider = ProviderId.INFRA,
                attrs = mapOf("officialDomain" to lookalike.officialDomain)
            )
        }

        if (lookalike.isTyposquat) {
            builder.add(
                EvidenceSource.INFRA_ANALYZER,
                EvidenceCode.TYPOSQUAT_LOOKALIKE,
                targetKey = normalizedHost,
                brandId = lookalike.brand.id,
                provider = ProviderId.INFRA,
                attrs = mapOf(
                    "officialDomain" to lookalike.officialDomain,
                    "distance" to lookalike.distance.toString()
                )
            )
        }

        builder.add(
            EvidenceSource.INFRA_ANALYZER,
            EvidenceCode.BRAND_IMPERSONATION,
            targetKey = normalizedHost,
            brandId = lookalike.brand.id,
            provider = ProviderId.INFRA,
            attrs = mapOf("officialDomain" to lookalike.officialDomain)
        )
        builder.add(
            EvidenceSource.INFRA_ANALYZER,
            EvidenceCode.OFFICIAL_DOMAIN_MISMATCH,
            targetKey = normalizedHost,
            brandId = lookalike.brand.id,
            provider = ProviderId.INFRA,
            attrs = mapOf("officialDomain" to lookalike.officialDomain)
        )
    }

    private fun findLookalikeDomainMatch(
        host: String,
        candidates: List<BrandPolicyLite>
    ): DomainLookalikeMatch? {
        val normalizedHost = normalizeDomain(host)
        val rawLabel = brandishLabel(normalizedHost)
        if (rawLabel.length < 3) return null

        val deconfusedHost = normalizeDomain(replaceConfusableCharacters(normalizedHost))
        val deconfusedLabel = brandishLabel(deconfusedHost)
        val hasConfusableChange = deconfusedHost != normalizedHost

        return candidates
            .asSequence()
            .flatMap { brand ->
                brand.officialDomains.asSequence().mapNotNull { official ->
                    val normalizedOfficial = normalizeDomain(official)
                    if (normalizedOfficial.isBlank() ||
                        normalizedHost == normalizedOfficial ||
                        normalizedHost.endsWith(".$normalizedOfficial")
                    ) {
                        return@mapNotNull null
                    }

                    val officialLabel = brandishLabel(normalizedOfficial)
                    if (officialLabel.length < 3) return@mapNotNull null

                    val exactLabelMatchDifferentDomain = rawLabel == officialLabel && normalizedHost != normalizedOfficial
                    val prefixedBrandLabel = deconfusedLabel.startsWith(officialLabel)
                    val containedBrandLabel = deconfusedLabel.contains(officialLabel)
                    val distance = levenshteinDistance(deconfusedLabel, officialLabel)
                    val isHomoglyph = hasConfusableChange && (prefixedBrandLabel || containedBrandLabel || distance <= 1)
                    val isTyposquat = exactLabelMatchDifferentDomain || distance in 1..2

                    if (!isHomoglyph && !isTyposquat) return@mapNotNull null

                    DomainLookalikeMatch(
                        brand = brand,
                        officialDomain = normalizedOfficial,
                        distance = distance,
                        isHomoglyph = isHomoglyph,
                        isTyposquat = isTyposquat
                    )
                }
            }
            .sortedWith(
                compareBy<DomainLookalikeMatch> { if (it.isHomoglyph) 0 else 1 }
                    .thenBy { it.distance }
                    .thenBy { it.officialDomain.length }
            )
            .firstOrNull()
    }

    private fun claimListsTargetAsOfficial(text: String, targetKey: String): Boolean {
        val target = normalizeDomain(targetKey)
        if (target.isBlank()) return false
        val hasOfficialSource = containsAny(text, "official_source_found=true", "official source found", "official_domains")
        return hasOfficialSource && text.contains(target)
    }

    private fun addMarketingSignals(builder: SignalBuilder, normalizedText: String) {
        if (containsAny(normalizedText, "voucher", "card cadou", "premiu", "gratuit", "promo code", "cod promo")) {
            builder.add(EvidenceSource.LOCAL_EXTRACTOR, EvidenceCode.VOUCHER_TEXT)
        }
        if (containsAny(normalizedText, "promo", "promotie", "promoție", "oferta", "ofertă", "reducere", "discount")) {
            builder.add(EvidenceSource.LOCAL_EXTRACTOR, EvidenceCode.PROMO_TEXT)
        }
        if (containsAny(normalizedText, "nu rata", "ultima sansa", "ultima șansă", "expira azi", "expiră azi", "urgent", "imediat")) {
            builder.add(EvidenceSource.LOCAL_EXTRACTOR, EvidenceCode.MARKETING_URGENCY)
        }
        if (containsAny(normalizedText, "click", "apas", "apasă", "deschide", "vezi oferta", "continua", "continuă", "confirma", "confirmă")) {
            builder.add(EvidenceSource.LOCAL_EXTRACTOR, EvidenceCode.CTA_TEXT)
        }
    }

    private fun detectSensitiveCodes(normalizedText: String, urls: List<String>): Set<EvidenceCode> {
        val visibleText = normalizedText
            .replace(Regex("(?is)<\\s*(style|script)\\b.*?</\\s*\\1\\s*>"), " ")
            .replace(Regex("(?is)<[^>]+>"), " ")
        val combined = (visibleText + " " + urls.joinToString(" ")).lowercase(Locale.US)
        val output = linkedSetOf<EvidenceCode>()
        val sensitiveCardField = Regex("""(?i)\b(name|id|placeholder)\s*=\s*['"][^'"]*(card|numar[_-]?card|număr[_-]?card|cc-number)[^'"]*['"]""")
            .containsMatchIn(normalizedText)
        val sensitiveCvvField = Regex("""(?i)\b(name|id|placeholder)\s*=\s*['"][^'"]*(cvv|cvc|cvv2|security[_-]?code)[^'"]*['"]""")
            .containsMatchIn(normalizedText)
        val cardIsEducationalNegation = containsAny(
            combined,
            "nu introduce card",
            "nu introduceți card",
            "nu introduceti card",
            "nu iti cerem coduri",
            "nu îți cerem coduri",
            "nu va cerem coduri",
            "nu vă cerem coduri"
        )
        val cardRequestPattern = Regex("""(?i)(introdu|completeaz|confirm|valideaz|plat(e|ă)ste|pl(a|ă)t(e|ă)|spune|r(a|ă)spunde|trimite|tax(a|ă)|prime(s|ș)ti banii).{0,48}(card|num(a|ă)r card|date card)|(card|num(a|ă)r card|date card).{0,48}(cvv|cvc|pin|confirm|valideaz|plat(e|ă)ste|pl(a|ă)t(e|ă)|tax(a|ă))""")
        if (!cardIsEducationalNegation && (sensitiveCardField || cardRequestPattern.containsMatchIn(combined) || containsAny(combined, "numar card", "număr card", "date card"))) {
            output.add(EvidenceCode.CARD_REQUEST)
        }
        if (sensitiveCvvField || containsAny(combined, "cvv", "cvc", "cvv2")) output.add(EvidenceCode.CVV_REQUEST)
        if (containsAny(combined, "otp", "cod sms", "codul sms", "cod whatsapp", "codul whatsapp", "cod de verificare", "codul primit", "cod primit", "3d secure")) output.add(EvidenceCode.OTP_REQUEST)
        if (containsAny(combined, "parola", "parolă", "password", "pin bancar", "pin-ul", "pin ", "date de acces")) output.add(EvidenceCode.PASSWORD_REQUEST)
        if (containsAny(
                combined,
                "cnp",
                "iban",
                "date personale",
                "datele personale",
                "actualizare date",
                "actualizeaza date",
                "actualizează date",
                "completeaza datele",
                "completează datele",
                "completeaza nume",
                "completează nume",
                "nume, adresa",
                "nume, adresă",
                "telefon pentru livrare",
                "verificare identitate",
                "identitate bancara",
                "identitate bancară",
                "/date",
                "/confirmare"
            )
        ) output.add(EvidenceCode.CNP_IBAN_REQUEST)
        if (containsAny(combined, "plata", "plată", "plateste", "plătește", "payment", "checkout", "taxa", "taxă")) output.add(EvidenceCode.PAYMENT_REQUEST)
        return output
    }

    private fun hasSensitiveForm(raw: String): Boolean {
        val normalized = normalizeText(raw)
        val hasForm = raw.contains(Regex("(?is)<\\s*(form|input|textarea|select)\\b"))
        val hasSensitive = containsAny(
            normalized,
            "card",
            "cvv",
            "cvc",
            "otp",
            "parola",
            "parolă",
            "password",
            "iban",
            "cnp",
            "payment",
            "checkout",
            "plata",
            "plată"
        )
        return hasForm && hasSensitive
    }

    private fun hasOfficialLookingTextToUnofficialHref(html: String, claimedBrands: List<BrandPolicyLite>): Boolean {
        val anchorPattern = Regex("""(?is)<\s*(a|button)[^>]*(?:href|formaction|data-href|data-url)\s*=\s*(["'])(.*?)\2[^>]*>(.*?)</\s*\1\s*>""")
        anchorPattern.findAll(html).forEach { match ->
            val href = normalizeUrl(match.groupValues.getOrNull(3)) ?: return@forEach
            val visible = normalizeText(match.groupValues.getOrNull(4).orEmpty())
            val host = hostOf(href) ?: return@forEach
            val claimsOfficial = allOfficialDomains.any { visible.contains(it) } || claimedBrands.any { brand ->
                brand.aliases.any { visible.contains(normalizeText(it)) }
            }
            if (claimsOfficial && !isOfficialHost(host) && !isApprovedTrackerHost(host)) return true
        }

        val normalizedHtml = normalizeText(html)
        val mentionedOfficialDomain = allOfficialDomains.any { normalizedHtml.contains(it) }
        val hrefHosts = HtmlLinkExtractor.extractHtmlLinks(html).mapNotNull(::hostOf)
        return mentionedOfficialDomain && hrefHosts.any { !isOfficialHost(it) && !isApprovedTrackerHost(it) }
    }

    private fun detectClaimedBrands(
        normalizedText: String,
        rawForAnalysis: String,
        urls: List<String>
    ): List<BrandPolicyLite> {
        val normalizedRaw = normalizeText(rawForAnalysis)
        val normalizedHosts = urls
            .mapNotNull(::hostOf)
            .joinToString(" ") { host ->
                normalizeText(
                    host.replace('.', ' ')
                        .replace('-', ' ')
                        .replace('_', ' ')
                )
            }
        return brandPolicies.filter { policy ->
            policy.aliases.any { alias ->
                containsAlias(normalizedText, alias) ||
                    containsAlias(normalizedRaw, alias) ||
                    containsAlias(normalizedHosts, alias)
            }
        }
    }

    private fun containsAlias(text: String, alias: String): Boolean {
        val normalizedAlias = normalizeText(alias)
        if (normalizedAlias.isBlank()) return false
        if (normalizedAlias.length <= 3) {
            return Regex("""(?<![a-z0-9])${Regex.escape(normalizedAlias)}(?![a-z0-9])""").containsMatchIn(text)
        }
        return text.contains(normalizedAlias)
    }

    private fun buildProviderStates(
        input: EvidenceNormalizerInput,
        signals: List<EvidenceSignal>
    ): Map<ProviderId, ProviderState> {
        val states = mutableMapOf<ProviderId, ProviderState>()
        states.putAll(input.providerStates)
        listOf(ProviderId.WEB_RISK, ProviderId.URLSCAN, ProviderId.VIRUSTOTAL).forEach { provider ->
            if (states[provider] == null) {
                val hasSignal = signals.any { it.provider == provider }
                states[provider] = when {
                    hasSignal -> ProviderState(provider, ProviderStatus.OK)
                    provider == ProviderId.VIRUSTOTAL && !input.virusTotalConfigured -> ProviderState(provider, ProviderStatus.SKIPPED, note = "VirusTotal not configured")
                    else -> ProviderState(provider, ProviderStatus.NOT_RUN)
                }
            }
        }
        signals.mapNotNull { it.provider }.distinct().forEach { provider ->
            states.putIfAbsent(provider, ProviderState(provider, ProviderStatus.OK))
        }
        input.threatIntel.forEach { item ->
            val provider = providerForThreatIntel(item) ?: return@forEach
            states[provider] = ProviderState(provider, inferProviderStatus(item))
        }
        return states
    }

    private fun inferProviderStatus(item: ThreatIntelSourceResult): ProviderStatus {
        val text = listOf(item.verdict, item.severity, item.details.orEmpty()).joinToString(" ").lowercase(Locale.US)
        return when {
            containsAny(text, "pending", "queued", "in-progress", "in progress", "processing") -> ProviderStatus.PENDING
            containsAny(text, "rate limited", "429") -> ProviderStatus.RATE_LIMITED
            containsAny(text, "timeout", "timed out") -> ProviderStatus.TIMEOUT
            containsAny(text, "error", "unavailable", "failed") -> ProviderStatus.ERROR
            containsAny(text, "skipped", "not configured", "not run") -> ProviderStatus.SKIPPED
            else -> ProviderStatus.OK
        }
    }

    private fun inferCompleteness(
        finalUrl: String?,
        providerStates: Map<ProviderId, ProviderState>,
        signals: List<EvidenceSignal>
    ): EvidenceCompleteness {
        if (providerStates.values.any { it.status == ProviderStatus.PENDING }) return EvidenceCompleteness.PARTIAL_ONLINE
        if (finalUrl != null) return EvidenceCompleteness.FULL
        if (providerStates.values.any { it.status == ProviderStatus.OK }) return EvidenceCompleteness.PARTIAL_ONLINE
        if (signals.any { it.provider != null }) return EvidenceCompleteness.PARTIAL_ONLINE
        return EvidenceCompleteness.LOCAL_ONLY
    }

    private fun providerForThreatIntel(item: ThreatIntelSourceResult): ProviderId? {
        val source = item.source.lowercase(Locale.US)
        val sourceKey = providerSourceKey(item.source)
        return when {
            sourceKey.contains("webrisk") -> ProviderId.WEB_RISK
            source.contains("urlscan") -> ProviderId.URLSCAN
            source.contains("virustotal") || source == "vt" -> ProviderId.VIRUSTOTAL
            sourceKey.contains("aiofferwebcheck") || sourceKey.contains("offerclaim") -> ProviderId.CLAIM_VERIFIER
            sourceKey.contains("infrahomoglyph") || sourceKey.contains("infratyposquat") ||
                sourceKey.contains("infradomainage") || sourceKey.contains("infraentropy") ||
                sourceKey.contains("infrapunycode") || sourceKey.contains("infraurlbehaviour") ||
                sourceKey.contains("infraurltransport") || sourceKey.contains("sigurscanlexical") -> ProviderId.INFRA
            sourceKey.contains("brandwarning") || sourceKey.contains("corpus") -> ProviderId.CORPUS
            sourceKey.contains("rag") -> ProviderId.RAG
            else -> null
        }
    }

    private fun providerSourceKey(source: String): String {
        return source.lowercase(Locale.US).replace(Regex("[^a-z0-9]+"), "")
    }

    private fun extractUrls(input: String): List<String> {
        return UrlTextExtractor.extract(input)
    }

    private fun normalizeUrl(raw: String?): String? {
        if (raw.isNullOrBlank()) return null
        return HtmlLinkExtractor.normalizeCandidateUrl(raw) ?: UrlTextExtractor.normalizeCandidate(raw)
    }

    private fun hostOf(url: String?): String? {
        val normalized = normalizeUrl(url) ?: url ?: return null
        val parsedHost = runCatching {
            URI(normalized).host?.lowercase(Locale.US)?.removePrefix("www.")?.takeIf { it.isNotBlank() }
        }.getOrNull()
        if (!parsedHost.isNullOrBlank()) return parsedHost

        val authorityCandidate = normalized
            .substringAfter("://", normalized)
            .substringBefore('/')
            .substringBefore('?')
            .substringBefore('#')
            .substringAfterLast('@')
            .substringBefore(':')
            .lowercase(Locale.US)
            .removePrefix("www.")
            .trim()

        return authorityCandidate.takeIf { it.isNotBlank() }
    }

    private fun normalizeDomain(domain: String): String = domain.lowercase(Locale.US).removePrefix("www.")

    private fun isOfficialHost(host: String): Boolean {
        val normalized = normalizeDomain(host)
        return allOfficialDomains.any { normalized == it || normalized.endsWith(".$it") }
    }

    private fun isApprovedTrackerHost(host: String): Boolean {
        val normalized = normalizeDomain(host)
        return approvedTrackerDomains.any { normalized == it || normalized.endsWith(".$it") }
    }

    private fun isShortenerHost(host: String): Boolean {
        val normalized = normalizeDomain(host)
        return shortenerDomains.any { normalized == it || normalized.endsWith(".$it") }
    }

    private fun isTrackingUrl(url: String): Boolean {
        val host = hostOf(url) ?: return false
        val normalized = url.lowercase(Locale.US)
        return isApprovedTrackerHost(host) ||
            containsAny(normalized, "track", "tracking", "click", "utm_", "redirect", "safelinks")
    }

    private fun isCourierClaim(text: String): Boolean {
        return containsAny(text, "fan courier", "fancourier", "fanbox", "posta", "poșta", "curier", "colet", "awb", "locker")
    }

    private fun hasMoneyRequest(text: String): Boolean {
        return containsAny(text, "trimite bani", "transfer", "bani", "ron", "euro", "lei", "plata", "plată", "depunere")
    }

    private fun extractFormActionUrls(html: String): List<String> {
        if (html.isBlank()) return emptyList()
        val pattern = Regex("""(?i)<\s*(form|button|input)\b[^>]*\b(formaction|action)\s*=\s*(?:(['\"])(.*?)\3|([^\"'\s>]+))""")
        return pattern.findAll(html)
            .mapNotNull { match ->
                val raw = listOfNotNull(
                    match.groupValues.getOrNull(4),
                    match.groupValues.getOrNull(5)
                ).firstOrNull { it.isNotBlank() }
                normalizeUrl(raw)
            }
            .distinct()
            .toList()
    }

    private fun looksLikeHtml(value: String): Boolean {
        return value.contains(Regex("(?is)<\\s*(html|body|a|button|form|input|div|span|p|meta|script)\\b"))
    }

    private fun normalizeText(value: String): String {
        val deconfused = replaceConfusableCharacters(value)
        val decomposed = Normalizer.normalize(deconfused, Normalizer.Form.NFD)
        return decomposed
            .replace(Regex("\\p{Mn}+"), "")
            .lowercase(Locale.getDefault())
    }

    private fun replaceConfusableCharacters(value: String): String {
        if (value.isBlank()) return value
        return buildString(value.length) {
            value.forEach { ch ->
                append(
                    when (ch) {
                        'а' -> 'a'
                        'е' -> 'e'
                        'о' -> 'o'
                        'р' -> 'p'
                        'с' -> 'c'
                        'у' -> 'y'
                        'х' -> 'x'
                        'і' -> 'i'
                        'ј' -> 'j'
                        'к' -> 'k'
                        'м' -> 'm'
                        'т' -> 't'
                        'А' -> 'A'
                        'Е' -> 'E'
                        'О' -> 'O'
                        'Р' -> 'P'
                        'С' -> 'C'
                        'Υ' -> 'Y'
                        'Χ' -> 'X'
                        'І' -> 'I'
                        'Ј' -> 'J'
                        'Κ', 'К' -> 'K'
                        'Μ', 'М' -> 'M'
                        'Τ', 'Т' -> 'T'
                        'Β', 'В' -> 'B'
                        else -> ch
                    }
                )
            }
        }
    }

    private fun containsAny(value: String, vararg needles: String): Boolean {
        return needles.any { value.contains(normalizeText(it)) || value.contains(it.lowercase(Locale.getDefault())) }
    }

    private fun brandishLabel(host: String): String {
        return normalizeDomain(host)
            .substringBefore(".")
            .replace(Regex("[^a-z0-9]"), "")
    }

    private fun levenshteinDistance(left: String, right: String): Int {
        if (left == right) return 0
        if (left.isEmpty()) return right.length
        if (right.isEmpty()) return left.length

        val previous = IntArray(right.length + 1) { it }
        val current = IntArray(right.length + 1)

        left.forEachIndexed { i, leftChar ->
            current[0] = i + 1
            right.forEachIndexed { j, rightChar ->
                val cost = if (leftChar == rightChar) 0 else 1
                current[j + 1] = minOf(
                    current[j] + 1,
                    previous[j + 1] + 1,
                    previous[j] + cost
                )
            }
            current.copyInto(previous)
        }

        return previous[right.length]
    }

    private fun textTargetKey(normalizedText: String): String {
        return "text:${sha256(normalizedText.take(256))}"
    }

    private fun sha256(value: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(value.toByteArray())
        return digest.joinToString("") { "%02x".format(it) }.take(16)
    }

    private data class BrandPolicyLite(
        val id: String,
        val aliases: List<String>,
        val officialDomains: List<String>,
        val approvedTrackerDomains: Set<String> = emptySet()
    ) {
        fun isOfficialHost(host: String): Boolean {
            val normalizedHost = normalizeDomain(host)
            return officialDomains.map(::normalizeDomain).any { normalizedHost == it || normalizedHost.endsWith(".$it") }
        }

        fun isApprovedTrackerHost(host: String): Boolean {
            val normalizedHost = normalizeDomain(host)
            return approvedTrackerDomains.map(::normalizeDomain).any { normalizedHost == it || normalizedHost.endsWith(".$it") }
        }
    }

    private data class DomainLookalikeMatch(
        val brand: BrandPolicyLite,
        val officialDomain: String,
        val distance: Int,
        val isHomoglyph: Boolean,
        val isTyposquat: Boolean
    )

    private class SignalBuilder(private val defaultTargetKey: String) {
        private val mutableSignals = mutableListOf<EvidenceSignal>()
        val signals: List<EvidenceSignal> get() = mutableSignals

        fun add(
            source: EvidenceSource,
            code: EvidenceCode,
            targetKey: String = defaultTargetKey,
            brandId: String? = null,
            provider: ProviderId? = null,
            attrs: Map<String, String> = emptyMap()
        ) {
            val key = listOf(source.name, code.name, targetKey, brandId.orEmpty(), provider?.name.orEmpty()).joinToString("|")
            if (mutableSignals.any { it.attrs["dedupeKey"] == key }) return
            mutableSignals.add(
                EvidenceSignal(
                    id = "sig-${mutableSignals.size + 1}-${code.name.lowercase(Locale.US)}",
                    source = source,
                    code = code,
                    targetKey = targetKey,
                    brandId = brandId,
                    provider = provider,
                    attrs = attrs + ("dedupeKey" to key)
                )
            )
        }
    }
}
