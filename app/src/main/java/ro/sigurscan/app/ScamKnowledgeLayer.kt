package ro.sigurscan.app

import java.text.Normalizer
import java.util.Locale

data class ScamKnowledgeInput(
    val rawText: String,
    val claimedBrandIds: Set<String> = emptySet(),
    val targetHost: String? = null,
    val targetIsOfficial: Boolean = false,
    val targetIsApprovedTracker: Boolean = false,
    val sensitiveCodes: Set<EvidenceCode> = emptySet(),
    val hasSensitiveForm: Boolean = false,
    val hasTarget: Boolean = !targetHost.isNullOrBlank()
)

data class ScamKnowledgeSignal(
    val source: EvidenceSource,
    val code: EvidenceCode,
    val brandId: String? = null,
    val targetKey: String? = null,
    val attrs: Map<String, String> = emptyMap()
)

object ScamKnowledgeLayer {
    fun evaluate(input: ScamKnowledgeInput): List<ScamKnowledgeSignal> {
        val text = normalizeText(input.rawText)
        val signals = mutableListOf<ScamKnowledgeSignal>()
        addBrandWarningSignals(input, signals)
        addRomaniaCorpusSignals(input, text, signals)
        addPackScenarioSignals(input, text, signals)
        addPackClaimContextSignals(input, text, signals)
        return signals.distinctBy { listOf(it.source.name, it.code.name, it.brandId.orEmpty(), it.targetKey.orEmpty()).joinToString("|") }
    }

    private fun addBrandWarningSignals(input: ScamKnowledgeInput, signals: MutableList<ScamKnowledgeSignal>) {
        val requestedAssets = input.sensitiveCodes.flatMap(::neverAskForForEvidenceCode).toSet()
        if (requestedAssets.isEmpty()) return

        input.claimedBrandIds.forEach { brandId ->
            val entry = BrandKnowledgeRegistry.findById(brandId) ?: return@forEach
            val violated = entry.neverAskFor.intersect(requestedAssets)
            if (violated.isEmpty()) return@forEach

            val scenario = when {
                brandId == "fanCourier" && violated.any { it in setOf(NeverAskFor.OTP_CODE, NeverAskFor.CARD_DATA, NeverAskFor.CVV) } ->
                    "fan_courier_whatsapp_takeover"
                brandId == "marketplace" && violated.any { it in setOf(NeverAskFor.CARD_DATA, NeverAskFor.OTP_CODE) } ->
                    "marketplace_receive_money_card"
                else -> "brand_never_ask_for"
            }

            signals.add(
                ScamKnowledgeSignal(
                    source = EvidenceSource.CORPUS,
                    code = EvidenceCode.CORPUS_BRAND_WARNING,
                    brandId = brandId,
                    targetKey = input.targetHost,
                    attrs = mapOf(
                        "neverAskFor" to violated.joinToString(",") { it.name },
                        "scenario" to scenario,
                        "sourceRefs" to entry.sourceRefs.joinToString(",")
                    )
                )
            )
        }
    }

    private fun addRomaniaCorpusSignals(
        input: ScamKnowledgeInput,
        text: String,
        signals: MutableList<ScamKnowledgeSignal>
    ) {
        val brand = primaryBrand(input.claimedBrandIds, text)
        val targetIsUnofficial = input.hasTarget && !input.targetIsOfficial && !input.targetIsApprovedTracker

        if (isCourierClaim(text) && targetIsUnofficial) {
            signals.add(
                ScamKnowledgeSignal(
                    source = EvidenceSource.ROMANIA_SCENARIO,
                    code = EvidenceCode.COURIER_UNOFFICIAL_DOMAIN,
                    brandId = brand.takeIf { it in setOf("fanCourier", "postaRomana", "couriers") } ?: "couriers",
                    targetKey = input.targetHost,
                    attrs = mapOf("scenario" to courierScenario(input, text))
                )
            )
        }

        if (isParcelPaymentOrLockerSensitive(text, input)) {
            signals.add(
                ScamKnowledgeSignal(
                    source = EvidenceSource.ROMANIA_SCENARIO,
                    code = EvidenceCode.PARCEL_TAX,
                    brandId = brand.takeIf { it in setOf("fanCourier", "postaRomana", "couriers") } ?: "couriers",
                    targetKey = input.targetHost,
                    attrs = mapOf("scenario" to courierScenario(input, text))
                )
            )
        }

        if (containsAny(text, "anaf", "spv", "impozit", "taxa", "rambursare", "restituire")) {
            signals.add(
                ScamKnowledgeSignal(
                    source = EvidenceSource.ROMANIA_SCENARIO,
                    code = EvidenceCode.TAX_NOTICE,
                    brandId = "anaf",
                    targetKey = input.targetHost,
                    attrs = mapOf("scenario" to "anaf_tax_or_refund_claim")
                )
            )
        }

        if (containsAny(text, "cont suspendat", "contul suspendat", "deblocare cont", "account suspend")) {
            signals.add(
                ScamKnowledgeSignal(
                    source = EvidenceSource.ROMANIA_SCENARIO,
                    code = EvidenceCode.ACCOUNT_SUSPEND,
                    brandId = brand,
                    targetKey = input.targetHost,
                    attrs = mapOf("scenario" to "account_suspension")
                )
            )
        }

        if (isWhatsappSecretRequest(text)) {
            signals.add(
                ScamKnowledgeSignal(
                    source = EvidenceSource.ROMANIA_SCENARIO,
                    code = EvidenceCode.WHATSAPP_CODE_REQUEST,
                    brandId = "whatsapp",
                    targetKey = input.targetHost,
                    attrs = mapOf("scenario" to whatsappScenario(text))
                )
            )
        }

        if (isWhatsappPatternDiscovery(text) || isWhatsappSecretRequest(text)) {
            signals.add(
                ScamKnowledgeSignal(
                    source = EvidenceSource.CORPUS,
                    code = EvidenceCode.CORPUS_SIMILARITY,
                    brandId = "whatsapp",
                    targetKey = input.targetHost,
                    attrs = mapOf("scenario" to whatsappScenario(text), "sourceRefs" to "docs/ROMANIA_SCAM_SCENARIO_CORPUS.md")
                )
            )
        }

        if (containsAny(text, "whatsapp") && containsAny(text, "dispozitiv", "device", "linking", "asociere")) {
            signals.add(
                ScamKnowledgeSignal(
                    source = EvidenceSource.ROMANIA_SCENARIO,
                    code = EvidenceCode.WHATSAPP_DEVICE_LINKING_REQUEST,
                    brandId = "whatsapp",
                    targetKey = input.targetHost,
                    attrs = mapOf("scenario" to "whatsapp_device_linking")
                )
            )
        }

        if (containsAny(text, "telefon stricat", "mi s-a stricat telefonul", "numar nou") && hasMoneyRequest(text)) {
            signals.add(
                ScamKnowledgeSignal(
                    source = EvidenceSource.ROMANIA_SCENARIO,
                    code = EvidenceCode.FAMILY_NEW_PHONE_MONEY,
                    brandId = "family",
                    attrs = mapOf("scenario" to "telefon_stricat")
                )
            )
        }

        if (containsAny(text, "accident", "nepot", "fiul tau", "fiica ta", "spital") && hasMoneyRequest(text)) {
            signals.add(
                ScamKnowledgeSignal(
                    source = EvidenceSource.ROMANIA_SCENARIO,
                    code = EvidenceCode.ACCIDENT_NEPHEW_MONEY,
                    brandId = "family",
                    attrs = mapOf("scenario" to "accident_nepot")
                )
            )
        }

        if (containsAny(text, "bnr", "cont sigur", "cont de siguranta")) {
            signals.add(
                ScamKnowledgeSignal(
                    source = EvidenceSource.ROMANIA_SCENARIO,
                    code = EvidenceCode.BNR_SAFE_ACCOUNT,
                    brandId = "cardAndBanks",
                    attrs = mapOf("scenario" to "bnr_cont_sigur")
                )
            )
        }

        if (containsAny(text, "credit fraudulos", "credit pe numele", "politia", "politist") &&
            containsAny(text, "banca", "transfer", "cont sigur", "bnr", "date de acces")) {
            signals.add(
                ScamKnowledgeSignal(
                    source = EvidenceSource.ROMANIA_SCENARIO,
                    code = EvidenceCode.FRAUDULENT_CREDIT_AUTHORITY_CHAIN,
                    brandId = "cardAndBanks",
                    attrs = mapOf("scenario" to "credit_fraudulos_autoritate_banca")
                )
            )
        }

        if (containsAny(text, "ca sa primesti banii", "ca sa incasezi", "primeste banii", "incaseaza banii")) {
            signals.add(
                ScamKnowledgeSignal(
                    source = EvidenceSource.ROMANIA_SCENARIO,
                    code = EvidenceCode.MARKETPLACE_RECEIVE_MONEY,
                    brandId = "marketplace",
                    targetKey = input.targetHost,
                    attrs = mapOf("scenario" to "marketplace_receive_money_card")
                )
            )
        }

        if (containsAny(text, "anydesk", "teamviewer", "remote access", "control la distanta")) {
            signals.add(
                ScamKnowledgeSignal(
                    source = EvidenceSource.ROMANIA_SCENARIO,
                    code = EvidenceCode.REMOTE_ACCESS_DOWNLOAD_UNOFFICIAL,
                    brandId = brand,
                    targetKey = input.targetHost,
                    attrs = mapOf("scenario" to "remote_access_investment_or_support")
                )
            )
        }

        if (containsAny(text, "apk", "instaleaza aplicatia", "descarca aplicatia", "aplicatie bancara")) {
            signals.add(
                ScamKnowledgeSignal(
                    source = EvidenceSource.ROMANIA_SCENARIO,
                    code = EvidenceCode.APK_DOWNLOAD_UNOFFICIAL,
                    brandId = brand,
                    targetKey = input.targetHost,
                    attrs = mapOf("scenario" to "apk_or_sideload")
                )
            )
        }

        if (hasMoneyRequest(text)) {
            signals.add(
                ScamKnowledgeSignal(
                    source = EvidenceSource.ROMANIA_SCENARIO,
                    code = EvidenceCode.MONEY_REQUEST,
                    brandId = brand,
                    attrs = mapOf("scenario" to "money_request")
                )
            )
        }

        if (containsAny(text, "raspunde cu cod", "trimite codul", "spune codul", "comunica codul")) {
            signals.add(
                ScamKnowledgeSignal(
                    source = EvidenceSource.ROMANIA_SCENARIO,
                    code = EvidenceCode.REPLY_WITH_CODE_REQUEST,
                    brandId = brand,
                    attrs = mapOf("scenario" to "reply_with_secret_code")
                )
            )
        }
    }

    private fun neverAskForForEvidenceCode(code: EvidenceCode): Set<NeverAskFor> = when (code) {
        EvidenceCode.CARD_REQUEST -> setOf(NeverAskFor.CARD_DATA)
        EvidenceCode.CVV_REQUEST -> setOf(NeverAskFor.CVV)
        EvidenceCode.OTP_REQUEST -> setOf(NeverAskFor.OTP_CODE)
        EvidenceCode.PASSWORD_REQUEST -> setOf(NeverAskFor.PASSWORD)
        EvidenceCode.CNP_IBAN_REQUEST -> setOf(NeverAskFor.CNP, NeverAskFor.IBAN)
        EvidenceCode.REMOTE_ACCESS_DOWNLOAD_UNOFFICIAL -> setOf(NeverAskFor.REMOTE_ACCESS)
        EvidenceCode.APK_DOWNLOAD_UNOFFICIAL -> setOf(NeverAskFor.APK_INSTALL)
        else -> emptySet()
    }

    private fun addPackScenarioSignals(
        input: ScamKnowledgeInput,
        text: String,
        signals: MutableList<ScamKnowledgeSignal>
    ) {
        SigurScanKnowledgePack.scenarioCorpus().forEach { scenario ->
            val matched = scenario.typicalTextPatterns
                .map(::normalizeText)
                .filter { it.isNotBlank() && text.contains(it) }
                .distinct()
            val roleMatch = normalizeText(scenario.claimedBrandOrRole).takeIf { it.isNotBlank() }?.let { text.contains(it) } == true
            if (matched.size < 2 && !(roleMatch && matched.isNotEmpty())) return@forEach

            signals.add(
                ScamKnowledgeSignal(
                    source = EvidenceSource.CORPUS,
                    code = EvidenceCode.CORPUS_SIMILARITY,
                    brandId = primaryBrand(input.claimedBrandIds, text),
                    targetKey = input.targetHost ?: scenario.scenarioId,
                    attrs = mapOf(
                        "scenarioId" to scenario.scenarioId,
                        "family" to scenario.family,
                        "matchedPatterns" to matched.take(5).joinToString(","),
                        "maxWithoutProviderScan" to scenario.maxVerdictWithoutProviderScan.orEmpty(),
                        "maxWithProviderScan" to scenario.maxVerdictWithProviderScan.orEmpty()
                    )
                )
            )
        }
    }

    private fun addPackClaimContextSignals(
        input: ScamKnowledgeInput,
        text: String,
        signals: MutableList<ScamKnowledgeSignal>
    ) {
        SigurScanKnowledgePack.claimVerifierTargets().forEach { target ->
            val terms = claimTermsFor(target)
            val matched = terms.filter { text.contains(it) }.distinct()
            val sourceHosts = target.officialSources.mapNotNull { it.url?.let(::hostFromUrlLike) }.distinct()
            val targetMatchesOfficialSource = input.targetHost != null && sourceHosts.any { official ->
                input.targetHost == official || input.targetHost.endsWith(".$official")
            }
            if (matched.size < 2 && !targetMatchesOfficialSource) return@forEach

            signals.add(
                ScamKnowledgeSignal(
                    source = EvidenceSource.CORPUS,
                    code = EvidenceCode.CORPUS_SIMILARITY,
                    brandId = primaryBrand(input.claimedBrandIds, text),
                    targetKey = input.targetHost ?: target.claimType,
                    attrs = mapOf(
                        "claimType" to target.claimType,
                        "matchedTerms" to matched.take(6).joinToString(","),
                        "officialSources" to target.officialSources.mapNotNull { it.url }.take(4).joinToString(","),
                        "claimConfirmed" to target.claimConfirmed.orEmpty(),
                        "claimNotFound" to target.claimNotFound.orEmpty(),
                        "claimContextOnly" to "true"
                    )
                )
            )
        }
    }

    private fun claimTermsFor(target: ClaimVerifierTarget): List<String> {
        val rawTerms = buildList {
            add(target.claimType)
            addAll(target.claimType.split(Regex("[\\s/,-]+")))
            addAll(target.legitimateExamples)
            addAll(target.fakeExamples)
        }
        return rawTerms
            .flatMap { term ->
                val normalized = normalizeText(term).trim()
                listOf(normalized, normalized.replace("-", ""), normalized.replace(" ", ""))
            }
            .filter { it.length >= 3 }
            .distinct()
    }

    private fun hostFromUrlLike(value: String): String? {
        val normalized = value
            .trim()
            .removePrefix("http://")
            .removePrefix("https://")
            .substringBefore("/")
            .substringBefore("?")
            .lowercase(Locale.US)
            .removePrefix("www.")
            .trimEnd('.')
        return normalized.takeIf { it.contains(".") }
    }

    private fun primaryBrand(claimedBrandIds: Set<String>, text: String): String? {
        if (claimedBrandIds.isNotEmpty()) return claimedBrandIds.first()
        return when {
            isCourierClaim(text) -> "couriers"
            containsAny(text, "olx", "marketplace") -> "marketplace"
            containsAny(text, "whatsapp") -> "whatsapp"
            containsAny(text, "anaf", "spv") -> "anaf"
            containsAny(text, "bnr", "banca", "politia") -> "cardAndBanks"
            else -> null
        }
    }

    private fun courierScenario(input: ScamKnowledgeInput, text: String): String = when {
        containsAny(text, "whatsapp", "cod") || input.sensitiveCodes.contains(EvidenceCode.OTP_REQUEST) ->
            "fan_courier_whatsapp_takeover"
        containsAny(text, "posta", "adresa") -> "posta_taxa_livrare"
        else -> "delivery_locker_or_fee"
    }

    private fun isCourierClaim(text: String): Boolean {
        return containsAny(text, "fan courier", "fancourier", "fanbox", "posta romana", "posta", "curier", "colet", "awb", "locker", "sameday", "easybox", "cargus")
    }

    private fun isParcelPaymentOrLockerSensitive(text: String, input: ScamKnowledgeInput): Boolean {
        val hasDeliveryContext = containsAny(text, "colet", "locker", "awb", "livrare", "curier", "posta", "fan courier", "sameday", "easybox")
        val hasPaymentContext = containsAny(text, "taxa", "plata", "ramburs", "card", "cvv", "cod whatsapp") ||
            input.sensitiveCodes.any { it in setOf(EvidenceCode.CARD_REQUEST, EvidenceCode.CVV_REQUEST, EvidenceCode.OTP_REQUEST, EvidenceCode.PAYMENT_REQUEST) }
        return hasDeliveryContext && hasPaymentContext
    }

    private fun isWhatsappSecretRequest(text: String): Boolean {
        val educationalNegation = containsAny(
            text,
            "nu introduce coduri whatsapp",
            "nu trimite coduri whatsapp",
            "nu comunica coduri whatsapp",
            "nu da codul whatsapp"
        )
        if (educationalNegation) return false
        val hasWhatsappOrKnownHook = containsAny(text, "whatsapp", "dispozitiv", "device", "asociere", "linking")
        val explicitlyAsksForCode = containsAny(
            text,
            "cod whatsapp",
            "codul whatsapp",
            "cod de verificare",
            "codul de verificare",
            "codul primit",
            "cod primit",
            "cod sms",
            "otp",
            "confirma cu cod",
            "confirmă cu cod",
            "trimite cod",
            "spune cod"
        )
        return hasWhatsappOrKnownHook && explicitlyAsksForCode
    }

    private fun isWhatsappPatternDiscovery(text: String): Boolean {
        return containsAny(text, "voteaza pe adeline", "voteaza", "adeline", "petitie whatsapp", "petitie", "sondaj whatsapp")
    }

    private fun whatsappScenario(text: String): String = when {
        containsAny(text, "adeline", "voteaza") -> "whatsapp_voteaza_pe_adeline"
        containsAny(text, "petitie") -> "whatsapp_petitie_takeover"
        else -> "whatsapp_code_takeover"
    }

    private fun hasMoneyRequest(text: String): Boolean {
        return containsAny(text, "trimite bani", "transfer", "bani", "ron", "euro", "lei", "plata", "depunere")
    }

    private fun containsAny(value: String, vararg needles: String): Boolean {
        return needles.any { needle -> value.contains(normalizeText(needle)) }
    }

    private fun normalizeText(value: String): String {
        val decomposed = Normalizer.normalize(value, Normalizer.Form.NFD)
        return decomposed
            .replace(Regex("\\p{Mn}+"), "")
            .lowercase(Locale.getDefault())
    }
}
