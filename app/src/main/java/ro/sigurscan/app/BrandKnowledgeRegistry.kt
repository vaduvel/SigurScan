package ro.sigurscan.app

enum class NeverAskFor {
    CARD_DATA,
    CVV,
    OTP_CODE,
    PIN_CODE,
    PASSWORD,
    CNP,
    IBAN,
    REMOTE_ACCESS,
    APK_INSTALL,
    SAFE_ACCOUNT_TRANSFER
}

data class BrandKnowledgeEntry(
    val id: String,
    val aliases: List<String>,
    val officialDomains: List<String>,
    val approvedTrackerDomains: Set<String> = emptySet(),
    val neverAskFor: Set<NeverAskFor> = emptySet(),
    val sourceRefs: List<String> = emptyList()
)

object BrandKnowledgeRegistry {
    private val commonMarketingTrackers = setOf("sng.link", "app.link", "branch.link", "bnc.lt")

    private val staticEntries: List<BrandKnowledgeEntry> = listOf(
        BrandKnowledgeEntry(
            id = "uber",
            aliases = listOf("uber", "uber eats", "ubereats"),
            officialDomains = listOf("uber.com", "uber.link", "ubereats.com"),
            approvedTrackerDomains = commonMarketingTrackers + "uber.link",
            sourceRefs = listOf("docs/OFFICIAL_DOMAINS_REGISTRY.md#uber")
        ),
        BrandKnowledgeEntry(
            id = "yoxo",
            aliases = listOf("yoxo", "buy-back yoxo", "buyback yoxo", "orange yoxo"),
            officialDomains = listOf("yoxo.ro", "buyback.yoxo.ro", "orange.ro"),
            sourceRefs = listOf("production-live-yoxo-sms")
        ),
        BrandKnowledgeEntry(
            id = "idroid",
            aliases = listOf("idroid", "service idroid", "reparatie idroid", "reparație idroid"),
            officialDomains = listOf("idroid.ro"),
            sourceRefs = listOf("production-live-idroid-sms")
        ),
        BrandKnowledgeEntry(
            id = "emag",
            aliases = listOf("emag", "eMAG"),
            officialDomains = listOf("emag.ro", "emag.delivery"),
            approvedTrackerDomains = commonMarketingTrackers + "emag.delivery",
            sourceRefs = listOf("docs/OFFICIAL_DOMAINS_REGISTRY.md#emag")
        ),
        BrandKnowledgeEntry(
            id = "fanCourier",
            aliases = listOf("fan courier", "fancourier", "fanbox", "awb"),
            officialDomains = listOf("fancourier.ro", "fanbox.ro", "fan-courier.ro", "selfawb.ro"),
            neverAskFor = setOf(NeverAskFor.CARD_DATA, NeverAskFor.CVV, NeverAskFor.OTP_CODE),
            sourceRefs = listOf(
                "docs/OFFICIAL_DOMAINS_REGISTRY.md#fan-courier",
                "docs/ROMANIA_SCAM_SCENARIO_CORPUS.md#surse-verificate"
            )
        ),
        BrandKnowledgeEntry(
            id = "postaRomana",
            aliases = listOf("posta romana", "poșta română", "posta", "poșta"),
            officialDomains = listOf("posta-romana.ro"),
            neverAskFor = setOf(NeverAskFor.CARD_DATA, NeverAskFor.CVV, NeverAskFor.PIN_CODE),
            sourceRefs = listOf("docs/OFFICIAL_DOMAINS_REGISTRY.md#posta-romana")
        ),
        BrandKnowledgeEntry(
            id = "anaf",
            aliases = listOf("anaf", "spv", "mfinante", "spatiul privat virtual", "spațiul privat virtual"),
            officialDomains = listOf("anaf.ro", "mfinante.gov.ro", "mfinante.ro"),
            neverAskFor = setOf(
                NeverAskFor.CARD_DATA,
                NeverAskFor.CVV,
                NeverAskFor.OTP_CODE,
                NeverAskFor.PASSWORD,
                NeverAskFor.PIN_CODE
            ),
            sourceRefs = listOf(
                "docs/OFFICIAL_DOMAINS_REGISTRY.md#anaf--ministerul-finantelor",
                "docs/gpt55-review/sonnet-extract.md#anaf-ca-regula-speciala"
            )
        ),
        BrandKnowledgeEntry(
            id = "revolut",
            aliases = listOf("revolut"),
            officialDomains = listOf("revolut.com", "revolut.me", "revolut.space"),
            neverAskFor = setOf(NeverAskFor.OTP_CODE, NeverAskFor.PASSWORD, NeverAskFor.PIN_CODE),
            sourceRefs = listOf("docs/OFFICIAL_DOMAINS_REGISTRY.md#bancar")
        ),
        BrandKnowledgeEntry(
            id = "cardAndBanks",
            aliases = listOf(
                "banca",
                "bcr",
                "ing",
                "bt",
                "banca transilvania",
                "george",
                "cont sigur",
                "raiffeisen",
                "brd",
                "cec",
                "cec bank",
                "cecbank"
            ),
            officialDomains = listOf(
                "ing.ro",
                "ing.com",
                "ingbusiness.ro",
                "bcr.ro",
                "george.bcr.ro",
                "bancatransilvania.ro",
                "btpay.ro",
                "neo-bt.ro",
                "neo.bancatransilvania.ro",
                "raiffeisen.ro",
                "smartmobile.raiffeisen.ro",
                "brd.ro",
                "youbrd.ro",
                "cec.ro",
                "cecbank.ro"
            ),
            neverAskFor = setOf(
                NeverAskFor.CARD_DATA,
                NeverAskFor.CVV,
                NeverAskFor.OTP_CODE,
                NeverAskFor.PASSWORD,
                NeverAskFor.PIN_CODE,
                NeverAskFor.SAFE_ACCOUNT_TRANSFER,
                NeverAskFor.REMOTE_ACCESS
            ),
            sourceRefs = listOf(
                "docs/OFFICIAL_DOMAINS_REGISTRY.md#bancar",
                "docs/ROMANIA_SCAM_SCENARIO_CORPUS.md#bnr--banca--politie--cont-sigur"
            )
        ),
        BrandKnowledgeEntry(
            id = "remoteAccess",
            aliases = listOf("anydesk", "teamviewer", "remote access", "control la distanta", "control la distanță"),
            officialDomains = listOf("anydesk.com", "teamviewer.com"),
            sourceRefs = listOf("docs/OFFICIAL_DOMAINS_REGISTRY.md#remote-access-legitim")
        ),
        BrandKnowledgeEntry(
            id = "whatsapp",
            aliases = listOf("whatsapp", "wa.me"),
            officialDomains = listOf("whatsapp.com", "web.whatsapp.com", "wa.me", "whatsapp.net"),
            neverAskFor = setOf(NeverAskFor.OTP_CODE),
            sourceRefs = listOf(
                "docs/OFFICIAL_DOMAINS_REGISTRY.md#whatsapp",
                "docs/ROMANIA_SCAM_SCENARIO_CORPUS.md#surse-verificate"
            )
        ),
        BrandKnowledgeEntry(
            id = "google",
            aliases = listOf("google", "gmail", "youtube", "android"),
            officialDomains = listOf("google.com", "google.ro", "android.com", "developer.android.com", "youtube.com", "gmail.com"),
            sourceRefs = listOf("docs/OFFICIAL_DOMAINS_REGISTRY.md#google")
        ),
        BrandKnowledgeEntry(
            id = "marketplace",
            aliases = listOf("olx", "marketplace"),
            officialDomains = listOf("olx.ro"),
            neverAskFor = setOf(NeverAskFor.CARD_DATA, NeverAskFor.CVV, NeverAskFor.OTP_CODE),
            sourceRefs = listOf("docs/ROMANIA_SCAM_SCENARIO_CORPUS.md#marketplace--olx-style--primeste-banii")
        ),
        BrandKnowledgeEntry(
            id = "dnsc",
            aliases = listOf("dnsc", "siguranta online", "siguranța online"),
            officialDomains = listOf("dnsc.ro", "sigurantaonline.ro"),
            sourceRefs = listOf("docs/ROMANIA_SCAM_SCENARIO_CORPUS.md#surse-verificate")
        ),
        BrandKnowledgeEntry(
            id = "utilities",
            aliases = listOf(
                "hidroelectrica",
                "digi",
                "vodafone",
                "orange",
                "e.on",
                "eon",
                "ppc",
                "engie",
                "telekom",
                "enel",
                "e-distributie",
                "edistributie"
            ),
            officialDomains = listOf(
                "hidroelectrica.ro",
                "digi.ro",
                "vodafone.ro",
                "orange.ro",
                "eon.ro",
                "ppcenergy.ro",
                "engie.ro",
                "telekom.ro",
                "enel.ro",
                "e-distributie.com"
            ),
            sourceRefs = listOf("docs/ROMANIA_SCAM_SCENARIO_CORPUS.md#investitii-false--hidroelectrica--broker--cripto")
        ),
        BrandKnowledgeEntry(
            id = "paymentsGovernment",
            aliases = listOf("ghiseul", "ghiseul.ro", "ghiseul ro"),
            officialDomains = listOf("ghiseul.ro"),
            sourceRefs = listOf("docs/ACCEPTANCE_TESTS_ROMANIA.md")
        ),
        BrandKnowledgeEntry(
            id = "couriers",
            aliases = listOf("sameday", "easybox", "curier", "colet", "locker"),
            officialDomains = listOf("sameday.ro", "easybox.ro"),
            neverAskFor = setOf(NeverAskFor.CARD_DATA, NeverAskFor.CVV, NeverAskFor.OTP_CODE),
            sourceRefs = listOf("docs/ROMANIA_SCAM_SCENARIO_CORPUS.md#delivery-phishing")
        ),
        BrandKnowledgeEntry(
            id = "retail",
            aliases = listOf("altex", "media galaxy", "dedeman", "kaufland", "lidl", "carrefour", "ikea"),
            officialDomains = listOf("altex.ro", "mediagalaxy.ro", "dedeman.ro", "kaufland.ro", "lidl.ro", "carrefour.ro", "ikea.com"),
            approvedTrackerDomains = commonMarketingTrackers,
            sourceRefs = listOf("docs/E2E_FIXTURE_PACK_V2_PREP.md")
        )
    )

    val entries: List<BrandKnowledgeEntry>
        get() = SigurScanKnowledgePack.entries(staticEntries)

    val trustedOfficialDomains: Map<String, List<String>>
        get() = entries.associate { it.id to it.officialDomains }

    val approvedTrackerDomains: Set<String>
        get() = entries.flatMap { it.approvedTrackerDomains }.map(::normalizeDomain).toSet() +
            setOf("safelinks.protection.outlook.com", "urldefense.com")

    fun initialize(context: android.content.Context?) {
        SigurScanKnowledgePack.initialize(context)
    }

    fun registryVersion(): String = SigurScanKnowledgePack.registryVersion()

    fun corpusVersion(): String = SigurScanKnowledgePack.corpusVersion()

    fun findById(id: String): BrandKnowledgeEntry? = entries.firstOrNull { it.id == id }

    fun isOfficialHost(host: String): Boolean {
        val normalized = normalizeDomain(host)
        return trustedOfficialDomains.values.flatten().any { official ->
            normalized == normalizeDomain(official) || normalized.endsWith(".${normalizeDomain(official)}")
        }
    }

    fun isApprovedTrackerHost(host: String): Boolean {
        val normalized = normalizeDomain(host)
        return approvedTrackerDomains.any { tracker ->
            normalized == tracker || normalized.endsWith(".$tracker")
        }
    }

    fun normalizeDomain(domain: String): String {
        return domain
            .trim()
            .removePrefix("http://")
            .removePrefix("https://")
            .substringBefore("/")
            .substringBefore("?")
            .lowercase()
            .removePrefix("www.")
            .trimEnd('.')
    }
}
