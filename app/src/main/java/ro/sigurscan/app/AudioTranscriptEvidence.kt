package ro.sigurscan.app

import java.text.Normalizer
import java.util.Locale

object AudioTranscriptEvidence {
    fun analyze(rawTranscript: String): AudioEvidenceResult {
        val text = normalize(rawTranscript)
        if (text.isBlank()) {
            return AudioEvidenceEngine.evaluate(AudioEvidenceInput())
        }

        val sensitiveAsks = detectSensitiveAsks(text)
        val arcFamily = detectArcFamily(text, sensitiveAsks)
        val claimedIdentity = detectClaimedIdentity(text, arcFamily)
        val campaignConfidence = when (arcFamily) {
            "CONV_BANK_SAFE_ACCOUNT" -> 0.96
            "CONV_BANK_FRAUDULENT_CREDIT" -> 0.92
            "CONV_TECH_SUPPORT_REMOTE_ACCESS" -> 0.91
            "CONV_BANK_ANTI_FRAUD_CALL" -> 0.84
            "CONV_INVESTMENT_REMOTE_ACCESS" -> 0.90
            "CONV_FAMILY_EMERGENCY" -> 0.88
            "CONV_TRUSTED_CONTACT_MONEY_URGENCY" -> 0.91
            "CONV_AUTHORITY_IMPERSONATION_LEGAL_THREAT" -> 0.90
            "CONV_UTILITIES_DISCONNECTION_PAYMENT" -> 0.88
            "CONV_PRIZE_RELEASE_FEE" -> 0.87
            "CONV_TELECOM_OPERATOR_ACCOUNT_TAKEOVER" -> 0.86
            "CONV_DELIVERY_CUSTOMS_RELEASE_FEE" -> 0.86
            "CONV_REFUND_OVERPAYMENT_REVERSAL" -> 0.89
            "CONV_JOB_TASK_ADVANCE_PAYMENT" -> 0.89
            "CONV_RECOVERY_SCAM" -> 0.91
            "CONV_VOICE_CLONE_EMERGENCY_IMPERSONATION" -> 0.91
            "CONV_MARKETPLACE_RECEIVE_MONEY" -> 0.90
            else -> 0.0
        }

        return AudioEvidenceEngine.evaluate(
            AudioEvidenceInput(
                transcriptRedacted = "[redactat]",
                claimedIdentity = claimedIdentity,
                sensitiveAsks = sensitiveAsks,
                arcFamily = arcFamily,
                campaignMatch = arcFamily?.lowercase(Locale.US),
                campaignConfidence = campaignConfidence
            )
        )
    }

    private fun detectSensitiveAsks(text: String): List<String> {
        val compact = text.replace(" ", "")
        val directInstruction = containsAny(
            text,
            "cititi mi",
            "comunicati",
            "spuneti mi",
            "dictati",
            "introduceti",
            "apasati",
            "confirmati acum",
            "transfera",
            "transferati",
            "trimite",
            "trimiteti",
            "depune",
            "depuneti",
            "platiti acum",
            "achitati acum"
        )
        val protectiveNoAsk = !directInstruction && containsAny(
            text,
            "nu va cerem",
            "nu cerem",
            "nu va trimitem",
            "nu trimitem",
            "nu va solicitam",
            "nu solicitam",
            "inchideti si sunati",
            "inchide si suna",
            "daca primiti apeluri",
            "daca primiti un apel",
            "verificati tranzactia in aplicatie",
            "verificati in aplicatie",
            "verificati statusul in aplicatia",
            "aplicatia oficiala",
            "site ul oficial",
            "numarul din aplicatie"
        )
        val asksForCode = Regex("""\bcod(?:ul)?\b""").containsMatchIn(text) &&
            !protectiveNoAsk &&
            containsAny(
                text,
                "confirmare",
                "anulare",
                "verificare",
                "primi",
                "primit",
                "mesaj",
                "sms",
                "pse mese",
                "cat suntem pe linie",
                "pe linie"
            )
        return buildSet {
            if (!protectiveNoAsk && (containsAny(text, "otp", "cod sms", "cod de verificare", "codul primit") || asksForCode)) add("otp")
            if (!protectiveNoAsk && containsAny(text, "cvv", "cvc", "datele cardului", "numarul cardului")) add("card")
            if (!protectiveNoAsk && containsAny(text, "parola", "password", "credentiale", "datele de acces", "date de acces")) add("password")
            if (!protectiveNoAsk && Regex("""\bpin\b""").containsMatchIn(text)) add("pin")
            if (containsAny(text, "crypto", "cripto", "bitcoin", "atm crypto", "portofel cripto")) add("crypto")
            if (
                containsAny(
                    text,
                    "anydesk",
                    "teamviewer",
                    "remote access",
                    "control la distanta",
                    "aplicatie de suport",
                    "aplicatia de support",
                    "suport tehnic",
                    "support technic",
                    "diagnoza la distanta",
                    "instalati aplicatia",
                    "instalata aplicatia",
                    "aplicatia noastra"
                )
            ) {
                add("remote")
            }
            if (!protectiveNoAsk &&
                containsAny(
                    text,
                    "buletin",
                    "pasaport",
                    "carte de identitate",
                    "date personale",
                    "datele personale",
                    "confirmati identitatea",
                    "confirmati scuteva atate personale",
                    "numele dumneavoastra"
                )
            ) {
                add("id_document")
            }
            if (!protectiveNoAsk &&
                containsAny(
                    text,
                    "transfer",
                    "cont sigur",
                    "cont de siguranta",
                    "sa muti",
                    "sa mutati",
                    "sa depui",
                    "sa depuneti",
                    "sa retragi",
                    "sa retrageti",
                    "iban",
                    "bani",
                    "fonduri",
                    "fondurile",
                    "suma disponibila",
                    "cont temporar",
                    "cont nou",
                    "suma mica",
                    "depunere mica",
                    "economiile",
                    "banii",
                    "trimite bani",
                    "trimite mi bani",
                    "am nevoie de bani",
                    "imprumut",
                    "imprumuta",
                    "lei cash",
                    "euro cash"
                ) || (!protectiveNoAsk && containsAny(compact, "multibani", "mutibani", "mutibanii", "conttemporar", "sumaDisponibila".lowercase()))
            ) {
                add("transfer")
            }
            if (
                Regex("""\bsim\b""").containsMatchIn(text) &&
                containsAny(text, "portare", "portarea", "duplicat", "inlocuire", "reactivare", "activare", "schimb")
            ) {
                add("sim_swap")
            }
            if (containsAny(text, "cod client", "cod de client", "codul de client", "cod abonat")) {
                add("cod_client")
            }
            if (containsAny(text, "card cadou", "carduri cadou", "gift card", "voucher", "vouchere", "tichet valoric")) {
                add("gift_card")
            }
        }.toList()
    }

    private fun detectArcFamily(text: String, sensitiveAsks: List<String>): String? {
        val compact = text.replace(" ", "")
        val hasBank = containsAny(
            text,
            "banca",
            "bancii",
            "bunci",
            "buncii",
            "bansin",
            "bansii",
            "abunci",
            "panca",
            "bnr",
            "raiffeisen",
            "bcr",
            "cec bank",
            "brd",
            "revolut",
            "mobile banking",
            "departamentul anti frauda",
            "departamentul antifrauda",
            "departamentul anti fraude",
            "departamentul antifraude",
            "departamentul de securitate",
            "departamento de seguridad",
            "credit line",
            "creditline",
            "acreditline",
            "crediline"
        ) ||
            Regex("""\bbt\b|\bing\b""").containsMatchIn(text)
        val hasAuthority = containsAny(text, "politie", "politist", "inspector", "procuror", "anaf")
        val hasFamily = containsAny(text, "nepot", "nepoata", "fiul tau", "fiica ta", "mama", "tata", "unchiule")
        val hasEmergency = containsAny(text, "accident", "spital", "urgente", "am fost jefuit", "sunt la politie")
        val hasVoiceCloneEmergency = containsAny(text, "sunt eu", "vocea mea", "safe word", "cuvant de siguranta") &&
            (hasFamily || containsAny(text, "retinut", "retinuta", "inchisoare", "arest", "nu spune nimanui")) &&
            (hasEmergency || containsAny(text, "urgent", "urgenta", "nu spune nimanui", "te rog acum"))
        val hasInvestment = containsAny(
            text,
            "investitie",
            "actiuni",
            "profit garantat",
            "randament garantat",
            "broker",
            "consultant",
            "oportunitate",
            "portofel cripto"
        )
        val hasTechSupport = containsAny(
            text,
            "suport tehnic",
            "support technic",
            "suport technique",
            "diagnoza la distanta",
            "aplicatie de suport",
            "aplicatia de support",
            "instalati aplicatia",
            "instalata aplicatia"
        )
        val hasTrustedContact = containsAny(
            text,
            "coleg",
            "colega",
            "prieten",
            "prietena",
            "seful tau",
            "sefa ta",
            "sef",
            "sefa",
            "vecin",
            "vecina",
            "cunoscut",
            "cunostinta"
        )
        val hasUrgency = containsAny(
            text,
            "urgent",
            "urgenta",
            "acum",
            "repede",
            "imediat",
            "azi",
            "rapid",
            "rapit",
            "pe final",
            "cat suntem pe linie",
            "in seara asta",
            "limitata in timp"
        )
        val hasSecrecy = containsAny(
            text,
            "nu spune",
            "nu zice",
            "nu suna",
            "ramane intre noi",
            "doar intre noi",
            "doar a intre noi",
            "confidential",
            "nu anunta",
            "sa nu afle"
        )
        val hasAntiFraudDepartment = containsAny(
            text,
            "anti frauda",
            "antifrauda",
            "anti fraude",
            "antifraude",
            "securitate",
            "seguridad",
            "suport tehnic",
            "support technic",
            "suport technique"
        )
        val hasTelecomIdentity = containsAny(
            text,
            "vodafone",
            "orange",
            "telekom",
            "digi mobil",
            "rcs rds",
            "operatorul dumneavoastra",
            "operatorul tau",
            "operator de telefonie",
            "compania de telefonie",
            "abonamentul",
            "ancom"
        ) || Regex("""\boperator\b|\boparator\b""").containsMatchIn(text)
        val telecomPretext = containsAny(
            text,
            "fidelizare",
            "fidelitate",
            "beneficii",
            "benificii",
            "puncte de fidelitate",
            "verificarea unor plati",
            "factura restanta",
            "restanta la abonament",
            "reabonare",
            "oferta de loialitate",
            "portare",
            "portarea"
        ) || "sim_swap" in sensitiveAsks
        val hasUtilityIdentity = containsAny(
            text,
            "electrica",
            "enel",
            "e on",
            "eon",
            "engie",
            "ppc",
            "distrigaz",
            "hidroelectrica",
            "furnizor de energie",
            "furnizorul de energie",
            "furnizorul de gaz",
            "gaze naturale",
            "energie electrica"
        )
        val utilityPretext = containsAny(
            text,
            "deconectare",
            "deconectarea",
            "deconectaria",
            "debransare",
            "debransarea",
            "sold restant",
            "soldu restant",
            "neplata",
            "neplatii",
            "intrerupere",
            "sistare",
            "reconectare",
            "reconectaria",
            "alimentarea poate fi stopata"
        )
        val hasCourierIdentity = containsAny(
            text,
            "curier",
            "curierat",
            "coletul",
            "colet",
            "coletu",
            "posta romana",
            "fan courier",
            "fancourier",
            "sameday",
            "cargus",
            "expediere",
            "livrarea"
        )
        val deliveryPretext = containsAny(
            text,
            "vama",
            "vamala",
            "vamale",
            "taxa vamala",
            "taxe vamale",
            "fama",
            "adresa incorecta",
            "adresa gresita",
            "deblocare",
            "taxa de deblocare",
            "suma simbolica",
            "eroare de date",
            "erori de date",
            "eroare de dati",
            "actualizare date",
            "taxa suplimentara",
            "taxe suplimentare"
        )
        val hasPrizePretext = containsAny(
            text,
            "ati castigat",
            "ai castigat",
            "castigat un premiu",
            "ati fost selectat",
            "norocosul castigator",
            "loterie",
            "tombola",
            "tragere la sorti",
            "concurs cu premii",
            "premiul dumneavoastra",
            "un cadou"
        )
        val prizeReleaseFee = containsAny(
            text,
            "taxa de eliberare",
            "taxa de procesare",
            "cost de procesare",
            "taxa de livrare",
            "taxa de transport",
            "comision de eliberare"
        ) || "gift_card" in sensitiveAsks ||
            (
                containsAny(text, "premiu", "premii", "cadou") &&
                    (
                        containsAny(text, "taxa", "sa platiti", "achitati", "comision") ||
                            "card" in sensitiveAsks ||
                            "transfer" in sensitiveAsks
                        )
                )
        val hasAuthorityLegalIdentity = hasAuthority || containsAny(
            text,
            "anap",
            "antifrauda",
            "antifraude",
            "garda financiara",
            "politia",
            "parchet",
            "instanta",
            "tribunal",
            "judecatorie",
            "fisc",
            "administratia financiara"
        )
        val legalThreat = containsAny(
            text,
            "dosar",
            "dosar penal",
            "amenda",
            "ancheta",
            "verificare fiscala",
            "executare silita",
            "mandat",
            "proces verbal",
            "consecinte legale",
            "raspundere penala",
            "perchezitie",
            "citatie",
            "urmarire penala",
            "neregula fiscala"
        )
        val hasRefundOverpayment = containsAny(
            text,
            "rambursat prea mult",
            "rambursare prea mare",
            "v am dat prea mult",
            "v am virat o suma in plus",
            "returnati diferenta",
            "trimite inapoi diferenta",
            "departamentul de plati",
            "eroare de rambursare",
            "supraplata"
        )
        val hasRecoveryScam = containsAny(
            text,
            "recuperare fonduri",
            "recuperare bani",
            "recuperam banii",
            "firma de recuperare",
            "taxa in avans",
            "despagubire",
            "despagubiri",
            "garantam recuperarea",
            "banii pierduti",
            "avocatul firmei de recuperare"
        )
        val hasTaskJob = containsAny(
            text,
            "task uri",
            "task-uri",
            "tasc",
            "platforma de recrutare",
            "recrutare",
            "castigati bani",
            "castigi bani",
            "debloca task",
            "task urile mai bine platite",
            "deblochezi task uri",
            "depuneti o suma",
            "fake earnings",
            "comision"
        )
        val hasMarketplaceReceiveMoney = containsAny(
            text,
            "olx",
            "olex",
            "marketplace",
            "cumparator",
            "cumparatorul",
            "primesti banii",
            "sa primesti banii",
            "linkul de livrare",
            "link de livrare",
            "introdu datele cardului",
            "datele cardului ca sa primesti"
        )

        return when {
            hasMarketplaceReceiveMoney &&
                (
                    "card" in sensitiveAsks ||
                        "otp" in sensitiveAsks ||
                        containsAny(text, "link", "livrare", "datele cardului")
                    ) ->
                "CONV_MARKETPLACE_RECEIVE_MONEY"

            hasRecoveryScam &&
                (
                    "transfer" in sensitiveAsks ||
                        "card" in sensitiveAsks ||
                        containsAny(text, "taxa", "avans", "platiti")
                    ) ->
                "CONV_RECOVERY_SCAM"

            hasRefundOverpayment &&
                (
                    "transfer" in sensitiveAsks ||
                        "gift_card" in sensitiveAsks ||
                        "remote" in sensitiveAsks ||
                        containsAny(text, "returnati", "diferenta", "inapoi")
                    ) ->
                "CONV_REFUND_OVERPAYMENT_REVERSAL"

            hasTaskJob &&
                (
                    "transfer" in sensitiveAsks ||
                        "crypto" in sensitiveAsks ||
                        containsAny(text, "depune", "depuneti", "suma", "top up", "debloca")
                    ) ->
                "CONV_JOB_TASK_ADVANCE_PAYMENT"

            hasVoiceCloneEmergency &&
                (
                    "transfer" in sensitiveAsks ||
                        "gift_card" in sensitiveAsks ||
                        "crypto" in sensitiveAsks ||
                        hasSecrecy
                    ) ->
                "CONV_VOICE_CLONE_EMERGENCY_IMPERSONATION"

            containsAny(text, "cont sigur", "cont de siguranta") ||
                containsAny(compact, "contsigur", "consigur", "condsigur") ||
                (hasBank && "transfer" in sensitiveAsks && containsAny(text, "fonduri", "fondurile", "cont temporar", "siguranta")) ||
                (hasBank && hasAuthority && "transfer" in sensitiveAsks) ->
                "CONV_BANK_SAFE_ACCOUNT"

            containsAny(
                text,
                "credit fraudulos",
                "credit pe numele",
                "cerere de credit",
                "credit online",
                "credit pe cine",
                "credit avantajos",
                "credit aprobat",
                "preaprobat",
                "veste buna"
            ) &&
                (hasBank || hasAuthority || hasUrgency) ->
                "CONV_BANK_FRAUDULENT_CREDIT"

            "remote" in sensitiveAsks && (hasTechSupport || hasBank) ->
                "CONV_TECH_SUPPORT_REMOTE_ACCESS"

            hasTechSupport && hasBank ->
                "CONV_TECH_SUPPORT_REMOTE_ACCESS"

            hasBank && hasAntiFraudDepartment ->
                "CONV_BANK_ANTI_FRAUD_CALL"

            "remote" in sensitiveAsks && hasInvestment ->
                "CONV_INVESTMENT_REMOTE_ACCESS"

            "crypto" in sensitiveAsks && hasInvestment && (hasUrgency || hasSecrecy || "transfer" in sensitiveAsks) ->
                "CONV_INVESTMENT_REMOTE_ACCESS"

            hasFamily && hasEmergency && "transfer" in sensitiveAsks ->
                "CONV_FAMILY_EMERGENCY"

            hasTrustedContact && "transfer" in sensitiveAsks && (hasUrgency || hasSecrecy) ->
                "CONV_TRUSTED_CONTACT_MONEY_URGENCY"

            !hasBank && hasAuthorityLegalIdentity && legalThreat &&
                (
                    "id_document" in sensitiveAsks ||
                        "card" in sensitiveAsks ||
                        "transfer" in sensitiveAsks ||
                        "crypto" in sensitiveAsks ||
                        hasUrgency
                    ) ->
                "CONV_AUTHORITY_IMPERSONATION_LEGAL_THREAT"

            hasUtilityIdentity && utilityPretext &&
                (
                    "card" in sensitiveAsks ||
                        "transfer" in sensitiveAsks ||
                        "cod_client" in sensitiveAsks ||
                        hasUrgency ||
                        containsAny(text, "plateste acum", "plata imediata", "link de plata", "sa platiti")
                    ) ->
                "CONV_UTILITIES_DISCONNECTION_PAYMENT"

            hasPrizePretext && prizeReleaseFee ->
                "CONV_PRIZE_RELEASE_FEE"

            hasTelecomIdentity && telecomPretext &&
                (
                    "otp" in sensitiveAsks ||
                        "id_document" in sensitiveAsks ||
                        "transfer" in sensitiveAsks ||
                        "sim_swap" in sensitiveAsks ||
                        hasUrgency
                    ) ->
                "CONV_TELECOM_OPERATOR_ACCOUNT_TAKEOVER"

            hasCourierIdentity && deliveryPretext &&
                (
                    "card" in sensitiveAsks ||
                        "otp" in sensitiveAsks ||
                        "id_document" in sensitiveAsks ||
                        hasUrgency ||
                        containsAny(text, "taxa", "sa platiti", "achitati")
                    ) ->
                "CONV_DELIVERY_CUSTOMS_RELEASE_FEE"

            else -> null
        }
    }

    private fun detectClaimedIdentity(text: String, arcFamily: String?): String? {
        return when {
            arcFamily == "CONV_VOICE_CLONE_EMERGENCY_IMPERSONATION" -> "familie"
            containsAny(text, "politie", "politist", "inspector", "procuror", "anaf") -> "autoritate"
            containsAny(
                text,
                "banca",
                "bancii",
                "bunci",
                "buncii",
                "panca",
                "bnr",
                "raiffeisen",
                "bcr",
                "cec bank",
                "brd",
                "revolut",
                "mobile banking",
                "credit line",
                "creditline",
                "acreditline",
                "crediline"
            ) ||
                Regex("""\bbt\b|\bing\b""").containsMatchIn(text) -> "banca"

            arcFamily == "CONV_FAMILY_EMERGENCY" -> "familie"
            arcFamily == "CONV_TRUSTED_CONTACT_MONEY_URGENCY" -> "contact_cunoscut"
            arcFamily == "CONV_TECH_SUPPORT_REMOTE_ACCESS" -> "suport_tehnic"
            arcFamily == "CONV_BANK_ANTI_FRAUD_CALL" -> "banca"
            arcFamily == "CONV_INVESTMENT_REMOTE_ACCESS" -> "consultant_investitii"
            arcFamily == "CONV_AUTHORITY_IMPERSONATION_LEGAL_THREAT" -> "autoritate"
            arcFamily == "CONV_TELECOM_OPERATOR_ACCOUNT_TAKEOVER" -> "operator_telecom"
            arcFamily == "CONV_UTILITIES_DISCONNECTION_PAYMENT" -> "furnizor_utilitati"
            arcFamily == "CONV_DELIVERY_CUSTOMS_RELEASE_FEE" -> "curier"
            arcFamily == "CONV_PRIZE_RELEASE_FEE" -> "organizator_premii"
            arcFamily == "CONV_REFUND_OVERPAYMENT_REVERSAL" -> "suport_refund"
            arcFamily == "CONV_JOB_TASK_ADVANCE_PAYMENT" -> "recrutor_task"
            arcFamily == "CONV_RECOVERY_SCAM" -> "recuperare_fonduri"
            arcFamily == "CONV_MARKETPLACE_RECEIVE_MONEY" -> "cumparator_marketplace"
            else -> null
        }
    }

    private fun containsAny(text: String, vararg needles: String): Boolean {
        return needles.any(text::contains)
    }

    private fun normalize(value: String): String {
        return Normalizer.normalize(value.lowercase(Locale.forLanguageTag("ro-RO")), Normalizer.Form.NFD)
            .replace(Regex("\\p{M}+"), "")
            .replace(Regex("[^a-z0-9 ]"), " ")
            .replace(Regex("\\s+"), " ")
            .trim()
    }
}
