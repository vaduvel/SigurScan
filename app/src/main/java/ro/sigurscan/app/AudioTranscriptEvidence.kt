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
        val asksForCode = Regex("""\bcod(?:ul)?\b""").containsMatchIn(text) &&
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
            if (containsAny(text, "otp", "cod sms", "cod de verificare", "codul primit") || asksForCode) add("otp")
            if (containsAny(text, "cvv", "cvc", "datele cardului", "numarul cardului")) add("card")
            if (containsAny(text, "parola", "password", "credentiale", "datele de acces", "date de acces")) add("password")
            if (Regex("""\bpin\b""").containsMatchIn(text)) add("pin")
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
            if (
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
            if (
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
                ) || containsAny(compact, "multibani", "mutibani", "mutibanii", "conttemporar", "sumaDisponibila".lowercase())
            ) {
                add("transfer")
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

        return when {
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

            else -> null
        }
    }

    private fun detectClaimedIdentity(text: String, arcFamily: String?): String? {
        return when {
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
