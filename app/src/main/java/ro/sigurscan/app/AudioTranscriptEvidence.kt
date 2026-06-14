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
            "CONV_INVESTMENT_REMOTE_ACCESS" -> 0.90
            "CONV_FAMILY_EMERGENCY" -> 0.88
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
        return buildSet {
            if (containsAny(text, "otp", "cod sms", "cod de verificare", "codul primit")) add("otp")
            if (containsAny(text, "cvv", "cvc", "datele cardului", "numarul cardului")) add("card")
            if (containsAny(text, "parola", "password", "credentiale", "datele de acces", "date de acces")) add("password")
            if (Regex("""\bpin\b""").containsMatchIn(text)) add("pin")
            if (containsAny(text, "crypto", "bitcoin", "atm crypto")) add("crypto")
            if (containsAny(text, "anydesk", "teamviewer", "remote access", "control la distanta", "aplicatie de suport")) add("remote")
            if (containsAny(text, "buletin", "pasaport", "carte de identitate")) add("id_document")
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
                    "economiile",
                    "banii",
                    "lei cash",
                    "euro cash"
                )
            ) {
                add("transfer")
            }
        }.toList()
    }

    private fun detectArcFamily(text: String, sensitiveAsks: List<String>): String? {
        val hasBank = containsAny(text, "banca", "bnr", "raiffeisen", "bcr", "cec bank", "brd", "revolut") ||
            Regex("""\bbt\b|\bing\b""").containsMatchIn(text)
        val hasAuthority = containsAny(text, "politie", "politist", "inspector", "procuror", "anaf")
        val hasFamily = containsAny(text, "nepot", "nepoata", "fiul tau", "fiica ta", "mama", "tata", "unchiule")
        val hasEmergency = containsAny(text, "accident", "spital", "urgente", "am fost jefuit", "sunt la politie")
        val hasInvestment = containsAny(text, "investitie", "actiuni", "profit garantat", "broker", "consultant")

        return when {
            containsAny(text, "cont sigur", "cont de siguranta") || (hasBank && hasAuthority && "transfer" in sensitiveAsks) ->
                "CONV_BANK_SAFE_ACCOUNT"

            containsAny(text, "credit fraudulos", "credit pe numele", "cerere de credit") && (hasBank || hasAuthority) ->
                "CONV_BANK_FRAUDULENT_CREDIT"

            "remote" in sensitiveAsks && hasInvestment ->
                "CONV_INVESTMENT_REMOTE_ACCESS"

            hasFamily && hasEmergency && "transfer" in sensitiveAsks ->
                "CONV_FAMILY_EMERGENCY"

            else -> null
        }
    }

    private fun detectClaimedIdentity(text: String, arcFamily: String?): String? {
        return when {
            containsAny(text, "politie", "politist", "inspector", "procuror", "anaf") -> "autoritate"
            containsAny(text, "banca", "bnr", "raiffeisen", "bcr", "cec bank", "brd", "revolut") ||
                Regex("""\bbt\b|\bing\b""").containsMatchIn(text) -> "banca"

            arcFamily == "CONV_FAMILY_EMERGENCY" -> "familie"
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
