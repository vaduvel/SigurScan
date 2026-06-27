package ro.sigurscan.app

object AudioTranscriptRedactor {
    private val emailPattern = Regex("""(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b""")
    private val ibanPattern = Regex("""(?i)\bRO[0-9A-Z]{2}(?:[\s-]?[0-9A-Z]){16,30}\b""")
    private val cnpPattern = Regex("""\b[1-9]\d{12}\b""")
    private val cardPattern = Regex("""\b(?:\d[ -]?){13,19}\b""")
    private val phonePattern = Regex("""(?i)(?<!\w)(?:\+?40[\s.-]?|0)7(?:[\s.-]?\d){8}(?!\w)""")
    private val codePattern = Regex("""(?i)\b(cod(?:ul)?|otp|sms)\b(\s*(?:este|e|:)?\s*)\d{4,8}\b""")

    fun redact(value: String): String {
        if (value.isBlank()) return ""
        return value
            .replace(emailPattern, "[email]")
            .replace(ibanPattern, "[iban]")
            .replace(cnpPattern, "[cnp]")
            .replace(cardPattern) { match ->
                if (match.value.count(Char::isDigit) >= 13) "[card]" else match.value
            }
            .replace(phonePattern, "[telefon]")
            .replace(codePattern) { match ->
                "${match.groupValues[1]} [cod]"
            }
            .replace(Regex("""\s+"""), " ")
            .trim()
    }
}
