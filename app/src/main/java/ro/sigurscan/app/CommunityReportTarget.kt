package ro.sigurscan.app

import java.nio.charset.StandardCharsets
import java.security.MessageDigest

data class CommunityReportTarget(
    val hash: String,
    val targetType: String
)

internal fun communityReportTarget(assessment: OfflineAssessment): CommunityReportTarget {
    val raw = assessment.originalText.trim()
    val normalizedPhone = PhoneNumberHasher.normalizePhoneNumber(raw)
    val phoneDigits = normalizedPhone.count(Char::isDigit)
    val phoneOnly = raw.isNotBlank() &&
        raw.all { it.isDigit() || it in "+().- " } &&
        phoneDigits in 10..15

    if (phoneOnly) {
        return CommunityReportTarget(
            hash = PhoneNumberHasher.hashPhone(normalizedPhone),
            targetType = "phone"
        )
    }

    val targetType = if (
        assessment.finalUrl?.isNotBlank() == true ||
        UrlTextExtractor.extract(raw).isNotEmpty()
    ) {
        "url"
    } else {
        "text"
    }
    val hash = MessageDigest.getInstance("SHA-256")
        .digest(raw.toByteArray(StandardCharsets.UTF_8))
        .joinToString("") { "%02x".format(it) }
    return CommunityReportTarget(hash = hash, targetType = targetType)
}
