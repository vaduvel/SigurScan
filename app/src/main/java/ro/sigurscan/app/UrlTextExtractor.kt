package ro.sigurscan.app

import java.net.IDN
import java.util.Locale
import java.util.regex.Pattern

internal object UrlTextExtractor {
    private val explicitUrlRegex = Pattern.compile(
        "(?:https?://|www\\.)[\\w\\-.~:/?#\\[\\]@!$&'()*+,;=%]+",
        Pattern.CASE_INSENSITIVE or Pattern.UNICODE_CHARACTER_CLASS
    )

    private val bareDomainRegex = Pattern.compile(
        "(?<![@\\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+(?:ro|com|org|net|eu|info|online|shop|xyz|top|click|biz|site|fun|app|link|me|space|delivery|gov|io|co|uk|de|fr|it|es|nl|be|pl|hu|bg|md)(?:/[\\w\\-.~:/?#\\[\\]@!$&'()*+,;=%]*)?",
        Pattern.CASE_INSENSITIVE
    )

    fun extract(input: String): List<String> {
        if (input.isBlank()) return emptyList()
        val urls = linkedSetOf<String>()
        collectMatches(explicitUrlRegex, input, urls)
        collectMatches(bareDomainRegex, input, urls)
        return urls.toList()
    }

    fun normalizeCandidate(raw: String?): String? {
        if (raw.isNullOrBlank()) return null
        val cleaned = raw
            .trim()
            .trimEnd('.', ',', ';', ':', ')', ']', '}', '"', '\'', '`')
            .takeIf { it.contains('.') }
            ?: return null
        val withoutTrailingSlashNoise = cleaned.trim()
        return when {
            withoutTrailingSlashNoise.startsWith("http://", ignoreCase = true) ||
                withoutTrailingSlashNoise.startsWith("https://", ignoreCase = true) -> withoutTrailingSlashNoise
            withoutTrailingSlashNoise.startsWith("//") -> "https:$withoutTrailingSlashNoise"
            else -> "https://$withoutTrailingSlashNoise"
        }.let(::normalizeIdnAuthority)
    }

    private fun normalizeIdnAuthority(url: String): String {
        val schemeSeparator = url.indexOf("://")
        if (schemeSeparator < 0) return url
        val scheme = url.substring(0, schemeSeparator)
        val rest = url.substring(schemeSeparator + 3)
        val authority = rest.substringBefore('/').substringBefore('?').substringBefore('#')
        if (authority.isBlank() || authority.startsWith("[")) return url

        val suffix = rest.substring(authority.length)
        val userInfo = authority.substringBeforeLast('@', missingDelimiterValue = "")
            .takeIf { authority.contains('@') }
        val hostPort = authority.substringAfterLast('@')
        val host = hostPort.substringBefore(':')
        val port = hostPort.substringAfter(':', missingDelimiterValue = "")
        if (host.isBlank() || host.all { it.code < 128 }) return url

        val asciiHost = runCatching {
            IDN.toASCII(host, IDN.USE_STD3_ASCII_RULES).lowercase(Locale.US)
        }.getOrNull() ?: return url
        val rebuiltAuthority = buildString {
            if (!userInfo.isNullOrBlank()) {
                append(userInfo)
                append('@')
            }
            append(asciiHost)
            if (port.isNotBlank()) {
                append(':')
                append(port)
            }
        }
        return "$scheme://$rebuiltAuthority$suffix"
    }

    private fun collectMatches(pattern: Pattern, input: String, output: MutableSet<String>) {
        val matcher = pattern.matcher(input)
        while (matcher.find()) {
            val normalized = normalizeCandidate(matcher.group()) ?: continue
            output.add(normalized)
        }
    }
}
