package ro.sigurscan.app

object MailShareInputAssembler {

    private const val MAX_PREVIEW_LINKS = 12
    private val webmailInfrastructureHosts = setOf(
        "s.yimg.com",
        "opus.analytics.yahoo.com",
        "mail.yahoo.com"
    )

    fun buildMailScanInput(rawText: String, links: List<String>, sourceLabel: String): String {
        val sanitizedText = sanitizeSharedText(rawText)
        val uniqueLinks = filterActionableMailLinks(links)

        if (uniqueLinks.isEmpty()) return sanitizedText

        val preview = uniqueLinks
            .take(MAX_PREVIEW_LINKS)
            .mapIndexed { index, url -> "${index + 1}. ${url.trim()}" }
            .joinToString("\n")

        return buildString {
            appendLine("SCANARE MAIL: $sourceLabel")
            appendLine("URL-uri ascunse/expuse detectate din mesaj:")
            appendLine(preview)
            appendLine()
            appendLine("Text original:")
            appendLine(sanitizedText)
        }
    }

    fun sanitizeSharedText(content: String): String {
        return content
            .replace(Regex("(?is)<!--.*?-->"), "")
            .let(::decodeHtmlEntities)
            .let(::removeInvisibleObfuscation)
            .replace(Regex("(?is)<[^>]*>"), " ")
            .replace(Regex("\\s+"), " ")
            .trim()
    }

    fun filterActionableMailLinks(links: List<String>): List<String> {
        return links
            .map { it.trim() }
            .filter { it.isNotBlank() }
            .distinct()
            .filterNot(::isWebmailInfrastructureUrl)
    }

    private fun isWebmailInfrastructureUrl(url: String): Boolean {
        val normalized = url.lowercase()
        val host = normalized
            .substringAfter("://", normalized)
            .substringBefore('/')
            .substringBefore('?')
            .substringBefore('#')
            .substringBefore(':')
            .removePrefix("www.")

        val isKnownWebmailHost = webmailInfrastructureHosts.any { known ->
            host == known || host.endsWith(".$known")
        }
        if (!isKnownWebmailHost) return false
        if (host == "mail.yahoo.com") return true

        val path = normalized.substringAfter(host, "")
        val looksLikeResource = listOf(".js", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2")
            .any { extension -> path.substringBefore('?').endsWith(extension) }
        val looksLikeAnalyticsFrame = host == "opus.analytics.yahoo.com" && path.contains("/tag/")

        return looksLikeResource || looksLikeAnalyticsFrame
    }

    private fun decodeHtmlEntities(input: String): String {
        var normalized = input
            .replace("&quot;", "\"")
            .replace("&#34;", "\"")
            .replace("&apos;", "'")
            .replace("&#39;", "'")
            .replace("&nbsp;", " ")
            .replace("&shy;", "")
            .replace("&lt;", "<")
            .replace("&gt;", ">")
            .replace("&amp;", "&")

        normalized = Regex("""&#x([0-9a-fA-F]+);?""").replace(normalized) { match ->
            match.groupValues[1].toIntOrNull(16)?.let(::codePointToString) ?: match.value
        }
        return Regex("""&#([0-9]{1,7});?""").replace(normalized) { match ->
            match.groupValues[1].toIntOrNull()?.let(::codePointToString) ?: match.value
        }
    }

    private fun removeInvisibleObfuscation(input: String): String {
        return input.replace(
            Regex("[\\u200B\\u200C\\u200D\\uFEFF\\u2060\\u00AD\\u202A-\\u202E\\u2066-\\u2069]"),
            ""
        )
    }

    private fun codePointToString(codePoint: Int): String {
        return runCatching { String(Character.toChars(codePoint)) }.getOrElse { "" }
    }
}
