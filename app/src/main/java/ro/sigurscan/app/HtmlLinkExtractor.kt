package ro.sigurscan.app

import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.util.Base64
import java.util.Locale
import java.util.regex.Pattern

object HtmlLinkExtractor {
    private const val MAX_RECURSIVE_DECODE_DEPTH = 4
    private const val MAX_DECODE_VARIANTS = 24

    private val urlRegex = Pattern.compile(
        "(?:https?://|www\\.)[\\w\\-.~:/?#\\[\\]@!$&'()*+,;=%]+",
        Pattern.CASE_INSENSITIVE
    )

    fun extractHtmlLinks(content: String): List<String> = extractHtmlLinks(content) { it }

    fun extractHtmlLinks(content: String, decodeHtml: (String) -> String): List<String> {
        if (content.isBlank()) return emptyList()

        val links = linkedSetOf<String>()
        val contentVariants = recursiveDecodeVariants(
            removeInvisibleObfuscation(content),
            decodeHtml
        )

        fun addCandidate(raw: String?) {
            expandCandidateUrls(raw, decodeHtml).forEach { links.add(it) }
        }

        contentVariants.forEach { variant ->
            links.addAll(extractHtmlLinksLegacy(variant, decodeHtml))
            links.addAll(extractHtmlLinksFromStyleBlocks(variant, decodeHtml))
            links.addAll(extractHtmlLinksFromScriptBlocks(variant, decodeHtml))
            links.addAll(extractHtmlLinksFromTaggedElements(variant, decodeHtml))
            extractCssUrlCandidates(variant).forEach(::addCandidate)
            urlMatches(variant).forEach(::addCandidate)
        }

        return links.toList()
    }

    private fun extractHtmlLinksFromScriptBlocks(content: String, decodeHtml: (String) -> String): List<String> {
        val links = linkedSetOf<String>()
        val normalized = content.replace("\r", " ").replace("\n", " ")
        val scriptBlockPattern = Regex("""(?is)<\s*script\b[^>]*>(.*?)</script>""")

        fun addCandidate(raw: String?) {
            expandCandidateUrls(raw, decodeHtml).forEach { links.add(it) }
        }

        scriptBlockPattern.findAll(normalized).forEach { match ->
            val scriptContent = match.groupValues.getOrNull(1) ?: return@forEach
            val decodedScript = decodeHtml(scriptContent)

            urlMatches(scriptContent).forEach(::addCandidate)
            urlMatches(decodedScript).forEach(::addCandidate)
            collectScriptEncodedCandidates(scriptContent, links, decodeHtml)
            collectScriptEncodedCandidates(decodedScript, links, decodeHtml)
        }

        return links.toList()
    }

    private fun extractHtmlLinksFromStyleBlocks(content: String, decodeHtml: (String) -> String): List<String> {
        val links = linkedSetOf<String>()
        val normalized = content.replace("\r", " ").replace("\n", " ")
        val styleBlockPattern = Regex("""(?is)<\s*style\b[^>]*>(.*?)</style>""")

        fun addCandidate(raw: String?) {
            expandCandidateUrls(raw, decodeHtml).forEach { links.add(it) }
        }

        styleBlockPattern.findAll(normalized).forEach { match ->
            val styleContent = match.groupValues.getOrNull(1) ?: return@forEach
            urlMatches(styleContent).forEach { addCandidate(it) }
            urlMatches(decodeHtml(styleContent)).forEach { addCandidate(it) }
            extractCssUrlCandidates(styleContent).forEach { addCandidate(it) }
            extractCssUrlCandidates(decodeHtml(styleContent)).forEach { addCandidate(it) }
        }

        return links.toList()
    }

    private fun extractHtmlLinksLegacy(content: String, decodeHtml: (String) -> String): List<String> {
        val links = linkedSetOf<String>()
        val normalised = content.replace("\r", " ").replace("\n", " ")
        val htmlDecoded = decodeHtml(normalised)

        fun addCandidate(raw: String?) {
            expandCandidateUrls(raw, decodeHtml).forEach { links.add(it) }
        }

        val linkAttributePatterns = listOf(
            """(?i)(href|src|action|formaction|data-href|xlink:href|poster|data-url|data-link|app-url)\s*=\s*(["'])([^"'\s>]+)\2""",
            """(?i)data-[a-z0-9_-]+\s*=\s*(["'])([^"']+)\2""",
            """(?i)\b(?:href|src|action|formaction)\s*=\s*([^'"\s>]+)"""
        )

        val jsPatterns = listOf(
            """(?is)on(?:click|submit|touchstart|mousedown|mouseover|focus|blur|change|error|load|keyup|keydown)\s*=\s*(["'])(.*?)\1""",
            """(?i)(?:window|document)\.(?:location|location\.href|location\.replace|location\.assign)\s*=\s*(["'])(.*?)\1""",
            """(?i)window\.open\s*\(\s*(["'])(.*?)\1"""
        )

        linkAttributePatterns.forEach { patternText ->
            val pattern = Regex(patternText, setOf(RegexOption.DOT_MATCHES_ALL, RegexOption.IGNORE_CASE))
            pattern.findAll(normalised).forEach { match ->
                val candidate = listOfNotNull(
                    match.groupValues.getOrNull(3),
                    match.groupValues.getOrNull(2),
                    match.groupValues.getOrNull(1)
                ).firstOrNull()
                addCandidate(candidate)
            }
            pattern.findAll(htmlDecoded).forEach { match ->
                val candidate = listOfNotNull(
                    match.groupValues.getOrNull(3),
                    match.groupValues.getOrNull(2),
                    match.groupValues.getOrNull(1)
                ).firstOrNull()
                addCandidate(candidate)
            }
        }

        jsPatterns.forEach { patternText ->
            val pattern = Regex(patternText, RegexOption.DOT_MATCHES_ALL)
            pattern.findAll(normalised).forEach { match ->
                val snippet = match.groupValues.getOrNull(2).orEmpty()
                urlMatches(snippet).forEach { addCandidate(it) }
                urlMatches(decodeHtml(snippet)).forEach { addCandidate(it) }
                collectScriptEncodedCandidates(snippet, links, decodeHtml)
            }
            pattern.findAll(htmlDecoded).forEach { match ->
                val snippet = match.groupValues.getOrNull(2).orEmpty()
                urlMatches(snippet).forEach { addCandidate(it) }
                collectScriptEncodedCandidates(snippet, links, decodeHtml)
            }
        }

        return links.toList()
    }

    private fun extractHtmlLinksFromTaggedElements(content: String, decodeHtml: (String) -> String): List<String> {
        val links = linkedSetOf<String>()
        val normalized = content.replace("\r", " ").replace("\n", " ")

        val linkableTagPattern = Regex(
            """(?is)<\s*(a|button|input|form|area|iframe|img|source|video|audio|embed|object|meta|div|span|p|script)\b[^>]*>"""
        )

        linkableTagPattern.findAll(normalized).forEach { match ->
            val tagName = match.groupValues.getOrNull(1)?.lowercase() ?: return@forEach
            val tag = match.value
            val attrs = extractHtmlAttributes(tag)

            val urlKeys = when (tagName) {
                "a", "area" -> listOf("href", "xlink:href", "data-href", "data-url", "data-link", "app-url")
                "form" -> listOf("action")
                "button" -> listOf("formaction")
                "input" -> listOf("formaction", "action", "src")
                "iframe", "img", "source", "video", "audio", "embed", "object" -> listOf("src", "srcset")
                "meta" -> listOf("content")
                else -> emptyList()
            }

            urlKeys.forEach { key ->
                val rawValue = attrs[key] ?: return@forEach
                if (key == "srcset") {
                    rawValue.split(',').forEach { entry ->
                        val token = entry.trim().split(Regex("\\s+")).firstOrNull()
                        expandCandidateUrls(token, decodeHtml).forEach { candidate -> links.add(candidate) }
                    }
                } else {
                    expandCandidateUrls(rawValue, decodeHtml).forEach { links.add(it) }
                }
            }

            if (tagName == "meta") {
                val contentValue = attrs["content"] ?: return@forEach
                urlMatches(contentValue).forEach { expandCandidateUrls(it, decodeHtml).forEach(links::add) }
                extractMetaRefreshTarget(contentValue)?.let { expandCandidateUrls(it, decodeHtml).forEach(links::add) }
            }

            listOf(
                "onclick",
                "ondblclick",
                "oncontextmenu",
                "onmousedown",
                "onmouseover",
                "onmouseout",
                "onmouseenter",
                "onmouseleave",
                "onpointerdown",
                "onpointerup",
                "onpointerover",
                "onsubmit",
                "onload",
                "onfocus",
                "onchange",
                "onerror",
                "ontouchstart",
                "ontouchend",
                "onkeydown",
                "onkeyup",
                "onblur"
            ).forEach { key ->
                val scriptValue = attrs[key] ?: return@forEach
                collectScriptEncodedCandidates(scriptValue, links, decodeHtml)
            }

            attrs["style"]?.let { styleValue ->
                urlMatches(styleValue).forEach { raw ->
                    expandCandidateUrls(raw, decodeHtml).forEach { candidate -> links.add(candidate) }
                }
                extractCssUrlCandidates(styleValue).forEach { raw ->
                    expandCandidateUrls(raw, decodeHtml).forEach { candidate -> links.add(candidate) }
                }
            }

            attrs["data"]?.let { dataValue ->
                collectScriptEncodedCandidates(dataValue, links, decodeHtml)
            }
        }

        return links.toList()
    }

    private fun extractHtmlAttributes(tag: String): Map<String, String> {
        val attrs = mutableMapOf<String, String>()
        val attributePattern = Regex(
            """(?i)\b([a-z0-9:_-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'<>]+))"""
        )
        attributePattern.findAll(tag).forEach { match ->
            val key = match.groupValues.getOrNull(1)?.lowercase() ?: return@forEach
            val rawValue = listOfNotNull(
                match.groupValues.getOrNull(2),
                match.groupValues.getOrNull(3),
                match.groupValues.getOrNull(4)
            ).firstOrNull { it.isNotBlank() } ?: return@forEach

            attrs[key] = rawValue
                .replace("\\\"", "\"")
                .replace("\\'", "'")
        }
        return attrs
    }

    private fun collectScriptEncodedCandidates(
        script: String,
        links: MutableSet<String>,
        decodeHtml: (String) -> String
    ) {
        fun addCandidate(raw: String?) {
            expandCandidateUrls(raw, decodeHtml).forEach { links.add(it) }
        }

        if (script.isBlank()) return

        val plainEscaped = decodeJsEscapes(script)
        val decoded = runCatching {
            URLDecoder.decode(plainEscaped, StandardCharsets.UTF_8.name())
        }.getOrNull() ?: plainEscaped
        val decodedHtml = decodeHtml(decoded)
        val candidateTexts = linkedSetOf(script, plainEscaped, decoded, decodedHtml, decodeHtmlEntities(script), decodeHtmlEntities(decoded))
        val variableMap = extractScriptStringAssignments(script) +
                extractScriptStringAssignments(decoded) +
                extractScriptStringAssignments(decodedHtml)

        candidateTexts.forEach { candidateText ->
            urlMatches(candidateText).forEach { addCandidate(it) }
            val decodedCandidateText = runCatching {
                URLDecoder.decode(candidateText, StandardCharsets.UTF_8.name())
            }.getOrNull()
            decodedCandidateText?.let { urlMatches(it).forEach { value -> addCandidate(value) } }
            extractConcatenatedScriptLinks(candidateText, links)
            extractTemplateLiteralLinks(candidateText, links, variableMap)
        }

        val jsRedirectPatterns = listOf(
            Regex("""(?is)\b(?:window\.location|document\.location)\.href\s*=\s*([^\n;]+)"""),
            Regex("""(?is)\b(?:window\.location|document\.location)\.(?:replace|assign)\s*\(\s*([^\)]+)"""),
            Regex("""(?is)\blocation\.(?:replace|assign)\s*\(\s*([^\)]+)"""),
            Regex("""(?is)\bwindow\.open\s*\(\s*(['"])(.*?)\1"""),
            Regex("""(?is)\blocation(?:\.href)?\s*=\s*(['"])(.*?)\1"""),
            Regex("""(?is)\b(?:self|top|parent|window|document)\.(?:location|location\.href)\s*=\s*([^'";>\s]+)"""),
            Regex("""(?is)\blocation\.search\s*=\s*(['"])(.*?)\1"""),
            Regex("""(?is)\blocation\.search\s*=\s*([^'";>\s]+)""")
        )

        fun addRedirectCandidate(match: MatchResult) {
            val candidate = when {
                match.groupValues.size > 2 && match.groupValues[2].isNotBlank() -> match.groupValues[2]
                match.groupValues.isNotEmpty() -> match.groupValues[1]
                else -> null
            }

            addCandidate(candidate)
            candidate?.let { resolveScriptAssignmentExpression(it, variableMap)?.let(::addCandidate) }
        }

        jsRedirectPatterns.forEach { pattern ->
            pattern.findAll(script).forEach { match ->
                addRedirectCandidate(match)
            }
            pattern.findAll(decoded).forEach { match ->
                addRedirectCandidate(match)
            }
            pattern.findAll(decodedHtml).forEach { match ->
                addRedirectCandidate(match)
            }
        }

        val base64Pattern = Regex("""(?i)\batob\((?:'|")([^'"]+)(?:'|")\)""")
        base64Pattern.findAll(script).forEach { match ->
            val decodedCandidate = runCatching {
                val raw = match.groupValues.getOrNull(1) ?: return@forEach
                val bytes = runCatching {
                    Base64.getUrlDecoder().decode(raw)
                }.getOrElse {
                    Base64.getDecoder().decode(raw)
                }
                String(bytes, StandardCharsets.UTF_8)
            }.getOrNull()
            if (decodedCandidate != null) {
                collectScriptEncodedCandidates(decodedCandidate, links, decodeHtml)
            }
        }

        val decodeUriPattern = Regex("""(?i)\bdecodeURIComponent\((['"])(.*?)\1\)""")
        decodeUriPattern.findAll(script).forEach { match ->
            val decodedMatch = runCatching {
                URLDecoder.decode(match.groupValues.getOrNull(2) ?: return@forEach, StandardCharsets.UTF_8.name())
            }.getOrNull()
            if (decodedMatch != null) {
                collectScriptEncodedCandidates(decodedMatch, links, decodeHtml)
            }
        }

        val unescapePattern = Regex("""(?i)\bunescape\((['"])(.*?)\1\)""")
        unescapePattern.findAll(script).forEach { match ->
            val decodedMatch = runCatching {
                URLDecoder.decode(match.groupValues.getOrNull(2) ?: return@forEach, StandardCharsets.UTF_8.name())
            }.getOrNull()
            if (decodedMatch != null) {
                collectScriptEncodedCandidates(decodedMatch, links, decodeHtml)
            }
        }
    }

    private fun extractConcatenatedScriptLinks(candidateText: String, links: MutableSet<String>) {
        val concatenatedPattern = Regex(
            """(?is)(?:(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')\s*\+\s*)+(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')"""
        )
        val quotedPattern = Regex("""(?:"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)')""")

        concatenatedPattern.findAll(candidateText).forEach { concatMatch ->
            val fragments = quotedPattern.findAll(concatMatch.value)
                .mapNotNull { match ->
                    val raw = match.groupValues.getOrNull(1)?.ifBlank { null }
                        ?: match.groupValues.getOrNull(2)
                    raw?.let(::decodeJsEscapes)
                }
                .filter { it.isNotBlank() }
                .toList()

            if (fragments.size >= 2) {
                val joined = fragments.joinToString(separator = "")
                urlMatches(joined).forEach { raw -> addConcatenatedCandidate(raw)?.let { links.add(it) } }
            }
        }
    }

    private fun extractTemplateLiteralLinks(
        candidateText: String,
        links: MutableSet<String>,
        variableMap: Map<String, String>
    ) {
        val templatePattern = Regex("""`([^`]*)`""")
        templatePattern.findAll(candidateText).forEach { match ->
            val candidate = resolveScriptTemplateLiteral(match.value, variableMap)
            if (candidate != null) {
                expandCandidateUrls(candidate).forEach { links.add(it) }
            }
        }
    }

    private fun extractScriptStringAssignments(script: String): Map<String, String> {
        if (script.isBlank()) return emptyMap()

        val assignments = linkedMapOf<String, String>()
        val patterns = listOf(
            Regex("""(?is)\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;]+)"""),
            Regex("""(?is)(?:^|[;\\n\\r\\t])([A-Za-z_$][\w$]*)\s*=\s*([^;]+)""")
        )

        val matches = mutableListOf<Triple<Int, String, String>>()
        patterns.forEach { pattern ->
            pattern.findAll(script).forEach { match ->
                val name = match.groupValues.getOrNull(1) ?: return@forEach
                val rawValue = match.groupValues.getOrNull(2)?.trim() ?: return@forEach
                matches.add(Triple(match.range.first, name, rawValue))
            }
        }

        matches.sortBy { it.first }

        matches.forEach { (_, name, rawValue) ->
            val resolved = resolveScriptAssignmentExpression(rawValue, assignments)
            if (resolved != null) {
                assignments[name] = resolved
            }
        }

        return assignments
    }

    private fun resolveScriptAssignmentExpression(
        expression: String,
        variables: Map<String, String>
    ): String? {
        var normalized = expression.trim().trimEnd(';').trim()
        if (normalized.isBlank()) return null

        normalized = normalized.removeSurrounding("(", ")").trim()

        if (normalized.startsWith("`") && normalized.endsWith("`")) {
            resolveScriptTemplateLiteral(normalized, variables)?.let { return it }
        }

        val concatenated = resolveScriptVariableConcatenation(normalized, variables)
        if (concatenated != null) return concatenated

        if (normalized.startsWith("'") || normalized.startsWith("\"") || normalized.startsWith("`")) {
            val unquoted = normalized.trim('\'', '\"', '`').trim()
            if (unquoted.isNotBlank()) return decodeJsEscapes(unquoted)
        }

        val direct = variables[normalized]
        if (direct != null) return direct

        val atobPattern = Regex("""(?i)\batob\((?:'|")([^'"]+)(?:'|")\)""")
        val atobMatch = atobPattern.find(normalized)
        if (atobMatch != null) {
            val decoded = runCatching {
                val raw = atobMatch.groupValues.getOrNull(1) ?: return@runCatching null
                val bytes = runCatching {
                    Base64.getUrlDecoder().decode(raw)
                }.getOrElse {
                    Base64.getDecoder().decode(raw)
                }
                String(bytes, StandardCharsets.UTF_8)
            }.getOrNull()
            if (decoded != null) return decoded
        }

        return null
    }

    private fun resolveScriptVariableConcatenation(
        expression: String,
        variables: Map<String, String>
    ): String? {
        if (expression.isBlank()) return null

        var candidate = expression
            .trim()
            .trimEnd(';')
            .removeSurrounding("(", ")")
            .trim()

        if (!candidate.contains('+')) return null

        val tokens = splitConcatenationExpression(candidate)
            .mapNotNull { token -> resolveScriptConcatenationToken(token, variables) }

        if (tokens.isEmpty()) return null

        val resolved = tokens.joinToString("")
        return if (resolved.isNotBlank()) resolved else null
    }

    private fun splitConcatenationExpression(expression: String): List<String> {
        val tokens = mutableListOf<String>()
        val current = StringBuilder()
        var inSingle = false
        var inDouble = false
        var inBacktick = false
        var inEscape = false

        for (char in expression) {
            if (inEscape) {
                current.append(char)
                inEscape = false
                continue
            }

            when (char) {
                '\\' -> {
                    current.append(char)
                    inEscape = true
                }
                '\'' -> {
                    inSingle = !inSingle
                    current.append(char)
                }
                '"' -> {
                    inDouble = !inDouble
                    current.append(char)
                }
                '`' -> {
                    inBacktick = !inBacktick
                    current.append(char)
                }
                '+' -> {
                    if (!inSingle && !inDouble && !inBacktick) {
                        tokens.add(current.toString().trim())
                        current.setLength(0)
                    } else {
                        current.append(char)
                    }
                }
                else -> current.append(char)
            }
        }

        val last = current.toString().trim()
        if (last.isNotBlank()) tokens.add(last)
        return tokens
    }

    private fun resolveScriptConcatenationToken(token: String, variables: Map<String, String>): String? {
        val trimmed = token.trim()
        if (trimmed.isBlank()) return null

        val unquoted = trimmed.removeSurrounding("'", "'")
            .removeSurrounding("\"", "\"")
            .removeSurrounding("`", "`")
        if (unquoted != trimmed) {
            return if (unquoted.isNotBlank()) decodeJsEscapes(unquoted) else null
        }

        val key = trimmed.trim().trim('(', ')', ' ').trim()
        if (key.isBlank()) return null
        return variables[key]
    }

    private fun resolveTemplateLiteralExpression(
        expression: String,
        variables: Map<String, String>
    ): String? {
        val trimmed = expression.trim()
        if (trimmed.isBlank()) return ""

        val unquoted = trimmed.removeSurrounding("'", "'")
            .removeSurrounding("\"", "\"")
            .removeSurrounding("`", "`")
        if (unquoted != trimmed) {
            return if (unquoted.isNotBlank()) decodeJsEscapes(unquoted) else null
        }

        val direct = variables[trimmed]
        if (direct != null) return direct

        if (trimmed.contains('+')) {
            return resolveScriptVariableConcatenation(trimmed, variables)
        }

        return null
    }

    private fun resolveScriptTemplateLiteral(
        template: String,
        variables: Map<String, String>
    ): String? {
        val normalized = template.trim()
        if (!normalized.startsWith("`") || !normalized.endsWith("`") || normalized.length < 2) return null

        val rawTemplate = normalized.substring(1, normalized.length - 1)
        val result = StringBuilder()
        var index = 0

        while (index < rawTemplate.length) {
            val openIndex = rawTemplate.indexOf("\${", index)
            if (openIndex < 0) {
                result.append(rawTemplate.substring(index))
                break
            }

            result.append(rawTemplate.substring(index, openIndex))

            val expressionStart = openIndex + 2
            var cursor = expressionStart
            var depth = 1
            while (cursor < rawTemplate.length && depth > 0) {
                when (rawTemplate[cursor]) {
                    '{' -> depth++
                    '}' -> depth--
                }
                cursor++
            }

            if (depth != 0) return null

            val expression = rawTemplate.substring(expressionStart, cursor - 1)
            val value = resolveTemplateLiteralExpression(expression, variables) ?: return null
            result.append(value)
            index = cursor
        }

        return normalizeJsConcatenation(decodeJsEscapes(result.toString()))
    }

    private fun addConcatenatedCandidate(raw: String?): String? {
        val normalized = normalizeJsConcatenation(raw)
        return normalizeCandidateUrl(normalized)
    }

    private fun normalizeJsConcatenation(raw: String?): String {
        return (raw ?: "")
            .replace("\\n", "")
            .replace("\\r", "")
            .replace("\\\"", "\"")
            .replace("\\'", "'")
            .replace("\\\\", "\\")
            .replace("\\u002f", "/")
            .replace("\\/", "/")
            .trim()
    }

    internal fun normalizeCandidateUrl(raw: String?): String? {
        if (raw == null) return null

        var candidate = raw
            .trim()
            .let { decodeHtmlEntities(it) }
            .let { decodeJsEscapes(it) }
            .let { removeInvisibleObfuscation(it) }
            .replace("&nbsp;", " ")
            .replace("\\u0026", "&")
            .trimEnd('.', ',', ';', '"', '\'', ')', ']', '}', '`')

        if (candidate.startsWith("javascript:", ignoreCase = true)) {
            val inner = candidate.removePrefix("javascript:").trim()
            val matcher = urlRegex.matcher(inner)
            if (!matcher.find()) return null
            candidate = matcher.group()
        }

        if (candidate.contains("%")) {
            runCatching {
                candidate = URLDecoder.decode(candidate, StandardCharsets.UTF_8.name())
            }
        }

        val normalized = when {
            candidate.startsWith("https://") || candidate.startsWith("http://") -> candidate
            candidate.startsWith("//") -> "https:$candidate"
            else -> UrlTextExtractor.normalizeCandidate(candidate)
        }

        return normalized?.let { unwrapRedirectWrapper(it) ?: it }
    }

    private fun expandCandidateUrls(raw: String?, decodeHtml: (String) -> String = { it }): List<String> {
        if (raw.isNullOrBlank()) return emptyList()

        val output = linkedSetOf<String>()
        recursiveDecodeVariants(raw, decodeHtml).forEach { variant ->
            decodeDataUriPayload(variant)?.let { payload ->
                extractHtmlLinks(payload, decodeHtml).forEach(output::add)
                urlMatches(payload).forEach { normalizeCandidateUrl(it)?.let(output::add) }
            }

            normalizeCandidateUrl(variant)?.let { normalized ->
                output.add(normalized)
                unwrapRedirectWrapper(normalized)?.let(output::add)
                extractNestedUrlTargets(normalized).forEach(output::add)
            }
        }

        return output.toList()
    }

    private fun recursiveDecodeVariants(
        input: String,
        decodeHtml: (String) -> String = { it }
    ): Set<String> {
        val seen = linkedSetOf<String>()
        var frontier = linkedSetOf(input)

        repeat(MAX_RECURSIVE_DECODE_DEPTH) {
            if (frontier.isEmpty() || seen.size >= MAX_DECODE_VARIANTS) return@repeat
            val next = linkedSetOf<String>()

            frontier.forEach { value ->
                if (value.isBlank() || !seen.add(value)) return@forEach

                val candidates = listOfNotNull(
                    runCatching { decodeHtml(value) }.getOrNull(),
                    decodeHtmlEntities(value),
                    decodeJsEscapes(value),
                    percentDecode(value),
                    decodeDataUriPayload(value)
                )

                candidates
                    .map(::removeInvisibleObfuscation)
                    .filter { it.isNotBlank() && it != value && it.length <= input.length * 8 + 4096 }
                    .forEach { candidate ->
                        if (seen.size + next.size < MAX_DECODE_VARIANTS) {
                            next.add(candidate)
                        }
                    }
            }

            frontier = next
        }

        seen.addAll(frontier.take(MAX_DECODE_VARIANTS - seen.size))
        return seen
    }

    private fun percentDecode(value: String): String? {
        if (!value.contains('%')) return null
        return runCatching {
            URLDecoder.decode(value, StandardCharsets.UTF_8.name())
        }.getOrNull()
    }

    private fun removeInvisibleObfuscation(input: String): String {
        if (input.isBlank()) return input
        return input
            .replace(Regex("""(?is)<!--.*?-->"""), "")
            .replace(Regex("""[\u200B\u200C\u200D\uFEFF\u2060\u00AD\u202A-\u202E\u2066-\u2069]"""), "")
    }

    private fun extractCssUrlCandidates(input: String): List<String> {
        val cssUrlPattern = Regex("""(?is)\burl\(\s*(?:"([^"]*)"|'([^']*)'|([^)]+?))\s*\)""")
        return cssUrlPattern.findAll(input)
            .mapNotNull { match ->
                listOf(
                    match.groupValues.getOrNull(1),
                    match.groupValues.getOrNull(2),
                    match.groupValues.getOrNull(3)
                ).firstOrNull { !it.isNullOrBlank() }?.trim()
            }
            .toList()
    }

    private fun decodeDataUriPayload(raw: String): String? {
        val value = raw.trim().trim('"', '\'')
        if (!value.startsWith("data:", ignoreCase = true)) return null
        val commaIndex = value.indexOf(',')
        if (commaIndex < 0 || commaIndex == value.lastIndex) return null

        val metadata = value.substring(5, commaIndex).lowercase(Locale.US)
        val payload = value.substring(commaIndex + 1)
        if (!metadata.contains("text/html") && !metadata.contains("image/svg") && !metadata.contains("text/plain")) {
            return null
        }

        return if (metadata.contains(";base64")) {
            runCatching {
                val bytes = runCatching {
                    Base64.getUrlDecoder().decode(payload)
                }.getOrElse {
                    Base64.getDecoder().decode(payload)
                }
                String(bytes, StandardCharsets.UTF_8)
            }.getOrNull()
        } else {
            percentDecode(payload) ?: payload
        }
    }

    private fun unwrapRedirectWrapper(url: String): String? {
        val lower = url.lowercase(Locale.US)
        val host = extractHost(lower)

        val queryParams = extractQueryParams(url)
        val queryTarget = when {
            host.endsWith("safelinks.protection.outlook.com") -> queryParams["url"]
            host == "www.google.com" || host == "google.com" -> queryParams["q"] ?: queryParams["url"]
            host.endsWith("facebook.com") && lower.contains("/l.php") -> queryParams["u"]
            else -> null
        }
        normalizeCandidateUrl(queryTarget)?.let { return it }

        if (host.endsWith("urldefense.com")) {
            unwrapProofpointUrlDefense(url)?.let { return it }
        }

        val marketingRedirectTarget = when {
            host.endsWith("sng.link") ||
                host.endsWith("app.link") ||
                host.endsWith("branch.link") ||
                host.endsWith("bnc.lt") -> queryParams["_fallback_redirect"]
                ?: queryParams["fallback_redirect"]
                ?: queryParams["fallback"]
                ?: queryParams["redirect"]
                ?: queryParams["redirect_url"]
                ?: queryParams["url"]
                ?: queryParams["u"]
                ?: queryParams["target"]
                ?: queryParams["destination"]
            else -> null
        }
        normalizeCandidateUrl(marketingRedirectTarget)?.let { return it }

        unwrapYahooRedirect(url)?.let { return it }

        return null
    }

    private fun extractNestedUrlTargets(url: String): List<String> {
        val redirectKeys = setOf(
            "url",
            "u",
            "uri",
            "redirect",
            "redirect_url",
            "return",
            "return_url",
            "target",
            "destination",
            "dest",
            "next",
            "continue",
            "to",
            "link",
            "href"
        )
        val output = linkedSetOf<String>()
        extractQueryParams(url).forEach { (key, value) ->
            if (key in redirectKeys) {
                normalizeCandidateUrl(value)?.let(output::add)
            }
            urlMatches(value).forEach { candidate ->
                normalizeCandidateUrl(candidate)?.let(output::add)
            }
        }
        return output.toList()
    }

    private fun extractHost(url: String): String {
        val withoutScheme = url.substringAfter("://", url)
        return withoutScheme.substringBefore('/').substringBefore('?').substringBefore('#')
            .substringBefore(':')
            .lowercase(Locale.US)
    }

    private fun extractQueryParams(url: String): Map<String, String> {
        val query = url.substringAfter('?', missingDelimiterValue = "")
            .substringBefore('#')
        if (query.isBlank()) return emptyMap()

        return query.split('&')
            .mapNotNull { pair ->
                if (pair.isBlank()) return@mapNotNull null
                val key = pair.substringBefore('=').lowercase(Locale.US)
                val value = pair.substringAfter('=', missingDelimiterValue = "")
                if (key.isBlank() || value.isBlank()) return@mapNotNull null
                key to (percentDecode(value) ?: decodeHtmlEntities(value))
            }
            .toMap()
    }

    private fun unwrapProofpointUrlDefense(url: String): String? {
        val markerIndex = url.indexOf("__")
        if (markerIndex < 0) return null
        val afterMarker = url.substring(markerIndex + 2)
        val encodedTarget = afterMarker.substringBefore("__").substringBefore(";")
        if (encodedTarget.isBlank()) return null
        val candidate = encodedTarget
            .replace("hxxps://", "https://", ignoreCase = true)
            .replace("hxxp://", "http://", ignoreCase = true)
        return normalizeCandidateUrl(candidate)
    }

    private fun unwrapYahooRedirect(url: String): String? {
        val markerIndex = url.indexOf("/RU=", ignoreCase = true)
        if (markerIndex < 0) return null
        val afterMarker = url.substring(markerIndex + "/RU=".length)
        val target = afterMarker.substringBefore("/RK=").substringBefore("/RS=")
        if (target.isBlank()) return null
        return normalizeCandidateUrl(percentDecode(target) ?: target)
    }

    private fun decodeHtmlEntities(input: String): String {
        var normalized = input
            .replace("&quot;", "\"")
            .replace("&#34;", "\"")
            .replace("&apos;", "'")
            .replace("&#39;", "'")
            .replace("&amp;", "&")
            .replace("&lt;", "<")
            .replace("&gt;", ">")

        val hexEntityPattern = Regex("""&#x([0-9a-fA-F]+);?""")
        normalized = hexEntityPattern.replace(normalized) { match ->
            val hex = match.groupValues.getOrNull(1) ?: return@replace match.value
            val codePoint = hex.toIntOrNull(16) ?: return@replace match.value
            codePoint.toChar().toString()
        }

        val decEntityPattern = Regex("""&#([0-9]{1,7});?""")
        normalized = decEntityPattern.replace(normalized) { match ->
            val value = match.groupValues.getOrNull(1) ?: return@replace match.value
            val codePoint = value.toIntOrNull() ?: return@replace match.value
            codePoint.toChar().toString()
        }

        return normalized
    }

    private fun decodeJsEscapes(raw: String): String {
        if (raw.isBlank()) return raw

        var normalized = raw
            .replace("\\n", "\n")
            .replace("\\r", "\r")
            .replace("\\t", "\t")
            .replace("\\\"", "\"")
            .replace("\\'", "'")
            .replace("\\/", "/")

        val hexPattern = Regex("""\\x([0-9A-Fa-f]{2})""")
        normalized = hexPattern.replace(normalized) { match ->
            val code = match.groupValues.getOrNull(1)?.toIntOrNull(16) ?: return@replace match.value
            code.toChar().toString()
        }

        val unicodePattern = Regex("""\\u([0-9A-Fa-f]{4})""")
        normalized = unicodePattern.replace(normalized) { match ->
            val code = match.groupValues.getOrNull(1)?.toIntOrNull(16) ?: return@replace match.value
            code.toChar().toString()
        }

        return normalized.replace("\\\\", "\\")
    }

    private fun urlMatches(input: String): List<String> {
        return UrlTextExtractor.extract(input)
    }

    private fun extractMetaRefreshTarget(content: String): String? {
        val refreshPattern = Regex("""(?i)\burl\s*=\s*([^;]+)""")
        val match = refreshPattern.find(content) ?: return null
        val candidate = match.groupValues.getOrNull(1)?.trim()
            ?.trim('\'', '"', ' ')
            ?.trimStart()
            ?.trimEnd()
        return if (candidate != null && candidate.isNotBlank()) {
            normalizeCandidateUrl(candidate)
        } else null
    }
}
