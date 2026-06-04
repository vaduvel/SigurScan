package ro.sigurscan.app

import java.nio.charset.Charset
import java.nio.charset.StandardCharsets
import java.util.Base64

object EmailMessageParser {
    data class ParsedEmailContent(
        val plainText: String,
        val htmlText: String,
        val bodyForAnalysis: String
    )

    fun parse(rawMessage: String): ParsedEmailContent {
        if (rawMessage.isBlank()) return ParsedEmailContent("", "", "")

        val (rawHeaders, bodyText) = splitHeadersAndBody(rawMessage)
        val headers = parseHeaders(rawHeaders)
        val contentType = headers["content-type"] ?: ""

        val content = if (contentType.lowercase().contains("multipart/")) {
            parseMultipartMessage(bodyText, contentType)
        } else {
            val decoded = decodePartContent(bodyText, headers)
            if (contentType.lowercase().contains("text/html")) {
                ParsedParts(html = listOf(decoded))
            } else if (isSvgLikePart(contentType.lowercase(), headers["content-disposition"]?.lowercase().orEmpty())) {
                ParsedParts(html = listOf(decoded))
            } else {
                ParsedParts(plain = listOf(decoded))
            }
        }

        val htmlText = content.html.firstOrNull { it.isNotBlank() } ?: ""
        val plainText = content.plain.filter { it.isNotBlank() }.joinToString("\n\n")
        val bodyForAnalysis = when {
            htmlText.isNotBlank() -> htmlText
            plainText.isNotBlank() -> plainText
            else -> bodyText
        }

        return ParsedEmailContent(
            plainText = plainText,
            htmlText = htmlText,
            bodyForAnalysis = bodyForAnalysis
        )
    }

    private data class ParsedParts(
        val html: List<String> = emptyList(),
        val plain: List<String> = emptyList()
    )

    private fun splitHeadersAndBody(raw: String): Pair<String, String> {
        val windowsSep = raw.indexOf("\r\n\r\n")
        if (windowsSep >= 0) {
            return raw.substring(0, windowsSep) to raw.substring(windowsSep + 4)
        }

        val unixSep = raw.indexOf("\n\n")
        if (unixSep >= 0) {
            return raw.substring(0, unixSep) to raw.substring(unixSep + 2)
        }

        return "" to raw
    }

    private fun parseHeaders(rawHeaders: String): Map<String, String> {
        val headers = linkedMapOf<String, String>()
        var activeHeader: String? = null

        val lines = rawHeaders.replace("\r\n", "\n").split('\n')
        for (line in lines) {
            if (line.isBlank()) continue
            if ((line.startsWith(" ") || line.startsWith("\t")) && activeHeader != null) {
                headers[activeHeader] = "${headers[activeHeader]} ${line.trim()}".trim()
                continue
            }

            val sep = line.indexOf(':')
            if (sep <= 0) continue
            val key = line.substring(0, sep).trim().lowercase()
            val value = line.substring(sep + 1).trim()
            headers[key] = value
            activeHeader = key
        }

        return headers
    }

    private fun parseMultipartMessage(rawBody: String, contentTypeHeader: String): ParsedParts {
        val boundary = extractBoundary(contentTypeHeader) ?: return ParsedParts()
        val marker = "--$boundary"
        val normalized = rawBody.replace("\r\n", "\n")
        val lines = normalized.split('\n')
        val partBuffers = mutableListOf<StringBuilder>()

        var currentPart: StringBuilder? = null
        for (line in lines) {
            when (line) {
                marker -> {
                    currentPart = StringBuilder()
                    partBuffers.add(currentPart)
                }
                "$marker--" -> {
                    break
                }
                else -> {
                    currentPart?.append(line)
                    currentPart?.append('\n')
                }
            }
        }

        val htmlParts = mutableListOf<String>()
        val plainParts = mutableListOf<String>()

        partBuffers.forEach { partBuilder ->
            val partRaw = partBuilder.toString()
            if (partRaw.isBlank()) return@forEach

            val (partHeaderRaw, partBodyRaw) = splitHeadersAndBody(partRaw)
            val partHeaders = parseHeaders(partHeaderRaw)

            val partContentType = partHeaders["content-type"]?.lowercase() ?: ""
            val contentDisposition = partHeaders["content-disposition"]?.lowercase() ?: ""
            val svgLikePart = isSvgLikePart(partContentType, contentDisposition)
            if (contentDisposition.startsWith("attachment") && !svgLikePart) {
                return@forEach
            }

            val decoded = decodePartContent(partBodyRaw, partHeaders)
            when {
                partContentType.contains("text/html") -> if (decoded.isNotBlank()) htmlParts.add(decoded)
                svgLikePart -> if (decoded.isNotBlank()) htmlParts.add(decoded)
                partContentType.contains("text/plain") || partContentType.isBlank() -> if (decoded.isNotBlank()) plainParts.add(decoded)
            }
        }

        return ParsedParts(html = htmlParts, plain = plainParts)
    }

    private fun isSvgLikePart(contentType: String, contentDisposition: String): Boolean {
        return contentType.contains("image/svg") ||
            contentType.contains("application/svg") ||
            contentType.contains("text/svg") ||
            contentType.contains("name=\"") && contentType.contains(".svg") ||
            contentType.contains("name=") && contentType.contains(".svg") ||
            contentDisposition.contains("filename=\"") && contentDisposition.contains(".svg") ||
            contentDisposition.contains("filename=") && contentDisposition.contains(".svg")
    }

    private fun decodePartContent(rawBody: String, headers: Map<String, String>): String {
        val encoding = headers["content-transfer-encoding"]?.lowercase()
        val charset = extractCharset(headers["content-type"]) ?: StandardCharsets.UTF_8
        val cleaned = rawBody
            .replace("\r\n", "\n")
            .replace("\n\r", "\n")
            .trim()

        return when {
            encoding?.contains("base64") == true -> {
                val sanitized = cleaned.replace(Regex("\\s"), "")
                val bytes = runCatching { Base64.getDecoder().decode(sanitized) }.getOrNull()
                if (bytes == null) cleaned else String(bytes, charset)
            }
            encoding?.contains("quoted-printable") == true -> decodeQuotedPrintable(cleaned)
            else -> cleaned
        }
    }

    private fun extractBoundary(contentType: String): String? {
        val lower = contentType.lowercase()
        val idx = lower.indexOf("boundary=")
        if (idx < 0) return null

        var boundary = contentType.substring(idx + "boundary=".length).trim()
        if (boundary.startsWith("\"")) {
            boundary = boundary.substring(1)
            val end = boundary.indexOf('"')
            if (end >= 0) boundary = boundary.substring(0, end)
        } else {
            boundary = boundary.trim()
                .substringBefore(';')
        }

        return boundary.ifBlank { null }
    }

    private fun extractCharset(contentType: String?): Charset? {
        if (contentType.isNullOrBlank()) return null
        val lower = contentType.lowercase()
        val idx = lower.indexOf("charset=")
        if (idx < 0) return null
        var charset = contentType.substring(idx + "charset=".length).trim()
        charset = charset.trim('"', '\'', ';', ' ')
        if (charset.isBlank()) return null
        return runCatching { Charset.forName(charset) }.getOrNull()
    }

    private fun decodeQuotedPrintable(input: String): String {
        val normalized = input.replace("\r", "\n")
        val out = StringBuilder()
        var i = 0

        while (i < normalized.length) {
            val ch = normalized[i]
            if (ch != '=') {
                out.append(ch)
                i++
                continue
            }

            if (i + 1 >= normalized.length) {
                out.append('=')
                i++
                continue
            }

            val next = normalized[i + 1]
            if (next == '\n') {
                i += 2
                continue
            }
            if (next == '\r' && i + 2 < normalized.length && normalized[i + 2] == '\n') {
                i += 3
                continue
            }
            if (i + 2 < normalized.length && isHexDigit(normalized[i + 1]) && isHexDigit(normalized[i + 2])) {
                val value = runCatching {
                    normalized.substring(i + 1, i + 3).toInt(16)
                }.getOrNull() ?: 0
                out.append(value.toChar())
                i += 3
                continue
            }

            out.append(ch)
            i++
        }

        return out.toString()
    }

    private fun isHexDigit(char: Char): Boolean {
        return char in '0'..'9' || char in 'a'..'f' || char in 'A'..'F'
    }
}
