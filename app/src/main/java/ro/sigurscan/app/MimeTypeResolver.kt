package ro.sigurscan.app

import java.util.Locale

internal fun resolveSharedMimeType(
    resolverMime: String?,
    fallbackMime: String?,
    fileName: String
): String {
    val resolver = resolverMime.normalizedMimeOrBlank()
    val fallback = fallbackMime.normalizedMimeOrBlank()
    val inferred = inferMimeTypeFromFileName(fileName)

    return when {
        resolver.isSpecificMime() -> resolver
        fallback.isSpecificMime() -> fallback
        inferred.isNotBlank() -> inferred
        resolver.isNotBlank() -> resolver
        else -> fallback
    }
}

private fun String?.normalizedMimeOrBlank(): String =
    orEmpty().substringBefore(';').trim().lowercase(Locale.ROOT)

private fun String.isSpecificMime(): Boolean =
    isNotBlank() && this != "application/octet-stream" && this != "*/*"

private fun inferMimeTypeFromFileName(fileName: String): String {
    val lowerName = fileName.lowercase(Locale.ROOT)
    return when {
        lowerName.endsWith(".png") -> "image/png"
        lowerName.endsWith(".jpg") || lowerName.endsWith(".jpeg") -> "image/jpeg"
        lowerName.endsWith(".heic") -> "image/heic"
        lowerName.endsWith(".heif") -> "image/heif"
        lowerName.endsWith(".webp") -> "image/webp"
        lowerName.endsWith(".pdf") -> "application/pdf"
        lowerName.endsWith(".eml") -> "message/rfc822"
        lowerName.endsWith(".html") || lowerName.endsWith(".htm") -> "text/html"
        lowerName.endsWith(".txt") -> "text/plain"
        lowerName.endsWith(".m4a") -> "audio/mp4"
        lowerName.endsWith(".mp3") -> "audio/mpeg"
        lowerName.endsWith(".wav") -> "audio/wav"
        lowerName.endsWith(".ogg") || lowerName.endsWith(".opus") -> "audio/ogg"
        else -> ""
    }
}
