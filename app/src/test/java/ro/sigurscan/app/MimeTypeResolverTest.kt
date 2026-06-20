package ro.sigurscan.app

import org.junit.Assert.assertEquals
import org.junit.Test

class MimeTypeResolverTest {
    @Test
    fun usesIntentFallbackWhenContentResolverCannotTypeSharedFile() {
        assertEquals(
            "image/png",
            resolveSharedMimeType(
                resolverMime = "",
                fallbackMime = "image/png",
                fileName = "download"
            )
        )
    }

    @Test
    fun prefersSpecificFallbackOverGenericOctetStream() {
        assertEquals(
            "image/png",
            resolveSharedMimeType(
                resolverMime = "application/octet-stream",
                fallbackMime = "image/png",
                fileName = "download"
            )
        )
    }

    @Test
    fun infersCommonImportMimeTypesFromFileName() {
        assertEquals("image/jpeg", resolveSharedMimeType("", "", "factura.JPG"))
        assertEquals("application/pdf", resolveSharedMimeType("", "application/octet-stream", "factura.pdf"))
        assertEquals("message/rfc822", resolveSharedMimeType("", "", "mail.eml"))
        assertEquals("audio/ogg", resolveSharedMimeType("", "", "voice-note.opus"))
    }
}
