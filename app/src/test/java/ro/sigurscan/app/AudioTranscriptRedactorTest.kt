package ro.sigurscan.app

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AudioTranscriptRedactorTest {
    @Test
    fun redactsSensitivePaymentIdentityAndContactTokensBeforeBackend() {
        val redacted = AudioTranscriptRedactor.redact(
            "Suna la 0722123456, trimite IBAN RO49AAAA1B31007593840000, " +
                "CNP 1960529123456, card 4111 1111 1111 1111, email ana@example.com, cod 123456."
        )

        assertTrue(redacted.contains("[telefon]"))
        assertTrue(redacted.contains("[iban]"))
        assertTrue(redacted.contains("[cnp]"))
        assertTrue(redacted.contains("[card]"))
        assertTrue(redacted.contains("[email]"))
        assertTrue(redacted.contains("[cod]"))
        assertFalse(redacted.contains("0722123456"))
        assertFalse(redacted.contains("RO49AAAA1B31007593840000"))
        assertFalse(redacted.contains("1960529123456"))
        assertFalse(redacted.contains("4111 1111 1111 1111"))
        assertFalse(redacted.contains("ana@example.com"))
        assertFalse(redacted.contains("123456"))
    }
}
