package ro.sigurscan.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class EmailMessageParserTest {

    @Test
    fun testMultipartEmailReturnsHtmlFirst() {
        val raw = """
            From: test@example.com
            To: user@example.com
            Subject: Confirmare
            MIME-Version: 1.0
            Content-Type: multipart/alternative; boundary="mix"
            
            --mix
            Content-Type: text/plain; charset="UTF-8"
            Content-Transfer-Encoding: quoted-printable
            
            Link text: https://text.example.com/plain
            =D0=9C =D1=8D =D1=82
            --mix
            Content-Type: text/html; charset="UTF-8"
            Content-Transfer-Encoding: quoted-printable
            
            <html><body><p>Confirma aici</p><a href="https://hidden.example.com/confirm">Apasa</a></body></html>
            --mix--
        """.trimIndent()

        val parsed = EmailMessageParser.parse(raw)
        assertTrue(parsed.htmlText.contains("https://hidden.example.com/confirm"))
        assertTrue(parsed.plainText.contains("https://text.example.com/plain"))
        assertTrue(parsed.bodyForAnalysis.contains("Apasa"))
    }

    @Test
    fun testBase64PartDecodingForHtml() {
        val html = "PHRoaXMgaXMgYSBzYW1wbGUgPHNhZmU+IGxpbms6IGh0dHBzOi8vYmFzZTY0LmV4YW1wbGUuY29tL2xpbms8L3NhZmU+"
        val raw = """
            Content-Type: text/html; charset="UTF-8"
            Content-Transfer-Encoding: base64
            
            $html
        """.trimIndent()

        val parsed = EmailMessageParser.parse(raw)
        assertTrue(parsed.htmlText.contains("https://base64.example.com/link"))
    }

    @Test
    fun testSvgAttachmentIsIncludedAsHtmlForLinkExtraction() {
        val svg = "PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPjxhIHhsaW5rOmhyZWY9Imh0dHBzOi8vc3ZnLWF0dGFjaG1lbnQudGVzdC9wYXkiPjx0ZXh0PlBsYXRlc3RlPC90ZXh0PjwvYT48L3N2Zz4="
        val raw = """
            From: courier@example.com
            To: user@example.com
            Subject: AWB
            MIME-Version: 1.0
            Content-Type: multipart/mixed; boundary="mix"
            
            --mix
            Content-Type: text/plain; charset="UTF-8"
            
            Verifică atașamentul.
            --mix
            Content-Type: image/svg+xml; name="awb.svg"
            Content-Disposition: attachment; filename="awb.svg"
            Content-Transfer-Encoding: base64
            
            $svg
            --mix--
        """.trimIndent()

        val parsed = EmailMessageParser.parse(raw)
        val links = HtmlLinkExtractor.extractHtmlLinks(parsed.bodyForAnalysis)
        assertTrue(parsed.htmlText.contains("svg-attachment.test/pay"))
        assertTrue(links.contains("https://svg-attachment.test/pay"))
    }
}
