package ro.sigurscan.app

import android.content.ClipData
import android.content.ClipDescription
import android.content.Intent
import android.net.Uri
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class SharedIntentStreamExtractorInstrumentedTest {
    @Test
    fun actionSendPlainTextMessageIsPlainTextOnly() {
        val message = "Coletul tău ajunge azi. Detalii: https://delivery.example.test/status"
        val intent = Intent(Intent.ACTION_SEND)
            .setType("text/plain")
            .putExtra(Intent.EXTRA_TEXT, message)

        val payload = resolveSharedTextPayload(intent)

        assertEquals(SharedContentFidelity.PLAIN_TEXT_ONLY, payload?.fidelity)
        assertEquals(false, payload?.preserveHtml)
        assertEquals("Conținut text partajat", payload?.sourceLabel)
        assertEquals(message, payload?.text)
    }

    @Test
    fun actionSendBrowserUrlIsPlainTextOnly() {
        val url = "https://sigurscan.example.test/articol"
        val intent = Intent(Intent.ACTION_SEND)
            .setType("text/plain")
            .putExtra(Intent.EXTRA_TEXT, url)

        val payload = resolveSharedTextPayload(intent)

        assertEquals(SharedContentFidelity.PLAIN_TEXT_ONLY, payload?.fidelity)
        assertEquals(false, payload?.preserveHtml)
        assertEquals(url, payload?.text)
    }

    @Test
    fun deepLinkScanTextPreservesEncodedNestedUrlQuery() {
        val nestedUrl = "https://example.com/search?q=a%2Bb&ref=sigurscan"
        val intent = Intent(
            Intent.ACTION_VIEW,
            Uri.parse("sigurscan://scan?text=${Uri.encode(nestedUrl)}")
        )

        assertEquals(nestedUrl, resolveDeepLinkScanText(intent))
    }

    @Test
    fun actionSendPrefersExtraHtmlTextOverVisibleText() {
        val html = """<a href="https://rides.sng.link/Aw5zn/hw3r?_fallback_redirect=https%3A%2F%2Fwww.uber.com">Comandă o cursă</a>"""
        val intent = Intent(Intent.ACTION_SEND)
            .setType("text/html")
            .putExtra(Intent.EXTRA_TEXT, "Comandă o cursă")
            .putExtra(Intent.EXTRA_HTML_TEXT, html)

        val payload = resolveSharedTextPayload(intent)

        assertEquals(SharedContentFidelity.FULL_HTML, payload?.fidelity)
        assertTrue(payload?.preserveHtml == true)
        assertEquals(html, payload?.text)
    }

    @Test
    fun clipDataHtmlTextIsTreatedAsFullHtml() {
        val html = """<button data-url="https://hidden.example.test/claim">Ridică premiul</button>"""
        val intent = Intent(Intent.ACTION_SEND).setType("text/html")
        intent.clipData = ClipData.newHtmlText("HTML mail", "Ridică premiul", html)

        val payload = resolveSharedTextPayload(intent)

        assertEquals(SharedContentFidelity.FULL_HTML, payload?.fidelity)
        assertTrue(payload?.preserveHtml == true)
        assertEquals("Conținut HTML din ClipData", payload?.sourceLabel)
        assertEquals(html, payload?.text)
    }

    @Test
    fun clipDataTextWithHtmlMimeIsTreatedAsFullHtml() {
        val html = """<span onclick="location.href='https://hidden.example.test/pay'">Plătește</span>"""
        val intent = Intent(Intent.ACTION_SEND).setType("text/html")
        intent.clipData = ClipData(
            ClipDescription("HTML mail", arrayOf("text/html")),
            ClipData.Item(html)
        )

        val payload = resolveSharedTextPayload(intent)

        assertEquals(SharedContentFidelity.FULL_HTML, payload?.fidelity)
        assertTrue(payload?.preserveHtml == true)
        assertEquals("Conținut HTML din ClipData", payload?.sourceLabel)
        assertEquals(html, payload?.text)
    }

    @Test
    fun actionSendMultipleCanCarryHtmlTextAndAttachmentsTogether() {
        val html = """<a href="https://email.example.test/action">Vezi detalii</a>"""
        val first = Uri.parse("content://ro.sigurscan.test/share/mail.eml")
        val second = Uri.parse("content://ro.sigurscan.test/share/invoice.pdf")
        val intent = Intent(Intent.ACTION_SEND_MULTIPLE)
            .setType("message/rfc822")
            .putExtra(Intent.EXTRA_HTML_TEXT, html)
            .putParcelableArrayListExtra(Intent.EXTRA_STREAM, arrayListOf(first, second))

        val payload = resolveSharedTextPayload(intent)

        assertEquals(SharedContentFidelity.FULL_HTML, payload?.fidelity)
        assertEquals(html, payload?.text)
        assertEquals(listOf(first, second), collectSharedStreamUris(intent))
    }

    @Test
    fun actionSendReadsSingleStreamUri() {
        val uri = Uri.parse("content://ro.sigurscan.test/share/email.eml")
        val intent = Intent(Intent.ACTION_SEND)
            .setType("message/rfc822")
            .putExtra(Intent.EXTRA_STREAM, uri)

        assertEquals(listOf(uri), collectSharedStreamUris(intent))
    }

    @Test
    fun actionSendReadsImageStreamUri() {
        val uri = Uri.parse("content://ro.sigurscan.test/share/screenshot.png")
        val intent = Intent(Intent.ACTION_SEND)
            .setType("image/png")
            .putExtra(Intent.EXTRA_STREAM, uri)

        assertEquals(listOf(uri), collectSharedStreamUris(intent))
    }

    @Test
    fun actionSendReadsPdfStreamUri() {
        val uri = Uri.parse("content://ro.sigurscan.test/share/invoice.pdf")
        val intent = Intent(Intent.ACTION_SEND)
            .setType("application/pdf")
            .putExtra(Intent.EXTRA_STREAM, uri)

        assertEquals(listOf(uri), collectSharedStreamUris(intent))
    }

    @Test
    fun actionSendMultipleReadsAllStreamUris() {
        val first = Uri.parse("content://ro.sigurscan.test/share/one.pdf")
        val second = Uri.parse("content://ro.sigurscan.test/share/two.png")
        val intent = Intent(Intent.ACTION_SEND_MULTIPLE)
            .setType("*/*")
            .putParcelableArrayListExtra(Intent.EXTRA_STREAM, arrayListOf(first, second))

        assertEquals(listOf(first, second), collectSharedStreamUris(intent))
    }

    @Test
    fun clipDataUrisAreIncludedAndDeduplicated() {
        val stream = Uri.parse("content://ro.sigurscan.test/share/body.html")
        val clipOnly = Uri.parse("content://ro.sigurscan.test/share/attachment.pdf")
        val contentResolver = InstrumentationRegistry.getInstrumentation()
            .targetContext
            .contentResolver
        val intent = Intent(Intent.ACTION_SEND)
            .setType("text/html")
            .putExtra(Intent.EXTRA_STREAM, stream)
        intent.clipData = ClipData.newUri(
            contentResolver,
            "SigurScan share",
            stream
        ).apply {
            addItem(ClipData.Item(clipOnly))
        }

        assertEquals(listOf(stream, clipOnly), collectSharedStreamUris(intent))
    }
}
