package ro.sigurscan.app

import android.content.ClipData
import android.content.ClipDescription
import android.content.Intent
import android.net.Uri
import android.text.SpannableString
import android.text.Spanned
import android.text.style.URLSpan
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
    fun deepLinkRadarPlansRadarNavigation() {
        val intent = Intent(Intent.ACTION_VIEW, Uri.parse("sigurscan://radar"))

        val plan = buildSharedIntentIntakePlan(intent)

        assertEquals(
            SharedIntentIntakePlan.Navigate(SharedIntentDestination.RADAR),
            plan
        )
    }

    @Test
    fun deepLinkSpeakerGuardPlansSpeakerGuardNavigation() {
        val intent = Intent(Intent.ACTION_VIEW, Uri.parse("sigurscan://speaker-guard"))

        val plan = buildSharedIntentIntakePlan(intent)

        assertEquals(
            SharedIntentIntakePlan.Navigate(SharedIntentDestination.SPEAKER_GUARD),
            plan
        )
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
    fun actionSendHtmlMimePreservesHtmlFromExtraText() {
        val html = """<a href="https://hidden.example.test/pay">Plătește factura</a>"""
        val intent = Intent(Intent.ACTION_SEND)
            .setType("text/html")
            .putExtra(Intent.EXTRA_TEXT, html)

        val payload = resolveSharedTextPayload(intent)

        assertEquals(SharedContentFidelity.FULL_HTML, payload?.fidelity)
        assertTrue(payload?.preserveHtml == true)
        assertEquals(html, payload?.text)
    }

    @Test
    fun actionSendSpannedTextPreservesUrlSpanAsHtml() {
        val visibleText = "Vezi factura"
        val spanned = SpannableString(visibleText).apply {
            setSpan(
                URLSpan("https://hidden.example.test/invoice"),
                0,
                visibleText.length,
                Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
            )
        }
        val intent = Intent(Intent.ACTION_SEND)
            .setType("text/plain")
            .putExtra(Intent.EXTRA_TEXT, spanned)

        val payload = resolveSharedTextPayload(intent)

        assertEquals(SharedContentFidelity.FULL_HTML, payload?.fidelity)
        assertTrue(payload?.preserveHtml == true)
        assertTrue(payload?.text?.contains("""href="https://hidden.example.test/invoice"""") == true)
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

    @Test
    fun htmlMailWithAttachmentPlansOneAtomicTextScanAfterStagingEverything() {
        val html = """<a href="https://hidden.example.test/pay">Vezi factura</a>"""
        val pdf = Uri.parse("content://ro.sigurscan.test/share/invoice.pdf")
        val intent = Intent(Intent.ACTION_SEND)
            .setType("message/rfc822")
            .putExtra(Intent.EXTRA_HTML_TEXT, html)
            .putExtra(Intent.EXTRA_STREAM, pdf)

        val plan = buildSharedIntentIntakePlan(intent)

        assertTrue(plan is SharedIntentIntakePlan.SharedContent)
        plan as SharedIntentIntakePlan.SharedContent
        assertEquals(SharedContentFidelity.FULL_HTML, plan.textPayload?.fidelity)
        assertEquals(listOf(pdf), plan.streams)
        assertEquals(SharedIntentAutoScan.TEXT, plan.autoScan)
    }

    @Test
    fun multipleAttachmentsWithoutTextAreStagedForIndividualScanning() {
        val first = Uri.parse("content://ro.sigurscan.test/share/one.pdf")
        val second = Uri.parse("content://ro.sigurscan.test/share/two.png")
        val intent = Intent(Intent.ACTION_SEND_MULTIPLE)
            .setType("*/*")
            .putParcelableArrayListExtra(Intent.EXTRA_STREAM, arrayListOf(first, second))

        val plan = buildSharedIntentIntakePlan(intent)

        assertTrue(plan is SharedIntentIntakePlan.SharedContent)
        plan as SharedIntentIntakePlan.SharedContent
        assertEquals(listOf(first, second), plan.streams)
        assertEquals(SharedIntentAutoScan.NONE, plan.autoScan)
    }

    @Test
    fun subjectOnlyShareFallsBackToTextScan() {
        val intent = Intent(Intent.ACTION_SEND)
            .setType("message/rfc822")
            .putExtra(Intent.EXTRA_SUBJECT, "Confirmă plata facturii")

        val plan = buildSharedIntentIntakePlan(intent)

        assertTrue(plan is SharedIntentIntakePlan.SharedContent)
        plan as SharedIntentIntakePlan.SharedContent
        assertEquals("Confirmă plata facturii", plan.textPayload?.text)
        assertEquals("Subiect", plan.textPayload?.sourceLabel)
        assertEquals(SharedIntentAutoScan.TEXT, plan.autoScan)
    }

    @Test
    fun executorStagesTextAndEveryAttachmentBeforeStartingTextScan() {
        val html = """<a href="https://hidden.example.test/pay">Vezi factura</a>"""
        val first = Uri.parse("content://ro.sigurscan.test/share/mail.eml")
        val second = Uri.parse("content://ro.sigurscan.test/share/invoice.pdf")
        val events = mutableListOf<String>()
        val sink = object : SharedIntentIntakeSink {
            override fun clear() {
                events += "clear"
            }

            override fun showDeepLink(text: String?) {
                events += "deep:$text"
            }

            override fun navigate(destination: SharedIntentDestination) {
                events += "navigate:$destination"
            }

            override fun stageText(payload: ResolvedSharedTextPayload, preservePendingFiles: Boolean) {
                events += "text:${payload.fidelity}:$preservePendingFiles"
            }

            override fun stageFile(uri: Uri, fallbackMime: String, preserveSharedTextState: Boolean) {
                events += "file:$uri:$preserveSharedTextState"
            }

            override fun scanText() {
                events += "scan:text"
            }

            override fun scanSingleFile() {
                events += "scan:file"
            }
        }
        val plan = SharedIntentIntakePlan.SharedContent(
            textPayload = ResolvedSharedTextPayload(
                text = html,
                sourceLabel = "Conținut HTML partajat",
                preserveHtml = true,
                fidelity = SharedContentFidelity.FULL_HTML
            ),
            streams = listOf(first, second),
            fallbackMime = "message/rfc822",
            autoScan = SharedIntentAutoScan.TEXT
        )

        executeSharedIntentIntakePlan(plan, sink)

        assertEquals(
            listOf(
                "clear",
                "text:FULL_HTML:true",
                "file:$first:true",
                "file:$second:true",
                "scan:text"
            ),
            events
        )
    }
}
