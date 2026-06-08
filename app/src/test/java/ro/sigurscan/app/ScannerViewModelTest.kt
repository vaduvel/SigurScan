package ro.sigurscan.app

import org.junit.Test
import org.junit.Assert.*
import java.io.File

class ScannerViewModelTest {

    private fun extractHtmlLinks(content: String): List<String> {
        return HtmlLinkExtractor.extractHtmlLinks(content)
    }

    @Test
    fun uploadedMediaAndMailUseOrchestratedPipelineAfterExtraction() {
        val viewModelSource = File("src/main/java/ro/sigurscan/app/ScannerViewModel.kt").readText()
        val apiSource = File("src/main/java/ro/sigurscan/app/SigurScanApi.kt").readText()
        val forbiddenDirectFinalScans = Regex("""api\.scan(?:Image|Pdf|Email)\(""")
        val forbiddenLegacyEndpoints = listOf(
            """@POST("v1/scan/image")""",
            """@POST("v1/scan/pdf")""",
            """@POST("v1/scan/email")""",
            """@POST("v1/scan/text")""",
            """@POST("v1/scan/url")"""
        )

        assertFalse(
            "Image/PDF/email UI flows must not call legacy final scan endpoints directly. " +
                "They may extract content, but final verdict must go through startOrchestratedScan + polling.",
            forbiddenDirectFinalScans.containsMatchIn(viewModelSource)
        )
        forbiddenLegacyEndpoints.forEach { endpoint ->
            assertFalse(
                "Android Retrofit API must not expose legacy final verdict endpoint $endpoint. " +
                    "Use extract endpoints for intake and /v1/scan/orchestrated for verdict.",
                apiSource.contains(endpoint)
            )
        }
    }

    @Test
    fun localOfflineEvaluatorStaysNeutralAndCannotEmitRiskVerdict() {
        val viewModelSource = File("src/main/java/ro/sigurscan/app/ScannerViewModel.kt").readText()
        val start = viewModelSource.indexOf("private fun evaluateOfflineText(scannedText: String): OfflineAssessment")
        val end = viewModelSource.indexOf("fun onCommunityReport()", start)
        assertTrue("evaluateOfflineText must exist as a neutral pending-state builder.", start >= 0 && end > start)

        val functionBody = viewModelSource.substring(start, end)
        assertTrue(functionBody.contains("""riskLevel = "unknown""""))
        assertTrue(functionBody.contains("""riskScore = 0"""))
        assertFalse(functionBody.contains("""riskLevel = "low""""))
        assertFalse(functionBody.contains("""riskLevel = "medium""""))
        assertFalse(functionBody.contains("""riskLevel = "high""""))
        assertFalse(functionBody.contains("PERICULOS"))
        assertFalse(functionBody.contains("SUSPECT"))
        assertFalse(functionBody.contains("SIGUR"))
    }

    @Test
    fun testHtmlLinkExtraction() {
        val html = """
            <html>
                <body>
                    <p>Click pe butonul de mai jos:</p>
                    <a href="https://confirmare-plata.ru/anaf">CONFIRMARE</a>
                </body>
            </html>
        """.trimIndent()
        val links = extractHtmlLinks(html)
        assertEquals(1, links.size)
        assertEquals("https://confirmare-plata.ru/anaf", links[0])
    }

    @Test
    fun testHiddenButtonOnclickLinkExtraction() {
        val html = """
            <html>
                <body>
                    <button onclick="window.location.href='https://scam-example.com/verify'">Apasă aici</button>
                </body>
            </html>
        """.trimIndent()

        val links = extractHtmlLinks(html)
        assertTrue(links.contains("https://scam-example.com/verify"))
    }

    @Test
    fun testFormActionLinkExtraction() {
        val html = """
            <form action="https://phishing.example.net/login">
                <button type="submit">Confirmă cont</button>
            </form>
        """.trimIndent()
        val links = extractHtmlLinks(html)
        assertTrue(links.contains("https://phishing.example.net/login"))
    }

    @Test
    fun testDataAndObfuscatedLinkExtraction() {
        val html = """
            <html>
                <body>
                    <a data-href="https://hidden.example.org/track">Apasă aici</a>
                    <div onclick="window.open('https://popup.example.org/landing')">Mai jos</div>
                </body>
            </html>
        """.trimIndent()
        val links = extractHtmlLinks(html)
        assertTrue(links.contains("https://hidden.example.org/track"))
        assertTrue(links.contains("https://popup.example.org/landing"))
    }

    @Test
    fun testFormActionAndOnsubmitLinkExtraction() {
        val html = """
            <html>
                <body>
                    <form action="https://checkout.example.net/confirm" onsubmit="return false;">
                        <button type="submit" formaction="https://fallback.example.net/submit">Trimite</button>
                    </form>
                </body>
            </html>
        """.trimIndent()
        val links = extractHtmlLinks(html)
        assertTrue(links.contains("https://checkout.example.net/confirm"))
        assertTrue(links.contains("https://fallback.example.net/submit"))
    }

    @Test
    fun testScriptRedirectEncodedLinkExtraction() {
        val encoded = "aHR0cHM6Ly9wcm9uY2UuZXhhbXBsZS5uZXQvaW9uZXQ/cD05"
        val html = """
            <html>
                <body>
                    <button onclick="window.location.assign(atob('$encoded')); return false;">Continuă</button>
                </body>
            </html>
        """.trimIndent()
        val links = extractHtmlLinks(html)
        assertTrue(links.contains("https://pronce.example.net/ionet?p=9"))
    }

    @Test
    fun testStyleAndDataSourceLinkExtraction() {
        val html = """
            <html>
                <body>
                    <div style="background:url('https://style-trace.example.net/overlay.png')">Click mai jos</div>
                    <button data-action="https://meta-action.example.net/track">Verifică</button>
                </body>
            </html>
        """.trimIndent()
        val links = extractHtmlLinks(html)
        assertTrue(links.contains("https://style-trace.example.net/overlay.png"))
        assertTrue(links.contains("https://meta-action.example.net/track"))
    }

    @Test
    fun testStyleBlockLinkExtraction() {
        val html = """
            <html>
                <head>
                    <style>
                        .hero { background-image: url(https://css-background.example.net/banner.png); }
                        @import url("https://css-import.example.net/import.css");
                    </style>
                </head>
            </html>
        """.trimIndent()
        val links = extractHtmlLinks(html)
        assertTrue(links.contains("https://css-background.example.net/banner.png"))
        assertTrue(links.contains("https://css-import.example.net/import.css"))
    }

    @Test
    fun testBase64ObfuscationLinkExtraction() {
        val encoded = "aHR0cHM6Ly9iYXNlNjQuZXhhbXBsZS5uZXQvY2hlY2suZG9uZQ=="
        val html = """
            <a onclick="window.location = atob('$encoded')">Continuă</a>
        """.trimIndent()
        val links = extractHtmlLinks(html)
        assertTrue(links.contains("https://base64.example.net/check.done"))
    }

    @Test
    fun testConcatenatedScriptLinkExtraction() {
        val html = """
            <button onclick="window.location.href='https://' + 'concat-test.example.net' + '/unlock'">Apasă aici</button>
        """.trimIndent()
        val links = extractHtmlLinks(html)
        assertTrue(links.contains("https://concat-test.example.net/unlock"))
    }

    @Test
    fun testHarderObfuscatedScriptLinkExtraction() {
        val encodedUrl = "aHR0cHM6Ly9sb2dpbi5leGFtcGxlLm5ldC92ZXJpZnk="
        val html = """
            <button onclick="window.location='https://' + 'hard' + '-test' + '.example.net' + '/verify?step=1'">Pas 1</button>
            <a onclick="window.open(atob('$encodedUrl'))">Pas 2</a>
            <a href="https://&#x68;&#x61;&#x72;&#x64;&#x65;&#x72;&#x2d;&#x65;&#x6e;&#x74;&#x69;&#x74;&#x79;.example.net/decode">
                Pas 3
            </a>
            <div onmouseover="location.href=unescape('https%3A%2F%2Funescape.example.net%2Fwarn')">Pas 4</div>
            <a onclick="location.assign(decodeURIComponent('https%3A%2F%2Fdecode.example.net%2Fpath'))">Pas 5</a>
        <form onsubmit="window.location.replace('https://%65%78%61%6d%70%6c%65.com/%66%69%6c%74%72%61%74%65')">Pas 6</form>
        """.trimIndent()
        val links = extractHtmlLinks(html)
        val extractedMessage = "Extracted links: ${links.joinToString(", ")}"
        assertTrue(extractedMessage, links.contains("https://hard-test.example.net/verify?step=1"))
        assertTrue(extractedMessage, links.contains("https://login.example.net/verify"))
        assertTrue(extractedMessage, links.contains("https://harder-entity.example.net/decode"))
        assertTrue(extractedMessage, links.contains("https://unescape.example.net/warn"))
        assertTrue(extractedMessage, links.contains("https://decode.example.net/path"))
        assertTrue(extractedMessage, links.contains("https://example.com/filtrate"))
    }

    @Test
    fun testHtmlEntityEncodedLinkExtraction() {
        val html = """
            <a href="https://&#x65;&#x78;&#x61;&#x6d;&#x70;&#x6c;&#x65;&#x2e;&#x63;&#x6f;&#x6d;">link</a>
            <a href="https://&#101;&#120;&#97;&#109;&#112;&#108;&#101;&#46;&#99;&#111;&#109;/entity">entity</a>
        """.trimIndent()
        val links = extractHtmlLinks(html)
        assertTrue(links.contains("https://example.com"))
        assertTrue(links.contains("https://example.com/entity"))
    }

    @Test
    fun testSelfLocationRedirectLinkExtraction() {
        val html = """
            <button onclick="self.location='https://self-link.example.org/verify'">Apasă mai jos</button>
        """.trimIndent()
        val links = extractHtmlLinks(html)
        assertTrue(links.contains("https://self-link.example.org/verify"))
    }

    @Test
    fun testMetaRefreshLinkExtraction() {
        val html = """
            <meta http-equiv="refresh" content="0;url=https://meta-refresh.example.com/redirect" />
        """.trimIndent()
        val links = extractHtmlLinks(html)
        assertTrue(links.contains("https://meta-refresh.example.com/redirect"))
    }

    @Test
    fun testScriptBlockLinkExtraction() {
        val encoded = "aHR0cHM6Ly9zY3JpcHQuZXhhbXBsZS5jb20vc2NyaXB0"
        val html = """
            <script>
              const base = 'https://';
              const host = 'script-block.example.com';
              const path = '/payload';
              window.location.href = base + host + path;
              window.open(atob('$encoded'));
              location.assign('https://assign.example.com/next');
            </script>
        """.trimIndent()
        val links = extractHtmlLinks(html)
        val extractedMessage = "Extracted links: ${links.joinToString(", ")}"
        assertTrue(extractedMessage, links.contains("https://script-block.example.com/payload"))
        assertTrue(extractedMessage, links.contains("https://script.example.com/script"))
        assertTrue(extractedMessage, links.contains("https://assign.example.com/next"))
    }

    @Test
    fun testSrcSetAndHiddenWrapperLinkExtraction() {
        val html = """
            <div onpointerdown="window.location='https://pointer-down.example.net/route'">
                <img srcset="/fallback 1x, https://imgset.example.net/photo.jpg 2x" alt="img">
            </div>
        """.trimIndent()
        val links = extractHtmlLinks(html)
        assertTrue(links.contains("https://pointer-down.example.net/route"))
        assertTrue(links.contains("https://imgset.example.net/photo.jpg"))
    }

    @Test
    fun testTemplateLiteralScriptLinkExtraction() {
        val html = """
            <script>
              const domain = 'template-link.example.com';
              const path = '/payload';
              window.location.href = `https://${'$'}{domain}${'$'}{path}`;
            </script>
        """.trimIndent()
        val links = extractHtmlLinks(html)
        assertTrue(links.contains("https://template-link.example.com/payload"))
    }

    @Test
    fun testVariableAliasLinkExtraction() {
        val html = """
            <script>
              const base = 'https://';
              const host = 'alias-link.example.com';
              const path = '/safe';
              const link = base + host + path;
              window.location = link;
            </script>
        """.trimIndent()
        val links = extractHtmlLinks(html)
        assertTrue(links.contains("https://alias-link.example.com/safe"))
    }

    @Test
    fun testBaseHrefResolvesRelativeButtonTarget() {
        val html = """
            <html>
                <head><base href="https://homebank-update.test/secure/"></head>
                <body><a href="../login">Actualizează HomeBank</a></body>
            </html>
        """.trimIndent()

        val links = extractHtmlLinks(html)
        assertTrue(links.contains("https://homebank-update.test/login"))
    }

    @Test
    fun testConditionalMsoAndVmlLinksAreExtracted() {
        val html = """
            <!--[if mso]>
              <v:roundrect href="https://bcr.ro/login">Intră în cont</v:roundrect>
            <![endif]-->
            <!--[if !mso]><!-->
              <a href="https://bcr-login-alert.test/login">Intră în cont</a>
            <!--<![endif]-->
        """.trimIndent()

        val links = extractHtmlLinks(html)
        assertTrue(links.contains("https://bcr.ro/login"))
        assertTrue(links.contains("https://bcr-login-alert.test/login"))
    }

    @Test
    fun testGenericOpenRedirectTargetIsExtracted() {
        val html = """
            <a href="https://trusted.example.com/redirect?next=https%3A%2F%2Fevil-landing.test%2Flogin">Continuă</a>
        """.trimIndent()

        val links = extractHtmlLinks(html)
        assertTrue(links.contains("https://evil-landing.test/login"))
    }

    @Test
    fun testUserInfoAtUrlKeepsActualHostCandidate() {
        val html = """<a href="https://bcr.ro@evil-bank.test/login">bcr.ro</a>"""

        val links = extractHtmlLinks(html)
        assertTrue(links.contains("https://bcr.ro@evil-bank.test/login"))
    }

    @Test
    fun testUnicodeIdnHostIsExtractedAsPunycode() {
        val html = """<a href="https://еmag.ro/login">eMAG</a>"""

        val links = extractHtmlLinks(html)
        assertTrue(links.contains("https://xn--mag-qdd.ro/login"))
    }

}
