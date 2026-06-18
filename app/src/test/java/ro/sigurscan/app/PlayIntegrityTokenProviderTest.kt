package ro.sigurscan.app

import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PlayIntegrityTokenProviderTest {
    private class FakeNonceSource(private val nonce: String?) : IntegrityNonceSource {
        var requests = 0

        override fun issueNonce(): String? {
            requests += 1
            return nonce
        }
    }

    private class FakeSource(private val token: String?) : IntegrityTokenSource {
        val nonces = mutableListOf<String>()

        override fun requestIntegrityToken(nonce: String): String? {
            nonces += nonce
            return token
        }
    }

    @Test
    fun disabledProviderDoesNotRequestToken() {
        val source = FakeSource("token")
        val nonceSource = FakeNonceSource("nonce-1")
        val provider = PlayIntegrityTokenProvider(
            enabled = false,
            source = source,
            nonceSource = nonceSource
        )

        assertNull(provider.currentToken())
        assertTrue(source.nonces.isEmpty())
        assertEquals(0, nonceSource.requests)
    }

    @Test
    fun enabledProviderReturnsTrimmedToken() {
        val source = FakeSource("  integrity-token \n")
        val nonceSource = FakeNonceSource(" nonce-1 ")
        val provider = PlayIntegrityTokenProvider(
            enabled = true,
            source = source,
            nonceSource = nonceSource
        )

        assertEquals("integrity-token", provider.currentToken())
        assertEquals(listOf("nonce-1"), source.nonces)
    }

    @Test
    fun blankTokenIsNotForwarded() {
        val source = FakeSource("   ")
        val provider = PlayIntegrityTokenProvider(
            enabled = true,
            source = source,
            nonceSource = FakeNonceSource("nonce-1")
        )

        assertNull(provider.currentToken())
    }

    @Test
    fun missingBackendNonceDoesNotRequestPlayToken() {
        val source = FakeSource("token")
        val provider = PlayIntegrityTokenProvider(
            enabled = true,
            source = source,
            nonceSource = FakeNonceSource(null)
        )

        assertNull(provider.currentToken())
        assertTrue(source.nonces.isEmpty())
    }

    @Test
    fun httpNonceSourceCallsDedicatedEndpointWithClientInstance() {
        val server = MockWebServer()
        server.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setHeader("Content-Type", "application/json")
                .setBody("""{"nonce":" nonce-from-server ","expires_in_seconds":120}""")
        )
        server.start()
        try {
            val source = HttpIntegrityNonceSource(
                backendBaseUrl = server.url("/").toString(),
                rawApiKey = null,
                clientInstanceId = " android-install-1 "
            )

            assertEquals("nonce-from-server", source.issueNonce())
            val request = server.takeRequest()
            assertEquals("POST", request.method)
            assertEquals("/v1/security/play-integrity/nonce", request.path)
            assertNull(request.getHeader(SIGURSCAN_API_KEY_HEADER))
            assertEquals("android-install-1", request.getHeader(SIGURSCAN_CLIENT_INSTANCE_HEADER))
        } finally {
            server.shutdown()
        }
    }
}
