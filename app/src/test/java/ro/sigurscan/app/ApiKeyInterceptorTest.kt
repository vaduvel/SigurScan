package ro.sigurscan.app

import okhttp3.Call
import okhttp3.Connection
import okhttp3.Interceptor
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ApiKeyInterceptorTest {

    private class RecordingChain(private val original: Request) : Interceptor.Chain {
        var forwarded: Request? = null

        override fun request(): Request = original

        override fun proceed(request: Request): Response {
            forwarded = request
            return Response.Builder()
                .request(request)
                .protocol(Protocol.HTTP_1_1)
                .code(200)
                .message("OK")
                .build()
        }

        override fun connection(): Connection? = null
        override fun call(): Call = throw UnsupportedOperationException()
        override fun connectTimeoutMillis(): Int = 0
        override fun withConnectTimeout(timeout: Int, unit: java.util.concurrent.TimeUnit): Interceptor.Chain = this
        override fun readTimeoutMillis(): Int = 0
        override fun withReadTimeout(timeout: Int, unit: java.util.concurrent.TimeUnit): Interceptor.Chain = this
        override fun writeTimeoutMillis(): Int = 0
        override fun withWriteTimeout(timeout: Int, unit: java.util.concurrent.TimeUnit): Interceptor.Chain = this
    }

    private fun requestThrough(
        interceptor: ApiKeyInterceptor,
        path: String = "/v1/scan/url",
        method: String = "POST"
    ): Request {
        val builder = Request.Builder().url("https://backend.example$path")
        if (method == "POST") {
            builder.post(okhttp3.RequestBody.create(null, ByteArray(0)))
        }
        val chain = RecordingChain(builder.build())
        interceptor.intercept(chain)
        return requireNotNull(chain.forwarded)
    }

    @Test
    fun `adds api key header when key is configured`() {
        val forwarded = requestThrough(ApiKeyInterceptor("secret-key"))
        assertEquals("secret-key", forwarded.header(SIGURSCAN_API_KEY_HEADER))
        assertEquals(SIGURSCAN_USER_AGENT, forwarded.header("User-Agent"))
    }

    @Test
    fun `trims whitespace around configured key`() {
        val forwarded = requestThrough(ApiKeyInterceptor("  secret-key \n"))
        assertEquals("secret-key", forwarded.header(SIGURSCAN_API_KEY_HEADER))
    }

    @Test
    fun `does not add api key when key is blank`() {
        val forwarded = requestThrough(ApiKeyInterceptor("   "))
        assertNull(forwarded.header(SIGURSCAN_API_KEY_HEADER))
        assertEquals(SIGURSCAN_USER_AGENT, forwarded.header("User-Agent"))
    }

    @Test
    fun `does not add api key when key is null`() {
        val forwarded = requestThrough(ApiKeyInterceptor(null))
        assertNull(forwarded.header(SIGURSCAN_API_KEY_HEADER))
        assertEquals(SIGURSCAN_USER_AGENT, forwarded.header("User-Agent"))
    }

    @Test
    fun `adds client instance header when configured`() {
        val forwarded = requestThrough(
            ApiKeyInterceptor(
                rawApiKey = null,
                clientInstanceId = " android-install-1 "
            )
        )

        assertNull(forwarded.header(SIGURSCAN_API_KEY_HEADER))
        assertEquals("android-install-1", forwarded.header(SIGURSCAN_CLIENT_INSTANCE_HEADER))
    }

    @Test
    fun `adds play integrity header when token provider returns token`() {
        val forwarded = requestThrough(
            ApiKeyInterceptor(
                rawApiKey = "secret-key",
                integrityTokenProvider = { "  integrity-token \n" }
            )
        )

        assertEquals("integrity-token", forwarded.header(SIGURSCAN_PLAY_INTEGRITY_HEADER))
    }

    @Test
    fun `does not add play integrity header when token provider is blank`() {
        val forwarded = requestThrough(
            ApiKeyInterceptor(
                rawApiKey = "secret-key",
                integrityTokenProvider = { "   " }
            )
        )

        assertNull(forwarded.header(SIGURSCAN_PLAY_INTEGRITY_HEADER))
    }

    @Test
    fun `does not request play integrity token for nonce endpoint or get requests`() {
        var tokenRequests = 0
        val interceptor = ApiKeyInterceptor(
            rawApiKey = "secret-key",
            integrityTokenProvider = {
                tokenRequests += 1
                "integrity-token"
            }
        )

        val nonceRequest = requestThrough(interceptor, "/v1/security/play-integrity/nonce")
        val getRequest = requestThrough(interceptor, "/v1/reputation/cache/stats", method = "GET")

        assertNull(nonceRequest.header(SIGURSCAN_PLAY_INTEGRITY_HEADER))
        assertNull(getRequest.header(SIGURSCAN_PLAY_INTEGRITY_HEADER))
        assertEquals(0, tokenRequests)
    }

    @Test
    fun `normalizedApiKey rejects blank and keeps trimmed value`() {
        assertNull(normalizedApiKey(null))
        assertNull(normalizedApiKey(""))
        assertNull(normalizedApiKey("   "))
        assertEquals("abc", normalizedApiKey(" abc "))
    }
}
