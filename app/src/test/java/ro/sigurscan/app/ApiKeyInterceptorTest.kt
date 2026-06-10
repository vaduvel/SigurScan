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

    private fun requestThrough(interceptor: ApiKeyInterceptor): Request {
        val chain = RecordingChain(Request.Builder().url("https://backend.example/v1/scan/url").build())
        interceptor.intercept(chain)
        return requireNotNull(chain.forwarded)
    }

    @Test
    fun `adds api key header when key is configured`() {
        val forwarded = requestThrough(ApiKeyInterceptor("secret-key"))
        assertEquals("secret-key", forwarded.header(SIGURSCAN_API_KEY_HEADER))
    }

    @Test
    fun `trims whitespace around configured key`() {
        val forwarded = requestThrough(ApiKeyInterceptor("  secret-key \n"))
        assertEquals("secret-key", forwarded.header(SIGURSCAN_API_KEY_HEADER))
    }

    @Test
    fun `leaves request untouched when key is blank`() {
        val forwarded = requestThrough(ApiKeyInterceptor("   "))
        assertNull(forwarded.header(SIGURSCAN_API_KEY_HEADER))
    }

    @Test
    fun `leaves request untouched when key is null`() {
        val forwarded = requestThrough(ApiKeyInterceptor(null))
        assertNull(forwarded.header(SIGURSCAN_API_KEY_HEADER))
    }

    @Test
    fun `normalizedApiKey rejects blank and keeps trimmed value`() {
        assertNull(normalizedApiKey(null))
        assertNull(normalizedApiKey(""))
        assertNull(normalizedApiKey("   "))
        assertEquals("abc", normalizedApiKey(" abc "))
    }
}
