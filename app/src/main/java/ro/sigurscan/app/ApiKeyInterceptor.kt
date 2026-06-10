package ro.sigurscan.app

import okhttp3.Interceptor
import okhttp3.Response

internal const val SIGURSCAN_API_KEY_HEADER = "X-API-KEY"

internal fun normalizedApiKey(raw: String?): String? =
    raw?.trim()?.takeIf { it.isNotEmpty() }

/**
 * Atașează cheia de client pe fiecare request către backend. Cheia vine din
 * BuildConfig (local.properties / env la build), deci e doar o barieră
 * anti-abuz, nu autentificare reală — vezi docs/API_SECURITY.md.
 */
class ApiKeyInterceptor(rawApiKey: String?) : Interceptor {
    private val apiKey: String? = normalizedApiKey(rawApiKey)

    override fun intercept(chain: Interceptor.Chain): Response {
        val key = apiKey ?: return chain.proceed(chain.request())
        val request = chain.request().newBuilder()
            .header(SIGURSCAN_API_KEY_HEADER, key)
            .build()
        return chain.proceed(request)
    }
}
