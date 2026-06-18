package ro.sigurscan.app

import okhttp3.Interceptor
import okhttp3.Response

internal const val SIGURSCAN_API_KEY_HEADER = "X-API-KEY"
internal const val SIGURSCAN_PLAY_INTEGRITY_HEADER = "X-Play-Integrity-Token"
internal const val SIGURSCAN_CLIENT_INSTANCE_HEADER = "X-SigurScan-Client-Instance"
internal const val SIGURSCAN_USER_AGENT = "SigurScan/1.0 Android OkHttp"
private val SIGURSCAN_INTEGRITY_GUARDED_PREFIXES =
    listOf("/v1/scan/", "/v1/extract/", "/v1/sandbox/urlscan")

internal fun normalizedApiKey(raw: String?): String? =
    raw?.trim()?.takeIf { it.isNotEmpty() }

internal fun shouldAttachPlayIntegrityToken(request: okhttp3.Request): Boolean =
    request.method == "POST" &&
        SIGURSCAN_INTEGRITY_GUARDED_PREFIXES.any { request.url.encodedPath.startsWith(it) }

/**
 * Atașează cheia de client pe fiecare request către backend. Cheia vine din
 * BuildConfig (local.properties / env la build), deci e doar o barieră
 * anti-abuz, nu autentificare reală — vezi docs/API_SECURITY.md.
 */
class ApiKeyInterceptor(
    rawApiKey: String?,
    clientInstanceId: String? = null,
    private val integrityTokenProvider: () -> String? = { null }
) : Interceptor {
    private val apiKey: String? = normalizedApiKey(rawApiKey)
    private val clientInstance: String? = normalizedApiKey(clientInstanceId)

    override fun intercept(chain: Interceptor.Chain): Response {
        val requestBuilder = chain.request().newBuilder()
            .header("User-Agent", SIGURSCAN_USER_AGENT)
        val key = apiKey
        if (key != null) {
            requestBuilder.header(SIGURSCAN_API_KEY_HEADER, key)
        }
        val instance = clientInstance
        if (instance != null) {
            requestBuilder.header(SIGURSCAN_CLIENT_INSTANCE_HEADER, instance)
        }
        if (shouldAttachPlayIntegrityToken(chain.request())) {
            val integrityToken = normalizedApiKey(integrityTokenProvider())
            if (integrityToken != null) {
                requestBuilder.header(SIGURSCAN_PLAY_INTEGRITY_HEADER, integrityToken)
            }
        }
        val request = requestBuilder.build()
        return chain.proceed(request)
    }
}
