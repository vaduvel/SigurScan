package ro.sigurscan.app

import android.content.Context
import com.google.android.gms.tasks.Tasks
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.IntegrityTokenRequest
import com.google.gson.Gson
import com.google.gson.annotations.SerializedName
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.util.concurrent.TimeUnit

interface IntegrityTokenSource {
    fun requestIntegrityToken(nonce: String): String?
}

interface IntegrityNonceSource {
    fun issueNonce(): String?
}

class PlayIntegrityTokenProvider(
    private val enabled: Boolean,
    private val source: IntegrityTokenSource,
    private val nonceSource: IntegrityNonceSource
) {
    fun currentToken(): String? {
        if (!enabled) return null
        val nonce = nonceSource.issueNonce()?.trim().orEmpty()
        if (nonce.isBlank()) return null
        return runCatching { source.requestIntegrityToken(nonce) }
            .getOrNull()
            ?.trim()
            ?.takeIf { it.isNotBlank() }
    }

    companion object {
        fun disabled(): PlayIntegrityTokenProvider =
            PlayIntegrityTokenProvider(
                enabled = false,
                source = NoopIntegrityTokenSource,
                nonceSource = NoopIntegrityNonceSource
            )

        fun fromContext(
            context: Context,
            backendBaseUrl: String,
            rawApiKey: String?,
            clientInstanceId: String?
        ): PlayIntegrityTokenProvider =
            PlayIntegrityTokenProvider(
                enabled = BuildConfig.SIGURSCAN_ENABLE_PLAY_INTEGRITY,
                source = PlayCoreIntegrityTokenSource(context.applicationContext),
                nonceSource = HttpIntegrityNonceSource(backendBaseUrl, rawApiKey, clientInstanceId)
            )
    }
}

private object NoopIntegrityTokenSource : IntegrityTokenSource {
    override fun requestIntegrityToken(nonce: String): String? = null
}

private object NoopIntegrityNonceSource : IntegrityNonceSource {
    override fun issueNonce(): String? = null
}

private data class IntegrityNonceResponse(
    val nonce: String? = null,
    @SerializedName("expires_in_seconds") val expiresInSeconds: Int? = null
)

internal class HttpIntegrityNonceSource(
    backendBaseUrl: String,
    rawApiKey: String?,
    clientInstanceId: String?
) : IntegrityNonceSource {
    private val endpoint = "${backendBaseUrl.trimEnd('/')}/v1/security/play-integrity/nonce"
    private val apiKey = normalizedApiKey(rawApiKey)
    private val clientInstance = normalizedApiKey(clientInstanceId)
    private val gson = Gson()
    private val client = OkHttpClient.Builder()
        .callTimeout(4, TimeUnit.SECONDS)
        .build()

    override fun issueNonce(): String? {
        val key = apiKey
        val instance = clientInstance ?: return null
        val builder = Request.Builder()
            .url(endpoint)
            .header(SIGURSCAN_CLIENT_INSTANCE_HEADER, instance)
            .header("User-Agent", SIGURSCAN_USER_AGENT)
            .post(ByteArray(0).toRequestBody("application/json".toMediaType()))
        if (key != null) {
            builder.header(SIGURSCAN_API_KEY_HEADER, key)
        }
        val request = builder.build()
        return client.newCall(request).execute().use { response ->
            if (!response.isSuccessful) return null
            gson.fromJson(response.body?.charStream(), IntegrityNonceResponse::class.java)
                ?.nonce
                ?.trim()
                ?.takeIf { it.isNotBlank() }
        }
    }
}

private class PlayCoreIntegrityTokenSource(context: Context) : IntegrityTokenSource {
    private val integrityManager = IntegrityManagerFactory.create(context)

    override fun requestIntegrityToken(nonce: String): String? {
        val request = IntegrityTokenRequest.builder()
            .setNonce(nonce)
            .build()
        val response = Tasks.await(
            integrityManager.requestIntegrityToken(request),
            4,
            TimeUnit.SECONDS
        )
        return response.token()
    }
}
