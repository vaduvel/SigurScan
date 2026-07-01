package ro.sigurscan.app

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import java.util.UUID
import java.util.concurrent.TimeUnit

internal object SigurScanClientIdentity {
    fun securePrefs(context: Context): SharedPreferences {
        val appContext = context.applicationContext
        val encryptedPrefs = runCatching {
            val masterKey = MasterKey.Builder(appContext)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()

            EncryptedSharedPreferences.create(
                appContext,
                "sigurscan_prefs",
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )
        }.getOrNull()

        return encryptedPrefs ?: appContext.getSharedPreferences("sigurscan_prefs", Context.MODE_PRIVATE)
    }

    fun loadOrCreateClientInstanceId(context: Context): String {
        val prefs = securePrefs(context)
        val existing = prefs.getString("client_instance_id", null)
            ?.trim()
            ?.takeIf { it.length in 8..128 }
        if (existing != null) return existing

        val generated = UUID.randomUUID().toString()
        prefs.edit().putString("client_instance_id", generated).apply()
        return generated
    }
}

internal fun configuredSigurScanBackendBaseUrl(): String {
    val configured = BuildConfig.SIGURSCAN_BACKEND_BASE_URL.trim()
    val allowed = configured.takeIf {
        it.startsWith("https://", ignoreCase = true) ||
            (BuildConfig.DEBUG && it.startsWith("http://", ignoreCase = true))
    }
    return (allowed ?: "https://offline.sigurscan.invalid/")
        .let { if (it.endsWith("/")) it else "$it/" }
}

internal fun buildSigurScanApiClient(
    callTimeoutSeconds: Long,
    readTimeoutSeconds: Long,
    writeTimeoutSeconds: Long,
    connectTimeoutSeconds: Long,
    clientInstanceId: String? = null,
    integrityTokenProvider: () -> String? = { null }
): SigurScanApi {
    val logging = HttpLoggingInterceptor().apply {
        level = HttpLoggingInterceptor.Level.NONE
    }
    val client = OkHttpClient.Builder()
        .callTimeout(callTimeoutSeconds, TimeUnit.SECONDS)
        .readTimeout(readTimeoutSeconds, TimeUnit.SECONDS)
        .writeTimeout(writeTimeoutSeconds, TimeUnit.SECONDS)
        .connectTimeout(connectTimeoutSeconds, TimeUnit.SECONDS)
        .addInterceptor(
            ApiKeyInterceptor(
                rawApiKey = BuildConfig.SIGURSCAN_API_KEY,
                clientInstanceId = clientInstanceId,
                integrityTokenProvider = integrityTokenProvider
            )
        )
        .addInterceptor(logging)
        .build()

    return Retrofit.Builder()
        .baseUrl(configuredSigurScanBackendBaseUrl())
        .client(client)
        .addConverterFactory(GsonConverterFactory.create())
        .build()
        .create(SigurScanApi::class.java)
}
