package ro.sigurscan.app

import android.content.Context
import android.content.SharedPreferences
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken

data class BtrSyncSnapshot(
    val version: String,
    val generatedAt: String? = null,
    val manifests: List<BtrManifest> = emptyList()
) {
    companion object {
        fun fromResponse(response: BtrSyncResponse, existing: BtrSyncSnapshot?): BtrSyncSnapshot? {
            if (!response.changed) return existing
            val version = response.version?.takeIf { it.isNotBlank() } ?: return existing
            return BtrSyncSnapshot(
                version = version,
                generatedAt = response.generatedAt,
                manifests = response.manifests.orEmpty()
            )
        }
    }
}

class BtrSyncStore(
    private val prefs: SharedPreferences,
    private val gson: Gson = Gson()
) {
    fun save(snapshot: BtrSyncSnapshot) {
        prefs.edit().putString(PREF_KEY, gson.toJson(snapshot)).apply()
    }

    fun load(): BtrSyncSnapshot? {
        val raw = prefs.getString(PREF_KEY, null) ?: return null
        return runCatching {
            gson.fromJson<BtrSyncSnapshot>(
                raw,
                object : TypeToken<BtrSyncSnapshot>() {}.type
            )
        }.getOrNull()
    }

    fun apply(response: BtrSyncResponse): BtrSyncSnapshot? {
        val snapshot = BtrSyncSnapshot.fromResponse(response, existing = load()) ?: return load()
        save(snapshot)
        return snapshot
    }

    companion object {
        private const val PREF_NAME = "sigurscan_btr_sync"
        private const val PREF_KEY = "snapshot_v1"

        fun fromContext(context: Context): BtrSyncStore {
            return BtrSyncStore(context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE))
        }
    }
}
