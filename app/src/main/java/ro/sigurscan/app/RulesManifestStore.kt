package ro.sigurscan.app

import android.content.Context
import android.content.SharedPreferences
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken

/**
 * P-RULES Felia 3 — device consumption of the semantic-rules manifest served by
 * /v1/rules/sync (backend Felia 1+2). Add-only plumbing: fetch + cache + a
 * manifest-driven matcher. It is NOT yet wired into detection — the on-device
 * rule engines stay the source of truth until backend<->Android parity is proven
 * (Felia 4). Mirrors BtrSyncStore.
 */
data class RulesManifestSnapshot(
    val version: String,
    val manifest: RulesManifestDto
) {
    companion object {
        fun fromResponse(response: RulesSyncResponse, existing: RulesManifestSnapshot?): RulesManifestSnapshot? {
            if (!response.changed) return existing
            val version = response.version?.takeIf { it.isNotBlank() } ?: return existing
            val manifest = response.manifest ?: return existing
            return RulesManifestSnapshot(version = version, manifest = manifest)
        }
    }
}

class RulesManifestStore(
    private val prefs: SharedPreferences,
    private val gson: Gson = Gson()
) {
    fun save(snapshot: RulesManifestSnapshot) {
        prefs.edit().putString(PREF_KEY, gson.toJson(snapshot)).apply()
    }

    fun load(): RulesManifestSnapshot? {
        val raw = prefs.getString(PREF_KEY, null) ?: return null
        return runCatching {
            gson.fromJson<RulesManifestSnapshot>(
                raw,
                object : TypeToken<RulesManifestSnapshot>() {}.type
            )
        }.getOrNull()
    }

    fun apply(response: RulesSyncResponse): RulesManifestSnapshot? {
        val snapshot = RulesManifestSnapshot.fromResponse(response, existing = load()) ?: return load()
        save(snapshot)
        return snapshot
    }

    companion object {
        private const val PREF_NAME = "sigurscan_rules_manifest"
        private const val PREF_KEY = "snapshot_v1"

        fun fromContext(context: Context): RulesManifestStore {
            return RulesManifestStore(context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE))
        }
    }
}

/**
 * Compiles the manifest patterns into Java [Regex] and matches text against them.
 *
 * The manifest patterns are authored for Python `re`; Java's regex engine is
 * close but not identical, so every pattern is compiled defensively — any that
 * Java cannot compile is collected in [unsupportedPatterns] instead of crashing.
 * That set is the backend<->Android parity signal: it must be empty (or explicitly
 * accepted) before Felia 4 flips the manifest on as the on-device source of truth.
 */
class RulesManifestMatcher(manifest: RulesManifestDto) {

    data class Unsupported(val group: String, val pattern: String, val error: String)

    val unsupportedPatterns: List<Unsupported>
    private val compiled: Map<String, List<Regex>>

    init {
        val groups = mutableMapOf<String, List<Regex>>()
        val bad = mutableListOf<Unsupported>()
        for ((group, patterns) in manifest.groups) {
            val regexes = mutableListOf<Regex>()
            for (p in patterns) {
                val options = if (p.flags.any { it.equals("IGNORECASE", ignoreCase = true) }) {
                    setOf(RegexOption.IGNORE_CASE)
                } else {
                    emptySet()
                }
                runCatching { Regex(p.pattern, options) }
                    .onSuccess { regexes.add(it) }
                    .onFailure { bad.add(Unsupported(group, p.pattern, it.message ?: it.javaClass.simpleName)) }
            }
            groups[group] = regexes
        }
        compiled = groups
        unsupportedPatterns = bad
    }

    /** Group names with at least one pattern matching [text]. */
    fun matchingGroups(text: String): Set<String> {
        if (text.isEmpty()) return emptySet()
        return compiled.filterValues { regexes -> regexes.any { it.containsMatchIn(text) } }.keys
    }
}
