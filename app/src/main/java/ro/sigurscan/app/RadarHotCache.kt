package ro.sigurscan.app

import android.content.Context
import android.content.SharedPreferences
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Locale

data class RadarHotCacheSnapshot(
    val generatedAtEpochMillis: Long,
    val ttlMinutes: Int,
    val hotCampaigns: List<RadarHotCampaign> = emptyList(),
    val numberReputation: List<RadarNumberReputation> = emptyList()
) {
    fun isExpired(nowMillis: Long = System.currentTimeMillis()): Boolean {
        if (generatedAtEpochMillis <= 0L) return true
        val ttlMillis = ttlMinutes.coerceAtLeast(1).toLong() * 60L * 1000L
        return nowMillis - generatedAtEpochMillis > ttlMillis
    }
}

data class RadarCallDecision(
    val action: RadarCallAction,
    val reason: String,
    val family: String? = null,
    val warningTitle: String? = null,
    val warningBody: String? = null,
    val rejectCall: Boolean = false,
    val silenceCall: Boolean = false,
    val isKnownContact: Boolean = false
)

enum class RadarCallAction {
    ALLOW,
    WARN
}

data class RadarScreeningAudit(
    val checkedAtEpochMillis: Long,
    val action: RadarCallAction,
    val reason: String,
    val family: String? = null,
    val isKnownContact: Boolean = false
) {
    companion object {
        fun fromDecision(decision: RadarCallDecision, checkedAtEpochMillis: Long = System.currentTimeMillis()): RadarScreeningAudit {
            return RadarScreeningAudit(
                checkedAtEpochMillis = checkedAtEpochMillis,
                action = decision.action,
                reason = decision.reason,
                family = decision.family,
                isKnownContact = decision.isKnownContact
            )
        }
    }
}

object SpeakerGuardCallPromptPolicy {
    const val PROMPT_TTL_MS = 60_000L

    fun shouldOffer(decision: RadarCallDecision): Boolean {
        return !decision.isKnownContact
    }

    fun shouldOffer(audit: RadarScreeningAudit, nowMillis: Long = System.currentTimeMillis()): Boolean {
        val ageMillis = nowMillis - audit.checkedAtEpochMillis
        if (audit.checkedAtEpochMillis <= 0L || ageMillis < 0L || ageMillis > PROMPT_TTL_MS) return false
        return shouldOffer(
            RadarCallDecision(
                action = audit.action,
                reason = audit.reason,
                family = audit.family,
                isKnownContact = audit.isKnownContact
            )
        )
    }
}

object PhoneNumberHasher {
    fun normalizePhoneNumber(raw: String?): String {
        val value = raw.orEmpty().trim()
        if (value.isBlank()) return ""
        val digits = value.filter(Char::isDigit)
        if (digits.isBlank()) return ""
        return when {
            digits.startsWith("0040") && digits.length >= 6 -> "+40${digits.drop(4)}"
            digits.startsWith("40") && digits.length >= 5 -> "+$digits"
            digits.startsWith("0") && digits.length >= 10 -> "+40${digits.drop(1)}"
            value.startsWith("+") -> "+$digits"
            else -> digits
        }
    }

    fun hashPhone(raw: String?): String {
        val normalized = normalizePhoneNumber(raw)
        if (normalized.isBlank()) return ""
        return MessageDigest.getInstance("SHA-256")
            .digest(normalized.toByteArray(StandardCharsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
    }
}

object RadarCallDecider {
    fun decide(rawPhoneNumber: String?, cache: RadarHotCacheSnapshot?, nowMillis: Long = System.currentTimeMillis()): RadarCallDecision {
        if (cache == null || cache.isExpired(nowMillis)) {
            return RadarCallDecision(
                action = RadarCallAction.ALLOW,
                reason = "radar_cache_missing_or_expired"
            )
        }
        val phoneHash = PhoneNumberHasher.hashPhone(rawPhoneNumber)
        if (phoneHash.isBlank()) {
            return RadarCallDecision(action = RadarCallAction.ALLOW, reason = "phone_unavailable")
        }

        val reputationHit = cache.numberReputation.firstOrNull {
            it.phoneHash.equals(phoneHash, ignoreCase = true) &&
                it.status.orEmpty().lowercase(Locale.US) in ACTIONABLE_REPUTATION_STATUSES
        }
        if (reputationHit != null) {
            val normalizedStatus = reputationHit.status.orEmpty().lowercase(Locale.US)
            val shouldReject = normalizedStatus in REJECT_REPUTATION_STATUSES
            return RadarCallDecision(
                action = RadarCallAction.WARN,
                reason = "${normalizedStatus}_number_bucket_${reputationHit.bucketCount.orEmpty()}",
                family = reputationHit.family,
                warningTitle = "Număr semnalat în Radar",
                warningBody = if (shouldReject) {
                    "Numărul are reputație de risc ridicat în Radar. Apelul poate fi respins automat; verifică pe canal oficial."
                } else {
                    "Numărul apare în rapoarte recente. Nu oferi date sau bani; verifică pe canal oficial."
                },
                rejectCall = shouldReject,
                silenceCall = true
            )
        }

        val campaignHit = cache.hotCampaigns.firstOrNull { campaign ->
            campaign.phoneHashPrefixes.any { prefix ->
                prefix.isNotBlank() && phoneHash.lowercase(Locale.US).startsWith(prefix.lowercase(Locale.US))
            }
        }
        if (campaignHit != null) {
            return RadarCallDecision(
                action = RadarCallAction.WARN,
                reason = "campaign_hash_prefix_match",
                family = campaignHit.family,
                warningTitle = campaignHit.warningTitle,
                warningBody = campaignHit.warningBody,
                rejectCall = false,
                silenceCall = true
            )
        }

        return RadarCallDecision(action = RadarCallAction.ALLOW, reason = "no_radar_hit")
    }

    private val ACTIONABLE_REPUTATION_STATUSES = setOf("reported", "blocked", "dangerous", "high_confidence")
    private val REJECT_REPUTATION_STATUSES = setOf("blocked", "dangerous", "high_confidence")
}

class RadarScreeningAuditStore(
    private val prefs: SharedPreferences,
    private val gson: Gson = Gson()
) {
    fun save(audit: RadarScreeningAudit) {
        prefs.edit().putString(PREF_KEY, gson.toJson(audit)).apply()
    }

    fun load(): RadarScreeningAudit? {
        val raw = prefs.getString(PREF_KEY, null) ?: return null
        return runCatching {
            gson.fromJson<RadarScreeningAudit>(
                raw,
                object : TypeToken<RadarScreeningAudit>() {}.type
            )
        }.getOrNull()
    }

    companion object {
        private const val PREF_NAME = "sigurscan_radar_screening_audit"
        private const val PREF_KEY = "last_screening_v1"

        fun fromContext(context: Context): RadarScreeningAuditStore {
            return RadarScreeningAuditStore(context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE))
        }
    }
}

class RadarHotCacheStore(
    private val prefs: SharedPreferences,
    private val gson: Gson = Gson()
) {
    fun save(snapshot: RadarHotCacheSnapshot) {
        prefs.edit().putString(PREF_KEY, gson.toJson(snapshot)).apply()
    }

    fun load(): RadarHotCacheSnapshot? {
        val raw = prefs.getString(PREF_KEY, null) ?: return null
        return runCatching {
            gson.fromJson<RadarHotCacheSnapshot>(
                raw,
                object : TypeToken<RadarHotCacheSnapshot>() {}.type
            )
        }.getOrNull()
    }

    companion object {
        private const val PREF_NAME = "sigurscan_radar_hot_cache"
        private const val PREF_KEY = "snapshot_v1"

        fun fromContext(context: Context): RadarHotCacheStore {
            return RadarHotCacheStore(context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE))
        }
    }
}
