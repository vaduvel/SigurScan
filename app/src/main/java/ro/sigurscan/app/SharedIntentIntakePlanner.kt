package ro.sigurscan.app

import android.content.Intent
import android.net.Uri
import java.util.Locale

internal enum class SharedIntentAutoScan {
    NONE,
    TEXT,
    SINGLE_FILE
}

internal sealed interface SharedIntentIntakePlan {
    data class DeepLink(val text: String?) : SharedIntentIntakePlan
    data class Navigate(
        val destination: SharedIntentDestination,
        val autoStartSpeakerGuard: Boolean = false
    ) : SharedIntentIntakePlan

    data class SharedContent(
        val textPayload: ResolvedSharedTextPayload?,
        val streams: List<Uri>,
        val fallbackMime: String,
        val autoScan: SharedIntentAutoScan
    ) : SharedIntentIntakePlan

    data object Ignore : SharedIntentIntakePlan
}

internal enum class SharedIntentDestination {
    RADAR,
    SPEAKER_GUARD
}

internal interface SharedIntentIntakeSink {
    fun clear()
    fun showDeepLink(text: String?)
    fun navigate(destination: SharedIntentDestination, autoStartSpeakerGuard: Boolean)
    fun stageText(payload: ResolvedSharedTextPayload, preservePendingFiles: Boolean)
    fun stageFile(uri: Uri, fallbackMime: String, preserveSharedTextState: Boolean)
    fun scanText()
    fun scanSingleFile()
}

internal fun buildSharedIntentIntakePlan(intent: Intent?): SharedIntentIntakePlan {
    if (intent == null) return SharedIntentIntakePlan.Ignore

    if (intent.action == Intent.ACTION_VIEW && isDeepLinkScanIntent(intent)) {
        return SharedIntentIntakePlan.DeepLink(resolveDeepLinkScanText(intent))
    }
    if (intent.action == Intent.ACTION_VIEW && isDeepLinkRadarIntent(intent)) {
        return SharedIntentIntakePlan.Navigate(
            destination = resolveDeepLinkDestination(intent),
            autoStartSpeakerGuard = shouldAutoStartSpeakerGuard(intent)
        )
    }

    if (
        intent.action != Intent.ACTION_SEND &&
        intent.action != Intent.ACTION_SEND_MULTIPLE &&
        intent.action != Intent.ACTION_PROCESS_TEXT
    ) {
        return SharedIntentIntakePlan.Ignore
    }

    val streams = collectSharedStreamUris(intent)
    val sharedText = resolveSharedTextPayload(intent)
        ?: intent.getCharSequenceExtra(Intent.EXTRA_SUBJECT)
            ?.toString()
            ?.takeIf { it.isNotBlank() }
            ?.let { subject ->
                ResolvedSharedTextPayload(
                    text = subject,
                    sourceLabel = "Subiect",
                    preserveHtml = false,
                    fidelity = SharedContentFidelity.PLAIN_TEXT_ONLY
                )
            }

    if (sharedText == null && streams.isEmpty()) {
        return SharedIntentIntakePlan.Ignore
    }

    val autoScan = when {
        sharedText != null -> SharedIntentAutoScan.TEXT
        streams.size == 1 -> SharedIntentAutoScan.SINGLE_FILE
        else -> SharedIntentAutoScan.NONE
    }

    return SharedIntentIntakePlan.SharedContent(
        textPayload = sharedText,
        streams = streams,
        fallbackMime = intent.type?.lowercase(Locale.getDefault()).orEmpty(),
        autoScan = autoScan
    )
}

internal fun executeSharedIntentIntakePlan(
    plan: SharedIntentIntakePlan,
    sink: SharedIntentIntakeSink
) {
    when (plan) {
        is SharedIntentIntakePlan.DeepLink -> sink.showDeepLink(plan.text)
        is SharedIntentIntakePlan.Navigate -> sink.navigate(plan.destination, plan.autoStartSpeakerGuard)
        SharedIntentIntakePlan.Ignore -> Unit
        is SharedIntentIntakePlan.SharedContent -> {
            sink.clear()
            plan.textPayload?.let { payload ->
                sink.stageText(
                    payload = payload,
                    preservePendingFiles = plan.streams.isNotEmpty()
                )
            }
            plan.streams.forEach { stream ->
                sink.stageFile(
                    uri = stream,
                    fallbackMime = plan.fallbackMime,
                    preserveSharedTextState = plan.textPayload != null
                )
            }
            when (plan.autoScan) {
                SharedIntentAutoScan.NONE -> Unit
                SharedIntentAutoScan.TEXT -> sink.scanText()
                SharedIntentAutoScan.SINGLE_FILE -> sink.scanSingleFile()
            }
        }
    }
}

private fun shouldAutoStartSpeakerGuard(intent: Intent): Boolean {
    val data = intent.data ?: return false
    val target = data.host?.lowercase(Locale.getDefault())
        ?: data.path?.trim('/')?.lowercase(Locale.getDefault())
        ?: return false
    if (target != "speaker-guard") return false
    return data.getQueryParameter("autostart")
        ?.trim()
        ?.lowercase(Locale.getDefault()) in setOf("1", "true", "yes")
}
