package ro.sigurscan.app

import android.Manifest
import android.annotation.SuppressLint
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat

class SpeakerGuardCallPromptNotifier private constructor(
    private val context: Context
) {
    fun showIfNeeded(decision: RadarCallDecision) {
        if (!BuildConfig.SIGURSCAN_ENABLE_AUDIO_ASR) return
        if (!SpeakerGuardCallPromptPolicy.shouldOffer(decision)) return
        if (!notificationsAllowed()) return
        ensureChannel()
        show(decision)
    }

    private fun notificationsAllowed(): Boolean {
        return Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU ||
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED
    }

    private fun ensureChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val manager = context.getSystemService(NotificationManager::class.java) ?: return
        val channel = NotificationChannel(
            CHANNEL_ID,
            "Urechea pentru apeluri",
            NotificationManager.IMPORTANCE_HIGH
        ).apply {
            description = "Prompt explicit când Radar detectează un apel care merită verificat."
        }
        manager.createNotificationChannel(channel)
    }

    @SuppressLint("MissingPermission")
    private fun show(decision: RadarCallDecision) {
        val prompt = speakerGuardCallPrompt(decision)
        val pendingIntent = PendingIntent.getActivity(
            context,
            REQUEST_CODE,
            SpeakerGuardPromptActivity.startIntent(context),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val notification = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentTitle(prompt.title)
            .setContentText(prompt.body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(prompt.body))
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setCategory(NotificationCompat.CATEGORY_CALL)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .setFullScreenIntent(pendingIntent, true)
            .addAction(R.drawable.ic_launcher_foreground, prompt.primaryCta, pendingIntent)
            .setTimeoutAfter(PROMPT_TIMEOUT_MS)
            .build()
        NotificationManagerCompat.from(context).notify(NOTIFICATION_ID, notification)
    }

    companion object {
        private const val CHANNEL_ID = "speaker_guard_call_prompt"
        private const val NOTIFICATION_ID = 4721
        private const val REQUEST_CODE = 4721
        private const val PROMPT_TIMEOUT_MS = 120_000L

        fun fromContext(context: Context): SpeakerGuardCallPromptNotifier {
            return SpeakerGuardCallPromptNotifier(context.applicationContext)
        }
    }
}
