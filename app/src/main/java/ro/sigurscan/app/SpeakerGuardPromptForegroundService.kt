package ro.sigurscan.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.util.Log
import android.widget.Toast
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat

class SpeakerGuardPromptForegroundService : Service() {
    private val handler = Handler(Looper.getMainLooper())

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return when (intent?.action) {
            ACTION_SHOW_CALL_PROMPT -> handleCallPrompt(intent, startId)
            else -> {
                stopSelf(startId)
                START_NOT_STICKY
            }
        }
    }

    override fun onDestroy() {
        handler.removeCallbacksAndMessages(null)
        super.onDestroy()
    }

    private fun handleCallPrompt(intent: Intent, startId: Int): Int {
        val decision = decisionFrom(intent)
        ensureChannel()
        startForeground(NOTIFICATION_ID, foregroundNotification(decision))
        SpeakerGuardCallPromptNotifier.fromContext(applicationContext).showIfNeeded(decision)
        showUnlockedIncomingCallNudge()
        handler.postDelayed({ stopSelf(startId) }, PROMPT_SERVICE_WINDOW_MS)
        return START_NOT_STICKY
    }

    private fun showUnlockedIncomingCallNudge() {
        Toast.makeText(
            applicationContext,
            "SigurScan: răspunde, pune pe difuzor, apoi folosește cardul de jos.",
            Toast.LENGTH_LONG
        ).show()
        Log.i(TAG, "speaker_guard_prompt_toast_shown")
    }

    private fun ensureChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val manager = getSystemService(NotificationManager::class.java) ?: return
        val channel = NotificationChannel(
            CHANNEL_ID,
            "Urechea prompt apel",
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = "Serviciu vizibil pentru promptul Urechea, fără captură audio."
        }
        manager.createNotificationChannel(channel)
    }

    private fun foregroundNotification(decision: RadarCallDecision): Notification {
        val prompt = speakerGuardCallPrompt(decision)
        val pendingIntent = PendingIntent.getActivity(
            this,
            FOREGROUND_REQUEST_CODE,
            SpeakerGuardPromptActivity.startIntent(this),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentTitle(prompt.title)
            .setContentText(prompt.body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(prompt.body))
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setOngoing(true)
            .setContentIntent(pendingIntent)
            .build()
    }

    companion object {
        private const val ACTION_SHOW_CALL_PROMPT = "ro.sigurscan.app.action.SHOW_SPEAKER_GUARD_CALL_PROMPT"
        private const val EXTRA_ACTION = "action"
        private const val EXTRA_REASON = "reason"
        private const val EXTRA_FAMILY = "family"
        private const val EXTRA_WARNING_TITLE = "warning_title"
        private const val EXTRA_WARNING_BODY = "warning_body"
        private const val EXTRA_REJECT_CALL = "reject_call"
        private const val EXTRA_SILENCE_CALL = "silence_call"
        private const val EXTRA_IS_KNOWN_CONTACT = "is_known_contact"
        private const val CHANNEL_ID = "speaker_guard_prompt_foreground"
        private const val NOTIFICATION_ID = 4731
        private const val FOREGROUND_REQUEST_CODE = 4731
        private const val PROMPT_SERVICE_WINDOW_MS = 12_000L
        private const val TAG = "SpeakerGuardPrompt"

        fun startForCallPrompt(context: Context, decision: RadarCallDecision) {
            if (!BuildConfig.SIGURSCAN_ENABLE_AUDIO_ASR) return
            if (!SpeakerGuardCallPromptPolicy.shouldOffer(decision)) return
            val intent = Intent(context, SpeakerGuardPromptForegroundService::class.java).apply {
                action = ACTION_SHOW_CALL_PROMPT
                putExtra(EXTRA_ACTION, decision.action.name)
                putExtra(EXTRA_REASON, decision.reason)
                putExtra(EXTRA_FAMILY, decision.family)
                putExtra(EXTRA_WARNING_TITLE, decision.warningTitle)
                putExtra(EXTRA_WARNING_BODY, decision.warningBody)
                putExtra(EXTRA_REJECT_CALL, decision.rejectCall)
                putExtra(EXTRA_SILENCE_CALL, decision.silenceCall)
                putExtra(EXTRA_IS_KNOWN_CONTACT, decision.isKnownContact)
            }
            ContextCompat.startForegroundService(context.applicationContext, intent)
        }

        private fun decisionFrom(intent: Intent): RadarCallDecision {
            val action = runCatching {
                RadarCallAction.valueOf(intent.getStringExtra(EXTRA_ACTION).orEmpty())
            }.getOrDefault(RadarCallAction.WARN)
            return RadarCallDecision(
                action = action,
                reason = intent.getStringExtra(EXTRA_REASON).orEmpty().ifBlank { "speaker_guard_prompt" },
                family = intent.getStringExtra(EXTRA_FAMILY),
                warningTitle = intent.getStringExtra(EXTRA_WARNING_TITLE),
                warningBody = intent.getStringExtra(EXTRA_WARNING_BODY),
                rejectCall = intent.getBooleanExtra(EXTRA_REJECT_CALL, false),
                silenceCall = intent.getBooleanExtra(EXTRA_SILENCE_CALL, false),
                isKnownContact = intent.getBooleanExtra(EXTRA_IS_KNOWN_CONTACT, false)
            )
        }
    }
}
