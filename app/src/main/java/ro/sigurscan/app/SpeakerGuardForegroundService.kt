package ro.sigurscan.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.Uri
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import java.util.concurrent.TimeUnit

object SpeakerGuardForegroundServiceEvents {
    private val _updates = MutableSharedFlow<SpeakerGuardUpdate>(replay = 1, extraBufferCapacity = 64)
    val updates: SharedFlow<SpeakerGuardUpdate> = _updates.asSharedFlow()

    fun publish(update: SpeakerGuardUpdate) {
        _updates.tryEmit(update)
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    fun clear() {
        _updates.resetReplayCache()
    }
}

class SpeakerGuardForegroundService : Service() {
    private val handler = Handler(Looper.getMainLooper())
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var captureSession: SpeakerGuardSession? = null
    private val audioSemanticApi: SigurScanApi by lazy { buildAudioSemanticApi() }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return when (intent?.action) {
            ACTION_SHOW_CALL_PROMPT -> handleCallPrompt(intent, startId)
            ACTION_START_CAPTURE -> handleStartCapture(intent, startId)
            ACTION_STOP_CAPTURE -> {
                stopCaptureSession()
                stopSelf(startId)
                START_NOT_STICKY
            }
            else -> {
                stopSelf(startId)
                START_NOT_STICKY
            }
        }
    }

    override fun onDestroy() {
        handler.removeCallbacksAndMessages(null)
        stopCaptureSession(removeForeground = false)
        serviceScope.cancel()
        super.onDestroy()
    }

    private fun handleCallPrompt(intent: Intent, startId: Int): Int {
        val decision = decisionFrom(intent)
        ensureChannel()
        val notification = foregroundNotification(decision)
        startForeground(NOTIFICATION_ID, notification)
        SpeakerGuardCallPromptNotifier.fromContext(applicationContext).showIfNeeded(decision)
        handler.postDelayed({ stopSelf(startId) }, PROMPT_SERVICE_WINDOW_MS)
        return START_NOT_STICKY
    }

    private fun handleStartCapture(intent: Intent, startId: Int): Int {
        val modelPath = intent.getStringExtra(EXTRA_MODEL_PATH).orEmpty()
        if (modelPath.isBlank()) {
            SpeakerGuardForegroundServiceEvents.publish(
                SpeakerGuardUpdate(
                    phase = SpeakerGuardPhase.ERROR,
                    active = false,
                    reasonCode = "asr_model_missing",
                    status = "Modelul audio local lipsește."
                )
            )
            stopSelf(startId)
            return START_NOT_STICKY
        }

        ensureChannel()
        startCaptureForeground()
        if (captureSession?.active == true) return START_STICKY

        val session = SpeakerGuardSession(
            context = applicationContext,
            semanticReviewer = BackendAudioSemanticReviewer(audioSemanticApi, channel = "call_live")
        )
        captureSession = session
        session.start(serviceScope, modelPath) { update ->
            SpeakerGuardForegroundServiceEvents.publish(update)
            if (!update.active && update.phase != SpeakerGuardPhase.PROCESSING) {
                stopCaptureSession()
                stopSelf(startId)
            }
        }
        return START_STICKY
    }

    private fun ensureChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val manager = getSystemService(NotificationManager::class.java) ?: return
        val channel = NotificationChannel(
            CHANNEL_ID,
            "Urechea SigurScan",
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = "Serviciu vizibil pentru promptul Urechea în timpul apelurilor."
        }
        manager.createNotificationChannel(channel)
    }

    private fun startCaptureForeground() {
        val notification = captureNotification()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(
                CAPTURE_NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE
            )
        } else {
            startForeground(CAPTURE_NOTIFICATION_ID, notification)
        }
    }

    private fun foregroundNotification(decision: RadarCallDecision): Notification {
        val prompt = speakerGuardCallPrompt(decision)
        val intent = speakerGuardDeepLinkIntent(this)
        val pendingIntent = PendingIntent.getActivity(
            this,
            FOREGROUND_REQUEST_CODE,
            intent,
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

    private fun captureNotification(): Notification {
        val intent = speakerGuardDeepLinkIntent(this)
        val pendingIntent = PendingIntent.getActivity(
            this,
            CAPTURE_REQUEST_CODE,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentTitle("Urechea ascultă")
            .setContentText("Analiza rulează local. Ține apelul pe difuzor.")
            .setStyle(NotificationCompat.BigTextStyle().bigText("Analiza rulează local. Nimic audio brut nu pleacă de pe telefon."))
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setOngoing(true)
            .setContentIntent(pendingIntent)
            .build()
    }

    private fun stopCaptureSession(removeForeground: Boolean = true) {
        captureSession?.stop()
        captureSession = null
        if (removeForeground) {
            runCatching { stopForeground(STOP_FOREGROUND_REMOVE) }
        }
    }

    private fun buildAudioSemanticApi(): SigurScanApi {
        val logging = HttpLoggingInterceptor().apply {
            level = HttpLoggingInterceptor.Level.NONE
        }
        val client = OkHttpClient.Builder()
            .callTimeout(15, TimeUnit.SECONDS)
            .readTimeout(15, TimeUnit.SECONDS)
            .writeTimeout(15, TimeUnit.SECONDS)
            .connectTimeout(8, TimeUnit.SECONDS)
            .addInterceptor(ApiKeyInterceptor(rawApiKey = BuildConfig.SIGURSCAN_API_KEY))
            .addInterceptor(logging)
            .build()

        return Retrofit.Builder()
            .baseUrl(configuredBackendBaseUrl())
            .client(client)
            .addConverterFactory(GsonConverterFactory.create())
            .build()
            .create(SigurScanApi::class.java)
    }

    private fun configuredBackendBaseUrl(): String {
        val configured = BuildConfig.SIGURSCAN_BACKEND_BASE_URL.trim()
        val allowed = configured.takeIf {
            it.startsWith("https://", ignoreCase = true) ||
                (BuildConfig.DEBUG && it.startsWith("http://", ignoreCase = true))
        }
        return (allowed ?: "https://offline.sigurscan.invalid/")
            .let { if (it.endsWith("/")) it else "$it/" }
    }

    companion object {
        private const val ACTION_SHOW_CALL_PROMPT = "ro.sigurscan.app.action.SHOW_SPEAKER_GUARD_CALL_PROMPT"
        private const val ACTION_START_CAPTURE = "ro.sigurscan.app.action.START_SPEAKER_GUARD_CAPTURE"
        private const val ACTION_STOP_CAPTURE = "ro.sigurscan.app.action.STOP_SPEAKER_GUARD_CAPTURE"
        private const val EXTRA_ACTION = "action"
        private const val EXTRA_REASON = "reason"
        private const val EXTRA_FAMILY = "family"
        private const val EXTRA_WARNING_TITLE = "warning_title"
        private const val EXTRA_WARNING_BODY = "warning_body"
        private const val EXTRA_REJECT_CALL = "reject_call"
        private const val EXTRA_SILENCE_CALL = "silence_call"
        private const val EXTRA_IS_KNOWN_CONTACT = "is_known_contact"
        private const val EXTRA_MODEL_PATH = "model_path"
        private const val CHANNEL_ID = "speaker_guard_foreground"
        private const val NOTIFICATION_ID = 4731
        private const val CAPTURE_NOTIFICATION_ID = 4732
        private const val FOREGROUND_REQUEST_CODE = 4731
        private const val CAPTURE_REQUEST_CODE = 4732
        private const val PROMPT_SERVICE_WINDOW_MS = 12_000L
        private const val DEEP_LINK = "sigurscan://speaker-guard?autostart=1&source=call_screening"

        fun startForCallPrompt(context: Context, decision: RadarCallDecision) {
            if (!BuildConfig.SIGURSCAN_ENABLE_AUDIO_ASR) return
            if (!SpeakerGuardCallPromptPolicy.shouldOffer(decision)) return
            val intent = Intent(context, SpeakerGuardForegroundService::class.java).apply {
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

        fun startCapture(context: Context, modelPath: String) {
            val intent = Intent(context, SpeakerGuardForegroundService::class.java).apply {
                action = ACTION_START_CAPTURE
                putExtra(EXTRA_MODEL_PATH, modelPath)
            }
            ContextCompat.startForegroundService(context.applicationContext, intent)
        }

        fun stopCapture(context: Context) {
            val intent = Intent(context, SpeakerGuardForegroundService::class.java).apply {
                action = ACTION_STOP_CAPTURE
            }
            runCatching { context.applicationContext.startService(intent) }
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

        private fun speakerGuardDeepLinkIntent(context: Context): Intent {
            return Intent(Intent.ACTION_VIEW, Uri.parse(DEEP_LINK)).apply {
                setPackage(context.packageName)
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
            }
        }
    }
}
