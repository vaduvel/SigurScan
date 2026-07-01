package ro.sigurscan.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.media.AudioManager
import android.net.Uri
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.util.Log
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
    private var callAudioModeWatcher: Runnable? = null
    private var latestCaptureUpdate: SpeakerGuardUpdate? = null
    private val clientInstanceId: String by lazy {
        SigurScanClientIdentity.loadOrCreateClientInstanceId(applicationContext)
    }
    private val playIntegrityTokenProvider: PlayIntegrityTokenProvider by lazy {
        if (BuildConfig.SIGURSCAN_ENABLE_PLAY_INTEGRITY) {
            PlayIntegrityTokenProvider.fromContext(
                applicationContext,
                configuredSigurScanBackendBaseUrl(),
                BuildConfig.SIGURSCAN_API_KEY,
                clientInstanceId
            )
        } else {
            PlayIntegrityTokenProvider.disabled()
        }
    }
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
        Log.i(TAG, "start_capture_requested modelPathPresent=${modelPath.isNotBlank()}")
        latestCaptureUpdate = null
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
            latestCaptureUpdate = update
            SpeakerGuardForegroundServiceEvents.publish(update)
            if (!update.active && update.phase != SpeakerGuardPhase.PROCESSING) {
                stopCaptureSession()
                stopSelf(startId)
            }
        }
        startCallAudioModeWatcher(startId)
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
        val intent = SpeakerGuardCallPromptActivity.intentForPrompt(this, decision)
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
        stopCallAudioModeWatcher()
        captureSession?.stop()
        captureSession = null
        if (removeForeground) {
            runCatching { stopForeground(STOP_FOREGROUND_REMOVE) }
        }
    }

    private fun startCallAudioModeWatcher(startId: Int) {
        stopCallAudioModeWatcher()
        val audioManager = getSystemService(AudioManager::class.java) ?: return
        val tracker = SpeakerGuardCallAudioModeTracker()
        val watcher = object : Runnable {
            override fun run() {
                val mode = runCatching { audioManager.mode }.getOrDefault(AudioManager.MODE_NORMAL)
                if (tracker.shouldStopForMode(mode)) {
                    Log.i(TAG, "call_audio_mode_ended mode=$mode")
                    SpeakerGuardForegroundServiceEvents.publish(callEndedUpdate())
                    stopCaptureSession()
                    stopSelf(startId)
                    return
                }
                handler.postDelayed(this, CALL_AUDIO_MODE_POLL_MS)
            }
        }
        callAudioModeWatcher = watcher
        handler.post(watcher)
    }

    private fun callEndedUpdate(): SpeakerGuardUpdate {
        val latest = latestCaptureUpdate
        val reasonCode = when {
            latest == null -> "call_ended_no_capture"
            latest.reasonCode == "recording_silenced_by_android" -> "call_ended_recording_silenced"
            latest.chunksAnalyzed == 0 && latest.result == null -> "call_ended_no_clear_audio"
            else -> latest.result?.reasonCode ?: latest.reasonCode ?: "call_ended"
        }
        val status = when (reasonCode) {
            "call_ended_no_capture" -> "Apelul s-a încheiat. Nu am putut confirma captura audio."
            "call_ended_recording_silenced" -> "Apelul s-a încheiat. Android a blocat microfonul în timpul apelului."
            "call_ended_no_clear_audio" -> "Apelul s-a încheiat. Nu am prins suficientă voce clară."
            else -> "Apelul s-a încheiat. Urechea s-a oprit."
        }
        return SpeakerGuardUpdate(
            phase = SpeakerGuardPhase.STOPPED,
            active = false,
            chunksAnalyzed = latest?.chunksAnalyzed ?: 0,
            chunksDropped = latest?.chunksDropped ?: 0,
            result = latest?.result,
            latencyMs = latest?.latencyMs,
            reasonCode = reasonCode,
            status = status
        )
    }

    private fun stopCallAudioModeWatcher() {
        callAudioModeWatcher?.let { handler.removeCallbacks(it) }
        callAudioModeWatcher = null
    }

    private fun buildAudioSemanticApi(): SigurScanApi {
        return buildSigurScanApiClient(
            callTimeoutSeconds = 15,
            readTimeoutSeconds = 15,
            writeTimeoutSeconds = 15,
            connectTimeoutSeconds = 8,
            clientInstanceId = clientInstanceId,
            integrityTokenProvider = { playIntegrityTokenProvider.currentToken() }
        )
    }

    companion object {
        private const val TAG = "SpeakerGuardService"
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
        private const val CALL_AUDIO_MODE_POLL_MS = 1_000L
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
