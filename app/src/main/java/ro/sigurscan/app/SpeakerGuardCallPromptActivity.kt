package ro.sigurscan.app

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import ro.sigurscan.app.ui.theme.SigurColors
import ro.sigurscan.app.ui.theme.SigurScanTheme

class SpeakerGuardCallPromptActivity : ComponentActivity() {
    private var decision by mutableStateOf(
        RadarCallDecision(
            action = RadarCallAction.ALLOW,
            reason = "speaker_guard_prompt",
            isKnownContact = false
        )
    )

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        configureWindowForCallPrompt()
        decision = decisionFrom(intent)
        setContent {
            SigurScanTheme {
                SpeakerGuardCallPromptScreen(
                    decision = decision,
                    startSpeakerGuard = { startSpeakerGuard() },
                    onDismiss = { finish() }
                )
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        decision = decisionFrom(intent)
    }

    private fun configureWindowForCallPrompt() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O_MR1) {
            setShowWhenLocked(true)
            setTurnScreenOn(true)
        } else {
            @Suppress("DEPRECATION")
            window.addFlags(
                WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED or
                    WindowManager.LayoutParams.FLAG_TURN_SCREEN_ON
            )
        }
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
    }

    private fun startSpeakerGuard() {
        startActivity(speakerGuardAutostartIntent(this))
        finish()
    }

    companion object {
        private const val EXTRA_ACTION = "action"
        private const val EXTRA_REASON = "reason"
        private const val EXTRA_FAMILY = "family"
        private const val EXTRA_WARNING_TITLE = "warning_title"
        private const val EXTRA_WARNING_BODY = "warning_body"
        private const val EXTRA_REJECT_CALL = "reject_call"
        private const val EXTRA_SILENCE_CALL = "silence_call"
        private const val EXTRA_IS_KNOWN_CONTACT = "is_known_contact"
        private const val DEEP_LINK = "sigurscan://speaker-guard?autostart=1&source=call_prompt_activity"

        fun intentForPrompt(context: Context, decision: RadarCallDecision): Intent {
            return Intent(context, SpeakerGuardCallPromptActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
                putExtra(EXTRA_ACTION, decision.action.name)
                putExtra(EXTRA_REASON, decision.reason)
                putExtra(EXTRA_FAMILY, decision.family)
                putExtra(EXTRA_WARNING_TITLE, decision.warningTitle)
                putExtra(EXTRA_WARNING_BODY, decision.warningBody)
                putExtra(EXTRA_REJECT_CALL, decision.rejectCall)
                putExtra(EXTRA_SILENCE_CALL, decision.silenceCall)
                putExtra(EXTRA_IS_KNOWN_CONTACT, decision.isKnownContact)
            }
        }

        private fun speakerGuardAutostartIntent(context: Context): Intent {
            return Intent(Intent.ACTION_VIEW, Uri.parse(DEEP_LINK)).apply {
                setPackage(context.packageName)
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)
            }
        }

        private fun decisionFrom(intent: Intent?): RadarCallDecision {
            val action = runCatching {
                RadarCallAction.valueOf(intent?.getStringExtra(EXTRA_ACTION).orEmpty())
            }.getOrDefault(RadarCallAction.ALLOW)
            return RadarCallDecision(
                action = action,
                reason = intent?.getStringExtra(EXTRA_REASON).orEmpty().ifBlank { "speaker_guard_prompt" },
                family = intent?.getStringExtra(EXTRA_FAMILY),
                warningTitle = intent?.getStringExtra(EXTRA_WARNING_TITLE),
                warningBody = intent?.getStringExtra(EXTRA_WARNING_BODY),
                rejectCall = intent?.getBooleanExtra(EXTRA_REJECT_CALL, false) ?: false,
                silenceCall = intent?.getBooleanExtra(EXTRA_SILENCE_CALL, false) ?: false,
                isKnownContact = intent?.getBooleanExtra(EXTRA_IS_KNOWN_CONTACT, false) ?: false
            )
        }
    }
}

@Composable
private fun SpeakerGuardCallPromptScreen(
    decision: RadarCallDecision,
    startSpeakerGuard: () -> Unit,
    onDismiss: () -> Unit
) {
    val prompt = speakerGuardCallPrompt(decision)
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(Color.Transparent)
            .statusBarsPadding()
            .navigationBarsPadding()
            .padding(horizontal = 16.dp, vertical = 18.dp)
    ) {
        Surface(
            modifier = Modifier
                .align(Alignment.BottomCenter)
                .fillMaxWidth(),
            shape = RoundedCornerShape(22.dp),
            color = SigurColors.BackgroundCard.copy(alpha = 0.98f),
            border = BorderStroke(1.dp, SigurColors.Brand.copy(alpha = 0.32f)),
            tonalElevation = 8.dp,
            shadowElevation = 12.dp
        ) {
            Column(
                modifier = Modifier.padding(18.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                Text(
                    text = prompt.title,
                    color = SigurColors.TextPrimary,
                    fontSize = 20.sp,
                    fontWeight = FontWeight.SemiBold
                )
                Text(
                    text = prompt.body,
                    color = SigurColors.TextSecondary,
                    fontSize = 14.sp,
                    lineHeight = 19.sp
                )
                Text(
                    text = "Răspunde normal, pune apelul pe difuzor, apoi pornește analiza.",
                    color = SigurColors.TextPrimary,
                    fontSize = 13.sp,
                    fontWeight = FontWeight.Medium,
                    lineHeight = 18.sp
                )
                Text(
                    text = prompt.privacyLine,
                    color = SigurColors.TextMuted,
                    fontSize = 12.sp,
                    lineHeight = 16.sp
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    OutlinedButton(
                        onClick = onDismiss,
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = SigurColors.TextSecondary)
                    ) {
                        Text(prompt.secondaryCta)
                    }
                    Spacer(modifier = Modifier.width(10.dp))
                    Button(
                        onClick = { startSpeakerGuard() },
                        colors = ButtonDefaults.buttonColors(
                            containerColor = SigurColors.Brand,
                            contentColor = SigurColors.TextInverse
                        )
                    ) {
                        Text(prompt.primaryCta)
                    }
                }
            }
        }
    }
}
