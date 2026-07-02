package ro.sigurscan.app.dialer

import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

/**
 * Minimal in-call screen shown while SigurScan is the default dialer.
 *
 * MVP scope: answer / hang up / speaker toggle, a radar warning banner and a
 * shortcut that puts the call on speaker and opens the existing Speaker Guard
 * (Urechea) flow via the sigurscan://speaker-guard deep link.
 */
class InCallActivity : ComponentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O_MR1) {
            setShowWhenLocked(true)
            setTurnScreenOn(true)
        }
        setContent {
            MaterialTheme {
                InCallScreen(
                    onListenWithUrechea = {
                        OngoingCallState.forceSpeakerOn()
                        startActivity(
                            Intent(Intent.ACTION_VIEW, Uri.parse("sigurscan://speaker-guard"))
                                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                        )
                    },
                    onFinished = { finish() }
                )
            }
        }
    }
}

@Composable
private fun InCallScreen(
    onListenWithUrechea: () -> Unit,
    onFinished: () -> Unit
) {
    val uiState by OngoingCallState.state.collectAsState()

    LaunchedEffect(uiState) {
        if (uiState == null) {
            onFinished()
        }
    }

    val state = uiState ?: return

    Scaffold { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.SpaceBetween
        ) {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text(
                    text = state.number ?: "Număr necunoscut",
                    style = MaterialTheme.typography.headlineMedium,
                    fontWeight = FontWeight.Bold
                )
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = state.stateLabel,
                    style = MaterialTheme.typography.bodyLarge
                )
                Spacer(modifier = Modifier.height(16.dp))
                RadarBanner(state)
            }

            Column(modifier = Modifier.fillMaxWidth()) {
                if (state.isActive) {
                    Button(
                        onClick = onListenWithUrechea,
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("\uD83D\uDC42 Pune pe difuzor și ascultă cu Urechea")
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedButton(
                        onClick = { OngoingCallState.toggleSpeaker() },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text(if (state.isSpeakerOn) "Difuzor: pornit" else "Difuzor: oprit")
                    }
                    Spacer(modifier = Modifier.height(16.dp))
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    if (state.isRinging) {
                        Button(
                            onClick = { OngoingCallState.answer() },
                            modifier = Modifier.weight(1f),
                            colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF2E7D32))
                        ) {
                            Text("Răspunde")
                        }
                    }
                    Button(
                        onClick = { OngoingCallState.hangup() },
                        modifier = Modifier.weight(1f),
                        colors = ButtonDefaults.buttonColors(containerColor = Color(0xFFC62828))
                    ) {
                        Text(if (state.isRinging) "Respinge" else "Închide")
                    }
                }
            }
        }
    }
}

@Composable
private fun RadarBanner(state: DialerUiState) {
    val action = state.radarAction ?: return
    if (action == "ALLOW") return

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = Color(0xFFFFF3E0))
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(
                text = "⚠️ Radar: atenție la acest număr",
                fontWeight = FontWeight.Bold,
                color = Color(0xFFE65100)
            )
            state.radarFamily?.takeIf { it.isNotBlank() }?.let {
                Text(text = "Familie de scam: $it", color = Color(0xFFE65100))
            }
            state.radarReason?.takeIf { it.isNotBlank() }?.let {
                Text(text = it, color = Color(0xFFE65100))
            }
        }
    }
}
