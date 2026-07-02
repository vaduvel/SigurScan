package ro.sigurscan.app.dialer

import android.telecom.Call
import android.telecom.CallAudioState
import android.telecom.InCallService
import android.telecom.VideoProfile
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * UI state for the active call handled by [SigurScanInCallService].
 */
data class DialerUiState(
    val number: String?,
    val callState: Int,
    val isSpeakerOn: Boolean = false,
    val radarAction: String? = null,
    val radarReason: String? = null,
    val radarFamily: String? = null
) {
    val isRinging: Boolean
        get() = callState == Call.STATE_RINGING

    val isActive: Boolean
        get() = callState == Call.STATE_ACTIVE

    val stateLabel: String
        get() = when (callState) {
            Call.STATE_RINGING -> "Apel primit"
            Call.STATE_DIALING -> "Se apelează…"
            Call.STATE_CONNECTING -> "Se conectează…"
            Call.STATE_ACTIVE -> "În convorbire"
            Call.STATE_HOLDING -> "În așteptare"
            Call.STATE_DISCONNECTING -> "Se închide…"
            Call.STATE_DISCONNECTED -> "Apel încheiat"
            else -> "Apel"
        }
}

/**
 * Single source of truth for the call currently managed by the in-call service.
 *
 * The service binds/unbinds itself here; the Compose UI observes [state] and
 * drives the call through [answer], [hangup] and [toggleSpeaker].
 */
object OngoingCallState {

    private val _state = MutableStateFlow<DialerUiState?>(null)
    val state: StateFlow<DialerUiState?> = _state.asStateFlow()

    private var call: Call? = null
    private var service: InCallService? = null

    private val callback = object : Call.Callback() {
        override fun onStateChanged(call: Call, newState: Int) {
            publish(call)
        }
    }

    fun bindService(inCallService: InCallService) {
        service = inCallService
    }

    fun unbindService(inCallService: InCallService) {
        if (service === inCallService) {
            service = null
        }
    }

    fun onCallAdded(newCall: Call) {
        call = newCall
        newCall.registerCallback(callback)
        publish(newCall)
    }

    fun onCallRemoved(removedCall: Call) {
        removedCall.unregisterCallback(callback)
        if (call === removedCall) {
            call = null
            _state.value = null
        }
    }

    fun onAudioStateChanged(audioState: CallAudioState) {
        _state.value = _state.value?.copy(
            isSpeakerOn = audioState.route == CallAudioState.ROUTE_SPEAKER
        )
    }

    fun setRadarInfo(action: String?, reason: String?, family: String?) {
        _state.value = _state.value?.copy(
            radarAction = action,
            radarReason = reason,
            radarFamily = family
        )
    }

    fun answer() {
        call?.answer(VideoProfile.STATE_AUDIO_ONLY)
    }

    fun hangup() {
        val current = call ?: return
        if (_state.value?.isRinging == true) {
            current.reject(false, null)
        } else {
            current.disconnect()
        }
    }

    fun toggleSpeaker() {
        val svc = service ?: return
        val speakerOn = _state.value?.isSpeakerOn == true
        svc.setAudioRoute(
            if (speakerOn) CallAudioState.ROUTE_EARPIECE else CallAudioState.ROUTE_SPEAKER
        )
    }

    /** Route audio to the loudspeaker so Urechea can hear both sides. */
    fun forceSpeakerOn() {
        service?.setAudioRoute(CallAudioState.ROUTE_SPEAKER)
    }

    private fun publish(call: Call) {
        @Suppress("DEPRECATION")
        val callState = call.state
        val previous = _state.value
        _state.value = DialerUiState(
            number = call.details?.handle?.schemeSpecificPart,
            callState = callState,
            isSpeakerOn = previous?.isSpeakerOn ?: false,
            radarAction = previous?.radarAction,
            radarReason = previous?.radarReason,
            radarFamily = previous?.radarFamily
        )
    }
}
