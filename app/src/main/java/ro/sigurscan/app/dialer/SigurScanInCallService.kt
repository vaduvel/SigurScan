package ro.sigurscan.app.dialer

import android.content.Intent
import android.telecom.Call
import android.telecom.CallAudioState
import android.telecom.InCallService
import android.util.Log
import ro.sigurscan.app.RadarCallDecider
import ro.sigurscan.app.RadarHotCacheStore

/**
 * Telecom binds this service while SigurScan holds ROLE_DIALER.
 *
 * Being the active in-call app is what exempts SigurScan from the Android 10+
 * concurrent-capture silencing policy: with the call on speaker, Urechea
 * (Speaker Guard) can finally hear both the user and the caller during a live
 * GSM call.
 */
class SigurScanInCallService : InCallService() {

    override fun onCreate() {
        super.onCreate()
        OngoingCallState.bindService(this)
    }

    override fun onDestroy() {
        OngoingCallState.unbindService(this)
        super.onDestroy()
    }

    override fun onCallAdded(call: Call) {
        OngoingCallState.onCallAdded(call)

        // Reuse the existing local reputation decision for the warning banner.
        runCatching {
            val number = call.details?.handle?.schemeSpecificPart
            val cache = RadarHotCacheStore.fromContext(applicationContext).load()
            val decision = RadarCallDecider.decide(number, cache)
            OngoingCallState.setRadarInfo(
                action = decision.action.name,
                reason = decision.reason,
                family = decision.family
            )
        }.onFailure {
            Log.w(TAG, "radar_decision_failed reason=${it.javaClass.simpleName}")
        }

        startActivity(
            Intent(this, InCallActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        )
    }

    override fun onCallRemoved(call: Call) {
        OngoingCallState.onCallRemoved(call)
    }

    override fun onCallAudioStateChanged(audioState: CallAudioState) {
        OngoingCallState.onAudioStateChanged(audioState)
    }

    companion object {
        private const val TAG = "SigurScanInCall"
    }
}
