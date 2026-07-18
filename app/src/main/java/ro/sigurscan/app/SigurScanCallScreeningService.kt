package ro.sigurscan.app

import android.os.Build
import android.telecom.Call
import android.telecom.CallScreeningService
import android.util.Log

class SigurScanCallScreeningService : CallScreeningService() {
    override fun onScreenCall(callDetails: Call.Details) {
        if (!BuildConfig.SIGURSCAN_ENABLE_LIVE_CALL) {
            respondToCall(callDetails, CallResponse.Builder().build())
            return
        }
        val number = callDetails.handle?.schemeSpecificPart
        val cache = RadarHotCacheStore.fromContext(applicationContext).load()
        val decision = RadarCallDecider.decide(number, cache)
            .copy(isKnownContact = !callDetails.contactDisplayName.isNullOrBlank())
        RadarScreeningAuditStore.fromContext(applicationContext).save(RadarScreeningAudit.fromDecision(decision))
        runCatching {
            SpeakerGuardForegroundService.startForCallPrompt(applicationContext, decision)
        }.onFailure {
            Log.w(TAG, "speaker_guard_prompt_failed reason=${it.javaClass.simpleName}")
        }
        Log.i(TAG, "call_screened action=${decision.action} reason=${decision.reason} family=${decision.family.orEmpty()}")
        val builder = CallResponse.Builder()
            .setDisallowCall(decision.rejectCall)
            .setRejectCall(decision.rejectCall)
            .setSkipCallLog(false)
            .setSkipNotification(false)

        if (
            !decision.rejectCall &&
            decision.action == RadarCallAction.WARN &&
            decision.silenceCall &&
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q
        ) {
            builder.setSilenceCall(true)
        }

        respondToCall(callDetails, builder.build())
    }

    companion object {
        private const val TAG = "SigurScanCallScreen"
    }
}
