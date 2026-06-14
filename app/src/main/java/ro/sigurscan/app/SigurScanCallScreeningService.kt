package ro.sigurscan.app

import android.os.Build
import android.telecom.Call
import android.telecom.CallScreeningService
import android.util.Log

class SigurScanCallScreeningService : CallScreeningService() {
    override fun onScreenCall(callDetails: Call.Details) {
        val number = callDetails.handle?.schemeSpecificPart
        val cache = RadarHotCacheStore.fromContext(applicationContext).load()
        val decision = RadarCallDecider.decide(number, cache)
        RadarScreeningAuditStore.fromContext(applicationContext).save(RadarScreeningAudit.fromDecision(decision))
        Log.i(TAG, "call_screened action=${decision.action} reason=${decision.reason} family=${decision.family.orEmpty()}")
        val builder = CallResponse.Builder()
            .setDisallowCall(false)
            .setRejectCall(false)
            .setSkipCallLog(false)
            .setSkipNotification(false)

        if (decision.action == RadarCallAction.WARN && decision.silenceCall && Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            builder.setSilenceCall(true)
        }

        respondToCall(callDetails, builder.build())
    }

    companion object {
        private const val TAG = "SigurScanCallScreen"
    }
}
