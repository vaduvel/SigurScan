package ro.sigurscan.app

import java.util.Locale

internal fun backendGateResult(response: ScanResponse): GateResult {
    if (response.isFinal != true) {
        return backendScanInProgressGateResult()
    }

    val action = when (response.userRiskLabel?.trim()?.uppercase(Locale.ROOT)) {
        "SAFE" -> GateAction.CONTINUE_WITH_CAUTION
        "SUSPECT" -> GateAction.VERIFY_OFFICIAL
        "DANGEROUS" -> GateAction.DO_NOT_CONTINUE
        "UNVERIFIED" -> GateAction.INSUFFICIENT_EVIDENCE
        else -> GateAction.INSUFFICIENT_EVIDENCE
    }
    val backendLabel = response.userRiskLabel?.trim()?.uppercase(Locale.ROOT)
    return GateResult(
        action = action,
        finality = GateFinality.FINAL,
        reasonCodes = listOf(
            if (backendLabel == "UNVERIFIED") {
                "BACKEND_UNVERIFIED"
            } else if (action == GateAction.INSUFFICIENT_EVIDENCE) {
                "BACKEND_FINAL_LABEL_MISSING"
            } else {
                "BACKEND_ORCHESTRATED_VERDICT"
            }
        ),
        decisiveSignalIds = emptyList(),
        unknownReason = if (backendLabel == "UNVERIFIED") {
            "BACKEND_UNVERIFIED"
        } else if (action == GateAction.INSUFFICIENT_EVIDENCE) {
            "BACKEND_FINAL_LABEL_MISSING"
        } else {
            null
        }
    )
}

internal fun backendGateResult(response: OrchestratedScanResponse): GateResult {
    return response.result?.let(::backendGateResult) ?: backendScanInProgressGateResult()
}

internal fun backendScanInProgressGateResult(): GateResult = GateResult(
    action = GateAction.INSUFFICIENT_EVIDENCE,
    finality = GateFinality.PROVISIONAL,
    reasonCodes = listOf("PROVIDER_REVIEW_REQUIRED"),
    decisiveSignalIds = emptyList(),
    asyncExpected = true,
    unknownReason = "BACKEND_SCAN_IN_PROGRESS"
)
