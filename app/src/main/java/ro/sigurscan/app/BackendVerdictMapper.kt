package ro.sigurscan.app

internal fun backendGateResult(response: ScanResponse): GateResult {
    if (response.isFinal != true) {
        return backendScanInProgressGateResult()
    }

    val action = when (response.userRiskLabel?.trim()?.uppercase()) {
        "SAFE" -> GateAction.CONTINUE_WITH_CAUTION
        "SUSPECT" -> GateAction.VERIFY_OFFICIAL
        "DANGEROUS" -> GateAction.DO_NOT_CONTINUE
        else -> GateAction.INSUFFICIENT_EVIDENCE
    }
    return GateResult(
        action = action,
        finality = GateFinality.FINAL,
        reasonCodes = listOf(
            if (action == GateAction.INSUFFICIENT_EVIDENCE) {
                "BACKEND_FINAL_LABEL_MISSING"
            } else {
                "BACKEND_ORCHESTRATED_VERDICT"
            }
        ),
        decisiveSignalIds = emptyList(),
        unknownReason = if (action == GateAction.INSUFFICIENT_EVIDENCE) {
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
