package ro.sigurscan.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class BackendVerdictMapperTest {

    @Test
    fun finalBackendLabelsRemainAuthoritativeOnAndroid() {
        assertEquals(
            GateAction.CONTINUE_WITH_CAUTION,
            backendGateResult(scanResponse(label = "SAFE", riskLevel = "low")).action
        )
        assertEquals(
            GateAction.VERIFY_OFFICIAL,
            backendGateResult(scanResponse(label = "SUSPECT", riskLevel = "medium")).action
        )
        assertEquals(
            GateAction.DO_NOT_CONTINUE,
            backendGateResult(scanResponse(label = "DANGEROUS", riskLevel = "high")).action
        )
    }

    @Test
    fun nonFinalBackendResultNeverShowsAProvisionalVerdict() {
        val result = backendGateResult(
            scanResponse(label = "SAFE", riskLevel = "low", isFinal = false)
        )

        assertEquals(GateAction.INSUFFICIENT_EVIDENCE, result.action)
        assertEquals(GateFinality.PROVISIONAL, result.finality)
        assertTrue(result.asyncExpected)
    }

    @Test
    fun orchestratedResponseWithoutBackendResultStaysProvisional() {
        val result = backendGateResult(
            OrchestratedScanResponse(
                scanId = "orch-pending",
                status = "scanning",
                result = null
            )
        )

        assertEquals(GateAction.INSUFFICIENT_EVIDENCE, result.action)
        assertEquals(GateFinality.PROVISIONAL, result.finality)
        assertTrue(result.asyncExpected)
        assertEquals("BACKEND_SCAN_IN_PROGRESS", result.unknownReason)
    }

    @Test
    fun orchestratedResponseWithFinalBackendResultUsesBackendLabel() {
        val result = backendGateResult(
            OrchestratedScanResponse(
                scanId = "orch-final",
                status = "complete",
                result = scanResponse(label = "DANGEROUS", riskLevel = "high", isFinal = true)
            )
        )

        assertEquals(GateAction.DO_NOT_CONTINUE, result.action)
        assertEquals(GateFinality.FINAL, result.finality)
    }

    @Test
    fun missingFinalBackendLabelDoesNotTriggerAnotherLocalJudge() {
        val result = backendGateResult(
            scanResponse(label = null, riskLevel = "low", isFinal = true)
        )

        assertEquals(GateAction.INSUFFICIENT_EVIDENCE, result.action)
        assertEquals(GateFinality.FINAL, result.finality)
        assertEquals("BACKEND_FINAL_LABEL_MISSING", result.unknownReason)
    }

    private fun scanResponse(
        label: String?,
        riskLevel: String,
        isFinal: Boolean = true
    ) = ScanResponse(
        scanId = "backend-verdict",
        riskScore = 10,
        riskLevel = riskLevel,
        isFinal = isFinal,
        userRiskLabel = label
    )
}
