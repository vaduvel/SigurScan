package ro.sigurscan.app

import android.util.Log
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.withLock

fun ScannerViewModel.beginPaymentCase() {
    val previousCaseId = paymentCaseId
    assessment = null
    invoiceResult = null
    invoiceSanbStatus = null
    lastInvoiceScanSource = null
    pendingOfferConfirmation = null
    officialReportPackage = null
    officialReportStatus = null
    text = ""
    clearAllPendingShared()
    clearPaymentCaseLocalState()
    paymentCaseActive = true
    paymentCaseStatus = "Începe cu factura sau documentul care cere plata."
    if (!previousCaseId.isNullOrBlank()) {
        viewModelScope.launch {
            runCatching { api.deletePaymentCase(previousCaseId) }
        }
    }
}

fun ScannerViewModel.discardPaymentCase() {
    val caseId = paymentCaseId
    assessment = null
    invoiceResult = null
    invoiceSanbStatus = null
    lastInvoiceScanSource = null
    clearPaymentCaseLocalState()
    if (!caseId.isNullOrBlank()) {
        viewModelScope.launch {
            runCatching { api.deletePaymentCase(caseId) }
        }
    }
}

internal fun ScannerViewModel.clearPaymentCaseLocalState() {
    paymentCaseGeneration += 1
    paymentCaseActive = false
    paymentCaseResult = null
    paymentCaseStatus = null
    paymentCaseLoading = false
    paymentCaseId = null
    attachedPaymentCaseArtifactRefs.clear()
    pendingPaymentCaseArtifactRefs.clear()
}

internal suspend fun ScannerViewModel.attachPaymentCaseArtifact(artifactRef: String?) {
    val normalizedRef = artifactRef?.trim().orEmpty()
    if (!paymentCaseActive) return
    if (normalizedRef.isBlank()) {
        paymentCaseStatus = "Dovada a fost analizată, dar nu a putut fi adăugată în acest caz. Reîncearcă scanarea."
        return
    }
    pendingPaymentCaseArtifactRefs += normalizedRef
    val capturedGeneration = paymentCaseGeneration
    paymentCaseMutex.withLock {
        if (!isCurrentPaymentCaseSession(capturedGeneration, paymentCaseGeneration, paymentCaseActive)) return
        if (normalizedRef in attachedPaymentCaseArtifactRefs) return
        paymentCaseLoading = true
        paymentCaseStatus = "Combinăm dovezile într-un singur verdict..."
        var remoteCaseId: String? = paymentCaseId
        try {
            val caseId = remoteCaseId ?: api.createPaymentCase().caseId.also {
                remoteCaseId = it
            }
            if (!isCurrentPaymentCaseSession(capturedGeneration, paymentCaseGeneration, paymentCaseActive)) {
                runCatching { api.deletePaymentCase(caseId) }
                return
            }
            paymentCaseId = caseId
            val updated = api.attachPaymentCaseArtifact(
                caseId,
                PaymentCaseArtifactRequest(normalizedRef),
            )
            if (!isCurrentPaymentCaseSession(capturedGeneration, paymentCaseGeneration, paymentCaseActive)) {
                runCatching { api.deletePaymentCase(caseId) }
                return
            }
            paymentCaseResult = updated
            attachedPaymentCaseArtifactRefs += normalizedRef
            pendingPaymentCaseArtifactRefs -= normalizedRef
            paymentCaseStatus = null
        } catch (error: Exception) {
            Log.w("SigurScan", "payment case attach failed: ${error.javaClass.simpleName}")
            if (isCurrentPaymentCaseSession(capturedGeneration, paymentCaseGeneration, paymentCaseActive)) {
                paymentCaseStatus = "Dovada a fost verificată separat, dar nu am putut actualiza cazul. Reîncearcă."
            }
        } finally {
            if (isCurrentPaymentCaseSession(capturedGeneration, paymentCaseGeneration, paymentCaseActive)) {
                paymentCaseLoading = false
            }
        }
    }
}

fun ScannerViewModel.retryPaymentCaseAttach() {
    val artifactRef = nextPaymentCaseRetryRef(
        pendingPaymentCaseArtifactRefs,
        attachedPaymentCaseArtifactRefs,
    ) ?: return
    viewModelScope.launch {
        attachPaymentCaseArtifact(artifactRef)
    }
}
