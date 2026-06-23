package ro.sigurscan.app

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LocalExtractionPresentationTest {
    @Test
    fun localExtractionFailuresAreNeutralNeverificatNotSuspect() {
        val result = GateResult(
            action = GateAction.UNVERIFIED,
            finality = GateFinality.FINAL,
            reasonCodes = listOf("LOCAL_IMAGE_OCR_INCOMPLETE"),
            decisiveSignalIds = emptyList(),
            unknownReason = "LOCAL_IMAGE_OCR_INCOMPLETE"
        )
        val copy = listOf(
            GateResultPresentation.familyLabel(result, "fallback"),
            GateResultPresentation.legacyRiskLevel(result),
            GateResultPresentation.userHeadline(result),
            GateResultPresentation.supportText(result),
            GateResultPresentation.reasonText(result, null),
            GateResultPresentation.primaryAction(result)
        )
            .plus(GateResultPresentation.recommendedActions(result))
            .joinToString(" ")
            .lowercase()

        assertTrue(GateResultPresentation.familyLabel(result, "fallback") == "Neverificat")
        assertTrue(GateResultPresentation.legacyRiskLevel(result) == "info")
        assertTrue(GateResultPresentation.legacyRiskScore(result) == 0)
        assertTrue(GateResultPresentation.userHeadline(result) == "Neverificat")
        assertTrue(copy.contains("nu am putut"))
        assertTrue(copy.contains("reîncearcă") || copy.contains("reincearcă") || copy.contains("reincearca"))
        assertFalse(copy.contains("suspect"))
        assertFalse(copy.contains("periculos"))
        assertFalse(copy.contains("scanarea nu este completa"))
        assertFalse(copy.contains("scanarea nu este completă"))
    }

    @Test
    fun everyLocalIntakeFailureUsesTheNeutralUnverifiedReducer() {
        fun body(source: String, signature: String, nextSignature: String? = null): String {
            val start = source.indexOf(signature)
            assertTrue("Missing $signature", start >= 0)
            val end = nextSignature?.let { source.indexOf(it, start + signature.length) } ?: source.length
            return source.substring(start, if (end > start) end else source.length)
        }

        val image = java.io.File("src/main/java/ro/sigurscan/app/ScannerViewModelImageQr.kt").readText()
        val shared = java.io.File("src/main/java/ro/sigurscan/app/ScannerViewModelSharedIntake.kt").readText()

        assertTrue(
            body(image, "internal fun ScannerViewModel.publishQrExtractionIncomplete", "fun ScannerViewModel.onImagePicked")
                .contains("localUnverifiedAssessment(")
        )
        assertTrue(
            body(image, "internal fun ScannerViewModel.publishImageExtractionIncomplete")
                .contains("localUnverifiedAssessment(")
        )
        assertTrue(
            body(shared, "if (importKind == FileImportKind.UNSUPPORTED", "if (importKind == FileImportKind.AUDIO)")
                .contains("localUnverifiedAssessment(")
        )
        assertTrue(
            body(shared, "internal fun ScannerViewModel.publishAudioShareRequiresTranscript")
                .contains("localUnverifiedAssessment(")
        )
        val pdfStart = shared.indexOf("family = \"Scanare incompletă\"")
        val audioStart = shared.indexOf("internal fun ScannerViewModel.publishAudioShareRequiresTranscript")
        assertTrue("PDF extraction fallback must exist.", pdfStart >= 0 && audioStart > pdfStart)
        val pdfReducer = shared.lastIndexOf("localUnverifiedAssessment(", pdfStart)
        assertTrue("PDF extraction must use the neutral reducer.", pdfReducer >= 0 && pdfReducer < pdfStart)
    }
}
