package ro.sigurscan.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Golden tests pentru cele 5 familii core RO adaugate din research brief (30.06).
 * Sursele de tipologie: ANAF, Politia Romana, Vodafone/Orange/Telekom, ANCOM,
 * Electrica/PPC, Posta Romana/FAN Courier, FTC/FBI/Europol/Scamwatch.
 * Variantele ASR sunt estimari ingineresti, nu citate.
 */
class AudioTranscriptEvidenceCoreAtlasV2Test {

    @Test
    fun telecomOperatorAccountTakeoverWithOtpProducesDangerous() {
        val result = AudioTranscriptEvidence.analyze(
            "Buna ziua, va sun de la Vodafone, departamentul de fidelizare. " +
                "Aveti beneficii financiare si trebuie sa confirmati portarea. " +
                "Va rog sa imi cititi codul primit prin SMS chiar acum."
        )

        assertEquals("CONV_TELECOM_OPERATOR_ACCOUNT_TAKEOVER", result.arcFamily)
        assertEquals("operator_telecom", result.claimedIdentity)
        assertEquals(AudioEvidenceVerdict.DANGEROUS, result.verdict)
        assertTrue(result.transcriptRedacted)
        assertFalse(result.rawAudioStored)
    }

    @Test
    fun utilitiesDisconnectionWithCardRequestProducesDangerous() {
        val result = AudioTranscriptEvidence.analyze(
            "Buna ziua, va sun de la Electrica Furnizare. Aveti un sold restant si urmeaza " +
                "deconectarea pe motiv de neplata. Pentru a evita intreruperea, cititi-mi acum " +
                "numarul cardului ca sa inregistram plata."
        )

        assertEquals("CONV_UTILITIES_DISCONNECTION_PAYMENT", result.arcFamily)
        assertEquals("furnizor_utilitati", result.claimedIdentity)
        assertEquals(AudioEvidenceVerdict.DANGEROUS, result.verdict)
    }

    @Test
    fun deliveryCustomsReleaseFeeWithCardProducesDangerous() {
        val result = AudioTranscriptEvidence.analyze(
            "Buna ziua, sunt curier de la Posta Romana. Coletul dumneavoastra este blocat la vama " +
                "si trebuie sa achitati o taxa vamala pentru deblocare. Confirmati acum datele cardului."
        )

        assertEquals("CONV_DELIVERY_CUSTOMS_RELEASE_FEE", result.arcFamily)
        assertEquals("curier", result.claimedIdentity)
        assertEquals(AudioEvidenceVerdict.DANGEROUS, result.verdict)
    }

    @Test
    fun authorityLegalThreatWithIdDocumentProducesDangerous() {
        val result = AudioTranscriptEvidence.analyze(
            "Buna ziua, sunt inspector ANAF Antifrauda. Aveti un dosar penal si o neregula fiscala. " +
                "Trebuie sa va confirmati datele personale si sa faceti un transfer acum, " +
                "altfel urmeaza consecinte legale."
        )

        assertEquals("CONV_AUTHORITY_IMPERSONATION_LEGAL_THREAT", result.arcFamily)
        assertEquals("autoritate", result.claimedIdentity)
        assertEquals(AudioEvidenceVerdict.DANGEROUS, result.verdict)
    }

    @Test
    fun prizeReleaseFeeWithCardProducesDangerous() {
        val result = AudioTranscriptEvidence.analyze(
            "Felicitari, ati castigat un premiu la o tombola. Pentru eliberare trebuie sa achitati " +
                "o taxa de eliberare si sa ne dati datele cardului."
        )

        assertEquals("CONV_PRIZE_RELEASE_FEE", result.arcFamily)
        assertEquals("organizator_premii", result.claimedIdentity)
        assertEquals(AudioEvidenceVerdict.DANGEROUS, result.verdict)
    }

    @Test
    fun utilitiesCampaignWithoutHardAskStaysSuspect() {
        val result = AudioTranscriptEvidence.analyze(
            "Buna ziua, sunt de la furnizorul de energie. Aveti sold restant si urmeaza deconectarea. " +
                "Va rog sa platiti acum."
        )

        assertEquals("CONV_UTILITIES_DISCONNECTION_PAYMENT", result.arcFamily)
        assertEquals(AudioEvidenceVerdict.SUSPECT, result.verdict)
    }

    @Test
    fun legitimateTelecomServiceCallIsNotDangerous() {
        val result = AudioTranscriptEvidence.analyze(
            "Buna ziua, va sun de la Vodafone pentru a confirma programarea unei vizite tehnice de maine."
        )

        assertFalse(result.verdict == AudioEvidenceVerdict.DANGEROUS)
        assertFalse(result.arcFamily == "CONV_TELECOM_OPERATOR_ACCOUNT_TAKEOVER")
    }

    @Test
    fun legitimateUtilityPaymentReminderIsNotDangerous() {
        val result = AudioTranscriptEvidence.analyze(
            "Buna ziua, sunt de la Electrica. Va reamintim ca puteti plati factura in aplicatia oficiala " +
                "sau la numarul de pe factura."
        )

        assertFalse(result.verdict == AudioEvidenceVerdict.DANGEROUS)
        assertFalse(result.arcFamily == "CONV_UTILITIES_DISCONNECTION_PAYMENT")
    }
}
