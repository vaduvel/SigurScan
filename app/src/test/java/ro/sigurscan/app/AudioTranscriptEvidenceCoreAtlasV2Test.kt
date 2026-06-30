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
    fun refundOverpaymentReturnDifferenceProducesDangerous() {
        val result = AudioTranscriptEvidence.analyze(
            "Buna ziua, sunt de la departamentul de plati al magazinului. Din greseala v-am rambursat " +
                "prea mult si trebuie sa returnati diferenta prin transfer acum. Va ghidez eu pas cu pas."
        )

        assertEquals("CONV_REFUND_OVERPAYMENT_REVERSAL", result.arcFamily)
        assertEquals("suport_refund", result.claimedIdentity)
        assertEquals(AudioEvidenceVerdict.DANGEROUS, result.verdict)
    }

    @Test
    fun jobTaskTopUpProducesDangerous() {
        val result = AudioTranscriptEvidence.analyze(
            "Va scriu de la platforma de recrutare. Castigati bani din task-uri simple, dar pentru " +
                "a debloca task-urile mai bine platite trebuie sa depuneti o suma acum pe contul indicat."
        )

        assertEquals("CONV_JOB_TASK_ADVANCE_PAYMENT", result.arcFamily)
        assertEquals("recrutor_task", result.claimedIdentity)
        assertEquals(AudioEvidenceVerdict.DANGEROUS, result.verdict)
    }

    @Test
    fun recoveryScamAdvanceFeeProducesDangerous() {
        val result = AudioTranscriptEvidence.analyze(
            "Sunt avocatul firmei de recuperare fonduri. Va putem recupera banii pierduti in investitii, " +
                "dar trebuie sa platiti o taxa in avans prin transfer pentru dosar."
        )

        assertEquals("CONV_RECOVERY_SCAM", result.arcFamily)
        assertEquals("recuperare_fonduri", result.claimedIdentity)
        assertEquals(AudioEvidenceVerdict.DANGEROUS, result.verdict)
    }

    @Test
    fun voiceCloneEmergencyWithSecretMoneyProducesDangerous() {
        val result = AudioTranscriptEvidence.analyze(
            "Mama, sunt eu. Am avut un accident si sunt retinut la politie. Am nevoie urgent de bani, " +
                "trimite prin transfer acum si nu spune nimanui."
        )

        assertEquals("CONV_VOICE_CLONE_EMERGENCY_IMPERSONATION", result.arcFamily)
        assertEquals("familie", result.claimedIdentity)
        assertEquals(AudioEvidenceVerdict.DANGEROUS, result.verdict)
    }

    @Test
    fun marketplaceReceiveMoneyCardDataProducesDangerous() {
        val result = AudioTranscriptEvidence.analyze(
            "Sunt cumparatorul de pe OLX. Ca sa primesti banii pentru produs, intra pe linkul de livrare " +
                "si introdu datele cardului, inclusiv codul primit prin SMS."
        )

        assertEquals("CONV_MARKETPLACE_RECEIVE_MONEY", result.arcFamily)
        assertEquals("cumparator_marketplace", result.claimedIdentity)
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

    @Test
    fun officialPolicyNegativeControlsAreNeverDangerous() {
        val controls = listOf(
            "Buna ziua, este un apel automat de confirmare a unei tranzactii. Daca ati facut dumneavoastra plata, confirmati. Daca nu o recunoasteti, inchideti si sunati la numarul din aplicatie.",
            "Va sunam de la banca pentru a va anunta o tranzactie neobisnuita. Nu va cerem niciun cod sau parola. Va rugam sa verificati tranzactia in aplicatie.",
            "Buna ziua, coletul dumneavoastra ajunge azi. Plata ramburs se face la curier sau la easybox. Nu va trimitem linkuri de plata prin SMS.",
            "Aveti un colet de livrat maine. Pentru confirmare avem nevoie doar de nume. Verificati statusul in aplicatia FAN Courier.",
            "Va reamintim ca aveti o factura de plata. O puteti achita in aplicatia oficiala, la ghiseu sau la ATM. Nu va cerem datele cardului la telefon.",
            "Buna ziua, factura lunii este disponibila in MyElectrica. Va rugam sa o achitati din aplicatie sau de pe site-ul oficial.",
            "Va sunam pentru a confirma o programare de instalare. Folosim numele si codul dumneavoastra de abonat. Nu va cerem parole sau coduri.",
            "Acesta este un mesaj informativ. Daca primiti apeluri care va cer bani sau date bancare in numele Politiei, inchideti si sunati la 112."
        )

        val dangerous = controls.mapIndexedNotNull { index, transcript ->
            val result = AudioTranscriptEvidence.analyze(transcript)
            if (result.verdict == AudioEvidenceVerdict.DANGEROUS) "control_$index:${result.arcFamily}:${result.reasonCodes}" else null
        }

        assertTrue("Official-policy safe controls became dangerous: $dangerous", dangerous.isEmpty())
    }
}
