package ro.sigurscan.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class AudioTranscriptEvidenceTest {
    @Test
    fun bankSafeAccountTranscriptProducesDangerousWithoutRetainingRawText() {
        val raw = "Sunt inspector de la Politie. BNR cere sa muti economiile intr-un cont sigur."

        val result = AudioTranscriptEvidence.analyze(raw)

        assertEquals(AudioEvidenceVerdict.DANGEROUS, result.verdict)
        assertEquals("CONV_BANK_SAFE_ACCOUNT", result.arcFamily)
        assertTrue(result.transcriptRedacted)
        assertFalse(result.toString().contains("economiile"))
    }

    @Test
    fun noisyWhisperTranscriptStillDetectsSafeAccountTransfer() {
        val result = AudioTranscriptEvidence.analyze("Benerecere sa multibani intr-un consiguracum")

        assertEquals(AudioEvidenceVerdict.SUSPECT, result.verdict)
        assertEquals("CONV_BANK_SAFE_ACCOUNT", result.arcFamily)
    }

    @Test
    fun remoteAccessInvestmentTranscriptProducesDangerous() {
        val result = AudioTranscriptEvidence.analyze(
            "Consultantul promite profit garantat si cere sa instalez AnyDesk pentru acces la distanta."
        )

        assertEquals(AudioEvidenceVerdict.DANGEROUS, result.verdict)
        assertEquals("CONV_INVESTMENT_REMOTE_ACCESS", result.arcFamily)
        assertTrue(result.reasonCodes.any { it == "sensitive_wrong_channel" || it == "identity_spoof" })
    }

    @Test
    fun familyEmergencyMoneyTranscriptProducesDangerous() {
        val result = AudioTranscriptEvidence.analyze(
            "Sunt nepotul tau, am facut accident. Avocatul cere 12000 lei cash si sa nu suni politia."
        )

        assertEquals(AudioEvidenceVerdict.DANGEROUS, result.verdict)
        assertEquals("CONV_FAMILY_EMERGENCY", result.arcFamily)
    }

    @Test
    fun trustedContactUrgentSecretMoneyRequestProducesDangerous() {
        val result = AudioTranscriptEvidence.analyze(
            "Sunt Mihai, colegul tau. Am nevoie urgent de bani. Trimite acum 1200 de lei si nu spune nimanui."
        )

        assertEquals(AudioEvidenceVerdict.DANGEROUS, result.verdict)
        assertEquals("CONV_TRUSTED_CONTACT_MONEY_URGENCY", result.arcFamily)
        assertEquals("contact_cunoscut", result.claimedIdentity)
    }

    @Test
    fun ordinaryColleagueMessageWithoutMoneyRequestIsNotDangerous() {
        val result = AudioTranscriptEvidence.analyze(
            "Sunt colegul tau Mihai. Ne auzim maine dupa sedinta."
        )

        assertFalse(result.verdict == AudioEvidenceVerdict.DANGEROUS)
    }

    @Test
    fun ordinaryUnknownCallWithoutSensitiveAskIsNotDangerous() {
        val result = AudioTranscriptEvidence.analyze(
            "Buna ziua, confirmam programarea de maine la ora zece."
        )

        assertTrue(result.verdict in setOf(AudioEvidenceVerdict.UNVERIFIED, AudioEvidenceVerdict.SUSPECT))
        assertFalse(result.verdict == AudioEvidenceVerdict.DANGEROUS)
    }

    @Test
    fun realAsrOtpCancellationCallProducesDangerous() {
        val result = AudioTranscriptEvidence.analyze(
            "Bunezioa, va sunt din partea bancii departamentul anti frauda. " +
                "Am detectat o incercare de logare de pe un dispozitiv nou. " +
                "Veti primi un cod de anulare pe mesaj. Va rog sa mi-l comunicati chiar acum, cat suntem pe linie."
        )

        assertEquals(AudioEvidenceVerdict.DANGEROUS, result.verdict)
        assertTrue(result.reasonCodes.any { it == "sensitive_wrong_channel" || it == "identity_spoof" })
    }

    @Test
    fun realAsrSafeAccountCallProducesDangerousDespiteNoisyBankWords() {
        val result = AudioTranscriptEvidence.analyze(
            "Buna ziua, va sun din partea Bunci Meridian departamentul de securitate. " +
                "Pentru protectie vom transfera fondurile intr-un cont temporar de siguranta. " +
                "Va rog sa confirmati suma disponibila si actionam acum pentru siguranta fondurilor."
        )

        assertEquals(AudioEvidenceVerdict.DANGEROUS, result.verdict)
        assertEquals("CONV_BANK_SAFE_ACCOUNT", result.arcFamily)
    }

    @Test
    fun tinyDeviceGradeSafeAccountSnippetStillProducesActionableEvidence() {
        val result = AudioTranscriptEvidence.analyze(
            "bunci securitate cont temporar siguranta fonduri actionam acum"
        )

        assertTrue(result.verdict in setOf(AudioEvidenceVerdict.SUSPECT, AudioEvidenceVerdict.DANGEROUS))
        assertEquals("CONV_BANK_SAFE_ACCOUNT", result.arcFamily)
    }

    @Test
    fun deviceTinyBankAntiFraudIntroFromProfi12IsSuspectNotResidual() {
        val result = AudioTranscriptEvidence.analyze(
            "Bu nezioa, văsun din partea bănsin o vă trast, departamentul anti-fraude. Am"
        )

        assertEquals(AudioEvidenceVerdict.SUSPECT, result.verdict)
        assertEquals("CONV_BANK_ANTI_FRAUD_CALL", result.arcFamily)
    }

    @Test
    fun deviceTinyBankSecurityIntroFromProfi13IsSuspectNotResidual() {
        val result = AudioTranscriptEvidence.analyze(
            "Bu neziva, văsun din parte abunci meridian, departamento de seguridad. Am o-pops, am o-p"
        )

        assertEquals(AudioEvidenceVerdict.SUSPECT, result.verdict)
        assertEquals("CONV_BANK_ANTI_FRAUD_CALL", result.arcFamily)
    }

    @Test
    fun realAsrFraudulentCreditCancellationCodeProducesDangerous() {
        val result = AudioTranscriptEvidence.analyze(
            "Buna ziua, va sun de la banca Dacia Capital din departamentul antifrauda. " +
                "Cineva a incercat sa obtina un credit online pe numele dumneavoastra. " +
                "Trebuie sa anulam de urgenta si sa fiti pe faza pentru codul de anulare."
        )

        assertEquals(AudioEvidenceVerdict.DANGEROUS, result.verdict)
        assertEquals("CONV_BANK_FRAUDULENT_CREDIT", result.arcFamily)
    }

    @Test
    fun tinyDeviceGradeOtpCancellationSnippetStillProducesDangerous() {
        val result = AudioTranscriptEvidence.analyze(
            "bancii anti frauda cod anulare pse mese comunicati acum pe linie"
        )

        assertEquals(AudioEvidenceVerdict.DANGEROUS, result.verdict)
    }

    @Test
    fun deviceTinyBankAntiFraudIntroFromProfi14IsSuspectNotResidual() {
        val result = AudioTranscriptEvidence.analyze(
            "Bu nezua, văsun de la Banca 10 a capital din departamentul antifraude. A-a bănța"
        )

        assertEquals(AudioEvidenceVerdict.SUSPECT, result.verdict)
        assertEquals("CONV_BANK_ANTI_FRAUD_CALL", result.arcFamily)
    }

    @Test
    fun deviceTinyCreditLineIntroFromProfi15IsSuspectNotResidual() {
        val result = AudioTranscriptEvidence.analyze(
            "Bu nezioa, văsun din parte acreditline Romania. Avem o veste buna, ats fune, ats f"
        )

        assertEquals(AudioEvidenceVerdict.SUSPECT, result.verdict)
        assertEquals("CONV_BANK_FRAUDULENT_CREDIT", result.arcFamily)
    }

    @Test
    fun realAsrRemoteSupportMobileBankingProducesDangerous() {
        val result = AudioTranscriptEvidence.analyze(
            "Buna ziua, sunt de la panca euro garant departamentul de suport tehnic. " +
                "Am detectat o problema de securitate in aplicatia de mobile banking. " +
                "Trebuie sa efectuam diagnoza la distanta si sa instalati aplicatia noastra de support."
        )

        assertEquals(AudioEvidenceVerdict.DANGEROUS, result.verdict)
        assertEquals("CONV_TECH_SUPPORT_REMOTE_ACCESS", result.arcFamily)
    }

    @Test
    fun tinyDeviceGradeRemoteSupportSnippetStillProducesDangerous() {
        val result = AudioTranscriptEvidence.analyze(
            "panca support technic mobile banking diagnoza la distanta instalati aplicatia acum"
        )

        assertEquals(AudioEvidenceVerdict.DANGEROUS, result.verdict)
        assertEquals("CONV_TECH_SUPPORT_REMOTE_ACCESS", result.arcFamily)
    }

    @Test
    fun deviceTinyBankTechSupportIntroFromProfi16IsSuspectNotResidual() {
        val result = AudioTranscriptEvidence.analyze(
            "Unăsiva, văsun de la Banca e Urogarant, departamentul de suport technique. Unăsiva, v"
        )

        assertEquals(AudioEvidenceVerdict.SUSPECT, result.verdict)
        assertEquals("CONV_TECH_SUPPORT_REMOTE_ACCESS", result.arcFamily)
    }

    @Test
    fun realAsrBaitAndSwitchConfirmationCodeProducesDangerous() {
        val result = AudioTranscriptEvidence.analyze(
            "Verificare de rutina, totul pare in regula. Acum pe final am nevoie sa imi spuneti " +
                "codul de confirmare chiar acum cat suntem pe linie ca sa finalizam totul rapid."
        )

        assertEquals(AudioEvidenceVerdict.DANGEROUS, result.verdict)
    }

    @Test
    fun realAsrCryptoOpportunityWithSecrecyProducesDangerous() {
        val result = AudioTranscriptEvidence.analyze(
            "Am descoperit o oportunitate cu randament garantat. Este limitata in timp. " +
                "Ar fi de ajuns o depunere mica intr-un portofel cripto. Evident, e doar intre noi."
        )

        assertEquals(AudioEvidenceVerdict.DANGEROUS, result.verdict)
        assertEquals("CONV_INVESTMENT_REMOTE_ACCESS", result.arcFamily)
    }

    @Test
    fun tinyDeviceGradeTrustedContactMoneySnippetStillProducesDangerous() {
        val result = AudioTranscriptEvidence.analyze(
            "prieten card blocat problema urgenda trimiti suma mica cont nou nu spune nimanui"
        )

        assertEquals(AudioEvidenceVerdict.DANGEROUS, result.verdict)
        assertEquals("CONV_TRUSTED_CONTACT_MONEY_URGENCY", result.arcFamily)
    }

    @Test
    fun protectiveBankCallbackAdviceDoesNotBecomeDangerous() {
        val result = AudioTranscriptEvidence.analyze(
            "Buna ziua, sunt de la banca dumneavoastra. Daca nu sunteti sigur, " +
                "va recomand sa sunati direct la numarul de pe spatele cardului."
        )

        assertFalse(result.verdict == AudioEvidenceVerdict.DANGEROUS)
    }

    @Test
    fun blankTranscriptStaysUnverified() {
        val result = AudioTranscriptEvidence.analyze("   ")

        assertEquals(AudioEvidenceVerdict.UNVERIFIED, result.verdict)
        assertFalse(result.transcriptRedacted)
    }

    @Test
    fun realisticCallTranscriptFixturePackProducesActionableLocalEvidence() {
        val fixtureDir = File("../e2e_fixtures/sigurscan_e2e_fixtures_v2_realistic/fixtures/call_transcripts")
        val fixtures = fixtureDir.listFiles { file -> file.extension == "txt" }.orEmpty().sortedBy(File::getName)

        assertEquals(34, fixtures.size)
        val results = fixtures.map { fixture -> fixture.name to AudioTranscriptEvidence.analyze(fixture.readText()) }
        val unverified = results.filter { (_, result) -> result.verdict == AudioEvidenceVerdict.UNVERIFIED }

        assertTrue("Scam call fixtures left unverified: ${unverified.map { it.first }}", unverified.isEmpty())
        assertTrue(results.all { (_, result) -> result.transcriptRedacted && !result.rawAudioStored })
    }
}
