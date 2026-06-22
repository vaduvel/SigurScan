package ro.sigurscan.app

object GateResultPresentation {
    fun isScanInProgress(result: GateResult): Boolean =
        result.asyncExpected || result.finality == GateFinality.PROVISIONAL

    fun isFinalUnverified(result: GateResult): Boolean =
        result.finality == GateFinality.FINAL &&
            (result.action == GateAction.UNVERIFIED || result.unknownReason == "BACKEND_UNVERIFIED")

    fun isVerificationUnavailable(result: GateResult): Boolean =
        result.finality == GateFinality.FINAL &&
            result.action == GateAction.INSUFFICIENT_EVIDENCE &&
            result.unknownReason in setOf("PROVIDERS_UNAVAILABLE", "BACKEND_UNAVAILABLE", "NETWORK_UNAVAILABLE")

    fun isLocalExtractionUnavailable(result: GateResult): Boolean =
        result.finality == GateFinality.FINAL &&
            result.action == GateAction.UNVERIFIED &&
            result.unknownReason in setOf(
                "LOCAL_QR_EXTRACTION_INCOMPLETE",
                "LOCAL_IMAGE_OCR_INCOMPLETE",
                "LOCAL_FILE_UNSUPPORTED",
                "LOCAL_OFFER_EXTRACTION_INCOMPLETE",
                "LOCAL_PDF_EXTRACTION_INCOMPLETE",
                "LOCAL_AUDIO_TRANSCRIPTION_REQUIRED"
            )

    fun userHeadline(result: GateResult): String =
        when {
            isScanInProgress(result) -> "Se verifică..."
            isFinalUnverified(result) || isVerificationUnavailable(result) -> "Neverificat"
            else -> result.userLabel
        }

    fun legacyRiskLevel(action: GateAction): String = when (action) {
        GateAction.DO_NOT_CONTINUE,
        GateAction.NO_ENTER_DATA,
        GateAction.NO_REPLY -> "dangerous"
        GateAction.VERIFY_OFFICIAL -> "medium"
        GateAction.CONTINUE_WITH_CAUTION -> "low"
        GateAction.UNVERIFIED -> "info"
        GateAction.INSUFFICIENT_EVIDENCE -> "error"
    }

    fun legacyRiskScore(action: GateAction): Int = when (action) {
        GateAction.DO_NOT_CONTINUE -> 95
        GateAction.NO_ENTER_DATA -> 88
        GateAction.NO_REPLY -> 82
        GateAction.VERIFY_OFFICIAL -> 55
        GateAction.CONTINUE_WITH_CAUTION -> 20
        GateAction.UNVERIFIED -> 0
        GateAction.INSUFFICIENT_EVIDENCE -> 0
    }

    fun legacyRiskScore(result: GateResult): Int =
        if (isScanInProgress(result) || isFinalUnverified(result) || isVerificationUnavailable(result)) {
            0
        } else {
            legacyRiskScore(result.action)
        }

    fun familyLabel(action: GateAction, fallback: String): String = when (action) {
        GateAction.DO_NOT_CONTINUE,
        GateAction.NO_ENTER_DATA,
        GateAction.NO_REPLY -> "Periculos"
        GateAction.VERIFY_OFFICIAL -> "Suspect"
        GateAction.CONTINUE_WITH_CAUTION -> "Sigur"
        GateAction.UNVERIFIED -> "Neverificat"
        GateAction.INSUFFICIENT_EVIDENCE -> "Suspect"
    }.ifBlank { fallback }

    fun familyLabel(result: GateResult, fallback: String): String =
        when {
            isScanInProgress(result) -> "Se verifică"
            isFinalUnverified(result) || isVerificationUnavailable(result) -> "Neverificat"
            else -> familyLabel(result.action, fallback)
        }

    fun legacyRiskLevel(result: GateResult): String =
        if (isScanInProgress(result) || isFinalUnverified(result) || isVerificationUnavailable(result)) {
            "info"
        } else {
            legacyRiskLevel(result.action)
        }

    fun supportText(result: GateResult): String = when {
        isScanInProgress(result) -> "Se verifică mesajul, destinația și sursele de risc."
        result.unknownReason == "LOCAL_AUDIO_TRANSCRIPTION_REQUIRED" -> "Audio primit. Pentru analiză este necesar transcriptul ales și trimis de tine."
        isLocalExtractionUnavailable(result) -> "Nu am putut citi suficient conținut verificabil pentru un verdict."
        isFinalUnverified(result) -> "Nu am găsit semnale clare de risc, dar nu avem confirmare oficială suficientă pentru un verdict sigur."
        isVerificationUnavailable(result) -> "Nu am putut finaliza verificarea online. Reîncearcă după ce conexiunea este stabilă."
        result.action == GateAction.DO_NOT_CONTINUE -> "Scanarea a gasit semnale clare de risc."
        result.action == GateAction.NO_ENTER_DATA -> "Pagina sau mesajul cere date sensibile pe un canal care nu este suficient validat."
        result.action == GateAction.NO_REPLY -> "Mesajul cere raspuns, coduri, bani sau continuarea conversatiei intr-un scenariu riscant."
        result.action == GateAction.VERIFY_OFFICIAL -> "Exista semnale care cer verificare manuala pe canalul oficial."
        result.action == GateAction.CONTINUE_WITH_CAUTION -> "Linkul verificat ajunge pe o destinatie oficiala sau delegata si nu am gasit cereri sensibile."
        else -> "Scanarea nu este completa inca."
    }

    fun primaryAction(result: GateResult): String = when {
        isScanInProgress(result) -> "Așteaptă verdictul final."
        result.unknownReason == "LOCAL_AUDIO_TRANSCRIPTION_REQUIRED" -> "Lipește transcriptul conversației înainte să continui."
        isLocalExtractionUnavailable(result) -> "Reîncearcă scanarea sau alege alt format."
        isFinalUnverified(result) -> "Verifică sursa în contextul oficial înainte de date sau plăți."
        isVerificationUnavailable(result) -> "Reîncearcă scanarea înainte să continui."
        result.action == GateAction.DO_NOT_CONTINUE -> "Nu apasa linkul si nu continua fluxul."
        result.action == GateAction.NO_ENTER_DATA -> "Nu introduce card, parola, CNP, IBAN sau cod OTP."
        result.action == GateAction.NO_REPLY -> "Nu raspunde si nu trimite coduri sau bani."
        result.action == GateAction.VERIFY_OFFICIAL -> "Deschide manual aplicatia sau site-ul oficial."
        result.action == GateAction.CONTINUE_WITH_CAUTION -> "Poti continua."
        else -> "Asteapta scanarea sau reincearca."
    }

    fun reasonText(result: GateResult, snapshot: EvidenceSnapshot?): String {
        val codes = result.reasonCodes.toSet()
        return when {
            "HIGH_CONFIDENCE_REPUTATION" in codes -> "Scanarea a gasit semnale clare de risc pe link."
            "SANDBOX_VERDICT" in codes -> "Pagina verificata a aratat comportament riscant."
            "SENSITIVE_FORM_ON_UNOFFICIAL_BRAND_DOMAIN" in codes -> "Pagina cere date sensibile pe un domeniu care nu apartine brandului mentionat."
            "BRAND_IMPERSONATION_UNOFFICIAL_SECRET_REQUEST" in codes -> "Mesajul pretinde un brand, dar linkul final cere secrete pe domeniu neoficial."
            "COURIER_UNOFFICIAL_SENSITIVE_REQUEST" in codes -> "Mesajul de curier cere plata sau date de card pe un domeniu neoficial."
            "LOOKALIKE_DOMAIN_SENSITIVE_REQUEST" in codes -> "Linkul final imita un brand oficial si cere date sensibile."
            "INFRASTRUCTURE_RISK_WITH_SENSITIVE_REQUEST" in codes -> "Linkul are semnale tehnice de imitare sau infrastructura improvizata si cere date sensibile."
            "UNOFFICIAL_HIGH_RISK_INFRASTRUCTURE" in codes -> "Linkul foloseste o infrastructura care nu inspira incredere si nu pare oficial."
            "CLAIM_NOT_CONFIRMED_ON_OFFICIAL_SOURCES" in codes -> "Linkul poate fi oficial, dar nu am confirmat public oferta sau promisiunea din mesaj."
            "PROMOTIONAL_CLAIM_NEEDS_CONFIRMATION" in codes -> "Mesajul vorbeste despre o oferta sau campanie care trebuie confirmata pe sursa oficiala."
            "DIRECT_REPLY_SECRET_REQUEST" in codes -> "Mesajul cere sa raspunzi cu un cod sau date sensibile."
            "TEXT_ONLY_SOCIAL_SCENARIO" in codes -> "Textul se potriveste unui scenariu social romanesc folosit pentru fraude."
            "MARKETPLACE_RECEIVE_MONEY_SENSITIVE_REQUEST" in codes -> "Fluxul de marketplace cere card sau OTP ca sa primesti bani."
            "SENSITIVE_FORM_UNOFFICIAL" in codes -> "Am gasit formular sensibil pe un domeniu nevalidat."
            "OFFICIAL_DESTINATION_AND_CLAIM_CONFIRMED" in codes -> "Linkul ajunge pe domeniu oficial, iar oferta sau contextul mentionat a fost confirmat."
            "OFFICIAL_DESTINATION_NO_SENSITIVE_COLLECTION" in codes -> "Linkul ajunge pe domeniu oficial/delegat si nu cere date sensibile."
            "BACKEND_ORCHESTRATED_VERDICT" in codes && hasUrlEvidence(snapshot) -> "Am verificat linkul final, captura securizata si reputatia destinatiei."
            "BACKEND_ORCHESTRATED_VERDICT" in codes -> "Am analizat mesajul si semnalele de risc disponibile."
            "BACKEND_UNVERIFIED" in codes && hasUrlEvidence(snapshot) -> "Verificarea s-a încheiat fără semnale clare de risc, dar destinația nu are proveniență oficială confirmată."
            "BACKEND_UNVERIFIED" in codes -> "Verificarea s-a încheiat fără semnale clare de risc în mesaj, dar nu avem suficiente dovezi oficiale pentru verdict verde."
            "LOCAL_QR_EXTRACTION_INCOMPLETE" in codes -> "Nu am putut citi conținut verificabil din codul QR."
            "LOCAL_IMAGE_OCR_INCOMPLETE" in codes -> "Nu am putut extrage text verificabil din imagine."
            "LOCAL_FILE_UNSUPPORTED" in codes -> "Fișierul nu este într-un format pe care îl putem analiza complet acum."
            "LOCAL_OFFER_EXTRACTION_INCOMPLETE" in codes -> "Nu am putut extrage conținut verificabil din ofertă."
            "LOCAL_PDF_EXTRACTION_INCOMPLETE" in codes -> "Nu am putut extrage text verificabil din PDF."
            "LOCAL_AUDIO_TRANSCRIPTION_REQUIRED" in codes -> "Audio primit; este necesar transcriptul pentru analiză."
            "WEAK_OR_EXPLANATORY_EVIDENCE_ONLY" in codes -> "Am gasit doar semnale slabe, precum marketing, CTA, tracking sau explicatii."
            "BRAND_OR_AUTHORITY_CLAIM_NEEDS_VERIFICATION" in codes -> "Mesajul mentioneaza un brand sau o autoritate si trebuie verificat pe canalul oficial."
            isVerificationUnavailable(result) -> "Nu am putut contacta serviciul de verificare. Reîncearcă scanarea când conexiunea este stabilă."
            "PROVIDER_REVIEW_REQUIRED" in codes && result.unknownReason == "PROVIDERS_PENDING_FOR_TARGET" -> "Se scaneaza linkul. Revenim cu verdictul dupa verificare."
            "PROVIDER_REVIEW_REQUIRED" in codes && result.unknownReason == "PROVIDERS_NOT_RUN_FOR_TARGET" -> "Se scaneaza linkul. Revenim cu verdictul dupa verificare."
            "PROVIDER_REVIEW_REQUIRED" in codes && result.unknownReason == "FINAL_URL_NOT_RESOLVED" -> "Urmarim destinatia finala a linkului inainte sa dam verdict."
            "PROVIDER_REVIEW_REQUIRED" in codes && result.unknownReason == "PILLARS_NOT_RUN" -> "Se scaneaza linkul. Revenim cu verdictul dupa verificare."
            result.action == GateAction.UNVERIFIED -> supportText(result)
            result.action == GateAction.INSUFFICIENT_EVIDENCE && result.unknownReason == "WEBMAIL_SHELL_ONLY" -> "Am primit doar shell-ul webmail, nu corpul complet al mesajului."
            result.action == GateAction.INSUFFICIENT_EVIDENCE && result.unknownReason == "OCR_LOW_CONFIDENCE" -> "OCR-ul nu a extras suficient text verificabil."
            result.action == GateAction.INSUFFICIENT_EVIDENCE && result.unknownReason == "PROVIDERS_UNAVAILABLE" -> "Nu am putut finaliza scanarea. Reincearca."
            result.action == GateAction.INSUFFICIENT_EVIDENCE && result.unknownReason == "NO_TARGET" -> "Nu am gasit un link complet pe care sa il putem scana."
            snapshot?.finalUrl != null -> "Am decis pe baza destinatiei finale, nu doar pe primul link."
            else -> supportText(result)
        }
    }

    fun hasUrlEvidence(snapshot: EvidenceSnapshot?): Boolean =
        snapshot != null && (
            !snapshot.primaryUrl.isNullOrBlank() ||
                !snapshot.finalUrl.isNullOrBlank() ||
                !snapshot.formActionUrl.isNullOrBlank() ||
                snapshot.redirectChain.any { it.isNotBlank() }
            )

    fun recommendedActions(result: GateResult): List<String> = when {
        isScanInProgress(result) -> listOf(
            "Așteaptă verdictul final.",
            "Nu introduce date până nu se termină scanarea."
        )
        isLocalExtractionUnavailable(result) -> listOf(
            "Reîncearcă cu o poză mai clară sau un PDF cu text selectabil.",
            "Pentru QR, apropie camera și ține codul drept în cadru.",
            "Dacă ai textul mesajului, copiază-l direct în câmpul de scanare."
        )
        isFinalUnverified(result) -> listOf(
            "Verifică sursa în aplicația, site-ul sau canalul oficial.",
            "Nu introduce card, parolă sau cod OTP dacă pagina cere date sensibile.",
            "Pentru plăți, caută manual comerciantul sau cere confirmare pe canal oficial."
        )
        isVerificationUnavailable(result) -> listOf(
            "Reîncearcă scanarea când ai conexiune stabilă.",
            "Nu introduce card, parolă sau cod OTP până nu primești verdictul.",
            "Dacă este urgent, deschide manual aplicația sau site-ul oficial."
        )
        result.action == GateAction.DO_NOT_CONTINUE -> listOf(
            "Nu apasa linkul.",
            "Deschide manual site-ul sau aplicatia oficiala.",
            "Daca ai introdus date, contacteaza banca imediat."
        )
        result.action == GateAction.NO_ENTER_DATA -> listOf(
            "Nu introduce date sensibile.",
            "Inchide pagina si verifica manual canalul oficial.",
            "Daca ai trimis card/OTP, blocheaza cardul si suna banca."
        )
        result.action == GateAction.NO_REPLY -> listOf(
            "Nu raspunde mesajului.",
            "Suna persoana sau institutia pe un numar cunoscut oficial.",
            "Nu trimite coduri, bani sau date personale."
        )
        result.action == GateAction.VERIFY_OFFICIAL -> listOf(
            "Verifica pe canalul oficial.",
            "Nu folosi numerele sau linkurile din mesaj.",
            "Continua doar dupa confirmare independenta."
        )
        result.action == GateAction.CONTINUE_WITH_CAUTION -> listOf(
            "Poti continua.",
            "Daca apare o cerere neasteptata de cod, card sau parola, opreste-te.",
            "Pentru plati sau date sensibile, foloseste aplicatia oficiala."
        )
        else -> listOf(
            "Asteapta finalizarea scanarii.",
            "Daca scanarea nu se finalizeaza, reincearca.",
            "Nu introduce date pana nu primesti verdictul."
        )
    }
}
