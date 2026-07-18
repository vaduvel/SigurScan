package ro.sigurscan.app

import java.util.Locale
import kotlin.math.max

data class SpeakerGuardReasonPresentation(
    val title: String,
    val body: String
)

data class SpeakerGuardPresentation(
    val title: String,
    val listeningLabel: String,
    val elapsedLabel: String,
    val privacyLine: String,
    val status: String,
    val verdictTitle: String,
    val primaryAction: String,
    val showHangUpCta: Boolean,
    val diagnosticLine: String?,
    val reasons: List<SpeakerGuardReasonPresentation>
)

data class SpeakerGuardCallPromptPresentation(
    val title: String,
    val body: String,
    val privacyLine: String,
    val primaryCta: String,
    val secondaryCta: String
)

fun speakerGuardPresentation(
    snapshot: SpeakerGuardSnapshot,
    evidence: AudioEvidenceResult?,
    nowMillis: Long = System.currentTimeMillis()
): SpeakerGuardPresentation {
    val rawVerdict = evidence?.verdict ?: snapshot.latestVerdict
    val verdict = when {
        !snapshot.active && rawVerdict == AudioEvidenceVerdict.UNVERIFIED -> null
        else -> rawVerdict
    }
    return SpeakerGuardPresentation(
        title = "Urechea ascultă",
        listeningLabel = if (snapshot.active) "Ascult conversația" else "Oprit",
        elapsedLabel = elapsedLabel(snapshot.startedAtEpochMillis, nowMillis),
        privacyLine = "Analizez pe telefonul tău. Nimic nu pleacă de pe el.",
        status = snapshot.status,
        verdictTitle = verdictTitle(verdict),
        primaryAction = primaryAction(verdict),
        showHangUpCta = verdict == AudioEvidenceVerdict.DANGEROUS,
        diagnosticLine = diagnosticLine(snapshot),
        reasons = reasonsFor(evidence, snapshot)
    )
}

fun speakerGuardCallPrompt(decision: RadarCallDecision): SpeakerGuardCallPromptPresentation {
    val warned = decision.action == RadarCallAction.WARN
    return SpeakerGuardCallPromptPresentation(
        title = if (warned) "Te sună un număr suspect" else "Te sună un număr necunoscut",
        body = "Vrei să-l pui pe difuzor și să ascult împreună cu tine, ca să-ți spun dacă pare o țeapă?",
        privacyLine = "Pornește doar dacă apeși. Analiza se face pe telefonul tău — nimic nu pleacă de pe el.",
        primaryCta = "Ascultă pe difuzor",
        secondaryCta = "Nu acum"
    )
}

private fun elapsedLabel(startedAtEpochMillis: Long?, nowMillis: Long): String {
    if (startedAtEpochMillis == null || nowMillis < startedAtEpochMillis) return "0:00"
    val totalSeconds = max(0L, (nowMillis - startedAtEpochMillis) / 1000L)
    return String.format(Locale.US, "%d:%02d", totalSeconds / 60L, totalSeconds % 60L)
}

private fun verdictTitle(verdict: AudioEvidenceVerdict?): String {
    return when (verdict) {
        AudioEvidenceVerdict.DANGEROUS -> "Pare o țeapă"
        AudioEvidenceVerdict.SUSPECT -> "Pare suspect"
        AudioEvidenceVerdict.UNVERIFIED -> "Încă verific"
        null -> "Ascult conversația"
    }
}

private fun primaryAction(verdict: AudioEvidenceVerdict?): String {
    return when (verdict) {
        AudioEvidenceVerdict.DANGEROUS -> "Închide apelul. Nu da date și nu transfera bani."
        AudioEvidenceVerdict.SUSPECT -> "Nu da date sau bani până nu verifici pe canal oficial."
        AudioEvidenceVerdict.UNVERIFIED -> "Continuă doar dacă ești sigur. Nu oferi date sensibile."
        null -> "Pune celălalt telefon pe difuzor și lasă analiza locală pornită."
    }
}

private fun diagnosticLine(snapshot: SpeakerGuardSnapshot): String? {
    if (!snapshot.active && snapshot.chunksAnalyzed == 0 && snapshot.chunksDropped == 0) return null
    val parts = mutableListOf<String>()
    if (snapshot.chunksAnalyzed == 0) {
        parts += "Aștept primul fragment audio clar"
    } else {
        parts += "Am analizat ${snapshot.chunksAnalyzed} ${fragmentLabel(snapshot.chunksAnalyzed)} local"
    }
    val latestReason = reasonLabel(snapshot.latestReasonCode)
        ?: verdictDiagnosticLabel(snapshot.latestVerdict)
    latestReason?.let { parts += "ultimul: $it" }
    if (snapshot.chunksDropped > 0) {
        parts += "${snapshot.chunksDropped} sărit"
    }
    return parts.joinToString(" · ")
}

private fun fragmentLabel(count: Int): String {
    return if (count == 1) "fragment" else "fragmente"
}

private fun reasonLabel(reasonCode: String?): String? {
    return when (reasonCode) {
        "empty_transcript" -> "voce neclară"
        "unsupported_audio_format" -> "format audio neacceptat"
        "whisper_native_unavailable" -> "motor audio indisponibil"
        "microphone_permission_missing" -> "microfon nepermis"
        "audio_record_unavailable", "audio_record_init_failed" -> "microfon indisponibil"
        null, "" -> null
        else -> "verificare locală"
    }
}

private fun verdictDiagnosticLabel(verdict: AudioEvidenceVerdict?): String? {
    return when (verdict) {
        AudioEvidenceVerdict.UNVERIFIED -> "fără semnale clare"
        AudioEvidenceVerdict.SUSPECT -> "semnale suspecte"
        AudioEvidenceVerdict.DANGEROUS -> "semnale puternice"
        null -> null
    }
}

private fun reasonsFor(
    evidence: AudioEvidenceResult?,
    snapshot: SpeakerGuardSnapshot
): List<SpeakerGuardReasonPresentation> {
    val codes = buildSet {
        addAll(evidence?.reasonCodes.orEmpty())
        snapshot.latestReasonCode?.let(::add)
    }
    val arcFamily = evidence?.arcFamily ?: snapshot.latestArcFamily
    return buildList {
        if ("identity_spoof" in codes) {
            add(
                SpeakerGuardReasonPresentation(
                    title = "Se dă drept bancă sau autoritate",
                    body = "Verifică mereu apelând instituția pe numărul oficial."
                )
            )
        }
        if ("sensitive_wrong_channel" in codes) {
            add(
                SpeakerGuardReasonPresentation(
                    title = "Îți cere coduri sau date sensibile",
                    body = "Banca reală nu cere coduri, PIN, CVV sau parole prin telefon."
                )
            )
        }
        if (arcFamily == "CONV_BANK_SAFE_ACCOUNT") {
            add(
                SpeakerGuardReasonPresentation(
                    title = "Cere transfer într-un cont sigur",
                    body = "Un cont nou indicat la telefon este un semnal clasic de fraudă."
                )
            )
        }
        if (arcFamily == "CONV_BANK_FRAUDULENT_CREDIT") {
            add(
                SpeakerGuardReasonPresentation(
                    title = "Invocă un credit sau dosar urgent",
                    body = "Închide și verifică direct la bancă sau la instituția reală."
                )
            )
        }
        if (arcFamily == "CONV_INVESTMENT_REMOTE_ACCESS") {
            add(
                SpeakerGuardReasonPresentation(
                    title = "Cere instalare sau control la distanță",
                    body = "Nu instala aplicații de control la indicația unui apelant."
                )
            )
        }
        if (arcFamily == "CONV_FAMILY_EMERGENCY") {
            add(
                SpeakerGuardReasonPresentation(
                    title = "Folosește o urgență de familie",
                    body = "Sună direct persoana sau familia pe un număr cunoscut."
                )
            )
        }
        if ("value_request_needs_verification" in codes) {
            add(
                SpeakerGuardReasonPresentation(
                    title = "Cere bani sau transfer",
                    body = "Nu transfera bani până nu confirmi dintr-o sursă independentă."
                )
            )
        }
        if ("campaign_match_only" in codes) {
            add(
                SpeakerGuardReasonPresentation(
                    title = "Seamănă cu un scenariu raportat",
                    body = "Tratăm apelul prudent până ai o confirmare oficială."
                )
            )
        }
    }.distinctBy { it.title }
}
