package ro.sigurscan.app

enum class SharedContentFidelity(
    val title: String,
    val description: String
) {
    FULL_HTML(
        title = "Am primit HTML complet",
        description = "Putem verifica structura emailului și linkurile ascunse sub butoane."
    ),
    PLAIN_TEXT_ONLY(
        title = "Am primit doar text vizibil",
        description = "Putem analiza mesajul și linkurile afișate. Dacă exista un buton cu link ascuns, aplicația de mail nu ni l-a trimis."
    ),
    FILE_OR_EMAIL(
        title = "Am primit fișier/email partajat",
        description = "Încercăm să citim fișierul complet și să extragem linkurile din HTML, PDF sau imagine."
    ),
    AUDIO_FILE(
        title = "Am primit audio partajat",
        description = "Transcriem local audio-ul pe telefon și analizăm semnalele de fraudă din conversație."
    )
}

internal enum class SharedTextCandidateKind {
    HTML,
    PLAIN_TEXT
}

internal data class SharedTextCandidate(
    val text: String,
    val kind: SharedTextCandidateKind,
    val sourceLabel: String
)

internal data class ResolvedSharedTextPayload(
    val text: String,
    val sourceLabel: String,
    val preserveHtml: Boolean,
    val fidelity: SharedContentFidelity
)

internal object SharedTextPayloadResolver {
    fun resolve(candidates: List<SharedTextCandidate>): ResolvedSharedTextPayload? {
        val validCandidates = candidates.filter { it.text.isNotBlank() }
        val selected = validCandidates.firstOrNull { it.kind == SharedTextCandidateKind.HTML }
            ?: validCandidates.firstOrNull { it.kind == SharedTextCandidateKind.PLAIN_TEXT }
            ?: return null

        val isHtml = selected.kind == SharedTextCandidateKind.HTML
        return ResolvedSharedTextPayload(
            text = selected.text,
            sourceLabel = selected.sourceLabel,
            preserveHtml = isHtml,
            fidelity = if (isHtml) SharedContentFidelity.FULL_HTML else SharedContentFidelity.PLAIN_TEXT_ONLY
        )
    }
}
