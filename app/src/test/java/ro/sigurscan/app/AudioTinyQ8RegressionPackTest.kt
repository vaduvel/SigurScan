package ro.sigurscan.app

import com.google.gson.Gson
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class AudioTinyQ8RegressionPackTest {
    private val gson = Gson()

    @Test
    fun tinyQ8FixturePackIsPresentAndTraceable() {
        val fixtures = loadFixtures()

        assertEquals(EXPECTED_IDS, fixtures.map { it.id }.toSet())
        assertEquals(fixtures.size, fixtures.map { it.id }.toSet().size)
        assertTrue(fixtures.all { it.device.contains("Nokia C22") })
        assertTrue(fixtures.all { it.asr_engine.contains("tiny-q8") })
        assertTrue(fixtures.all { it.chunk_seconds == 3 })
    }

    @Test
    fun capturedTinyQ8ScamTranscriptsDoNotFallBackToUnverified() {
        val failures = loadFixtures().mapNotNull { fixture ->
            val result = AudioTranscriptEvidence.analyze(fixture.tiny_transcript)
            val expectedRank = rank(AudioEvidenceVerdict.valueOf(fixture.expected_min_verdict))
            val actualRank = rank(result.verdict)
            val familyOk = fixture.expected_family.isNullOrBlank() || result.arcFamily == fixture.expected_family
            val verdictOk = actualRank >= expectedRank
            val privacyOk = result.transcriptRedacted && !result.rawAudioStored

            if (verdictOk && familyOk && privacyOk && result.verdict != AudioEvidenceVerdict.UNVERIFIED) {
                null
            } else {
                "${fixture.id}: verdict=${result.verdict}, family=${result.arcFamily}, " +
                    "redacted=${result.transcriptRedacted}, rawAudioStored=${result.rawAudioStored}"
            }
        }

        assertTrue("Tiny-q8 device scam fixtures regressed: $failures", failures.isEmpty())
    }

    private fun loadFixtures(): List<TinyQ8Fixture> {
        val root = fixtureRoot()
        val files = root.listFiles { file -> file.extension == "json" }.orEmpty().sortedBy(File::getName)
        assertFalse("Missing tiny-q8 fixture files in ${root.absolutePath}", files.isEmpty())
        return files.map { file -> gson.fromJson(file.readText(), TinyQ8Fixture::class.java) }
    }

    private fun fixtureRoot(): File {
        val candidates = listOf(
            File("app/src/test/resources/fixtures/audio/tiny_q8_c22"),
            File("src/test/resources/fixtures/audio/tiny_q8_c22")
        )
        return candidates.firstOrNull { it.isDirectory } ?: candidates.first()
    }

    private fun rank(verdict: AudioEvidenceVerdict): Int = when (verdict) {
        AudioEvidenceVerdict.UNVERIFIED -> 0
        AudioEvidenceVerdict.SUSPECT -> 1
        AudioEvidenceVerdict.DANGEROUS -> 2
    }

    private data class TinyQ8Fixture(
        val id: String,
        val source_audio: String,
        val device: String,
        val asr_engine: String,
        val chunk_seconds: Int,
        val tiny_transcript: String,
        val expected_min_verdict: String,
        val expected_family: String?,
        val ground_truth: String,
        val notes: String?
    )

    private companion object {
        val EXPECTED_IDS = setOf(
            "profi_go_12_tiny_q8_c22",
            "profi_go_13_tiny_q8_c22",
            "profi_go_14_tiny_q8_c22",
            "profi_go_15_tiny_q8_c22",
            "profi_go_16_tiny_q8_c22"
        )
    }
}
