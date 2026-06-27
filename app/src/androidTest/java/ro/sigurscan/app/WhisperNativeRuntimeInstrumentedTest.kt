package ro.sigurscan.app

import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.ext.junit.runners.AndroidJUnit4
import android.util.Log
import com.google.gson.JsonParser
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class WhisperNativeRuntimeInstrumentedTest {
    @Test
    fun whisperNativeRuntimeLoadsOnDevice() {
        assertTrue(WhisperCppNativeBridge.available)
    }

    @Test
    fun bundledWhisperModelLoadsOnDevice() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val modelFile = File(context.cacheDir, "sigurscan-whisper/ggml-model.bin")
        modelFile.parentFile?.mkdirs()
        context.assets.open("asr/whispercpp/ggml-model.bin").use { input ->
            modelFile.outputStream().use { output -> input.copyTo(output) }
        }

        assertEquals(readManifestSha256(), sha256(modelFile))
        assertTrue(WhisperCppNativeBridge.canLoadModel(modelFile.absolutePath))
    }

    @Test
    fun romanianFixtureProducesActionableLocalEvidenceOnDevice() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val modelFile = copyBundledModelToCache()
        val pcm16 = instrumentation.context.assets.open("asr/romanian_vishing_fixture.wav").use { input ->
            readPcm16Mono16kWav(input.readBytes())
        }

        val startedAt = System.currentTimeMillis()
        val result = WhisperCppAsrEngine().transcribe(
            LocalAsrRequest(
                pcm16Mono = pcm16,
                sampleRateHz = 16_000,
                language = "ro",
                modelPath = modelFile.absolutePath
            )
        )
        val elapsedMs = System.currentTimeMillis() - startedAt
        Log.i(
            "SigurScanWhisperTest",
            "elapsed_ms=$elapsedMs transcript_present=${result.transcript.isNotBlank()} " +
                "verdict=${result.evidence?.verdict} reason=${result.reasonCode ?: "ok"}"
        )

        assertTrue("ASR should succeed without retaining transcript in logs; reason=${result.reasonCode}", result.success)
        assertNotNull(result.evidence)
        assertNotEquals(AudioEvidenceVerdict.UNVERIFIED, result.evidence!!.verdict)
    }

    private fun sha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            while (true) {
                val read = input.read(buffer)
                if (read <= 0) break
                digest.update(buffer, 0, read)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    private fun copyBundledModelToCache(): File {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val modelFile = File(context.cacheDir, "sigurscan-whisper/ggml-model.bin")
        modelFile.parentFile?.mkdirs()
        context.assets.open("asr/whispercpp/ggml-model.bin").use { input ->
            modelFile.outputStream().use { output -> input.copyTo(output) }
        }
        return modelFile
    }

    private fun readManifestSha256(): String {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val raw = context.assets.open("asr/whispercpp/model-manifest.json").bufferedReader().use { it.readText() }
        return JsonParser.parseString(raw).asJsonObject.get("sha256").asString
    }

    private fun readPcm16Mono16kWav(bytes: ByteArray): ShortArray {
        require(bytes.size > 44)
        require(String(bytes, 0, 4) == "RIFF")
        require(String(bytes, 8, 4) == "WAVE")

        var offset = 12
        var sampleRate = 0
        var channels = 0
        var bitsPerSample = 0
        var dataOffset = -1
        var dataSize = 0
        while (offset + 8 <= bytes.size) {
            val chunkId = String(bytes, offset, 4)
            val chunkSize = ByteBuffer.wrap(bytes, offset + 4, 4).order(ByteOrder.LITTLE_ENDIAN).int
            val chunkDataOffset = offset + 8
            when (chunkId) {
                "fmt " -> {
                    channels = ByteBuffer.wrap(bytes, chunkDataOffset + 2, 2).order(ByteOrder.LITTLE_ENDIAN).short.toInt()
                    sampleRate = ByteBuffer.wrap(bytes, chunkDataOffset + 4, 4).order(ByteOrder.LITTLE_ENDIAN).int
                    bitsPerSample = ByteBuffer.wrap(bytes, chunkDataOffset + 14, 2).order(ByteOrder.LITTLE_ENDIAN).short.toInt()
                }
                "data" -> {
                    dataOffset = chunkDataOffset
                    dataSize = chunkSize
                    break
                }
            }
            offset = chunkDataOffset + chunkSize + (chunkSize % 2)
        }

        require(channels == 1)
        require(sampleRate == 16_000)
        require(bitsPerSample == 16)
        require(dataOffset >= 0)

        val pcm = ShortArray(dataSize / 2)
        val buffer = ByteBuffer.wrap(bytes, dataOffset, dataSize).order(ByteOrder.LITTLE_ENDIAN)
        for (i in pcm.indices) {
            pcm[i] = buffer.short
        }
        return pcm
    }
}
