package ro.sigurscan.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.io.File

class SandboxPreviewModelTest {
    @Test
    fun sandboxPreviewDoesNotUseFaviconFallbackBeforeScreenshotExists() {
        assertNull(sandboxScreenshotModel(null))
    }

    @Test
    fun sandboxPreviewUsesUrlscanScreenshotWhenAvailable() {
        assertEquals(
            "https://urlscan.io/screenshots/scan-id.png",
            sandboxScreenshotModel("https://urlscan.io/screenshots/scan-id.png")
        )
    }

    @Test
    fun sandboxPreviewKeepsLocalPrivateScreenshotUriUnchanged() {
        val cachedFile = File.createTempFile("sigurscan-urlscan", ".png").apply {
            writeBytes(byteArrayOf(0x01, 0x02, 0x03))
            deleteOnExit()
        }
        val localUrl = cachedFile.toURI().toString()

        assertEquals(
            localUrl,
            sandboxScreenshotModel(localUrl)
        )
    }

    @Test
    fun urlscanScreenshotUrlPointsToPublicScreenshotAsset() {
        assertEquals(
            "https://urlscan.io/screenshots/019e8715-bb13-75e8-ab41-ddb55713c24e.png",
            urlscanScreenshotUrl("019e8715-bb13-75e8-ab41-ddb55713c24e")
        )
    }
}
