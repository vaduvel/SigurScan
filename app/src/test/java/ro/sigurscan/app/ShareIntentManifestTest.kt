package ro.sigurscan.app

import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class ShareIntentManifestTest {
    @Test
    fun sendMultipleAcceptsImagesAndMixedAttachments() {
        val manifest = File("src/main/AndroidManifest.xml").readText()
        val sendMultipleFilter = Regex(
            """<intent-filter>[\s\S]*?<action android:name="android.intent.action.SEND_MULTIPLE" />[\s\S]*?</intent-filter>"""
        ).find(manifest)?.value

        assertNotNull("Manifest must declare ACTION_SEND_MULTIPLE.", sendMultipleFilter)
        assertTrue(
            "Multiple screenshots/images must expose SigurScan in the Android share sheet.",
            sendMultipleFilter?.contains("""android:mimeType="image/*"""") == true
        )
        assertTrue(
            "Mixed PDF/image/email attachments commonly arrive as */* and must remain shareable to SigurScan.",
            sendMultipleFilter?.contains("""android:mimeType="*/*"""") == true
        )
    }
}
