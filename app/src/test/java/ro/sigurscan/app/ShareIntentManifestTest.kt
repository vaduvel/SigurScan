package ro.sigurscan.app

import org.junit.Assert.assertNotNull
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class ShareIntentManifestTest {
    private val manifest: String
        get() = File("src/main/AndroidManifest.xml").readText()

    @Test
    fun sendMultipleAcceptsImagesAndMixedAttachments() {
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

    @Test
    fun sensitiveBackgroundPermissionsStayOutOfReleaseOverlay() {
        val releaseOverlay = File("src/release/AndroidManifest.xml").readText()
        assertTrue(
            "Public release must remove RECORD_AUDIO until Speaker Guard has final Play policy coverage.",
            releaseOverlay.contains("""android:name="android.permission.RECORD_AUDIO"""") &&
                releaseOverlay.contains("""tools:node="remove"""")
        )
        assertTrue(
            "Public release must remove READ_PHONE_STATE until Radar CallScreening ships as a reviewed opt-in surface.",
            releaseOverlay.contains("""android:name="android.permission.READ_PHONE_STATE"""") &&
                releaseOverlay.contains("""tools:node="remove"""")
        )
        assertTrue(
            "Public release must remove CallScreeningService from the mainstream manifest.",
            releaseOverlay.contains("""android:name=".SigurScanCallScreeningService"""") &&
                releaseOverlay.contains("""tools:node="remove"""")
        )
    }

    @Test
    fun sensitiveSmsAndContactsPermissionsStayOutOfManifest() {
        val forbiddenPermissions = listOf(
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.SEND_SMS",
            "android.permission.READ_CALL_LOG",
            "android.permission.READ_CONTACTS",
            "android.permission.POST_NOTIFICATIONS"
        )

        forbiddenPermissions.forEach { permission ->
            assertFalse(
                "$permission must not be declared without a product/privacy review.",
                manifest.contains("""android:name="$permission"""")
            )
        }
    }

    @Test
    fun processTextAcceptsSelectedConversationText() {
        assertTrue(
            "Selected text from chat/email apps should expose SigurScan through ACTION_PROCESS_TEXT.",
            manifest.contains("""android.intent.action.PROCESS_TEXT""")
        )
    }
}
