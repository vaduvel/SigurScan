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
    fun sensitiveBackgroundPermissionsStayOutOfManifest() {
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
    fun speakerGuardDeclaresReviewedMicrophonePermission() {
        assertTrue(
            "Speaker Guard needs explicit RECORD_AUDIO for user-started microphone capture.",
            manifest.contains("""android:name="android.permission.RECORD_AUDIO"""")
        )
    }

    @Test
    fun callScreeningServiceIsDeclaredWithoutAutoRejectPermissions() {
        assertTrue(
            "Radar CallScreening requires READ_PHONE_STATE for OS integration.",
            manifest.contains("""android:name="android.permission.READ_PHONE_STATE"""")
        )
        assertTrue(
            "CallScreening service must be bound only through the platform screening permission.",
            manifest.contains("""android:permission="android.permission.BIND_SCREENING_SERVICE"""")
        )
        assertTrue(
            "Manifest must expose the Telecom CallScreeningService action.",
            manifest.contains("""android:name="android.telecom.CallScreeningService"""")
        )
    }
}
