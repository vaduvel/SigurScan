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
        assertTrue(
            "Voice notes shared with other files must remain visible to SigurScan.",
            sendMultipleFilter?.contains("""android:mimeType="audio/*"""") == true
        )
    }

    @Test
    fun sendAcceptsUserInitiatedVoiceNotes() {
        val sendFilters = Regex(
            """<intent-filter>[\s\S]*?<action android:name="android.intent.action.SEND" />[\s\S]*?</intent-filter>"""
        ).findAll(manifest).map { it.value }.toList()

        assertTrue(
            "A single voice note/audio file shared from WhatsApp/Telegram/Files must expose SigurScan in the share sheet.",
            sendFilters.any { it.contains("""android:mimeType="audio/*"""") }
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
            "Public release must remove READ_PHONE_STATE; Radar uses the official opt-in CallScreening role, not broad phone-state access.",
            releaseOverlay.contains("""android:name="android.permission.READ_PHONE_STATE"""") &&
                releaseOverlay.contains("""tools:node="remove"""")
        )
        assertTrue(
            "Main manifest must declare the official CallScreeningService for opt-in Radar caller protection.",
            manifest.contains("""android:name=".SigurScanCallScreeningService"""") &&
                manifest.contains("""android.permission.BIND_SCREENING_SERVICE""") &&
                manifest.contains("""android.telecom.CallScreeningService""")
        )
        assertFalse(
            "Public release must not remove CallScreeningService now that Radar caller protection is opt-in and number-only.",
            releaseOverlay.contains("""android:name=".SigurScanCallScreeningService"""")
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
            "android.permission.READ_PHONE_NUMBERS",
            "android.permission.ANSWER_PHONE_CALLS",
            "android.permission.PROCESS_OUTGOING_CALLS"
        )

        forbiddenPermissions.forEach { permission ->
            assertFalse(
                "$permission must not be declared without a product/privacy review.",
                manifest.contains("""android:name="$permission"""")
            )
        }
    }

    @Test
    fun callTimeSpeakerGuardPromptCanUseNotificationsButNotOverlays() {
        assertTrue(
            "Incoming-call Speaker Guard needs a user-visible system prompt; Android 13+ requires POST_NOTIFICATIONS for that prompt.",
            manifest.contains("""android:name="android.permission.POST_NOTIFICATIONS"""")
        )
        assertTrue(
            "Speaker Guard call-time prompts must run through a foreground service before any microphone flow can start.",
            manifest.contains("""android:name="android.permission.FOREGROUND_SERVICE"""")
        )
        assertTrue(
            "Live-call Speaker Guard must declare the microphone foreground-service permission so Android keeps capture alive behind the dialer.",
            manifest.contains("""android:name="android.permission.FOREGROUND_SERVICE_MICROPHONE"""")
        )
        assertTrue(
            "The call-time prompt may need a full-screen intent when the app is closed and the phone is ringing.",
            manifest.contains("""android:name="android.permission.USE_FULL_SCREEN_INTENT"""")
        )
        val speakerGuardForegroundService = Regex(
            """<service[\s\S]*?android:name="\.SpeakerGuardForegroundService"[\s\S]*?/?>"""
        ).find(manifest)?.value.orEmpty()
        assertTrue(
            "SpeakerGuardForegroundService must be declared as an internal prompt carrier.",
            speakerGuardForegroundService.contains("""android:name=".SpeakerGuardForegroundService"""") &&
                speakerGuardForegroundService.contains("""android:exported="false"""")
        )
        assertTrue(
            "After user consent, SpeakerGuardForegroundService must claim microphone foreground type for live-call capture.",
            speakerGuardForegroundService.contains("""android:foregroundServiceType="microphone"""")
        )
        val speakerGuardPromptActivity = Regex(
            """<activity[\s\S]*?android:name="\.SpeakerGuardCallPromptActivity"[\s\S]*?/?>"""
        ).find(manifest)?.value.orEmpty()
        assertTrue(
            "Incoming-call Speaker Guard needs an internal, lock-screen capable prompt Activity instead of only navigating to MainActivity.",
            speakerGuardPromptActivity.contains("""android:name=".SpeakerGuardCallPromptActivity"""") &&
                speakerGuardPromptActivity.contains("""android:exported="false"""") &&
                speakerGuardPromptActivity.contains("""android:showWhenLocked="true"""") &&
                speakerGuardPromptActivity.contains("""android:turnScreenOn="true""")
        )
        assertFalse(
            "Speaker Guard must not use overlay permission for call-time prompts.",
            manifest.contains("""android:name="android.permission.SYSTEM_ALERT_WINDOW"""")
        )
    }

    @Test
    fun processTextAcceptsSelectedConversationText() {
        assertTrue(
            "Selected text from chat/email apps should expose SigurScan through ACTION_PROCESS_TEXT.",
            manifest.contains("""android.intent.action.PROCESS_TEXT""")
        )
    }
}
