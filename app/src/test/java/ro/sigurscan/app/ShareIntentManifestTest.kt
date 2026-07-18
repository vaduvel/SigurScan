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
    fun v1ReleaseKeepsManualListenerButRemovesLiveCallSurface() {
        val releaseOverlay = File("src/release/AndroidManifest.xml").readText()
        assertFalse(
            "V1 must keep RECORD_AUDIO for the explicit Urechea listener; only same-phone live-call automation is deferred.",
            releaseOverlay.contains("""android:name="android.permission.RECORD_AUDIO"""") &&
                releaseOverlay.contains("""tools:node="remove"""")
        )
        assertTrue(
            "V1 must remove READ_PHONE_STATE because same-phone live-call detection is deferred.",
            releaseOverlay.contains("""android:name="android.permission.READ_PHONE_STATE"""") &&
                releaseOverlay.contains("""tools:node="remove"""")
        )
        assertTrue(
            "Main manifest may retain the compiled V2 CallScreeningService behind its own feature flag.",
            manifest.contains("""android:name=".SigurScanCallScreeningService"""") &&
                manifest.contains("""android.permission.BIND_SCREENING_SERVICE""") &&
                manifest.contains("""android.telecom.CallScreeningService""")
        )
        assertTrue(
            "The V1 release manifest must remove CallScreeningService entirely, not merely disable it.",
            releaseOverlay.contains("""android:name=".SigurScanCallScreeningService"""")
        )
        assertTrue(
            "The V1 release manifest must remove USE_FULL_SCREEN_INTENT with the live-call prompt.",
            releaseOverlay.contains("""android:name="android.permission.USE_FULL_SCREEN_INTENT""") &&
                releaseOverlay.contains("""tools:node="remove""")
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
    fun manualSpeakerGuardListenerUsesVisibleMicrophoneServiceWithoutOverlays() {
        assertTrue(
            "The manual Urechea listener needs a visible foreground notification on Android 13+.",
            manifest.contains("""android:name="android.permission.POST_NOTIFICATIONS"""")
        )
        assertTrue(
            "The manual Urechea listener must run through a foreground service.",
            manifest.contains("""android:name="android.permission.FOREGROUND_SERVICE"""")
        )
        assertTrue(
            "The manual Urechea listener must declare the microphone foreground-service permission.",
            manifest.contains("""android:name="android.permission.FOREGROUND_SERVICE_MICROPHONE"""")
        )
        assertTrue(
            "The source manifest may retain the V2 full-screen permission only because the V1 release overlay removes it.",
            manifest.contains("""android:name="android.permission.USE_FULL_SCREEN_INTENT"""")
        )
        val speakerGuardForegroundService = Regex(
            """<service[\s\S]*?android:name="\.SpeakerGuardForegroundService"[\s\S]*?/?>"""
        ).find(manifest)?.value.orEmpty()
        assertTrue(
            "SpeakerGuardForegroundService must remain internal to the explicit listener flow.",
            speakerGuardForegroundService.contains("""android:name=".SpeakerGuardForegroundService"""") &&
                speakerGuardForegroundService.contains("""android:exported="false"""")
        )
        assertTrue(
            "After user consent, SpeakerGuardForegroundService must claim microphone foreground type for listener capture.",
            speakerGuardForegroundService.contains("""android:foregroundServiceType="microphone"""")
        )
        assertFalse(
            "Urechea must not use overlay permission.",
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
