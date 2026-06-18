package ro.sigurscan.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class AndroidBuildConfigPolicyTest {
    private val gradleFile: String
        get() = File("build.gradle.kts").readText()
    private val mainActivityFile: String
        get() = File("src/main/java/ro/sigurscan/app/MainActivity.kt").readText()
    private val manifest: String
        get() = File("src/main/AndroidManifest.xml").readText()

    @Test
    fun directProviderKeysAreOptInAndProviderBuildConfigFieldsStayEmpty() {
        assertTrue(
            "Direct provider keys must default to disabled.",
            gradleFile.contains("""localProperties.getProperty("SIGURSCAN_ENABLE_DIRECT_PROVIDER_KEYS")""") &&
                gradleFile.contains("""?: "false"""")
        )

        assertEquals(
            "URLScan key must stay empty in debug and release BuildConfig.",
            2,
            Regex(
                """buildConfigField\(\s*"String",\s*"URLSCAN_API_KEY",\s*"\\"\\""\s*\)""",
                RegexOption.DOT_MATCHES_ALL
            ).findAll(gradleFile).count()
        )
        assertEquals(
            "Google Web Risk key must stay empty in debug and release BuildConfig.",
            2,
            Regex(
                """buildConfigField\(\s*"String",\s*"GOOGLE_WEB_RISK_API_KEY",\s*"\\"\\""\s*\)""",
                RegexOption.DOT_MATCHES_ALL
            ).findAll(gradleFile).count()
        )
    }

    @Test
    fun audioAsrFeatureFlagDefaultsOff() {
        assertTrue(
            "Audio ASR must default to disabled unless explicitly enabled for a reviewed build.",
            gradleFile.contains("""localProperties.getProperty("SIGURSCAN_ENABLE_AUDIO_ASR")""") &&
                gradleFile.contains("""?: "false"""")
        )
        assertTrue(
            "Both debug and release must use the same reviewed audio gate flag.",
            Regex(
                """buildConfigField\("Boolean",\s*"SIGURSCAN_ENABLE_AUDIO_ASR",\s*enableAudioAsr\.toString\(\)\)"""
            ).findAll(gradleFile).count() >= 2
        )
        assertTrue(
            "Release builds with audio disabled must not package the local ASR model assets.",
            gradleFile.contains("""if (enableAudioAsr)""") &&
                gradleFile.contains("""assets.srcDir("src/audioAsr/assets")""")
        )
        assertTrue(
            "Whisper native build must be opt-in with the reviewed audio flag.",
            gradleFile.contains("""if (enableAudioAsr)""") &&
                gradleFile.contains("""externalNativeBuild""")
        )
        assertTrue(
            "Public release must not show the Speaker Guard/ASR surface while the audio flag is disabled.",
            mainActivityFile.contains("""if (BuildConfig.SIGURSCAN_ENABLE_AUDIO_ASR)""") &&
                mainActivityFile.contains("""AudioAsrReadinessCard(""")
        )
    }

    @Test
    fun playIntegrityFeatureFlagDefaultsOff() {
        assertTrue(
            "Play Integrity token requests must default to disabled until Play Console/SDK rollout is reviewed.",
            gradleFile.contains("""localProperties.getProperty("SIGURSCAN_ENABLE_PLAY_INTEGRITY")""") &&
                gradleFile.contains("""?: "false"""")
        )
        assertTrue(
            "Debug and release builds must use the same reviewed Play Integrity gate flag.",
            Regex(
                """buildConfigField\("Boolean",\s*"SIGURSCAN_ENABLE_PLAY_INTEGRITY",\s*enablePlayIntegrity\.toString\(\)\)"""
            ).findAll(gradleFile).count() >= 2
        )
    }

    @Test
    fun releaseStaticApiKeyIsExplicitFallbackOnly() {
        assertTrue(
            "Release builds must not embed a static client API key unless a conscious fallback flag is set.",
            gradleFile.contains("""localProperties.getProperty("SIGURSCAN_ALLOW_RELEASE_STATIC_API_KEY")""") &&
                gradleFile.contains("""fun releaseApiKeyBuildConfigString()""") &&
                gradleFile.contains("""if (allowReleaseStaticApiKey)""") &&
                gradleFile.contains("""buildConfigField("String", "SIGURSCAN_API_KEY", releaseApiKeyBuildConfigString())""")
        )
    }

    @Test
    fun releaseBackendBaseUrlDefaultsToOfficialApiDomain() {
        assertTrue(
            "Release builds must not silently fall back to offline.sigurscan.invalid when local release config is missing.",
            gradleFile.contains(
                """buildConfigSafeString("SIGURSCAN_RELEASE_BACKEND_BASE_URL", "SIGURSCAN_RELEASE_BACKEND_BASE_URL", "https://api.sigurscan.com/")"""
            )
        )
    }

    @Test
    fun networkSecurityConfigDisablesCleartextForOfficialApi() {
        val networkSecurity = File("src/main/res/xml/network_security_config.xml").readText()

        assertTrue(
            "App manifest must bind Android network security config.",
            manifest.contains("""android:networkSecurityConfig="@xml/network_security_config"""")
        )
        assertTrue(
            "App manifest must explicitly disable cleartext traffic.",
            manifest.contains("""android:usesCleartextTraffic="false"""")
        )
        assertTrue(
            "Network security config must disable cleartext by default.",
            networkSecurity.contains("""<base-config cleartextTrafficPermitted="false">""")
        )
        assertTrue(
            "Official API domain must be declared without cleartext.",
            networkSecurity.contains(""">api.sigurscan.com</domain>""") &&
                networkSecurity.contains("""<domain-config cleartextTrafficPermitted="false">""")
        )
    }
}
