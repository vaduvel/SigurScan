import java.io.FileInputStream
import java.util.Properties

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.serialization)
}

val localProperties = Properties().apply {
    val localPropertiesFile = rootProject.file("local.properties")
    if (localPropertiesFile.exists()) {
        FileInputStream(localPropertiesFile).use { load(it) }
    }
}

val keystoreProperties = Properties().apply {
    val keystorePropertiesFile = rootProject.file("keystore.properties")
    if (keystorePropertiesFile.exists()) {
        FileInputStream(keystorePropertiesFile).use { load(it) }
    }
}

val hasReleaseKeystore = listOf("storeFile", "storePassword", "keyAlias", "keyPassword")
    .all { !keystoreProperties.getProperty(it).isNullOrBlank() }

val allowDirectProviderKeys = (
    localProperties.getProperty("SIGURSCAN_ENABLE_DIRECT_PROVIDER_KEYS")
        ?: System.getenv("SIGURSCAN_ENABLE_DIRECT_PROVIDER_KEYS")
        ?: "false"
    ).trim().lowercase() in setOf("1", "true", "yes", "on")

val enableAudioAsr = (
    localProperties.getProperty("SIGURSCAN_ENABLE_AUDIO_ASR")
        ?: System.getenv("SIGURSCAN_ENABLE_AUDIO_ASR")
        ?: "false"
    ).trim().lowercase() in setOf("1", "true", "yes", "on")

val enableLiveCall = (
    localProperties.getProperty("SIGURSCAN_ENABLE_LIVE_CALL")
        ?: System.getenv("SIGURSCAN_ENABLE_LIVE_CALL")
        ?: "false"
    ).trim().lowercase() in setOf("1", "true", "yes", "on")

if (enableAudioAsr) {
    val whisperCMake = rootProject.file("third_party/whisper.cpp/CMakeLists.txt")
    val whisperModel = file("src/audioAsr/assets/asr/whispercpp/ggml-model.bin")
    if (!whisperCMake.isFile) {
        throw GradleException(
            "SIGURSCAN_ENABLE_AUDIO_ASR=true requires the whisper.cpp submodule. " +
                "Run: git submodule update --init --recursive third_party/whisper.cpp"
        )
    }
    if (!whisperModel.isFile) {
        throw GradleException(
            "SIGURSCAN_ENABLE_AUDIO_ASR=true requires the bundled Whisper model at " +
                "app/src/audioAsr/assets/asr/whispercpp/ggml-model.bin"
        )
    }
}

val enablePlayIntegrity = (
    localProperties.getProperty("SIGURSCAN_ENABLE_PLAY_INTEGRITY")
        ?: System.getenv("SIGURSCAN_ENABLE_PLAY_INTEGRITY")
        ?: "false"
    ).trim().lowercase() in setOf("1", "true", "yes", "on")

val allowReleaseStaticApiKey = (
    localProperties.getProperty("SIGURSCAN_ALLOW_RELEASE_STATIC_API_KEY")
        ?: System.getenv("SIGURSCAN_ALLOW_RELEASE_STATIC_API_KEY")
        ?: "false"
    ).trim().lowercase() in setOf("1", "true", "yes", "on")

fun buildConfigSafeString(key: String, envFallback: String, defaultValue: String = ""): String {
    val value = (localProperties.getProperty(key) ?: System.getenv(envFallback) ?: defaultValue).trim()
    return "\"${value.replace("\\", "\\\\").replace("\"", "\\\"")}\""
}

fun providerBuildConfigSafeString(key: String, envFallback: String): String {
    return if (allowDirectProviderKeys) {
        buildConfigSafeString(key, envFallback)
    } else {
        "\"\""
    }
}

fun releaseApiKeyBuildConfigString(): String {
    return if (allowReleaseStaticApiKey) {
        buildConfigSafeString("SIGURSCAN_RELEASE_API_KEY", "SIGURSCAN_RELEASE_API_KEY")
    } else {
        "\"\""
    }
}

android {
    namespace = "ro.sigurscan.app"
    ndkVersion = "29.0.14206865"
    compileSdk {
        version = release(36) {
            minorApiLevel = 1
        }
    }

    defaultConfig {
        applicationId = "ro.sigurscan.app"
        minSdk = 24
        targetSdk = 36
        versionCode = 1
        versionName = "1.0"

        buildConfigField(
            "String",
            "SIGURSCAN_BACKEND_BASE_URL",
            buildConfigSafeString("SIGURSCAN_BACKEND_BASE_URL", "SIGURSCAN_BACKEND_BASE_URL")
        )
        buildConfigField(
            "String",
            "SIGURSCAN_PRIVACY_URL",
            buildConfigSafeString("SIGURSCAN_PRIVACY_URL", "SIGURSCAN_PRIVACY_URL")
        )
        buildConfigField(
            "String",
            "SIGURSCAN_API_KEY",
            buildConfigSafeString("SIGURSCAN_API_KEY", "SIGURSCAN_API_KEY")
        )
        buildConfigField(
            "String",
            "URLSCAN_API_KEY",
            "\"\""
        )
        buildConfigField(
            "String",
            "GOOGLE_WEB_RISK_API_KEY",
            "\"\""
        )
        buildConfigField("Boolean", "SIGURSCAN_ENABLE_AUDIO_ASR", enableAudioAsr.toString())
        buildConfigField("Boolean", "SIGURSCAN_ENABLE_LIVE_CALL", enableLiveCall.toString())
        buildConfigField("Boolean", "SIGURSCAN_ENABLE_PLAY_INTEGRITY", enablePlayIntegrity.toString())
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    signingConfigs {
        if (hasReleaseKeystore) {
            create("release") {
                storeFile = rootProject.file(keystoreProperties.getProperty("storeFile"))
                storePassword = keystoreProperties.getProperty("storePassword")
                keyAlias = keystoreProperties.getProperty("keyAlias")
                keyPassword = keystoreProperties.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        release {
            buildConfigField("String", "SIGURSCAN_BACKEND_BASE_URL", buildConfigSafeString("SIGURSCAN_RELEASE_BACKEND_BASE_URL", "SIGURSCAN_RELEASE_BACKEND_BASE_URL", "https://api.sigurscan.com/"))
            buildConfigField("String", "SIGURSCAN_PRIVACY_URL", buildConfigSafeString("SIGURSCAN_RELEASE_PRIVACY_URL", "SIGURSCAN_RELEASE_PRIVACY_URL"))
            buildConfigField("String", "SIGURSCAN_API_KEY", releaseApiKeyBuildConfigString())
            buildConfigField("String", "URLSCAN_API_KEY", "\"\"")
            buildConfigField("String", "GOOGLE_WEB_RISK_API_KEY", "\"\"")
            buildConfigField("Boolean", "SIGURSCAN_ENABLE_AUDIO_ASR", enableAudioAsr.toString())
            buildConfigField("Boolean", "SIGURSCAN_ENABLE_LIVE_CALL", enableLiveCall.toString())
            buildConfigField("Boolean", "SIGURSCAN_ENABLE_PLAY_INTEGRITY", enablePlayIntegrity.toString())
            if (hasReleaseKeystore) {
                signingConfig = signingConfigs.getByName("release")
            }
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        isCoreLibraryDesugaringEnabled = true
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    buildFeatures {
        compose = true
        buildConfig = true
    }
    if (enableAudioAsr) {
        externalNativeBuild {
            cmake {
                path = file("src/main/cpp/CMakeLists.txt")
                version = "3.31.6"
            }
        }
    }
    sourceSets {
        getByName("main") {
            if (enableAudioAsr) {
                assets.srcDir("src/audioAsr/assets")
            }
        }
        getByName("androidTest") {
            assets.srcDirs(rootProject.file("e2e_fixtures"))
        }
    }
}

tasks.register("verifyV1ReleaseManifest") {
    dependsOn("processReleaseMainManifest")
    doLast {
        val mergedManifest = layout.buildDirectory
            .file("intermediates/merged_manifest/release/processReleaseMainManifest/AndroidManifest.xml")
            .get()
            .asFile
        check(mergedManifest.isFile) {
            "Merged V1 release manifest is missing: ${mergedManifest.absolutePath}"
        }
        val manifestText = mergedManifest.readText()
        check("android.permission.READ_PHONE_STATE" !in manifestText) {
            "V1 release must not request READ_PHONE_STATE."
        }
        check("android.permission.USE_FULL_SCREEN_INTENT" !in manifestText) {
            "V1 release must not request USE_FULL_SCREEN_INTENT."
        }
        check("SigurScanCallScreeningService" !in manifestText) {
            "V1 release must not package CallScreeningService."
        }
        check("android.permission.RECORD_AUDIO" in manifestText) {
            "V1 release must keep RECORD_AUDIO for the explicit Urechea listener."
        }
        check("SpeakerGuardForegroundService" in manifestText) {
            "V1 release must keep the explicit Urechea foreground service."
        }
        check("android:foregroundServiceType=\"microphone\"" in manifestText) {
            "V1 Urechea foreground service must retain microphone type."
        }
        check("android:mimeType=\"audio/*\"" in manifestText) {
            "V1 release must remain available for user-shared audio files."
        }
    }
}

dependencies {
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.compose.material.icons.extended)
    implementation("io.coil-kt:coil-compose:2.6.0")
    implementation(libs.gson)
    implementation(libs.google.mlkit.text.recognition)
    implementation(libs.google.mlkit.barcode)
    implementation(libs.retrofit)
    implementation(libs.retrofit.gson)
    implementation(libs.okhttp.logging)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.play.integrity)
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
    
    implementation(libs.androidx.camera.core)
    implementation(libs.androidx.camera.lifecycle)
    implementation(libs.androidx.camera.camera2)
    implementation(libs.androidx.camera.view)

    coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.1.5")

    testImplementation(libs.junit)
    testImplementation("com.squareup.okhttp3:mockwebserver:4.11.0")
    testImplementation("org.apache.pdfbox:pdfbox:2.0.31")
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(libs.androidx.junit)
    debugImplementation(libs.androidx.compose.ui.test.manifest)
    debugImplementation(libs.androidx.compose.ui.tooling)
}
