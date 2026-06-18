# Speaker Guard Release QA - 2026-06-14

Scope: Android release verification for Speaker Guard and the `sigurscan://speaker-guard`
deep link on a physical Nokia C22, Android 13.

Commit under test:

- `26ce154` - `Harden Speaker Guard device flow`

Build artifacts:

- `app/build/outputs/apk/release/app-release.apk` - 63 MB
- `app/build/outputs/bundle/release/app-release.aab` - 61 MB

Mainline status:

- `origin/main` fast-forwarded from `1ab5b7c` to `26ce154`.
- Cloud Run backend was not redeployed for this QA pass because the diff is Android-only.

Checks run:

- `SIGURSCAN_ENABLE_AUDIO_ASR=true ./gradlew testDebugUnitTest assembleDebug`
- `SIGURSCAN_ENABLE_AUDIO_ASR=true ./gradlew connectedDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=ro.sigurscan.app.SharedIntentStreamExtractorInstrumentedTest`
  - Nokia C22: 20/20 passed.
- `SIGURSCAN_ENABLE_AUDIO_ASR=true ./gradlew connectedDebugAndroidTest`
  - Nokia C22: 27/27 passed.
- `SIGURSCAN_ENABLE_AUDIO_ASR=true ./gradlew lintDebug`
- `SIGURSCAN_ENABLE_AUDIO_ASR=true ./gradlew :app:assembleRelease :app:bundleRelease`
- `apksigner verify --verbose --print-certs app/build/outputs/apk/release/app-release.apk`
  - Verified with APK Signature Scheme v2.
  - Signer DN: `CN=SigurScan, OU=Mobile Security, O=SigurScan, L=Bucharest, ST=Bucharest, C=RO`.
- `python3 tools/audit_android_release_secrets.py app/build/outputs/apk/release/app-release.apk`
- `python3 tools/audit_android_release_secrets.py app/build/outputs/bundle/release/app-release.aab`
  - Provider/admin/service secrets were not embedded.
  - Current release policy: `SIGURSCAN_RELEASE_API_KEY` is not embedded unless `SIGURSCAN_ALLOW_RELEASE_STATIC_API_KEY=true` is set as an explicit fallback; see `docs/RELEASE_PROCESS.md`.
- `strings app/build/outputs/apk/release/app-release.apk | rg "SUPABASE|eyJhbGci|URLSCAN_API_KEY|VIRUSTOTAL_API_KEY|GOOGLE_SAFE|ANDROID_ID|ro\\.nudaclick|com\\.example\\.myapplication"`
  - No matches.

Release device test:

- Installed `app-release.apk` cleanly on Nokia C22.
- Package details:
  - `versionName=1.0`
  - `versionCode=1`
  - `targetSdk=36`
  - signing version 2
  - no `DEBUGGABLE` flag in package dump
- Granted `android.permission.RECORD_AUDIO`.
- Launched with:
  - `adb shell am start -a android.intent.action.VIEW -d sigurscan://speaker-guard ro.sigurscan.app`
- Deep link opened the Radar tab and exposed the Speaker Guard card after scroll.
- Startup/deep-link did not force Whisper readiness automatically; readiness is evaluated on explicit user action.
- After checking both consent boxes and starting Speaker Guard:
  - UI showed `asculta`.
  - UI showed analyzed chunks increasing; observed `Fragmente analizate: 6`, `pierdute: 0`, `audio brut salvat: nu`.
  - AudioFlinger confirmed active built-in microphone input:
    - package `ro.sigurscan.app`
    - source `AUDIO_SOURCE_VOICE_RECOGNITION`
    - sample rate `16000`
    - input device `AUDIO_DEVICE_IN_BUILTIN_MIC`
- After tapping the actual visible stop button:
  - UI returned to `oprit`.
  - AudioFlinger confirmed the input thread entered standby and input device returned to `AUDIO_DEVICE_NONE`.
  - Logcat confirmed `AudioRecord stop`, `AudioRecord destructor`, and `Release mSessionId`.

Notes:

- MobAI MCP detected the Nokia C22, but `start_bridge` returned `HTTP 402 device_limit_reached` for the Guest account. Device verification was completed via ADB and Android system dumps.
- Android logs include `CALL_AUDIO_INTERCEPTION denied`, which is expected. Speaker Guard does not intercept call audio; it uses explicit microphone capture after the user puts the call on speaker.
- Nokia C22 still shows generic Compose startup jank on cold launch, but the previous Whisper/native-load startup path is removed from deep-link startup.
