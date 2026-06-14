# Android Audio Capture Policy - 2026-06-14

SigurScan must not claim production audio/call ASR until all of these are true:

- The feature is explicitly enabled by a build/runtime flag.
- The user gives explicit consent before capture.
- The user accepts a privacy disclosure for audio processing.
- An on-device ASR model is packaged, versioned, and tested.
- The app does not perform hidden call recording.
- The feature has real-device QA evidence.

Current state:

- Audio capture is blocked by `AudioSafetyPolicy` by default.
- No Vosk/ASR production model is bundled.
- No hidden call recording is implemented.
- The Android manifest does not request `android.permission.RECORD_AUDIO`.
- The current UI is a readiness gate, not an audio capture feature.
- PR-9/PR-10 remain gated until the above requirements are implemented and verified.
