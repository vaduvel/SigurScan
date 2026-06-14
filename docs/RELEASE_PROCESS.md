# SigurScan Release Process

## Branching

- `main`: cod stabil, verificat, gata pentru release candidate.
- `release/vX.Y.Z`: pregătire release, semnare, verificări finale.
- `feature/*`: schimbări izolate pentru parser, gate, UI sau provider adapters.

## Versioning

- `versionName`: user-facing, de exemplu `1.0.0`.
- `versionCode`: crește la fiecare upload în Play Console.
- Tag git final: `vX.Y.Z-android`.

## Required Checks Before Release

Rulează din root-ul proiectului:

```bash
JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home" ./gradlew :app:testDebugUnitTest
JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home" ./gradlew :app:lintDebug
JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home" ./gradlew :app:assembleDebug
JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home" ./gradlew :app:assembleRelease
JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home" ./gradlew :app:bundleRelease
```

Verifică APK-ul release:

```bash
JAVA_HOME="/Applications/Android Studio.app/Contents/jbr/Contents/Home" /Users/vaduvageorge/Library/Android/sdk/build-tools/36.1.0/apksigner verify --verbose --print-certs app/build/outputs/apk/release/app-release.apk
```

Scanează artefactul pentru chei sau identitate veche:

```bash
strings app/build/outputs/apk/release/app-release.apk | rg "SUPABASE|eyJhbGci|URLSCAN_API_KEY|VIRUSTOTAL_API_KEY|GOOGLE_SAFE|ANDROID_ID|ro.nudaclick|com.example.myapplication"
```

Verifică valorile reale din fișierele locale/secret-env fără să le afișezi:

```bash
python3 tools/audit_android_release_secrets.py app/build/outputs/apk/release/app-release.apk
python3 tools/audit_android_release_secrets.py app/build/outputs/bundle/release/app-release.aab
```

Acest audit trebuie să eșueze pentru provider/admin/service secrets embeduite.
`SIGURSCAN_API_KEY` / `SIGURSCAN_RELEASE_API_KEY` sunt warning-uri cunoscute
pentru build-ul privat curent; pentru release public larg trebuie înlocuite cu
Play Integrity sau token scurt emis de backend.

## Store Readiness

Înainte de upload public:

- Privacy Policy pe domeniu/alias SigurScan.
- Data Safety completată pentru scanări user-initiated și servicii terțe.
- Fără chei provider în APK/AAB.
- Release AAB semnat cu upload key păstrat offline.
- Minimum 25 fluxuri star testate pe emulator/device: URL, email HTML, Gmail/Outlook share, QR, OCR, PDF, provider timeout/conflict.

## Update Discipline

Orice schimbare la EvidenceGate sau parser trebuie să treacă:

- unit tests existente;
- fixture pack E2E;
- cel puțin un caz real benign de marketing;
- cel puțin un caz real scam cu link ascuns sub buton.
