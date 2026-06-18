# 📋 Google Play — evaluare de readiness (2026-06-15)

> Evaluare în pielea recenzentului Google Play, pe cerințele REALE actuale (verificate web)
> + audit pe config (`app/build.gradle.kts`, `AndroidManifest.xml`, `libs.versions.toml`) și cod.
>
> **Verdict scurt:** ✅ **Tehnic TRECE** (targetSdk 36, permisiuni minime, 16KB ok, fără native 32-bit).
> ⛔ **Blochează NU pe cod, ci pe formularele de consolă** — în primul rând **Data Safety** și
> **Privacy Policy** (obligatorii, app-ul transmite conținut sensibil la backend + la terți urlscan/WebRisk).

---

## 1. ✅ Gate-uri TEHNICE — toate PASS

| Cerință Play | Stare app | Verdict |
|---|---|---|
| **Target API ≥ 35** (nou: oblig. din 31 aug 2025; în 1 an de la ultima versiune) | `targetSdk = 36` / `compileSdk = 36` (Android 16) | ✅ PASS (depășește) |
| **minSdk rezonabil** | `minSdk = 24` (Android 7) | ✅ acoperire largă |
| **16 KB page size** (target 35+, deadline 31 mai 2026; doar apps cu native) | AGP **9.2.1**, CameraX **1.4.1**, ML Kit GMS-backed (19.0.1/18.3.1) — toate 16KB-aligned | ✅ PASS* (vezi notă) |
| **64-bit** (fără 32-bit-only) | fără NDK propriu; ML Kit/CameraX livrează arm64+x86_64 | ✅ PASS |
| **App Bundle (.aab)** pt. apps noi | AGP standard → `bundleRelease` produce AAB | ✅ suportat (build-ul de release) |
| **Semnare release** | `signingConfigs.release` din `keystore.properties` (condiționat) | ✅ (necesită keystore-ul la release) |
| **Permisiuni minime** | **doar `INTERNET` + `CAMERA`** — zero restricționate (fără SMS/Call Log/Location/QUERY_ALL_PACKAGES/MANAGE_EXTERNAL_STORAGE/Accessibility) | ✅ EXCELENT — fără formulare de permisiuni |
| **CAMERA justificată** | feature de bază (scanare QR), cerută la runtime | ✅ |
| **Componente exportate sigure** | doar `MainActivity` (launcher + share + deep-link); intent-urile tratate de parsere defensive | ✅ |
| **Fără secrete hardcodate** | chei prin gradle; `URLSCAN`/`WebRisk` goale în client (server-side) | ✅ |
| **Backup/cleartext** | `allowBackup=false`, cleartext dezactivat (SDK 36), `EncryptedSharedPreferences` | ✅ |
| **Account deletion** (dacă există conturi) | **NU există login/conturi** — date anonime locale | ✅ N/A |

> *16KB: high-confidence PASS (libs recente). Confirmarea definitivă o dă **automat Play Console** la
> upload-ul AAB (te avertizează dacă vreun `.so` nu e aliniat). De rulat o dată `bundleRelease` + upload pe o track internă.

---

## 2. ⛔ NEEDS-WORK — formulare de CONSOLĂ & POLICY (aici e blocajul real)

Astea **nu se rezolvă în cod** — se completează în Play Console înainte de publicare. Fără ele, review-ul respinge.

### 2.1 🔴 Data Safety form (CRITIC — cel mai probabil motiv de respingere)
App-ul **colectează și transmite conținut de utilizator** la backend: text, link-uri, **screenshot-uri, PDF-uri, emailuri, facturi (IBAN/CUI)** — potențial **date personale și financiare**. Backend-ul mai trimite URL-uri la **terți: urlscan.io și Google Web Risk**.
Formularul Data Safety **trebuie să declare exact**:
- **Colectează:** „User content" (mesaje/poze/fișiere), posibil „Financial info" (facturi), „App activity".
- **Transmis:** DA, criptat în tranzit (HTTPS).
- **Partajat cu terți:** DA — procesatori (urlscan.io, Google Web Risk) pentru analiză URL.
- **Scop:** securitate/anti-fraudă.
- **Ștergere:** mecanism de cerere ștergere date (chiar dacă nu sunt conturi, trebuie politica).
→ **Inconsistența dintre ce face app-ul și ce declari aici = respingere directă.**

### 2.2 🔴 Privacy Policy (obligatorie — app cu date sensibile)
- Câmpul `SIGURSCAN_PRIVACY_URL` e plumbed și **link-ul e afișat în app** (`MainActivity.kt:4226`). ✅ plumbing.
- **De făcut:** o **politică de confidențialitate publicată la URL public**, care acoperă: ce date se trimit, către cine (backend + urlscan/WebRisk), retenție, ștergere, contact. URL-ul trebuie setat în release (`SIGURSCAN_RELEASE_PRIVACY_URL`) **și** în câmpul din Play Console.

### 2.3 🟠 Content rating (IARC) + Target audience
- De completat chestionarul de rating (app de securitate → general/adult, **nu** pentru copii).
- De declarat „Target audience": adulți/general.

### 2.4 🟠 App access pentru recenzori
- App-ul e **inutil dacă backend-ul e jos** la review. Recenzorii Google îl testează live →
  - backend-ul de producție **trebuie să fie up**;
  - build-ul de release trebuie să folosească Play Integrity monitor/enforce sau, doar temporar, `SIGURSCAN_ALLOW_RELEASE_STATIC_API_KEY=true` cu `SIGURSCAN_RELEASE_API_KEY`;
  - dă în „App access" instrucțiuni: „nu necesită cont; lipește un link/text și apasă Scanează".

### 2.5 🟠 Impersonation / brand & IP policy (risc mediu — specific app-ului)
App-ul folosește **nume de branduri** (bănci, eMAG, DIGI, ANAF, curieri) în detecție/educație.
- Uz defensiv/educațional = în general permis, DAR:
  - **nu folosi logo-uri** pe care nu ai drept; folosește nume text.
  - listarea în store **nu trebuie să sugereze** parteneriat/aprobare de la aceste branduri.
  - evită să pari „oficial ANAF/bancă".

### 2.6 🟠 Claims de securitate („antivirus"-style)
- Apps care „detectează amenințări" au scrutin extra. **Punct forte:** app-ul are deja disclaimer-ul onest
  („SigurScan oferă o estimare automată… poate rata scamuri noi"). **Păstrează-l.**
- În listare **evită absolutisme** („blochează toate țepele"). Folosește „te ajută să verifici".

---

## 3. 🟡 CALITATE — afectează Android Vitals / pre-launch report (nu blochează review-ul, dar contează)

| Item | Detaliu | Recomandare |
|---|---|---|
| **Dependență ALPHA în producție** | `androidx.security:security-crypto:1.1.0-alpha06` (EncryptedSharedPreferences) | Risc de stabilitate; de evaluat o variantă stabilă sau acceptat conștient |
| **R8/minify oprit** | `isMinifyEnabled = false` în release | Recomandat `true` (AAB mai mic + ofuscare); testează ProGuard rules |
| **Bug-uri din audit** (vezi `AUDIT_CODEX_2026-06-15.md`) | P0 scan-evasion (backend), `!!` NPE ×6, ANR-risk pe `.execute()` | Cresc rata crash/ANR în Vitals **după** lansare → pot reduce vizibilitatea. De fixat înainte de scale. |
| **Pre-launch report** | Google rulează app-ul pe device-uri reale | Backend trebuie să răspundă; altfel raportul arată „crashes/ANR" |

---

## 4. ✅ Checklist de submit (ordine recomandată)

**Cod / build (aproape gata):**
- [ ] `bundleRelease` cu keystore-ul de release → AAB.
- [ ] `SIGURSCAN_RELEASE_BACKEND_BASE_URL` + `SIGURSCAN_RELEASE_PRIVACY_URL` setate.
- [ ] Play Integrity configurat pentru release (`SIGURSCAN_ENABLE_PLAY_INTEGRITY=true`, backend `PLAY_INTEGRITY_MODE=monitor/enforce`) sau fallback static key activat explicit și documentat.
- [ ] (recomandat) `isMinifyEnabled = true` + verifică ProGuard.
- [ ] Upload pe **Internal testing** → Play Console confirmă automat 16KB + 64-bit + targetSdk.

**Consolă / policy (blocajul real):**
- [ ] **Data Safety** completat corect (conținut user + financiar + partajare urlscan/WebRisk).
- [ ] **Privacy Policy** publicată + URL în Console și în build.
- [ ] **Content rating** (IARC) + Target audience (general/adult).
- [ ] **App access** (fără cont; instrucțiuni de test) + backend live.
- [ ] Listare fără logo-uri de brand neautorizate, fără claim de aprobare oficială, fără absolutisme.
- [ ] Icon adaptiv + screenshot-uri + descriere.

---

## 5. 📊 Verdict de recenzent

> **Ar trece review-ul?** — **DA, condiționat.** Codul/config-ul sunt **production-grade și conforme**
> (targetSdk 36, permisiuni minime, 16KB, fără native 32-bit, semnare, fără secrete). **Nu codul te blochează.**
>
> **Singurele lucruri care opresc publicarea sunt formularele de consolă** — în special **Data Safety**
> (trebuie să reflecte fidel că trimiți conținut + la terți) și **Privacy Policy** publicată. Astea sunt
> ~1-2 ore de muncă în Console + o pagină de politică, nu refactor de cod.
>
> Recomandare: rezolvă §2.1 + §2.2, urcă un build pe Internal testing (lasă Play să confirme 16KB),
> apoi promovează. P0/P1 din auditul de cod sunt de fixat **înainte de scale** (pentru Vitals), nu pentru aprobare.

*Întocmit de Claude (Opus 4.8). Evaluare pe cerințele Play reale (target API 35+ din 31 aug 2025; 16KB până la 31 mai 2026). Read-only — niciun fișier de producție modificat.*
