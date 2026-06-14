# SigurScan Android - Play Privacy & Data Safety Notes

Ultima actualizare: 2026-06-03

## Principiul produsului

SigurScan scaneaza doar continut ales explicit de utilizator:

- text/link lipit manual;
- share intent din Gmail/Outlook/Yahoo/WhatsApp/SMS/etc.;
- imagine/QR/PDF selectate manual;
- fisier/email importat manual.

Aplicatia nu face scanare automata de notificari, SMS-uri, inbox, clipboard sau background.

## Date procesate la scanare

Pentru o scanare, aplicatia poate procesa local:

- text vizibil din mesaj;
- HTML primit prin share intent, cand aplicatia sursa il furnizeaza;
- URL-uri vizibile si URL-uri ascunse in HTML sub butoane/linkuri/form actions;
- imagine/QR/PDF selectat de utilizator;
- rezultat OCR local sau backend, in functie de flux.

Backend-ul trebuie sa primeasca doar datele necesare pentru scanare. Pentru URL-uri, backend-ul normalizeaza si elimina parametri zgomotosi de marketing. Pentru texte/email, backend-ul foloseste redactor PII pentru email, telefon, IBAN si OTP in payload-ul de analiza.

## Servicii terte

In release, cheile provider nu sunt incluse in APK. Providerii se acceseaza prin backend/proxy:

- SigurScan backend/Vercel pentru scanare;
- urlscan.io pentru sandbox si screenshot securizat al URL-ului final;
- Google Web Risk / Safe Browsing backend-side, unde este configurat;
- URLhaus si Phishing.Database backend-side, unde sunt configurate;
- Supabase, accesat doar backend-side, pentru evenimente agregate, feedback si campanii comunitare validate.

Privacy Policy publica pentru Play Console:

- temporar, backend live existent: `https://nudaclick-backend.vercel.app/privacy`
- pentru release public SigurScan, creeaza alias/domeniu dedicat si actualizeaza app + Play listing.

Debug/local poate activa chei directe doar cu opt-in explicit:

`SIGURSCAN_ENABLE_DIRECT_PROVIDER_KEYS=true`

Fara acest flag, BuildConfig are provider keys goale inclusiv in debug.

## Declaratii Google Play Data Safety

Colectare/transmitere:

- URL-uri si continut suspect: doar cand utilizatorul declanseaza scanarea.
- Feedback scan: doar cand utilizatorul trimite feedback.
- Device registration: dezactivat in v1; aplicatia nu trimite automat ANDROID_ID, device hash sau push token la startup.
- Camera: folosita doar pentru scanare QR/OCR la actiunea utilizatorului.

Permisiuni Android declarate in v1:

- `INTERNET` pentru scanare prin backend.
- `ACCESS_NETWORK_STATE`, adaugata de dependinte Android, pentru verificarea starii conexiunii.
- `CAMERA` pentru QR/OCR doar la actiunea utilizatorului.
- `READ_PHONE_STATE` pentru integrarea optionala Radar/CallScreening activata de utilizator prin rolul OS.

Permisiuni evitate explicit:

- `READ_SMS`, `RECEIVE_SMS`, `SEND_SMS`, `READ_CALL_LOG`, `READ_CONTACTS`.
- `RECORD_AUDIO` pana cand PR-9/PR-10 are model ASR local, consimtamant, disclosure si QA real-device.
- `READ_EXTERNAL_STORAGE`, `READ_MEDIA_IMAGES`, `READ_MEDIA_VIDEO` pentru flow-ul curent, deoarece fisierele sunt alese prin picker/share intent.
- `POST_NOTIFICATIONS`, deoarece nu facem monitorizare automata sau alerte push in v1.

Partajare cu terti:

- URL-uri pot fi trimise catre backend si mai departe catre providerii de reputatie/sandbox.
- Capturile screenshot ale URL-ului final sunt produse de urlscan si afisate in aplicatie prin proxy backend.

Nu se face:

- monitorizare automata inbox/SMS/notificari;
- citire clipboard in background;
- acces permanent la Gmail/Outlook;
- upload automat al tuturor mesajelor;
- captura audio sau call recording ascuns;
- inregistrare automata a device-ului;
- acces direct din APK la Supabase cu anon key;
- distributie de date brute catre terti fara actiune de scanare.

## Cerinte inainte de publicare

- Privacy Policy publica, accesibila din Play listing si aplicatie, pe domeniu/alias SigurScan.
- Data Safety completata cu URL/content scan, third-party processing si encryption in transit.
- `ENABLE_RATE_LIMIT=true` pe backend pentru productie.
- `REQUIRE_API_KEY=true` este acceptabil pentru build-uri private ca bariera anti-abuz, dar cheia de client din APK este extractabila.
- Pentru release public larg: trecere la Play Integrity in `monitor/enforce` sau token scurt emis de backend; nu trata shared client API key din APK ca autentificare reala.
- Supabase RLS hardening aplicat remote: anon nu citeste/scrie tabele brute de telemetry, feedback, device sau community reports.
- `SIGURSCAN_URLSCAN_API_KEY`, Google Web Risk, URLhaus si Phishing.Database configurate doar in backend/Vercel.
- VirusTotal Public API nu este folosit in produsul comercial v1; daca revine, trebuie contract/licenta compatibila comercial.
- Confirmare ca release APK/AAB nu contine provider/admin/service secrets:
  `python3 tools/audit_android_release_secrets.py app/build/outputs/apk/release/app-release.apk`
  si acelasi script pe `.aab`.

## Verificari executate

- `./gradlew clean :app:testDebugUnitTest :app:lintDebug :app:assembleDebug :app:assembleRelease`
- `python3 -m pytest test_backend.py` din `/Users/vaduvageorge/Desktop/SigurScan/backend`
- Verificare BuildConfig: `provider_key_buildconfig_violations=0`
- Test privacy policy public: `python3 -m pytest test_backend.py -q -k "privacy_policy"`
- E2E emulator share HTML Uber: Android `ACTION_SEND text/html` a primit HTML complet, a afisat verdictul sus si a incarcat preview securizat urlscan.
