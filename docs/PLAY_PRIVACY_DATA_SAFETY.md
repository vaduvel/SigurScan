# SigurScan Android - Play Privacy & Data Safety Notes

Ultima actualizare: 2026-06-16

## Principiul produsului

SigurScan scaneaza doar continut ales explicit de utilizator:

- text/link lipit manual;
- share intent din Gmail/Outlook/Yahoo/WhatsApp/SMS/etc.;
- imagine/QR/PDF selectate manual;
- fisier/email importat manual.
- factura/document comercial scanat cu camera sau incarcat manual;
- fisier audio/transcript partajat explicit catre SigurScan, fara monitorizare audio automata.

Aplicatia nu face scanare automata de notificari, SMS-uri, inbox, clipboard sau background.

## Date procesate la scanare

Pentru o scanare, aplicatia poate procesa local:

- text vizibil din mesaj;
- HTML primit prin share intent, cand aplicatia sursa il furnizeaza;
- URL-uri vizibile si URL-uri ascunse in HTML sub butoane/linkuri/form actions;
- imagine/QR/PDF selectat de utilizator;
- rezultat OCR local sau backend, in functie de flux.
- facturi si date de plata extrase din documente selectate explicit: CUI, IBAN, nume furnizor, suma, banca, explicatii de plata, cand apar in document.
- audio partajat user-initiated sau transcript lipit manual; build-ul public nu porneste microfonul in ascuns si nu inregistreaza apeluri.

Backend-ul trebuie sa primeasca doar datele necesare pentru scanare. Pentru URL-uri, backend-ul normalizeaza si elimina parametri zgomotosi de marketing. Pentru texte/email, backend-ul foloseste redactor PII pentru email, telefon, IBAN si OTP in payload-ul de analiza.

## Servicii terte

In release, cheile provider nu sunt incluse in APK. Providerii se acceseaza prin backend/proxy:

- SigurScan backend pe Google Cloud Run, public prin `https://api.sigurscan.com`;
- Cloudflare pentru edge/TLS/protectie ruta API;
- Upstash/rate-limit, unde este configurat;
- urlscan.io pentru sandbox si screenshot securizat al URL-ului final;
- Google Web Risk / Safe Browsing backend-side, unde este configurat;
- URLhaus si Phishing.Database backend-side, unde sunt configurate;
- Scam-Blocklist NRD (jarelllama) si PhishDestroy/destroylist backend-side, unde sunt configurate;
- Supabase, accesat doar backend-side, pentru evenimente agregate, feedback si campanii comunitare validate.
- provider AI optional backend-side, precum Gemini/Mistral, pentru explicatii si second opinion semantic, cu gate-ul SigurScan pastrand controlul verdictului.

Privacy Policy publica pentru Play Console:

- `https://api.sigurscan.com/privacy`
- acelasi URL trebuie setat in app prin `SIGURSCAN_PRIVACY_URL` / `SIGURSCAN_RELEASE_PRIVACY_URL` si in Play listing.

Debug/local poate activa chei directe doar cu opt-in explicit:

`SIGURSCAN_ENABLE_DIRECT_PROVIDER_KEYS=true`

Fara acest flag, BuildConfig are provider keys goale inclusiv in debug.

## Declaratii Google Play Data Safety

Colectare/transmitere:

- URL-uri si continut suspect: doar cand utilizatorul declanseaza scanarea.
- Feedback scan: doar cand utilizatorul trimite feedback.
- Device registration: dezactivat in v1; aplicatia nu trimite automat ANDROID_ID, device hash sau push token la startup.
- Camera: folosita doar pentru scanare QR/OCR la actiunea utilizatorului.
- Radar/Call Screening: doar dupa activarea rolului oficial Android de catre utilizator; analiza se face pe numarul apelantului si cache local, nu pe continutul apelului.
- Rapoarte comunitare pentru numere: serverul primeste hash-uri/bucket-uri, nu trebuie sa publice sau sa expuna numere brute.

Permisiuni Android declarate in release public:

- `INTERNET` pentru scanare prin backend.
- `ACCESS_NETWORK_STATE`, adaugata de dependinte Android, pentru verificarea starii conexiunii.
- `CAMERA` pentru QR/OCR doar la actiunea utilizatorului.
- serviciul `android.telecom.CallScreeningService` cu `android.permission.BIND_SCREENING_SERVICE` pentru Radar opt-in; acesta nu este o permisiune runtime de citire larga a telefonului si necesita rolul OS.

Permisiuni evitate explicit:

- `READ_SMS`, `RECEIVE_SMS`, `SEND_SMS`, `READ_CALL_LOG`, `READ_CONTACTS`.
- `READ_PHONE_STATE` in release public; overlay-ul de release o elimina.
- `RECORD_AUDIO` in release public; overlay-ul de release o elimina pana cand audio/call ASR are model local, consimtamant, disclosure si QA real-device.
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
- ascultare live a apelurilor in release public;
- inregistrare automata a device-ului;
- acces direct din APK la Supabase cu anon key;
- distributie de date brute catre terti fara actiune de scanare.

## Cerinte inainte de publicare

- Privacy Policy publica, accesibila din Play listing si aplicatie, pe domeniu/alias SigurScan.
- Data Safety completata cu URL/content scan, third-party processing si encryption in transit.
- `ENABLE_RATE_LIMIT=true` pe backend pentru productie.
- `REQUIRE_API_KEY=true` este acceptabil pentru build-uri private ca bariera anti-abuz, dar cheia de client din APK este extractabila.
- Pentru release public larg: `SIGURSCAN_RELEASE_API_KEY` este gol implicit si poate fi inclus doar prin fallback explicit (`SIGURSCAN_ALLOW_RELEASE_STATIC_API_KEY=true`). Fluxul matur este Play Integrity cu nonce anti-replay distribuit, pornit in `monitor` si trecut in `enforce` numai dupa configurarea secretului de service account, activarea build-ului Play semnat si masurarea pass rate-ului. Nu trata shared client API key din APK ca autentificare reala.
- Supabase RLS hardening aplicat remote: anon nu citeste/scrie tabele brute de telemetry, feedback, device sau community reports.
- `SIGURSCAN_URLSCAN_API_KEY`, Google Web Risk, URLhaus si Phishing.Database configurate doar in backend/Cloud Run.
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
