"""Static/landing pages, health checks and Play Integrity nonce.

References main config/helpers via `import main; main.X` (resolved at call time)
so monkeypatching keeps working; routers are registered at the end of main.py.
"""

import time
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse

import main
from services import play_integrity_nonce

router = APIRouter()


@router.get("/")
def read_root():
    return {
        "project": "SigurScan",
        "status": "active",
        "version": "1.0",
        "api_docs": "/docs" if main.EXPOSE_API_DOCS else None,
        "privacy_policy": "/privacy",
    }


main.PRIVACY_POLICY_HTML = """<!doctype html>
<html lang="ro">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Politica de confidentialitate SigurScan</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; line-height: 1.6; margin: 0; color: #172033; background: #f7f9fc; }
    main { max-width: 860px; margin: 0 auto; padding: 40px 20px 64px; }
    section { background: #fff; border: 1px solid #dfe7f3; border-radius: 12px; padding: 24px; margin: 18px 0; }
    h1, h2 { line-height: 1.2; }
    h1 { font-size: 2rem; margin-bottom: 8px; }
    h2 { font-size: 1.2rem; margin-top: 0; }
    .muted { color: #647089; }
    li { margin: 8px 0; }
    code { background: #eef3ff; border-radius: 6px; padding: 2px 6px; }
  </style>
</head>
<body>
<main>
  <h1>Politica de confidentialitate SigurScan</h1>
  <p class="muted">Ultima actualizare: 16 iunie 2026. URL public: <code>https://api.sigurscan.com/privacy</code>.</p>

  <section>
    <h2>Principiul de baza</h2>
    <p>SigurScan scaneaza doar continut pe care utilizatorul alege explicit sa il verifice. Aplicatia nu citeste automat notificari, SMS-uri, inbox Gmail/Outlook/Yahoo, clipboard sau alte aplicatii in fundal. Nu pornim scanari fara actiunea utilizatorului si nu folosim datele pentru publicitate.</p>
  </section>

  <section>
    <h2>Ce date pot fi procesate</h2>
    <ul>
      <li>text sau link introdus manual;</li>
      <li>continut primit prin Android Share Intent, inclusiv HTML daca aplicatia sursa il furnizeaza;</li>
      <li>URL-uri vizibile si URL-uri ascunse in HTML sub butoane/linkuri;</li>
      <li>imagini, coduri QR, PDF-uri sau fisiere selectate manual de utilizator;</li>
      <li>facturi, date de plata si documente comerciale selectate manual, inclusiv CUI, IBAN, nume furnizor, suma si explicatii de plata, cand acestea apar in document;</li>
      <li>fisiere audio partajate sau transcripturi trimise explicit catre SigurScan; daca transcrierea audio nu este activa in build-ul folosit, aplicatia poate cere utilizatorului sa lipeasca transcriptul;</li>
      <li>feedback trimis explicit de utilizator despre un verdict.</li>
    </ul>
  </section>

  <section>
    <h2>Cum folosim datele</h2>
    <p>Datele sunt folosite pentru a extrage linkuri, a urmari redirecturi, a verifica reputatia URL-urilor, a analiza cereri de plata/facturi si a afisa un verdict simplu de risc. Backend-ul aplica redactare si minimizare pentru date precum email, telefon, IBAN si coduri OTP unde este posibil, iar URL-urile cu tokeni sau date sensibile pot fi reduse la origine sau blocate de la preview.</p>
  </section>

  <section>
    <h2>Radar si protectia apelurilor</h2>
    <p>Radar foloseste, cand utilizatorul il activeaza din setarile Android, serviciul oficial Android Call Screening. Pentru aceasta functie, SigurScan analizeaza numarul apelantului local, pe telefon, printr-un cache de reputatie sincronizat anterior. SigurScan nu inregistreaza apeluri, nu asculta continutul apelurilor si nu citeste jurnalul de apeluri.</p>
    <p>Numerele raportate sunt tratate privacy-first: cache-ul foloseste hash-uri SHA-256 si bucket-uri de numar de raportari, nu liste publice cu numere brute. Rapoartele comunitare pot genera avertizare, silent ring sau blocare doar pentru reputatie ridicata/explicit blocata.</p>
  </section>

  <section>
    <h2>Servicii terte</h2>
    <p>Pentru scanari declansate de utilizator, SigurScan poate folosi servicii terte prin backend-ul SigurScan rulat pe Google Cloud Run, in spatele domeniului <code>api.sigurscan.com</code> si al protectiei Cloudflare:</p>
    <ul>
      <li><strong>urlscan.io</strong> pentru sandbox si preview securizat al paginii finale;</li>
      <li><strong>Google Web Risk / Safe Browsing</strong> pentru verificari de malware, phishing si social engineering;</li>
      <li><strong>URLhaus / abuse.ch</strong> pentru reputatie URL malware/phishing, cand cheia este configurata server-side;</li>
      <li><strong>Phishing.Database</strong> ca feed open-source pentru domenii si linkuri active de phishing;</li>
      <li><strong>Scam-Blocklist</strong> (jarelllama) si <strong>PhishDestroy</strong> pentru feed-uri publice de domenii suspecte, cand sunt activate;</li>
      <li><strong>Supabase</strong> pentru joburi de scanare, cache de preview/reputatie, feedback si rapoarte comunitare agregate;</li>
      <li>provideri AI optionali, precum Gemini sau Mistral, pentru explicatii si second-opinion semantic; verdictul ramane controlat de gate-ul SigurScan si providerii hard.</li>
    </ul>
  </section>

  <section>
    <h2>Ce nu facem</h2>
    <ul>
      <li>nu monitorizam automat inbox, SMS-uri, notificari sau clipboard;</li>
      <li>nu cerem permisiuni de citire SMS, contacte, jurnal apeluri sau media larga in build-ul public;</li>
      <li>nu inregistram apeluri si nu pornim microfonul in ascuns;</li>
      <li>nu vindem date personale;</li>
      <li>nu trimitem scanari fara actiunea explicita a utilizatorului;</li>
      <li>nu includem cheile providerilor in aplicatia Android de productie.</li>
    </ul>
  </section>

  <section>
    <h2>Securitate si retentie</h2>
    <p>Comunicarea cu backend-ul se face prin HTTPS. Cache-ul de reputatie foloseste hash-uri si TTL-uri pentru a reduce apelurile repetate la provideri. Pastram date operationale necesare pentru scanare, debugging de securitate, rate-limit, preview cache si rapoarte agregate; acolo unde este posibil, stocarea foloseste date redactionate, normalizate sau hash-uite.</p>
  </section>

  <section>
    <h2>Cookie-uri si analytics</h2>
    <p>Endpointul API de privacy nu are nevoie de cookie-uri de cont si SigurScan nu foloseste datele de scanare pentru advertising. Protectiile de infrastructura, precum Cloudflare sau rate-limit-ul, pot procesa metadata tehnica necesara pentru securitate si disponibilitate.</p>
  </section>

  <section>
    <h2>Contact</h2>
    <p>Pentru solicitari privind confidentialitatea, corectarea sau stergerea feedbackului trimis, contacteaza echipa SigurScan la <code>privacy@sigurscan.ro</code> sau prin canalul public indicat in Google Play.</p>
  </section>
</main>
</body>
</html>"""


@router.get("/privacy", response_class=HTMLResponse)
@router.get("/privacy-policy", response_class=HTMLResponse)
def privacy_policy() -> HTMLResponse:
    return HTMLResponse(content=main.PRIVACY_POLICY_HTML)


main.TERMS_OF_SERVICE_HTML = """<!doctype html>
<html lang="ro">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Termeni si conditii SigurScan</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; line-height: 1.6; margin: 0; color: #172033; background: #f7f9fc; }
    main { max-width: 860px; margin: 0 auto; padding: 40px 20px 64px; }
    section { background: #fff; border: 1px solid #dfe7f3; border-radius: 12px; padding: 24px; margin: 18px 0; }
    h1, h2 { line-height: 1.2; }
    h1 { font-size: 2rem; margin-bottom: 8px; }
    h2 { font-size: 1.2rem; margin-top: 0; }
    .muted { color: #647089; }
    li { margin: 8px 0; }
    code { background: #eef3ff; border-radius: 6px; padding: 2px 6px; }
  </style>
</head>
<body>
<main>
  <h1>Termeni si conditii de utilizare SigurScan</h1>
  <p class="muted">Ultima actualizare: 17 iunie 2026. URL public: <code>https://api.sigurscan.com/terms</code>.</p>

  <section>
    <h2>1. Natura aplicatiei</h2>
    <p>SigurScan este un <strong>asistent digital de informare si prevenire a fraudelor</strong>. Aplicatia analizeaza continut pe care utilizatorul il furnizeaza explicit (text, linkuri, fisiere, imagini, facturi etc.) si emite un <strong>verdict automat de risc</strong> pe baza datelor disponibile in acel moment.</p>
    <p><strong>SigurScan NU este:</strong></p>
    <ul>
      <li>institutie de ordine publica, politie, parchet sau organ de ancheta;</li>
      <li>instanta de judecata sau arbitru cu autoritate legala;</li>
      <li>consilier financiar, juridic sau de investitii;</li>
      <li>entitate care poate confirma cu certitudine absoluta intentiile unei terte parti.</li>
    </ul>
    <p>Verdictul emis de SigurScan (de exemplu: SAFE, UNVERIFIED, SUSPECT, DANGEROUS) este <strong>o indicatie automata</strong>, nu o constatare legala sau o condamnare.</p>
  </section>

  <section>
    <h2>2. Obligatia utilizatorului de a verifica</h2>
    <p>In cazul in care SigurScan indica un risc sau in orice situatie de suspiciune, <strong>utilizatorul are obligatia de a verifica independent datele reale</strong> inainte de a actiona. Recomandam:</p>
    <ul>
      <li>contactarea directa a entitatii pretinse prin canale oficiale verificate;</li>
      <li>verificarea identitatii apelantului/expeditorului prin mijloace proprii;</li>
      <li>consultarea unei institutii abilitate (Politie, banca, ANAF, ANPC, DNSC) atunci cand exista pierderi financiare sau suspiciuni grave.</li>
    </ul>
    <p><strong>Nu luati niciodata o decizie financiara, legala sau de securitate personala doar pe baza verdictului SigurScan.</strong></p>
  </section>

  <section>
    <h2>3. Ce face si ce nu face SigurScan</h2>
    <p>SigurScan poate analiza URL-uri, texte, fisiere, facturi si alte continuturi pe care utilizatorul alege sa le scaneze; poate compara informatiile cu baze de date de reputatie, feed-uri publice de phishing, liste de IBAN-uri raportate si cunostinte despre modul de operare al scammerilor; poate emite un verdict de risc si explicatii orientative.</p>
    <p>SigurScan <strong>nu poate</strong> accesa sau verifica conturi bancare, identitati reale sau situatii juridice ale tertilor; nu poate garanta ca un continut „SAFE" este in siguranta absoluta; nu poate garanta detectarea tuturor fraudelor; nu poate substitui verificarea umana sau interventia autoritatilor.</p>
  </section>

  <section>
    <h2>4. Limitarea raspunderii</h2>
    <p>In masura permisa de lege, dezvoltatorul SigurScan nu isi asuma raspunderea pentru daune directe, indirecte, accidentale sau consecutive rezultate din utilizarea sau incapacitatea de a utiliza aplicatia; pentru decizii luate de utilizator pe baza verdictelor emise de SigurScan; pentru pierderi financiare, de date, de timp sau de reputatie; pentru erori, omisiuni, intarzieri sau rezultate incorecte ale algoritmilor sau providerilor terti.</p>
    <p>Utilizatorul foloseste SigurScan <strong>pe propriul risc</strong>.</p>
  </section>

  <section>
    <h2>5. Rapoarte comunitare</h2>
    <p>Rapoartele trimise prin functiile de feedback sau raportare comunitara sunt anonimizate si agregate. Transmiterea unui raport prin aplicatie <strong>nu constituie o plangere oficiala</strong>. Pentru sesizari catre autoritati, utilizatorul trebuie sa foloseasca canalele oficiale (Politie, ANPC, banca etc.).</p>
  </section>

  <section>
    <h2>6. Abonamente si plati</h2>
    <p>Daca SigurScan ofera functii contra cost, acestea sunt gestionate prin platformele oficiale (Google Play, Stripe etc.). Anularea si rambursarea se fac conform politicilor platformei respective.</p>
  </section>

  <section>
    <h2>7. Modificari ale termenilor</h2>
    <p>Termenii pot fi actualizati. Utilizatorul va fi informat la deschiderea aplicatiei daca modificarile sunt substantiale. Continuarea utilizarii dupa notificare inseamna acceptarea noilor termeni.</p>
  </section>

  <section>
    <h2>8. Legea aplicabila si jurisdictia</h2>
    <p>Prezentul acord este guvernat de legislatia din <strong>Romania</strong>. Orice disputa derivata din sau in legatura cu utilizarea SigurScan va fi solutionata de instantele competente din Romania.</p>
  </section>

  <section>
    <h2>9. Acceptarea termenilor</h2>
    <p>Prin descarcarea, instalarea si utilizarea SigurScan, utilizatorul confirma ca a citit, inteles si acceptat Termenii si conditiile si Politica de confidentialitate. Daca nu sunteti de acord, nu utilizati aplicatia.</p>
  </section>

  <section>
    <h2>10. Contact</h2>
    <p>Pentru intrebari legate de termeni: <code>legal@sigurscan.ro</code>.</p>
  </section>
</main>
</body>
</html>"""


@router.get("/terms", response_class=HTMLResponse)
@router.get("/terms-of-service", response_class=HTMLResponse)
def terms_of_service() -> HTMLResponse:
    return HTMLResponse(content=main.TERMS_OF_SERVICE_HTML)


@router.get("/health")
@router.get("/healthz")
def read_health():
    return {
        "status": "ok",
        "service": "SigurScan API",
        "version": "1.0",
        "timestamp": int(time.time()),
        "config": main._provider_config_status(),
    }


@router.get("/health/security")
def read_security_health():
    return main._provider_config_status()


@router.post("/v1/security/play-integrity/nonce")
def issue_play_integrity_nonce(request: Request):
    result = play_integrity_nonce.issue_nonce(
        main._play_integrity_client_binding(request, main._extract_api_key(request))
    )
    if result.get("status") != "issued":
        if result.get("status") in {"invalid_client", "invalid_request"}:
            raise HTTPException(
                status_code=400,
                detail="Missing Play Integrity client binding.",
            )
        raise HTTPException(
            status_code=503,
            detail="Play Integrity nonce service is unavailable.",
        )
    return {
        "nonce": result["nonce"],
        "expires_in_seconds": result["expires_in_seconds"],
    }
