# SigurScan — Knowledge Pack „Ofertă + Plată" (companion la PR Plan)

> **Ce este acest document**
> Acesta este **materialul de cunoaștere** (domain knowledge) distilat din cele 3 cercetări, pregătit exact în forma de care are nevoie Fable. Se dă **împreună cu** `SigurScan_Offer_Fable_PR_Plan_CODE_GROUNDED.md` (documentul de execuție).
>
> - **Documentul de execuție** = *CUM* se construiește (arhitectură, PR-uri, ce reutilizezi din cod).
> - **Acest Knowledge Pack** = *CE* cunoaștere se codifică înăuntru (familii de scam, reguli de verdict, conținut juridic).
>
> **Regula de aur pentru Fable:** conținutul de mai jos NU se citește ca eseu și NU se rescrie liber. Se codifică în **fișiere de date** (`data/scam_atlas_offer_seed.json`, `data/legal_kb.json`) pe care le consumă codul. Părțile JSON de la final sunt gata de copiat 1:1.
>
> Sursa de adevăr (cele 3 cercetări, în workspace-ul george daniel):
> - Cercetarea #1 + #2 — Atlas „Ofertă + Plată" + Partea II EvidenceGate
> - Cercetarea #3 — Juristul SigurScan (strat de educație juridică)

---

## 0. Cum se mapează fiecare parte pe PR-urile din documentul de execuție

| Parte din Knowledge Pack | Devine (fișier de date / cod) | PR-ul care îl consumă |
|---|---|---|
| **Partea A** — Atlas familii OP-00..OP-09 + semnale | `data/scam_atlas_offer_seed.json` → încărcat de `family_classifier` (extinde `ScamAtlasEngine`) | PR1 (clasificator familie) + PR2 (combinații la gate) |
| **Partea B** — Reguli EvidenceGate (verdict) | reguli în `offer_evidence_gate_mapper` care alimentează `reduce_verdict` | PR2 (ANAF + IBAN + EvidenceGate) |
| **Partea C** — Juristul (educație juridică) | `data/legal_kb.json` → `legal_layer.py` | PR5 (strat „Ce spune legea") |
| **Partea D** — Surse de verificare per domeniu | statusuri oneste în `registry_verification/*` | PR4 (snapshots registre) |

> ⚠️ EvidenceGate (Partea B) e DEJA reflectat în „Partea 1 — Reguli de aur" din documentul de execuție. Aici e versiunea completă, cu tabelul de semnale și logica de combinație, ca să poată fi codificată exact.

---

# PARTEA A — Atlas de scam „Ofertă + Plată" (familii OP)

## Legendă putere semnal

| Putere | Ce înseamnă |
|---|---|
| 🔴 Decisiv | determină aproape sigur frauda → verdict **PERICULOS** (de regulă în combinație) |
| 🟠 Mediu | indică suspiciune → verdict **SUSPECT**, necesită coroborare |
| 🟡 Slab | singur nu e concludent, dar contează cumulat |

## Taxonomia familiilor (enum complet, aliniat cu `OfferFields.family` din PR1)

| Cod | Familie | Stare cunoaștere |
|---|---|---|
| OP-00 | Necategorizat / implicit | default când nu se potrivește nimic |
| OP-01 | Turism / agenții de turism false | ✅ playbook complet |
| OP-02 | Cazare scurtă (Airbnb/Booking/VRBO/FB) | ✅ playbook complet |
| OP-03 | Chirii termen lung (apartamente/case) | ✅ playbook complet |
| OP-04 | Vânzare auto (inclusiv transport/import) | ✅ playbook complet |
| OP-05 | Bilete evenimente / „vacanță gratuită" | ✅ playbook complet |
| OP-06 | Marketplace general (OLX/FB Marketplace) | ✅ playbook complet |
| OP-07 | Furt de identitate → financiar (IFN/credit) | ✅ susținut (caz auto + strat juridic) |
| OP-08 | Joburi false / oferte de muncă | ⚠️ stub — de extins, nu e în corpusul actual |
| OP-09 | Investiții / crypto / profit „garantat" | 🟡 parțial (din EvidenceGate + scara de plată) |

> **Modificator transversal (NU e familie):** `ai_generated` = documente/site-uri/voci generate AI (deepfake). Se aplică PESTE orice familie. Se modelează ca **flag boolean**, nu ca familie separată. AI face documentul credibil, NU face entitatea reală — ancora rămâne verificarea în registre.

---

## OP-01 — Turism / agenții de turism false

**Playbook:** site/pagină FB care imită o agenție/hotel/operator zbor, prețuri mult sub piață (uneori atac direct pe clienții Booking/Airbnb prin phishing) → încredere falsă cu logo-uri, licență falsă, recenzii fabricate, uneori **CUI real al unei agenții licențiate** → presiune („promoție ultim moment", „ultima cameră") → plată imediat **în afara platformei** (cont personal/Revolut) → dispare, rezervarea nu există.

**Artefacte:** factură/proformă PDF cu logo fals (IBAN, sumă, scadență, eventual QR); email confirmare cu domeniu similar Booking/hotel + link phishing care cere date card; contract pachet turistic fără CUI/licență.

**Semnale pe document:**
- 🔴 IBAN pe persoană fizică (nu firmă cu licență) — nepotrivire nume firmă vs titular IBAN.
- 🟠 Lipsă CUI/licență pe factură.
- 🟠 Domeniu email suspect (typosquatting / gmail), linkuri spre domenii neoficiale.
- 🟠 Preț sub piață + urgență („doar azi").
- 🔴 Plată în afara platformei (la Airbnb/Booking transferul direct e interzis).

**Surse de verificare:** Registru agenții licențiate ANAT (situr.gov.ro/OpenData — snapshot, fără API); CUI la ANAF (API gratuit v9); ONRC (dump data.gov.ro / wrappere); SANB (nume titular IBAN vs operator); SITUR (structuri clasificate).

**Metode de plată & risc:** transfer cont personal = mare; Revolut/fintech = mare; cripto = extrem; card pe site oficial cu 3DS = scăzut.

**Variante AI:** site-uri turistice generate AI cu recenzii fabricate; facturi/contracte AI cu logo+semnătură dar CUI/licență/adresă false; voce clonată „operator".

---

## OP-02 — Cazare scurtă (Airbnb / Booking / VRBO / anunțuri Facebook)

**Playbook:** copiază poze de pe Airbnb/Booking, postează pe FB Marketplace la preț atractiv → mută discuția off-platform, oferă „contract"/factură rezervare; uneori subînchiriere ilegală („apartamente fantomă") → cere transfer/Revolut, promite codurile de acces după plată → accesul nu există.

**Artefacte:** factură/proformă cu „avans chirie"/„taxă rezervare", IBAN personal, fără CUI valid; contract închiriere (uneori AI sau din acte reale); confirmare rezervare cu „cod acces" + instrucțiuni plată.

**Semnale pe document:**
- 🔴 IBAN personal pentru chirie scurtă / lipsă date firmă.
- 🟠 Preț sub piață + avans mare „de rezervare".
- 🔴 Cerere plată în afara platformei (Airbnb/Booking).
- 🟠 CUI inexistent/inactiv în contract.
- 🟠 Cod QR care duce la plată în cont personal (scanare → extragi IBAN).

**Surse de verificare:** platformele oficiale (confirmi cu gazda prin mesaje interne; orice link extern = suspect); ANAF/ONRC pentru firma care pretinde că deține apartamentul; sisteme recenzii (recenzii identice/inexistente); SANB.

**Metode de plată & risc:** transfer/Revolut = mare; card pe platforme oficiale = scăzut.

**Variante AI:** contracte AI (șabloane legale, nume firmă nepotrivit); subînchiriere cu date furate ale proprietarilor; apeluri „de confirmare" cu voce clonată.

---

## OP-03 — Chirii pe termen lung (apartamente / case)

**Playbook:** anunț sub piață → ești invitat să plătești „garanția" + „prima lună" **înainte de vizionare** („se închiriază rapid"); contract pe email → documente false (CI/proprietate), uneori CUI real al unei firme inactive → banii merg în cont personal, „proprietarul" dispare.

**Artefacte:** contract închiriere (date „proprietar"+chiriaș, adresă, chirie, cont, semnătură scanată); factură proformă pentru garanție.

**Semnale pe document:**
- 🟠 Contract neînregistrat la notar; date proprietar neverificabile.
- 🔴 IBAN personal pentru garanție (verifică SANB).
- 🟠 Nume firmă vs CUI nepotrivit (ANAF/ONRC); firmă inactivă sau care nu figurează ca proprietar.
- 🟠 Adresă reală dar nume proprietar care nu corespunde (Carte Funciară).
- 🟠 Preț prea mic + presiune pentru avans urgent.

**Surse de verificare:** ANAF/ONRC; Cartea Funciară / ANCPI (proprietar real — contra cost, prin notar, fără API public); SANB.

**Metode de plată & risc:** transfer cont personal = mare; depunere numerar la automat = mare; agenție licențiată cu cont escrow = scăzut.

**Variante AI:** acte identitate deepfake; vizionări online cu video deepfake → cere vizionare fizică sau gest specific la apel video.

---

## OP-04 — Vânzare auto (inclusiv transport / import auto)

**Playbook:** mașini cu 30–40% sub piață, poze și date reale ale unor firme în insolvență/executare → „am multe oferte" → cere avans (3.000–45.000 lei) pentru rezervare/transport; proforme + acte recepție falsificate → plata în conturi pe numele unor persoane vulnerabile, retrase rapid → dispare; uneori livrează vehicul furat.

> **Caz real (dublă fraudă):** după avans de 200€ pentru „aducere pe platformă", escrocul a cerut datele de buletin → a generat factură + desfășurător bancar fals și a luat **IFN/credit pe numele victimei**. Înșelăciune la plată **+ furt de identitate → credit**. Regula: **niciodată copie CI / date complete buletin** către vânzător necunoscut.

**Semnale pe document:**
- 🔴 IBAN vs nume firmă nepotrivit (SANB).
- 🟠 Preț foarte mic + avans mare.
- 🟠 Refuz vizionare fizică („e în depozit").
- 🟠 Acte incomplete (lipsă serie șasiu / dată primă înmatriculare / scanuri neclare).
- 🟠 Presiune („alții sunt interesați", „plătește azi").
- 🔴 Cerere copie CI / date complete buletin (risc furt identitate → IFN). [legătură OP-07]

**Surse de verificare:** RAR „Istoric Vehicul" (pe VIN, taxă, fără API); ONRC/ANAF (firmă există/insolvență); SANB; rapoarte auto (Carvertical/Autovit — neoficial); Biroul de Credit / ANAF SPV (furt identitate).

**Metode de plată & risc:** avans prin transfer/Revolut = mare; plată integrală la livrare prin dealer autorizat, în contul dealerului = scăzut.

**Variante AI:** anunțuri text+poze AI; contracte cu semnături/ștampile deepfake; voce clonată „vânzător".

---

## OP-05 — Bilete evenimente / concerte / „vacanță gratuită"

**Playbook:** oferte last-minute pe rețele/site-uri necunoscute la concerte/festivaluri sau „vacanță gratuită" → „aproape sold out" → plată imediată → primești QR/„bilet" PDF/jpg pe WhatsApp (duplicat sau inexistent) → la intrare biletul e invalidat.

**Semnale pe document:**
- 🟠 Vânzător cu profil nou, fără recenzii.
- 🔴 IBAN personal (biletele oficiale: Eventim/iabilet/Ticketmaster).
- 🟠 Bilet ca print screen (ușor de falsificat).
- 🟠 Preț sub valoarea nominală („nu mai pot participa").
- 🟠 Lipsă factură fiscală (doar proformă fără date firmă).

**Surse de verificare:** platformele oficiale de ticketing (verifici codul biletului); ANPC + DNSC.

**Metode de plată & risc:** transfer/Revolut = mare; card pe platforma oficială = scăzut.

**Variante AI:** QR replicate/generate AI; roboți care trimit oferte în masă prin DM; emailuri „ai câștigat o vacanță" care cer „taxe".

---

## OP-06 — Marketplace general (OLX, Facebook Marketplace)

**Playbook:** A) *cumpărător fals*: „plătesc imediat", trimite link care imită „Livrare OLX"/curier și cere datele cardului (număr, CVV, 3DS) → golesc cardul. B) *vânzător fals*: produs la preț mic, cere plata integrală în avans → dispare.

**Artefacte:** linkuri care copiază OLX pe alt domeniu (ex. `olx-pay.online`); factură cu „preț transport" + link de plată.

**Semnale pe document:**
- 🔴 Solicitare CVV / cod 3D Secure (nicio platformă legitimă nu le cere).
- 🟠 Domeniu non-`olx.ro`.
- 🟠 Plată integrală în avans în cont personal.
- 🟠 Factură cu CUI inexistent (ANAF/ONRC).
- 🟠 Mutarea discuției pe WhatsApp.

**Surse de verificare:** OLX/Facebook (chat intern, semnalări fraudă); ANAF/ONRC; SANB.

**Metode de plată & risc:** plată cu card prin link extern = mare; plată la livrare (ramburs) = scăzut.

**Variante AI:** linkuri phishing AI (design profesional, text localizat perfect → verifică domeniul); apeluri cu voce clonată „curier" care cere „taxa de transport".

---

## OP-07 — Furt de identitate → financiar (IFN / credit pe numele tău)

**Playbook:** sub pretextul unei tranzacții (auto, chirii, job), escrocul cere **copie CI / date complete buletin / CNP** → cu datele tale ia **credite la IFN/bancă pe numele tău**. Combină **fals privind identitatea (art. 327)** + **fals în înscrisuri (art. 322)** + **înșelăciune (art. 244)**.

**Semnale pe document:**
- 🔴 Cerere copie CI / poză buletin / CNP pentru o simplă vânzare-cumpărare.
- 🟠 „Trimite poza buletinului ca să pregătesc contractul" + plată avans.
- 🟠 Factură + desfășurător bancar fals generat după ce ai dat datele.

**Surse de verificare:** Biroul de Credit; ANAF SPV; raportare DNSC/Poliție/ANPC.

**Regula:** niciodată poză buletin/CNP pentru o simplă vânzare. Dacă s-a întâmplat: anunță banca, Biroul de Credit, plângere la Poliție, sesizare DNSC.

---

## OP-08 — Joburi false / oferte de muncă (⚠️ stub)

> **Stare:** nu există încă playbook detaliat în corpusul de cercetare. Lăsat în enum pentru completitudine. **De extins** într-o iterație ulterioară (nu inventa semnale acum). Default behavior: tratează ca OP-00 până la completare.

---

## OP-09 — Investiții / crypto / profit „garantat" (🟡 parțial)

**Semnale (din EvidenceGate + scara de plată):**
- 🔴 Promisiune profit rapid + cerere de aplicații de acces la distanță.
- 🔴 Metodă irevocabilă: crypto / wallet / QR crypto.
- 🟠 „Investiție garantată" fără sursă licențiată (verifică ASF).

**Surse de verificare:** ASF (registre/liste — siif); DNSC.

> **Stare:** parțial documentat. Semnalele de mai sus sunt solide; playbook-ul complet e de extins ulterior.

---

# PARTEA B — EvidenceGate: reguli de decizie (verdict)

> Acesta e stratul de decizie peste playbook-uri. Verdictul NU se bazează pe estetica documentului, ci pe dovezi deterministe. Se codifică în `offer_evidence_gate_mapper` care alimentează `reduce_verdict` (NU un scorer paralel).

## Principii hard pentru verdict

- Document frumos + logo corect **≠** legitim (AI generează PDF-uri credibile).
- Marketing agresiv / preț bun / termen-limită **nu** sunt suficiente singure pentru PERICULOS.
- **PERICULOS cere COMBINAȚIE:** plată irevocabilă **+** domeniu neoficial/lookalike **+** CUI/IBAN nealiniat **+** cerere card/CVV/OTP — sau provider/registru confirmă risc.
- Lipsa unei informații în registru = **SUSPECT**, nu automat PERICULOS. Excepție: CUI invalid/inexistent + factură de firmă + avans.
- Contextul real al userului **nu** scade riscul (atacatorul poate avea detalii reale ale unei rezervări/anunț).
- Niciun caz nu e „100% safe" — nu există verdict de siguranță absolută.

## Tabel de semnale cu logică de verdict (sursă pentru `offer_evidence_gate_mapper`)

| Semnal | Unde apare | Cum verifici | Putere | Verdict |
|---|---|---|---|---|
| Beneficiar IBAN persoană fizică pentru firmă/hotel/agenție | Factură / proformă / instrucțiuni plată | Extrage beneficiar+IBAN; compară cu emitent/CUI; ANAF/ONRC | Decisiv (dacă pretinde firmă + avans) | PERICULOS cu urgență/off-platform; altfel SUSPECT |
| Plată în afara platformei (Airbnb/Booking/OLX) | Mesaj / PDF / buton / QR | Domeniu+canal oficial; detectează WhatsApp/email extern | Puternic | SUSPECT; PERICULOS dacă cere card/CVV/OTP/transfer urgent |
| Cere card/CVV/OTP pentru „rezervare"/„preautorizare"/„primire bani" | Formular / link / PDF / mesaj | Extractor text + link + detector formular | Decisiv | PERICULOS |
| CUI lipsă/invalid/inactiv sau nu corespunde numelui | Factură / contract | ANAF/ONRC; OCR CUI; fuzzy match nume firmă | Puternic | SUSPECT; PERICULOS în combo cu avans/IBAN nealiniat |
| Domeniu/link lookalike sau recent pentru un brand cunoscut | Email / buton HTML / QR / footer factură | URL extractor + RDAP/TLS/Web Risk/urlscan | Puternic în combo | SUSPECT solo; PERICULOS cu brand + plată/date sensibile |
| Preț mult sub piață + termen scurt de plată | Text ofertă / factură | Heuristic + context (prețul e greu de verificat automat) | Mediu | SUSPECT solo |
| Metodă irevocabilă: crypto / gift card / Western Union / MoneyGram | Instrucțiuni plată | Text extractor + clasificator metodă plată | Decisiv | PERICULOS |
| QR de plată fără domeniu oficial / către wallet | PDF / poză / contract | QR decoder + detector URL/wallet | Puternic | SUSPECT; PERICULOS dacă crypto/wallet/impersonare brand |
| Document vizual profesionist, dar fără câmpuri legale coerente | Factură / contract / proformă | OCR câmpuri: emitent, CUI, adresă, IBAN, total, TVA | Mediu | SUSPECT; combo pentru PERICULOS |
| Canal privat după contactul inițial pe platformă | Mesaj / instrucțiuni | Canal input + pattern text | Mediu/puternic | SUSPECT; PERICULOS cu plată externă |
| Cerere copie CI / date buletin | Chat / contract | Niciun vânzător real nu are nevoie — risc IFN | Decisiv | PERICULOS (furt identitate) |

## Scara metodelor de plată (risc) — pentru `payment_method_classifier`

| Metodă de plată | Risc |
|---|---|
| Card în platformă oficială cu 3D Secure | scăzut/mediu |
| Transfer bancar către firmă verificată | mediu |
| Transfer bancar către persoană fizică pentru firmă/agenție/hotel | mare |
| Revolut / persoană fizică / alias | mare |
| Western Union / MoneyGram | periculos |
| Gift card / cod voucher | periculos |
| Crypto / wallet / QR crypto | periculos |

## Surse de verificare — cu limitări oneste (pentru PR4 `registry_verification`)

| Sursă | Ce verifici | Acces | Limitare |
|---|---|---|---|
| ANAF | CUI, TVA, inactiv/reactivat | Portal + servicii web (v9 gratuit) | Nu valida e-Factura fără acces autorizat; lipsa în e-Factura ≠ scam |
| ONRC | denumire, CUI, nr. RC, sediu, stare, administrator | Portal/servicii, parțial contra cost; API public gratuit neconfirmat | Bun pentru verificare manuală/semi-auto; atenție GDPR |
| Autoritate turism (ANAT/Minister) | licență agenție, structuri clasificate | Neconfirmat tehnic (turism.gov.ro a dat timeout) | NU transforma în regulă hard până nu avem URL/listă/API stabil |
| ANPC | ghiduri, reclamații | Site public + formular | Sursă educațională + UX „verifică/raportează", nu verdict automat |
| Airbnb / Booking / OLX (oficial) | domenii+canale oficiale, reguli platform-only | Public; fără API pentru rezervarea userului fără login | Utile pentru false-positive guard + off-platform risk |

## Limitări cunoscute (gaps) — Fable trebuie să le respecte

- Registrul licențelor de turism: confirmă manual un URL/listă stabilă înainte de integrare.
- Nu există API public universal pentru a valida rezervări Booking/Airbnb/VRBO fără login/consimțământ.
- Nu există mod sigur de verificare automată a proprietății unui apartament fără date sensibile / Carte Funciară; **evită stocarea datelor personale**.
- IBAN-ul validează **formatul**, nu proprietarul real.
- Un CUI valid **nu** garantează că oferta e reală (poate fi CUI furat/impersonat).
- AI-detection vizual pe PDF/poze e semnal **slab**; folosește verificări deterministe.
- Prețul sub piață e semnal slab/mediu, **nu** decisiv.
- Documentele Booking/Airbnb cu detalii reale pot fi tot scam dacă plata e mutată off-platform.

## Exemple concrete pe document (fixtures de test pe familie)

**OP-01 Turism**
```text
PDF: "SC Holiday Dreams SRL, CUI 12345678, IBAN RO.. pe POPESCU ION, avans 2.400 lei azi pana la 17:00"
WhatsApp: "mai am 2 locuri in Antalya 5*, plata pe Revolut @travel-maria"
Proforma cu logo ANAT, dar fara numar licenta si beneficiar persoana fizica
Pret: 399 euro all-inclusive 7 nopti + avion, in sezon, fara explicatie
```

**OP-02 Cazare scurtă**
```text
"Your reservation is at risk. Verify your card at booking-secure-verify.test"
PDF "Booking Confirmation" cu buton "Pay deposit" catre reservation-wallet.test
Factura cu beneficiar "ANDREI M." desi cazarea e "Hotel Central SRL"
```

**OP-03 Chirii lungă durată**
```text
"Sunt in Germania, trimit cheia prin Airbnb escrow dupa garantie"
Contract: proprietar "Maria I." dar IBAN beneficiar "SC Logistic Rent SRL"
Cerere Western Union pentru "garantie chei"
```

**OP-04 Auto**
```text
"BMW 2019, 6.900 euro, masina e in Hamburg, transport inclus dupa avans 500 euro"
Factura "EuroTransport Auto SRL" dar IBAN beneficiar persoana fizica
"Plateste asigurarea transportului prin crypto wallet"
```

**OP-05 Bilete / vacanță gratuită**
```text
"Am 2 bilete Untold, 40% reducere, platesti acum pe Revolut"
PDF e-ticket cu QR catre check-ticket-event.test
"Ai castigat vacanta gratuita, plateste taxa de activare 99 lei"
```

**OP-06 Marketplace**
```text
"Am facut plata, intra aici sa primesti banii" + link clona OLX
Formular cere numar card, sold si CVV (ca sa "primesti" bani)
PDF "Factura eMAG Marketplace" dar domeniu emag-marketplace-plata.test
```

**Transversal AI (`ai_generated`)**
```text
PDF impecabil "Booking Payment Verification" dar linkul e booking-verify-pay.test
Voce: "Sunt de la receptie, trebuie reconfirmat cardul" -> documentul cere CVV
Site clona cu certificat emis ieri + logo real
```

---

# PARTEA C — Juristul (strat de educație juridică)

> Al treilea pilon: după ce motorul dă verdict (SIGUR/SUSPECT/PERICULOS), atașează un card **„Ce spune legea"**. Se codifică în `data/legal_kb.json` + `legal_layer.py` (PR5). **NU mutează niciodată verdictul** — e doar informativ.

## Ce ESTE / ce NU este

| ✅ ESTE | ❌ NU este |
|---|---|
| Educație juridică în limbaj simplu (penal + fiscal + consumator) | Avocat / reprezentare în instanță |
| „Ce ți se întâmplă, ce drepturi ai, unde reclami" | Sfat juridic personalizat pe cazul exact |
| Răspuns determinist, pe articole de lege reale | Opinie inventată sau „garanție" că vei câștiga |
| Surse oficiale gratuite (legislatie.just.ro, ANAF, ANPC, DNSC) | Date din servicii plătite |

**Rol AI limitat:** doar reformulare prietenoasă a textului din KB, cu trimitere la articolul real; **fără invenții** de articole/pedepse. Cardul juridic apare ca informativ indiferent de verdict (chiar la SIGUR poate explica dreptul de retragere 14 zile).

## Module de cunoaștere juridică

### 1. Penal — când devine infracțiune
- **Înșelăciunea — art. 244 Cod penal:** inducere în eroare prin prezentarea ca adevărată a unei fapte mincinoase, pentru folos injust + pagubă → 6 luni–3 ani; cu nume/calități mincinoase ori mijloace frauduloase → 1–5 ani; împăcarea înlătură răspunderea.
- **Fals în înscrisuri — art. 320–323:** contrafacere/alterare documente (inclusiv facturi/contracte sub semnătură privată — art. 322) + uz de fals (art. 323).
- **Fals privind identitatea — art. 327:** identitate falsă / folosirea identității altcuiva.
- **Falsificarea de instrumente de plată — art. 311:** carduri, titluri de credit.
- *Pentru user:* ofertă „prea bună" + avans cerut + dispariție = tabloul clasic al înșelăciunii. Nu e „ghinion comercial" — e infracțiune, se depune plângere penală.

### 2. Fiscal / Factură
- **Factura — art. 319 Cod fiscal:** informații obligatorii (emitent + CUI, beneficiar, serie/număr, dată, descriere, preț, TVA).
- **RO e-Factura (2026):** din 1 ian 2026, B2B/B2C/B2G se transmit în RO e-Factura în 5 zile lucrătoare; persoanele fizice prin CNP — termen tranzitoriu până la 1 iun 2026 (OUG 120/2021, mod. OUG 89/2025).
- **Capcana „factura e reală deci e sigur" — FALS.** O factură poate fi corectă fiscal și totuși parte dintr-o înșelăciune. Factură validă ≠ tranzacție legitimă.
- **Mitul „zilei de scadență":** NU există zi de scadență universală impusă de lege; termenul e cel din contract/factură. „Plătește azi până la 17:00" = manipulare prin urgență artificială.

### 3. Protecția consumatorului
- **Drept de retragere 14 zile — OUG 34/2014:** la cumpărături la distanță, fără motive/penalizări. Dacă nu te-a informat, se prelungește până la 12 luni + 14 zile. Excepții: cazare/transport cu dată fixă, produse personalizate.
- **Termen livrare:** max 30 zile dacă nu s-a convenit altfel; altfel reziliere + bani înapoi.
- **Garanție legală de conformitate:** minimum 2 ani.
- **Adaos comercial — prețuri LIBERE:** nu există plafon general de adaos. Turism/auto/chirii/bilete = fără plafon. Singura plafonare (2026) e pe ~17 alimente de bază (OUG 22/2026). Ilegal doar dacă e practică comercială înșelătoare (Legea 363/2007) sau înșelăciune (art. 244).

### 4. Furt de identitate → credite / IFN
- Copie buletin/CI/CNP la vânzător necunoscut → credite IFN/bancă pe numele tău. Combină art. 327 + art. 322 + art. 244.
- Regulă: nu trimite poză buletin/CNP pentru o vânzare. Dacă s-a întâmplat: anunță banca + Biroul de Credit + plângere Poliție + DNSC.

## Mapare: semnal / familie → ce spune legea → ce faci (sursă pentru carduri)

| Situație / semnal | Ce spune legea | Ce faci |
|---|---|---|
| Avans cerut, apoi dispariție (auto, chirii, turism) | Înșelăciune — art. 244 | Plângere penală Poliție/Parchet; păstrează dovezile |
| Factură/contract contrafăcut sau alterat | Fals în înscrisuri — art. 320–323 | Nu plăti; sesizează Poliția; verifică CUI pe ANAF |
| Ți s-a cerut copie buletin/CNP | Risc fals identitate (art. 327) + credite frauduloase | Nu trimite; dacă ai trimis, anunță banca + Biroul de Credit + DNSC |
| Cerere plată off-platform (Airbnb/Booking/OLX) | Nu e infracțiune în sine, dar pierzi protecția platformei | Plătește doar în platformă; raportează contul |
| Preț „cu 50% peste/sub piață" | Prețuri libere — legal; ilegal doar dacă induce în eroare | Verifică emitentul, nu te grăbi din cauza prețului |
| Produs comandat online, vrei să renunți | Drept de retragere 14 zile — OUG 34/2014 | Declarație de retragere; cere rambursarea |
| Cerere card/CVV/OTP pentru „verificare" | Indiciu fraudă instrumente de plată — art. 311 | Nu da datele; sună banca; raportează DNSC |

## Unde reclami
- **112 / Poliția** — înșelăciune, fals, furt identitate.
- **DNSC** (dnsc.ro, 1911) — incidente cyber, phishing, fraude online.
- **ANPC** (anpc.ro) — probleme comerciale, drepturi consumator, retur.
- **ANAF** (anaf.ro) — facturi false, firme suspecte, verificare CUI/TVA.
- **Banca + Biroul de Credit** — transferuri frauduloase, credite pe numele tău.

## Disclaimer obligatoriu (de afișat în app)
> Informațiile sunt **educație juridică generală**, nu sfat juridic personalizat și nu înlocuiesc consultarea unui avocat. Articolele și termenele se pot modifica; pentru cazuri concrete adresează-te unui specialist sau autorităților. SigurScan nu garantează un rezultat juridic.

## Surse oficiale gratuite
- legislatie.just.ro — Cod penal (Legea 286/2009), Cod fiscal (Legea 227/2015)
- anaf.ro — RO e-Factura, verificare CUI/TVA, registrul inactivilor
- anpc.ro — drepturile consumatorilor, OUG 34/2014
- dnsc.ro — alerte fraude, raportare incidente
- onrc.ro — date firme (denumire, CUI, stare)

---

# PARTEA D — Seed-uri JSON gata de folosit

> Copiază aceste structuri 1:1 în repo. Sunt forma pe care o consumă codul. Versiunea/datele se actualizează la fiecare revizuire a legislației/atlasului.

## D.1 — `data/scam_atlas_offer_seed.json`

```json
{
  "version": "2026-06-11",
  "source": "Atlas Oferta+Plata + EvidenceGate Partea II",
  "power_legend": {
    "decisiv": "determina aproape sigur frauda -> PERICULOS (de regula in combinatie)",
    "mediu": "indica suspiciune -> SUSPECT, necesita coroborare",
    "slab": "singur nu e concludent, conteaza cumulat"
  },
  "cross_cutting_modifiers": [
    {
      "id": "ai_generated",
      "label": "Document/site/voce generate AI (deepfake)",
      "note": "Flag boolean peste orice familie. AI face documentul credibil, nu entitatea reala. Ancora ramane verificarea in registre. AI-detection vizual = semnal slab."
    }
  ],
  "families": [
    {
      "code": "OP-00",
      "name": "Necategorizat",
      "status": "default",
      "signals": []
    },
    {
      "code": "OP-01",
      "name": "Turism / agentii de turism false",
      "status": "complet",
      "signals": [
        {"text": "IBAN pe persoana fizica pentru firma/agentie", "where": "factura/contract/instructiuni plata", "verify": "SANB nume titular vs operator; ANAF/ONRC", "power": "decisiv", "verdict": "periculos_in_combo"},
        {"text": "Lipsa CUI/licenta pe factura", "where": "factura/contract", "verify": "ANAF v9; lista ANAT (snapshot)", "power": "mediu", "verdict": "suspect"},
        {"text": "Domeniu email suspect / linkuri neoficiale", "where": "email", "verify": "analiza domeniu typosquat", "power": "mediu", "verdict": "suspect"},
        {"text": "Pret sub piata + urgenta", "where": "oferta", "verify": "heuristic + context", "power": "mediu", "verdict": "suspect"},
        {"text": "Plata in afara platformei", "where": "instructiuni plata", "verify": "politici platforma", "power": "decisiv", "verdict": "periculos_in_combo"}
      ],
      "verification_sources": ["ANAT (situr.gov.ro/OpenData, snapshot)", "ANAF v9", "ONRC (data.gov.ro)", "SANB", "SITUR"],
      "payment_risk": {"transfer_cont_personal": "mare", "revolut_fintech": "mare", "crypto": "extrem", "card_3ds_site_oficial": "scazut"}
    },
    {
      "code": "OP-02",
      "name": "Cazare scurta (Airbnb/Booking/VRBO/FB)",
      "status": "complet",
      "signals": [
        {"text": "IBAN personal pentru chirie scurta / lipsa date firma", "where": "factura/proforma", "verify": "SANB; ANAF/ONRC", "power": "decisiv", "verdict": "periculos_in_combo"},
        {"text": "Pret sub piata + avans mare de rezervare", "where": "oferta", "verify": "heuristic", "power": "mediu", "verdict": "suspect"},
        {"text": "Cerere plata in afara platformei", "where": "mesaj/instructiuni", "verify": "canal oficial", "power": "decisiv", "verdict": "periculos_in_combo"},
        {"text": "CUI inexistent/inactiv in contract", "where": "contract", "verify": "ANAF/ONRC", "power": "mediu", "verdict": "suspect"},
        {"text": "Cod QR catre plata in cont personal", "where": "factura/confirmare", "verify": "QR decode -> IBAN", "power": "mediu", "verdict": "suspect_to_periculos"}
      ],
      "verification_sources": ["Platforme oficiale (mesaje interne)", "ANAF/ONRC", "SANB", "sisteme recenzii"],
      "payment_risk": {"transfer_revolut": "mare", "card_platforma_oficiala": "scazut"}
    },
    {
      "code": "OP-03",
      "name": "Chirii termen lung",
      "status": "complet",
      "signals": [
        {"text": "Contract neinregistrat la notar; date proprietar neverificabile", "where": "contract", "verify": "notar/Carte Funciara", "power": "mediu", "verdict": "suspect"},
        {"text": "IBAN personal pentru garantie", "where": "proforma garantie", "verify": "SANB", "power": "decisiv", "verdict": "periculos_in_combo"},
        {"text": "Nume firma vs CUI nepotrivit / firma inactiva", "where": "contract", "verify": "ANAF/ONRC", "power": "mediu", "verdict": "suspect"},
        {"text": "Adresa reala dar nume proprietar care nu corespunde", "where": "contract", "verify": "Carte Funciara/ANCPI", "power": "mediu", "verdict": "suspect"},
        {"text": "Pret prea mic + presiune avans urgent inainte de vizionare", "where": "oferta", "verify": "heuristic", "power": "mediu", "verdict": "suspect"}
      ],
      "verification_sources": ["ANAF/ONRC", "Carte Funciara/ANCPI (contra cost)", "SANB"],
      "payment_risk": {"transfer_cont_personal": "mare", "numerar_automat": "mare", "agentie_escrow": "scazut"}
    },
    {
      "code": "OP-04",
      "name": "Vanzare auto (inclusiv transport/import)",
      "status": "complet",
      "signals": [
        {"text": "IBAN vs nume firma nepotrivit", "where": "proforma", "verify": "SANB; ANAF/ONRC", "power": "decisiv", "verdict": "periculos_in_combo"},
        {"text": "Pret foarte mic + avans mare", "where": "oferta", "verify": "heuristic", "power": "mediu", "verdict": "suspect"},
        {"text": "Refuz vizionare fizica", "where": "mesaj", "verify": "pattern text", "power": "mediu", "verdict": "suspect"},
        {"text": "Acte incomplete (lipsa VIN / data prima inmatriculare)", "where": "acte", "verify": "RAR pe VIN", "power": "mediu", "verdict": "suspect"},
        {"text": "Presiune (altii sunt interesati / plateste azi)", "where": "mesaj", "verify": "pattern text", "power": "mediu", "verdict": "suspect"},
        {"text": "Cerere copie CI / date complete buletin", "where": "chat/contract", "verify": "regula hard - nimeni real nu cere", "power": "decisiv", "verdict": "periculos", "links_family": "OP-07"}
      ],
      "verification_sources": ["RAR Istoric Vehicul (VIN)", "ONRC/ANAF", "SANB", "Biroul de Credit / ANAF SPV"],
      "payment_risk": {"avans_transfer_revolut": "mare", "plata_la_livrare_dealer_autorizat": "scazut"}
    },
    {
      "code": "OP-05",
      "name": "Bilete evenimente / vacanta gratuita",
      "status": "complet",
      "signals": [
        {"text": "Vanzator cu profil nou, fara recenzii", "where": "profil", "verify": "reputatie", "power": "mediu", "verdict": "suspect"},
        {"text": "IBAN personal (biletele oficiale: Eventim/iabilet/Ticketmaster)", "where": "proforma", "verify": "SANB; platforma oficiala", "power": "decisiv", "verdict": "periculos_in_combo"},
        {"text": "Bilet ca print screen", "where": "imagine", "verify": "cod pe platforma oficiala", "power": "mediu", "verdict": "suspect"},
        {"text": "Pret sub valoarea nominala", "where": "oferta", "verify": "heuristic", "power": "mediu", "verdict": "suspect"},
        {"text": "Lipsa factura fiscala (doar proforma fara date firma)", "where": "document", "verify": "ANAF", "power": "mediu", "verdict": "suspect"}
      ],
      "verification_sources": ["Platforme ticketing oficiale", "ANPC", "DNSC"],
      "payment_risk": {"transfer_revolut": "mare", "card_platforma_oficiala": "scazut"}
    },
    {
      "code": "OP-06",
      "name": "Marketplace general (OLX/FB Marketplace)",
      "status": "complet",
      "signals": [
        {"text": "Solicitare CVV / cod 3D Secure", "where": "link/formular", "verify": "norme bancare - nimeni legitim nu cere", "power": "decisiv", "verdict": "periculos"},
        {"text": "Domeniu non-olx.ro", "where": "link", "verify": "verificare domeniu", "power": "mediu", "verdict": "suspect"},
        {"text": "Plata integrala in avans in cont personal", "where": "instructiuni", "verify": "SANB", "power": "mediu", "verdict": "suspect"},
        {"text": "Factura cu CUI inexistent", "where": "factura", "verify": "ANAF/ONRC", "power": "mediu", "verdict": "suspect"},
        {"text": "Mutarea discutiei pe WhatsApp", "where": "mesaj", "verify": "canal", "power": "mediu", "verdict": "suspect"}
      ],
      "verification_sources": ["OLX/Facebook (chat intern)", "ANAF/ONRC", "SANB"],
      "payment_risk": {"card_prin_link_extern": "mare", "plata_la_livrare_ramburs": "scazut"}
    },
    {
      "code": "OP-07",
      "name": "Furt de identitate -> financiar (IFN/credit)",
      "status": "sustinut",
      "signals": [
        {"text": "Cerere copie CI / poza buletin / CNP pentru o simpla vanzare", "where": "chat/contract", "verify": "regula hard", "power": "decisiv", "verdict": "periculos"},
        {"text": "Trimite poza buletinului ca sa pregatesc contractul + plata avans", "where": "chat", "verify": "pattern text", "power": "mediu", "verdict": "suspect"},
        {"text": "Factura + desfasurator bancar fals generat dupa ce ai dat datele", "where": "document", "verify": "context", "power": "mediu", "verdict": "suspect"}
      ],
      "verification_sources": ["Biroul de Credit", "ANAF SPV", "DNSC/Politie/ANPC"],
      "payment_risk": {}
    },
    {
      "code": "OP-08",
      "name": "Joburi false / oferte de munca",
      "status": "stub",
      "note": "Fara playbook in corpusul actual. Trateaza ca OP-00 pana la completare. Nu inventa semnale.",
      "signals": []
    },
    {
      "code": "OP-09",
      "name": "Investitii / crypto / profit garantat",
      "status": "partial",
      "signals": [
        {"text": "Promisiune profit rapid + cerere aplicatii acces la distanta", "where": "mesaj", "verify": "pattern text", "power": "decisiv", "verdict": "periculos"},
        {"text": "Metoda irevocabila: crypto / wallet / QR crypto", "where": "instructiuni plata", "verify": "clasificator metoda plata", "power": "decisiv", "verdict": "periculos"},
        {"text": "Investitie garantata fara sursa licentiata", "where": "oferta", "verify": "ASF SIIF", "power": "mediu", "verdict": "suspect"}
      ],
      "verification_sources": ["ASF (registre/liste)", "DNSC"],
      "payment_risk": {"crypto_wallet": "periculos"}
    }
  ]
}
```

## D.2 — `data/legal_kb.json`

```json
{
  "version": "2026-06-11",
  "disclaimer": "Informatiile sunt educatie juridica generala, nu sfat juridic personalizat si nu inlocuiesc consultarea unui avocat. Articolele si termenele se pot modifica; pentru cazuri concrete adreseaza-te unui specialist sau autoritatilor. SigurScan nu garanteaza un rezultat juridic.",
  "ai_role": "Doar reformulare prietenoasa a textului din KB, cu trimitere la articolul real. Fara inventii de articole/pedepse. Nu muta niciodata verdictul motorului.",
  "modules": {
    "penal": ["art_244", "art_320_323", "art_327", "art_311"],
    "fiscal": ["art_319_cod_fiscal", "ro_efactura_2026", "mit_scadenta"],
    "consumator": ["oug_34_2014_retragere", "termen_livrare_30zile", "garantie_2ani", "preturi_libere"],
    "identitate": ["furt_identitate_ifn"]
  },
  "cards": [
    {
      "id": "law-inselaciune-244",
      "triggers": ["avans_apoi_disparitie", "oferta_prea_buna_avans"],
      "title": "Inselaciunea (art. 244 Cod penal)",
      "summary": "Inducerea in eroare prin prezentarea ca adevarata a unei fapte mincinoase, pentru folos injust + paguba: 6 luni-3 ani; cu nume/calitati mincinoase ori mijloace frauduloase: 1-5 ani. Avans cerut + disparitie = tabloul clasic al inselaciunii, nu ghinion comercial.",
      "actions": ["Plangere penala la Politie/Parchet", "Pastreaza toate dovezile (mesaje, factura, dovada platii)"],
      "source_refs": ["legislatie.just.ro - Cod penal art. 244"]
    },
    {
      "id": "law-fals-inscrisuri-320-323",
      "triggers": ["factura_contrafacuta", "document_alterat"],
      "title": "Fals in inscrisuri (art. 320-323 Cod penal)",
      "summary": "Contrafacerea/alterarea de documente, inclusiv facturi/contracte sub semnatura privata (art. 322) si uzul de fals (art. 323).",
      "actions": ["Nu plati", "Sesizeaza Politia", "Verifica CUI pe ANAF"],
      "source_refs": ["legislatie.just.ro - Cod penal art. 320-323"]
    },
    {
      "id": "law-furt-identitate-327",
      "triggers": ["cerere_copie_ci", "cerere_cnp", "cerere_buletin"],
      "title": "Furt de identitate -> credite frauduloase (art. 327 + 322 + 244)",
      "summary": "Cu copie buletin/CI/CNP se pot lua credite IFN/banca pe numele tau. Combina fals privind identitatea (327) + fals in inscrisuri (322) + inselaciune (244).",
      "actions": ["Nu trimite poza buletin/CNP pentru o vanzare", "Daca ai trimis: anunta banca + Biroul de Credit + plangere Politie + DNSC"],
      "source_refs": ["legislatie.just.ro - Cod penal art. 327, 322, 244"]
    },
    {
      "id": "law-instrumente-plata-311",
      "triggers": ["cerere_card_cvv_otp"],
      "title": "Falsificarea de instrumente de plata (art. 311)",
      "summary": "Cererea de card/CVV/OTP pentru verificare este indiciu de frauda cu instrumente de plata. Nicio platforma/banca legitima nu cere CVV/OTP.",
      "actions": ["Nu da datele", "Suna banca", "Raporteaza DNSC"],
      "source_refs": ["legislatie.just.ro - Cod penal art. 311"]
    },
    {
      "id": "law-factura-319-efactura",
      "triggers": ["factura_reala_dar_scam", "intrebare_validitate_factura"],
      "title": "Factura valida != tranzactie legitima (art. 319 Cod fiscal + RO e-Factura)",
      "summary": "Factura are informatii obligatorii (art. 319). Din 1 ian 2026 B2B/B2C/B2G se transmit in RO e-Factura in 5 zile lucratoare (persoane fizice prin CNP - tranzitoriu pana la 1 iun 2026, OUG 120/2021 mod. OUG 89/2025). DAR o factura corecta fiscal NU garanteaza ca tranzactia e reala.",
      "actions": ["Verifica emitentul (CUI) pe ANAF", "Nu te baza pe aspectul facturii"],
      "source_refs": ["Cod fiscal art. 319", "OUG 120/2021 mod. OUG 89/2025"]
    },
    {
      "id": "law-scadenta-urgenta",
      "triggers": ["presiune_termen_limita", "plateste_azi"],
      "title": "Mitul zilei de scadenta",
      "summary": "Nu exista zi de scadenta universala impusa de lege; termenul e cel din contract/factura. 'Plateste azi pana la 17:00' = manipulare prin urgenta artificiala.",
      "actions": ["Nu te grabi din cauza urgentei", "La cumparaturi online ai drept de retragere 14 zile (cu exceptii)"],
      "source_refs": ["OUG 34/2014"]
    },
    {
      "id": "law-retragere-14-zile",
      "triggers": ["renuntare_comanda_online"],
      "title": "Drept de retragere 14 zile (OUG 34/2014)",
      "summary": "La cumparaturi la distanta te poti retrage in 14 zile calendaristice, fara motive/penalizari. Daca nu te-a informat, se prelungeste pana la 12 luni + 14 zile. Exceptii: cazare/transport cu data fixa, produse personalizate.",
      "actions": ["Trimite declaratie de retragere", "Cere rambursarea"],
      "source_refs": ["OUG 34/2014"]
    },
    {
      "id": "law-preturi-libere",
      "triggers": ["pret_mare", "pret_50_la_suta"],
      "title": "Preturile sunt libere",
      "summary": "Nu exista plafon general de adaos comercial. Turism/auto/chirii/bilete = fara plafon. Singura plafonare (2026) e pe ~17 alimente de baza (OUG 22/2026). Devine ilegal doar daca e practica comerciala inselatoare (Legea 363/2007) sau inselaciune (art. 244).",
      "actions": ["Verifica emitentul, nu te grabi din cauza pretului"],
      "source_refs": ["OUG 22/2026", "Legea 363/2007", "Cod penal art. 244"]
    },
    {
      "id": "law-off-platform",
      "triggers": ["plata_off_platform"],
      "title": "Plata in afara platformei",
      "summary": "Nu e infractiune in sine, dar pierzi protectia platformei (fara chargeback, fara garantie) - semnal major de risc.",
      "actions": ["Plateste doar in platforma", "Raporteaza contul"],
      "source_refs": ["Airbnb/Booking/OLX Trust & Safety"]
    }
  ],
  "report_channels": [
    {"name": "112 / Politia", "for": "inselaciune, fals, furt identitate"},
    {"name": "DNSC", "contact": "dnsc.ro, 1911", "for": "incidente cyber, phishing, fraude online"},
    {"name": "ANPC", "contact": "anpc.ro", "for": "probleme comerciale, drepturi consumator, retur"},
    {"name": "ANAF", "contact": "anaf.ro", "for": "facturi false, firme suspecte, verificare CUI/TVA"},
    {"name": "Banca + Biroul de Credit", "for": "transferuri frauduloase, credite pe numele tau"}
  ]
}
```

---

## Checklist pentru Fable (cum folosești acest pachet)

1. Pune `data/scam_atlas_offer_seed.json` și `data/legal_kb.json` în repo (copiate din Partea D).
2. PR1: `family_classifier` încarcă seed-ul atlas și EXTINDE `ScamAtlasEngine` (NU engine paralel).
3. PR2: `offer_evidence_gate_mapper` codifică tabelul de semnale (Partea B) și alimentează `reduce_verdict` (NU scorer paralel).
4. PR4: `registry_verification/*` folosește statusurile oneste din Partea B (MATCH/NO_MATCH/INCONCLUSIVE/NOT_CONFIGURED/SOURCE_TIMEOUT/SOURCE_ERROR).
5. PR5: `legal_layer.py` încarcă `legal_kb.json`; AI doar reformulează, niciodată nu mută verdictul.
6. Respectă gap-urile (limitări oneste) — nu transforma în reguli hard ce nu e confirmat (ex. registru turism).
