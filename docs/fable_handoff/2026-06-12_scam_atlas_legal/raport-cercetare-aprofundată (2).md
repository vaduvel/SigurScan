# Cercetare pentru stratul Verifică o ofertă sau o plată

## Ce poate confirma realist motorul înainte de plată

Pentru un motor pre-plată, verificările cu adevărat utile sunt cele care pornesc din ce vezi deja în ofertă sau document: denumirea emitentului, CUI-ul, IBAN-ul, site-ul, linkul de plată, QR-ul, licența invocată, identitatea vehiculului sau a imobilului și metoda de plată cerută. În România, coloana vertebrală realistă a acestui strat este formată din: ANAF pentru existență fiscală și status TVA, ONRC pentru existență/stare firmă prin portal și snapshoturi CSV oficiale, SITUR/OpenData pentru agenții de turism licențiate și radiate, ASF pentru entități autorizate și alertele privind entități neautorizate, BNR pentru registrele IFN/instituții de plată și accesul persoanei la datele CRC, RAR pentru Auto-Pass/ITP/autenticitate, ANCPI pentru carte funciară și plan cadastral și ANEVAR pentru evaluatori autorizați. Unde nu există un registru public central operațional pe care l-am putut identifica în această cercetare — mai ales pentru „agenți imobiliari licențiați” sau „dealeri auto legitimi” ca listă unică națională — motorul nu trebuie să inventeze autoritate; verdictul trebuie mutat pe verificarea firmei, a activului, a proprietății/vehiculului și a reputației online. citeturn6search0turn39search0turn39search4turn8search0turn8search1turn8search2turn4view3turn18search5turn5search0turn5search2turn35search1turn35search3turn35search9turn36search1turn36search2turn36search12turn37search1turn37search5

Din perspectiva prioritizării, datele DNSC/ING arată că fraudele de investiții au ajuns pe primul loc la nivel european, iar numai 4% dintre victime spun că își recuperează banii; la aceeași ediție Fraudy Talks, reprezentantul IGPR a indicat 928 de dosare de fraudă informatică în lucru în primele 4 luni din 2025, dintre care 170 înregistrate în 2025. Tradus pe românește: dacă documentul miroase a „profit rapid”, „link urgent” sau „cont personal”, nu e parfum, e benzină. citeturn34search4turn34search5

## Inventar de surse oficiale și recomandarea live versus snapshot

Inventarul de mai jos reține doar surse reale pe care le poți transforma într-un strat operațional. Am separat clar ce merită interogat live și ce merită ingerat ca snapshot. Când nu am identificat un API public real, am spus asta explicit. citeturn39search0turn39search1turn39search4turn35search1turn35search2turn35search9turn36search1turn36search2turn36search4turn37search1

```json
{
  "verification_source_inventory": [
    {
      "name": "ANAF PlatitorTvaRest v9",
      "covers": ["firme/CUI", "status TVA"],
      "url": "https://webservicesp.anaf.ro/api/PlatitorTvaRest/v9/tva",
      "access_type": "API live oficial",
      "api_or_list": "REST; documentație publică ANAF pe zona static.anaf.ro",
      "returns": ["date fiscale contribuabil", "status înregistrare TVA"],
      "recommended_runtime": "live",
      "notes": "Primul gate pentru existență fiscală și coerența CUI-ului din ofertă/factură."
    },
    {
      "name": "DemoANAF",
      "covers": ["firme/CUI"],
      "url": "https://www.demoanaf.ro/",
      "access_type": "wrapper gratuit, neoficial",
      "api_or_list": "API/wrapper",
      "returns": ["date ANAF simplificate"],
      "recommended_runtime": "live optional",
      "notes": "Util ca redundanță tehnică sau fallback UX; nu trebuie tratat ca sursă primară de adevăr."
    },
    {
      "name": "ONRC - snapshoturi open data",
      "covers": ["firme/CUI", "stare firmă", "sediu", "activități autorizate"],
      "url": "https://data.gov.ro/organization/onrc",
      "access_type": "listă descărcabilă oficială",
      "api_or_list": "CSV snapshot",
      "returns": ["profesioniști", "sediu social", "starea firmei", "activități autorizate"],
      "recommended_runtime": "snapshot",
      "notes": "Foarte bun pentru bază internă locală; nu e substitut perfect pentru un lookup live la zi."
    },
    {
      "name": "ONRC - portal servicii online / BPI",
      "covers": ["firme", "buletinul procedurilor de insolvență", "informații oficiale ONRC"],
      "url": "https://myportal.onrc.ro/",
      "access_type": "portal oficial; fără API public gratuit identificat în această cercetare",
      "api_or_list": "interfață web",
      "returns": ["servicii online ONRC", "acces BPI", "furnizare informații"],
      "recommended_runtime": "manual/hybrid",
      "notes": "Folosește-l pentru verificări ponctuale și pentru cazuri în care snapshotul nu ajunge."
    },
    {
      "name": "SITUR OpenData - agenții licențiate",
      "covers": ["turism", "agenții licențiate"],
      "url": "https://situr.gov.ro/portal/open-data",
      "access_type": "listă descărcabilă oficială",
      "api_or_list": "XLS/XLSX",
      "returns": ["agenții licențiate", "număr licență", "status publicat în fișier"],
      "recommended_runtime": "snapshot",
      "notes": "Ingest periodic; schema exactă trebuie citită din fișier la ingestie."
    },
    {
      "name": "SITUR OpenData - agenții radiate / retrase",
      "covers": ["turism", "agenții radiate", "licențe retrase"],
      "url": "https://situr.gov.ro/portal/open-data",
      "access_type": "listă descărcabilă oficială",
      "api_or_list": "XLS/XLSX",
      "returns": ["agenții radiate", "status retragere/radiere"],
      "recommended_runtime": "snapshot",
      "notes": "Obligatoriu în scoring; o agenție radiată înseamnă pericol, nu nostalgie."
    },
    {
      "name": "ASF - registrul entităților autorizate",
      "covers": ["investiții", "piață de capital", "asigurări", "pensii"],
      "url": "https://www.asfromania.ro/ro/a/2818/registrul-a.s.f.",
      "access_type": "registru oficial online",
      "api_or_list": "interfață web; fără API public identificat în această cercetare",
      "returns": ["entități autorizate/înregistrate/supravegheate"],
      "recommended_runtime": "live/hybrid",
      "notes": "Esențial pentru orice ofertă de investiții sau „broker” invocat în document."
    },
    {
      "name": "ASF - alerte investitori / entități neautorizate",
      "covers": ["investiții", "alerte de fraudă"],
      "url": "https://www.asfromania.ro/ro/c/214/atentie-la-entitati-neautorizate%21",
      "access_type": "pagină oficială de avertismente",
      "api_or_list": "interfață web",
      "returns": ["alerte privind clone, grupuri WhatsApp/Telegram, zero comision, propuneri telefonice false"],
      "recommended_runtime": "live",
      "notes": "Trebuie folosită ca semnal OSINT oficial, nu doar ca pagină de lectură."
    },
    {
      "name": "BNR - registre și liste",
      "covers": ["IFN", "instituții de plată", "instituții emitente de monedă electronică", "alte entități supravegheate BNR"],
      "url": "https://www.bnr.ro/Registre-si-Liste-717.aspx",
      "access_type": "registru oficial online",
      "api_or_list": "interfață web; fără API public identificat în această cercetare",
      "returns": ["registre și liste oficiale BNR"],
      "recommended_runtime": "live/hybrid",
      "notes": "Pentru oferte de credit, plăți, conturi escrow invocate și verificarea IFN-urilor."
    },
    {
      "name": "BNR - Centrala Riscului de Credit",
      "covers": ["verificare expuneri pe numele persoanei"],
      "url": "https://www.bnr.ro/Centrala-Riscului-de-Credit-%28CRC%29-2105-Mobile.aspx",
      "access_type": "interogare individuală / drept de acces la date",
      "api_or_list": "portal/informații oficiale",
      "returns": ["date privind expuneri raportate către CRC"],
      "recommended_runtime": "manual post-alert",
      "notes": "Limitare importantă: CRC are praguri proprii de raportare; nu înlocuiește Biroul de Credit."
    },
    {
      "name": "Biroul de Credit",
      "covers": ["istoric de credit", "interogare proprie pentru credite pe numele tău"],
      "url": "https://www.birouldecredit.ro/",
      "access_type": "portal oficial individual",
      "api_or_list": "fără API public identificat",
      "returns": ["raport de credit / acces persoană la datele proprii"],
      "recommended_runtime": "manual post-alert",
      "notes": "Este traseul practic pentru victima care vrea să verifice dacă s-a deschis credit pe numele ei."
    },
    {
      "name": "RAR Auto-Pass",
      "covers": ["istoric vehicul", "kilometraj", "daune"],
      "url": "https://www.rarom.ro/?p=298531",
      "access_type": "serviciu online oficial",
      "api_or_list": "interfață web; fără API public identificat",
      "returns": ["certificat digital RAR Auto-Pass"],
      "recommended_runtime": "live/manual",
      "notes": "Pentru auto este sursa oficială consumator-friendly cu cea mai mare greutate."
    },
    {
      "name": "RAR - verificare ITP",
      "covers": ["status ITP"],
      "url": "https://prog.rarom.ro/rarpol/",
      "access_type": "serviciu online oficial",
      "api_or_list": "interfață web",
      "returns": ["validitatea ITP după CIV sau VIN"],
      "recommended_runtime": "live/manual",
      "notes": "Bun ca semnal complementar, nu suficient singur."
    },
    {
      "name": "RAR - certificarea autenticității",
      "covers": ["autenticitate vehicul pentru înmatriculare"],
      "url": "https://www.rarom.ro/?page_id=619",
      "access_type": "serviciu oficial",
      "api_or_list": "procedură RAR",
      "returns": ["certificare autenticității"],
      "recommended_runtime": "manual",
      "notes": "Relevant când oferta invocă mașină importată sau documente de autentificare."
    },
    {
      "name": "ANCPI - extras carte funciară pentru informare",
      "covers": ["proprietate imobiliară"],
      "url": "https://epay.ancpi.ro/epay/SelectProd.action?prodId=1420",
      "access_type": "serviciu online oficial",
      "api_or_list": "interfață web; fără API public consumer identificat",
      "returns": ["extras CF pentru informare"],
      "recommended_runtime": "manual/hybrid",
      "notes": "Pentru vânzări/chirii: verifică titular, sarcini, ipoteci, situația juridică de bază."
    },
    {
      "name": "ANCPI - MyEterra",
      "covers": ["proprietarii își descarcă gratuit extrasele"],
      "url": "https://myeterra.ancpi.ro/",
      "access_type": "platformă oficială",
      "api_or_list": "interfață web",
      "returns": ["extrase gratuite pentru proprietari"],
      "recommended_runtime": "manual",
      "notes": "Utilă dacă vânzătorul pretinde că este proprietar și poate genera legal extrasul."
    },
    {
      "name": "ANCPI - Geoportal/Imobile",
      "covers": ["localizare și explorare cadastrală"],
      "url": "https://geoportal.ancpi.ro/imobile.html",
      "access_type": "aplicație oficială web",
      "api_or_list": "interfață web",
      "returns": ["căutare adresă/UAT/număr carte funciară"],
      "recommended_runtime": "live/manual",
      "notes": "Semnal vizual util pentru coerența adresei și a identificatorilor imobiliari."
    },
    {
      "name": "ANEVAR - căutare evaluator",
      "covers": ["evaluatori autorizați"],
      "url": "https://www.anevar.ro/cautare",
      "access_type": "registru profesional public",
      "api_or_list": "interfață web; fără API public identificat",
      "returns": ["căutare după nume, legitimație, județ, specializare"],
      "recommended_runtime": "live/manual",
      "notes": "Util numai când documentul invocă evaluări sau rapoarte ANEVAR."
    },
    {
      "name": "ANPC - reclamații consumatori",
      "covers": ["reclamații, sesizări pre și post tranzacție"],
      "url": "https://eservicii.anpc.ro/Depune-Cerere?serviciufilter-Category=Reclamatii+Consumatori&serviciupagesize=8",
      "access_type": "serviciu oficial",
      "api_or_list": "interfață web",
      "returns": ["canal de depunere reclamații"],
      "recommended_runtime": "manual post-alert",
      "notes": "Nu validează entitatea, dar este capătul oficial de escaladare pentru consumator."
    },
    {
      "name": "Poliția Română - petiții online",
      "covers": ["sesizare penală / petiție"],
      "url": "https://politiaromana.ro/ro/petitii-online",
      "access_type": "serviciu oficial",
      "api_or_list": "interfață web",
      "returns": ["canal de sesizare"],
      "recommended_runtime": "manual post-alert",
      "notes": "Relevant mai ales la furt de identitate, credit fraudulos, falsuri și înșelăciune."
    }
  ],
  "implementation_recommendation": {
    "query_live": [
      "ANAF PlatitorTvaRest v9",
      "ASF registru + alerte",
      "BNR registre și liste",
      "RAR Auto-Pass / ITP",
      "ANCPI unde utilizatorul poate furniza identificatorii imobiliari"
    ],
    "ingest_as_snapshot": [
      "ONRC CSV de pe data.gov.ro",
      "SITUR/OpenData liste agenții licențiate/radiate"
    ],
    "no_official_public_source_identified": [
      "registru public central al agenților imobiliari licențiați",
      "registru public central al dealerilor auto legitimi"
    ]
  }
}
```

## Patch pentru OP-08 joburi false

În corpusul 2024–2026 apar constant aceleași trei familii de job-scam: pseudo-joburi „ușoare” pe WhatsApp/Telegram, task scams cu like-uri/review-uri și recrutări care te transformă în cărăuș de bani sau îți cer acces la dispozitiv și la conturile tale. Sursele românești credibile repetă aceleași semnale: contact nesolicitat, câștig nerealist, mutarea discuției în afara canalelor corporate, lipsa unui angajator verificabil și cererea de plată / instalare remote access / furnizare CI sau date bancare. citeturn32search0turn32search1turn34search0turn20search5

```json
{
  "code": "OP-08",
  "name": "Joburi false / oferte de muncă fictive",
  "status": "sustinut",
  "signals": [
    {
      "text": "Primul contact vine nesolicitat pe WhatsApp, Telegram, SMS sau apel automat și susține că ai fost „selectat” fără să fi aplicat.",
      "where": "mesaj",
      "verify": "Verifică dacă postul există pe site-ul oficial al firmei și dacă expeditorul folosește un domeniu corporate real; dacă firma invocată nu poate fi confirmată în ANAF/ONRC, semnalul urcă.",
      "power": "mediu",
      "verdict": "suspect"
    },
    {
      "text": "Oferta promite bani rapizi pentru like-uri, review-uri, follow-uri, task-uri simple sau „work from home” fără contract și fără interviu real.",
      "where": "mesaj",
      "verify": "Confirmă dacă oferta apare pe site-ul oficial al angajatorului și dacă există contract cu denumire, CUI și adresă verificabile; lipsa acestora este incompatibilă cu o ofertă legitimă.",
      "power": "mediu",
      "verdict": "suspect_to_periculos"
    },
    {
      "text": "Se cere taxă în avans pentru training, echipament, activare cont, verificare, viză ori „deblocarea câștigurilor”.",
      "where": "instructiuni plata",
      "verify": "Un job legitim nu cere plată în contul recrutorului; verifică beneficiarul în ANAF/ONRC și compară-l cu angajatorul pretins. Dacă plata este către persoană fizică sau cont care nu aparține entității, semnalul este critic.",
      "power": "decisiv",
      "verdict": "periculos"
    },
    {
      "text": "Instrucțiunile cer instalarea AnyDesk, TeamViewer, Binance sau alte aplicații la indicația „recrutorului/angajatorului”.",
      "where": "mesaj",
      "verify": "Verifică dacă angajatorul are proces oficial de onboarding și suport IT pe site-ul său. Pentru utilizatorul obișnuit, cererea de remote access înainte de angajare se tratează ca fraudă operațională.",
      "power": "decisiv",
      "verdict": "periculos"
    },
    {
      "text": "Ți se cere să primești bani în contul tău și să-i retrimiți mai departe sau să trimiți colete primite la domiciliu.",
      "where": "contract",
      "verify": "Compară activitatea cerută cu modelul clasic de money mule/reshipping; verifică entitatea în ANAF/ONRC și refuză orice „job” în care contul tău personal devine instrument de tranzit.",
      "power": "decisiv",
      "verdict": "periculos"
    },
    {
      "text": "Contractul/oferta nu conține denumirea completă a angajatorului, CUI, sediu, reprezentant identificabil sau conține date care nu bat între ele.",
      "where": "contract",
      "verify": "Lookup în ANAF și ONRC; dacă CUI lipsește, nu există ori firma este inactivă/radiată, oferta pică gate-ul.",
      "power": "decisiv",
      "verdict": "periculos"
    },
    {
      "text": "Salariul este mult peste piață pentru efort minim și fără cerințe reale de experiență, iar accentul cade pe urgență și pe „începi azi”.",
      "where": "oferta",
      "verify": "Compară remunerația cu joburi similare publice și caută prezența reală a angajatorului; dacă totul e prea frumos și prea urgent, nu e hrănitor, e capcană.",
      "power": "slab",
      "verdict": "periculos_in_combo"
    },
    {
      "text": "Ți se cere copie CI, selfie, date bancare, card, OTP sau credențiale înainte să fie validat angajatorul.",
      "where": "mesaj",
      "verify": "Verifică întâi identitatea firmei și politica de recrutare de pe site-ul oficial; cererea prematură de date sensibile se tratează ca risc de furt de identitate.",
      "power": "mediu",
      "verdict": "suspect_to_periculos"
    },
    {
      "text": "Linkul de înscriere sau de „activare job” duce spre un domeniu look-alike ori fără legătură cu brandul pretins.",
      "where": "link",
      "verify": "Compară domeniul cu site-ul oficial și verifică linkul prin scanare de reputație; dacă brandul din mesaj nu corespunde domeniului, semnalul este puternic.",
      "power": "decisiv",
      "verdict": "periculos"
    }
  ],
  "verification_sources": [
    "https://ing.ro/ing-in-romania/informatii-utile/securitate/joburi-false",
    "https://ing.ro/ing-in-romania/informatii-utile/securitate/carausi-de-bani",
    "https://economedia.ro/te-a-sunat-un-robot-sa-ti-spuna-ca-ai-fost-acceptat-la-un-job-nu-vei-fi-platit-pentru-like-urile-pe-care-te-pune-sa-le-dai-si-risti-sa-platesti-tu-pentru-a-creste-artificial-conturile-altora-de-tikto.html",
    "https://webservicesp.anaf.ro/api/PlatitorTvaRest/v9/tva",
    "https://data.gov.ro/organization/onrc",
    "https://myportal.onrc.ro/"
  ],
  "payment_risk": {
    "fara_plata": "scazut",
    "transfer_instant_catre_cont_personal": "periculos",
    "transfer_bancar_catre_firma_neverificata": "mare",
    "card_pe_link_primit_in_mesaj": "periculos",
    "crypto_atm_sau_crypto_wallet": "extrem",
    "primire_si_retrimitere_bani_prin_contul_tau": "extrem"
  }
}
```

Fixture-urile de mai jos sunt parafraze anonimizate ale unor mesaje și scenarii reale descrise public, nu citate lungi. Le-am scris scurt, ca să intre direct în testele de seed. citeturn32search0turn32search1turn34search0turn20search5

```json
{
  "examples": [
    {
      "text": "Bună! Ai fost selectat pentru un job remote. Tot ce faci este să dai like-uri și follow. Câștigi 300-800 lei/zi. Continuăm pe Telegram.",
      "family": "OP-08",
      "expected_signals": [
        "contact nesolicitat",
        "câștig nerealist",
        "mutare pe Telegram",
        "fără angajator verificabil"
      ],
      "source": "https://ing.ro/ing-in-romania/informatii-utile/securitate/joburi-false"
    },
    {
      "text": "Felicitări, ai trecut interviul! Pentru activarea contului și training trebuie achitată o taxă de 150 lei, returnabilă la primul salariu.",
      "family": "OP-08",
      "expected_signals": [
        "taxă în avans pentru job",
        "urgență artificială",
        "fără contract real"
      ],
      "source": "https://ing.ro/ing-in-romania/informatii-utile/securitate/joburi-false"
    },
    {
      "text": "Compania caută colaborator logistic. Primești colete la domiciliu și le retrimiți; păstrezi comision din fiecare expediere.",
      "family": "OP-08",
      "expected_signals": [
        "reshipping",
        "job fără activitate economică clară",
        "angajare cu risc penal"
      ],
      "source": "https://ing.ro/ing-in-romania/informatii-utile/securitate/carausi-de-bani"
    },
    {
      "text": "Vei primi bani de la clienți în contul tău, apoi îi trimiți mai departe. Este doar o procedură internă de procesare plăți.",
      "family": "OP-08",
      "expected_signals": [
        "money mule",
        "folosirea contului personal",
        "job incompatibil cu practici legitime"
      ],
      "source": "https://ing.ro/ing-in-romania/informatii-utile/securitate/carausi-de-bani"
    },
    {
      "text": "Pentru retragerea comisioanelor și configurarea platformei, instalează AnyDesk și Binance; consultantul te va ghida.",
      "family": "OP-08",
      "expected_signals": [
        "remote access",
        "platformă externă obscură",
        "preluare control dispozitiv"
      ],
      "source": "https://ing.ro/ing-in-romania/informatii-utile/securitate/joburi-false"
    },
    {
      "text": "Avem task-uri de promovare pe TikTok și Telegram. Primele misiuni sunt plătite, apoi trebuie să depui o sumă mai mare ca să urci de nivel.",
      "family": "OP-08",
      "expected_signals": [
        "task scam",
        "escaladare prin depuneri",
        "câștiguri artificiale de început"
      ],
      "source": "https://economedia.ro/te-a-sunat-un-robot-sa-ti-spuna-ca-ai-fost-acceptat-la-un-job-nu-vei-fi-platit-pentru-like-urile-pe-care-te-pune-sa-le-dai-si-risti-sa-platesti-tu-pentru-a-creste-artificial-conturile-altora-de-tikto.html"
    }
  ]
}
```

## Patch pentru OP-09 investiții și crypto

Pentru 2024–2026, topologia este clară: reclame cu profit nerealist, clone de brokeri/platforme, deepfake cu persoane publice sau instituții, grupuri WhatsApp/Telegram, „consilierul” care vrea AnyDesk/TeamViewer și, după pierdere, al doilea strat de fraudă — recovery scam. În România, sursele cele mai solide pentru confirmare sunt ASF, BNR, MAI/Poliția Română, DNSC și paginile de securitate publicate de bănci mari. citeturn33search2turn18search1turn18search2turn18search5turn18search7turn18search12turn19search0turn20search0turn20search1turn20search2turn20search3

```json
{
  "code": "OP-09",
  "name": "Investiții false / crypto / profit garantat",
  "status": "sustinut",
  "signals": [
    {
      "text": "Oferta promite profit rapid, garantat sau cvasi-garantat, de tipul «investești puțin, câștigi lunar sume mari».",
      "where": "oferta",
      "verify": "Compară promisiunea cu avertismentele MAI/ASF/BNR; un randament fix și spectaculos, mai ales în crypto, este semnal de risc major.",
      "power": "decisiv",
      "verdict": "periculos"
    },
    {
      "text": "Se invocă imaginea unei celebrități, a guvernatorului BNR, a ASF sau a altor instituții pentru a valida platforma.",
      "where": "profil",
      "verify": "Verifică dacă BNR/ASF au anunț oficial despre campanie; BNR a avertizat explicit asupra deepfake-urilor cu imaginea guvernatorului.",
      "power": "decisiv",
      "verdict": "periculos"
    },
    {
      "text": "Entitatea sau platforma nu apare în registrul ASF ori nu figurează ca intermediar autorizat / notificat.",
      "where": "oferta",
      "verify": "Lookup obligatoriu în Registrul ASF și, după caz, în lista intermediarilor BVB; absența din registru este gate blocker.",
      "power": "decisiv",
      "verdict": "periculos"
    },
    {
      "text": "«Consultantul» cere instalarea AnyDesk/TeamViewer ori vrea să gestioneze el contul tău sau retragerea banilor.",
      "where": "mesaj",
      "verify": "Orice cerere de remote access în context investițional se tratează ca fraudă; verifică recomandările BCR/ING și avertismentele MAI.",
      "power": "decisiv",
      "verdict": "periculos"
    },
    {
      "text": "Plata se cere în crypto, prin QR, în cont personal sau prin alte metode irevocabile/off-platform.",
      "where": "instructiuni plata",
      "verify": "Compară metoda cerută cu standardul pieței reglementate; plata ireversibilă către beneficiar neverificat este semnal critic.",
      "power": "decisiv",
      "verdict": "periculos"
    },
    {
      "text": "Există un grup WhatsApp/Telegram de «investiții» cu recomandări, semnale, zero comision sau «comunitate premium».",
      "where": "profil",
      "verify": "ASF avertizează explicit asupra grupurilor de investiții pe WhatsApp/Telegram; verifică și dacă numele entității apare în alertele ASF.",
      "power": "mediu",
      "verdict": "suspect_to_periculos"
    },
    {
      "text": "După ce ai «profit» pe platformă, ți se cer taxe de retragere, comisioane de deblocare sau comision de recuperare a banilor pierduți.",
      "where": "instructiuni plata",
      "verify": "Tratează-l ca recovery scam; nu există retragere legitimă care să ceară taxă către cont personal sau portofel obscur înainte de restituirea fondurilor.",
      "power": "decisiv",
      "verdict": "periculos"
    },
    {
      "text": "Site-ul sau linkul arată ca brandul invocat, dar domeniul este look-alike, nou sau fără prezență oficială coerentă.",
      "where": "link",
      "verify": "Compară domeniul cu site-ul oficial al entității și caută dacă apare în avertismente publice; clonele și domeniile look-alike sunt frecvente în trading scam.",
      "power": "decisiv",
      "verdict": "periculos"
    },
    {
      "text": "Apelul sau mesajul vine cu presiune: «oferta expiră azi», «valoarea intrării minime este acum», «dacă nu depui, pierzi profitul».",
      "where": "mesaj",
      "verify": "Corelează urgența cu celelalte semnale; singură poate fi medie, dar în combinație cu neautorizarea și plata irevocabilă urcă la maxim.",
      "power": "slab",
      "verdict": "periculos_in_combo"
    }
  ],
  "verification_sources": [
    "https://www.asfromania.ro/ro/a/2818/registrul-a.s.f.",
    "https://www.asfromania.ro/ro/c/214/atentie-la-entitati-neautorizate%21",
    "https://www.bnr.ro/25285-2026-02-18-tentativa-de-frauda-financiara-tip-deepfake-care-foloseste-imaginea-guvernatorului-bnr",
    "https://www.bnr.ro/24948-avertisment-cu-privire-la-campanii-de-dezinformare-si-tentative-de-frauda-in-numele-bnr",
    "https://www.mai.gov.ro/atentie-la-inselaciunile-prin-metoda-trading-scam/",
    "https://www.dnsc.ro/citeste/alerta-investitii-sau-capcana-modelul-fraudulos-txex-co",
    "https://www.bcr.ro/ro/persoane-fizice/informatii-utile/securitate/securitatea-tranzactiilor-pe-internet",
    "https://ing.ro/ing-in-romania/informatii-utile/securitate/fraude-investitii"
  ],
  "payment_risk": {
    "transfer_catre_broker_reglementat_confirmat": "scazut",
    "transfer_bancar_catre_cont_personal": "periculos",
    "card_pe_link_primit_din_reclama_sau_chat": "periculos",
    "crypto_wallet_sau_crypto_qr": "extrem",
    "atm_crypto": "extrem",
    "plata_taxei_de_retragere_sau_recovery_fee": "extrem"
  }
}
```

Și aici fixture-urile sunt parafraze compacte ale mesajelor și scenariilor documentate public. Când vezi „profit garantat” plus „instalează AnyDesk”, nu mai e investiție, e teleportare a banilor în alt buzunar. citeturn33search2turn18search2turn18search7turn19search0turn20search0turn20search1

```json
{
  "examples": [
    {
      "text": "Investește 1.200 lei în acțiuni la [companie mare] și poți începe să câștigi de la 10.000 lei în fiecare lună.",
      "family": "OP-09",
      "expected_signals": [
        "profit nerealist",
        "brand exploatat abuziv",
        "ofertă neverificabilă"
      ],
      "source": "https://www.mai.gov.ro/atentie-la-inselaciunile-prin-metoda-trading-scam/"
    },
    {
      "text": "BNR recomandă noua platformă de investiții. Vezi video-ul cu Mugur Isărescu și înscrie-te acum.",
      "family": "OP-09",
      "expected_signals": [
        "deepfake",
        "impersonare instituțională",
        "autoritate falsă"
      ],
      "source": "https://www.bnr.ro/25285-2026-02-18-tentativa-de-frauda-financiara-tip-deepfake-care-foloseste-imaginea-guvernatorului-bnr"
    },
    {
      "text": "Te adăugăm într-un grup WhatsApp premium cu semnale de investiții, comision zero și randamente zilnice.",
      "family": "OP-09",
      "expected_signals": [
        "grup WhatsApp/Telegram",
        "zero comision",
        "promisiuni speculative"
      ],
      "source": "https://www.asfromania.ro/ro/c/214/atentie-la-entitati-neautorizate%21"
    },
    {
      "text": "Pentru validarea contului și retragerea profitului, instalează AnyDesk / TeamViewer; consultantul te va ghida pas cu pas.",
      "family": "OP-09",
      "expected_signals": [
        "remote access",
        "broker care preia dispozitivul",
        "risc de golire a contului"
      ],
      "source": "https://www.bcr.ro/ro/persoane-fizice/informatii-utile/securitate/securitatea-tranzactiilor-pe-internet"
    },
    {
      "text": "Fondurile tale sunt blocate temporar. Pentru deblocare și recuperare achită taxa de retragere în crypto.",
      "family": "OP-09",
      "expected_signals": [
        "recovery scam",
        "taxă de retragere",
        "plată irevocabilă"
      ],
      "source": "https://ing.ro/ing-in-romania/informatii-utile/securitate/fraude-investitii"
    },
    {
      "text": "Platforma TXEX oferă tranzacționare simplă și câștiguri rapide; te contactăm pe Telegram pentru pașii de depunere.",
      "family": "OP-09",
      "expected_signals": [
        "platformă reclamată public",
        "mutare pe Telegram",
        "depunere dirijată"
      ],
      "source": "https://www.dnsc.ro/citeste/alerta-investitii-sau-capcana-modelul-fraudulos-txex-co"
    }
  ]
}
```

## Corpus de fixture-uri reale pentru OP-01..07

Setul de mai jos păstrează doar exemple reale sau parafraze foarte apropiate de mesajele/scenariile relatate public în România, 2024–2026. Nu am umplut artificial până la 5–8 perfect textuale pentru fiecare familie, pentru că spațiul public nu publică uniform capturi de conversații; acolo unde presa descrie clar mecanismul, fixture-ul este o parafrază scurtă și fidelă a acelui mecanism. citeturn24search0turn24search3turn24search6turn25search0turn25search1turn26search9turn26search12turn26search17turn30search0turn30search5turn30search9turn30search13turn23search0turn23search6turn23search7turn23search9turn21search0turn21search1turn21search6turn31search1turn31search3turn31search5turn31search9

```json
{
  "examples": [
    {
      "text": "Am acces la pachete last-minute în Turcia și Maldive. Doar azi mai prindem tariful. Trimite avansul, iar ordinul de plată ți-l trimit imediat.",
      "family": "OP-01",
      "expected_signals": ["urgență", "avans înainte de documente finale", "pretins intermediar"],
      "payment_method": "transfer bancar",
      "why_fraud": "Scenariul folosește presiune și dovadă de plată falsă pentru vacanțe inexistente sau neplătite real.",
      "source": "https://stirileprotv.ro/stiri/actualitate/vacante-last-minute-metoda-ingenioasa-de-inselaciune-o-femeie-din-bucuresti-a-fost-retinuta-dupa-fraude-de-40-000-de-euro.html"
    },
    {
      "text": "Pachetul e de la o agenție adevărată, eu doar intermediez și plătesc în numele tău. Tu transferi către mine și primești voucherul după confirmare.",
      "family": "OP-01",
      "expected_signals": ["intermediar neclar", "plată către alt beneficiar", "agenție invocată, dar necontractantă"],
      "payment_method": "transfer bancar",
      "why_fraud": "Datele unei persoane sau ale unei firme reale sunt folosite pentru a acoperi o intermediere frauduloasă.",
      "source": "https://stirileprotv.ro/stiri/actualitate/vacante-last-minute-metoda-ingenioasa-de-inselaciune-o-femeie-din-bucuresti-a-fost-retinuta-dupa-fraude-de-40-000-de-euro.html"
    },
    {
      "text": "Vacanța este achitată, uite desfășurătorul. Mai trebuie doar să-mi trimiți diferența azi, altfel pierzi locurile.",
      "family": "OP-01",
      "expected_signals": ["ordin de plată fals", "urgență", "dovadă de plată neverificată"],
      "payment_method": "transfer bancar",
      "why_fraud": "În cazurile documentate au fost trimise ordine de plată false pentru a liniști victimele până după încasare.",
      "source": "https://www.news.ro/justitie/femeie-inselat-150-000-euro-doua-agentii-turism-zeci-persoane-fizice-carora-le-promis-vacante-last-minute-destinatii-externe-trimisa-judecata-incercat-scape-dand-vina-persoana-1922405209002026061422473931"
    },

    {
      "text": "Revalidează datele cardului în următoarele 2 ore, altfel rezervarea Booking va fi anulată. Intră pe linkul de mai jos.",
      "family": "OP-02",
      "expected_signals": ["link de plată în chat", "urgență", "cerere de revalidare card"],
      "payment_method": "card pe link",
      "why_fraud": "Hotelul sau contul de comunicare este compromis ori este imitat; clientul e scos din fluxul normal Booking și împins spre phishing.",
      "source": "https://stirileprotv.ro/stiri/ibani/cum-puteti-ramane-fara-banii-de-concediu-patania-unui-roman-care-a-crezut-ca-plateste-hotelul.html"
    },
    {
      "text": "Pentru confirmarea sejurului trebuie să plătești acum un avans din chat-ul proprietății; altfel camera se eliberează.",
      "family": "OP-02",
      "expected_signals": ["avans cerut prin link extern", "presiune de timp", "off-platform"],
      "payment_method": "card pe link",
      "why_fraud": "DNSC și presa locală au descris exact acest tip de mesaj trimis după compromiterea conturilor de hotel.",
      "source": "https://www.dnsc.ro/citeste/stirile-saptamanii-din-cybersecurity-19-06-2025"
    },
    {
      "text": "Apartamentul există, dar proprietarul cere plata în afara platformei și promite check-in-ul după transfer.",
      "family": "OP-02",
      "expected_signals": ["plată off-platform", "proprietar neverificat", "ocolirea protecției platformei"],
      "payment_method": "transfer bancar",
      "why_fraud": "Oferta mută plata în afara platformei tocmai ca să taie protecția de procesator și mecanismele anti-fraudă.",
      "source": "https://stirileprotv.ro/stiri/ibani/cum-puteti-ramane-fara-banii-de-concediu-patania-unui-roman-care-a-crezut-ca-plateste-hotelul.html"
    },

    {
      "text": "Apartamentul este foarte căutat. Ca să-l țin pentru tine până la vizionare, trimite garanția și prima chirie.",
      "family": "OP-03",
      "expected_signals": ["garanție înainte de vizionare", "presiune", "chirie sub piață"],
      "payment_method": "transfer bancar",
      "why_fraud": "Înșelăciunea mută plata înainte de orice verificare fizică sau juridică a imobilului.",
      "source": "https://observatornews.ro/eveniment/anunturi-capcana-pe-siteurile-de-imobiliare-tineri-pacaliti-sa-plateasca-un-avans-pentru-chirii-inexistente-627235.html"
    },
    {
      "text": "Sunt plecat, dar îți trimit contractul și actele. După ce virezi garanția, îți rezerv apartamentul și primești cheia.",
      "family": "OP-03",
      "expected_signals": ["acte trimise la distanță", "garanție înainte de acces", "proprietar imposibil de întâlnit"],
      "payment_method": "transfer bancar",
      "why_fraud": "Schema folosește documente și acte false pentru a înlocui întâlnirea și verificarea proprietății.",
      "source": "https://snoop.ro/escrocheria-cu-apartamente-de-pe-airbnb-bazata-pe-date-furate-banii-duc-catre-firma-fondata-de-hackerul-din-dosarul-hexi-pharma/"
    },
    {
      "text": "Chiria este sigură, dar plata se face în crypto; după confirmare îți trimit locația și detaliile finale.",
      "family": "OP-03",
      "expected_signals": ["crypto pentru chirie", "fără verificare ANCPI", "anonimizare beneficiar"],
      "payment_method": "crypto",
      "why_fraud": "În dosarul de chirii fictive documentat în 2026, suspecții cereau inclusiv transferuri prin criptomonede.",
      "source": "https://www.bucurestifm.ro/2026/02/19/perchezitii-in-bucuresti-si-teleorman-intr-un-dosar-de-chirii-fictive/"
    },

    {
      "text": "Mașina este rezervată pentru tine; trimite un avans azi și ți-o păstrez până ajunge transportul.",
      "family": "OP-04",
      "expected_signals": ["avans pentru vehicul", "bun neaflat la vedere", "rezervare urgentă"],
      "payment_method": "transfer bancar",
      "why_fraud": "Cazurile din 2025–2026 arată vânzători care încasau avansuri pentru mașini pe care nu le dețineau.",
      "source": "https://stirileprotv.ro/stiri/actualitate/escrocherie-cu-masini-de-lux-un-barbat-din-bucuresti-a-fost-retinut-dupa-ce-a-luat-avansuri-si-a-disparut-cu-7-000-de-euro.html"
    },
    {
      "text": "Anunțul este al unei firme reale, avem toate datele conforme. Transferă avansul și primești factura după confirmare.",
      "family": "OP-04",
      "expected_signals": ["impersonare firmă reală", "date aparent conforme", "avans înainte de verificare RAR"],
      "payment_method": "transfer bancar",
      "why_fraud": "Gruparea documentată de Digi24 folosea poze și datele unei firme reale pentru a legitima oferta.",
      "source": "https://www.digi24.ro/stiri/cum-au-fost-inselati-zeci-de-oameni-cu-masini-puse-la-vanzare-online-toate-datele-erau-conforme-cu-realitatea-am-platit-integral-3291797"
    },
    {
      "text": "Avem publicarea oficială de vânzare și contul pentru plată. Trimiți banii și mașina intră direct la tine în proprietate.",
      "family": "OP-04",
      "expected_signals": ["publicație de vânzare falsificată", "cont bancar modificat", "document aparent oficial"],
      "payment_method": "transfer bancar",
      "why_fraud": "Escrocii au falsificat publicații oficiale, au schimbat datele bancare și au înlocuit bunurile cu automobile luate de pe site-uri reale.",
      "source": "https://tvrinfo.ro/inselaciuni-cu-vanzari-de-masini-pe-internet-liderul-gruparii-are-un-trecut-infractional-bogat/"
    },
    {
      "text": "Îți aduc mașina din stoc extern după ce intră avansul; oferta e valabilă doar azi.",
      "family": "OP-04",
      "expected_signals": ["bun neprezentat", "avans în avans", "presiune de timp"],
      "payment_method": "transfer bancar",
      "why_fraud": "În cazurile publice, samsarii încasau banii în avans pentru mașini pe care nu le mai aduceau niciodată.",
      "source": "https://www.libertatea.ro/stiri/samsar-bihor-inselaciune-facut-jumatate-milion-euro-incasat-bani-masini-in-avans-5497190"
    },

    {
      "text": "Am un bilet la festival sub prețul oficial. Dacă vrei să-l păstrez, plătești acum și ți-l trimit imediat în format PDF/QR.",
      "family": "OP-05",
      "expected_signals": ["sub prețul pieței", "plată rapidă", "bilet digital neverificat"],
      "payment_method": "transfer instant",
      "why_fraud": "Fraudele cu bilete false sau deja revândute se bazează pe urgență și pe imposibilitatea de a valida autenticitatea în timp real.",
      "source": "https://observatornews.ro/economic/teapa-cu-biletele-de-la-festival-625952.html"
    },
    {
      "text": "Trimit captura comenzii și confirmarea, dar doar după plata integrală în contul meu personal.",
      "family": "OP-05",
      "expected_signals": ["cont personal", "confirmări ușor falsificabile", "off-platform"],
      "payment_method": "transfer bancar",
      "why_fraud": "Organizatorii și băncile au avertizat asupra biletelor false, anulate sau vândute de mai multe ori.",
      "source": "https://www.librabank.ro/blog/Ticket-Scam---evita-fraudele-cu-bilete-false-la-concerte-festivaluri-sau-evenimente-sportive/2278"
    },
    {
      "text": "Sunt ultimele locuri; plata se face acum, altfel le dau altcuiva. Îți trimit biletele pe Messenger.",
      "family": "OP-05",
      "expected_signals": ["urgență", "livrare prin social media", "vânzător neautorizat"],
      "payment_method": "transfer instant",
      "why_fraud": "EMAGIC și presa au relatat cazuri de bilete false și ticket scalping care au lăsat oameni la poartă.",
      "source": "https://stirileprotv.ro/stiri/actualitate/reactia-organizatorului-concertului-metallica-de-la-bucuresti-dupa-incidentele-cu-bilete-false-raportate.html"
    },

    {
      "text": "Am plătit produsul prin OLX. Pentru a primi banii, intră pe acest link și completează datele cardului.",
      "family": "OP-06",
      "expected_signals": ["link fals cu logo OLX", "cerere date card pentru încasare", "off-platform"],
      "payment_method": "card pe link",
      "why_fraud": "Schema clasică de pe marketplace cere vânzătorului datele cardului și codul 3D Secure sub pretextul încasării.",
      "source": "https://www.bcr.ro/ro/persoane-fizice/informatii-utile/securitate/cumparatori-rapizi-pe-olx"
    },
    {
      "text": "Curierul e pregătit. Confirmă plata prin Livrare OLX accesând pagina de mai jos și introdu datele cardului.",
      "family": "OP-06",
      "expected_signals": ["curier folosit ca pretext", "pagini clonă", "cerere CVV/3D Secure"],
      "payment_method": "card pe link",
      "why_fraud": "OLX avertizează explicit că linkurile false pentru «articole plătite» cer date de card și soldul contului.",
      "source": "https://ajutor.olx.ro/olxhelpro/s/article/ai-grija-la-linkurile-false-pentru-articole-platite-recunoaste-semnalele-unui-atac-de-phishing-V7"
    },
    {
      "text": "Hai pe WhatsApp să rezolvăm rapid. Îți trimit acolo linkul de încasare, e mai simplu decât în chat-ul platformei.",
      "family": "OP-06",
      "expected_signals": ["mutare pe WhatsApp", "ocolirea chatului platformei", "link de plată extern"],
      "payment_method": "card pe link",
      "why_fraud": "BCR descrie exact mutarea discuției pe mesagerie externă ca etapă standard a fraudei.",
      "source": "https://www.bcr.ro/ro/persoane-fizice/informatii-utile/securitate/cumparatori-rapizi-pe-olx"
    },

    {
      "text": "Trimite o fotografie clară a buletinului față-verso ca să-ți pot confirma rezervarea/contractul și să-ți emit documentele.",
      "family": "OP-07",
      "expected_signals": ["cerere copie CI prematură", "furt de identitate", "documente reale folosite fraudulos"],
      "payment_method": "fără plată inițială",
      "why_fraud": "Investigațiile și cazurile din 2024–2025 arată că datele din CI au fost folosite pentru credite online și alte falsuri documentare.",
      "source": "https://snoop.ro/fenomenul-creditelor-false-cu-buletine-furate-pentru-credite-la-ifn-uri-sub-ochii-autoritatilor/"
    },
    {
      "text": "Ai o tentativă de credit pe numele tău. Ca să o blocăm, trebuie să iei tu un împrumut de verificare și să-l depui la ATM crypto.",
      "family": "OP-07",
      "expected_signals": ["apel de panică", "credit de verificare", "ATM crypto", "engineering social"],
      "payment_method": "crypto",
      "why_fraud": "Cazul din Cluj a fost exact un astfel de scenariu: victimă speriată, credit real făcut de ea, bani depuși în ATM crypto.",
      "source": "https://observatornews.ro/eveniment/cum-a-fost-pacalita-o-clujeanca-sa-faca-un-credit-de-100000-de-lei-dupa-un-simplu-apel-desigur-suma-maxima-616191.html"
    },
    {
      "text": "Ai fost aprobat rapid online. Confirmă datele și continuăm. Mai târziu victima află că există deja un credit pe numele ei.",
      "family": "OP-07",
      "expected_signals": ["credit online deschis fără cunoștința victimei", "verificare slabă a identității", "abuz de date personale"],
      "payment_method": "credit online",
      "why_fraud": "Observator și Snoop au documentat victime care s-au trezit cu credite ori rate făcute cu identitatea lor.",
      "source": "https://observatornews.ro/eveniment/cum-sa-trezit-untanar-cu-un-credit-online-deschis-pe-numele-lui-de-carehabar-nu-avea-a-pierdut-15000-de-lei-617987.html"
    },
    {
      "text": "Trimite codul și datele de verificare, altfel dosarul de credit pe numele tău nu poate fi stopat.",
      "family": "OP-07",
      "expected_signals": ["coduri cerute sub pretext de securitate", "panică", "preluare control identitate financiară"],
      "payment_method": "n/a",
      "why_fraud": "Atacatorii folosesc frica de furt de identitate pentru a împinge victima să autorizeze singură operațiuni financiare.",
      "source": "https://observatornews.ro/eveniment/actrita-din-cluj-povesteste-cum-a-fost-pacalita-sa-faca-un-credit-de-100000-de-lei-acum-va-plati-rate-lunar-616232.html"
    }
  ]
}
```

## Refresh pentru KB-ul legal

Pe partea legală, ce e stabil și confirmabil în surse oficiale este următorul: articolele de cod penal cerute rămân în vigoare cu pedepsele de bază indicate mai jos; RO e-Factura a fost modificată prin OUG 89/2025 și apoi ajustată pentru persoanele care se identifică fiscal prin CNP prin Ordonanța nr. 6/2026; OUG 34/2014 a rămas baza dreptului de retragere, dar a fost și ea modificată prin OUG 18/2026; Legea 363/2007 rămâne în vigoare, însă este modificată în 2026 de aceeași OUG 18/2026; pentru „OUG 22/2026” privind plafonările nu am reușit să localizez, în această sesiune, textul oficial pe Portalul Legislativ, iar forma oficială consolidată a OUG 67/2023 pe care am putut-o recupera indică aplicarea până la 31 martie 2026. citeturn40search0turn40search1turn13search0turn14search0turn14search3turn15view0turn13search8turn11view0turn11view1turn12search6turn12search4turn12search1turn16search0turn17view1turn17view2turn17view3turn41search2turn9view1turn9view2

```json
[
  {
    "item": "art_244",
    "status": "confirmat",
    "current_text": "Art. 244 Cod penal: înșelăciunea se pedepsește cu închisoare de la 6 luni la 3 ani; dacă este săvârșită prin nume/calități mincinoase ori alte mijloace frauduloase, pedeapsa este de la 1 la 5 ani.",
    "source": "https://legislatie.just.ro/Public/DetaliiDocument/109855"
  },
  {
    "item": "art_320",
    "status": "confirmat",
    "current_text": "Art. 320 Cod penal: falsul material în înscrisuri oficiale rămâne în vigoare; alin. (1) prevede pedeapsa de la 6 luni la 3 ani pentru falsificarea unui înscris oficial de natură să producă consecințe juridice.",
    "source": "https://legislatie.just.ro/Public/DetaliiDocumentAfis/304554"
  },
  {
    "item": "art_321",
    "status": "confirmat",
    "current_text": "Art. 321 Cod penal: falsul intelectual se pedepsește cu închisoare de la 1 la 5 ani; tentativa se pedepsește.",
    "source": "https://legislatie.just.ro/Public/DetaliiDocument/109855"
  },
  {
    "item": "art_322",
    "status": "confirmat",
    "current_text": "Art. 322 Cod penal: falsul în înscrisuri sub semnătură privată se pedepsește cu închisoare de la 6 luni la 3 ani sau cu amendă; tentativa se pedepsește.",
    "source": "https://legislatie.just.ro/Public/DetaliiDocumentAfis/304554"
  },
  {
    "item": "art_323",
    "status": "confirmat",
    "current_text": "Art. 323 Cod penal: uzul de fals se pedepsește, când înscrisul este oficial, cu închisoare de la 3 luni la 3 ani sau amendă, iar când înscrisul este sub semnătură privată, cu închisoare de la 3 luni la 2 ani sau amendă.",
    "source": "https://legislatie.just.ro/Public/DetaliiDocument/109855"
  },
  {
    "item": "art_327",
    "status": "confirmat",
    "current_text": "Art. 327 Cod penal: falsul privind identitatea se pedepsește în forma-tip cu închisoare de la 6 luni la 3 ani; când se folosește identitatea reală a altei persoane, pedeapsa este de la 1 la 5 ani; încredințarea actului spre folosire fără drept se pedepsește cu 3 luni la 2 ani sau amendă.",
    "source": "https://legislatie.just.ro/Public/DetaliiDocumentAfis/232457"
  },
  {
    "item": "art_311",
    "status": "confirmat",
    "current_text": "Art. 311 Cod penal: falsificarea de titluri de credit sau instrumente de plată se pedepsește cu închisoare de la 2 la 7 ani; dacă privește un instrument de plată electronică, pedeapsa este de la 3 la 10 ani; tentativa se pedepsește.",
    "source": "https://legislatie.just.ro/Public/DetaliiDocumentAfis/143710"
  },
  {
    "item": "efactura_2026",
    "status": "modificat",
    "current_text": "În 2026, RO e-Factura rămâne obligatorie pentru relațiile deja obligatorii B2G și B2B; OUG 89/2025 extinde și clarifică regimul, inclusiv pentru persoane impozabile nestabilite, dar înregistrate în scopuri de TVA în România, și fixează termenul de transmitere la 5 zile lucrătoare. Pentru furnizorii/prestatorii care se identifică fiscal prin CNP, Ordonanța nr. 6/2026 amână obligația până la 1 iunie 2026.",
    "source": "https://legislatie.just.ro/Public/DetaliiDocument/307679 ; https://legislatie.just.ro/Public/DetaliiDocumentAfis/306803 ; https://static.anaf.ro/static/10/Anaf/AsistentaContribuabili_r/Ghid_RO_eFactura.pdf"
  },
  {
    "item": "oug_34_2014_retragere",
    "status": "modificat",
    "current_text": "OUG 34/2014 păstrează regula de bază a dreptului de retragere de 14 zile pentru contractele la distanță și în afara spațiilor comerciale. Excepțiile relevante rămân pentru bunuri personalizate și pentru servicii de cazare non-rezidențială, transport de mărfuri, închiriere de mașini, catering și activități de agrement atunci când contractul prevede o dată sau o perioadă specifică. În 2026 actul este modificat prin OUG 18/2026, dar nu abrogat.",
    "source": "https://legislatie.just.ro/Public/FormaPrintabila/00000G2ACJO3VWFUC362CAMC00FVCJCM ; https://legislatie.just.ro/Public/DetaliiDocument/308474"
  },
  {
    "item": "oug_22_2026_plafonare",
    "status": "incert",
    "current_text": "În această sesiune nu am putut confirma din text oficial recuperat pe Portalul Legislativ conținutul exact al «OUG 22/2026». Forma oficială consolidată a OUG 67/2023 pe care am recuperat-o indică aplicarea măsurii până la 31 martie 2026 inclusiv. Dacă vrei un card KB strict oficialist, marchează acest punct ca incert până la verificarea directă în Monitorul Oficial/e-monitor a actului 22/2026.",
    "source": "https://legislatie.just.ro/Public/FormaPrintabila/00000G23TQOQXI7KE1J2BSQYQQ9YDXZK ; https://monitoruloficial.ro/e-monitor/"
  },
  {
    "item": "legea_363_2007",
    "status": "modificat",
    "current_text": "Legea 363/2007 privind practicile comerciale incorecte rămâne cadrul de bază pentru practici comerciale înșelătoare/agresive, dar în 2026 este modificată și completată prin OUG 18/2026.",
    "source": "https://legislatie.just.ro/Public/DetaliiDocument/308474"
  }
]
```

## Miezul de implementare și matricea agregată de semnale

Dacă vrei un singur gate robust înainte de plată, regula cea mai bună este: documentul trece doar dacă identitatea emitentului este coerentă intern, entitatea există și este activă în sursa oficială relevantă, iar promisiunea comercială nu este contrazisă de metoda de plată sau de urgența artificială. În practică, verificările live merită păstrate pentru ANAF, registrele ASF/BNR și serviciile punctuale RAR/ANCPI; snapshoturile merită pentru ONRC și SITUR. Fără sursă oficială, verdictul trebuie degradat la „suspect” sau „periculos în combinație”, nu „confirmat”. citeturn39search0turn39search4turn8search0turn8search1turn18search5turn5search2turn35search1turn36search2

```json
{
  "matrice_agregata_semnale": [
    {
      "signal": "CUI lipsă sau neverificabil",
      "unde_apare": "factura/contract/oferta",
      "sursa_oficiala": "ANAF PlatitorTvaRest v9 + ONRC data.gov.ro / myportal.onrc.ro",
      "power": "puternic",
      "verdict": "periculos"
    },
    {
      "signal": "Firmă inactivă, radiată sau care nu bate cu denumirea din document",
      "unde_apare": "factura/contract",
      "sursa_oficiala": "ANAF + ONRC",
      "power": "puternic",
      "verdict": "periculos"
    },
    {
      "signal": "Agenție de turism care nu apare în lista licențiată sau apare în lista radiată/retrasă",
      "unde_apare": "oferta/contract/factura",
      "sursa_oficiala": "SITUR OpenData",
      "power": "puternic",
      "verdict": "periculos"
    },
    {
      "signal": "Broker/platformă de investiții absent(ă) din Registrul ASF",
      "unde_apare": "oferta/link/profil",
      "sursa_oficiala": "Registrul ASF + pagina ASF de entități neautorizate",
      "power": "puternic",
      "verdict": "periculos"
    },
    {
      "signal": "IFN / instituție de plată / entitate financiară invocată care nu apare în registrele BNR",
      "unde_apare": "contract/oferta/instructiuni plata",
      "sursa_oficiala": "BNR Registre și Liste",
      "power": "puternic",
      "verdict": "periculos"
    },
    {
      "signal": "Plată cerută într-un cont personal pentru o ofertă comercială pretinsă corporate",
      "unde_apare": "factura/instructiuni plata",
      "sursa_oficiala": "verificare indirectă ANAF/ONRC + lipsa coerenței documentare",
      "power": "mediu",
      "verdict": "suspect_to_periculos"
    },
    {
      "signal": "Link de plată trimis în chat/mesaj extern, nu în fluxul oficial al platformei",
      "unde_apare": "link/mesaj",
      "sursa_oficiala": "confirmare indirectă prin regulile oficiale ale platformei și alertele de securitate",
      "power": "puternic",
      "verdict": "periculos"
    },
    {
      "signal": "Vehicul fără Auto-Pass/RAR coerent sau cu presiune de avans înainte de verificarea VIN/CIV",
      "unde_apare": "oferta/contract",
      "sursa_oficiala": "RAR Auto-Pass + verificare ITP + CIV",
      "power": "puternic",
      "verdict": "periculos"
    },
    {
      "signal": "Pretins proprietar care nu poate livra extras CF / date cadastrale coerente",
      "unde_apare": "contract/oferta",
      "sursa_oficiala": "ANCPI extras CF / Geoportal",
      "power": "puternic",
      "verdict": "periculos"
    },
    {
      "signal": "Cerere de copie CI, selfie, OTP sau date bancare înainte ca entitatea să fie verificată",
      "unde_apare": "mesaj/oferta",
      "sursa_oficiala": "nu există registru care să legitimeze cererea; verificarea se face prin existența și calitatea entității în ANAF/ONRC/ASF/BNR",
      "power": "mediu",
      "verdict": "suspect_to_periculos"
    },
    {
      "signal": "Metodă de plată irevocabilă: crypto, ATM crypto, gift-card, QR obscur, transfer instant la persoană fizică",
      "unde_apare": "instructiuni plata",
      "sursa_oficiala": "confirmare indirectă prin verificarea neconcordanței dintre entitate și rail-ul de plată",
      "power": "puternic",
      "verdict": "periculos"
    }
  ]
}
```

## Ce merită reținut ca regulă de produs

Dacă motorul tău face un singur lucru bine, acela ar trebui să fie acesta: nu se lasă impresionat de PDF-uri frumoase, ștampile colorate și „doar azi”. Verifică dacă documentul e coerent, dacă entitatea există în sursa oficială corectă și dacă oferta are urme reale pe internet. Când una dintre cele trei lipsește, verdictul trebuie să se înrăutățească; când lipsesc toate trei și se mai cere și avans off-platform, verdictul nu mai este „suspect”, este „nu plăti”. citeturn34search4turn34search5turn21search0turn25search1turn30search0turn31search3