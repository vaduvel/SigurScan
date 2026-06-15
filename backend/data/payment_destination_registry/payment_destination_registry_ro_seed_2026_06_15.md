# Payment Destination Registry RO — seed 2026-06-15
Seed oficial pentru verificarea facturilor în SigurScan. Nu este listă completă națională și nu trebuie distribuit raw în Android.
## Reguli de folosire
- `IBAN valid MOD-97` singur = **UNVERIFIED**, nu SAFE.
- `SAFE` cere issuer match + destinație T0/T1/T2 + canal oficial/document oficial + fără cerere sensibilă.
- IBAN-urile brute stau **server-side only**; în client se trimite doar trust result + IBAN mascat.
- Intrările cu `X` sunt **pattern-uri mascate oficiale**, nu match exact; nu pot contribui la SAFE până la confirmare exactă.
## Rezumat

- Branduri/entități: 10
- IBAN-uri complete oficiale T1: 20
- IBAN-uri/pattern-uri mascate oficiale: 4
- Branduri cu canal oficial dar fără IBAN confirmat: 6

## PPC Energy / PPC Energie (`ppc_energy`)
- CUI: `needs_confirmation`
- Legal name: needs_confirmation
- Note: Legal name/CUI not asserted from the scraped payment page in this seed; verify separately before issuer-safe rules.

### Official payment channels
- `online_payment_no_auth` domain/confidence: `ppcenergy.ro` / `high` — Official page supports online payment without authentication by payment code/invoice ID/email.
- `myppc_app_or_portal` domain/confidence: `ppcenergy.ro` / `high` — 
- `bank_transfer` domain/confidence: `n/a` / `high` — 

### Payment destinations
- `RO45 BTRL RONI NCS0 0073 9101` — Banca Transilvania — T1_PUBLIC_OFFICIAL — energy_bill_payment — can_safe=True
- `RO68 RNCB 0285 0875 8894 0001` — BCR — T1_PUBLIC_OFFICIAL — energy_bill_payment — can_safe=True
- `RO22 CECE B318 44RO N254 9947` — CEC Bank — T1_PUBLIC_OFFICIAL — energy_bill_payment — can_safe=True
- `RO81 UGBI 0000 3620 0627 8RON` — Garanti Bank — T1_PUBLIC_OFFICIAL — energy_bill_payment — can_safe=True
- `RO84 INGB 0002 0000 0000 1111` — ING — T1_PUBLIC_OFFICIAL — energy_bill_payment — can_safe=True
- `RO96 WBAN 2511 0000 4150 3311` — Intesa Sanpaolo Bank — T1_PUBLIC_OFFICIAL — energy_bill_payment — can_safe=True
- `RO07 RZBR 0000 0600 0942 4399` — Raiffeisen Bank — T1_PUBLIC_OFFICIAL — energy_bill_payment — can_safe=True
- `RO19 BACX 0000 0002 1435 3000` — UniCredit Bank — T1_PUBLIC_OFFICIAL — energy_bill_payment — can_safe=True
- `RO86 BRDE 450S V476 5347 4500` — BRD — T1_PUBLIC_OFFICIAL — energy_bill_payment — can_safe=True

## E.ON Energie România (`eon_energie_romania`)
- CUI: `22043010`
- Legal name: E.ON Energie România S.A.
- Note: Source page caveat: Delgaz Grid/E.ON Asist Complet invoices may use different accounts printed on those invoices; do not apply E.ON energy bill whitelist to those entities.

### Official payment channels
- `myline_app_or_portal` domain/confidence: `eon.ro` / `high` — 
- `bank_transfer` domain/confidence: `n/a` / `high` — 

### Payment destinations
- `RO 53 BRDE 270S V239 0401 2700` — BRD — T1_PUBLIC_OFFICIAL — energy_gas_bill_payment — can_safe=True
- `RO 27 INGB 0015 0000 2818 8911` — ING Bank — T1_PUBLIC_OFFICIAL — energy_gas_bill_payment — can_safe=True
- `RO 58 BACX 0000 0037 0162 5003` — Unicredit Bank — T1_PUBLIC_OFFICIAL — energy_gas_bill_payment — can_safe=True
- `RO 88 CRCO X130 0130 0008 8260` — CreditCoop — T1_PUBLIC_OFFICIAL — energy_gas_bill_payment — can_safe=True
- `RO 86 RZBR 0000 0600 1235 5190` — Raiffeisen Bank — T1_PUBLIC_OFFICIAL — energy_gas_bill_payment — can_safe=True
- `RO14 TREZ 4765 069X XX00 7593` — Trezoreria Târgu Mureș — MASKED/PATTERN ONLY — can_safe=False

## APAVITAL Iași (`apavital_iasi`)
- CUI: `needs_confirmation`
- Legal name: APAVITAL S.A.
- Note: Source tells transfer should include user name, client code, invoice number and date.

### Official payment channels
- `online_payment_website` domain/confidence: `apavital.ro` / `high` — 
- `ghiseul_ro` domain/confidence: `ghiseul.ro` / `high` — 
- `bank_transfer` domain/confidence: `n/a` / `high` — 

### Payment destinations
- `RO37BRDE240SV47757172400` — BRD Iași — T1_PUBLIC_OFFICIAL — water_bill_payment — can_safe=True
- `RO37BRDE240SV08267502400` — BRD Iași Anastasie Panu — T1_PUBLIC_OFFICIAL — water_bill_payment — can_safe=True
- `RO47RZBR0000060003107233` — Raiffeisen Bank S.A. Agenția Iași — T1_PUBLIC_OFFICIAL — water_bill_payment — can_safe=True
- `RO56BTRL02401202E61068XX` — Banca Transilvania S.A. — MASKED/PATTERN ONLY — can_safe=False
- `RO21RNCB0175012554420001` — BCR Iași — T1_PUBLIC_OFFICIAL — water_bill_payment — can_safe=True
- `RO17TREZ4065069XXX002179` — Trezoreria Iași — MASKED/PATTERN ONLY — can_safe=False

## Compania Apa Brașov (`compania_apa_brasov`)
- CUI: `RO1096128`
- Legal name: Compania Apa Brașov
- Note: Official page lists company banking details and CUI.

### Official payment channels
- `bank_transfer` domain/confidence: `n/a` / `high` — 

### Payment destinations
- `RO78BACX0000000642579002` — Unicredit Tiriac Bank SA — T1_PUBLIC_OFFICIAL — water_bill_payment — can_safe=True
- `RO81BRDE080SV05660200800` — BRD Groupe Societe Generale — T1_PUBLIC_OFFICIAL — water_bill_payment — can_safe=True
- `RO63TREZ1315069XXX000650` — Trezorerie — MASKED/PATTERN ONLY — can_safe=False

## Hidroelectrica (`hidroelectrica`)
- CUI: `needs_confirmation`
- Legal name: needs_confirmation
- Note: No official IBAN found in this pass. Do not add IBAN until public official or partner-signed source is available.

### Official payment channels
- `portal_no_auth_invoice_contract_code` domain/confidence: `hidroelectrica.ro` / `high` — Official homepage says invoices can be paid directly from Portal without account/authentication using invoice number and contract code, with card/Google Pay/Apple Pay.

### Payment destinations
- No official IBAN confirmed in this pass.

## ENGIE România (`engie_romania`)
- CUI: `needs_confirmation`
- Legal name: needs_confirmation
- Note: No official IBAN found in this pass.

### Official payment channels
- `online_payment` domain/confidence: `engie.ro` / `high` — Official online payment form uses client code, invoice number, email and amount.
- `myengie_app_or_portal` domain/confidence: `engie.ro` / `high` — 

### Payment destinations
- No official IBAN confirmed in this pass.

## Electrica Furnizare (`electrica_furnizare`)
- CUI: `needs_confirmation`
- Legal name: Electrica Furnizare S.A.
- Note: Official site warns about phishing emails urging payment via insecure link; no official IBAN found in this pass.

### Official payment channels
- `myelectrica_app_or_portal` domain/confidence: `electricafurnizare.ro` / `high` — 
- `online_payment_or_partners` domain/confidence: `electricafurnizare.ro` / `high` — 

### Payment destinations
- No official IBAN confirmed in this pass.

## DIGI România (`digi_romania`)
- CUI: `needs_confirmation`
- Legal name: needs_confirmation
- Note: No official IBAN found in this pass.

### Official payment channels
- `online_payment` domain/confidence: `digi.ro` / `high` — Official site/payment modal references online bill payment and payment from invoice email.

### Payment destinations
- No official IBAN confirmed in this pass.

## Orange România (`orange_romania`)
- CUI: `needs_confirmation`
- Legal name: needs_confirmation
- Note: No official IBAN found in this pass.

### Official payment channels
- `my_orange_app_or_portal` domain/confidence: `orange.ro` / `high` — 
- `online_payment` domain/confidence: `orange.ro` / `high` — 

### Payment destinations
- No official IBAN confirmed in this pass.

## Apa Nova București (`apa_nova_bucuresti`)
- CUI: `RO12276949`
- Legal name: Apa Nova București S.A.
- Note: No official IBAN found in this pass; source confirms company CUI and online/app payment.

### Official payment channels
- `online_payment` domain/confidence: `apanovabucuresti.ro` / `high` — 
- `app_or_account` domain/confidence: `apanovabucuresti.ro` / `high` — 

### Payment destinations
- No official IBAN confirmed in this pass.
