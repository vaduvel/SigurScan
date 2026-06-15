# Invoice IBAN Research

## Product Decision

Frauda cu facturi si schimbare de IBAN este tratata ca pilon de evidenta, nu ca
verdict separat. Verdictul ramane in `verdict_gate`.

Reguli active:

- IBAN raportat cu provenienta verificata: semnal hard prin `negative_iban_registry`.
- Beneficiar persoana fizica pe factura de firma: semnal hard de destinatie.
- IBAN strain pe factura RO: semnal suspect; devine periculos in combinatie cu
  limbaj de cont schimbat sau alte semnale.
- Istoric vendor: daca aceeasi firma/CUI a avut anterior un IBAN curat, un IBAN
  nou este semnal BEC si nu se memoreaza automat.
- Canal neoficial, precum WhatsApp/SMS, blocheaza SAFE pentru facturi aparent
  oficiale, dar nu creeaza DANGEROUS singur.

## False Positive Guard

Sursele publice gasite descriu tiparul de frauda, dar nu ofera o lista oficiala
de IBAN-uri frauduloase. De aceea seed-urile fara sursa per-IBAN sunt pastrate in
`quarantine_review` si nu influenteaza verdictul.

Un IBAN intra in `reported_ibans` activ doar daca are:

- `status` verificat;
- `confidence` ridicat;
- `source_kind`;
- `source_url`, `source_ref` sau `case_id`.

## Positive Payment Destination Registry

Seed-ul `payment_destination_registry_ro_seed_2026_06_15` este registry pozitiv,
nu blacklist. El contine destinatii publice oficiale pentru furnizori unde sursa
a fost gasita pe pagina oficiala.

Regula de produs:

- Match T1/T0/T2 poate sustine SAFE doar impreuna cu issuer/canal aliniat.
- IBAN valid dar necunoscut pentru un brand care are registry activ nu poate
  produce SAFE; ramane cel mult SUSPECT daca se cere plata.
- IBAN oficial pentru alt brand este mismatch de destinatie si poate urca la
  DANGEROUS.
- Backend-ul nu expune IBAN-urile brute catre Android; API-ul returneaza numai
  trust result si varianta mascata.

## Sources

- ING Romania: `https://ing.ro/inbusiness-blog-antreprenori/business-abc/Cum-ne-ferim`
- Asociatia Romana a Bancilor: `https://www.arb.ro/arb-talks-alin-becheanu-arb-atunci-cand-vrem-sa-incasam-sume-de-bani-furnizam-doar-contul-iban/`
- Bancherul.ro: `https://www.bancherul.ro/schimbarea-contului-iban-poate-fi-o-inselaciune/`
