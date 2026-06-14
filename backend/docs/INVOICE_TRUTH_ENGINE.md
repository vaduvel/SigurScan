# InvoiceTruth — motor de factură pe piloni (un singur judecător)

Branch: `feature/invoice-truth-hardening`. Îmbunătățește motorul EXISTENT de
factură ca un set de PILONI de semnal care alimentează **un singur `verdict_gate`**
(simetric cu ruta ofertă/link). NU e un al doilea creier.

## Arhitectura
```
invoice_parser  (toate IBAN-urile + beneficiar)
   ├─ ANAF / issuer            ─┐
   ├─ IBAN / payment-destination ┤
   ├─ Coherence                 ┤→ invoice_evidence_gate_mapper → verdict_gate
   ├─ Fraud-signals             ┤        (fuziune, ca offer mapper)   (UNICUL creier)
   └─ Registru negativ IBAN    ─┘
```

## Piloni implementați (toți → verdict_gate)
| Pilon | Semnal | Efect verdict |
|---|---|---|
| **Parser** | toate IBAN-urile (RO+străine) + beneficiar/titular | alimentează ceilalți |
| **ANAF/issuer** | CUI există/activ, nume↔denumire | inactiv→malicious; lipsă→unknown |
| **Fraud-signals** | beneficiar persoană≠firmă; IBAN străin; „cont schimbat" (BEC); presiune | persoană≠firmă→**PERICULOS**; combo BEC→**PERICULOS**; străin/cont-schimbat→**SUSPECT** |
| **Registru negativ IBAN** | IBAN raportat anterior ca fraudă | →**PERICULOS** determinist (victima #2) |
| **Coherence** | math/TVA/date | incoerent→suspicious |
| **Whitelist (CUI+domeniu)** | impersonare brand pe domeniu/CUI | mismatch→**PERICULOS** |

Regula supremă păstrată: **CUI valid + IBAN valid = NEVERIFICAT, nu SIGUR.**

## Decizii (de ce NU am făcut anumite lucruri)
### Whitelist cu IBAN EXACT (PPC/Orange/utilități) — NU seed-at, intenționat
`match_brand` tratează **non-match de IBAN = impersonare** când `official_ibans` e
seed-at (vezi `test_energy_gas_official_iban_mismatch`). Pentru utilități/telecom
asta produce **fals-pozitiv pe facturi legitime**: brandurile au mai multe conturi
de încasare / încasează prin cod client (documentul intern, regula #4). Seed-ul de
IBAN e sigur DOAR pentru entități cu cont unic cunoscut (ex. ANAF=doar Trezorerie,
deja în cod). **De făcut DOAR cu lista completă de conturi per brand**, altfel strică
facturi bune. Valoarea whitelist-ului rămâne pe **CUI + domeniu** (deja funcționează).

### Channel provenance (intake: WhatsApp/email DKIM) — pilon următor
„Factura pe WhatsApp nu poate fi SIGUR" cere ca SAFE să depindă de canal oficial.
Motorul email (DKIM/DMARC) există; de cablat ca pilon în mapper cu grijă la edge-case
(brand-official prin WhatsApp nu trebuie să rămână SAFE). Nu introduce fals-DANGEROUS.

### Out-of-band coaching + VoP — Android / 2027
Coaching „citește numele beneficiarului în app-ul băncii" = UI Android. VoP gratuit
pe RON = abia iulie 2027. Ambele rămân în afara backend-ului acum.

## Feed-uri de alimentat (Codex/owner) ca să crească detecția
1. **Registru negativ IBAN** (`data/negative_iban_registry_v1.json`) — gol acum;
   de alimentat din alerte DNSC + rapoarte comunitare (Radar `/v1/report`). Fiecare
   IBAN adăugat = o țeapă prinsă determinist la următoarea victimă.
2. **vendor_memory** (IBAN per CUI, istoric) — „cont schimbat față de data trecută"
   = cel mai tare semnal pe BEC (research). Necesită store; pilon viitor.

## Plafonul onest
Un IBAN complice **românesc**, **fără** nume de titular scris, **fără** limbaj „cont
schimbat", **neraportat** încă → rămâne NEVERIFICAT la prima scanare. Nu există
semnal gratuit pentru asta (nu există sursă CUI→IBAN în RO). Acoperit de: registru
negativ (victima #2) + out-of-band (Android) + verdictul onest NEVERIFICAT.
