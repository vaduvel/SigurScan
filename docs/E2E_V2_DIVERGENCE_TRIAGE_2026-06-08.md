# E2E v2 Divergence Triage - 2026-06-08

Scope: `e2e_fixtures/sigurscan_e2e_fixtures_v2_realistic`, rulat dupa fixurile de provider normalization si semantic atlas preservation.

Comanda:

```bash
python3 backend/eval/e2e_fixture_runner.py \
  --pack e2e_fixtures/sigurscan_e2e_fixtures_v2_realistic \
  --output /tmp/sigurscan_e2e_v2_report_after_semantic_preserve.json \
  --allow-false-positive-guards \
  --allow-false-negatives \
  --max-failures 999
```

## Rezumat

| Metric | Valoare |
| --- | ---: |
| Total cazuri | 406 |
| Passed | 334 |
| Failed/divergente | 72 |
| Pass rate | 82.27% |
| False negatives | 0 |
| False-positive guard failures | 0 |
| Danger recall | 1.0 |
| Danger precision | 0.7188 |

Toate cele 72 divergente sunt `expected SUSPECT -> actual PERICULOS`.

Nu exista:

- cazuri legitime ridicate la `PERICULOS`;
- cazuri scam ratate ca `SIGUR`;
- false-positive guard fail.

## Distributie divergente

| Expected decision/status | Actual | Cazuri |
| --- | --- | ---: |
| `NO_REPLY / SUSPECT` | `PERICULOS` | 41 |
| `NO_ENTER_DATA / SUSPECT` | `PERICULOS` | 31 |

## Familii afectate

| Familie | Cazuri | Interpretare |
| --- | ---: | --- |
| `F13` telefon stricat / accident / nepot | 30 | Escalare prin `semantic_high_value_request`; acceptata cand cere bani/transfer pe reply/WhatsApp/telefon. |
| `F01` ANAF refund/SPV phishing | 12 | Escalare prin provider malicious; acceptata. |
| `F09` BNR / Politie / cont sigur | 11 | Escalare prin `sensitive_wrong_channel`; acceptata cand cere transfer/crypto/card/remote. |
| `MINOR_005_SOCIAL_PAGE_OWNERSHIP_PHISH` | 8 | Escalare prin provider malicious; acceptata. |
| `F05` marketplace card/payment | 6 | Escalare prin identity spoof; acceptata daca domeniul/identitatea sunt neoficiale si cere date/plata. |
| `F15` job/task/depunere | 2 | Escalare prin provider malicious; acceptata. |
| `F03` Posta/colet/taxa | 2 | Escalare prin provider malicious; acceptata. |
| `MINOR_001_PARKING_QR_QUISHING` | 1 | Escalare prin provider malicious; acceptata. |

## Motive gate

| Gate reason | Cazuri | Decizie triaj |
| --- | ---: | --- |
| `semantic_high_value_request` | 30 | Acceptat pentru familii high-risk + bani/transfer pe canal gresit. |
| `provider_malicious` | 25 | Acceptat: hard evidence de provider. |
| `sensitive_wrong_channel` | 11 | Acceptat: hard-sensitive pe canal gresit. |
| `identity_spoof` | 6 | Acceptat daca identity este `lookalike/unrelated` si exista intent sensibil. |

## Observatie produs

Aceste divergente nu sunt un motiv sa slabim gate-ul. Ele indica faptul ca fixture-urile v2 au expected-uri mai nuantate (`NO_REPLY`, `NO_ENTER_DATA`) decat produsul final cu trei etichete (`SIGUR`, `SUSPECT`, `PERICULOS`).

Pentru user non-tehnic, cazurile de mai sus pot fi `PERICULOS` daca se incadreaza in contractul v1:

- provider malicious;
- identity spoof + intent sensibil;
- hard-sensitive wrong-channel;
- high-risk semantic family + transfer/bani pe canal gresit.

## Ce NU facem

- Nu schimbam automat toate cele 72 expected-uri fara review.
- Nu folosim acest set pentru tuning la infinit.
- Nu cream un set nou inainte sa inchidem acest triaj.

## Urmatorul pas recomandat

1. Actualizam fixture-urile numai pentru categoriile acceptate de mai sus.
2. Pastram o lista separata de cazuri borderline daca apare vreun caz fara hard evidence sau fara cerere concreta.
3. Dupa rebaseline, construim doua holdout-uri inghetate:
   - scam RO proaspat, orb, nefolosit la tuning;
   - corpus benign real, redactat PII, pentru masurarea false positives/alert fatigue.
