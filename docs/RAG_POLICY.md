# SigurScan RAG Policy

Ultima actualizare: 2026-06-02

Scop: definim rolul AI/RAG in produs. RAG ajuta la explicatie si comparatie, dar nu decide verdictul.

## Regula centrala

RAG-ul este consultant, nu judecator.

Judecatorul este:

- Evidence Gate;
- Decision Matrix;
- Corpus Tests.

## Ce are voie sa faca RAG

RAG poate:

- compara mesajul cu cazuri din corpus;
- genera explicatii simple pentru user;
- identifica posibile brand claims;
- sugera ce dovezi lipsesc;
- rezuma de ce o pagina pare similara cu un scam cunoscut;
- genera motive user-facing din dovezi deja confirmate;
- crea raport tehnic pentru suport intern.

Observatie de implementare:

- hinturile statice din knowledge pack despre claim-uri/oferta nu sunt RAG; ele sunt context de corpus si intra ca semnale consultative, nu ca output AI.

## Ce nu are voie sa faca RAG

RAG nu poate:

- seta `DANGEROUS`, `SUSPICIOUS`, `LOW_RISK` sau `UNKNOWN` singur;
- contrazice Web Risk/urlscan/DNSC fara dovezi;
- inventa final URL;
- inventa domenii oficiale;
- marca marketing normal ca scam fara dovezi;
- decide ca o oferta este reala doar pentru ca suna plauzibil;
- decide ca o oferta este falsa doar pentru ca nu a gasit-o in corpus.

## Input permis in RAG

RAG primeste doar date minim necesare:

- text vizibil sanitizat;
- brand claim;
- domeniu final;
- evidence summary;
- corpus snippets relevante;
- verdict determinist deja calculat sau starea `UNKNOWN`.

Nu trimite catre RAG:

- email complet cu PII daca nu este necesar;
- tokenuri, session IDs, reset codes;
- date card/OTP/parole;
- atasamente brute fara redaction.

## Output permis din RAG

Output acceptat:

- `explanation_short`
- `explanation_detailed`
- `similar_cases`
- `missing_evidence`
- `recommended_user_copy`

Output interzis:

- verdict final fara Decision Engine;
- scor procentual nou;
- domeniu oficial nou fara registry update;
- afirmatii absolute de siguranta.

## Copy rules

Foloseste:

- `Nu am gasit semnale cunoscute de risc`
- `Nu pot verifica suficient`
- `Verifica direct pe site-ul oficial`
- `Preview-ul securizat arata unde duce linkul fara sa intri tu pe site`

Evita:

- `100% sigur`
- `garantat legitim`
- `oferta este reala`
- `detectam toate scamurile`
- `oficial DNSC/Politie/ANAF`, fara parteneriat.
