# SigurScan Romania Knowledge Layer Research v1

Creat: 2026-06-03

Acest pack conține knowledge layer pentru SigurScan / NuDaClick România 2025–2026:
- OfficialRegistry updates
- BrandWarnings / never_ask_for
- Romania scam scenarios
- ClaimVerifier targets
- Corpus signal mapping
- False positive guards

Fișiere runtime:
- `romania_knowledge_layer_compact.json` — JSON compact pentru registry, warnings, corpus semantic și claim targets.

Fișiere suport:
- `romania_knowledge_layer.json` — JSON complet curățat de oracole de verdict.
- `source_index.json` — index surse cu URL, data publicării, data accesării.

Important:
- Corpus/RAG nu decide verdictul singur.
- Testele stricte de verdict stau în backend ca Evidence Bundle fixtures, nu în asset-ul runtime Android.
- Reddit/Facebook/community sunt noisy și nu hard evidence.
- `Sigur` nu înseamnă 100% safe.
