# 🔍 Audit de producție — handoff pentru Codex (2026-06-15)

> Audit cap-coadă (read-only) pe `main`: **26 fișiere Kotlin (14.956 l)** + **58 fișiere Python (26.390 l)**.
> Baseline la momentul auditului: backend **828 teste PASS**, Android Lint **0 erori / 64 warning**, build verde.
> **Nimic nu a fost modificat** — doar raportat. Fix-urile de mai jos sunt propuse, nu aplicate.
>
> Concluzie scurtă: codul e **production-grade, foarte defensiv**. Singurul lucru sever e lanțul **P0 backend** de mai jos (atribuit deja ție mai demult — confirm că `main` încă îl are). Restul e i18n + robustețe + mentenanță.

---

## 🔴 P0 — lanț de evadare a scanerului (backend)

**Un atacator poate crafta un URL care blochează permanent scanarea acelui input.**
Trei verigi, toate confirmate prezente în `main`:

### 1. `_canonical_url_variants` — `ValueError` neprins pe port malformat
`backend/services/url_reputation.py:571-586`
```python
def _canonical_url_variants(url: str) -> set[str]:
    parsed = urlparse(url.strip())
    ...
    if parsed.port:          # ← linia 577: .port aruncă ValueError pe port invalid
        netloc = f"{hostname}:{parsed.port}"
```
`urlparse("http://evil.com:999999/").port` și `urlparse("http://h:abc").port` aruncă
`ValueError: Port out of range / could not be cast`. Funcția nu are try/except.

**Fix propus:**
```python
def _safe_port(parsed) -> int | None:
    try:
        return parsed.port
    except ValueError:
        return None
...
    port = _safe_port(parsed)
    if port:
        netloc = f"{hostname}:{port}"
```

### 2. `_gather_external_intel_safe` — prinde DOAR `TypeError`
`backend/main.py:~1885-1895`
```python
    except TypeError:
        # Compatibility for tests that monkeypatch the helper ...
        return _gather_external_intel(resolved_urls)
```
Numele zice „safe", dar orice altă excepție (inclusiv `ValueError` de la #1, erori de rețea,
`KeyError`) trece neprinsă. Pentru un wrapper „safe" pe calea de scan, asta e exact ce nu vrem.

**Fix propus:** păstrează compat-ul pe `TypeError`, dar prinde restul și degradează grațios
(întoarce intel gol → scanul continuă cu pilonii care merg):
```python
    except TypeError:
        return _gather_external_intel(resolved_urls)
    except Exception:
        logger.exception("external intel gathering failed; degrading to empty")
        return {}
```

### 3. `_refresh_orchestrated_job` + GET endpoint — fără guard → 500-loop permanent
`backend/main.py:7310` (`_refresh_orchestrated_job`, fără try/except top-level) +
`backend/main.py:7670` (`get_orchestrated_scan`):
```python
    async with lock:
        job = _load_orchestrated_job(scan_id)
        ...
        job = await _refresh_orchestrated_job(job, request)   # ← dacă aruncă aici...
        response = _orchestrated_status_payload(job)
        job = _persist_orchestrated_job(job)                  # ← ...asta NU se mai atinge
        return response
```
Dacă `_refresh_orchestrated_job` aruncă (lanțul #1→#2 la stage „resolved", `main.py:7340`):
- nu e prins → FastAPI întoarce **500** (nu crash de proces, dar);
- `_persist_orchestrated_job` nu rulează → job-ul rămâne în aceeași stare →
  **fiecare poll re-rulează aceeași excepție** → scanarea e **blocată definitiv în 500**.

→ Impact real: un scammer pune un port malformat în URL și **scanul nu se mai termină niciodată**.
Pentru un anti-țeapă = **evaziune** (user-ul nu primește verdict).

**Fix propus:** #1+#2 rezolvă cauza. Suplimentar, defense-in-depth în endpoint —
persistă/marchează job-ul ca degradat chiar și pe eroare de refresh:
```python
        try:
            job = await _refresh_orchestrated_job(job, request)
        except Exception:
            logger.exception("orchestrated refresh failed for %s", scan_id)
            job = _mark_required_pillars_timeout(job)   # sau un terminal degradat existent
        response = _orchestrated_status_payload(job)
        job = _persist_orchestrated_job(job)
        return response
```

**Test de regresie sugerat:** un test care POST-ează un URL cu port `:999999` și verifică
că GET-ul ulterior întoarce un verdict terminal degradat (nu 500, nu „scanning" la infinit).

---

## 🟠 P1 — matching de securitate stricat de locale (Android, „Turkish-i")

`Locale.getDefault()` folosit pe **hostname / identificatori** — pe device-uri cu locale
turcă/azeră, `"I".lowercase()` → `"ı"` (i fără punct), deci comparațiile pică.

| Loc | Problemă |
|---|---|
| `app/.../ScannerViewModel.kt:1400` | `host.lowercase(Locale.getDefault())` înainte de `isOfficialHost` → pe locale TR, „DIGI.ro" → „dıgi.ro" ≠ „digi.ro" → **ratează host-ul oficial** (poate marca un site legitim ca suspect). |
| `app/.../PrimaryUrlPicker.kt:67` și `:105` | matching alias-uri de brand cu `Locale.getDefault()` → poate rata/greși detecția de brand. |

**Fix:** `Locale.ROOT` pentru orice lowercase/uppercase pe hostname/identificatori/IBAN/CUI
(nu depind de limbă). Notă: `BackendVerdictMapper` folosește `.uppercase()` fără Locale pe
„SAFE/SUSPECT/DANGEROUS" — întâmplător **imun** (cuvintele n-au „i"), dar de pus `Locale.ROOT`
defensiv dacă se schimbă etichetele.

---

## 🟡 P2 — robustețe (impact mic, dar real)

- **`!!` ×6 dublu-read `mutableStateOf`** — `MainActivity.kt:746, 751, 755, 786, 1138, 1151`.
  Pattern `if (vm.x != null) … vm.x!!` — Compose nu garantează aceeași valoare la a doua citire
  dacă un coroutine schimbă starea între ele → NPE rar. *Fix:* capturează local (`val x = vm.x; if (x != null) …`).
- **`DefaultLocale` ×7** — `MainActivity.kt:1996, 4088, 4100, 4101, 4124, 4140, 4181`.
  `"%.2f %s".format(...)` fără Locale → separator zecimal inconsistent între device-uri
  (virgulă vs punct pe sume de factură). *Fix:* `String.format(Locale.getDefault(), …)` explicit.
- **OkHttp `.execute()` sincron** în funcții non-suspend — `ScannerViewModel.kt:1875, 1900, 3276`.
  De confirmat că toți apelanții sunt pe `Dispatchers.IO` (par a fi — codul folosește IO
  consistent). Dacă vreunul ajunge pe Main → **ANR**.
- **`EvidenceGate` cascadă** — `EvidenceGate.kt:320-321`: `continueWithCaution` e evaluat
  **înaintea** lui `verifyOfficial` (inversiune de severitate). Mitigat puternic de guard-urile
  din `continueWithCaution` (737-760, exclude toate codurile de pericol), deci practic teoretic —
  **de confirmat că ordinea e intenționată**, altfel un semnal VERIFY_OFFICIAL semantic (RAG)
  peste o destinație curată ar putea fi coborât la CONTINUE_WITH_CAUTION.
- **`onScanClick`** (`ScannerViewModel.kt:1354`) — fără guard `if (loading) return`; dublu-scan
  dacă e apelat programatic (UI-ul atenuează prin `enabled = !loading`).

---

## ⚪ P3 — mentenanță (din Lint, 0 impact funcțional)
- 28× dependențe vechi (`GradleDependency` / `NewerVersionAvailable` / `UseTomlInstead`).
- 14× `UseKtx`, 7× resurse nefolosite, 1× `OldTargetApi`, 1× `RedundantLabel`.
- 4× `SuspiciousIndentation` (`ScannerViewModel.kt:403, 1570, 1573, 1874`) — **verificat: doar
  tab/spațiu amestecat, NU bug de logică.**

---

## ✅ Mapat și CURAT (apărare excelentă — de păstrat așa)
| Modul / zonă | Rezultat |
|---|---|
| Parsere URL/HTML/PDF/Email | bounds-check + `runCatching` peste tot — nu crapă pe input ostil |
| Parsing JSON backend (Android) | **0 cast-uri nesigure** — tot `as?` + `filterIsInstance` + `mapNotNull` |
| `EvidenceGate` (1057 l) | cascadă „pericol întâi"; `continueWithCaution` cu 15 guard-uri |
| Polling orchestrat (Android) | mărginit de deadline + status `Locale.US` — fără buclă infinită |
| IO fișiere / OCR | `.use{}` dublu + limită mărime (`MAX_UPLOAD_BYTES`) + ștergere temp; ML Kit |
| Camera / QR | `unbindAll` pe dispose + `imageProxy.close()` + `KEEP_ONLY_LATEST` |
| Family score / toate împărțirile | ghidate (`isEmpty()→75`, `max(1,…)`, `if total>0`) — NaN/ZeroDiv prevenite |
| Module mici (ThreatIntel/Mail/Shared/FileImport/GateResult) | 0 `!!` / 0 first / 0 substring / 0 cast nesigur |
| Backend (Python) | 0 `eval/exec/shell=True/pickle/verify=False/ReDoS/mutable-default-arg` |
| Securitate | `allowBackup=false`, cleartext off (SDK 36), chei via gradle (nu hardcodate), `sha256`, doar launcher exported, `EncryptedSharedPreferences` (AES256-GCM) |

---

## 📌 Prioritate de acțiune (recomandare)
1. **P0 #1+#2+#3** — fix de ~15 min, cu test de regresie pe port malformat. **Singurul sever.**
2. **P1 Turkish-i** — `Locale.ROOT` în cele 3 locuri (fals-pozitiv real pe device-uri non-EN).
3. P2 — când prinzi timp (hardening).

*Întocmit de Claude (Opus 4.8) pe branch-ul `feature/ui-redesign`, audit pe `main`. Read-only — niciun fișier de producție modificat.*
