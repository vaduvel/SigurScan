"""Jurist Dinamic Lvl 2 (M6, PR-8) — plan de acțiune personalizat post-incident.

Construiește planul de remediere de pe TriageScreen: după ce verdict_gate a dat
verdictul și (opțional) după ce userul a fost lovit, întoarce pașii concreți,
ordonați pe urgență, plus pachetul de raportare (reuse PR-5) și cardurile legale
verbatim (reuse L1 legal_layer).

Reguli:
- NU schimbă verdictul (rulează post-gate, ca legal_layer).
- Pașii sunt OPERAȚIONALI (sună banca, schimbă parola, deconectează dispozitivul);
  articolele de lege NU se inventează aici — vin verbatim din legal_kb.json prin
  legal_cards_for. Separația asta ține „zero invenție juridică".
- Determinist: aceleași intrări → același plan (inclusiv ordinea).
- Label UI „Plan de acțiune", niciodată „Jurist"/„Avocat".
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from services import offer_signals as S
from services.legal_layer import legal_cards_for
from services.report_builder import build_report_package

UI_LABEL = "Plan de acțiune"

_DISCLAIMER = (
    "Plan orientativ de remediere, nu sfat juridic personalizat. Verifică și "
    "acționează tu fiecare pas; pentru situații complexe consultă un avocat."
)

# Ordinea urgenței (rank crescător). Pașii se sortează stabil după acest rank.
URGENCY_ORDER = ("now", "today", "soon")


def _step(urgency: str, title: str, detail: str,
          channel: Optional[str] = None, legal_card_id: Optional[str] = None) -> Dict[str, Any]:
    return {
        "urgency": urgency,
        "title": title,
        "detail": detail,
        "channel": channel,
        "legal_card_id": legal_card_id,
    }


# Impact (ce a făcut userul) -> pași operaționali, în ordinea „natural" de prioritate.
# Pașii primesc urgency; sortarea finală pe urgență se face global.
_IMPACT_STEPS: Dict[str, List[Dict[str, Any]]] = {
    "shared_card": [
        _step("now", "Blochează cardul acum",
              "Sună banca pe numărul de pe card și cere blocarea imediată; dacă nu "
              "prinzi telefonic, blochează cardul din aplicația băncii.",
              channel="Banca + Biroul de Credit", legal_card_id="law-instrumente-plata-311"),
        _step("today", "Contestă tranzacțiile neautorizate",
              "Verifică extrasul și contestă în scris orice tranzacție pe care nu ai făcut-o."),
    ],
    "shared_otp": [
        _step("now", "Blochează cardul acum",
              "Sună banca pe numărul de pe card și cere blocarea imediată; dacă nu "
              "prinzi telefonic, blochează cardul din aplicația băncii.",
              channel="Banca + Biroul de Credit", legal_card_id="law-instrumente-plata-311"),
        _step("now", "Schimbă codurile de acces bancar",
              "Schimbă parola de internet/mobile banking de pe un dispozitiv sigur."),
    ],
    "shared_credentials": [
        _step("now", "Schimbă parola contului afectat",
              "Schimbă parola de pe un dispozitiv sigur și deloghează sesiunile active."),
        _step("today", "Activează 2FA",
              "Pornește autentificarea în doi pași și verifică dispozitivele conectate."),
    ],
    "shared_id_document": [
        _step("today", "Anunță Biroul de Credit",
              "Cere o alertă de fraudă la Biroul de Credit — există risc de credit "
              "luat pe numele tău (IFN/bancă).",
              channel="Banca + Biroul de Credit", legal_card_id="law-furt-identitate-327"),
        _step("today", "Depune sesizare pentru furt de identitate",
              "Sesizează Poliția pentru folosirea datelor tale de identitate.",
              channel="112 / Politia", legal_card_id="law-furt-identitate-327"),
        _step("soon", "Monitorizează credite noi pe CNP",
              "Verifică periodic dacă apar IFN-uri/credite deschise pe numele tău."),
    ],
    "installed_remote_access": [
        _step("now", "Deconectează dispozitivul",
              "Deconectează telefonul/PC-ul de la internet; pornește-l în mod sigur "
              "dacă e posibil."),
        _step("now", "Dezinstalează aplicația de acces la distanță",
              "Dezinstalează AnyDesk/TeamViewer și orice aplicație necunoscută instalată recent."),
        _step("today", "Schimbă parolele de pe alt dispozitiv curat",
              "Schimbă parolele de email și bancă de pe un dispozitiv în care ai încredere."),
    ],
    "paid_transfer": [
        _step("now", "Cere rechemarea (recall) transferului",
              "Sună banca imediat și cere recall/oprirea transferului — primele minute contează.",
              channel="Banca + Biroul de Credit", legal_card_id="law-inselaciune-244"),
        _step("today", "Depune plângere penală pentru înșelăciune",
              "Depune plângere pentru înșelăciune (art. 244 Cod penal), cu dovezile strânse.",
              channel="112 / Politia", legal_card_id="law-inselaciune-244"),
    ],
    "paid_crypto": [
        _step("now", "Salvează dovezile tranzacției crypto",
              "Notează TX hash-ul și adresa portofelului; raportează la platforma de crypto.",
              legal_card_id="law-inselaciune-244"),
        _step("today", "Depune plângere penală pentru înșelăciune",
              "Depune plângere pentru înșelăciune (art. 244 Cod penal), cu dovezile strânse.",
              channel="112 / Politia", legal_card_id="law-inselaciune-244"),
    ],
    "clicked_link": [
        _step("today", "Schimbă parolele introduse pe acel site",
              "Schimbă parolele oricărui cont ale cărui date le-ai introdus pe site-ul suspect."),
        _step("today", "Scanează dispozitivul de malware",
              "Rulează o scanare de securitate; nu deschide alte linkuri din același mesaj."),
    ],
    "none": [
        _step("now", "Nu plăti și nu introduce date",
              "Nu efectua plata și nu furniza date personale/bancare până nu verifici pe canal oficial."),
        _step("now", "Folosește Cercul pentru a doua opinie",
              "Cere o verificare out-of-band prin Cerc (rupe izolarea — nu decide singur sub presiune)."),
    ],
}

# Impact -> semnale L1 pentru cardurile legale verbatim.
_IMPACT_TO_SIGNALS: Dict[str, List[str]] = {
    "shared_card": [S.OFFER_CARD_CVV_OTP_REQUEST],
    "shared_otp": [S.OFFER_CARD_CVV_OTP_REQUEST],
    "shared_id_document": [S.OFFER_ID_DOCUMENT_REQUEST],
    "paid_transfer": [S.OFFER_PAYMENT_METHOD_HIGH_RISK],
    "paid_crypto": [S.OFFER_PAYMENT_METHOD_HIGH_RISK],
}


def _normalize_impacts(impacts: Optional[List[str]]) -> List[str]:
    seen: List[str] = []
    for raw in impacts or []:
        imp = str(raw or "").strip().lower()
        if imp and imp not in seen:
            seen.append(imp)
    if not seen:
        seen = ["none"]
    return seen


def build_action_plan(
    *,
    verdict: str,
    family: Optional[str] = None,
    impacts: Optional[List[str]] = None,
    target: Optional[Dict[str, Any]] = None,
    document_type: Optional[str] = None,
) -> Dict[str, Any]:
    """Plan de acțiune post-incident, determinist. NU schimbă verdictul."""
    norm_impacts = _normalize_impacts(impacts)

    # 1) Adună pașii din toate impacturile, dedup pe titlu (păstrând prima apariție).
    collected: List[Dict[str, Any]] = []
    seen_titles: set[str] = set()
    for imp in norm_impacts:
        for step in _IMPACT_STEPS.get(imp, []):
            if step["title"] in seen_titles:
                continue
            seen_titles.add(step["title"])
            collected.append(dict(step))

    # 2) Sortare stabilă pe urgență (now < today < soon), apoi numerotare 1..n.
    def _rank(step: Dict[str, Any]) -> int:
        try:
            return URGENCY_ORDER.index(step["urgency"])
        except ValueError:
            return len(URGENCY_ORDER)

    collected.sort(key=_rank)  # stabil: păstrează ordinea de inserție în cadrul urgenței
    steps: List[Dict[str, Any]] = []
    for i, step in enumerate(collected, start=1):
        step["order"] = i
        steps.append(step)

    # 3) Carduri legale verbatim (reuse L1) din semnalele mapate.
    signals: List[str] = []
    for imp in norm_impacts:
        for sig in _IMPACT_TO_SIGNALS.get(imp, []):
            if sig not in signals:
                signals.append(sig)
    legal = legal_cards_for(signals, family_code=family, document_type=document_type)

    # 4) Pachet de raportare (reuse PR-5).
    report_target = target or {"type": "unknown", "value_redacted": "[redactat]"}
    report_package = build_report_package(
        target=report_target, family=family or "UNKNOWN", verdict=verdict,
    )

    return {
        "label": UI_LABEL,
        "verdict": verdict,           # passthrough — niciodată modificat aici
        "family": family,
        "impacts": norm_impacts,
        "steps": steps,
        "legal": legal,
        "report_package": report_package,
        "disclaimer": _DISCLAIMER,
    }
