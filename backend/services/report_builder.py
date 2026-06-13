"""Raport 1-tap (MoatOS §7, PR-5) — pachet precompletat pentru autorități RO.

Construiește un pachet de raportare gata de trimis (DNSC/1911, PNRISC-Poliție,
ANPC, bancă), din care userul trimite cu un tap. NU trimite automat (onest:
pregătește, omul confirmă). Determinist, fără PII brut — doar ținta redactată.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

REPORT_DISCLAIMER = (
    "SigurScan pregătește un raport precompletat pe baza datelor pe care le-ai "
    "introdus. Verifică și trimite tu raportul către autoritate. Nu trimitem "
    "automat și nu transmitem date personale fără acțiunea ta."
)

# Familii pe care le rutăm explicit și către alte canale decât DNSC.
_FINANCIAL_FAMILIES = {
    "CONV_BANK_SAFE_ACCOUNT", "DOC_BEC_IBAN_CHANGE", "CONV_INVESTMENT_DEEPFAKE",
}
_CONSUMER_FAMILIES = {
    "DOC_OFFER_ADVANCE_PAYMENT", "CONV_MARKETPLACE_RECEIVE_MONEY",
}

_TARGET_LABEL = {
    "phone": "numărul de telefon",
    "iban": "contul IBAN",
    "domain": "domeniul/site-ul",
    "url": "linkul",
    "email": "adresa de e-mail",
}


def _target_phrase(target: Dict[str, Any]) -> str:
    label = _TARGET_LABEL.get(str(target.get("type")), "elementul")
    value = str(target.get("value_redacted") or "[redactat]")
    return f"{label} {value}"


def _dnsc_channel(target: Dict[str, Any], family: str, verdict: str) -> Dict[str, Any]:
    tphrase = _target_phrase(target)
    return {
        "name": "DNSC",
        "contact": "1911 (gratuit) sau dnsc.ro/raporteaza",
        "for": "incidente cyber, phishing, fraude online",
        "prefilled_subject": "Raportare tentativă de fraudă online",
        "prefilled_body": (
            f"Bună ziua, raportez o tentativă de fraudă (verdict SigurScan: {verdict}). "
            f"Am primit un mesaj/apel suspect care implică {tphrase}. "
            "Atașez capturi și detalii. Vă rog să investigați."
        ),
        "fields": {
            "target_type": target.get("type"),
            "target_redacted": target.get("value_redacted"),
            "family": family,
            "verdict": verdict,
        },
    }


def _pnrisc_channel(target: Dict[str, Any], family: str, verdict: str) -> Dict[str, Any]:
    return {
        "name": "PNRISC / Poliția Română",
        "contact": "politiaromana.ro (PNRISC) sau 112 pentru urgență",
        "for": "înșelăciune, fraudă, furt de identitate",
        "prefilled_subject": "Sesizare tentativă de înșelăciune",
        "prefilled_body": (
            f"Sesizez o tentativă de înșelăciune care implică {_target_phrase(target)}. "
            "Nu am suferit/am suferit o pagubă (completează). Solicit verificare."
        ),
        "fields": {"target_redacted": target.get("value_redacted"), "family": family},
    }


def _anpc_channel(target: Dict[str, Any], family: str, verdict: str) -> Dict[str, Any]:
    return {
        "name": "ANPC",
        "contact": "anpc.ro",
        "for": "probleme comerciale, ofertă/comerciant înșelător",
        "prefilled_subject": "Reclamație practică comercială înșelătoare",
        "prefilled_body": (
            f"Reclam o ofertă/comerciant suspect care implică {_target_phrase(target)}."
        ),
        "fields": {"target_redacted": target.get("value_redacted"), "family": family},
    }


def _bank_channel(target: Dict[str, Any], family: str, verdict: str) -> Dict[str, Any]:
    return {
        "name": "Banca + Biroul de Credit",
        "contact": "numărul de pe cardul tău (canal oficial)",
        "for": "transfer fraudulos, card compromis, credit pe numele tău",
        "prefilled_subject": "Suspiciune de fraudă financiară",
        "prefilled_body": (
            "Sună banca pe numărul oficial de pe card. Dacă ai introdus date sau "
            "ai trimis bani, cere blocarea cardului/contului și verifică Biroul de Credit."
        ),
        "fields": {"target_redacted": target.get("value_redacted"), "family": family},
    }


def build_report_package(
    *,
    target: Dict[str, Any],
    family: str,
    verdict: str,
    redacted_summary: Optional[str] = None,
) -> Dict[str, Any]:
    """Pachet de raportare precompletat. DNSC mereu inclus; canale extra pe familie."""
    target = target or {"type": "unknown", "value_redacted": "[redactat]"}
    fam = family or "UNKNOWN"

    channels: List[Dict[str, Any]] = [_dnsc_channel(target, fam, verdict)]
    channels.append(_pnrisc_channel(target, fam, verdict))
    if fam in _FINANCIAL_FAMILIES or target.get("type") == "iban":
        channels.append(_bank_channel(target, fam, verdict))
    if fam in _CONSUMER_FAMILIES:
        channels.append(_anpc_channel(target, fam, verdict))

    return {
        "generated_for": {
            "family": fam,
            "verdict": verdict,
            "target_type": target.get("type"),
            "target_redacted": target.get("value_redacted"),
        },
        "redacted_summary": redacted_summary,
        "channels": channels,
        "disclaimer": REPORT_DISCLAIMER,
    }
