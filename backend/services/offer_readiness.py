"""Offer readiness — generalizează invoice_readiness_gate pentru oferte.

REUSE: ReadinessState / ReadinessGateResult / ReadinessGateItem din
invoice_readiness_gate. NU duplicăm fișierul; îl wrap-uim. Pragul de încredere
OCR rămâne 0.6, stările rămân aceleași.

Diferența față de factură: o ofertă poate fi analizabilă FĂRĂ CUI/total
(ex. chirie de la persoană fizică, anunț marketplace). E „gata de analiză" dacă
avem măcar o ancoră de ofertă: emitent, IBAN, beneficiar plată, sumă, sau URL/QR.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from services.invoice_readiness_gate import (
    ReadinessGateItem,
    ReadinessGateResult,
    ReadinessState,
)

if TYPE_CHECKING:
    from services.offer_parser import OfferFields

CONFIDENCE_THRESHOLD = 0.6


def _offer_anchors(fields: "OfferFields") -> int:
    anchors = [
        fields.issuer_name or fields.emitent,
        fields.cui,
        fields.iban,
        fields.payment_beneficiary,
        fields.total,
        bool(fields.urls),
        fields.platform_name,
    ]
    return sum(1 for a in anchors if a)


def evaluate_offer_readiness(
    fields: "OfferFields", ocr_confidence: float | None = None
) -> ReadinessGateResult:
    """Evaluează dacă o ofertă are destule date pentru analiză.

    Stările + pragul 0.6 sunt identice cu invoice_readiness_gate.
    """
    confidence = (
        ocr_confidence
        if ocr_confidence is not None
        else fields.extraction_confidence
    )
    anchors = _offer_anchors(fields)
    items: list[ReadinessGateItem] = []

    # Nicio ancoră → nu putem analiza nimic.
    if anchors == 0:
        items.append(
            ReadinessGateItem(
                id="offer-missing-anchors",
                label="Date ofertă",
                detail="Nu am putut citi nimic util din ofertă (emitent, IBAN, beneficiar, sumă sau link).",
                next_action="Reîncarcă o poză mai clară sau adaugă textul ofertei.",
            )
        )
        return ReadinessGateResult(
            state=ReadinessState.MISSING,
            headline="Nu am suficiente date pentru un verdict",
            explanation="Nu am putut extrage destule informații din ofertă pentru a o verifica.",
            next_action="Adaugă o poză mai clară a documentului sau textul complet al ofertei.",
            blocks_safe_verdict=True,
            items=items,
        )

    # Document citit cu încredere scăzută.
    if confidence < CONFIDENCE_THRESHOLD:
        for missing in fields.missing_fields:
            items.append(
                ReadinessGateItem(
                    id=f"offer-missing-{missing}",
                    label=missing,
                    detail=f"Nu am putut citi campul {missing} din ofertă.",
                    next_action="Verifică/completează manual în ecranul de confirmare.",
                )
            )
        return ReadinessGateResult(
            state=ReadinessState.LOW_CONFIDENCE,
            headline="Oferta s-a citit parțial",
            explanation="Am citit doar o parte din date. Verdictul rămâne cu precauție; verifică datele extrase.",
            next_action="Corectează datele în ecranul de confirmare și reîncearcă.",
            blocks_safe_verdict=True,
            items=items,
        )

    return ReadinessGateResult(
        state=ReadinessState.READY,
        headline="Oferta poate fi verificată",
        explanation="Am extras datele principale ale ofertei și putem începe verificările.",
        next_action="Se efectuează verificările automate.",
        blocks_safe_verdict=False,
        items=items,
    )
