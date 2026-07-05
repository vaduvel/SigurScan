from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import re
from typing import TYPE_CHECKING, List

from services.invoice_parser import InvoiceFields

if TYPE_CHECKING:
    from services.offer_parser import OfferFields


class ReadinessState(str, Enum):
    READY = "ready_for_analysis"
    MISSING = "missing_documents"
    BLOCKED = "procedural_blocker"
    LOW_CONFIDENCE = "analysis_allowed_but_low_confidence"


@dataclass
class ReadinessGateItem:
    id: str
    label: str
    detail: str
    next_action: str


@dataclass
class ReadinessGateResult:
    state: ReadinessState
    headline: str
    explanation: str
    next_action: str
    blocks_safe_verdict: bool
    items: List[ReadinessGateItem] = field(default_factory=list)

    def can_be_safe(self) -> bool:
        return self.state == ReadinessState.READY

    def verdict_minimum(self) -> str:
        if self.state == ReadinessState.READY:
            return "any"
        return "suspect"


_CARD_SETTLEMENT_RE = re.compile(
    r"\btip\s+plat[ăa]\s*:\s*(?:card|cards|pos|sibs|visa|mastercard|maestro)\b"
    r"|(?:pl[ăa]tit[ăa]?|achitat[ăa]?)\s+(?:cu|prin)\s+card\b",
    re.IGNORECASE,
)


def _has_card_settlement_evidence(fields: InvoiceFields) -> bool:
    return bool(_CARD_SETTLEMENT_RE.search(getattr(fields, "raw_text", "") or ""))


def evaluate_readiness(fields: InvoiceFields, ocr_confidence: float | None = None) -> ReadinessGateResult:
    confidence = ocr_confidence if ocr_confidence is not None else _estimate_ocr_confidence(fields)
    items: List[ReadinessGateItem] = []

    has_cui = bool(fields.cui)
    has_iban = bool(fields.iban)
    has_total = fields.total is not None
    card_settled = _has_card_settlement_evidence(fields)
    has_dates = bool(fields.data_emitere) and (bool(fields.scadenta) or card_settled)
    is_international_invoice = fields.invoice_profile == "international"

    if is_international_invoice:
        missing_international = []
        if not fields.emitent:
            missing_international.append("emitent")
        if not fields.nr_factura:
            missing_international.append("număr factură")
        if not has_total:
            missing_international.append("total")
        if not has_dates:
            missing_international.append("date")
        if not fields.currency:
            missing_international.append("monedă")

        if missing_international:
            items.append(
                ReadinessGateItem(
                    id="missing-international-fields",
                    label="Câmpuri factură internațională",
                    detail="Lipsesc: " + ", ".join(missing_international) + ".",
                    next_action="Verifică manual factura sau încarcă o poză/PDF mai clar.",
                )
            )
            return ReadinessGateResult(
                state=ReadinessState.LOW_CONFIDENCE,
                headline="Factura internațională s-a citit parțial",
                explanation="Nu toate câmpurile comerciale standard au putut fi citite. Fără ele nu putem valida coerent documentul.",
                next_action="Verifică emitentul, numărul facturii, totalul, moneda și datele înainte de plată.",
                blocks_safe_verdict=True,
                items=items,
            )

        if confidence < 0.6:
            items.append(
                ReadinessGateItem(
                    id="low-ocr-confidence",
                    label="Document neclar",
                    detail="Factura internațională s-a citit cu încredere scăzută.",
                    next_action="Reîncarcă o poză mai clară sau verifică manual datele extrase.",
                )
            )
            return ReadinessGateResult(
                state=ReadinessState.LOW_CONFIDENCE,
                headline="Documentul s-a citit parțial",
                explanation="Datele principale există, dar OCR-ul are încredere scăzută. Te rog verifică-le manual.",
                next_action="Corectează datele în ecranul de confirmare și reîncearcă.",
                blocks_safe_verdict=True,
                items=items,
            )

        return ReadinessGateResult(
            state=ReadinessState.READY,
            headline="Factura internațională poate fi verificată",
            explanation="Am extras emitentul, numărul facturii, datele, totalul și moneda. CUI/ANAF nu se aplică pentru acest tip de factură.",
            next_action="Se efectuează verificările automate disponibile.",
            blocks_safe_verdict=False,
            items=items,
        )

    if not has_cui and not has_iban:
        items.append(
            ReadinessGateItem(
                id="missing-cui-iban",
                label="CUI și IBAN",
                detail="Nu am putut citi nici CUI-ul, nici IBAN-ul facturii.",
                next_action="Verifică manual emitentul și datele de plată de pe factură.",
            )
        )
        return ReadinessGateResult(
            state=ReadinessState.MISSING,
            headline="Nu am suficiente date pentru un verdict",
            explanation="Nu am putut extrage CUI-ul și IBAN-ul din document. Fără aceste date nu pot verifica emitentul sau destinația plății.",
            next_action="Verifică manual emitentul facturii pe site-ul ANAF sau contactează compania pe canalele oficiale.",
            blocks_safe_verdict=True,
            items=items,
        )

    if not has_cui:
        items.append(
            ReadinessGateItem(
                id="missing-cui",
                label="CUI",
                detail="Nu am putut citi CUI-ul facturii.",
                next_action="Verifică numele și datele emitentului manual.",
            )
        )
    if not has_iban:
        items.append(
            ReadinessGateItem(
                id="missing-iban",
                label="IBAN",
                detail="Nu am putut citi IBAN-ul facturii.",
                next_action="Verifică IBAN-ul înainte de plată.",
            )
        )

    if confidence < 0.6:
        items.append(
            ReadinessGateItem(
                id="low-ocr-confidence",
                label="Document neclar",
                detail="Documentul s-a citit cu încredere scăzută. Datele extrase s-ar putea să fie incorecte.",
                next_action="Reîncarcă o poză mai clară sau verifică manual datele extrase.",
            )
        )
        return ReadinessGateResult(
            state=ReadinessState.LOW_CONFIDENCE,
            headline="Documentul s-a citit parțial",
            explanation="Nu am putut citi documentul suficient de clar. Datele extrase ar putea fi incomplete sau incorecte. Te rog verifică-le manual.",
            next_action="Corectează datele în ecranul de confirmare și reîncearcă.",
            blocks_safe_verdict=True,
            items=items,
        )

    if not has_total or not has_dates:
        items.append(
            ReadinessGateItem(
                id="missing-fields",
                label="Câmpuri factură",
                detail="Nu am putut extrage toate câmpurile obligatorii (total, date).",
                next_action="Verifică factura manual.",
            )
        )
        return ReadinessGateResult(
            state=ReadinessState.LOW_CONFIDENCE,
            headline="Date insuficiente pentru verificare completă",
            explanation="Am citit emitentul, dar lipsesc câmpuri importante. Verdictul rămâne cu precauție.",
            next_action="Completează datele lipsă și scanează din nou.",
            blocks_safe_verdict=True,
            items=items,
        )

    return ReadinessGateResult(
        state=ReadinessState.READY,
        headline="Documentul poate fi verificat",
        explanation="Am extras datele principale din factură și putem începe verificările.",
        next_action="Se efectuează verificările automate.",
        blocks_safe_verdict=False,
        items=items,
    )


def _estimate_ocr_confidence(fields: InvoiceFields) -> float:
    if fields.invoice_profile == "international":
        total_fields = 6
        filled = sum(
            1
            for f in [
                fields.emitent,
                fields.nr_factura,
                fields.data_emitere,
                fields.scadenta,
                fields.currency,
            ]
            if f
        )
        if fields.total is not None:
            filled += 1
        return filled / total_fields

    total_fields = 7
    filled = sum(
        1 for f in [fields.cui, fields.iban, fields.emitent, fields.nr_factura,
                     fields.data_emitere, fields.scadenta]
        if f
    )
    if fields.total is not None:
        filled += 1
    if total_fields == 0:
        return 0.0
    return filled / total_fields


CONFIDENCE_THRESHOLD = 0.6


def _offer_anchors(fields: OfferFields) -> int:
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
    fields: OfferFields, ocr_confidence: float | None = None
) -> ReadinessGateResult:
    confidence = (
        ocr_confidence
        if ocr_confidence is not None
        else fields.extraction_confidence
    )
    anchors = _offer_anchors(fields)
    items: List[ReadinessGateItem] = []

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
