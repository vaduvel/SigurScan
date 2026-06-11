"""Payment method risk classifier — scara LOW/MEDIUM/HIGH/CRITICAL.

Determinist, pe text + context (IBAN, beneficiar PF, QR). NU produce verdict
(asta e treaba verdict_gate.reduce_verdict în PR2) — întoarce doar nivelul de
risc al metodei de plată + motivele, ca semnal pentru gate.

Scara (din planul de execuție PR1):
  LOW: card/platformă oficială, fără cerere CVV/OTP în document
  MEDIUM: transfer către firmă verificabilă; cash la predare/inspecție
  HIGH: transfer către PF pentru firmă/hotel/agenție; Revolut/PF/alias;
        avans înainte de vizionare/livrare
  CRITICAL: Western Union / MoneyGram / gift card / crypto / QR crypto /
            cerere CVV-OTP pentru „primire bani"
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class PaymentRisk(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_RISK_ORDER = {
    PaymentRisk.LOW: 0,
    PaymentRisk.MEDIUM: 1,
    PaymentRisk.HIGH: 2,
    PaymentRisk.CRITICAL: 3,
}


@dataclass
class PaymentClassification:
    risk: PaymentRisk
    method: Optional[str]
    reasons: List[str] = field(default_factory=list)


# — CRITICAL —
WESTERN_UNION = re.compile(r"\b(?:western\s*union|money\s*gram|moneygram)\b", re.IGNORECASE)
GIFT_CARD = re.compile(r"\b(?:gift\s*card|card\s*cadou|voucher|cod\s*(?:de\s*)?reincarcare|steam\s*card|paysafe)\b", re.IGNORECASE)
CRYPTO = re.compile(r"\b(?:crypto|cripto|bitcoin|btc|usdt|tether|ethereum|\beth\b|wallet|portofel\s*crypto|metamask|binance)\b", re.IGNORECASE)
# „dă CVV/OTP ca să PRIMEȘTI bani" — inversarea clasică din marketplace
CVV_OTP_RECEIVE = re.compile(
    r"(?:cvv|cvc|cod\s*(?:de\s*)?(?:3d\s*secure|otp|sms)|cod\s*card).{0,60}(?:primi|primesti|incasezi|primire|ca\s*sa\s*primesti)"
    r"|(?:primi|primesti|incasezi|primire).{0,60}(?:cvv|cvc|otp|cod\s*card|cod\s*sms|3d\s*secure)",
    re.IGNORECASE | re.DOTALL,
)

# — HIGH —
REVOLUT = re.compile(r"\b(?:revolut|wise|paypal\s*friends|prieteni\s*paypal|@[a-z0-9_.]+)\b", re.IGNORECASE)
AVANS_INAINTE = re.compile(
    r"avans.{0,40}(?:inainte|înainte|pana|până)|(?:inainte|înainte)\s*de\s*(?:vizionare|livrare|predare).{0,40}(?:plat|avans|transfer)",
    re.IGNORECASE,
)
CARD_REQUEST = re.compile(
    r"(?:introdu|completeaz|trimite|da[-\s]?ne).{0,30}(?:datele\s*cardului|num[ăa]r(?:ul)?\s*card|cvv|cvc|cod\s*card)",
    re.IGNORECASE,
)

# — MEDIUM —
TRANSFER = re.compile(r"\b(?:transfer\s*bancar|virament|in\s*cont|plata\s*prin\s*transfer)\b", re.IGNORECASE)
CASH_ON_DELIVERY = re.compile(r"\b(?:ramburs|la\s*livrare|cash\s*la\s*predare|numerar\s*la\s*predare|plata\s*la\s*inspectie)\b", re.IGNORECASE)

# — LOW —
OFFICIAL_CARD = re.compile(r"\b(?:3d\s*secure|3ds|plata\s*cu\s*card(?:ul)?\s*(?:pe|in)\s*(?:platform|site)|card\s*pe\s*platforma)\b", re.IGNORECASE)


def classify_payment_method(
    text: str,
    *,
    iban_is_trezorerie: bool = False,
    beneficiary_is_person: Optional[bool] = None,
    issuer_claims_company: bool = False,
    has_qr: bool = False,
) -> PaymentClassification:
    """Clasifică riscul metodei de plată. Întoarce cel mai ridicat nivel detectat.

    `beneficiary_is_person` + `issuer_claims_company`: dacă beneficiarul e PF
    dar documentul pretinde firmă/agenție/hotel → HIGH (transfer către PF).
    """
    body = text or ""
    reasons: List[str] = []
    risk = PaymentRisk.LOW
    method: Optional[str] = None

    def bump(level: PaymentRisk, reason: str, label: Optional[str] = None) -> None:
        nonlocal risk, method
        if _RISK_ORDER[level] > _RISK_ORDER[risk]:
            risk = level
            if label:
                method = label
        reasons.append(reason)

    # CRITICAL
    if WESTERN_UNION.search(body):
        bump(PaymentRisk.CRITICAL, "Western Union / MoneyGram — irevocabil, fără protecție.", "western_union")
    if GIFT_CARD.search(body):
        bump(PaymentRisk.CRITICAL, "Gift card / voucher — metodă tipică de fraudă, irevocabilă.", "gift_card")
    if CRYPTO.search(body):
        bump(PaymentRisk.CRITICAL, "Crypto / wallet — plată irevocabilă, fără recurs.", "crypto")
    if CVV_OTP_RECEIVE.search(body):
        bump(PaymentRisk.CRITICAL, "Cere CVV/OTP pentru a primi bani — nicio platformă nu cere asta.", "card_cvv_otp")

    # HIGH
    if AVANS_INAINTE.search(body):
        bump(PaymentRisk.HIGH, "Avans cerut înainte de vizionare/livrare.", method or "avans")
    if REVOLUT.search(body):
        bump(PaymentRisk.HIGH, "Revolut / cont personal / alias — fără protecția unui comerciant.", method or "revolut_pf")
    if CARD_REQUEST.search(body):
        bump(PaymentRisk.HIGH, "Cere datele cardului în afara unei platforme oficiale.", method or "card_offplatform")
    if beneficiary_is_person and issuer_claims_company:
        bump(
            PaymentRisk.HIGH,
            "Beneficiar persoană fizică deși documentul pretinde firmă/agenție/hotel.",
            method or "transfer_pf",
        )

    # MEDIUM
    if CASH_ON_DELIVERY.search(body):
        bump(PaymentRisk.MEDIUM, "Plata la livrare/inspecție — risc moderat.", method or "cash_on_delivery")
    if TRANSFER.search(body):
        bump(PaymentRisk.MEDIUM, "Transfer bancar — risc moderat dacă beneficiarul nu e verificat.", method or "bank_transfer")

    # LOW
    if OFFICIAL_CARD.search(body) and risk == PaymentRisk.LOW:
        bump(PaymentRisk.LOW, "Card cu 3D Secure pe platformă oficială.", "card_3ds")

    # IBAN Trezorerie = neutru-spre-sigur (plată legitimă către stat). Nu ridică riscul.
    if iban_is_trezorerie and risk == PaymentRisk.LOW:
        reasons.append("IBAN Trezoreria Statului — destinație de plată către stat.")
        method = method or "trezorerie"

    if has_qr and risk in (PaymentRisk.LOW, PaymentRisk.MEDIUM):
        reasons.append("Conține cod QR de plată — verifică destinația înainte de scanare.")

    return PaymentClassification(risk=risk, method=method, reasons=reasons)
