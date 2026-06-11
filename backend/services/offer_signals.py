"""Offer signals — mapează câmpurile/contextul ofertei în semnale OFFER_*.

Namespace dedicat rutei ofertă (distinct de signal_mapping din
brand_knowledge_pack.json, care e ruta mesaj/link). Aceste semnale NU produc
verdict — sunt intrarea pe care PR2 (offer_evidence_gate_mapper) o trece prin
verdict_gate.reduce_verdict. Determinist, fără calls externe.
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING, List, Optional

from services.invoice_coherence import CoherenceResult
from services.iban_validator import IbanResult
from services.invoice_readiness_gate import ReadinessGateResult, ReadinessState
from services.payment_method_classifier import PaymentClassification, PaymentRisk

if TYPE_CHECKING:
    from services.offer_parser import OfferFields

# — Coduri OFFER_* (conform planului de execuție PR1) —
OFFER_MISSING_ANCHORS = "OFFER_MISSING_ANCHORS"
OFFER_LOW_OCR_CONFIDENCE = "OFFER_LOW_OCR_CONFIDENCE"
OFFER_IBAN_INVALID_STRUCTURE = "OFFER_IBAN_INVALID_STRUCTURE"
OFFER_IBAN_TREZORERIE = "OFFER_IBAN_TREZORERIE"
OFFER_PAYMENT_METHOD_HIGH_RISK = "OFFER_PAYMENT_METHOD_HIGH_RISK"
OFFER_PAYMENT_METHOD_CRITICAL = "OFFER_PAYMENT_METHOD_CRITICAL"
OFFER_OFF_PLATFORM_PAYMENT = "OFFER_OFF_PLATFORM_PAYMENT"
OFFER_CARD_CVV_OTP_REQUEST = "OFFER_CARD_CVV_OTP_REQUEST"
OFFER_ID_DOCUMENT_REQUEST = "OFFER_ID_DOCUMENT_REQUEST"
OFFER_PRICE_URGENCY = "OFFER_PRICE_URGENCY"
OFFER_TOTALS_INCOHERENT = "OFFER_TOTALS_INCOHERENT"
OFFER_VAT_INCOHERENT = "OFFER_VAT_INCOHERENT"
OFFER_DATES_INCOHERENT = "OFFER_DATES_INCOHERENT"
OFFER_HAS_QR_PAYMENT = "OFFER_HAS_QR_PAYMENT"
OFFER_HAS_CRYPTO_WALLET = "OFFER_HAS_CRYPTO_WALLET"
OFFER_FAMILY_CLASSIFIED = "OFFER_FAMILY_CLASSIFIED"

# — Pattern-uri text deterministe —
OFF_PLATFORM = re.compile(
    r"\b(?:in\s*afara\s*platform|off[-\s]?platform|continu[ăa]m\s*pe\s*whatsapp|"
    r"hai\s*pe\s*whatsapp|scrie[-\s]?mi\s*pe\s*whatsapp|d[ăa][-\s]?mi\s*num[ăa]rul|"
    r"plata\s*direct(?:\s*la\s*mine)?|transfer\s*direct)\b",
    re.IGNORECASE,
)
CARD_CVV_OTP = re.compile(
    r"\b(?:cvv|cvc|cod\s*(?:de\s*)?(?:3d\s*secure|otp|sms)|cod\s*card|"
    r"introdu\s*datele\s*cardului|num[ăa]r(?:ul)?\s*card)\b",
    re.IGNORECASE,
)
ID_DOCUMENT = re.compile(
    r"\b(?:copie\s*(?:ci|buletin|carte\s*de\s*identitate)|poz[ăa]\s*(?:la\s*)?buletin|"
    r"buletin(?:ul)?|carte\s*de\s*identitate|\bcnp\b|cod\s*numeric\s*personal|selfie\s*cu\s*(?:ci|buletin))\b",
    re.IGNORECASE,
)
URGENCY = re.compile(
    r"\b(?:doar\s*azi|ultim(?:a|ele)\s*(?:loc|camer|bilet|oferta)|"
    r"se\s*(?:vinde|inchiriaza|închiriază)\s*repede|pl[ăa]te[șs]te\s*(?:azi|acum|urgent)|"
    r"pana\s*la\s*ora|p[âa]n[ăa]\s*la\s*ora|gr[ăa]be[șs]te|expir[ăa]|"
    r"al[țt]ii\s*sunt\s*interesa[țt]i)\b",
    re.IGNORECASE,
)
PRICE_HINT = re.compile(
    r"\b(?:pre[țt]|redu(?:cere|s)|sub\s*pia[țt][ăa]|ofert[ăa]|gratis|gratuit|%|lei|euro|eur|ron)\b",
    re.IGNORECASE,
)
CRYPTO_WALLET = re.compile(
    r"\b(?:crypto|cripto|bitcoin|btc|usdt|tether|ethereum|\beth\b|wallet|portofel\s*crypto|metamask|binance)\b",
    re.IGNORECASE,
)


def derive_offer_signals(
    fields: "OfferFields",
    *,
    iban_result: Optional[IbanResult] = None,
    coherence: Optional[CoherenceResult] = None,
    payment: Optional[PaymentClassification] = None,
    family_code: Optional[str] = None,
    readiness: Optional[ReadinessGateResult] = None,
) -> List[str]:
    """Întoarce lista de coduri OFFER_* active pentru această ofertă (dedupe, ordonat)."""
    text = fields.raw_text or ""
    signals: List[str] = []

    def add(code: str) -> None:
        if code not in signals:
            signals.append(code)

    # Readiness
    if readiness is not None:
        if readiness.state == ReadinessState.MISSING:
            add(OFFER_MISSING_ANCHORS)
        if readiness.state == ReadinessState.LOW_CONFIDENCE:
            add(OFFER_LOW_OCR_CONFIDENCE)
    elif fields.extraction_confidence < 0.6:
        add(OFFER_LOW_OCR_CONFIDENCE)

    # IBAN
    if iban_result is not None:
        if fields.iban and not iban_result.valid_structure:
            add(OFFER_IBAN_INVALID_STRUCTURE)
        if iban_result.is_trezorerie:
            add(OFFER_IBAN_TREZORERIE)

    # Payment method risk
    if payment is not None:
        if payment.risk == PaymentRisk.HIGH:
            add(OFFER_PAYMENT_METHOD_HIGH_RISK)
        elif payment.risk == PaymentRisk.CRITICAL:
            add(OFFER_PAYMENT_METHOD_CRITICAL)

    # Text-derived
    if OFF_PLATFORM.search(text):
        add(OFFER_OFF_PLATFORM_PAYMENT)
    if CARD_CVV_OTP.search(text):
        add(OFFER_CARD_CVV_OTP_REQUEST)
    if ID_DOCUMENT.search(text):
        add(OFFER_ID_DOCUMENT_REQUEST)
    if URGENCY.search(text) and PRICE_HINT.search(text):
        add(OFFER_PRICE_URGENCY)
    if CRYPTO_WALLET.search(text):
        add(OFFER_HAS_CRYPTO_WALLET)

    # Coherence
    if coherence is not None:
        if not coherence.totals_match:
            add(OFFER_TOTALS_INCOHERENT)
        if not coherence.tva_rate_plausible:
            add(OFFER_VAT_INCOHERENT)
        if not coherence.dates_plausible:
            add(OFFER_DATES_INCOHERENT)

    # QR
    if fields.qr_payloads:
        add(OFFER_HAS_QR_PAYMENT)

    # Family
    if family_code and family_code != "OP-00":
        add(OFFER_FAMILY_CLASSIFIED)

    return signals
