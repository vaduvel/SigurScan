"""Offer parser — extinde parserul de factură către „ofertă/plată".

REUSE: invoice_parser.parse_invoice / InvoiceFields (factura e un caz particular
de ofertă). OfferFields EXTINDE InvoiceFields, iar parse_offer apelează
parse_invoice și apoi îmbogățește cu câmpurile specifice ofertei.

Nu face calls externe. Nu construiește alt OCR (textul vine din
google_vision_ocr server-side). Brand-ul „pretins" rămâne pe seama
brand_registry.match_brand din PR2 — aici extragem doar semnale ieftine din text.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Literal, Optional

from services.invoice_parser import (
    CUI_PATTERN,
    IBAN_PATTERN,
    InvoiceFields,
    parse_invoice,
)

InputType = Literal["offer", "invoice"]

# — Extractoare ieftine, deterministe —
URL_PATTERN = re.compile(r"\bhttps?://[^\s<>\"')]+", re.IGNORECASE)
BARE_DOMAIN_PATTERN = re.compile(
    r"\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,})\b", re.IGNORECASE
)
EMAIL_PATTERN = re.compile(r"\b[\w.+-]+@([\w-]+\.[\w.-]+)\b", re.IGNORECASE)
# VIN: 17 caractere, fără I/O/Q (standard ISO 3779)
VIN_PATTERN = re.compile(r"\b([A-HJ-NPR-Z0-9]{17})\b")
LICENSE_PATTERN = re.compile(
    r"(?:licen[țt][aă]|brevet)\s*(?:de\s*turism)?\s*(?:nr\.?|num[ăa]r)?\s*[:#]?\s*([A-Z0-9/.\-]{3,})",
    re.IGNORECASE,
)
BENEFICIAR_PATTERN = re.compile(
    r"(?:beneficiar|titular(?:\s*cont)?|c[ăa]tre|in\s*contul(?:\s*lui)?)\s*[:\-]?\s*(.+?)(?:\n|$|,|;)",
    re.IGNORECASE,
)

CURRENCY_MAP = [
    (re.compile(r"\b(?:eur|euro|€)\b", re.IGNORECASE), "EUR"),
    (re.compile(r"\b(?:usd|dolari?|\$)\b", re.IGNORECASE), "USD"),
    (re.compile(r"\b(?:gbp|lire|£)\b", re.IGNORECASE), "GBP"),
    (re.compile(r"\b(?:ron|lei|lej)\b", re.IGNORECASE), "RON"),
]

# Platforme cunoscute (doar etichetare; verificarea de brand e în PR2).
PLATFORM_HINTS = {
    "olx": "OLX",
    "facebook": "Facebook Marketplace",
    "fb marketplace": "Facebook Marketplace",
    "marketplace": "Facebook Marketplace",
    "booking": "Booking",
    "airbnb": "Airbnb",
    "vrbo": "VRBO",
    "emag": "eMAG",
    "eventim": "Eventim",
    "iabilet": "iaBilet",
    "ticketmaster": "Ticketmaster",
    "autovit": "Autovit",
    "revolut": "Revolut",
}

# Tip document — heuristică simplă pe text.
DOC_TYPE_HINTS = [
    (re.compile(r"\bproform[aă]\b", re.IGNORECASE), "proforma"),
    (re.compile(r"\bcontract\b", re.IGNORECASE), "contract"),
    (re.compile(r"\b(?:bilet|e-?ticket|tichet)\b", re.IGNORECASE), "ticket"),
    (re.compile(r"\bfactur[aă]\b", re.IGNORECASE), "invoice"),
    (re.compile(r"\b(?:rezervare|reservation|booking confirmation)\b", re.IGNORECASE), "reservation"),
]


@dataclass
class OfferFields(InvoiceFields):
    """Ofertă/plată — superset al InvoiceFields. Factura = caz particular."""

    issuer_name: Optional[str] = None
    issuer_registration_no: Optional[str] = None
    issuer_address: Optional[str] = None
    claimed_brand: Optional[str] = None
    payment_beneficiary: Optional[str] = None
    payment_method: Optional[str] = None
    payment_instructions: Optional[str] = None
    currency: str = "RON"
    document_type: str = "offer"
    urls: List[str] = field(default_factory=list)
    email_domains: List[str] = field(default_factory=list)
    license_number: Optional[str] = None  # turism (OP-01)
    vin: Optional[str] = None  # auto (OP-04)
    property_address: Optional[str] = None  # chirii (OP-03)
    event_name: Optional[str] = None  # bilete (OP-05)
    platform_name: Optional[str] = None
    input_type: InputType = "offer"
    extraction_confidence: float = 0.0
    missing_fields: List[str] = field(default_factory=list)

    @property
    def issuer_cui(self) -> Optional[str]:
        """Alias peste InvoiceFields.cui — emitentul ofertei e identificat prin CUI."""
        return self.cui


def _detect_currency(text: str) -> str:
    for pattern, code in CURRENCY_MAP:
        if pattern.search(text):
            return code
    return "RON"


def _detect_document_type(text: str, input_type: InputType) -> str:
    for pattern, label in DOC_TYPE_HINTS:
        if pattern.search(text):
            return label
    return "invoice" if input_type == "invoice" else "offer"


def _detect_platform(text: str, urls: List[str]) -> Optional[str]:
    haystack = (text + " " + " ".join(urls)).lower()
    for needle, label in PLATFORM_HINTS.items():
        if needle in haystack:
            return label
    return None


def _extract_urls(text: str, links: List[str], qr_payloads: List[str]) -> List[str]:
    found: List[str] = []
    for source in (links, qr_payloads):
        for item in source:
            if item and item not in found:
                found.append(item)
    for match in URL_PATTERN.finditer(text):
        url = match.group(0).rstrip(".,);")
        if url not in found:
            found.append(url)
    return found


def _extract_email_domains(text: str) -> List[str]:
    domains: List[str] = []
    for match in EMAIL_PATTERN.finditer(text):
        domain = match.group(1).lower().rstrip(".")
        if domain and domain not in domains:
            domains.append(domain)
    return domains


def _extract_beneficiary(text: str) -> Optional[str]:
    match = BENEFICIAR_PATTERN.search(text)
    if not match:
        return None
    value = match.group(1).strip().rstrip(".,;")
    # Evită capturarea liniilor cu CUI/IBAN ca „beneficiar".
    if not value or CUI_PATTERN.search(value) or IBAN_PATTERN.search(value):
        return None
    if len(value) < 2 or len(value) > 80:
        return None
    return value


def _extract_vin(text: str) -> Optional[str]:
    for match in VIN_PATTERN.finditer(text):
        candidate = match.group(1).upper()
        # Un VIN real conține atât litere cât și cifre; evită cod numeric pur.
        if any(ch.isalpha() for ch in candidate) and any(ch.isdigit() for ch in candidate):
            return candidate
    return None


def _extract_license(text: str) -> Optional[str]:
    match = LICENSE_PATTERN.search(text)
    return match.group(1).strip().rstrip(".,;") if match else None


def _estimate_extraction_confidence(fields: "OfferFields") -> float:
    """Fracție din ancorele relevante pentru o ofertă care au putut fi citite."""
    anchors = [
        fields.issuer_name or fields.emitent,
        fields.cui,
        fields.iban,
        fields.payment_beneficiary,
        fields.total,
        bool(fields.urls) or None,
    ]
    filled = sum(1 for a in anchors if a)
    return round(filled / len(anchors), 4)


def _missing_fields(fields: "OfferFields") -> List[str]:
    missing: List[str] = []
    if not (fields.issuer_name or fields.emitent):
        missing.append("issuer_name")
    if not fields.cui:
        missing.append("issuer_cui")
    if not fields.iban and not fields.payment_beneficiary:
        missing.append("payment_destination")
    if fields.total is None:
        missing.append("total_amount")
    return missing


def parse_offer(
    ocr_text: str,
    links: Optional[List[str]] = None,
    qr_payloads: Optional[List[str]] = None,
    input_type: InputType = "offer",
) -> OfferFields:
    """Parsează o ofertă/plată: reuse parse_invoice, apoi îmbogățește.

    `links` + `qr_payloads` sunt threadate în parse_invoice (corectează drift-ul
    în care orchestratorul nu le pasa).
    """
    base = parse_invoice(ocr_text, pdf_links=links, qr_payloads=qr_payloads)
    text = base.raw_text

    offer = OfferFields(**vars(base))
    offer.input_type = input_type
    offer.issuer_name = base.emitent
    offer.currency = _detect_currency(text)
    offer.document_type = _detect_document_type(text, input_type)
    offer.urls = _extract_urls(text, links or [], qr_payloads or [])
    offer.email_domains = _extract_email_domains(text)
    offer.payment_beneficiary = _extract_beneficiary(text)
    offer.platform_name = _detect_platform(text, offer.urls)
    offer.vin = _extract_vin(text)
    offer.license_number = _extract_license(text)

    offer.extraction_confidence = _estimate_extraction_confidence(offer)
    offer.missing_fields = _missing_fields(offer)
    return offer
