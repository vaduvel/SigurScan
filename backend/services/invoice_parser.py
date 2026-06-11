from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List

CUI_PATTERN = re.compile(r"(?:CUI|CIF|RO)\s*[:\s]*(\d{2,10})\b", re.IGNORECASE)
IBAN_PATTERN = re.compile(r"RO\d{2}[A-Z0-9]{20,24}", re.IGNORECASE)
AMOUNT_PATTERN = re.compile(
    r"(?:Total|TVA|Subtotal|Suma|Valoare|Plata|De plata)\s*(?:factur[ai]|plat[iă]|)?[:\s]*"
    r"(\d[\d\s]*(?:[.,]\d{1,2})?)",
    re.IGNORECASE,
)
AMOUNT_WITH_TVA_RATE = re.compile(
    r"TVA.*?(\d[\d\s]*(?:[.,]\d{1,2})?)\s*(?:RON|LEI|lei|Eur|EUR)", re.IGNORECASE
)
AMOUNT_FALLBACK = re.compile(r"(\d[\d\s]*(?:[.,]\d{1,2})?)\s*(?:RON|LEI|lei|Eur|EUR)")
DATE_PATTERN = re.compile(
    r"\b(0[1-9]|[12]\d|3[01])[./](0[1-9]|1[0-2])[./](20\d{2})\b"
)
SCADENTA_LABEL = re.compile(r"scaden[ţt][aă]", re.IGNORECASE)
TOTAL_LABEL = re.compile(r"\btotal\b(?!\s*(?:tva|net))", re.IGNORECASE)
TVA_LABEL = re.compile(r"\btva\b", re.IGNORECASE)
SUBTOTAL_LABEL = re.compile(r"\bsubtotal\b|^[ \t]*valoare\b", re.IGNORECASE)
EMITENT_LABEL = re.compile(
    r"(?:furnizor|emitent|prestator|vânzător|vanzator|societatea)\s*[:\s]+(.+?)(?:\n|$)",
    re.IGNORECASE,
)


@dataclass
class InvoiceFields:
    emitent: str | None = None
    cui: str | None = None
    client: str | None = None
    nr_factura: str | None = None
    data_emitere: str | None = None
    scadenta: str | None = None
    subtotal: float | None = None
    tva: float | None = None
    total: float | None = None
    iban: str | None = None
    links: List[str] = field(default_factory=list)
    qr_payloads: List[str] = field(default_factory=list)
    lines: List[dict] = field(default_factory=list)
    raw_text: str = ""


def _normalize_cui(raw: str) -> str:
    return re.sub(r"\D", "", raw)


def _parse_ro_amount(raw: str) -> float | None:
    cleaned = raw.strip()
    if not cleaned:
        return None
    cleaned = re.sub(r"[^\d,.\-]", "", cleaned)
    if not cleaned:
        return None
    has_comma = "," in cleaned
    has_dot = "." in cleaned
    if has_comma and has_dot:
        cleaned = cleaned.replace(".", "").replace(",", ".")
    elif has_comma:
        cleaned = cleaned.replace(",", ".")
    elif has_dot:
        cleaned = cleaned.replace(" ", "")
    try:
        return round(float(cleaned), 2)
    except (ValueError, TypeError):
        return None


def _parse_amounts(text: str) -> dict:
    amounts = {"subtotal": [], "tva": [], "total": []}
    lines = text.split("\n")
    for i, line in enumerate(lines):
        lower = line.strip().lower()
        if not lower:
            continue
        if TVA_LABEL.search(lower) and "total" not in lower:
            matched = False
            for match in AMOUNT_WITH_TVA_RATE.finditer(line):
                val = _parse_ro_amount(match.group(1))
                if val is not None:
                    amounts["tva"].append(val)
                    matched = True
                    break
            if not matched:
                for match in AMOUNT_PATTERN.finditer(line):
                    val = _parse_ro_amount(match.group(1))
                    if val is not None:
                        amounts["tva"].append(val)
                        matched = True
                        break
            if not matched:
                for match in AMOUNT_FALLBACK.finditer(line):
                    val = _parse_ro_amount(match.group(1))
                    if val is not None:
                        amounts["tva"].append(val)
                        break
        if SUBTOTAL_LABEL.search(lower):
            for match in AMOUNT_PATTERN.finditer(line):
                val = _parse_ro_amount(match.group(1))
                if val is not None:
                    amounts["subtotal"].append(val)
                    break
            if not amounts["subtotal"]:
                for match in AMOUNT_FALLBACK.finditer(line):
                    val = _parse_ro_amount(match.group(1))
                    if val is not None:
                        amounts["subtotal"].append(val)
                        break
        if TOTAL_LABEL.search(lower) and "net" not in lower:
            for match in AMOUNT_PATTERN.finditer(line):
                val = _parse_ro_amount(match.group(1))
                if val is not None:
                    amounts["total"].append(val)
                    break
            if not amounts["total"]:
                for match in AMOUNT_FALLBACK.finditer(line):
                    val = _parse_ro_amount(match.group(1))
                    if val is not None:
                        amounts["total"].append(val)
                        break
    return amounts


def _extract_scadenta(text: str) -> str | None:
    lines = text.split("\n")
    for i, line in enumerate(lines):
        if SCADENTA_LABEL.search(line):
            for match in DATE_PATTERN.finditer(line):
                return _normalize_date(match.group(0))
            if i + 1 < len(lines):
                for match in DATE_PATTERN.finditer(lines[i + 1]):
                    return _normalize_date(match.group(0))
    return None


def _normalize_date(raw: str) -> str:
    parts = re.split(r"[./]", raw)
    if len(parts) == 3:
        return f"{parts[2]}-{parts[1]}-{parts[0]}"
    return raw


def _extract_dates(text: str) -> list[str]:
    dates = []
    for match in DATE_PATTERN.finditer(text):
        dates.append(_normalize_date(match.group(0)))
    return dates


def parse_invoice(
    ocr_text: str,
    pdf_links: list[str] | None = None,
    qr_payloads: list[str] | None = None,
) -> InvoiceFields:
    text = ocr_text.strip()
    if not text:
        return InvoiceFields(raw_text="")

    # CUI
    cui_match = CUI_PATTERN.search(text)
    cui = _normalize_cui(cui_match.group(0)) if cui_match else None

    # IBAN
    iban_match = IBAN_PATTERN.search(text)
    iban = iban_match.group(0).upper().replace(" ", "") if iban_match else None

    # Emitent
    emit_match = EMITENT_LABEL.search(text)
    emitent = emit_match.group(1).strip() if emit_match else None

    # Dates
    all_dates = _extract_dates(text)
    data_emitere = all_dates[0] if len(all_dates) > 0 else None
    scadenta = _extract_scadenta(text) or (all_dates[1] if len(all_dates) > 1 else None)

    # Amounts
    amounts = _parse_amounts(text)
    subtotal = amounts["subtotal"][0] if amounts["subtotal"] else None
    tva = amounts["tva"][0] if amounts["tva"] else None
    total = amounts["total"][0] if amounts["total"] else None

    nr_factura_match = re.search(
        r"(?:nr[. ]?factur[ai]|serie|număr|numar|factura nr)\s*[.:\s]*\s*(\S+)",
        text,
        re.IGNORECASE,
    )
    nr_factura = nr_factura_match.group(1).strip().rstrip(".") if nr_factura_match else None

    return InvoiceFields(
        emitent=emitent,
        cui=cui,
        nr_factura=nr_factura,
        data_emitere=data_emitere,
        scadenta=scadenta,
        subtotal=subtotal,
        tva=tva,
        total=total,
        iban=iban,
        links=pdf_links or [],
        qr_payloads=qr_payloads or [],
        raw_text=text,
    )
