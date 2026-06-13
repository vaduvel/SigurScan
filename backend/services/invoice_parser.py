from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List

CUI_PATTERN = re.compile(r"(?:CUI|CIF|RO)\s*[:\s]*(\d{2,10})\b", re.IGNORECASE)
# Bug#9: IBAN-ul RO are lungime fixă de 24 caractere (RO + 2 cifre de control +
# 20 alfanumerice). {20,24} permitea 24-28 caractere total, capturând text de
# după IBAN ca parte din el.
IBAN_PATTERN = re.compile(r"RO\d{2}[A-Z0-9]{20}", re.IGNORECASE)
MONTHS = {
    "january": "01",
    "jan": "01",
    "february": "02",
    "feb": "02",
    "march": "03",
    "mar": "03",
    "april": "04",
    "apr": "04",
    "may": "05",
    "june": "06",
    "jun": "06",
    "july": "07",
    "jul": "07",
    "august": "08",
    "aug": "08",
    "september": "09",
    "sep": "09",
    "sept": "09",
    "october": "10",
    "oct": "10",
    "november": "11",
    "nov": "11",
    "december": "12",
    "dec": "12",
}
CURRENCY_SYMBOLS = {"€": "EUR", "$": "USD", "£": "GBP"}
CURRENCY_PATTERN = re.compile(r"\b(RON|LEI|EUR|USD|GBP)\b|[€$£]", re.IGNORECASE)
# Bug#1 (capătul end-to-end): un număr poate avea grupe de mii separate prin
# punct/virgulă/spațiu (1.260 / 1 500 / 1,234,567) urmate opțional de 2 zecimale.
# Vechiul `\d[\d\s]*(?:[.,]\d{1,2})?` trunchia "1.260" la "1.26" înainte ca
# _parse_ro_amount să apuce să dezambiguizeze separatorul. Întâi forma cu grupe,
# apoi forma simplă; _parse_ro_amount decide RO vs EN pe șirul complet.
_AMOUNT_NUM = r"\d+(?:[.,\s]\d{3})+(?:[.,]\d{1,2})?|\d+(?:[.,]\d{1,2})?"
AMOUNT_VALUE_PATTERN = re.compile(
    r"(?:[€$£]\s*(" + _AMOUNT_NUM + r"))"
    r"|(?:(" + _AMOUNT_NUM + r")\s*(?:RON|LEI|lei|EUR|USD|GBP|€|\$|£))",
    re.IGNORECASE,
)
AMOUNT_PATTERN = re.compile(
    r"(?:Total|TVA|Tax|Subtotal|Amount due|Total due|Balance due|Suma|Valoare|Plata|De plata)\s*(?:factur[ai]|plat[iă]|)?[:\s]*"
    r"(" + _AMOUNT_NUM + r")",
    re.IGNORECASE,
)
AMOUNT_WITH_TVA_RATE = re.compile(
    r"(?:TVA|Tax).*?(" + _AMOUNT_NUM + r")\s*(?:RON|LEI|lei|Eur|EUR|USD|GBP|€|\$|£)", re.IGNORECASE
)
AMOUNT_FALLBACK = re.compile(r"(" + _AMOUNT_NUM + r")\s*(?:RON|LEI|lei|Eur|EUR|USD|GBP|€|\$|£)")
DATE_PATTERN = re.compile(
    r"\b(0[1-9]|[12]\d|3[01])[./](0[1-9]|1[0-2])[./](20\d{2})\b"
)
MONTH_DATE_PATTERN = re.compile(
    r"\b("
    r"Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|"
    r"Jul(?:y)?|Aug(?:ust)?|Sep(?:t|tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?"
    r")\s+([0-3]?\d),\s*(20\d{2})\b",
    re.IGNORECASE,
)
# Bug#11: facturile RO scriu data ca „15 ianuarie 2026" (zi, lună în română, an)
# — ordine inversă față de formatul englezesc „January 15, 2026" și fără virgulă.
RO_MONTHS = {
    "ianuarie": "01", "februarie": "02", "martie": "03", "aprilie": "04",
    "mai": "05", "iunie": "06", "iulie": "07", "august": "08",
    "septembrie": "09", "octombrie": "10", "noiembrie": "11", "decembrie": "12",
}
RO_MONTH_DATE_PATTERN = re.compile(
    r"\b([0-3]?\d)\s+(" + "|".join(RO_MONTHS.keys()) + r")\s+(20\d{2})\b",
    re.IGNORECASE,
)
SCADENTA_LABEL = re.compile(r"scaden[ţt][aă]|\bdue date\b|\bdate due\b|\bpayment due\b", re.IGNORECASE)
ISSUE_DATE_LABEL = re.compile(r"\bdata\b|\bdate of issue\b|\bissued on\b|\binvoice date\b", re.IGNORECASE)
TOTAL_LABEL = re.compile(r"\btotal\b(?!\s*(?:tva|net))|\bamount due\b|\bbalance due\b|\btotal due\b", re.IGNORECASE)
TVA_LABEL = re.compile(r"\btva\b|\btax\b", re.IGNORECASE)
SUBTOTAL_LABEL = re.compile(r"\bsubtotal\b|^[ \t]*valoare\b|\btotal excluding tax\b", re.IGNORECASE)
EMITENT_LABEL = re.compile(
    r"(?:furnizor|emitent|prestator|vânzător|vanzator|societatea)\s*[:\s]+(.+?)(?:\n|$)",
    re.IGNORECASE,
)
EMITENT_SKIP_LINE = re.compile(
    r"^(?:"
    r"invoice|invoice\s+(?:number|no\.?|#)|date(?:\s+of\s+issue|\s+due)?|issued\s+on|due\s+date|"
    r"bill\s+to|pay\s+online|description|qty|unit\s+price|subtotal|tax|total|amount\s+due|"
    r"payment|address|customer|client|page\s+\d+|united\s+states|romania|"
    r"cui|cif|ro|nr\.?\s|factura|data|scaden|perioada|cod|seria|stimate|tva|iban|tel"
    r")\b",
    re.IGNORECASE,
)


@dataclass
class InvoiceFields:
    emitent: str | None = None
    cui: str | None = None
    nr_factura: str | None = None
    data_emitere: str | None = None
    scadenta: str | None = None
    subtotal: float | None = None
    tva: float | None = None
    total: float | None = None
    currency: str | None = None
    invoice_profile: str = "ro"
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
        # Ultimul separator întâlnit este zecimalul; celălalt = separator de mii.
        if cleaned.rfind(",") > cleaned.rfind("."):
            # RO: punct=mii, virgulă=zecimal (1.260,50)
            cleaned = cleaned.replace(".", "").replace(",", ".")
        else:
            # EN: virgulă=mii, punct=zecimal (1,500.00)
            cleaned = cleaned.replace(",", "")
    elif has_comma:
        # O singură virgulă cu exact 3 cifre după = separator de mii (1,500);
        # altfel virgula e zecimalul RO (12,50 / 19,00).
        parts = cleaned.split(",")
        if len(parts) == 2 and len(parts[1]) == 3 and parts[0].lstrip("-").isdigit():
            cleaned = cleaned.replace(",", "")
        else:
            cleaned = cleaned.replace(",", ".")
    elif has_dot:
        # Toate grupele de după prima au exact 3 cifre = separator de mii RO
        # (1.500 / 2.000 / 1.234.567); altfel punctul rămâne zecimal (119.99).
        parts = cleaned.split(".")
        if len(parts) >= 2 and parts[0].lstrip("-").isdigit() and all(
            len(p) == 3 and p.isdigit() for p in parts[1:]
        ):
            cleaned = cleaned.replace(".", "")
    try:
        return round(float(cleaned), 2)
    except (ValueError, TypeError):
        return None


def _extract_amount_values(line: str) -> list[float]:
    values: list[float] = []
    for match in AMOUNT_VALUE_PATTERN.finditer(line):
        raw_value = match.group(1) or match.group(2)
        value = _parse_ro_amount(raw_value)
        if value is not None:
            values.append(value)
    if values:
        return values
    for match in AMOUNT_PATTERN.finditer(line):
        value = _parse_ro_amount(match.group(1))
        if value is not None:
            values.append(value)
    return values


def _detect_currency(text: str) -> str | None:
    for match in CURRENCY_PATTERN.finditer(text):
        token = match.group(0)
        if token in CURRENCY_SYMBOLS:
            return CURRENCY_SYMBOLS[token]
        upper = token.upper()
        if upper == "LEI":
            return "RON"
        return upper
    return None


def _parse_amounts(text: str) -> dict:
    amounts = {"subtotal": [], "tva": [], "total": []}
    lines = text.split("\n")
    for i, line in enumerate(lines):
        lower = line.strip().lower()
        if not lower:
            continue
        values = _extract_amount_values(line)
        next_values = _next_amount_values(lines, i)
        if TVA_LABEL.search(lower) and "total" not in lower:
            if lower in {"tax", "tva"} or "unit price" in lower or lower.startswith("description"):
                continue
            if len(values) > 1:
                amounts["tva"].append(values[-1])
                continue
            if " on " in lower:
                # "Tax (21% on €18.00)" contains the taxable base, not the tax value.
                # Only trust a following value if it is directly attached to the label;
                # otherwise the grouped-summary parser maps the later value block safely.
                immediate_values = _immediate_next_amount_values(lines, i)
                if immediate_values:
                    amounts["tva"].append(immediate_values[-1])
                continue
            if values:
                amounts["tva"].append(values[-1])
                continue
            if next_values:
                amounts["tva"].append(next_values[-1])
                continue
            for match in AMOUNT_WITH_TVA_RATE.finditer(line):
                val = _parse_ro_amount(match.group(1))
                if val is not None:
                    amounts["tva"].append(val)
                    break
        if SUBTOTAL_LABEL.search(lower):
            if values:
                amounts["subtotal"].append(values[-1])
                continue
            if next_values:
                amounts["subtotal"].append(next_values[-1])
                continue
        if TOTAL_LABEL.search(lower) and "net" not in lower and "excluding" not in lower:
            if values:
                amounts["total"].append(values[-1])
                continue
            if next_values:
                amounts["total"].append(next_values[-1])
                continue
    _merge_grouped_summary_amounts(amounts, lines)
    return amounts


def _next_amount_values(lines: list[str], index: int, lookahead: int = 3) -> list[float]:
    for next_line in lines[index + 1 : index + 1 + lookahead]:
        values = _extract_amount_values(next_line)
        if values:
            return values
    return []


def _immediate_next_amount_values(lines: list[str], index: int) -> list[float]:
    for next_line in lines[index + 1 :]:
        if not next_line.strip():
            continue
        return _extract_amount_values(next_line)
    return []


def _summary_label_key(line: str) -> str | None:
    lower = line.strip().lower()
    if not lower:
        return None
    if lower.startswith("subtotal"):
        return "subtotal"
    if lower.startswith("total excluding tax"):
        return "subtotal"
    if lower.startswith(("amount due", "balance due", "total due")):
        return "total"
    if lower == "total":
        return "total"
    if lower.startswith("tax ") or lower.startswith("tax("):
        return "tva"
    if lower.startswith("tva ") or lower.startswith("tva("):
        return "tva"
    return None


def _merge_grouped_summary_amounts(amounts: dict, lines: list[str]) -> None:
    """Handle OCR layouts where summary labels are grouped before their values.

    Some invoice images produce text like:
    Subtotal / Total excluding tax / Tax (...) / Total / Amount due
    ...table headers...
    €18.00 / €18.00 / €3.78 / €21.78 / €21.78

    The final N monetary values after the label cluster correspond to those labels.
    """
    stripped = [line.strip() for line in lines]
    for start, line in enumerate(stripped):
        if _summary_label_key(line) != "subtotal":
            continue
        labels: list[str] = []
        cursor = start
        while cursor < len(stripped):
            key = _summary_label_key(stripped[cursor])
            if key is None:
                break
            labels.append(key)
            cursor += 1
        if len(labels) < 3 or "total" not in labels:
            continue

        trailing_values: list[float] = []
        for next_line in stripped[cursor : cursor + 35]:
            if re.match(r"^page\s+\d+\s+of\s+\d+", next_line, re.IGNORECASE):
                break
            values = _extract_amount_values(next_line)
            if values:
                trailing_values.append(values[-1])
        if len(trailing_values) < len(labels):
            continue

        summary_values = trailing_values[-len(labels) :]
        for key, value in zip(labels, summary_values):
            amounts[key].append(value)
        return


def _dates_from_line(line: str) -> list[str]:
    dates: list[tuple[int, str]] = []
    for match in DATE_PATTERN.finditer(line):
        dates.append((match.start(), _normalize_date(match.group(0))))
    for match in MONTH_DATE_PATTERN.finditer(line):
        dates.append((match.start(), _normalize_month_date(match.group(0))))
    for match in RO_MONTH_DATE_PATTERN.finditer(line):
        dates.append((match.start(), _normalize_ro_month_date(match.group(0))))
    return [date for _, date in sorted(dates, key=lambda item: item[0])]


def _extract_scadenta(text: str) -> str | None:
    lines = text.split("\n")
    for i, line in enumerate(lines):
        if SCADENTA_LABEL.search(line):
            dates = _dates_from_line(line)
            if dates:
                return dates[0]
            if i + 1 < len(lines):
                dates = _dates_from_line(lines[i + 1])
                if dates:
                    return dates[0]
    return None


def _normalize_date(raw: str) -> str:
    parts = re.split(r"[./]", raw)
    if len(parts) == 3:
        return f"{parts[2]}-{parts[1]}-{parts[0]}"
    return raw


def _normalize_month_date(raw: str) -> str:
    match = MONTH_DATE_PATTERN.search(raw)
    if not match:
        return raw
    month = MONTHS[match.group(1).lower()]
    day = int(match.group(2))
    year = match.group(3)
    return f"{year}-{month}-{day:02d}"


def _normalize_ro_month_date(raw: str) -> str:
    match = RO_MONTH_DATE_PATTERN.search(raw)
    if not match:
        return raw
    day = int(match.group(1))
    month = RO_MONTHS[match.group(2).lower()]
    year = match.group(3)
    return f"{year}-{month}-{day:02d}"


def _extract_dates(text: str) -> list[str]:
    dates: list[tuple[int, str]] = []
    for match in DATE_PATTERN.finditer(text):
        dates.append((match.start(), _normalize_date(match.group(0))))
    for match in MONTH_DATE_PATTERN.finditer(text):
        dates.append((match.start(), _normalize_month_date(match.group(0))))
    for match in RO_MONTH_DATE_PATTERN.finditer(text):
        dates.append((match.start(), _normalize_ro_month_date(match.group(0))))
    return [date for _, date in sorted(dates, key=lambda item: item[0])]


def _extract_issue_date(text: str) -> str | None:
    lines = text.split("\n")
    for i, line in enumerate(lines):
        if ISSUE_DATE_LABEL.search(line) and not SCADENTA_LABEL.search(line):
            dates = _dates_from_line(line)
            if dates:
                return dates[0]
            if i + 1 < len(lines):
                dates = _dates_from_line(lines[i + 1])
                if dates:
                    return dates[0]
    return None


def _is_emitent_candidate(line: str) -> bool:
    candidate = line.strip()
    if not candidate:
        return False
    if _dates_from_line(candidate):
        return False
    if EMITENT_SKIP_LINE.search(candidate):
        return False
    if "@" in candidate or "http://" in candidate.lower() or "https://" in candidate.lower():
        return False
    if re.match(r"^[\d\s,./-]+$", candidate):
        return False
    if re.match(r"^\d", candidate):
        return False
    return bool(re.search(r"[A-Za-zĂÂÎȘŞȚŢăâîșşțţ]{3,}", candidate))


def _extract_invoice_number(text: str) -> str | None:
    patterns = [
        r"\binvoice\s+(?:number|no\.?|#)\s*[:#]?\s*([A-Z0-9][A-Z0-9._/-]+)",
        r"\bfactura\s+seri[aă]\s+\S+\s*/\s*nr[.\s]*\s*([A-Z0-9][A-Z0-9._/-]+)",
        r"\bseri[aă]\s+\S+\s+nr[.\s]*\s*([A-Z0-9][A-Z0-9._/-]+)",
        r"\bnr[.\s]*factur[ai]\s*[.:\s]*\s*([A-Z0-9][A-Z0-9._/-]+)",
        r"\bnum[aă]r[.\s]*factur[ăa]\s*[.:\s]*\s*([A-Z0-9][A-Z0-9._/-]+)",
        r"\bfactura\s+nr[.\s]*[:#]?\s*([A-Z0-9][A-Z0-9._/-]+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(1).strip().rstrip(".,")
    return None


def _detect_invoice_profile(cui: str | None, iban: str | None, currency: str | None, text: str) -> str:
    if cui or (iban and iban.upper().startswith("RO")):
        return "ro"
    if currency and currency != "RON":
        return "international"
    if re.search(r"\binvoice\b|\bdate of issue\b|\bissued on\b|\bamount due\b|\bbill to\b", text, re.IGNORECASE):
        return "international"
    return "ro"


def parse_invoice(
    ocr_text: str,
    pdf_links: list[str] | None = None,
    qr_payloads: list[str] | None = None,
) -> InvoiceFields:
    text = ocr_text.strip()
    if not text:
        return InvoiceFields(raw_text="")

    # CUI — group(1) e cifrele propriu-zise; group(0) include prefixul CUI/CIF/RO.
    cui_match = CUI_PATTERN.search(text)
    cui = _normalize_cui(cui_match.group(1)) if cui_match else None

    # IBAN
    iban_match = IBAN_PATTERN.search(text)
    iban = iban_match.group(0).upper().replace(" ", "") if iban_match else None

    # Emitent
    emit_match = EMITENT_LABEL.search(text)
    emitent = emit_match.group(1).strip() if emit_match else None
    if not emitent:
        for line in text.split("\n")[:15]:
            line = line.strip()
            if _is_emitent_candidate(line):
                emitent = line
                break

    # Dates
    all_dates = _extract_dates(text)
    data_emitere = _extract_issue_date(text) or (all_dates[0] if len(all_dates) > 0 else None)
    scadenta = _extract_scadenta(text) or (all_dates[1] if len(all_dates) > 1 else None)

    # Amounts
    amounts = _parse_amounts(text)
    # Bug#12: subtotal/tva foloseau primul element, total ultimul — pe facturi
    # cu mai multe linii "Subtotal"/"TVA" (ex. un subtotal pe produse urmat de
    # subtotalul real de sumar), valorile comparate de coerență veneau din
    # rânduri diferite și nu se mai aliniau cu total. Ultimul element e cel
    # din blocul de sumar final, alături de total.
    subtotal = amounts["subtotal"][-1] if amounts["subtotal"] else None
    tva = amounts["tva"][-1] if amounts["tva"] else None
    total = amounts["total"][-1] if amounts["total"] else None
    currency = _detect_currency(text)

    nr_factura = _extract_invoice_number(text)
    invoice_profile = _detect_invoice_profile(cui, iban, currency, text)

    return InvoiceFields(
        emitent=emitent,
        cui=cui,
        nr_factura=nr_factura,
        data_emitere=data_emitere,
        scadenta=scadenta,
        subtotal=subtotal,
        tva=tva,
        total=total,
        currency=currency,
        invoice_profile=invoice_profile,
        iban=iban,
        links=pdf_links or [],
        qr_payloads=qr_payloads or [],
        raw_text=text,
    )
