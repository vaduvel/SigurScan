from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import List

CUI_PATTERN = re.compile(
    r"(?:\b(?:CUI|CIF)\s*[:\s]*(?:RO\s*)?(?P<label>\d{2,10})\b|"
    r"\bRO\s*(?P<bare>\d{5,10})\b)",
    re.IGNORECASE,
)
# Bug#9: IBAN-ul RO are lungime fixă de 24 caractere (RO + 2 cifre de control +
# 20 alfanumerice). {20,24} permitea 24-28 caractere total, capturând text de
# după IBAN ca parte din el.
IBAN_PATTERN = re.compile(r"RO\d{2}[A-Z0-9]{20}", re.IGNORECASE)
ANY_IBAN_PATTERN = re.compile(
    r"\b[A-Z]{2}[ \t-]*\d{2}(?:[ \t-]*[A-Z0-9]){11,30}\b",
    re.IGNORECASE,
)
RO_IBAN_OCR_PATTERN = re.compile(
    r"\bR[0O][ \t-]*\d{2}(?:[ \t-]*[A-Z0-9]){20}\b",
    re.IGNORECASE,
)
BENEFICIAR_EXPLICIT_PATTERN = re.compile(
    r"^[ \t]*(?:nume[ \t]+)?(?:"
    r"beneficiar(?:ul|ului)?(?:[ \t]+(?:plat[ăa]|plata|cont|final))?|"
    r"titular(?:ul|ului)?(?:[ \t]+cont)?"
    r")[ \t]*[:\-]?[ \t]*([^\n\r,;]+)",
    re.IGNORECASE | re.MULTILINE,
)
BENEFICIAR_CONTEXT_PATTERN = re.compile(
    r"(?:c[ăa]tre|in[ \t]*contul(?:[ \t]*lui)?|[iî]n[ \t]*contul(?:[ \t]*lui)?)"
    r"[ \t]*[:\-]?[ \t]*([^\n\r,;]+)",
    re.IGNORECASE,
)
# Numele băncii tipărit pe factură ("Banca: BRD", "Banca Transilvania",
# "Bank name: ..."). Folosit de bank_name_crosscheck pentru a compara banca
# afișată cu banca implicată de codul IBAN.
BANK_LABEL_PATTERN = re.compile(
    r"\b(?:banc[ăa](?:\s+(?:beneficiar(?:ului)?|emitent(?:ului)?))?|bank(?:\s+name)?)\b"
    r"\s*[:\-]?\s*([^\n\r,;]+)",
    re.IGNORECASE,
)
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
BARE_AMOUNT_VALUE_PATTERN = re.compile(r"^\s*(" + _AMOUNT_NUM + r")\s*$", re.IGNORECASE)
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
SUBTOTAL_LABEL = re.compile(
    r"\bsubtotal\b|\bvaloare[ \t]+(?:net[ăa]|f[ăa]r[ăa][ \t]+tva|fara[ \t]+tva)\b|"
    r"^[ \t]*valoare[ \t]*(?::|[€$£]?\d)|\btotal excluding tax\b|\bnet amount\b",
    re.IGNORECASE,
)
QUALIFIED_SUBTOTAL_LABEL = re.compile(
    r"\bsubtotal\b|\bvaloare[ \t]+(?:net[ăa]|f[ăa]r[ăa][ \t]+tva|fara[ \t]+tva)\b|"
    r"\btotal excluding tax\b|\bnet amount\b",
    re.IGNORECASE,
)
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
    all_ibans: List[str] = field(default_factory=list)
    payment_beneficiary: str | None = None
    links: List[str] = field(default_factory=list)
    qr_payloads: List[str] = field(default_factory=list)
    lines: List[dict] = field(default_factory=list)
    raw_text: str = ""
    printed_bank_name: str | None = None


def _normalize_cui(raw: str) -> str:
    return re.sub(r"\D", "", raw)


def _cui_from_match(match: re.Match[str] | None) -> str | None:
    if not match:
        return None
    return _normalize_cui(match.group("label") or match.group("bare") or "")


def _extract_all_ibans(text: str) -> List[str]:
    from services.iban_validator import IBAN_LENGTH_BY_COUNTRY, normalize_iban, validate_iban

    seen: set[str] = set()
    output: List[str] = []
    candidates_raw = [match.group(0) for match in ANY_IBAN_PATTERN.finditer(text or "")]
    for match in RO_IBAN_OCR_PATTERN.finditer(text or ""):
        raw = match.group(0)
        normalized_raw = re.sub(r"[\s-]+", "", raw).upper()
        if normalized_raw.startswith("R0"):
            candidates_raw.append("RO" + normalized_raw[2:])
    for raw in candidates_raw:
        normalized = normalize_iban(raw)
        if not normalized:
            continue
        candidates = [normalized]
        expected_len = IBAN_LENGTH_BY_COUNTRY.get(normalized[:2])
        if expected_len and len(normalized) > expected_len:
            candidates.append(normalized[:expected_len])
        for candidate in candidates:
            if candidate in seen:
                continue
            if validate_iban(candidate).valid_structure:
                seen.add(candidate)
                output.append(candidate)
                break
    return output


def _extract_cui(text: str) -> str | None:
    cui = _cui_from_match(CUI_PATTERN.search(text))
    if cui:
        return cui

    lines = [line.strip() for line in (text or "").splitlines()]
    label_re = re.compile(r"^(?:CUI|CIF)\s*:?\s*$", re.IGNORECASE)
    numeric_re = re.compile(r"^(?:RO\s*)?(\d{2,10})\b", re.IGNORECASE)
    for i, line in enumerate(lines[:-1]):
        if not label_re.match(line):
            continue
        for next_line in lines[i + 1 : i + 4]:
            match = numeric_re.search(next_line)
            if match:
                return _normalize_cui(match.group(1))
            if next_line and not re.match(r"^(?:reg\.?\s*com|adres[ăa]|iban|banca|swift)\b", next_line, re.IGNORECASE):
                break
    return None


# R2 — zonă emitent vs client. Când o factură are MAI MULTE CUI-uri, extractorul
# curent ia primul din text, care poate fi al clientului (dacă blocul client apare
# primul). Segmentarea preferă CUI-ul din zona emitentului. Gated INVOICE_ZONE_CUI
# (default OFF); pentru un singur CUI / zonă neclară => comportamentul curent.
_EMITTER_ZONE_RE = re.compile(
    r"\b(?:furnizor|emitent|prestator|v[âa]nz[ăa]tor|societatea)\b", re.IGNORECASE
)
_CLIENT_ZONE_RE = re.compile(
    r"\b(?:client|cump[ăa]r[ăa]tor|c[ăa]tre|delegat)\b", re.IGNORECASE
)


def _zone_cui_enabled() -> bool:
    return os.getenv("INVOICE_ZONE_CUI", "0").strip().lower() in {"1", "true", "yes", "on"}


def _nearest_preceding_zone(text: str, pos: int) -> str | None:
    """'emitter'/'client'/None = kind of the last zone label before ``pos``."""
    best_pos, best_kind = -1, None
    head = text[:pos]
    for m in _EMITTER_ZONE_RE.finditer(head):
        if m.start() > best_pos:
            best_pos, best_kind = m.start(), "emitter"
    for m in _CLIENT_ZONE_RE.finditer(head):
        if m.start() > best_pos:
            best_pos, best_kind = m.start(), "client"
    return best_kind


def _extract_cui_zone_aware(text: str) -> str | None:
    if not _zone_cui_enabled():
        return _extract_cui(text)
    positioned = [
        (m.start(), c)
        for m in CUI_PATTERN.finditer(text or "")
        if (c := _cui_from_match(m))
    ]
    if len({c for _, c in positioned}) <= 1:
        return _extract_cui(text)  # single/none -> unchanged
    # Multiple CUIs: prefer the first whose nearest preceding label is the emitter.
    for pos, cui in positioned:
        if _nearest_preceding_zone(text, pos) == "emitter":
            return cui
    return _extract_cui(text)  # no clear emitter zone -> conservative fallback


def _normalize_lookup_text(value: str) -> str:
    return value.lower().translate(str.maketrans("ăâîșşțţ", "aaisstt"))


def _clean_payment_beneficiary_candidate(raw: str) -> str | None:
    candidate = re.split(
        r"[ \t]+(?:IBAN|CUI|CIF|SWIFT|BIC|banc[ăa]|bank)[ \t]*[:\-]?",
        raw,
        maxsplit=1,
        flags=re.IGNORECASE,
    )[0].strip(" \t\r\n.:-")
    if len(candidate) < 3:
        return None
    if ANY_IBAN_PATTERN.search(candidate) or re.fullmatch(r"[\d\s./-]+", candidate):
        return None
    normalized = _normalize_lookup_text(candidate)
    if normalized in {"iban", "cont", "cont bancar", "cui", "cif", "factura"}:
        return None
    if re.fullmatch(
        r"(?:(?:beneficiar(?:ul|ului)?|titular(?:ul|ului)?|cont(?:ul|ului)?)[ -]+)?"
        r"(?:(?:indicat|mentionat|specificat)(?:[ -]+(?:mai sus|in factura|din factura))?|"
        r"de mai sus|din factura)",
        normalized,
    ):
        return None
    if not re.search(r"[A-Za-zĂÂÎȘŞȚŢăâîșşțţ]{2,}", candidate):
        return None
    return candidate


def _extract_payment_beneficiary(text: str) -> str | None:
    source = text or ""
    # An explicit field label is stronger evidence than prose such as
    # "plătiți către beneficiarul indicat", regardless of document order.
    for pattern in (BENEFICIAR_EXPLICIT_PATTERN, BENEFICIAR_CONTEXT_PATTERN):
        for match in pattern.finditer(source):
            candidate = _clean_payment_beneficiary_candidate(match.group(1))
            if candidate:
                return candidate
    return None


def _extract_printed_bank_name(text: str) -> str | None:
    match = BANK_LABEL_PATTERN.search(text or "")
    if not match:
        return None
    candidate = match.group(1)
    candidate = IBAN_PATTERN.sub("", candidate)
    candidate = ANY_IBAN_PATTERN.sub("", candidate)
    candidate = candidate.strip(" \t\r\n.:-")
    if len(candidate) < 2:
        return None
    if not re.search(r"[A-Za-zĂÂÎȘŞȚŢăâîșşțţ]{2,}", candidate):
        return None
    if candidate.lower() in {"iban", "cont", "cont bancar", "swift", "cod"}:
        return None
    return candidate


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


def _extract_bare_amount_values(line: str) -> list[float]:
    """Extract a standalone amount when a previous label gives the context.

    OCR often emits "Total:" and the value on the next line without currency
    (the Altex card-receipt layout). Kept separate from the general amount
    extractor so table row quantities do not become money unless a caller is
    explicitly in label lookahead mode.
    """
    match = BARE_AMOUNT_VALUE_PATTERN.match(line or "")
    if not match:
        return []
    value = _parse_ro_amount(match.group(1))
    return [value] if value is not None else []


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
        is_subtotal = bool(SUBTOTAL_LABEL.search(lower))
        if is_subtotal:
            if values:
                amounts["subtotal"].append(values[-1])
                continue
            # Bare "Valoare" is commonly a table header. Only qualified
            # summary labels are allowed to borrow a value from a later line.
            if QUALIFIED_SUBTOTAL_LABEL.search(lower) and next_values:
                amounts["subtotal"].append(next_values[-1])
            continue
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
        values = _extract_bare_amount_values(next_line)
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


def _plausible_invoice_number(candidate: str, *, heading: bool = False) -> bool:
    # Un număr de factură conține practic întotdeauna cel puțin o cifră. Fără
    # guard, pe layout-uri OCR pe coloane ("Număr factură  Data emiterii" cu
    # valorile pe rândul următor) `\s` traversează newline-ul și capturează
    # următorul CUVÂNT-etichetă ("Data") drept număr — un câmp corupt silențios,
    # mai rău decât unul lipsă.
    if not candidate or len(candidate) > 64 or not any(ch.isdigit() for ch in candidate):
        return False
    if not re.fullmatch(r"[A-Z0-9][A-Z0-9._/-]*(?:[ \t]+[A-Z0-9][A-Z0-9._/-]*){0,2}", candidate, re.IGNORECASE):
        return False
    tokens = {_normalize_lookup_text(token).strip("._/-") for token in candidate.split()}
    descriptive_tokens = {
        "copie", "curenta", "data", "exemplar", "fiscala", "original", "proforma",
        "restanta", "scadenta", "storno", "zile",
    }
    if tokens & descriptive_tokens:
        return False
    if heading:
        compact = re.sub(r"\s+", "", candidate)
        # A bare four-digit year is too ambiguous after the word "Factura".
        if compact.isdigit() and len(compact) < 6:
            return False
    return True


def _clean_invoice_number_candidate(raw: str, *, allow_spaces: bool = False, heading: bool = False) -> str | None:
    candidate = re.split(
        r"[ \t]+(?:din|data|date|emis[ăa]?|issued|scaden[țt][ăa]?|due|total)\b",
        raw,
        maxsplit=1,
        flags=re.IGNORECASE,
    )[0].strip(" \t\r\n,;:#")
    candidate = re.sub(r"[ \t]+", " ", candidate).rstrip(".")
    if not allow_spaces and re.search(r"[ \t]", candidate):
        candidate = candidate.split()[0]
    return candidate if _plausible_invoice_number(candidate, heading=heading) else None


def _extract_invoice_number(text: str) -> str | None:
    patterns = [
        r"\binvoice\s+(?:number|no\.?|#)\s*[:#]?\s*([A-Z0-9][A-Z0-9._/-]+)",
        r"\bfactura\s+seri[aă]\s+\S+\s*/\s*nr[.\s]*\s*([A-Z0-9][A-Z0-9._/-]+)",
        r"\bseri[aă]\s+\S+\s+nr[.\s]*\s*([A-Z0-9][A-Z0-9._/-]+)",
        r"\bnr[.\s]*factur(?:a|ă|ii)\s*[.:\s]*\s*([A-Z0-9][A-Z0-9._/-]+)",
        r"\bnum[aă]r(?:ul)?[.\s]*factur(?:a|ă|ii)\s*[.:\s]*\s*([A-Z0-9][A-Z0-9._/-]+)",
        r"\bfactura\s+nr[.\s]*[:#]?\s*([A-Z0-9][A-Z0-9._/-]+)",
        r"^\s*seri[eaă]?\s*/\s*num[aă]r\s*[:#.]?\s*([A-Z0-9][A-Z0-9._/-]+)",
        r"^\s*factur[ăa]\s*[:#]\s*([A-Z0-9][A-Z0-9._/-]+)",
    ]
    lines = [line.strip() for line in (text or "").splitlines()]
    for line in lines:
        for pattern in patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                candidate = _clean_invoice_number_candidate(match.group(1))
                if candidate:
                    return candidate
    # Layout pe coloane/etichetă singură pe rând: valoarea vine pe unul din
    # rândurile imediat următoare (lookahead 3, ca la sume).
    label_re = re.compile(
        r"^(?:"
        r"serie\s*(?:(?:si|și|şi)\s*)?(?:nr\.?|num[aă]r)|"
        r"nr\.?\s*factur(?:a|ă|ii)|num[aă]r(?:ul)?\s*factur(?:a|ă|ii)|"
        r"invoice\s*(?:number|no\.?|#)"
        r")\s*[:#.]?\s*$",
        re.IGNORECASE,
    )
    value_re = re.compile(r"^[A-Z0-9][A-Z0-9._/-]{2,}$", re.IGNORECASE)
    for i, line in enumerate(lines[:-1]):
        if not label_re.match(line):
            continue
        for next_line in lines[i + 1 : i + 4]:
            raw_candidate = next_line.strip().rstrip(".,")
            candidate = _clean_invoice_number_candidate(raw_candidate)
            if value_re.match(raw_candidate) and candidate:
                return candidate
            if raw_candidate:
                break
    # Compact invoice headings often contain only the document word followed
    # by a series and number (for example "Factura MGH 0013"). Descriptive
    # headings are rejected by the candidate validator above.
    heading_re = re.compile(r"^\s*factur[ăa]?\s+(.+?)\s*$", re.IGNORECASE)
    for line in lines:
        match = heading_re.match(line)
        if not match:
            continue
        candidate = _clean_invoice_number_candidate(match.group(1), allow_spaces=True, heading=True)
        if candidate:
            return candidate
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

    # CUI — Google Vision may split "CIF:" and the numeric value on adjacent lines.
    # R2: emitter-zone aware for multi-CUI invoices (gated INVOICE_ZONE_CUI, OFF => _extract_cui).
    cui = _extract_cui_zone_aware(text)

    # IBAN
    iban_match = IBAN_PATTERN.search(text)
    all_ibans = _extract_all_ibans(text)
    iban = iban_match.group(0).upper().replace(" ", "") if iban_match else None
    if not iban:
        iban = next((candidate for candidate in all_ibans if candidate.startswith("RO")), None)
    payment_beneficiary = _extract_payment_beneficiary(text)
    printed_bank_name = _extract_printed_bank_name(text)

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
        all_ibans=all_ibans,
        payment_beneficiary=payment_beneficiary,
        links=pdf_links or [],
        qr_payloads=qr_payloads or [],
        raw_text=text,
        printed_bank_name=printed_bank_name,
    )
