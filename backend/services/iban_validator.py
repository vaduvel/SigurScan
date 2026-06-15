from __future__ import annotations

from dataclasses import dataclass
from typing import Dict

# Romanian bank BIC codes (first 4 chars after RO) per BNR registry.
RO_BANK_CODES: Dict[str, str] = {
    "TREZ": "Trezoreria Statului",
    "RNCB": "BCR",
    "BTRL": "Banca Transilvania",
    "BRDE": "BRD",
    "INGB": "ING",
    "RZBR": "Raiffeisen",
    "BACX": "UniCredit",
    "CECE": "CEC Bank",
    "CARP": "Carpatica (Neutră)",
    "CRCO": "Creditcoop",
    "DAFB": "Alpha Bank",
    "EXIM": "Exim Banca Românească",
    "BRMA": "Exim Banca Românească",
    "GBRE": "Garanti BBVA",
    "BFER": "Techventures",
    "HURD": "Techventures",
    "INTL": "Intesa Sanpaolo",
    "WBAN": "Intesa Sanpaolo",
    "BREL": "Libra Internet Bank",
    "LIBL": "Libra Internet Bank",
    "MIND": "Banca Română de Credite și Investiții",
    "EGNA": "Vista Bank",
    "MIRB": "MKB Romexterrra",
    "MIRO": "ProCredit Bank",
    "NEGB": "Neutră",
    "PIRB": "First Bank",
    "PORL": "Portofoliu (Neutră)",
    "PROC": "ProCredit",
    "ROIN": "Salt Bank",
    "FNNB": "Nexent Bank",
    "BLOM": "Banque Banorient France",
    "REVO": "Revolut Bank",
    "TRPC": "Transfer Rapid Electronic",
}

IBAN_LENGTH_BY_COUNTRY: Dict[str, int] = {
    "RO": 24,
    "DE": 22,
    "FR": 27,
    "IT": 27,
    "ES": 24,
    "NL": 18,
    "BE": 16,
    "AT": 20,
    "BG": 22,
    "HU": 28,
    "PL": 28,
    "CZ": 24,
    "SK": 24,
    "HR": 21,
    "SI": 19,
}


@dataclass
class IbanResult:
    valid_structure: bool
    bank_code: str | None
    bank_name: str | None
    is_trezorerie: bool


def _mod97(value: str) -> int:
    remainder = 0
    for ch in value:
        remainder = (remainder * 10 + (ord(ch) - ord("0"))) % 97
    return remainder


def normalize_iban(raw: str) -> str | None:
    cleaned = raw.strip().upper().replace(" ", "").replace("-", "")
    if not cleaned:
        return None
    return cleaned


def validate_iban(raw: str) -> IbanResult:
    iban = normalize_iban(raw)
    if not iban:
        return IbanResult(valid_structure=False, bank_code=None, bank_name=None, is_trezorerie=False)
    country = iban[:2]
    expected_len = IBAN_LENGTH_BY_COUNTRY.get(country)
    if not expected_len:
        return IbanResult(valid_structure=False, bank_code=None, bank_name=None, is_trezorerie=False)
    if len(iban) != expected_len:
        return IbanResult(valid_structure=False, bank_code=None, bank_name=None, is_trezorerie=False)
    digits = iban[4:] + iban[:4]
    numeric = "".join(str(ord(ch) - 55) if ch.isalpha() else ch for ch in digits)
    if _mod97(numeric) != 1:
        return IbanResult(valid_structure=False, bank_code=None, bank_name=None, is_trezorerie=False)
    bank_code = iban[4:8] if country == "RO" else None
    bank_name = RO_BANK_CODES.get(bank_code) if bank_code else None
    is_trezorerie = bank_code == "TREZ"
    return IbanResult(
        valid_structure=True,
        bank_code=bank_code,
        bank_name=bank_name,
        is_trezorerie=is_trezorerie,
    )
