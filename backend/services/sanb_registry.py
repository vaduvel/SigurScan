from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


SANB_SOURCE_URL = "https://www.transfond.ro/pdf/Lista_bancilor_care_ofera_SANB.pdf"
SANB_SOURCE_ACCESSED_AT = "2026-06-15"


@dataclass(frozen=True)
class SanbParticipant:
    bank_code: str
    bic: str
    institution: str
    source_url: str = SANB_SOURCE_URL
    source_accessed_at: str = SANB_SOURCE_ACCESSED_AT


# Snapshot Transfond SANB, mapped to the 4-character Romanian IBAN bank identifier
# used by iban_validator. Some institutions expose a BIC in the Transfond PDF that
# differs from the common IBAN bank identifier seen in customer invoices; keep
# aliases conservative and source-backed where possible.
SANB_PARTICIPANTS_BY_BANK_CODE: dict[str, SanbParticipant] = {
    "BREL": SanbParticipant("BREL", "BRELROBU", "LIBRA INTERNET BANK S.A."),
    "LIBL": SanbParticipant("LIBL", "BRELROBU", "LIBRA INTERNET BANK S.A."),
    "INGB": SanbParticipant("INGB", "INGBROBU", "ING BANK N.V., AMSTERDAM - SUCURSALA BUCURESTI"),
    "CECE": SanbParticipant("CECE", "CECEROBU", "CEC BANK S.A."),
    "ROIN": SanbParticipant("ROIN", "ROINROBU", "SALT BANK S.A."),
    "RNCB": SanbParticipant("RNCB", "RNCBROBU", "BANCA COMERCIALA ROMANA S.A."),
    "MIND": SanbParticipant("MIND", "MINDROBU", "BANCA ROMANA DE CREDITE SI INVESTITII S.A."),
    "EGNA": SanbParticipant("EGNA", "EGNAROBX", "VISTA BANK (ROMANIA) S.A."),
    "BTRL": SanbParticipant("BTRL", "BTRLRO22", "BANCA TRANSILVANIA S.A."),
    "CARP": SanbParticipant("CARP", "CARPRO22", "PATRIA BANK S.A."),
    "CRCO": SanbParticipant("CRCO", "CRCOROBU", "BANCA CENTRALA COOPERATISTA CREDITCOOP"),
    "BFER": SanbParticipant("BFER", "BFERROBU", "TECHVENTURES BANK S.A."),
    "HURD": SanbParticipant("HURD", "BFERROBU", "TECHVENTURES BANK S.A."),
    "BACX": SanbParticipant("BACX", "BACXROBU", "UNICREDIT BANK S.A."),
    "BRDE": SanbParticipant("BRDE", "BRDEROBU", "BRD - GROUPE SOCIETE GENERALE S.A."),
    "FNNB": SanbParticipant("FNNB", "FNNBROBU", "NEXENT BANK N.V. AMSTERDAM SUCURSALA BUCURESTI"),
    "BRMA": SanbParticipant("BRMA", "BRMAROBU", "EXIM BANCA ROMANEASCA"),
    "EXIM": SanbParticipant("EXIM", "BRMAROBU", "EXIM BANCA ROMANEASCA"),
    "RZBR": SanbParticipant("RZBR", "RZBRROBU", "RAIFFEISEN BANK S.A."),
    "WBAN": SanbParticipant("WBAN", "WBANRO22", "BANCA COMERCIALA INTESA SANPAOLO ROMANIA S.A."),
    "INTL": SanbParticipant("INTL", "WBANRO22", "BANCA COMERCIALA INTESA SANPAOLO ROMANIA S.A."),
    "BLOM": SanbParticipant("BLOM", "BLOMROBU", "BANQUE BANORIENT FRANCE S.A. SUCURSALA ROMANIA"),
    "REVO": SanbParticipant("REVO", "REVOROBB", "REVOLUT BANK UAB VILNIUS SUCURSALA BUCURESTI"),
    "TRPC": SanbParticipant("TRPC", "TRPCROB2", "TRANSFER RAPID ELECTRONIC SRL"),
    "MIRO": SanbParticipant("MIRO", "MIROROBU", "PROCREDIT BANK S.A."),
    "PROC": SanbParticipant("PROC", "MIROROBU", "PROCREDIT BANK S.A."),
}


def lookup_sanb_participant(bank_code: Optional[str]) -> Optional[SanbParticipant]:
    if not bank_code:
        return None
    return SANB_PARTICIPANTS_BY_BANK_CODE.get(str(bank_code).strip().upper())
