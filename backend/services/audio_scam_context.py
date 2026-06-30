"""Privacy-safe scam context for Urechea semantic review.

The audio endpoint sends only redacted transcript text to Mistral. This module
adds SigurScan's call-scam knowledge as compact hints so the model judges the
conversation against known Romanian vishing/social-engineering patterns without
echoing or storing the user's transcript.
"""

from __future__ import annotations

import json
import re
import unicodedata
from pathlib import Path
from typing import Any, Dict, List


_FAMILIES: List[Dict[str, Any]] = [
    {
        "id": "CONV_TRUSTED_CONTACT_MONEY_URGENCY",
        "title": "Contact cunoscut care cere bani urgent",
        "signals": [
            "pretinde ca este coleg, prieten, sef, vecin sau alta persoana cunoscuta",
            "cere bani, imprumut, transfer sau plata rapida",
            "adauga urgenta si/sau cere secret",
        ],
        "danger_levers": ["trusted_contact", "urgency", "secrecy", "money_transfer"],
        "keywords": [
            "coleg",
            "colega",
            "prieten",
            "prietena",
            "sef",
            "sefa",
            "vecin",
            "cunoscut",
            "cunostinta",
            "bani",
            "imprumut",
            "transfer",
            "urgent",
            "repede",
            "imediat",
            "nu spune",
            "nu zice",
            "ramane intre noi",
        ],
    },
    {
        "id": "CONV_BANK_SAFE_ACCOUNT",
        "title": "Banca/autoritate cere mutarea banilor intr-un cont sigur",
        "signals": [
            "pretinde banca, BNR, politie, procuror sau inspector",
            "cere mutarea economiilor intr-un cont sigur/de siguranta",
            "descurajeaza verificarea pe canal oficial",
        ],
        "danger_levers": ["authority", "fear", "safe_account", "anti_verification"],
        "keywords": [
            "banca",
            "bnr",
            "politie",
            "procuror",
            "inspector",
            "cont sigur",
            "cont de siguranta",
            "muta banii",
            "economiile",
            "nu inchide",
            "nu suna",
        ],
    },
    {
        "id": "CONV_BANK_FRAUDULENT_CREDIT",
        "title": "Credit fraudulos / cont compromis",
        "signals": [
            "spune ca exista credit/cerere pe numele victimei",
            "cere coduri, date bancare sau actiuni imediate",
            "foloseste frica de pierdere financiara",
        ],
        "danger_levers": ["authority", "fear", "account_takeover"],
        "keywords": [
            "credit",
            "credit fraudulos",
            "pe numele tau",
            "cont compromis",
            "credit line",
            "creditline",
            "acreditline",
            "crediline",
            "credit aprobat",
            "preaprobat",
            "veste buna",
            "cod sms",
            "cod de verificare",
            "otp",
        ],
    },
    {
        "id": "CONV_BANK_ANTI_FRAUD_CALL",
        "title": "Apel pretins de la banca / anti-frauda",
        "signals": [
            "pretinde banca, departament anti-frauda, securitate sau suport bancar",
            "poate fi doar primul fragment ASR al apelului live, inainte de cererea explicita",
            "cauta cereri ulterioare de cod, transfer, credit, date sensibile sau acces remote",
        ],
        "danger_levers": ["financial_authority", "fear", "partial_transcript"],
        "keywords": [
            "banca",
            "banci",
            "buncii",
            "bunci",
            "bansin",
            "bansii",
            "abunci",
            "panca",
            "anti frauda",
            "antifrauda",
            "anti fraude",
            "antifraude",
            "securitate",
            "seguridad",
            "suport bancar",
            "suport tehnic",
            "support technic",
            "suport technique",
        ],
    },
    {
        "id": "CONV_TECH_SUPPORT_REMOTE_ACCESS",
        "title": "Suport tehnic cere acces la telefon/calculator",
        "signals": [
            "pretinde suport tehnic, banca sau investitii",
            "cere instalare AnyDesk, TeamViewer sau aplicatie de suport",
            "ghideaza victima sa acorde control la distanta",
        ],
        "danger_levers": ["remote_access", "technical_authority", "step_by_step_control"],
        "keywords": [
            "anydesk",
            "teamviewer",
            "remote",
            "control la distanta",
            "aplicatie de suport",
            "suport tehnic",
            "instaleaza",
        ],
    },
    {
        "id": "CONV_FAMILY_EMERGENCY",
        "title": "Urgenta de familie / accident",
        "signals": [
            "pretinde ruda sau intermediar medical/politie",
            "invoca accident, spital, arest sau urgenta",
            "cere bani rapid pentru rezolvare",
        ],
        "danger_levers": ["family", "panic", "urgent_money_transfer"],
        "keywords": [
            "mama",
            "tata",
            "nepot",
            "nepoata",
            "accident",
            "spital",
            "urgenta",
            "politie",
            "bani",
        ],
    },
    {
        "id": "CONV_INVESTMENT_REMOTE_ACCESS",
        "title": "Investitii/recuperare bani cu acces remote",
        "signals": [
            "promite profit sau recuperare bani",
            "cere aplicatie de suport sau transfer/crypto",
            "foloseste presiune pentru decizie rapida",
        ],
        "danger_levers": ["greed", "remote_access", "crypto_or_transfer"],
        "keywords": [
            "investitie",
            "profit garantat",
            "broker",
            "recuperare bani",
            "crypto",
            "bitcoin",
            "anydesk",
            "teamviewer",
        ],
    },
]


def _load_audio_atlas_v2(fallback: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    path = Path(__file__).resolve().parents[1] / "data" / "audio_scam_atlas_v2.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return fallback

    families: List[Dict[str, Any]] = []
    for item in payload.get("families", []):
        family_id = str(item.get("id") or "").strip()
        if not family_id:
            continue
        identity_tokens = [str(value) for value in item.get("identity_tokens_ro", [])]
        core_signals = [str(value) for value in item.get("core_signals_ro", [])]
        garbled_tokens = [str(value) for value in item.get("garbled_asr_tokens", [])]
        hard_asks = [str(value) for value in item.get("hard_asks", [])]
        behavioral_markers = [str(value) for value in item.get("behavioral_markers", [])]
        aliases = [str(value) for value in item.get("aliases", [])]
        families.append(
            {
                "id": family_id,
                "aliases": aliases,
                "title": str(item.get("title_ro") or family_id),
                "signals": [
                    "claimed_identity_matches_family",
                    "script_matches_core_scam_pattern",
                    *[f"behavior:{value}" for value in behavioral_markers[:4]],
                    *[f"hard_ask:{value}" for value in hard_asks[:4]],
                ],
                "danger_levers": hard_asks + behavioral_markers,
                "keywords": identity_tokens + core_signals + garbled_tokens + hard_asks + behavioral_markers + aliases,
            }
        )
    return families or fallback


_FAMILIES = _load_audio_atlas_v2(_FAMILIES)


def _normalize(value: str) -> str:
    text = unicodedata.normalize("NFD", str(value or "").lower())
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Mn")
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9 ]+", " ", text)).strip()


def _score_family(text: str, family: Dict[str, Any], hinted_family: str | None) -> int:
    score = 0
    if hinted_family and (hinted_family == family.get("id") or hinted_family in set(family.get("aliases", []))):
        score += 8
    for keyword in family.get("keywords", []):
        if _normalize(keyword) in text:
            score += 1
    return score


def build_audio_scam_context(
    redacted_transcript: str,
    *,
    local_family: str | None = None,
    local_reason_codes: List[str] | None = None,
    max_families: int = 4,
) -> Dict[str, Any]:
    """Return compact, privacy-safe audio scam hints for Mistral.

    The returned object intentionally excludes transcript excerpts and personal
    names. It carries only generic family descriptions, matched signal labels,
    and the safety contract for the reviewer.
    """

    text = _normalize(redacted_transcript)
    scored = [
        (score, family)
        for family in _FAMILIES
        if (score := _score_family(text, family, local_family)) > 0
    ]
    scored.sort(key=lambda item: item[0], reverse=True)
    selected = [family for _, family in scored[:max_families]]
    if not selected:
        selected = _FAMILIES[:max_families]

    return {
        "source": "sigurscan_audio_scam_context_v1",
        "recall_first": True,
        "anti_downgrade": "mistral_may_escalate_only",
        "input_policy": "redacted_transcript_only_no_raw_audio",
        "local_family_hint": local_family,
        "local_reason_codes": list(local_reason_codes or [])[:8],
        "candidate_families": [
            {
                "id": family["id"],
                "title": family["title"],
                "signals": family["signals"],
                "danger_levers": family["danger_levers"],
            }
            for family in selected
        ],
    }
