from __future__ import annotations

import json
import os
import re
from functools import lru_cache
from typing import Any, Optional


DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "data")
DEFAULT_PATH = os.path.join(DATA_DIR, "brand_never_asks_v1.json")

_DIACRITICS = str.maketrans("ăâîșşțţ", "aaisstt")
_WRONG_SMS_CHANNELS = {"sms"}
_WRONG_SOCIAL_CHANNELS = {"whatsapp", "social_dm", "messenger", "telegram"}
_CHANNEL_ALIASES = {
    "whatsapp_image": "whatsapp",
    "whatsapp_share": "whatsapp",
    "facebook": "social_dm",
    "instagram": "social_dm",
    "tiktok": "social_dm",
}
_BRAND_ALIASES = {
    "ing": {"ing", "ing bank"},
    "banca_transilvania": {"banca transilvania", "bt", "bt bank"},
    "bcr": {"bcr", "banca comerciala romana", "george"},
    "brd": {"brd", "brd groupe societe generale"},
    "unicredit": {"unicredit", "uni credit"},
    "sameday": {"sameday", "same day", "easybox", "sdy"},
    "aquatim": {"aquatim"},
    "ghiseul_ro": {"ghiseul.ro", "ghiseul", "snep"},
    "fan_courier": {"fan courier", "fancourier", "fan"},
    "posta_romana": {"posta romana", "posta", "postaromana"},
    "dhl": {"dhl", "dhl express"},
    "raiffeisen": {"raiffeisen", "raiffeisen bank"},
    "cec": {"cec", "cec bank"},
    "revolut_ro": {"revolut"},
    "anaf": {"anaf", "agentia nationala de administrare fiscala", "fisc", "spv"},
    "politia_romana_general_warning": {"politia romana", "politia", "mai", "igpr"},
    "orange": {"orange", "yoxo"},
    "vodafone": {"vodafone"},
    "digi": {"digi", "rcs rds", "rcs-rds"},
}

_IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9 ]{10,34}\b", re.IGNORECASE)
_URL_RE = re.compile(r"https?://|www\.", re.IGNORECASE)
_PAYMENT_RE = re.compile(
    r"\b(plateste|plati[țt]i|achita|achitati|taxa|tarif|cost|fee|comision|"
    r"neachitat|restant|virament|transfer|iban|cont\s+bancar|card)\b",
    re.IGNORECASE,
)
_EXTRA_FEE_RE = re.compile(
    r"\b(taxa|fee|comision|cost|diferenta)\b.*\b(livrare|colet|transport|suplimentar|extra|neachitat)\b|"
    r"\b(livrare|colet|transport)\b.*\b(taxa|fee|comision|cost|suplimentar|extra|neachitat)\b",
    re.IGNORECASE,
)
_CUSTOMS_FEE_RE = re.compile(r"\b(taxe?\s+vamale?|vama|vam[ăa]|customs|import\s+dut(y|ies))\b", re.IGNORECASE)
_CARD_CVV_RE = re.compile(r"\b(cvv|cvc|codul\s+de\s+pe\s+spate|numarul\s+cardului|datele\s+cardului)\b", re.IGNORECASE)
_PIN_RE = re.compile(r"\b(pin|cod\s+pin)\b", re.IGNORECASE)
_PASSWORD_RE = re.compile(r"\b(parola|password|user(name)?|utilizator|token\s+password)\b", re.IGNORECASE)
_SAFE_ACCOUNT_RE = re.compile(
    r"\b(cont\s+sigur|cont\s+de\s+siguranta|transfera\s+banii|muta\s+banii|"
    r"cont\s+securizat|cont\s+nou|salveaza\s+banii|protejeaza\s+banii)\b",
    re.IGNORECASE,
)
_REMOTE_ACCESS_RE = re.compile(r"\b(anydesk|airdroid|teamviewer|remote\s+access|control\s+la\s+distanta)\b", re.IGNORECASE)
_CRYPTO_RE = re.compile(r"\b(crypto|bitcoin|btc|usdt|wallet|portofel\s+digital)\b", re.IGNORECASE)
_GIFT_CARD_RE = re.compile(r"\b(gift\s*card|voucher|cod\s+voucher|card\s+cadou)\b", re.IGNORECASE)
_BANK_ACCOUNT_DATA_RE = re.compile(r"\b(cont(?:ul|uri|ul)?\s+bancar(?:e)?|date\s+bancare|sold|extras\s+de\s+cont)\b", re.IGNORECASE)
_PERSONAL_DATA_RE = re.compile(r"\b(date\s+personale|cnp|serie\s+buletin|carte\s+de\s+identitate)\b", re.IGNORECASE)
_FINANCIAL_DATA_RE = re.compile(r"\b(date\s+financiare|sold|extras\s+de\s+cont|conturi\s+bancare)\b", re.IGNORECASE)
_OTP_RE = re.compile(r"\b(otp|cod\s+de\s+verificare|cod\s+sms|cod\s+whatsapp)\b", re.IGNORECASE)
_CASH_FIELD_RE = re.compile(
    r"\b(incaseaza|incasare|plata|plateste)\b.*\b(teren|domiciliu|agent|angajat|numerar|cash)\b|"
    r"\b(agent|angajat)\b.*\b(teren|domiciliu|numerar|cash|incaseaza)\b",
    re.IGNORECASE,
)
_SAFETY_EDUCATION_RE = re.compile(
    r"(nu\s+(?:iti|îti|iti|va|vă|comunica|trimite|spune|introduce|dezvalui|"
    r"cerem|solicitam|solicităm)|niciodata\s+nu|niciodată\s+nu)"
    r".{0,80}\b(otp|pin|cvv|cvc|parola|password|cod(?:ul)?\s+(?:sms|de\s+verificare))\b|"
    r"\b(otp|pin|cvv|cvc|parola|password|cod(?:ul)?\s+(?:sms|de\s+verificare))\b"
    r".{0,80}(nu\s+(?:comunica|trimite|spune|introduce|dezvalui)|niciodata\s+nu|niciodată\s+nu)",
    re.IGNORECASE,
)


def _norm(value: Any) -> str:
    return str(value or "").strip().lower().translate(_DIACRITICS)


def normalize_source_channel(source_channel: Optional[str]) -> str:
    channel = _norm(source_channel)
    return _CHANNEL_ALIASES.get(channel, channel)


@lru_cache(maxsize=4)
def _registry(path: Optional[str] = None) -> dict[str, dict[str, Any]]:
    src = path or os.getenv("BRAND_NEVER_ASKS_PATH") or DEFAULT_PATH
    with open(src, "r", encoding="utf-8") as handle:
        raw = json.load(handle)
    return {
        str(item.get("brand_id") or "").strip().lower(): item
        for item in raw.get("brands", [])
        if isinstance(item, dict) and item.get("brand_id")
    }


def _candidate_brand_ids(
    claimed_brand: Optional[str],
    text: str,
    payment_destination: Optional[dict[str, Any]],
    *,
    include_text_candidates: bool = True,
) -> list[str]:
    candidates: list[str] = []
    destination_brand = None
    if isinstance(payment_destination, dict):
        destination_brand = payment_destination.get("brand_id")
    for value in (claimed_brand, destination_brand):
        normalized = _norm(value).replace("_", " ")
        for brand_id, aliases in _BRAND_ALIASES.items():
            if normalized == brand_id or normalized in aliases:
                candidates.append(brand_id)
    if include_text_candidates:
        normalized_text = _norm(text)
        for brand_id, aliases in _BRAND_ALIASES.items():
            if any(re.search(rf"\b{re.escape(alias)}\b", normalized_text) for alias in aliases):
                candidates.append(brand_id)
    seen: set[str] = set()
    return [brand for brand in candidates if not (brand in seen or seen.add(brand))]


def evaluate_brand_never_asks(
    *,
    claimed_brand: Optional[str],
    text: str,
    source_channel: Optional[str],
    fraud_flags: Optional[list[str]] = None,
    payment_destination: Optional[dict[str, Any]] = None,
    include_text_candidates: bool = True,
) -> dict[str, Any]:
    registry = _registry()
    normalized_channel = normalize_source_channel(source_channel)
    flags = set(fraud_flags or [])
    violations: list[str] = []
    refs: list[dict[str, str]] = []
    matched_brands: list[str] = []
    normalized_text = _norm(text)
    candidate_brand_ids = _candidate_brand_ids(
        claimed_brand,
        text,
        payment_destination,
        include_text_candidates=include_text_candidates,
    )
    if _SAFETY_EDUCATION_RE.search(normalized_text):
        return {
            "brand_ids": candidate_brand_ids,
            "violated_never_asks": [],
            "source_channel": normalized_channel,
            "source_refs": [],
        }

    for brand_id in candidate_brand_ids:
        manifest = registry.get(brand_id)
        if not manifest:
            continue
        matched_brands.append(brand_id)
        allowed = set(manifest.get("never_asks") or [])
        brand_violations: list[str] = []

        if brand_id == "sameday":
            payment_request = bool(_PAYMENT_RE.search(text or "") or _IBAN_RE.search(text or ""))
            if normalized_channel in _WRONG_SMS_CHANNELS and payment_request and "payment_request_sms" in allowed:
                brand_violations.append("payment_request_sms")
            if normalized_channel in _WRONG_SOCIAL_CHANNELS and payment_request and "payment_request_social_media" in allowed:
                brand_violations.append("payment_request_social_media")
            if normalized_channel in _WRONG_SMS_CHANNELS and _EXTRA_FEE_RE.search(text or "") and "extra_fee_sms" in allowed:
                brand_violations.append("extra_fee_sms")

        if brand_id in {
            "ing",
            "brd",
            "unicredit",
            "banca_transilvania",
            "bcr",
            "raiffeisen",
            "cec",
            "revolut_ro",
        }:
            if _URL_RE.search(text or "") and re.search(r"\b(login|autentific|activeaza|verifica)\b", normalized_text):
                if "login_link" in allowed:
                    brand_violations.append("login_link")
            if _CARD_CVV_RE.search(text or ""):
                if "cvv" in allowed:
                    brand_violations.append("cvv")
                if "card_number" in allowed:
                    brand_violations.append("card_number")
                if "card_data_for_receiving_money" in allowed:
                    brand_violations.append("card_data_for_receiving_money")
            if _PIN_RE.search(text or ""):
                brand_violations.extend(item for item in ("pin",) if item in allowed)
            if _PASSWORD_RE.search(text or ""):
                brand_violations.extend(item for item in ("username", "password", "token_password") if item in allowed)
            if _OTP_RE.search(text or ""):
                brand_violations.extend(item for item in ("otp", "whatsapp_code") if item in allowed)
            if _SAFE_ACCOUNT_RE.search(text or "") and "safe_account_transfer" in allowed:
                brand_violations.append("safe_account_transfer")
            if _REMOTE_ACCESS_RE.search(text or "") and "remote_access" in allowed:
                brand_violations.append("remote_access")
            if _CRYPTO_RE.search(text or "") and "crypto" in allowed:
                brand_violations.append("crypto")
            if _PERSONAL_DATA_RE.search(text or "") and "personal_data" in allowed:
                brand_violations.append("personal_data")
            if _FINANCIAL_DATA_RE.search(text or "") and "financial_data" in allowed:
                brand_violations.append("financial_data")

        if brand_id in {"orange", "vodafone", "digi"}:
            if _PIN_RE.search(text or ""):
                brand_violations.extend(item for item in ("pin",) if item in allowed)
            if _PASSWORD_RE.search(text or ""):
                brand_violations.extend(item for item in ("username", "password") if item in allowed)
            if _CARD_CVV_RE.search(text or ""):
                brand_violations.extend(item for item in ("card_number", "cvv") if item in allowed)
            if _OTP_RE.search(text or ""):
                brand_violations.extend(item for item in ("otp",) if item in allowed)
            if _BANK_ACCOUNT_DATA_RE.search(text or ""):
                brand_violations.extend(item for item in ("financial_data",) if item in allowed)

        if brand_id == "anaf":
            wrong_channel = normalized_channel in {"email", "sms", "phone", "whatsapp", "social_dm"}
            if wrong_channel and _URL_RE.search(text or "") and "link_request" in allowed:
                brand_violations.append("link_request")
            if _CARD_CVV_RE.search(text or ""):
                brand_violations.extend(item for item in ("card_number", "cvv") if item in allowed)
            if _BANK_ACCOUNT_DATA_RE.search(text or ""):
                brand_violations.extend(item for item in ("financial_data",) if item in allowed)

        if brand_id == "politia_romana_general_warning":
            if _SAFE_ACCOUNT_RE.search(text or "") and "safe_account_transfer" in allowed:
                brand_violations.append("safe_account_transfer")
            if _CARD_CVV_RE.search(text or ""):
                brand_violations.extend(item for item in ("card_number", "cvv") if item in allowed)
            if _PIN_RE.search(text or ""):
                brand_violations.extend(item for item in ("pin",) if item in allowed)
            if _PASSWORD_RE.search(text or ""):
                brand_violations.extend(item for item in ("password",) if item in allowed)
            if _OTP_RE.search(text or ""):
                brand_violations.extend(item for item in ("otp",) if item in allowed)
            if _REMOTE_ACCESS_RE.search(text or "") and "remote_access" in allowed:
                brand_violations.append("remote_access")
            if _CRYPTO_RE.search(text or "") and "crypto" in allowed:
                brand_violations.append("crypto")
            if _GIFT_CARD_RE.search(text or "") and "gift_card" in allowed:
                brand_violations.append("gift_card")

        if brand_id == "ghiseul_ro" and normalized_channel in _WRONG_SMS_CHANNELS | _WRONG_SOCIAL_CHANNELS:
            if _PAYMENT_RE.search(text or "") or re.search(r"\bobligati(e|a)\s+de\s+plata\b", normalized_text):
                if "payment_obligation_sms" in allowed:
                    brand_violations.append("payment_obligation_sms")
                if _URL_RE.search(text or "") and "card_data_by_link" in allowed:
                    brand_violations.append("card_data_by_link")

        if brand_id in {"fan_courier", "posta_romana"}:
            delivery_payment = bool(_PAYMENT_RE.search(text or "") and re.search(r"\b(colet|livrare|awb|curier)\b", normalized_text))
            if normalized_channel in _WRONG_SMS_CHANNELS | _WRONG_SOCIAL_CHANNELS and delivery_payment:
                if "delivery_fee_sms" in allowed:
                    brand_violations.append("delivery_fee_sms")
            if _CARD_CVV_RE.search(text or ""):
                brand_violations.extend(item for item in ("card_number", "cvv") if item in allowed)
            if _PIN_RE.search(text or ""):
                brand_violations.extend(item for item in ("pin",) if item in allowed)
            if _PASSWORD_RE.search(text or ""):
                brand_violations.extend(item for item in ("password",) if item in allowed)
            if _OTP_RE.search(text or ""):
                brand_violations.extend(item for item in ("otp", "whatsapp_code") if item in allowed)

        if brand_id == "dhl":
            delivery_payment = bool(
                _PAYMENT_RE.search(text or "")
                and re.search(r"\b(colet|livrare|awb|curier|expediere|transport)\b", normalized_text)
            )
            customs_payment = bool(_CUSTOMS_FEE_RE.search(text or ""))
            wrong_message_channel = normalized_channel in {"sms", "email", "whatsapp", "social_dm", "messenger", "telegram"}
            if wrong_message_channel and delivery_payment and not customs_payment:
                if "delivery_fee_sms" in allowed:
                    brand_violations.append("delivery_fee_sms")
            if normalized_channel in _WRONG_SOCIAL_CHANNELS and _PAYMENT_RE.search(text or ""):
                if "payment_request_social_media" in allowed:
                    brand_violations.append("payment_request_social_media")
            if _CARD_CVV_RE.search(text or ""):
                brand_violations.extend(item for item in ("card_number", "cvv") if item in allowed)

        if brand_id == "aquatim" and _CASH_FIELD_RE.search(text or "") and "cash_collection_on_field" in allowed:
            brand_violations.append("cash_collection_on_field")

        if "SENSITIVE_DATA_REQUESTED" in flags and brand_id in {
            "ing",
            "brd",
            "unicredit",
            "banca_transilvania",
            "bcr",
            "raiffeisen",
            "cec",
            "revolut_ro",
            "fan_courier",
            "posta_romana",
            "dhl",
            "orange",
            "vodafone",
            "digi",
            "anaf",
            "politia_romana_general_warning",
        }:
            brand_violations.extend(item for item in ("cvv", "card_number", "pin") if item in allowed)

        if brand_violations:
            refs.append(
                {
                    "brand_id": brand_id,
                    "official_statement_url": str(manifest.get("official_statement_url") or ""),
                    "confidence": str(manifest.get("confidence") or ""),
                    "verified_at": str(manifest.get("verified_at") or ""),
                }
            )
            violations.extend(brand_violations)

    seen: set[str] = set()
    unique_violations = [item for item in violations if not (item in seen or seen.add(item))]
    return {
        "brand_ids": matched_brands,
        "violated_never_asks": unique_violations,
        "source_channel": normalized_channel,
        "source_refs": refs,
    }
