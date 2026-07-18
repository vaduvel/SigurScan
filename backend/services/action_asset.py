"""Canonical Action & Asset extraction.

The contract is intentionally verdict-neutral. It records only normalized
categories and never persists the source transcript or secret values.
"""

from __future__ import annotations

import copy
import re
import unicodedata
from typing import Any, Dict, Iterable, Mapping, Optional


ACTION_ASSET_SCHEMA = "sigurscan_action_asset_v1"

_ACTION_ORDER = (
    "transfer_money",
    "share_code",
    "enter_code",
    "share_card_data",
    "enter_card_data",
    "share_credentials",
    "enter_credentials",
    "install_app",
    "grant_remote_access",
    "screen_share",
    "share_identity",
    "submit_identity",
    "approve_transaction",
    "change_payment_destination",
    "pay_to_receive",
    "buy_gift_card",
    "transfer_crypto",
    "scan_payment_qr",
    "open_banking_app",
    "stay_on_call",
)

_ASSET_ORDER = (
    "money",
    "otp",
    "pin",
    "password",
    "card_data",
    "application",
    "device_access",
    "screen_content",
    "identity_document",
    "cnp",
    "selfie",
    "transaction_approval",
    "iban",
    "bank_account",
    "crypto",
    "gift_card",
    "payment_qr",
)

_PROTECTED_ACTION_BY_REQUEST = {
    "transfer_money": "transfer_money",
    "share_code": "share_authentication_secret",
    "enter_code": "share_authentication_secret",
    "share_credentials": "share_authentication_secret",
    "enter_credentials": "share_authentication_secret",
    "share_card_data": "share_card_data",
    "enter_card_data": "share_card_data",
    "install_app": "install_app",
    "grant_remote_access": "grant_remote_access",
    "screen_share": "screen_share",
    "share_identity": "share_identity",
    "submit_identity": "share_identity",
    "approve_transaction": "approve_transaction",
    "change_payment_destination": "change_payment_destination",
    "pay_to_receive": "pay_to_receive",
    "buy_gift_card": "transfer_alternative_value",
    "transfer_crypto": "transfer_alternative_value",
    "scan_payment_qr": "scan_payment_qr",
}

_PROTECTED_ORDER = (
    "transfer_money",
    "share_authentication_secret",
    "share_card_data",
    "install_app",
    "grant_remote_access",
    "screen_share",
    "share_identity",
    "approve_transaction",
    "change_payment_destination",
    "pay_to_receive",
    "transfer_alternative_value",
    "scan_payment_qr",
    "guided_banking",
)

_RISKY_CHANNELS = {"phone", "sms", "whatsapp", "social", "email", "audio"}


def _fold(value: Any) -> str:
    text = str(value or "")
    text = (
        text.replace("[OTP_REDACTED]", " otp ")
        .replace("[CARD_REDACTED]", " card_data ")
        .replace("[CNP_REDACTED]", " cnp ")
        .replace("[IBAN_REDACTED]", " iban ")
    )
    decomposed = unicodedata.normalize("NFKD", text)
    text = "".join(ch for ch in decomposed if not unicodedata.combining(ch)).lower()
    text = re.sub(r"[\u200b-\u200d\ufeff]", "", text)
    return re.sub(r"\s+", " ", text).strip()


def _ordered(values: Iterable[str], order: Iterable[str]) -> list[str]:
    unique = {str(value) for value in values if value}
    rank = {value: index for index, value in enumerate(order)}
    return sorted(unique, key=lambda value: (rank.get(value, len(rank)), value))


def _clauses(text: str) -> list[str]:
    return [
        clause.strip(" ,:-")
        for clause in re.split(r"(?:[\r\n]+|(?<=[.!?;])\s+)", text)
        if clause.strip(" ,:-")
    ]


_DIRECT_SHARE_VERB = (
    r"(?:spune(?:-mi|-ne)?|comunica(?:-mi|-ne)?|dicta(?:-mi|-ne)?|trimite(?:-mi|-ne)?|"
    r"citeste|da(?:-mi|-ne)?|furnizeaza|transmite(?:-mi|-ne)?)"
)
_DIRECT_ENTRY_VERB = (
    r"(?:introdu(?:ce|ceti)?|tasteaza|completeaza|scrie|foloseste|confirma)"
)
_DIRECT_PAYMENT_VERB = (
    r"(?:transfera|muta|trimite|depune|alimenteaza|plateste|achita|efectueaza|"
    r"pune|vireaza|virezi|varsa)"
)
_CODE_TARGET = (
    r"(?:otp|pin(?:-ul)?|parola|password|cod(?:ul)?\s+(?:otp|unic|nou|de\s+verificare|"
    r"primit|din\s+sms|de\s+securitate|din\s+aplicatia\s+bancara))"
)
_CARD_TARGET = (
    r"(?:cvv|cvc|numarul\s+cardului|datele\s+cardului|card_data|data\s+expirarii)"
)
_IDENTITY_TARGET = (
    r"(?:cnp|buletin(?:ul)?|carte(?:a)?\s+de\s+identitate|act(?:ul)?\s+de\s+identitate|"
    r"date(?:le)?\s+(?:de\s+)?identitate|date(?:le)?\s+personale|selfie)"
)

_ACTION_PATTERNS: Dict[str, tuple[re.Pattern[str], ...]] = {
    "share_code": (
        re.compile(rf"\b{_DIRECT_SHARE_VERB}\b.{{0,70}}\b{_CODE_TARGET}\b"),
        re.compile(
            rf"\b{_DIRECT_SHARE_VERB}\b.{{0,55}}\b(?:cifrele|numerele|caracterele)\b"
            r".{0,55}\b(?:mesaj(?:ul)?|sms|verificare|confirmare)\b"
        ),
    ),
    "enter_code": (
        re.compile(rf"\b{_DIRECT_ENTRY_VERB}\b.{{0,70}}\b{_CODE_TARGET}\b"),
    ),
    "share_card_data": (
        re.compile(rf"\b{_DIRECT_SHARE_VERB}\b.{{0,70}}\b{_CARD_TARGET}\b"),
    ),
    "enter_card_data": (
        re.compile(rf"\b{_DIRECT_ENTRY_VERB}\b.{{0,70}}\b{_CARD_TARGET}\b"),
    ),
    "share_credentials": (
        re.compile(
            rf"\b{_DIRECT_SHARE_VERB}\b.{{0,70}}\b(?:parola|password|credentiale|"
            r"date(?:le)?\s+de\s+autentificare|user(?:name)?)\b"
        ),
    ),
    "enter_credentials": (
        re.compile(
            rf"\b{_DIRECT_ENTRY_VERB}\b.{{0,70}}\b(?:parola|password|credentiale|"
            r"date(?:le)?\s+de\s+autentificare|user(?:name)?)\b"
        ),
    ),
    "install_app": (
        re.compile(
            r"\b(?:instaleaza|descarca|ia)\b.{0,70}\b(?:aplicatia|aplicatie|apk|anydesk|"
            r"teamviewer|rustdesk|quicksupport|quick\s+support)\b"
        ),
    ),
    "grant_remote_access": (
        re.compile(
            r"\b(?:acorda|permite|da|activeaza|lasa)\b.{0,60}\b(?:acces|control)\b"
            r".{0,45}\b(?:la\s+distanta|remote|telefon(?:ul)?|dispozitiv(?:ul)?)\b"
        ),
        re.compile(
            r"\b(?:acorda|permite|da|activeaza|lasa)\b.{0,80}\b(?:anydesk|teamviewer|"
            r"rustdesk|quicksupport|quick\s+support)\b"
        ),
        re.compile(
            r"\b(?:permite|lasa|da\s+voie)\b.{0,65}\b(?:controleze|manevreze|opereze|"
            r"foloseasca|acceseze)\b.{0,45}\b(?:telefon(?:ul)?|dispozitiv(?:ul)?|"
            r"calculator(?:ul)?)\b"
        ),
    ),
    "screen_share": (
        re.compile(
            r"\b(?:partajeaza|trimite|arata|porneste|fa)\b.{0,60}\b(?:ecran(?:ul|ului)?|"
            r"screen\s*share|screenshot|captura\s+de\s+ecran)\b"
        ),
    ),
    "share_identity": (
        re.compile(rf"\b{_DIRECT_SHARE_VERB}\b.{{0,70}}\b{_IDENTITY_TARGET}\b"),
    ),
    "submit_identity": (
        re.compile(rf"\b{_DIRECT_ENTRY_VERB}\b.{{0,70}}\b{_IDENTITY_TARGET}\b"),
    ),
    "approve_transaction": (
        re.compile(
            r"\b(?:aproba|autorizeaza|confirma)\b.{0,60}\b(?:tranzactia|tranzactie|"
            r"plata|transferul)\b"
        ),
        re.compile(
            r"\b(?:apasa|selecteaza|alege)\b.{0,35}\b(?:accept|confirma|aproba)\b"
            r".{0,80}\b(?:operatiunea|operatie|tranzactia|tranzactie|plata|transferul)\b"
        ),
    ),
    "transfer_money": (
        re.compile(
            rf"\b{_DIRECT_PAYMENT_VERB}\b.{{0,90}}\b(?:banii|bani|suma|sold(?:ul)?|"
            r"lei|ron|eur|euro|cont(?:ul)?|iban|factura|plata)\b"
        ),
    ),
    "change_payment_destination": (
        re.compile(
            r"\b(?:foloseste|utilizeaza|transfera|plateste|trimite|muta|ignora|pune|"
            r"vireaza|virezi|varsa)\b.{0,100}"
            r"\b(?:cont(?:ul)?\s+(?:nou|sigur|de\s+siguranta|de\s+protectie|temporar)|"
            r"seif(?:ul)?\s+(?:temporar|de\s+protectie|de\s+siguranta)|"
            r"iban(?:ul)?\s+nou|noul\s+iban|beneficiar(?:ul)?\s+nou|iban(?:ul)?\s+vechi)\b"
        ),
    ),
    "pay_to_receive": (
        re.compile(
            r"\b(?:plateste|achita|trimite|depune)\b.{0,70}\b(?:taxa|comision(?:ul)?|"
            r"depozit(?:ul)?|token(?:ul)?|avans(?:ul)?)\b.{0,90}\b(?:ca\s+sa|pentru\s+a|"
            r"inainte\s+(?:de\s+a|sa))\s+(?:primi|prime|debloca|elibera|recupera|incasa|ridica|activa)\w*\b"
        ),
        re.compile(
            r"\b(?:pentru\s+a|ca\s+sa)\b.{0,75}\b(?:primi|incasa|vira|rambursa|"
            r"debloca|elibera|recupera|ridica|activa)\w*\b.{0,110}\b(?:plateste|achita|"
            r"trimite|depune)\b.{0,55}\b(?:taxa|comision(?:ul)?|depozit(?:ul)?|"
            r"token(?:ul)?|avans(?:ul)?)\b"
        ),
    ),
    "buy_gift_card": (
        re.compile(
            r"\b(?:cumpara|achizitioneaza|ia)\b.{0,60}\b(?:gift\s*card|card(?:uri)?\s+cadou|"
            r"voucher(?:e)?)\b"
        ),
    ),
    "transfer_crypto": (
        re.compile(
            r"\b(?:trimite|transfera|depune|cumpara|muta)\b.{0,70}\b(?:crypto|bitcoin|ethereum|"
            r"usdt|wallet|portofel\s+crypto)\b"
        ),
    ),
    "scan_payment_qr": (
        re.compile(
            r"\b(?:scaneaza|fotografiaza|deschide)\b.{0,60}\b(?:cod(?:ul)?\s+qr|qr)\b"
            r".{0,70}\b(?:plata|platesti|activare|transfer)\b"
        ),
    ),
    "open_banking_app": (
        re.compile(
            r"\b(?:deschide|intra|acceseaza|autentifica-te)\b.{0,70}\b(?:aplicatia\s+bancara|"
            r"internet\s+banking|mobile\s+banking|cont(?:ul)?\s+bancar)\b"
        ),
    ),
    "stay_on_call": (
        re.compile(r"\bnu\s+inchide(?:ti)?\b.{0,30}\b(?:apel(?:ul)?|telefon(?:ul)?)\b"),
        re.compile(r"\bram(?:ai|aneti)\b.{0,25}\bpe\s+(?:linie|fir)\b"),
        re.compile(
            r"\b(?:tine-ma|tineti-ma|ramai|ramaneti)\b.{0,35}\b(?:in\s+(?:convorbire|apel)|"
            r"pe\s+(?:linie|fir))\b"
        ),
    ),
}

_PROTECTIVE_RE = re.compile(
    r"\b(?:nu|niciodata|evita|evitati|fara\s+sa)\b.{0,55}\b(?:comunica|spune|trimite|"
    r"introduce|tasteaza|transfera|plateste|achita|folosi|partaja|instala|deschide|"
    r"scana|aproba|autoriza|"
    r"otp|pin|parola|cvv|datele\s+cardului|cnp)\b"
)


def _is_negated_action(clause: str, start: int, action: str) -> bool:
    if action == "stay_on_call":
        return False
    local_start = max(
        clause.rfind(",", 0, start),
        clause.rfind(";", 0, start),
        clause.rfind("dar", 0, start),
        clause.rfind("insa", 0, start),
        clause.rfind("totusi", 0, start),
    )
    prefix = clause[max(local_start + 1, start - 42) : start]
    return bool(re.search(r"\b(?:nu|niciodata|evita|evitati|fara\s+sa)\b", prefix))


def _assets_for_action(action: str, clause: str) -> set[str]:
    if action in {"share_code", "enter_code"}:
        output = set()
        if re.search(r"\bpin\b", clause):
            output.add("pin")
        if re.search(r"\b(?:parola|password)\b", clause):
            output.add("password")
        if re.search(r"\b(?:otp|cod)\b", clause):
            output.add("otp")
        return output or {"otp"}
    return {
        "share_card_data": {"card_data"},
        "enter_card_data": {"card_data"},
        "share_credentials": {"password"},
        "enter_credentials": {"password"},
        "install_app": {"application"},
        "grant_remote_access": {"device_access"},
        "screen_share": {"screen_content"},
        "approve_transaction": {"transaction_approval"},
        "transfer_money": {"money"},
        "change_payment_destination": {"money", "iban"},
        "pay_to_receive": {"money"},
        "buy_gift_card": {"gift_card"},
        "transfer_crypto": {"crypto"},
        "scan_payment_qr": {"payment_qr", "money"},
        "open_banking_app": {"bank_account"},
        "stay_on_call": set(),
        "share_identity": (
            {"cnp"}
            if re.search(r"\bcnp\b", clause)
            else {"selfie"}
            if re.search(r"\bselfie\b", clause)
            else {"identity_document"}
        ),
        "submit_identity": (
            {"cnp"}
            if re.search(r"\bcnp\b", clause)
            else {"selfie"}
            if re.search(r"\bselfie\b", clause)
            else {"identity_document"}
        ),
    }.get(action, set())


def _observed_assets(text: str, pre_redaction: Optional[Mapping[str, Any]]) -> set[str]:
    output: set[str] = set()
    patterns = {
        "otp": r"\b(?:otp|cod(?:ul)?\s+(?:unic|de\s+verificare|primit|din\s+sms))\b",
        "pin": r"\bpin\b",
        "password": r"\b(?:parola|password|credentiale)\b",
        "card_data": r"\b(?:cvv|cvc|datele\s+cardului|numarul\s+cardului|card_data)\b",
        "cnp": r"\bcnp\b",
        "identity_document": r"\b(?:buletin|carte\s+de\s+identitate|act\s+de\s+identitate)\b",
        "selfie": r"\bselfie\b",
        "iban": r"\biban\b",
        "crypto": r"\b(?:crypto|bitcoin|ethereum|usdt|wallet|seed\s+phrase)\b",
        "gift_card": r"\b(?:gift\s*card|card\s+cadou|voucher)\b",
        "payment_qr": r"\b(?:cod\s+qr|qr)\b",
    }
    for asset, pattern in patterns.items():
        if re.search(pattern, text):
            output.add(asset)

    pre_redaction = pre_redaction if isinstance(pre_redaction, Mapping) else {}
    if int(pre_redaction.get("iban_count") or 0) > 0:
        output.add("iban")
    aliases = {"card": "card_data", "cnp": "cnp", "otp": "otp"}
    for value in pre_redaction.get("sensitive_asset_types") or []:
        mapped = aliases.get(str(value).strip().lower())
        if mapped:
            output.add(mapped)
    return output


def _claimed_actor(text: str) -> str:
    actor_patterns = (
        ("authority", r"\b(?:anaf|politia|politie|parchet|procuror|diicot|dna|bnr|autoritate)\b"),
        ("bank", r"\b(?:banca|bancar|antifrauda|departamentul\s+de\s+frauda)\b"),
        ("courier", r"\b(?:curier|colet|vama|livrare)\b"),
        ("utility", r"\b(?:electricitate|energie|gaze|apa|deconectare|furnizor\s+utilitati)\b"),
        ("telecom", r"\b(?:operator\s+telecom|sim|e-?sim|abonament\s+telefon)\b"),
        ("employer", r"\b(?:angajator|recrutor|hr|loc\s+de\s+munca|job)\b"),
        ("marketplace", r"\b(?:platforma|marketplace|cumparator|vanzator)\b"),
        ("family_or_acquaintance", r"\b(?:mama|tata|fiul|fiica|nepot|prieten|coleg)\b"),
        ("investment_broker", r"\b(?:broker|investitii|trading|portofoliu)\b"),
        ("tech_support", r"\b(?:suport\s+tehnic|tehnician|service\s+it)\b"),
        ("merchant", r"\b(?:magazin|comerciant|furnizor)\b"),
    )
    return next((actor for actor, pattern in actor_patterns if re.search(pattern, text)), "unknown")


def _channel(source_channel: Optional[str]) -> str:
    value = _fold(source_channel)
    if "whatsapp" in value:
        return "whatsapp"
    if "sms" in value:
        return "sms"
    if any(token in value for token in ("audio", "listener", "ureche")):
        return "audio"
    if any(token in value for token in ("phone", "call", "apel")):
        return "phone"
    if "email" in value or "mail" in value:
        return "email"
    if any(token in value for token in ("social", "telegram", "messenger")):
        return "social"
    if "invoice" in value or "factur" in value:
        return "invoice"
    if "offer" in value or "ofert" in value:
        return "offer"
    if "qr" in value:
        return "qr"
    if any(token in value for token in ("url", "web", "browser")):
        return "web"
    if "app" in value or "android_native" in value:
        return "app"
    if any(token in value for token in ("text", "manual", "share")):
        return "text"
    return "unknown"


def _destination(text: str, observed_assets: set[str]) -> Dict[str, Any]:
    changed = bool(
        re.search(
            r"\b(?:cont(?:ul)?\s+(?:nou|sigur|de\s+siguranta|de\s+protectie|temporar)|"
            r"seif(?:ul)?\s+(?:temporar|de\s+protectie|de\s+siguranta)|"
            r"iban(?:ul)?\s+nou|noul\s+iban|beneficiar(?:ul)?\s+nou|ignora\w*\s+iban(?:ul)?\s+vechi|"
            r"datele\s+bancare\s+s-au\s+schimbat)\b",
            text,
        )
    )
    if "payment_qr" in observed_assets:
        destination_type = "payment_qr"
    elif "crypto" in observed_assets:
        destination_type = "crypto_wallet"
    elif "gift_card" in observed_assets:
        destination_type = "gift_card"
    elif "iban" in observed_assets or re.search(r"\bcont(?:ul)?\b", text):
        destination_type = "iban"
    elif re.search(r"\b(?:aplicatia\s+bancara|internet\s+banking|mobile\s+banking)\b", text):
        destination_type = "banking_app"
    elif re.search(r"https?://|\blink\b", text):
        destination_type = "link"
    elif re.search(r"\b(?:google\s+play|app\s+store)\b", text):
        destination_type = "app_store"
    else:
        destination_type = "unknown"
    return {"type": destination_type, "trust": "unknown", "changed": changed}


def build_action_asset_contract(
    raw_text: str,
    *,
    source_channel: Optional[str] = None,
    pre_redaction_summary: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    """Return a privacy-safe normalized contract for one artifact."""

    text = _fold(raw_text)
    actions: set[str] = set()
    requested_assets: set[str] = set()
    protective_warning = bool(_PROTECTIVE_RE.search(text))
    for clause in _clauses(text):
        for action, patterns in _ACTION_PATTERNS.items():
            for pattern in patterns:
                for match in pattern.finditer(clause):
                    if _is_negated_action(clause, match.start(), action):
                        protective_warning = True
                        continue
                    actions.add(action)
                    requested_assets.update(_assets_for_action(action, clause))

    observed_assets = _observed_assets(text, pre_redaction_summary)
    observed_assets.update(requested_assets)
    compositions: set[str] = set()
    if "share_code" in actions and requested_assets.intersection({"otp", "pin", "password"}):
        compositions.add("credential_exfiltration")
    if "install_app" in actions and "grant_remote_access" in actions:
        compositions.add("remote_access_install")
    if actions.intersection({"transfer_money", "change_payment_destination"}) and _destination(text, observed_assets)["changed"]:
        compositions.add("transfer_to_changed_destination")
    if "pay_to_receive" in actions:
        compositions.add("advance_fee")
    if {"stay_on_call", "open_banking_app"}.issubset(actions):
        compositions.add("guided_banking")

    protected_actions = {
        _PROTECTED_ACTION_BY_REQUEST[action]
        for action in actions
        if action in _PROTECTED_ACTION_BY_REQUEST
    }
    if "guided_banking" in compositions:
        protected_actions.add("guided_banking")

    normalized_channel = _channel(source_channel)
    actor = _claimed_actor(text)
    destination = _destination(text, observed_assets)
    corroboration: set[str] = set()
    if actions:
        corroboration.add("positive_request")
    if protected_actions:
        corroboration.add("protected_action")
    if requested_assets:
        corroboration.add("requested_asset")
    if compositions:
        corroboration.add("composition")
    if destination["changed"]:
        corroboration.add("changed_destination")
    if normalized_channel in _RISKY_CHANNELS:
        corroboration.add("risky_channel")
    if actor != "unknown":
        corroboration.add("claimed_actor")
    if re.search(r"\b(?:urgent|imediat|acum|azi|secret|confidential|nu\s+spune\w*\s+nimanui)\b", text):
        corroboration.add("social_pressure")

    return {
        "schema": ACTION_ASSET_SCHEMA,
        "shadow_only": True,
        "requested_actions": _ordered(actions, _ACTION_ORDER),
        "requested_assets": _ordered(requested_assets, _ASSET_ORDER),
        "observed_assets": _ordered(observed_assets, _ASSET_ORDER),
        "destination": destination,
        "claimed_actor": actor,
        "channel": normalized_channel,
        "positive_request": bool(actions),
        "protective_warning": protective_warning,
        "descriptive_context": bool(
            not actions
            and (
                observed_assets
                or re.search(
                    r"\b(?:factura|raport|articol|ghid|descrie|mention(?:eaza|at)|"
                    r"a\s+fost|au\s+fost|va\s+aparea|programat|istoric|extras)\b",
                    text,
                )
            )
        ),
        "local_corroboration": len(corroboration),
        "corroboration_signals": sorted(corroboration),
        "composition_rules": sorted(compositions),
        "protected_actions": _ordered(protected_actions, _PROTECTED_ORDER),
        "raw_text_persisted": False,
    }


def normalize_action_asset_contract(candidate: Any) -> Dict[str, Any]:
    if isinstance(candidate, Mapping) and isinstance(candidate.get("contract"), Mapping):
        candidate = candidate.get("contract")
    candidate = candidate if isinstance(candidate, Mapping) else {}
    return {
        "schema": ACTION_ASSET_SCHEMA,
        "shadow_only": True,
        "requested_actions": _ordered(candidate.get("requested_actions") or [], _ACTION_ORDER),
        "requested_assets": _ordered(candidate.get("requested_assets") or [], _ASSET_ORDER),
        "observed_assets": _ordered(candidate.get("observed_assets") or [], _ASSET_ORDER),
        "destination": copy.deepcopy(candidate.get("destination"))
        if isinstance(candidate.get("destination"), Mapping)
        else {"type": "unknown", "trust": "unknown", "changed": False},
        "claimed_actor": str(candidate.get("claimed_actor") or "unknown"),
        "channel": str(candidate.get("channel") or "unknown"),
        "positive_request": candidate.get("positive_request") is True,
        "protective_warning": candidate.get("protective_warning") is True,
        "descriptive_context": candidate.get("descriptive_context") is True,
        "local_corroboration": max(0, int(candidate.get("local_corroboration") or 0)),
        "corroboration_signals": sorted(
            {str(value) for value in candidate.get("corroboration_signals") or [] if str(value)}
        ),
        "composition_rules": sorted(
            {str(value) for value in candidate.get("composition_rules") or [] if str(value)}
        ),
        "protected_actions": _ordered(candidate.get("protected_actions") or [], _PROTECTED_ORDER),
        "raw_text_persisted": False,
    }
