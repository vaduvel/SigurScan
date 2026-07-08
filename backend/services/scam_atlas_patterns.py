"""Pure static detection constants for ScamAtlas.

These literal pattern/keyword tables were extracted verbatim from scam_atlas.py to separate
static detection data from the ScamAtlasEngine logic. They depend only on `re`.
"""

import re


SUSPICIOUS_PATH_SEGMENTS = {
    "login",
    "signin",
    "verify",
    "verifica",
    "recover",
    "unlock",
    "otp",
    "security",
    "reactiveaza",
    "reactiveare",
    "reactivare",
    "cont",
    "date",
    "card",
    "cod",
    "formular",
    "form",
    "plata",
    "plată",
    "pay",
    "identitate",
    "confirmare",
    "update",
    "suspendat",
    "suspendare",
    "bloqueaza",
    "auth",
    "authorization",
    "authorize",
}

SUSPICIOUS_QUERY_KEYS = {
    "redirect",
    "next",
    "return",
    "continue",
    "url",
    "target",
    "dest",
    "u",
    "r",
}

TRACKING_QUERY_KEYS = {
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "utm_id",
    "utm_referrer",
    "gclid",
    "fbclid",
}

SUSPICIOUS_TOP_LEVEL_DOMAINS = {
    ".ru",
    ".top",
    ".xyz",
    ".club",
    ".info",
    ".online",
    ".site",
    ".cc",
    ".link",
    ".live",
    ".space",
    ".click",
    ".store",
    ".win",
    ".top",
    ".download",
}

HIGH_RISK_PORTS = {
    8080,
    8081,
    8888,
    10000,
    1337,
    4444,
    5555,
    8088,
}

SENSITIVE_CREDENTIAL_PATTERNS = (
    re.compile(r"\b(?:cvc|cvv|otp|pin)\b", re.IGNORECASE),
    re.compile(
        r"\b(?:cod(?:ul)?\s+(?:de|al)?\s*(?:verificare|confirmare|activare|acces))\b",
        re.IGNORECASE,
    ),
    re.compile(r"\b(?:parol(?:a|ele|ile)|parola ta|parolele)\b", re.IGNORECASE),
)

SENSITIVE_WHATSAPP_PATTERNS = (
    re.compile(r"\bwhatsapp\b.*\b(?:cod(?:ul)?|otp)\b|\b(?:cod(?:ul)?|otp)\b.*\bwhatsapp\b", re.IGNORECASE),
)

SENSITIVE_PAYMENT_PATTERNS = (
    re.compile(
        r"\btransfer[a-z]*\b.*\b(?:bani(?:i)?|sum[aă]|ron|eur|usd)\b|\btrimite[a-z]*\s+bani(?:i)?\b|\bpl[aă]te[a-z]*\s+(?:taxa|comisionul|livrare|factur|abonament|restanta)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\bcont(?:ul)?\s+sigur\b|\btrimite(?:ti|ti)?\s+bani(?:i)?\b|\bpl[aă]t[a-z]*\s+(?:sum[aă]|taxa)\b", re.IGNORECASE),
    re.compile(r"\btrimite\s+transfer\s+bancar\b", re.IGNORECASE),
    re.compile(r"\btrimite\s+depunere\s+(?:initiala|inițial[ăa]?|bani|initial|sum[aă])\b|\bdepunere\s+(?:bani|initiala|inițial[ăa]?|sum[aă])\b", re.IGNORECASE),
    re.compile(r"\btrimite\s+confirmare\b|\btrimite\s+.+\s+confirmare\b", re.IGNORECASE),
)

MALWARE_APK_PATTERNS = (
    re.compile(r"\binstal\w*\s+.*\sapk\b", re.IGNORECASE),
    re.compile(r"\b(?:instaleaz[aăa]|instala\-?zi|instalare)\b\s+(?:app|aplicat\w+|aplicație|aplicatia|apk)\b", re.IGNORECASE),
    re.compile(r"\b(?:apk|app)\s+.*\b(?:fals|neoficial|suspect|scam)\b", re.IGNORECASE),
)

SENSITIVE_QR_PATTERNS = (
    re.compile(r"\b(?:qr|q\s*r|cod\s+qr)\b", re.IGNORECASE),
    re.compile(r"\b(?:scan\w*|scanare|scan-at|scanat)\b", re.IGNORECASE),
    re.compile(r"\b(?:pl[aă]t[aă]|factur|abonament|parcare|reducer|taxa)\b", re.IGNORECASE),
)

SENSITIVE_SEXTORTION_PATTERNS = (
    re.compile(r"\b(?:camera|poze|video|imagini|fișiere|documente)\b", re.IGNORECASE),
    re.compile(r"\bplat[aă]\b.*\b(?:crypto|bani|suma|ron|eur)\b", re.IGNORECASE),
    re.compile(
        r"\b(?:ameninț|compromis|parole|acces)\b(?:\s+\w+){0,8}\b(?:plat[aă]|bani|taxa|sum[aă]|ron|eur)\b",
        re.IGNORECASE,
    ),
)

SENSITIVE_SIM_SWAP_PATTERNS = (
    re.compile(r"\bsim\b.*\b(?:swap|schimb|înlocui|actualizare)\b", re.IGNORECASE),
    re.compile(r"\b(?:date\s+personale|coduri?|codurile?)\b.*\b(?:acces|cont|operator|telefon)\b", re.IGNORECASE),
    re.compile(r"\b(?:abonament|linie)\b.*\b(?:nu\s+merge|nu\s+funcționează|schimbat|probleme)\b", re.IGNORECASE),
    re.compile(r"\bschimb\w*\b.*\bsim\b", re.IGNORECASE),
)

OLX_CARD_PATTERNS = (
    re.compile(r"\bprim\w*\s+bani\w*\s+direct\s+pe\s+card\b", re.IGNORECASE),
    re.compile(r"\bincaseaz[a-z]*\b|\bîncas[a-z]*\b|\bintroduce[a-z]*\s+card[a-z]*\s+pentru\s+a\s+primi\b", re.IGNORECASE),
)

REMOTE_ACCESS_PATTERNS = (
    re.compile(r"\b(anydesk|teamviewer|rustdesk)\b", re.IGNORECASE),
    re.compile(r"\b(?:instal|instale[az]i|instalare|instala|instalez|instalați)\b.*\b(?:aplica(?:ție|t?ie)|app|software|program)\b", re.IGNORECASE),
)

URGENCY_MANIPULATION_PATTERNS = (
    re.compile(r"\burgent[a-z]*\b|\burgenta\b|\bimediat\b|\b24\s*ore\b", re.IGNORECASE),
    re.compile(r"\bbloc[aă]t\b|\bsuspendat\b|\bexpir[aă]\b", re.IGNORECASE),
    re.compile(r"\b(?:suspend[ăa]\w*|bloc(?:heaz[ăa]|at|are)|dezactiv(?:eat|are))\w*\b.{0,60}\b(?:cont(?:ul)?|acces(?:ul)?|card(?:ul)?)\b", re.IGNORECASE),
    re.compile(r"\b(?:verific[ăa]\w*|confirm[ăa]\w*|reautoriz\w+)\b.{0,60}\b(?:identitate|date|cont|acces)\b.{0,60}\b(?:suspend|bloc|dezactiv|restriction|expir)\w*", re.IGNORECASE),
)

MANIPULATION_REWARD_PATTERNS = (
    re.compile(r"\bcâ[sș]tig[a-z]*\b|\bcastig[a-z]*\b|\bpremi[a-z]*\b", re.IGNORECASE),
    re.compile(r"\binvesti[a-z]*\b|\bprofit[a-z]*\b|\bgarantat[a-z]*\b|\bramburs[a-z]*\b", re.IGNORECASE),
)

DELIVERY_MANIPULATION_PATTERNS = (
    re.compile(r"\bcolet[a-z]*\b.*\b(?:taxa|vama|locker|awb|livr|ridic|adresa|expedi)\b", re.IGNORECASE),
    re.compile(r"\b(?:taxe|taxa|vam[a-z]*|locker)\b.*\b(?:colet|livrare|parcel|pachet)\b", re.IGNORECASE),
)

HIGH_RISK_TEXT_ONLY_SIGNAL_MARKERS = {
    "ACCIDENT_CLAIM",
    "APK_INSTALL_REQUEST",
    "BANK_HANDOFF",
    "CARD_OR_BANKING_REQUEST",
    "CARD_OR_ID_REQUEST",
    "CREDENTIAL_REQUEST",
    "CRYPTO_PAYMENT_REQUEST",
    "DO_NOT_VERIFY_PRESSURE",
    "FAMILY_EMERGENCY_CLAIM",
    "GUARANTEED_RETURN_PROMISE",
    "OTP_REQUEST",
    "PASSWORD_REQUEST",
    "REMOTE_ACCESS_APP_REQUEST",
    "SAFE_ACCOUNT_TRANSFER_REQUEST",
    "URGENT_CASH_REQUEST",
    "WHATSAPP_VERIFICATION_CODE_REQUEST",
}

HIGH_RISK_TEXT_ONLY_ASK_MARKERS = {
    "anydesk",
    "apk",
    "banking pin",
    "card",
    "cash",
    "crypto",
    "cvv",
    "iban",
    "money transfer",
    "otp",
    "password",
    "remote access",
    "teamviewer",
    "whatsapp code",
}

KNOWN_DEEPLINK_PROVIDERS = {
    "onelink.me",
    "app.link",
    "branch.link",
    "bnc.lt",
    "go.link",
    "page.link",
    "smart.link",
    "sng.link",
}
