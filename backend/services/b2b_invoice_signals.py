from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse


FREE_EMAIL_DOMAINS = {
    "gmail.com",
    "googlemail.com",
    "yahoo.com",
    "yahoo.ro",
    "outlook.com",
    "hotmail.com",
    "live.com",
    "icloud.com",
    "proton.me",
    "protonmail.com",
}

KNOWN_PAYMENT_OR_PSP_DOMAINS = {
    "stripe.com",
    "checkout.stripe.com",
    "paypal.com",
    "www.paypal.com",
    "euplatesc.ro",
    "secure.euplatesc.ro",
    "mobilpay.ro",
    "netopia-payments.com",
    "payu.ro",
    "payu.com",
    "revolut.com",
    "business.revolut.com",
    "bancatransilvania.ro",
    "www.bancatransilvania.ro",
    "ghiseul.ro",
    "www.ghiseul.ro",
}

EMAIL_HEADER_RE = re.compile(
    r"(?im)^\s*(?P<label>from|reply-to|return-path|expeditor|raspunde(?:ti)?\s*la|r[ăa]spunde(?:[țt]i)?\s*la)\s*[:\-]\s*(?P<value>.+)$"
)
EMAIL_RE = re.compile(r"[\w.+%-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
CONTEXTUAL_REPLY_TO_RE = re.compile(
    r"\b(?:reply-to|reply\s+to|raspunde(?:ti)?\s+la|r[ăa]spunde(?:[țt]i)?\s+la)\b"
    r"\s*(?:[:=\-]|\s+)\s*(?P<email>[\w.+%-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})",
    re.IGNORECASE,
)
URL_RE = re.compile(r"https?://[^\s<>()\"']+", re.IGNORECASE)
ANCHOR_RE = re.compile(
    r"""<a\b[^>]*\bhref=["'](?P<href>https?://[^"']+)["'][^>]*>(?P<label>.*?)</a>""",
    re.IGNORECASE | re.DOTALL,
)
ACCOUNT_CHANGE_RE = re.compile(
    r"(cont(?:ul)?\s+(?:nou|modificat|actualizat|schimbat)|iban(?:ul)?\s+(?:nou|modificat|actualizat|schimbat)|"
    r"schimbat\s+cont(?:ul)?|modificat\s+cont(?:ul)?|actualizat\s+cont(?:ul)?|"
    r"new\s+(?:bank\s+)?account|changed\s+(?:bank\s+)?account)",
    re.IGNORECASE,
)
AUTHORITY_ROLE_RE = re.compile(
    r"\b(?:ceo|director(?:ul)?|administrator(?:ul)?|manager(?:ul)?|patron(?:ul)?|sef(?:ul)?|șef(?:ul)?)\b",
    re.IGNORECASE,
)
CONFIDENTIALITY_PRESSURE_RE = re.compile(
    r"\b(?:confiden[țt]ial[ăa]?|secret|nu\s+suna|nu\s+m[ăa]\s+contacta|nu\s+discuta|discret)\b",
    re.IGNORECASE,
)
PAYMENT_TRANSFER_TERMS_RE = re.compile(
    r"\b(?:plat[ăa]|pl[ăa]te[șs]te|transfer|iban|cont|virament)\b",
    re.IGNORECASE,
)
REMOTE_ACCESS_RE = re.compile(
    r"\b(?:anydesk|any\s*desk|teamviewer|team\s*viewer|rustdesk|remote\s*access|"
    r"acces\s*la\s*distan[țt][ăa]|control\s+la\s+distan[țt][ăa])\b",
    re.IGNORECASE,
)
EF_ACTURA_CLAIM_RE = re.compile(r"\b(?:e[-\s]?factura|spv|xml)\b", re.IGNORECASE)
EF_ACTURA_PROOF_RE = re.compile(
    r"\b(?:xml\s+(?:ata[șs]at|atasat|semnat|validat)|hash\s+xml|id\s+(?:incarcare|încărcare)|"
    r"sigiliu|semn[ăa]tur[ăa]\s+electronic[ăa])\b",
    re.IGNORECASE,
)
ARCHIVE_OR_MACRO_RE = re.compile(
    r"\.(?:zip|rar|7z|exe|scr|js|vbs|bat|cmd|docm|xlsm)\b|\bmacro(?:uri)?\b",
    re.IGNORECASE,
)
PAYMENT_LINK_RE = re.compile(r"\b(?:achit[ăa]|pl[ăa]te[șs]te|payment|checkout|pay|link\s+de\s+plat[ăa])\b", re.IGNORECASE)
PAYMENT_OR_INVOICE_CONTEXT_RE = re.compile(
    r"\b(?:factur[ăa]|pl[ăa]t|achit|transfer|iban|cont|virament|proform[ăa])\b",
    re.IGNORECASE,
)
COMPANY_MARKER_RE = re.compile(r"\b(?:s\.?\s?r\.?\s?l|s\.?\s?a|pfa|i\.?\s?i|cui|cif|factur[ăa])\b", re.IGNORECASE)
OSIM_TRADEMARK_CONTEXT_RE = re.compile(
    r"\b(?:osim|tmview|m[ăa]rc(?:a|[ăa]|ii|i)?|trademark|proprietate\s+industrial[ăa]|"
    r"catalog(?:ul)?\s+interna[țt]ional|registr(?:u|ul)\s+online)\b",
    re.IGNORECASE,
)
OSIM_PAYMENT_CONTEXT_RE = re.compile(
    r"\b(?:factur[ăa]|tax[ăa]|plat[ăa]|achita(?:re|[țt]i)?|scadent[ăa]?|neplata|"
    r"publicare|operator(?:ul)?\s+privat|confirmare)\b",
    re.IGNORECASE,
)
LEGAL_DEMAND_RE = re.compile(
    r"\b(?:soma[țt]ie|recuperare\s+crean[țt]e|executor|avocat|penalit[ăa][țt]i)\b"
    r".{0,160}\b(?:iban|cont\s+nou|achita[țt]i\s+urgent)\b",
    re.IGNORECASE | re.DOTALL,
)
DOMAIN_RENEWAL_RE = re.compile(
    r"\b(?:renewal|reinnoire|reînnoire|domain|domeniu|hosting|ssl|dns)\b"
    r".{0,120}\b(?:factur[ăa]|invoice|payment|plat[ăa]|achita[țt]i)\b",
    re.IGNORECASE | re.DOTALL,
)
GRANT_CONSULTING_RE = re.compile(
    r"\b(?:fonduri|grant|subven[țt]ie|program\s+ue|pnrr|finan[țt]are)\b"
    r".{0,220}\b(?:tax[ăa]\s+(?:de\s+)?dosar|garan[țt]ie|analiz[ăa]|avans|rezervarea\s+liniei|"
    r"achita[țt]i\s+taxa)\b",
    re.IGNORECASE | re.DOTALL,
)
SAAS_LICENSE_AUDIT_RE = re.compile(
    r"\b(?:audit\s+licen[țt]e|software\s+compliance|cloud\s+subscription|microsoft\s*365|google\s+workspace|adobe)\b"
    r".{0,180}\b(?:plat[ăa]\s+urgent[ăa]|pl[ăa]ti[țt]i|tax[ăa]\s+(?:de\s+)?audit|regularizare|"
    r"suspendare|instala[țt]i\s+aplica[țt]ia\s+de\s+suport)\b",
    re.IGNORECASE | re.DOTALL,
)
OVERPAYMENT_RETURN_RE = re.compile(
    r"\b(?:supraplat[ăa]|eroare\s+plat[ăa]|returna[țt]i\s+diferen[țt]a|p[ăa]stra[țt]i\s+comisionul)\b"
    r".{0,180}\b(?:returna[țt]i|diferen[țt]a|comision|iban|cont)\b|"
    r"\b(?:ordin\s+de\s+plat[ăa]|plat[ăa])\b.{0,100}\b(?:mai\s+mare|supraplat[ăa]|overpayment)\b"
    r".{0,180}\b(?:vira[țt]i|returna[țt]i|diferen[țt]a|transportator|ter[țt])\b|"
    r"\b(?:purchase\s+order|\bpo[-\s]?\d+)\b"
    r".{0,180}\b(?:supraplat[ăa]|overpayment|returna[țt]i|refund|diferen[țt]a|comision)\b",
    re.IGNORECASE | re.DOTALL,
)
PROCUREMENT_FEE_RE = re.compile(
    r"\b(?:seap|licita[țt]ie|contract\s+public|subcontractare)\b"
    r".{0,160}\b(?:tax[ăa]|garan[țt]ie|inscriere|înscriere|dosar)\b",
    re.IGNORECASE | re.DOTALL,
)
PAYROLL_DATA_RE = re.compile(
    r"\b(?:stat\s+de\s+plat[ăa]|salarii|cnp|cont(?:uri(?:lor)?)?\s+(?:noi\s+de\s+)?salarii|"
    r"iban\s+salariu|date\s+angaja[țt]i|payroll\s+cutoff)\b"
    r".{0,180}\b(?:actualizare|transmite[țt]i|confirma[țt]i|confirmare|trimite[țt]i)\b|"
    r"\b(?:actualizare|transmite[țt]i|confirma[țt]i|confirmare|trimite[țt]i)\b"
    r".{0,180}\b(?:stat\s+de\s+plat[ăa]|salarii|cnp|cont(?:uri(?:lor)?)?\s+(?:noi\s+de\s+)?salarii|"
    r"iban\s+salariu|date\s+angaja[țt]i|payroll\s+cutoff)\b",
    re.IGNORECASE | re.DOTALL,
)
REGULATED_FINANCE_CONTEXT_RE = re.compile(
    r"\b(?:credit|linie\s+de\s+credit|capital\s+de\s+lucru|refinan[țt]are|finan[țt]are|"
    r"factoring|leasing|investi[țt]ii|trading|dashboard(?:-ul)?\s+de\s+trading|bnr|asf|ifn|profit)\b",
    re.IGNORECASE,
)
REGULATED_FINANCE_ADVANCE_FEE_RE = re.compile(
    r"\b(?:tax[ăa]\s+(?:de\s+)?analiz[ăa]|comision(?:ul)?\s+(?:de\s+)?(?:activare|platform[ăa]|accesare)|"
    r"depuner(?:e|ea)\s+ini[țt]ial[ăa]|usdt|crypto|ci\s+administrator|certificat\s+onrc|dosar(?:ul)?\s+a\s+fost\s+aprobat|"
    r"instalarea\s+aplica[țt]iei\s+de\s+suport|verificarea\s+conturilor\s+bancare|factur[ăa]\s+de\s+activare|"
    r"profit\s+estimat\s+\d+%|cont(?:ul)?\s+de\s+procesare|pentru\s+deblocare|oferta\s+final[ăa])\b",
    re.IGNORECASE,
)
COURIER_CONTEXT_RE = re.compile(
    r"\b(?:dhl|cargus|fan\s*courier|\bfan\b|sameday|dpd|po[șs]ta|selfawb|awb|colet|livrare|vamal[ăa]|vam[ăa]|locker)\b",
    re.IGNORECASE,
)
COURIER_CUSTOMS_OR_ADDRESS_FEE_RE = re.compile(
    r"\b(?:factur[ăa]\s+)?vamal[ăa]\b.{0,100}\b(?:card|achita[țt]i|plata|plat[ăa])\b|"
    r"\b(?:valida[țt]i|actualiza[țt]i)\s+adresa\b.{0,120}\b(?:achita[țt]i|tax[ăa]|\d+[,.]\d{2}\s*ron)\b|"
    r"\b(?:achita[țt]i|pl[ăa]te[șs]te)\b.{0,40}\b\d+[,.]\d{2}\s*ron\b|"
    r"\btax[ăa]\s+livrare\b.{0,120}\bplata\s+online\s+este\s+obligatorie\b",
    re.IGNORECASE | re.DOTALL,
)
COURIER_OTP_OR_WHATSAPP_CODE_RE = re.compile(
    r"\b(?:cod(?:ul)?\s+whatsapp|whatsapp\s+primit|cod(?:ul)?\s+primit\s+prin\s+sms|"
    r"introduce[țt]i\s+cod(?:ul)?|trimite[țt]i\s+cod(?:ul)?)\b",
    re.IGNORECASE,
)
COURIER_OTP_NEGATION_RE = re.compile(
    r"\b(?:f[ăa]r[ăa]\s+cerere\s+de|nu\s+(?:cere|solicit[ăa]))\b"
    r".{0,100}\b(?:cod(?:ul)?\s+whatsapp|whatsapp|card|cvc|cvv)\b",
    re.IGNORECASE | re.DOTALL,
)
BEC_NEW_IBAN_OR_ACCOUNT_RE = re.compile(
    r"\b(?:cont(?:ul)?\s+(?:bancar\s+)?s-?a\s+schimbat|cont(?:ul)?\s+(?:nou|vechi)|"
    r"iban(?:-?ul)?\s+(?:nou|vechi)|noul\s+iban)\b",
    re.IGNORECASE,
)
BEC_EXCLUSIVE_OR_OLD_DETAILS_RE = re.compile(
    r"\b(?:folosi[țt]i\s+exclusiv|exclusiv\s+noul|ignora[țt]i\s+datele\s+vechi|"
    r"nu\s+folosi[țt]i\s+(?:datele|contul|iban(?:-?ul)?)\s+vechi)\b",
    re.IGNORECASE | re.DOTALL,
)
BEC_THREAD_CONTEXT_RE = re.compile(
    r"\b(?:re:|fw:|fwd:|comanda\s+\d+|proform[ăa]|trimis[ăa]\s+anterior|thread(?:ul)?)\b",
    re.IGNORECASE,
)
BEC_THREAD_IBAN_CHANGE_HINT_RE = re.compile(
    r"\b(?:cont(?:ul)?\s+vechi|iban(?:-?ul)?\s+nou|contabilitatea\s+solicit[ăa]|"
    r"restul\s+datelor\s+r[ăa]m[âa]n\s+neschimbate)\b",
    re.IGNORECASE | re.DOTALL,
)
TAX_AUTHORITY_CONTEXT_RE = re.compile(
    r"\b(?:anaf|ministerul\s+finan[țt]elor|popriri|facturi\s+respinse|penalizare|reactivare|"
    r"regularizare|amend[ăa]|desc[ăa]rca[țt]i\s+notificarea|login)\b",
    re.IGNORECASE,
)
TAX_AUTHORITY_PAYMENT_ACTION_RE = re.compile(
    r"\b(?:achita[țt]i|pl[ăa]ti[țt]i|tax[ăa]\s+de\s+reactivare|regularizare|"
    r"amend[ăa]|penalizare|poprirea|iban(?:-?ul)?\s+indicat|login|desc[ăa]rca[țt]i\s+notificarea)\b",
    re.IGNORECASE | re.DOTALL,
)
TAX_AUTHORITY_SENSITIVE_CONTEXT_RE = re.compile(
    r"\b(?:anaf|spv|e[-\s]?factura|ministerul\s+finan[țt]elor|popriri)\b",
    re.IGNORECASE,
)
TAX_AUTHORITY_SENSITIVE_FIELD_RE = re.compile(
    r"\b(?:cnp|date\s+card|card|cui|administrator|parol[ăa]|otp|cod\s+sms|completa[țt]i)\b",
    re.IGNORECASE,
)
TAX_AUTHORITY_SENSITIVE_ACTION_RE = re.compile(
    r"\b(?:suspendat|reactivare|deblocare|validare(?:a)?|actualizare|verificare)\b",
    re.IGNORECASE,
)
TAX_AUTHORITY_EFACTURA_CONTEXT_RE = re.compile(
    r"\b(?:anaf|spv|e[-\s]?factura|factura\s+electronic[ăa])\b",
    re.IGNORECASE,
)
TAX_AUTHORITY_APPROVAL_CLAIM_RE = re.compile(
    r"\b(?:aprobat[ăa]?\s+de\s+anaf|validat[ăa]?|validare)\b",
    re.IGNORECASE,
)
TAX_AUTHORITY_UPDATED_IBAN_RE = re.compile(
    r"\b(?:cont(?:ul)?\s+nou|iban(?:-?ul)?\s+actualizat|iban(?:-?ul)?\s+nou|datele\s+bancare\s+actualizate)\b",
    re.IGNORECASE,
)
OFFICIAL_REGISTRY_CLAIM_RE = re.compile(
    r"\b(?:onrc|bnr|asf|anpc|osim|registru|autorizat|certificat)\b"
    r".{0,160}\b(?:plat[ăa]|achita[țt]i|tax[ăa]|urgent)\b",
    re.IGNORECASE | re.DOTALL,
)
PAYMENT_DIVERSION_HOLD_RE = re.compile(
    r"\b(?:tine[țt]i|ține[țt]i|suspenda[țt]i|opri[țt]i|stopa[țt]i|amanati|am[aâ]na[țt]i|hold|suspend|stop)\b"
    r".{0,120}\b(?:pl[ăa][țt]ile|plati|payments|viramentele|transferurile)\b"
    r".{0,180}\b(?:noi\s+instruc[țt]iuni|further\s+instructions|noul\s+cont|cont(?:ul)?\s+bancar|iban)\b|"
    r"\b(?:trimiteti|trimite[țt]i|send|transmiteti|transmite[țt]i)\b"
    r".{0,140}\b(?:lista\s+facturilor\s+deschise|facturi(?:lor)?\s+deschise|open\s+invoices)\b"
    r".{0,180}\b(?:noul\s+cont|cont(?:ul)?\s+bancar|iban|noi\s+instruc[țt]iuni|further\s+instructions)\b",
    re.IGNORECASE | re.DOTALL,
)
IP_OFFICE_PAYMENT_RE = re.compile(
    r"\b(?:wipo|epo|euipo|world\s+intellectual\s+property|european\s+patent|"
    r"patent\s+office|intellectual\s+property\s+office)\b"
    r".{0,220}\b(?:administrative\s+protection\s+fee|protection\s+fee|publication\s+fee|"
    r"registration\s+fee|tax[ăa]\s+(?:de\s+)?(?:protec[țt]ie|publicare|inregistrare|înregistrare)|"
    r"achita[țt]i|payment|invoice|factur[ăa])\b",
    re.IGNORECASE | re.DOTALL,
)
OFFICIAL_IP_OFFICE_DOMAIN_RE = re.compile(
    r"\b(?:https?://)?(?:[^/\s]+\.)?(?:wipo\.int|epo\.org|euipo\.europa\.eu)\b",
    re.IGNORECASE,
)
URGENT_PAYMENT_OVERRIDE_RE = re.compile(
    r"\b(?:urgent[ăa]?|azi|imediat|confiden[țt]ial[ăa]?|nu\s+suna|sunt\s+(?:in|în)\s+(?:sedinta|ședință))\b"
    r".{0,180}\b(?:plat[ăa]|transfer|ordin|iban|virament)\b|"
    r"\b(?:plat[ăa]|transfer|ordin|iban|virament)\b"
    r".{0,180}\b(?:urgent[ăa]?|azi|imediat|confiden[țt]ial[ăa]?|nu\s+suna|sunt\s+(?:in|în)\s+(?:sedinta|ședință))\b",
    re.IGNORECASE | re.DOTALL,
)
OFFICIAL_OSIM_DOMAIN_RE = re.compile(r"\b(?:https?://)?(?:portal\.)?osim\.ro\b", re.IGNORECASE)
APPROVAL_EVIDENCE_RE = re.compile(r"\b(?:ticket\s*#?\d+|aprobat(?:[ăa])?\s+de|aprobare\s+(?:valid[ăa]|intern[ăa])|po[-\s]?\d+)\b", re.IGNORECASE)


@dataclass
class B2BSignalResult:
    flags: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


def _add(result: B2BSignalResult, flag: str, warning: Optional[str] = None) -> None:
    if flag not in result.flags:
        result.flags.append(flag)
    if warning and warning not in result.warnings:
        result.warnings.append(warning)


def _domain_from_email(raw: str) -> Optional[str]:
    match = EMAIL_RE.search(raw or "")
    return match.group(1).lower() if match else None


def _contextual_reply_to_domain(text: str) -> Optional[str]:
    match = CONTEXTUAL_REPLY_TO_RE.search(text or "")
    if not match:
        return None
    return _domain_from_email(match.group("email"))


def _header_domains(text: str) -> dict[str, str]:
    domains: dict[str, str] = {}
    for match in EMAIL_HEADER_RE.finditer(text or ""):
        label = match.group("label").lower()
        value = match.group("value")
        domain = _domain_from_email(value)
        if not domain:
            continue
        if label in {"reply-to", "raspunde la", "raspundeti la", "răspunde la", "răspundeți la"}:
            domains["reply_to_domain"] = domain
        elif label in {"from", "expeditor"}:
            domains["from_domain"] = domain
        elif label == "return-path":
            domains["return_path_domain"] = domain
    if "reply_to_domain" not in domains:
        contextual_reply_to = _contextual_reply_to_domain(text)
        if contextual_reply_to:
            domains["reply_to_domain"] = contextual_reply_to
            domains["reply_to_source"] = "context"
    return domains


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower().removeprefix("www.")
    except Exception:
        return ""


def _domain_like_url(text: str) -> Optional[str]:
    match = URL_RE.search(text or "")
    return _host(match.group(0)) if match else None


def _looks_unknown_payment_link(text: str) -> Optional[str]:
    for raw_url in URL_RE.findall(text or ""):
        host = _host(raw_url)
        if not host or host in {d.removeprefix("www.") for d in KNOWN_PAYMENT_OR_PSP_DOMAINS}:
            continue
        url_context = raw_url.lower()
        surrounding = text[max(0, text.find(raw_url) - 80) : text.find(raw_url) + len(raw_url) + 80]
        if PAYMENT_LINK_RE.search(url_context) or PAYMENT_LINK_RE.search(surrounding):
            return host
    return None


def _anchor_display_mismatch(text: str) -> Optional[dict]:
    for match in ANCHOR_RE.finditer(text or ""):
        href_host = _host(match.group("href"))
        label_host = _domain_like_url(re.sub(r"<[^>]+>", "", match.group("label")))
        if href_host and label_host and href_host != label_host:
            return {"href_host": href_host, "label_host": label_host}
    return None


def evaluate_b2b_invoice_signals(text: str, *, claimed_vendor: Optional[str] = None) -> B2BSignalResult:
    result = B2BSignalResult()
    raw = text or ""
    domains = _header_domains(raw)
    result.metadata.update(domains)

    from_domain = domains.get("from_domain")
    reply_to_domain = domains.get("reply_to_domain")
    has_account_change = bool(
        ACCOUNT_CHANGE_RE.search(raw)
        or BEC_NEW_IBAN_OR_ACCOUNT_RE.search(raw)
        or BEC_EXCLUSIVE_OR_OLD_DETAILS_RE.search(raw)
    )
    has_payment_pressure = bool(
        URGENT_PAYMENT_OVERRIDE_RE.search(raw)
        or (CONFIDENTIALITY_PRESSURE_RE.search(raw) and PAYMENT_TRANSFER_TERMS_RE.search(raw))
    )
    if from_domain and reply_to_domain and from_domain != reply_to_domain:
        _add(
            result,
            "REPLY_TO_MISMATCH",
            "Reply-To diferă de domeniul expeditorului; confirmă plata pe un canal cunoscut.",
        )

    looks_company = bool(COMPANY_MARKER_RE.search(raw) or claimed_vendor)
    if looks_company and from_domain in FREE_EMAIL_DOMAINS:
        _add(
            result,
            "FREE_EMAIL_FOR_COMPANY_INVOICE",
            "Factura pretinde firmă, dar expeditorul este un domeniu gratuit de e-mail.",
        )
    if looks_company and reply_to_domain in FREE_EMAIL_DOMAINS:
        _add(
            result,
            "FREE_EMAIL_REPLY_TO_FOR_COMPANY_INVOICE",
            "Factura pretinde firmă, dar Reply-To este un domeniu gratuit de e-mail.",
        )

    if (
        AUTHORITY_ROLE_RE.search(raw)
        and CONFIDENTIALITY_PRESSURE_RE.search(raw)
        and PAYMENT_TRANSFER_TERMS_RE.search(raw)
    ):
        _add(
            result,
            "CEO_CONFIDENTIAL_PAYMENT",
            "Mesajul combină autoritate, confidențialitate și cerere de plată.",
        )

    if REMOTE_ACCESS_RE.search(raw) and PAYMENT_OR_INVOICE_CONTEXT_RE.search(raw):
        _add(
            result,
            "REMOTE_ACCESS_REQUEST",
            "Factura/mesajul cere acces la distanță; nu instala și nu permite controlul dispozitivului.",
        )

    if REGULATED_FINANCE_CONTEXT_RE.search(raw) and REGULATED_FINANCE_ADVANCE_FEE_RE.search(raw):
        _add(
            result,
            "REGULATED_FINANCE_ADVANCE_FEE_OR_ID_REQUEST",
            "Serviciu financiar/investițional cere comision, depunere, cripto sau documente înainte de verificare/autorizare.",
        )

    if COURIER_CONTEXT_RE.search(raw) and COURIER_CUSTOMS_OR_ADDRESS_FEE_RE.search(raw):
        _add(
            result,
            "COURIER_CUSTOMS_OR_ADDRESS_FEE_PAYMENT",
            "Mesaj de curier/vamă cere taxă, card sau validare adresă pe canal neconfirmat.",
        )

    if (
        COURIER_CONTEXT_RE.search(raw)
        and COURIER_OTP_OR_WHATSAPP_CODE_RE.search(raw)
        and not COURIER_OTP_NEGATION_RE.search(raw)
    ):
        _add(
            result,
            "COURIER_OTP_OR_WHATSAPP_CODE_REQUEST",
            "Mesaj de curier/locker cere cod WhatsApp/SMS sau cod de acces pe canal neconfirmat.",
        )

    if BEC_NEW_IBAN_OR_ACCOUNT_RE.search(raw) and BEC_EXCLUSIVE_OR_OLD_DETAILS_RE.search(raw):
        _add(
            result,
            "BEC_EXCLUSIVE_NEW_IBAN_WITH_OLD_DETAILS_SUPPRESSION",
            "Mesajul impune folosirea exclusivă a unui IBAN nou și ignorarea datelor bancare vechi.",
        )

    if BEC_THREAD_CONTEXT_RE.search(raw) and BEC_THREAD_IBAN_CHANGE_HINT_RE.search(raw):
        _add(
            result,
            "BEC_INVOICE_THREAD_IBAN_CHANGE",
            "Reply/thread de factură schimbă IBAN-ul față de proforma/contul anterior.",
        )

    if TAX_AUTHORITY_CONTEXT_RE.search(raw) and TAX_AUTHORITY_PAYMENT_ACTION_RE.search(raw):
        _add(
            result,
            "TAX_AUTHORITY_PAYMENT_REQUEST_UNOFFICIAL_CHANNEL",
            "Mesaj ANAF/Ministerul Finanțelor/e-Factura cere plată, regularizare sau IBAN pe canal neconfirmat.",
        )

    if (
        TAX_AUTHORITY_SENSITIVE_CONTEXT_RE.search(raw)
        and TAX_AUTHORITY_SENSITIVE_FIELD_RE.search(raw)
        and TAX_AUTHORITY_SENSITIVE_ACTION_RE.search(raw)
    ):
        _add(
            result,
            "TAX_AUTHORITY_SENSITIVE_DATA_REQUEST",
            "Mesaj ANAF/SPV/e-Factura cere CNP, date card, cod sau date de administrator pe canal neconfirmat.",
        )

    if (
        TAX_AUTHORITY_EFACTURA_CONTEXT_RE.search(raw)
        and TAX_AUTHORITY_APPROVAL_CLAIM_RE.search(raw)
        and TAX_AUTHORITY_UPDATED_IBAN_RE.search(raw)
    ):
        _add(
            result,
            "TAX_AUTHORITY_APPROVES_UPDATED_IBAN",
            "Mesajul pretinde că ANAF/e-Factura aprobă un IBAN sau cont bancar nou al furnizorului.",
        )

    if EF_ACTURA_CLAIM_RE.search(raw) and not EF_ACTURA_PROOF_RE.search(raw):
        _add(
            result,
            "EFACTURA_CLAIM_WITHOUT_DOCUMENT",
            "Textul invocă e-Factura/SPV, dar nu conține dovadă XML/semnătură verificabilă.",
        )

    if ARCHIVE_OR_MACRO_RE.search(raw):
        _add(
            result,
            "INVOICE_ATTACHMENT_EXECUTABLE",
            "Atașamentul menționat este arhivă/executabil/macro, risc ridicat pentru facturi false.",
        )

    unknown_payment_host = _looks_unknown_payment_link(raw)
    if unknown_payment_host:
        result.metadata["unknown_payment_host"] = unknown_payment_host
        _add(
            result,
            "PAYMENT_LINK_UNKNOWN_PSP",
            "Linkul de plată nu aparține unui procesator sau canal cunoscut.",
        )

    mismatch = _anchor_display_mismatch(raw)
    if mismatch:
        result.metadata["anchor_mismatch"] = mismatch
        _add(
            result,
            "PHISHING_LINK_IN_INVOICE_EMAIL",
            "Linkul afișat și destinația reală din e-mail nu coincid.",
        )

    if has_account_change and reply_to_domain and from_domain and reply_to_domain != from_domain:
        _add(
            result,
            "BEC_REPLY_TO_ACCOUNT_CHANGE",
            "Schimbare de cont bancar plus Reply-To diferit: tipar puternic de fraudă BEC.",
        )
    elif has_account_change and has_payment_pressure and looks_company and reply_to_domain in FREE_EMAIL_DOMAINS:
        _add(
            result,
            "BEC_REPLY_TO_ACCOUNT_CHANGE",
            "Schimbare de cont bancar plus Reply-To gratuit și presiune de plată: tipar puternic de fraudă BEC.",
        )

    if (
        OSIM_TRADEMARK_CONTEXT_RE.search(raw)
        and OSIM_PAYMENT_CONTEXT_RE.search(raw)
        and not OFFICIAL_OSIM_DOMAIN_RE.search(raw)
    ):
        _add(
            result,
            "OSIM_TRADEMARK_FEE_UNOFFICIAL_SENDER",
            "Solicitare de plată pentru marcă/OSIM/TMview fără canal oficial OSIM verificabil.",
        )

    if LEGAL_DEMAND_RE.search(raw):
        _add(
            result,
            "LEGAL_DEMAND_PAYMENT_TO_NEW_IBAN",
            "Somație/recuperare creanțe cere plată urgentă către IBAN/cont nou.",
        )

    if DOMAIN_RENEWAL_RE.search(raw):
        _add(
            result,
            "DOMAIN_RENEWAL_INVOICE_NO_EXISTING_VENDOR",
            "Factură de reînnoire domeniu/hosting/SSL de la furnizor neverificat.",
        )

    if GRANT_CONSULTING_RE.search(raw):
        _add(
            result,
            "GRANT_CONSULTING_FEE_BEFORE_CONTRACT",
            "Taxă/garanție pentru grant/fonduri înainte de contract sau verificare oficială.",
        )

    if SAAS_LICENSE_AUDIT_RE.search(raw):
        _add(
            result,
            "SAAS_LICENSE_AUDIT_URGENT_PAYMENT",
            "Pretins audit/licență software cere plată urgentă sau regularizare.",
        )

    if OVERPAYMENT_RETURN_RE.search(raw):
        _add(
            result,
            "PO_OR_OVERPAYMENT_RETURN_REQUEST",
            "Cerere de returnare diferență/supraplată către alt cont: tipar B2B de fraudă.",
        )

    if PROCUREMENT_FEE_RE.search(raw):
        _add(
            result,
            "NEW_VENDOR_PUBLIC_PROCUREMENT_FEE",
            "Contract public/subcontractare cere taxă de înscriere/garanție înainte de verificare.",
        )

    if PAYROLL_DATA_RE.search(raw):
        _add(
            result,
            "PAYROLL_OR_EMPLOYEE_DATA_REQUEST_VIA_INVOICE_THREAD",
            "Thread de factură cere date angajați/CNP/IBAN salariu.",
        )

    if OFFICIAL_REGISTRY_CLAIM_RE.search(raw) and not OFFICIAL_OSIM_DOMAIN_RE.search(raw):
        _add(
            result,
            "OFFICIAL_REGISTRY_CLAIM_BUT_NO_PROVENANCE",
            "Documentul invocă registru/autoritate, dar fără proveniență oficială verificabilă.",
        )

    if PAYMENT_DIVERSION_HOLD_RE.search(raw):
        _add(
            result,
            "PAYMENT_DIVERSION_HOLD_INSTRUCTIONS",
            "Mesajul cere oprirea plăților/lista facturilor deschise și promite instrucțiuni/cont nou ulterior.",
        )

    if IP_OFFICE_PAYMENT_RE.search(raw) and not OFFICIAL_IP_OFFICE_DOMAIN_RE.search(raw):
        _add(
            result,
            "IP_OFFICE_PAYMENT_REQUEST_UNOFFICIAL_CHANNEL",
            "Cerere de plată pentru WIPO/EPO/EUIPO/proprietate intelectuală fără domeniu oficial verificabil.",
        )

    if URGENT_PAYMENT_OVERRIDE_RE.search(raw) and not APPROVAL_EVIDENCE_RE.search(raw):
        _add(
            result,
            "URGENT_PAYMENT_OVERRIDE_NO_TICKET",
            "Cerere de plată urgentă care ocolește procedura internă/ticket/aprobare.",
        )

    return result
