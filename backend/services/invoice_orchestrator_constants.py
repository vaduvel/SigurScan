"""Static detection constants for the invoice/offer orchestrator.

Regex patterns, beneficiary stopword sets and the B2B fraud-flag taxonomies were
extracted from invoice_orchestrator.py to separate static detection data from scan
logic. Pure literals depending only on `re`.
"""

import re


_DIACRITICS = str.maketrans("ăâîșşțţ", "aaisstt")
_COMPANY_MARKERS = re.compile(
    r"\b(s\.?\s?r\.?\s?l|s\.?\s?a|s\.?\s?c|p\.?\s?f\.?\s?a|i\.?\s?i|s\.?\s?n\.?\s?c|"
    r"s\.?\s?c\.?\s?s|s\.?\s?c\.?\s?a|i\.?\s?f\.?\s?n|i\.?\s?f|r\.?\s?a|"
    r"societate|societatea|asociat|fundat|regia|intreprindere|cooperativa|cabinet|"
    r"sucursala|gmbh|ltd|llc|inc|s\.?p\.?a)\b",
    re.IGNORECASE,
)
_ACCOUNT_CHANGE_RE = re.compile(
    r"(am\s+schimbat\s+(contul|banca|iban)|cont(ul)?\s+(nou|s-?a\s+schimbat|modificat|actualizat)|"
    r"noul\s+(nostru\s+)?(cont|iban)|iban[-\s]*(ul)?\s*(nou|s-?a\s+(schimbat|modificat))|"
    r"schimbare\s+(de\s+)?cont\s+bancar|date(le)?\s+bancare\s+(au\s+fost\s+)?(modificat|actualizat|schimbat)|"
    r"changed\s+(our\s+)?(bank\s+account|account\s+details|iban)|new\s+(bank\s+)?account)",
    re.IGNORECASE,
)
_PRESSURE_RE = re.compile(
    r"(astazi|imediat|(?:in|în)\s*24\s*(?:h|ore|de\s*ore)?|\b24\s*h\b|ultima\s+zi|chiar\s+acum|de\s+urgenta|"
    r"altfel\s+(se\s+)?(suspend|debrans|deconect|pierde|anuleaz|sista)|debransare|"
    r"deconectare|executare\s+silita|poprire|pierdeti\s+comanda|risc(ati)?\s+(suspendare|debransare)|"
    r"evita(?:ti)?\s+(?:suspendarea|deconectarea|debransarea|penalizarile|blocarea))",
    re.IGNORECASE,
)
_NAME_STOPWORDS = {
    "sc",
    "srl",
    "srld",
    "sa",
    "pfa",
    "ii",
    "if",
    "ifn",
    "snc",
    "scs",
    "sca",
    "ra",
    "de",
    "si",
    "buna",
    "ziua",
    "salut",
    "hello",
    "echipa",
    "departament",
    "departamentul",
    "cu",
    "stima",
}
_GENERIC_BENEFICIARY_TERMS = {
    "beneficiar",
    "cont",
    "firma",
    "furnizor",
    "nou",
    "noua",
    "partener",
    "plata",
    "procesator",
    "societate",
    "vendor",
}
B2B_HIGH_RISK_FLAGS = {
    "BEC_REPLY_TO_ACCOUNT_CHANGE",
    "QR_PRINTED_IBAN_MISMATCH",
    "FAKE_EFACTURA_RECONCILIATION_PAYMENT",
    "FRAGMENTED_IBAN_PAYMENT_TARGET",
    "UNDISCLOSED_INTERMEDIARY_BENEFICIARY",
    "BENEFICIARY_COMPANY_MISMATCH",
    "DOCUMENT_LAYER_IBAN_CONFLICT",
    "CEO_CONFIDENTIAL_PAYMENT",
    "PHISHING_LINK_IN_INVOICE_EMAIL",
    "INVOICE_ATTACHMENT_EXECUTABLE",
    "REMOTE_ACCESS_REQUEST",
    "OSIM_TRADEMARK_FEE_UNOFFICIAL_SENDER",
    "LEGAL_DEMAND_PAYMENT_TO_NEW_IBAN",
    "SAAS_LICENSE_AUDIT_URGENT_PAYMENT",
    "PO_OR_OVERPAYMENT_RETURN_REQUEST",
    "PAYROLL_OR_EMPLOYEE_DATA_REQUEST_VIA_INVOICE_THREAD",
    "URGENT_PAYMENT_OVERRIDE_NO_TICKET",
    "EFACTURA_OFFICIAL_DOCUMENT_MISMATCH",
    "PAYMENT_DIVERSION_HOLD_INSTRUCTIONS",
    "IP_OFFICE_PAYMENT_REQUEST_UNOFFICIAL_CHANNEL",
    "REGULATED_FINANCE_ADVANCE_FEE_OR_ID_REQUEST",
    "COURIER_CUSTOMS_OR_ADDRESS_FEE_PAYMENT",
    "GRANT_CONSULTING_FEE_BEFORE_CONTRACT",
    "BEC_EXCLUSIVE_NEW_IBAN_WITH_OLD_DETAILS_SUPPRESSION",
    "BEC_INVOICE_THREAD_IBAN_CHANGE",
    "TAX_AUTHORITY_PAYMENT_REQUEST_UNOFFICIAL_CHANNEL",
    "TAX_AUTHORITY_SENSITIVE_DATA_REQUEST",
    "COURIER_OTP_OR_WHATSAPP_CODE_REQUEST",
    "TAX_AUTHORITY_APPROVES_UPDATED_IBAN",
}
B2B_MEDIUM_RISK_FLAGS = {
    "REPLY_TO_MISMATCH",
    "FREE_EMAIL_FOR_COMPANY_INVOICE",
    "EFACTURA_CLAIM_WITHOUT_DOCUMENT",
    "EFACTURA_OFFICIAL_DOCUMENT_UNREADABLE",
    "PAYMENT_LINK_UNKNOWN_PSP",
    "DOMAIN_RENEWAL_INVOICE_NO_EXISTING_VENDOR",
    "NEW_VENDOR_PUBLIC_PROCUREMENT_FEE",
    "OFFICIAL_REGISTRY_CLAIM_BUT_NO_PROVENANCE",
    "HIGH_VALUE_UNCONFIRMED_PAYMENT_DESTINATION",
}
_SENSITIVE_NEGATION_RE = re.compile(
    r"\b(nu|niciodata|niciodată|fara|fără|nici\s+un)\b",
    re.IGNORECASE,
)


_UNTRUSTED_INTAKE = {"whatsapp", "sms", "phone", "social_dm", "messenger", "telegram", "unknown"}
