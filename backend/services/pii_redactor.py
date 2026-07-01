import re

# Regex patterns for common PII in Romania
EMAIL_REGEX = re.compile(
    r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'
)

# Romanian IBAN: RO followed by 2 digits, then 4 letters, then 16 alphanumeric chars (typically digits)
# Example: RO89 BTRL 0130 1202 3456 78XX or RO89BTRL0130120234567800
IBAN_REGEX = re.compile(
    r'\bRO\d{2}[A-Z]{4}[A-Z0-9]{16}\b|\bRO\s*\d{2}\s*[A-Z]{4}(\s*[A-Z0-9]{4}){4}\b',
    re.IGNORECASE
)

# Credit Card (13 to 19 digits, possibly separated by spaces or hyphens)
CARD_REGEX = re.compile(
    r'\b(?:\d[ -]*?){13,19}\b'
)

# Romanian Phone numbers: prefix +40 or 0040 followed by 9 digits, or local 07xx, 02xx, 03xx
# E.g., 0722 123 456, +40722123456, 0722-123-456, 0722.123.456, etc.
PHONE_REGEX = re.compile(
    r'(?:\+40|0040|40)?[ -|\.]?[0-9]{3}[ -|\.]?[0-9]{3}[ -|\.]?[0-9]{3,4}\b|\b07[0-9]{2}[ -|\.]?[0-9]{3}[ -|\.]?[0-9]{3}\b'
)

# Romanian CNP is 13 digits, usually introduced by the CNP keyword. Keep this
# keyword-scoped so ordinary order IDs are not masked as identity data.
CNP_REGEX = re.compile(
    r'\b(CNP|cod\s+numeric\s+personal)\s*[:#-]?\s*(\d{13})\b',
    re.IGNORECASE
)

# One-Time Passwords / Verification codes:
# Usually a 4-8 digit code near keywords like "cod", "verification", "verificare", "OTP", "activare", "autorizare"
OTP_KEYWORDS = [
    "cod",
    "codul",
    "otp",
    "verificare",
    "verification",
    "activare",
    "autorizare",
    "confirmare",
    "security",
    "securitate",
]
OTP_REGEX = re.compile(
    rf'\b(?:{"|".join(OTP_KEYWORDS)})\b.*?\b(\d{{4,8}}|\d{{3}}[- ]\d{{3,4}})\b',
    re.IGNORECASE
)

def redact_pii(text: str) -> str:
    """
    Redacts personally identifiable information (PII) from a given text.
    Replaces:
    - Email addresses with [EMAIL_REDACTED]
    - Romanian IBANs with [IBAN_REDACTED]
    - Credit Card numbers with [CARD_REDACTED]
    - Phone numbers with [PHONE_REDACTED]
    - OTP/verification codes with [OTP_REDACTED]
    """
    if not text:
        return ""

    # 1. Redact Email addresses
    text = EMAIL_REGEX.sub("[EMAIL_REDACTED]", text)

    # 2. Redact IBANs
    text = IBAN_REGEX.sub("[IBAN_REDACTED]", text)

    # 3. Redact OTP/Verification codes (specifically the code matched by capture group)
    # We do a custom replacement since we only want to mask the number, not the keyword
    def otp_replacer(match):
        full_match = match.group(0)
        code = match.group(1)
        # Find start and end of code in full match and replace it
        start_idx = full_match.rfind(code)
        redacted_full = full_match[:start_idx] + "[OTP_REDACTED]" + full_match[start_idx + len(code):]
        return redacted_full

    # Run OTP replacer a few times to get multiple matches if present
    # We loop or run sub
    text = OTP_REGEX.sub(otp_replacer, text)

    # 3b. Redact Romanian CNP values when explicitly labeled as such.
    text = CNP_REGEX.sub(lambda match: f"{match.group(1)} [CNP_REDACTED]", text)

    # 4. Redact Credit Cards (make sure we don't redact plain short numbers, CARD_REGEX is 13-19 digits)
    text = CARD_REGEX.sub("[CARD_REDACTED]", text)

    # 5. Redact Romanian Phone Numbers
    text = PHONE_REGEX.sub("[PHONE_REDACTED]", text)

    return text
