import re


_OBFUSCATED_DOT_RE = re.compile(r"\[\.\]|\(\.\)|\{\.\}")
# Zero-width and bidirectional control characters used to shatter keywords
# ("ca<ZWSP>rd") or reverse displayed URLs (RLO U+202E). Stripped before any
# matching so detection sees the real text.
_ZERO_WIDTH_BIDI_CHARS = "".join(
    chr(c)
    for c in (
        0x200B,
        0x200C,
        0x200D,
        0x200E,
        0x200F,  # zero-width, LRM, RLM
        0x202A,
        0x202B,
        0x202C,
        0x202D,
        0x202E,  # bidi embeddings / overrides (RLO)
        0x2060,
        0x2066,
        0x2067,
        0x2068,
        0x2069,  # word joiner, bidi isolates
        0xFEFF,  # BOM / ZWNBSP
    )
)
_ZERO_WIDTH_BIDI_RE = re.compile(f"[{re.escape(_ZERO_WIDTH_BIDI_CHARS)}]")
# Spaced-out single letters ("c a r d u l u i") used to evade keyword matching.
# Requires a run of >=4 single letters separated by single spaces and bounded by
# whitespace/edges, so ordinary words and short acronyms ("T V A") are untouched.
_SPACED_LETTERS_RE = re.compile(r"(?<!\S)[A-Za-z](?: [A-Za-z]){3,}(?!\S)")


def _normalise_obfuscated_text(value: str) -> str:
    """
    Make phishing-style obfuscated URLs more detectable.

    Handles common tricks:
    - hxxp:// / hxxps://
    - example[.]com, example(.)com, example{.}com
    - "http ://" spaces around separators
    """
    if not value:
        return value

    # Strip zero-width / bidi control characters before anything else, so keyword
    # and URL matching sees the real text ("ca<ZWSP>rd" -> "card").
    normalized = _ZERO_WIDTH_BIDI_RE.sub("", value)
    normalized = re.sub(
        r"hxxp(s?)\s*://",
        lambda match: f"http{'s' if match.group(1) else ''}://",
        normalized,
        flags=re.IGNORECASE,
    )
    normalized = _OBFUSCATED_DOT_RE.sub(".", normalized)
    # Keep phishing-style "brand . ro" detectable, but do not join normal sentence
    # boundaries ("...pierzi acces. NU amana", "Suna acum. nu astepta") into fake
    # domains. A deliberately obfuscated domain carries whitespace BEFORE the dot
    # ("brand . ro"); a sentence period does not ("acces."). Requiring \\s+ before
    # the dot is the discriminator — without it, common Romanian words that are
    # also ccTLDs (nu/da/ro) get fabricated into .nu/.da/.ro domains.
    normalized = re.sub(
        r"(?<=[A-Za-z0-9-])\s+\.\s*(?=(?:[a-z]{2,24}|[A-Z]{2,24})(?:\b|/))",
        ".",
        normalized,
    )
    normalized = re.sub(
        r"\b(https?)\s*:\s*/\s*/",
        lambda match: f"{match.group(1)}://",
        normalized,
        flags=re.IGNORECASE,
    )
    # Collapse spaced-out single letters ("c a r d u l u i" -> "cardului") so the
    # keyword survives. Bounded + >=4 letters, so ordinary words are untouched.
    normalized = _SPACED_LETTERS_RE.sub(lambda match: match.group(0).replace(" ", ""), normalized)
    return normalized
