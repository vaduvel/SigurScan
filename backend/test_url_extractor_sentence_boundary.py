"""Regression: URL extractor must not fabricate domains from Romanian sentence
boundaries.

'.nu' / '.ro' / '.da' are real ccTLDs, and 'NU'/'nu'/'DA' are everyday Romanian
words. A period that ends a sentence ("...pierzi acces. NU amana") was joined
into a fake domain ("acces.nu") which then got resolved/RDAP'd against real
providers and polluted the verdict.

A genuine obfuscated domain carries a space BEFORE the dot ("brand . ro"); a
sentence period does not ("acces."). That is the discriminator.
"""

from main import _normalise_obfuscated_text, extract_urls


# ── must NOT fabricate URLs from sentence boundaries ─────────────────────────

def test_extract_urls_ignores_allcaps_word_after_period():
    assert extract_urls("Mergi acasa. NU uita cheile.") == []


def test_extract_urls_ignores_nu_after_otp_code():
    assert extract_urls("Codul tau este 482913. NU il da nimanui.") == []


def test_extract_urls_ignores_lowercase_word_after_period():
    assert extract_urls("Suna acum. nu mai astepta raspunsul.") == []


# ── must STILL keep genuine links and obfuscated domains ─────────────────────

def test_extract_urls_keeps_real_link():
    assert extract_urls("Viziteaza https://emag.ro/promo acum") == ["https://emag.ro/promo"]


def test_normalise_keeps_spaced_obfuscated_domain():
    # deliberate obfuscation: space BEFORE the dot
    assert "brand.ro" in _normalise_obfuscated_text("intra pe brand . ro acum")


def test_normalise_keeps_bracket_obfuscated_domain():
    assert "brand.ro" in _normalise_obfuscated_text("intra pe brand[.]ro acum")
