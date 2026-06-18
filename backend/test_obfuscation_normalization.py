"""L0 normalization: defeat zero-width, bidi, and spaced-letter obfuscation so
downstream keyword/regex detection sees the real text.

OBF-01 ("i n t r o d u c e t i  c a r d u l u i") and OBF-03 ("ca<ZWSP>rd")
previously slipped past every text rule because the keyword was shattered before
any matching happened.
"""

from main import _normalise_obfuscated_text


# ── zero-width strip (U+200B..U+200D, U+FEFF) ────────────────────────────────

def test_strips_zero_width_space():
    out = _normalise_obfuscated_text("Confirma datele ca​rdului si paro​la")
    assert "​" not in out
    assert "cardului" in out.lower()


def test_strips_zero_width_joiner_and_bom():
    out = _normalise_obfuscated_text("co‍d o﻿tp")
    assert "‍" not in out and "﻿" not in out


# ── bidi control strip (RLO etc.) ────────────────────────────────────────────

def test_strips_bidi_controls():
    out = _normalise_obfuscated_text("livrare‮gpa.kcart‬/confirm")
    for ch in ("‪", "‫", "‬", "‭", "‮"):
        assert ch not in out


# ── spaced-letter collapse ───────────────────────────────────────────────────

def test_collapses_spaced_out_word():
    out = _normalise_obfuscated_text(
        "Pentru deblocare, i n t r o d u c e t i  d a t e l e  c a r d u l u i aici"
    )
    assert "card" in out.lower()
    assert "introduceti" in out.lower()


# ── must NOT mangle ordinary text ────────────────────────────────────────────

def test_does_not_collapse_ordinary_sentence():
    text = "Plec la mare cu o barca si un caine maine."
    assert _normalise_obfuscated_text(text) == text


def test_does_not_collapse_short_initials():
    # 3 single letters (e.g. an acronym spelled out) must stay intact
    text = "Lucrez la T V A de ani de zile"
    assert _normalise_obfuscated_text(text) == text
