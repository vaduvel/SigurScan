"""P0 regression: tier1 calibrator must not stomp a real social-engineering
intent verdict down to benign.

Root cause (confirmed in code): _calibrate_semantic_review_with_tier1 overrode
risk_class -> "benign" whenever the naive-Bayes tier1 classifier said "legit"
with confidence >= 0.55, WITHOUT looking at what the semantic analysis (Mistral)
concluded. Formal-sounding authority scams ("Parchet", "dosar penal") get
classified as official_notice -> stomped to benign -> gate falls to UNVERIFIED/SAFE.

The fix is source/severity-aware AND social-engineering-aware, while still letting
tier1 calm down genuine marketing false positives.
"""

import main as app_main
from main import _calibrate_semantic_review_with_tier1, _has_social_engineering_pressure
from services.tier1_classifier import _tokens


AUTHORITY_SCAM = (
    "Buna ziua, sunt comisar la Parchet. Pe numele dumneavoastra exista un dosar "
    "penal. Nu spuneti nimanui din familie, ancheta e clasificata. Ramaneti pe linie "
    "si urmati instructiunile."
)
SAFE_ACCOUNT_SCAM = (
    "Sunt de la anti-frauda bancii. Pentru a bloca atacatorul, mutati imediat soldul "
    "in contul de protectie temporar."
)
LEGIT_BANK_ALERT = "BT: tranzactie aprobata 149.99 lei la eMAG. Detalii in aplicatia BT Pay."
LEGIT_COURIER = "Sameday: coletul AWB 712334 este in livrare azi. Urmareste in aplicatie."
LEGIT_MARKETING = "eMAG: oferta limitata weekendul acesta, pana la -50%. Vezi produsele."


# ── Condition 1b helper: _has_social_engineering_pressure ────────────────────

def test_se_pressure_true_on_authority_scam():
    assert _has_social_engineering_pressure(AUTHORITY_SCAM) is True


def test_se_pressure_true_on_safe_account_scam():
    assert _has_social_engineering_pressure(SAFE_ACCOUNT_SCAM) is True


def test_se_pressure_false_on_legit_bank_alert():
    assert _has_social_engineering_pressure(LEGIT_BANK_ALERT) is False


def test_se_pressure_false_on_legit_marketing():
    assert _has_social_engineering_pressure(LEGIT_MARKETING) is False


# ── Condition 1a: SE pressure blocks downgrade even of a HIGH verdict ─────────

def test_calibrator_cannot_downgrade_high_review_with_se_pressure():
    """Even a high verdict + tier1 'legit' cannot be stomped to benign when the
    text carries social-engineering pressure (authority/secrecy/callback)."""
    review = {"risk_class": "high", "source": "mistral_semantic_pillar", "reason_codes": []}
    tier1 = {"label": "official_notice", "confidence": 0.9, "source": "tier1_local_classifier"}
    out = _calibrate_semantic_review_with_tier1(review, tier1, raw_text=AUTHORITY_SCAM)
    assert out["risk_class"] == "high"


def test_calibrator_still_downgrades_high_marketing_false_positive():
    """Precision invariant we must NOT regress: a high atlas/Mistral false-positive
    on plain marketing text (no SE pressure) is still calmed to benign by tier1."""
    review = {"risk_class": "high", "source": "mistral_semantic_pillar", "reason_codes": []}
    tier1 = {"label": "legit_marketing", "confidence": 0.82, "source": "tier1_local_classifier"}
    out = _calibrate_semantic_review_with_tier1(
        review, tier1, raw_text="SALE pana la -50%! Pantofi de top la jumatate de pret."
    )
    assert out["risk_class"] == "benign"


# ── Condition 1b: SE-lever guard (even for weak/unknown incoming review) ──────

def test_calibrator_cannot_downgrade_when_se_pressure_present():
    review = {"risk_class": "unknown", "source": "scam_atlas_family_match", "reason_codes": []}
    tier1 = {"label": "official_notice", "confidence": 0.92, "source": "tier1_local_classifier"}
    out = _calibrate_semantic_review_with_tier1(review, tier1, raw_text=AUTHORITY_SCAM)
    assert out["risk_class"] != "benign"


# ── Condition 4 (precision preserved): genuine marketing still calmed down ────

def test_calibrator_still_downgrades_benign_marketing():
    review = {"risk_class": "unknown", "source": "scam_atlas_family_match", "reason_codes": []}
    tier1 = {"label": "legit_marketing", "confidence": 0.9, "source": "tier1_local_classifier"}
    out = _calibrate_semantic_review_with_tier1(review, tier1, raw_text=LEGIT_MARKETING)
    assert out["risk_class"] == "benign"
    assert out["claim_matches_legit_template"] is True


# ── Condition 3: tier1 stopword hygiene ──────────────────────────────────────

def test_tier1_tokens_drop_romanian_stopwords():
    toks = _tokens("Aveti o factura noua de la furnizor pe luna aceasta")
    assert "de" not in toks
    assert "la" not in toks
    assert "pe" not in toks
    # meaningful content words survive
    assert "factura" in toks
    assert "furnizor" in toks
