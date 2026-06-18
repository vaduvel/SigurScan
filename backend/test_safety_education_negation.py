"""EDGE-04: educational anti-scam content that DESCRIBES scams and tells the
reader "nu da codul nimanui" must not be flagged DANGEROUS.

The protective-negation requirement is also the discriminator against adversarial
"educational" framing that hides a real request ("exerseaza introducand datele
cardului") — that has no negation, so it must NOT be treated as safety education.
"""

from main import (
    _apply_provider_gate_verdict,
    _looks_like_official_safety_education,
    _normalise_obfuscated_text,
    engine,
)
from services.pii_redactor import redact_pii


EDU = (
    "Newsletter educatie financiara: cum recunosti un scam cu OTP, IBAN fals si "
    "transfer in cont sigur. Nu da niciodata codul nimanui."
)
ADVERSARIAL_EDU_WITH_REQUEST = (
    "Ghid educativ de securitate: ca sa intelegi cum arata o verificare reala, "
    "exerseaza acum introducand datele cardului in formularul-demo de mai jos."
)


def _label(text, channel="email"):
    red = redact_pii(_normalise_obfuscated_text(text))
    a = engine.analyze(red, urls=[], external_threat_intel={})
    a.setdefault("evidence", {})["source_channel"] = channel
    fa = _apply_provider_gate_verdict(a, [], raw_text=red, pillars={})
    return fa["evidence"]["verdict_gate"]["label"]


def test_education_with_protective_negation_is_detected():
    assert _looks_like_official_safety_education(EDU) is True


def test_education_content_is_not_dangerous():
    assert _label(EDU) != "DANGEROUS"


def test_adversarial_education_with_real_request_is_not_safety_education():
    # has a positive request and no protective negation -> stays detectable
    assert _looks_like_official_safety_education(ADVERSARIAL_EDU_WITH_REQUEST) is False
