"""P-MORPH-WIRE — ro_morphology wired into the scam_atlas semantic detectors.

Two guarantees, both on the false-PERICOL-sensitive path:
1. RECALL — morphological scam phrasings that the pre-P-MORPH keyword layer missed
   (diacritics, inflection, context inflection) are now detected. These are the
   cases the #118 recall gate measured as missed (recall 0.766 -> 0.915).
2. FP SAFETY — benign messages that STRESS the same widened patterns (a friendly
   "thanks for the transfer, got the money", a benign WhatsApp code, a benign
   "my account is safe now") do NOT become DANGEROUS at verdict level.
"""

import pytest

from services.scam_atlas import ScamAtlasEngine, _morph_fold
from eval.large_offline_fixture_runner import _run_case

_ENGINE = ScamAtlasEngine()


def _signals(text: str) -> str:
    return " || ".join(
        _ENGINE.check_sensitive_requests(text) + _ENGINE.check_language_manipulation(text)
    ).lower()


# scam phrasings missed before P-MORPH-WIRE; (text, expected signal substring)
NEWLY_DETECTED = [
    ("Muta suma in contul sigur indicat de noi.", "transfer de bani"),
    ("Transferă toți banii în contul sigur al băncii.", "transfer de bani"),
    ("Trimite banii prin transfer bancar imediat.", "transfer de bani"),
    ("Instalează RustDesk ca suportul tehnic să preia controlul.", "acces la distan"),
    ("Pune AnyDesk pe telefon ca brokerul sa vada contul.", "acces la distan"),
    ("Trimite-mi codul de pe WhatsApp ca sa confirm.", "whatsapp"),
    ("Spune codul primit pe WhatsApp pentru verificare.", "whatsapp"),
]


@pytest.mark.parametrize("text,expected_sub", NEWLY_DETECTED)
def test_morphological_scam_phrasings_now_detected(text, expected_sub):
    assert expected_sub in _signals(text), text


# benign messages that stress the widened patterns; must stay non-DANGEROUS.
BENIGN_STRESS = [
    "Multumesc pentru transfer, am primit banii pentru bilete. Pe curand!",
    "Contul meu de Instagram e sigur acum, am pus verificare in doi pasi.",
    "Ti-am trimis codul de la interfon pe WhatsApp, e 4821, ne vedem sus.",
    "Am vorbit cu consultantul de la banca despre credit, totul e ok.",
    "Transfera-mi te rog partea ta cand poti, nu-i graba.",
    "Am facut un transfer bancar catre proprietar pentru chirie.",
]


@pytest.mark.parametrize("text", BENIGN_STRESS)
def test_benign_stress_not_flagged_dangerous(text):
    res = _run_case({"source": "pmw", "id": "b", "expected": "SAFE", "meta": {}, "text": text})
    actual = "SUSPECT" if res["actual"] == "UNVERIFIED" else res["actual"]
    assert actual != "DANGEROUS", (text, res["actual"])


def test_fold_escape_hatch(monkeypatch):
    monkeypatch.setenv("SCAM_ATLAS_MORPH_FOLD", "0")
    assert _morph_fold("transferă") == "transferă"  # disabled: not folded
    monkeypatch.setenv("SCAM_ATLAS_MORPH_FOLD", "1")
    assert _morph_fold("transferă") == "transfera"  # default: folded
