"""SCAM_ATLAS_OFFER_ADVANCE_FAMILIES flag (default OFF) — offer-advance families.

Measured on prod 2026-07-10 (revision 00182-vsj, real e2e scans), then
re-verified on origin/main after #123. The current main already raises the car
advance to DANGEROUS, but labels it as an unrelated charity family. The
romance/stranded case stays SUSPECT and is mislabeled as sextortion.

The slice adds two specific atlas subfamilies whose signature is STRUCTURAL
(advance demanded before verification + refusal of verification + unreachable
counterparty). It improves classification without changing the verdict gate:
family-only evidence remains capped at SUSPECT, while an independently parsed
actionable money request can still reach DANGEROUS through the existing gate.

SYNTHETIC TEST VECTORS ONLY (constructed, not real reported cases).
"""

import os
import json
from pathlib import Path

import pytest

import eval.large_offline_fixture_runner as runner


def _base_env():
    for k, v in {
        "PRIVACY_SAFE_MODE": "false",
        "ENABLE_CLOUD_AI_EXPLANATION": "false",
        "ENABLE_MISTRAL_SHADOW_ADJUDICATION": "false",
        "ENABLE_DNS_REPUTATION": "false",
        "INVOICE_CACHE_HMAC_KEY": "ci-test-hmac-key",
    }.items():
        os.environ.setdefault(k, v)


def _result(text, channel="sms"):
    _base_env()
    return runner._run_case(
        {"id": "x", "text": text, "expected": "SAFE", "source": "synthetic", "meta": {"input_type": channel}}
    )


def _verdict(text, channel="sms"):
    return _result(text, channel=channel).get("actual")


@pytest.fixture
def families_on():
    _base_env()
    os.environ["SCAM_ATLAS_OFFER_ADVANCE_FAMILIES"] = "1"
    runner.engine.load_seed_data()
    yield
    os.environ.pop("SCAM_ATLAS_OFFER_ADVANCE_FAMILIES", None)
    runner.engine.load_seed_data()


CAR_ADVANCE_SCAM = (
    "Buna ziua, masina este inca disponibila, Golf 7 din 2019, 4900 EUR, pret redus ca plec "
    "urgent in Germania. Nu pot face proba, dar v-o trimit prin firma de transport cu verificare "
    "la destinatie. Trebuie doar sa achitati avansul de 500 EUR pentru transport si rezervare in "
    "contul firmei, restul la livrare."
)
ROMANCE_STRANDED_SCAM = (
    "Draga mea, sunt blocat pe aeroportul din Istanbul, mi-au retinut bagajul cu toate "
    "documentele. Am nevoie de 800 EUR pentru taxa de eliberare, iti returnez tot cand ajung. "
    "Te rog nu spune nimanui, mi-e rusine."
)


# ── flag OFF (default): seed not loaded, behaviour identical to main ────────

def test_flag_off_families_not_loaded():
    os.environ.pop("SCAM_ATLAS_OFFER_ADVANCE_FAMILIES", None)
    runner.engine.load_seed_data()
    ids = {f.get("id") for f in runner.engine.families}
    assert "RO-ADV-01" not in ids
    assert "RO-ADV-02" not in ids


def test_flag_off_pre_slice_verdicts_pinned():
    # #123 already catches the car request, while the cleanly-written romance
    # request remains warning-only. Neither may be SAFE.
    os.environ.pop("SCAM_ATLAS_OFFER_ADVANCE_FAMILIES", None)
    runner.engine.load_seed_data()
    assert _verdict(CAR_ADVANCE_SCAM) == "DANGEROUS"
    assert _verdict(ROMANCE_STRANDED_SCAM, channel="whatsapp") in {"SUSPECT", "UNVERIFIED"}


# ── flag ON: the two measured misses escalate ───────────────────────────────

def test_flag_on_families_loaded(families_on):
    ids = {f.get("id") for f in runner.engine.families}
    assert {"RO-ADV-01", "RO-ADV-02"} <= ids


def test_flag_on_car_advance_scam_escalates(families_on):
    result = _result(CAR_ADVANCE_SCAM)
    assert result["actual"] == "DANGEROUS"
    assert result["detected_family_id"] == "RO-ADV-01"


def test_flag_on_romance_stranded_scam_escalates(families_on):
    result = _result(ROMANCE_STRANDED_SCAM, channel="whatsapp")
    assert result["actual"] == "SUSPECT"
    assert result["detected_family_id"] == "RO-ADV-02"


@pytest.mark.parametrize(
    "text",
    [
        "Am facut un accident, am nevoie urgent de bani pentru cautiune, nu spune nimanui.",
        "Certificat marca OSIM aprobat. Platiti taxa de eliberare in IBAN-ul atasat.",
        (
            "Pachetul medical a ajuns in UE, dar robotul vamal nu poate asocia destinatarul. "
            "Trebuie cumparat un token digital de eliberare; il rambursez cand ajung."
        ),
    ],
)
def test_flag_on_romance_family_requires_relationship_and_travel_context(families_on, text):
    assert _result(text)["detected_family_id"] != "RO-ADV-02"


def test_offer_advance_families_have_official_provenance():
    seed_path = Path(__file__).parent / "data" / "scam_atlas_offer_advance_seed.json"
    payload = json.loads(seed_path.read_text(encoding="utf-8"))
    for family in payload["scam_families"]:
        refs = family.get("source_refs") or []
        assert refs, family["id"]
        assert all(ref.get("url", "").startswith("https://") for ref in refs)
        assert all(ref.get("source_type") == "official" for ref in refs)


# ── flag ON: FP boundaries — legit offers must NOT become DANGEROUS ─────────

def test_flag_on_legit_car_sale_with_viewing_not_dangerous(families_on):
    text = (
        "Buna ziua, masina se poate vedea si proba oricand in Bucuresti, sector 3. "
        "Accept verificare in orice service doriti. Pretul este 4900 EUR, usor negociabil "
        "la fata locului."
    )
    assert _verdict(text) != "DANGEROUS"


def test_flag_on_legit_rental_with_viewing_not_dangerous(families_on):
    text = (
        "Apartamentul de 2 camere este disponibil, chirie 450 EUR pe luna. Programam o "
        "vizionare maine dupa-amiaza, iar contractul se semneaza la notariat. Plata se face "
        "dupa semnarea contractului."
    )
    assert _verdict(text) != "DANGEROUS"


def test_flag_on_family_loan_not_dangerous(families_on):
    text = "Mama, poti sa-mi imprumuti 200 de lei pana vineri? Ti-i dau inapoi cand iau salariul."
    assert _verdict(text, channel="whatsapp") != "DANGEROUS"


def test_flag_on_benign_ticket_money_not_dangerous(families_on):
    # ps-02 shape from the P-MORPH benign set: descriptive, past-tense payment.
    text = "Multumesc pentru transfer, am primit banii pentru bilete. Pe curand!"
    assert _verdict(text, channel="whatsapp") != "DANGEROUS"


def test_flag_on_legit_agency_offer_not_dangerous(families_on):
    text = (
        "Oferta City Break Roma, 3 nopti, 199 EUR de persoana. Rezervarea se face pe site-ul "
        "agentiei, cu plata online securizata si factura fiscala. Detalii si conditii pe pagina ofertei."
    )
    assert _verdict(text, channel="email") != "DANGEROUS"


def test_flag_on_descriptive_past_payment_not_dangerous(families_on):
    # Describing an already-made payment is not a request (intent analysis guard).
    text = "Am platit ieri avansul pentru apartament, contractul e semnat la notariat."
    assert _verdict(text) != "DANGEROUS"
