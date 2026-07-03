"""Red->green guard for BUG#1: authority/vishing identity-data requests.

Authority impersonation scams ask for generic "date de identificare" / "date
personale" / CNP rather than "act de identitate"/"buletin". Before the fix that
phrasing produced no HARD_SENSITIVE_REQUESTS token, so the gate could not
escalate sensitive-on-wrong-channel (police-impersonation vishing -> SUSPECT/
UNVERIFIED). These tests pin the deterministic floor and its parity across the
two sensitivity derivations, plus the anti-false-positive gating.
"""

from services.provider_gate import _request_sensitivity_from_signals_impl as pg_sensitivity
from services.scan_analysis import _request_sensitivity_from_signals as sa_sensitivity
from services.verdict_gate import verdict

POLICE = (
    "Sunt de la Politie, o institutie a statului. Numele dvs. e implicat intr-un dosar. "
    "Pentru a va dovedi nevinovatia, furnizati datele de identificare si cooperati telefonic acum."
)


def _sens(fn, text, dsr=True):
    return fn(
        raw_text=text,
        brand_warning={"triggered": False, "matched_assets": []},
        direct_sensitive_request=dsr,
        sensitive_url_path=False,
        official_destination=False,
        resolved_urls=[],
    )


def test_identity_data_request_maps_to_id_document_both_paths():
    # Parity: both the provider-gate and scan-analysis derivations agree.
    assert _sens(pg_sensitivity, POLICE) == "id_document"
    assert _sens(sa_sensitivity, POLICE) == "id_document"


def test_cnp_request_maps_to_cnp_both_paths():
    text = "Pentru verificare, transmiteti CNP-ul si datele personale."
    assert _sens(pg_sensitivity, text) == "cnp"
    assert _sens(sa_sensitivity, text) == "cnp"


def test_existing_act_de_identitate_still_maps():
    # Regression: the pre-existing detection must keep working.
    assert _sens(pg_sensitivity, "Trimiteti o poza cu actul de identitate.") == "id_document"


def test_official_kyc_portal_identity_upload_stays_none_both_paths():
    text = (
        "Pentru deschiderea contului de brokeraj, conform cerintelor legale KYC, "
        "incarcati actul de identitate si extrasul de cont in portalul oficial "
        "securizat. Nu efectuati nicio plata in afara platformei oficiale."
    )
    assert _sens(pg_sensitivity, text) == "none"
    assert _sens(sa_sensitivity, text) == "none"


def test_benign_identity_mentions_stay_none_both_paths():
    benign = [
        "Nu transmitem niciodata date personale prin telefon.",
        "Prelucrarea datelor personale se face conform GDPR si politicii de confidentialitate.",
        "Datele personale sunt protejate si nu sunt partajate cu terti.",
    ]
    for text in benign:
        assert _sens(pg_sensitivity, text, dsr=False) == "none", text
        assert _sens(sa_sensitivity, text, dsr=False) == "none", text


def test_identity_request_escalates_dangerous_on_wrong_channel():
    # End-to-end: id_document + wrong channel + action -> DANGEROUS deterministically
    # (independent of providers / Mistral).
    result = verdict({
        "request": {"sensitive": "id_document", "channel": "phone", "positive_action_request": True},
        "semantic_review": {"status": "done"},
    })
    assert result["label"] == "DANGEROUS", result
    assert "sensitive_wrong_channel" in result["reason_codes"], result
