from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

import main as app_main
from services.cross_scan_knowledge import evaluate_cross_scan_knowledge
from services.anaf_cui import CuiResult
from services.invoice_orchestrator import scan_offer
from services.offer_evidence_gate_mapper import evaluate_offer_verdict
from services.offer_entity_verifier import OfferEntityResult
from services.offer_parser import parse_offer


def test_cross_scan_matches_official_payment_destination_for_any_text():
    text = (
        "DPD Romania: taxa Non-UE se achita in contul "
        "RO92RZBR0000060002951611."
    )

    result = evaluate_cross_scan_knowledge(
        text=text,
        claimed_brand="dpd_romania",
        cui="9566918",
        source_channel="sms",
    )

    payment = result["payment_destinations"][0]
    assert payment["matched"] is True
    assert payment["brand_matches"] is True
    assert payment["can_contribute_to_safe"] is True
    assert payment["iban_masked_for_client"] == "RO92 RZBR **** **** **** 1611"


def test_cross_scan_ignores_ron_text_before_official_iban():
    text = (
        "DPD Romania: taxa Non-UE 17 RON se achita in contul "
        "RO92RZBR0000060002951611."
    )

    result = evaluate_cross_scan_knowledge(
        text=text,
        claimed_brand="dpd_romania",
        source_channel="sms",
    )

    assert len(result["payment_destinations"]) == 1
    assert result["payment_destinations"][0]["matched"] is True
    assert result["fraud_flags"] == []


def test_cross_scan_trims_overcaptured_word_after_iban():
    text = (
        "RETIM Ecologic Service S.A. CUI 9112229. "
        "Cont contractual RO54BRDE360SV07195093600 pentru servicii de salubritate."
    )

    result = evaluate_cross_scan_knowledge(
        text=text,
        claimed_brand="retim",
        cui="9112229",
        source_channel="sms",
    )

    payment = result["payment_destinations"][0]
    assert payment["matched"] is True
    assert payment["brand_id"] == "retim_ecologic_service"
    assert payment["confidence"] == "medium"
    assert payment["can_contribute_to_safe"] is False


def test_cross_scan_marks_unknown_payment_destination_for_known_brand():
    text = (
        "DPD Romania: achita urgent diferenta de livrare in contul "
        "RO49AAAA1B31007593840000."
    )

    result = evaluate_cross_scan_knowledge(
        text=text,
        claimed_brand="dpd_romania",
        cui="9566918",
        source_channel="sms",
    )

    payment = result["payment_destinations"][0]
    assert payment["matched"] is False
    assert payment["registry_has_brand_destinations"] is True
    assert "UNKNOWN_PAYMENT_DESTINATION" in result["fraud_flags"]


def test_cross_scan_applies_brand_never_asks_to_non_invoice_text():
    text = "BCR securitate: instaleaza AnyDesk si muta banii intr-un cont sigur."

    result = evaluate_cross_scan_knowledge(
        text=text,
        claimed_brand="bcr",
        source_channel="sms",
    )

    assert "bcr" in result["brand_never_asks"]["brand_ids"]
    assert "remote_access" in result["brand_never_asks"]["violated_never_asks"]
    assert "safe_account_transfer" in result["brand_never_asks"]["violated_never_asks"]


def test_cross_scan_does_not_treat_safety_education_as_never_asks_violation():
    text = (
        "Banca Transilvania: daca nu recunosti tranzactia, suna la banca. "
        "Nu comunica niciodata codul OTP sau PIN-ul."
    )

    result = evaluate_cross_scan_knowledge(
        text=text,
        claimed_brand="banca_transilvania",
        source_channel="sms",
    )

    assert result["brand_never_asks"]["violated_never_asks"] == []


def test_cross_scan_applies_olx_card_for_receiving_money_warning():
    text = (
        "Am platit pe OLX. Ca sa primesti banii, intra pe link si introdu "
        "datele cardului si codul CVV: https://olx-incasare.example/card"
    )

    result = evaluate_cross_scan_knowledge(
        text=text,
        claimed_brand="olx",
        source_channel="whatsapp",
    )

    assert "olx" in result["brand_never_asks"]["brand_ids"]
    assert "card_data_for_receiving_money" in result["brand_never_asks"]["violated_never_asks"]
    assert "card_number" in result["brand_never_asks"]["violated_never_asks"]
    assert "cvv" in result["brand_never_asks"]["violated_never_asks"]


def test_cross_scan_applies_dpd_card_data_warning_from_romania_research():
    text = (
        "DPD Romania: coletul tau necesita confirmare. "
        "Achita taxa si introdu datele cardului plus CVV: https://dpd-plata.example/card"
    )

    result = evaluate_cross_scan_knowledge(
        text=text,
        claimed_brand="dpd_romania",
        source_channel="sms",
    )

    assert "dpd_romania" in result["brand_never_asks"]["brand_ids"]
    assert "card_number" in result["brand_never_asks"]["violated_never_asks"]
    assert "cvv" in result["brand_never_asks"]["violated_never_asks"]


@pytest.mark.asyncio
async def test_offer_bundle_carries_cross_scan_payment_destination_context():
    text = (
        "DPD Romania SRL\nCUI: 9566918\nTaxa Non-UE: 17 RON\n"
        "IBAN: RO92RZBR0000060002951611"
    )
    cui = CuiResult(
        exists=True,
        checked=True,
        denumire="DYNAMIC PARCEL DISTRIBUTION SA",
        activ=True,
        data_inactivare=None,
        platitor_tva=True,
        enrolled_efactura=False,
        raw=None,
    )

    with patch("services.offer_entity_verifier.check_cui", new_callable=AsyncMock) as mock:
        mock.return_value = cui
        result = await scan_offer(text)

    cross = result.bundle["context"]["cross_scan_knowledge"]
    assert cross["payment_destinations"][0]["matched"] is True
    assert cross["payment_destinations"][0]["brand_matches"] is True


def test_generic_provider_gate_carries_cross_scan_never_asks_context():
    analysis = {
        "claimed_brand": "bcr",
        "risk_level": "low",
        "risk_score": 10,
        "evidence": {
            "source_channel": "sms",
            "external_intel_summary": {},
            "semantic_review": {"status": "done", "risk_class": "low", "completeness": True},
        },
    }

    result = app_main._apply_provider_gate_verdict(
        analysis,
        [],
        raw_text="BCR securitate: instaleaza AnyDesk si muta banii intr-un cont sigur.",
    )

    bundle = result["evidence"]["decision_bundle"]
    assert "remote_access" in bundle["identity"]["violated_never_asks"]
    assert "safe_account_transfer" in bundle["identity"]["violated_never_asks"]


def test_orchestrated_job_keeps_sanitized_cross_scan_context_after_iban_redaction(monkeypatch):
    text = "DPD Romania: taxa Non-UE se achita in contul RO92RZBR0000060002951611."

    with monkeypatch.context() as patched:
        patched.setattr(app_main.orchestrated_engine, "_persist_orchestrated_job", lambda candidate: candidate)
        patched.setattr(app_main.orchestrated_engine, "_emit_orchestrated_telemetry", lambda *args, **kwargs: None)
        job = app_main.asyncio.run(
            app_main.orchestrated_engine._create_orchestrated_job(
                app_main.OrchestratedScanRequest(
                    input_type="offer",
                    text=text,
                    source_channel="sms",
                )
            )
        )

    serialized = app_main.json.dumps(job, ensure_ascii=False)
    assert "RO92RZBR0000060002951611" not in serialized
    assert "[IBAN_REDACTED]" in job["redacted_text"]
    payment = job["cross_scan_knowledge"]["payment_destinations"][0]
    assert payment["matched"] is True
    assert payment["brand_matches"] is True
    assert payment["iban_masked_for_client"] == "RO92 RZBR **** **** **** 1611"


def test_offer_gate_uses_official_payment_context_to_avoid_redaction_induced_spoof():
    fields = parse_offer(
        "DPD Romania: taxa Non-UE se achita in contul [IBAN_REDACTED].",
        input_type="offer",
    )
    entity = OfferEntityResult(
        claimed_brand="dpd_romania",
        brand_impersonation=True,
        warnings=["Posibilă impersonare a brandului dpd_romania"],
    )
    cross = evaluate_cross_scan_knowledge(
        text="DPD Romania: taxa Non-UE se achita in contul RO92RZBR0000060002951611.",
        claimed_brand="dpd_romania",
        source_channel="sms",
    )

    out = evaluate_offer_verdict(
        fields,
        signals=[],
        entity=entity,
        coherence=None,
        family_code="OP-00",
        readiness=None,
        redacted_text=fields.raw_text,
        cross_scan_knowledge=cross,
    )

    assert out["bundle"]["identity"]["status"] != "lookalike"
    assert out["gate"]["label"] != "DANGEROUS"


def test_provider_gate_uses_cross_scan_official_payment_destination_for_text_scan():
    text = (
        "OSIM: plata taxa marca se poate face catre contul oficial "
        "RO38RNCB0080005630320005 mentionat pe site-ul osim.ro."
    )
    analysis = {
        "risk_level": "high",
        "risk_score": 90,
        "detected_family_id": "domain_or_trademark_scare_payment",
        "claimed_brand": "OSIM",
        "evidence": {
            "source_channel": "sms",
            "external_intel_summary": {
                "google_web_risk": {"status": "clean", "consulted": True},
                "urlscan": {"status": "clean", "consulted": True},
                "urlhaus": {"status": "clean", "consulted": True},
                "phishing_database": {"status": "clean", "consulted": True},
                "infra_dns": {"status": "clean", "consulted": True},
                "infra_domain_age": {"status": "clean", "consulted": True},
            },
            "semantic_review": {
                "status": "done",
                "risk_class": "high",
                "confidence": 0.9,
                "claim_matches_known_scam_family": True,
                "matched_family": "domain_or_trademark_scare_payment",
                "reason_codes": ["semantic:domain_or_trademark_scare_payment"],
                "completeness": True,
            },
        },
    }
    resolved = [
        {
            "url": "https://osim.ro/",
            "final_url": "https://osim.ro/",
            "final_hostname": "osim.ro",
            "final_registered_domain": "osim.ro",
        }
    ]

    result = app_main._apply_provider_gate_verdict(analysis, resolved, raw_text=text)
    bundle = result["evidence"]["decision_bundle"]

    assert bundle["providers"]["payment_destination"]["matched"] is True
    assert bundle["providers"]["payment_destination"]["trust_tier"] == "T1_PUBLIC_OFFICIAL"
    assert result["evidence"]["provider_gate"]["label"] == "SAFE"
    assert result["evidence"]["provider_gate"]["reason"] == "positive_provenance_clean"


def test_provider_gate_preserves_pre_redaction_payment_destination():
    raw_text = (
        "OSIM: plata taxa marca se poate face catre contul oficial "
        "RO38RNCB0080005630320005 mentionat pe site-ul osim.ro."
    )
    cross = evaluate_cross_scan_knowledge(
        text=raw_text,
        claimed_brand="OSIM",
        source_channel="sms",
    )
    redacted_text = "OSIM: plata taxa marca se poate face catre contul oficial [IBAN] mentionat pe site-ul osim.ro."
    analysis = {
        "risk_level": "high",
        "risk_score": 90,
        "detected_family_id": "domain_or_trademark_scare_payment",
        "claimed_brand": "OSIM",
        "evidence": {
            "source_channel": "sms",
            "cross_scan_knowledge": cross,
            "external_intel_summary": {
                "google_web_risk": {"status": "clean", "consulted": True},
                "urlscan": {"status": "clean", "consulted": True},
                "urlhaus": {"status": "clean", "consulted": True},
                "phishing_database": {"status": "clean", "consulted": True},
                "infra_dns": {"status": "clean", "consulted": True},
                "infra_domain_age": {"status": "clean", "consulted": True},
            },
            "semantic_review": {
                "status": "done",
                "risk_class": "high",
                "confidence": 0.9,
                "claim_matches_known_scam_family": True,
                "matched_family": "domain_or_trademark_scare_payment",
                "reason_codes": ["semantic:domain_or_trademark_scare_payment"],
                "completeness": True,
            },
        },
    }
    resolved = [
        {
            "url": "https://osim.ro/",
            "final_url": "https://osim.ro/",
            "final_hostname": "osim.ro",
            "final_registered_domain": "osim.ro",
        }
    ]

    result = app_main._apply_provider_gate_verdict(analysis, resolved, raw_text=redacted_text)
    bundle = result["evidence"]["decision_bundle"]

    assert bundle["providers"]["payment_destination"]["matched"] is True
    assert bundle["providers"]["payment_destination"]["trust_tier"] == "T1_PUBLIC_OFFICIAL"
    assert result["evidence"]["provider_gate"]["label"] == "SAFE"


def test_cui_match_suppresses_false_brand_mismatch():
    """A matched official IBAN whose CUI confirms the SAME legal entity must NOT
    raise PAYMENT_DESTINATION_BRAND_MISMATCH just because the brand-name string
    did not match (e.g. 'Dante International SA' vs 'eMAG'). cui_matches=True is
    affirmative proof it is the same entity."""
    text = "Factura. IBAN: RO49AAAA1B31007593840000"
    same_entity = {
        "matched": True, "brand_matches": False, "cui_matches": True,
        "registry_has_brand_destinations": True,
    }
    diff_entity = {
        "matched": True, "brand_matches": False, "cui_matches": False,
        "registry_has_brand_destinations": True,
    }
    with patch("services.cross_scan_knowledge.match_payment_destination", return_value=same_entity):
        res = evaluate_cross_scan_knowledge(text=text, claimed_brand="dante", cui="14399840")
        assert "PAYMENT_DESTINATION_BRAND_MISMATCH" not in res["fraud_flags"]
    with patch("services.cross_scan_knowledge.match_payment_destination", return_value=diff_entity):
        res = evaluate_cross_scan_knowledge(text=text, claimed_brand="dante", cui="999")
        assert "PAYMENT_DESTINATION_BRAND_MISMATCH" in res["fraud_flags"]


def test_cui_match_real_registry_contributes_to_safe():
    """REAL registry path (no mock): the official eMAG/Dante IBAN with the matching
    CUI must be can_contribute_to_safe=True even though the textual brand differs."""
    from services.payment_destination_registry import match_payment_destination
    m = match_payment_destination(
        "RO38BRDE450SV88376004500", claimed_brand="dante international sa", cui="14399840"
    )
    assert m["matched"] is True
    assert m["cui_matches"] is True
    assert m["brand_matches"] is False  # textual brand differs (eMAG vs Dante)
    assert m["can_contribute_to_safe"] is True  # CUI match stands in for brand match


def test_invoice_truth_state_cui_match_not_mismatch():
    """InvoiceTruth reducer: cui_matches=True overrides a textual brand mismatch."""
    from services.invoice_truth_v4 import _payment_destination_state
    same = {"matched": True, "brand_matches": False, "cui_matches": True, "can_contribute_to_safe": True}
    diff = {"matched": True, "brand_matches": False, "cui_matches": False, "can_contribute_to_safe": False}
    neither = {"matched": True, "brand_matches": False, "cui_matches": None, "can_contribute_to_safe": False}
    assert _payment_destination_state(same, {}) == "OFFICIAL_REGISTRY_MATCH"
    assert _payment_destination_state(diff, {}) == "MISMATCH"
    # brand mismatch with no CUI confirmation is still a mismatch (recall-safe)
    assert _payment_destination_state(neither, {}) == "MISMATCH"


def test_invoice_payment_display_cui_match_not_other_entity():
    """Client UI: cui_matches=True must not render 'IBAN asociat altei entități'."""
    from types import SimpleNamespace
    same = SimpleNamespace(payment_destination={
        "matched": True, "brand_matches": False, "cui_matches": True,
        "can_contribute_to_safe": True, "trust_tier": "T1_PUBLIC_OFFICIAL",
    })
    diff = SimpleNamespace(payment_destination={
        "matched": True, "brand_matches": False, "cui_matches": False,
        "can_contribute_to_safe": False, "trust_tier": "T1_PUBLIC_OFFICIAL",
    })
    out_same = app_main._invoice_payment_destination_for_client(same)
    out_diff = app_main._invoice_payment_destination_for_client(diff)
    assert out_same["display"] != "IBAN asociat altei entități"
    assert out_diff["display"] == "IBAN asociat altei entități"
