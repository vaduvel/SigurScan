import asyncio

import pytest

from api_models import OrchestratedScanRequest
from services.action_asset import ACTION_ASSET_SCHEMA, build_action_asset_contract
from services.protected_action_shadow import (
    PROTECTED_ACTION_SHADOW_SCHEMA,
    evaluate_protected_action_shadow,
)
from services.orchestrated_scan import orchestrated_engine


@pytest.mark.parametrize(
    ("text", "expected_actions", "expected_assets", "expected_composition"),
    [
        (
            "Spune-mi codul OTP primit prin SMS chiar acum.",
            {"share_code"},
            {"otp"},
            "credential_exfiltration",
        ),
        (
            "Instalează AnyDesk și acordă-ne acces la distanță la telefon.",
            {"install_app", "grant_remote_access"},
            {"device_access"},
            "remote_access_install",
        ),
        (
            "Transferă soldul în noul cont de siguranță și ignoră IBAN-ul vechi.",
            {"transfer_money", "change_payment_destination"},
            {"money", "iban"},
            "transfer_to_changed_destination",
        ),
        (
            "Plătește taxa de eliberare ca să primești coletul.",
            {"pay_to_receive"},
            {"money"},
            "advance_fee",
        ),
        (
            "Nu închide apelul; deschide aplicația bancară cât timp rămânem pe linie.",
            {"stay_on_call", "open_banking_app"},
            {"bank_account"},
            "guided_banking",
        ),
    ],
)
def test_action_asset_compositions_are_extracted_without_story_specific_rules(
    text,
    expected_actions,
    expected_assets,
    expected_composition,
):
    contract = build_action_asset_contract(text, source_channel="phone")

    assert contract["schema"] == ACTION_ASSET_SCHEMA
    assert contract["shadow_only"] is True
    assert contract["positive_request"] is True
    assert expected_actions.issubset(set(contract["requested_actions"]))
    assert expected_assets.issubset(set(contract["requested_assets"]))
    assert expected_composition in contract["composition_rules"]
    assert contract["raw_text_persisted"] is False


@pytest.mark.parametrize(
    "text",
    [
        "Nu comunica niciodată codul OTP primit prin SMS.",
        "Sună la numărul de pe spatele cardului și nu comunica nimănui codul OTP.",
        "Acest ghid explică faptul că escrocii cer coduri OTP și transferuri.",
        "Factura menționează că plata se face în IBAN-ul furnizorului.",
    ],
)
def test_protective_or_descriptive_mentions_do_not_become_positive_requests(text):
    contract = build_action_asset_contract(text, source_channel="manual")
    shadow = evaluate_protected_action_shadow(contract)

    assert contract["positive_request"] is False
    assert contract["requested_actions"] == []
    assert contract["requested_assets"] == []
    assert shadow["candidate_min_label"] is None


def test_protective_sentence_cannot_hide_a_later_positive_request():
    contract = build_action_asset_contract(
        "Nu comunica vechiul cod. Spune-mi codul OTP nou primit prin SMS.",
        source_channel="phone",
    )
    shadow = evaluate_protected_action_shadow(contract)

    assert contract["protective_warning"] is True
    assert contract["positive_request"] is True
    assert contract["requested_actions"] == ["share_code"]
    assert shadow["candidate_min_label"] == "DANGEROUS"
    assert "protected_authentication_secret_wrong_channel" in shadow["reason_codes"]


def test_educational_message_intro_cannot_bind_to_negated_transfer_after_colon():
    contract = build_action_asset_contract(
        (
            "ING Business trimite un mesaj educational: nu te loga prin linkuri primite, "
            "nu transfera bani in cont seif, suna banca pe numarul oficial."
        ),
        source_channel="sms",
    )
    shadow = evaluate_protected_action_shadow(contract, identity_status="official")

    assert contract["protective_warning"] is True
    assert contract["positive_request"] is False
    assert contract["requested_actions"] == []
    assert shadow["candidate_min_label"] is None


@pytest.mark.parametrize(
    "text",
    [
        "Mama, mi s-a stricat telefonul. Trimite urgent 1.800 lei in contul acesta.",
        "Trimite acum 1.800 lei pentru garantia de externare; iti explic dupa.",
        "Trimite avansul de 12.000 EUR catre noul nostru partener.",
    ],
)
def test_ambiguous_send_verb_keeps_nearby_payment_requests(text):
    contract = build_action_asset_contract(text, source_channel="whatsapp")

    assert "transfer_money" in contract["requested_actions"]
    assert "transfer_money" in contract["protected_actions"]


def test_official_store_install_is_not_promoted_to_dangerous_without_remote_access():
    contract = build_action_asset_contract(
        "Instalează aplicația oficială din Google Play pentru a vedea factura.",
        source_channel="web",
    )
    shadow = evaluate_protected_action_shadow(contract)

    assert contract["requested_actions"] == ["install_app"]
    assert "grant_remote_access" not in contract["requested_actions"]
    assert shadow["candidate_min_label"] == "SUSPECT"


def test_entering_code_on_official_page_is_not_treated_as_sharing_it_with_sender():
    contract = build_action_asset_contract(
        "Pentru activare introdu codul primit pe pagina oficială. Nu trimite codul nimănui.",
        source_channel="sms",
    )
    shadow = evaluate_protected_action_shadow(
        contract,
        identity_status="official",
        actual_label="SAFE",
    )

    assert contract["requested_actions"] == ["enter_code"]
    assert "share_code" not in contract["requested_actions"]
    assert shadow["candidate_min_label"] == "SUSPECT"
    assert "protected_authentication_secret_wrong_channel" not in shadow["reason_codes"]


def test_explicit_web_destination_wins_over_ambiguous_account_wording():
    contract = build_action_asset_contract(
        (
            "Factura este disponibila in cont. Plateste din contul tau pe "
            "https://www.digi.ro/asistenta/modalitati-de-plata"
        ),
        source_channel="email",
    )

    assert contract["destination"]["type"] == "link"


@pytest.mark.parametrize(
    "text",
    [
        "Plateste taxele locale din cont pe https://www.ghiseul.ro/.",
        "Pentru activare introdu codul primit pe https://www.digi.ro/. Nu trimite codul nimanui.",
    ],
)
def test_confirmed_official_web_destination_satisfies_proof_before_safe(text):
    contract = build_action_asset_contract(text, source_channel="sms")
    shadow = evaluate_protected_action_shadow(
        contract,
        decision_bundle={
            "identity": {"status": "official"},
            "provenance": {"official_domain_match": True},
            "resolution": {"status": "resolved", "final_url": "https://www.digi.ro/"},
            "providers": {"verdict": "clean", "completeness": True},
        },
        actual_label="SAFE",
    )

    assert shadow["proof_before_safe"]["status"] == "satisfied"
    assert shadow["candidate_min_label"] is None


def test_unknown_web_destination_still_requires_proof_for_protected_action():
    contract = build_action_asset_contract(
        "Pentru activare introdu codul primit pe https://digi-confirmare.example/.",
        source_channel="sms",
    )
    shadow = evaluate_protected_action_shadow(
        contract,
        decision_bundle={
            "identity": {"status": "unknown"},
            "provenance": {"official_domain_match": False},
            "resolution": {"status": "resolved", "final_url": "https://digi-confirmare.example/"},
            "providers": {"verdict": "clean", "completeness": True},
        },
        actual_label="SAFE",
    )

    assert shadow["proof_before_safe"]["status"] == "blocked"
    assert shadow["candidate_min_label"] == "SUSPECT"


def test_plain_conversation_is_not_mislabeled_as_descriptive_artifact():
    contract = build_action_asset_contract("Bună ziua, ce mai faci?", source_channel="text")

    assert contract["positive_request"] is False
    assert contract["descriptive_context"] is False


@pytest.mark.parametrize(
    ("text", "protected_action"),
    [
        ("Transferă suma în contul indicat.", "transfer_money"),
        ("Spune-mi codul OTP primit prin SMS.", "share_authentication_secret"),
        ("Trimite-mi datele cardului și CVV-ul.", "share_card_data"),
        ("Instalează aplicația indicată.", "install_app"),
        ("Acordă-ne acces remote la telefon.", "grant_remote_access"),
        ("Partajează ecranul telefonului.", "screen_share"),
        ("Trimite-mi o poză cu buletinul.", "share_identity"),
        ("Aprobă tranzacția în aplicație.", "approve_transaction"),
        ("Folosește noul IBAN pentru plată.", "change_payment_destination"),
        ("Achită taxa înainte să primești premiul.", "pay_to_receive"),
        ("Cumpără un voucher și trimite codul.", "transfer_alternative_value"),
        ("Scanează codul QR pentru plată.", "scan_payment_qr"),
    ],
)
def test_all_protected_action_categories_get_at_least_a_suspect_shadow_floor(
    text,
    protected_action,
):
    contract = build_action_asset_contract(text, source_channel="whatsapp")
    shadow = evaluate_protected_action_shadow(
        contract,
        identity_status="unknown",
        actual_label="SAFE",
    )

    assert protected_action in contract["protected_actions"]
    assert shadow["candidate_min_label"] in {"SUSPECT", "DANGEROUS"}
    assert shadow["would_raise_actual"] is True
    assert shadow["applied_to_verdict"] is False


def test_shadow_never_downgrades_an_existing_dangerous_verdict():
    contract = build_action_asset_contract(
        "Instalează aplicația oficială din magazinul telefonului.",
        source_channel="web",
    )
    shadow = evaluate_protected_action_shadow(
        contract,
        identity_status="unknown",
        actual_label="DANGEROUS",
    )

    assert shadow["candidate_min_label"] == "SUSPECT"
    assert shadow["actual_label"] == "DANGEROUS"
    assert shadow["would_raise_actual"] is False
    assert shadow["applied_to_verdict"] is False


@pytest.mark.parametrize(
    "text",
    [
        "Nu transfera bani în conturi comunicate la telefon.",
        "Nu comunica nimănui codul OTP primit prin SMS.",
        "Nu trimite datele cardului sau codul CVV.",
        "Nu instala aplicații primite prin mesaje.",
        "Nu acorda acces remote la telefon.",
        "Nu partaja ecranul cu persoane necunoscute.",
        "Nu trimite o fotografie cu buletinul.",
        "Nu aproba tranzacții pe care nu le recunoști.",
        "Nu folosi un IBAN nou comunicat prin mesaj.",
        "Nu achita taxe ca să primești un premiu.",
        "Nu cumpăra carduri cadou la cererea unui apelant.",
        "Nu transfera crypto într-un portofel necunoscut.",
        "Nu scana coduri QR pentru plată din surse necunoscute.",
    ],
)
def test_negated_protected_actions_do_not_create_a_shadow_floor(text):
    contract = build_action_asset_contract(text, source_channel="phone")
    shadow = evaluate_protected_action_shadow(contract, identity_status="unknown")

    assert contract["positive_request"] is False
    assert contract["protected_actions"] == []
    assert contract["protective_warning"] is True
    assert shadow["candidate_min_label"] is None


@pytest.mark.parametrize(
    ("actual_label", "would_raise"),
    [
        ("SAFE", True),
        ("UNVERIFIED", True),
        ("SUSPECT", True),
        ("DANGEROUS", False),
    ],
)
def test_protected_action_shadow_is_monotonic_for_every_existing_label(
    actual_label,
    would_raise,
):
    contract = build_action_asset_contract(
        "Spune-mi codul OTP primit prin SMS.",
        source_channel="phone",
    )
    shadow = evaluate_protected_action_shadow(
        contract,
        identity_status="unknown",
        actual_label=actual_label,
    )

    assert shadow["candidate_min_label"] == "DANGEROUS"
    assert shadow["actual_label"] == actual_label
    assert shadow["would_raise_actual"] is would_raise
    assert shadow["applied_to_verdict"] is False


def test_pre_redaction_presence_is_observed_but_does_not_invent_a_request():
    contract = build_action_asset_contract(
        "Documentul conține date redactate.",
        source_channel="share_image",
        pre_redaction_summary={
            "present": True,
            "iban_count": 1,
            "sensitive_asset_types": ["otp", "card", "cnp"],
        },
    )

    assert set(contract["observed_assets"]) == {"card_data", "cnp", "iban", "otp"}
    assert contract["requested_assets"] == []
    assert contract["positive_request"] is False


def test_same_transcript_has_same_action_asset_contract_across_text_and_audio():
    text = "Transferă banii în noul cont de siguranță și nu închide apelul."
    text_contract = build_action_asset_contract(text, source_channel="share_text")
    audio_contract = build_action_asset_contract(text, source_channel="audio_listener")

    for key in (
        "requested_actions",
        "requested_assets",
        "destination",
        "claimed_actor",
        "positive_request",
        "protective_warning",
        "composition_rules",
        "protected_actions",
    ):
        assert text_contract[key] == audio_contract[key]
    assert text_contract["channel"] == "text"
    assert audio_contract["channel"] == "audio"


def test_proof_before_safe_distinguishes_confirmed_unknown_and_mismatched_payment():
    contract = build_action_asset_contract(
        "Plătește factura prin transfer în contul furnizorului.",
        source_channel="invoice",
    )

    confirmed = evaluate_protected_action_shadow(
        contract,
        identity_status="official",
        payment_destination={"matched": True, "can_contribute_to_safe": True},
        actual_label="SAFE",
    )
    unknown = evaluate_protected_action_shadow(
        contract,
        identity_status="unknown",
        payment_destination={"matched": False},
        actual_label="SAFE",
    )
    mismatched = evaluate_protected_action_shadow(
        contract,
        identity_status="lookalike",
        payment_destination={"matched": False, "brand_matches": False},
        actual_label="SAFE",
    )

    assert confirmed["proof_before_safe"]["status"] == "satisfied"
    assert confirmed["candidate_min_label"] is None
    assert unknown["proof_before_safe"]["status"] == "blocked"
    assert unknown["candidate_min_label"] == "SUSPECT"
    assert unknown["would_raise_actual"] is True
    assert mismatched["candidate_min_label"] == "DANGEROUS"


def test_shadow_is_internal_and_does_not_change_public_scan_status(monkeypatch):
    with monkeypatch.context() as patched:
        patched.setattr(orchestrated_engine, "_persist_orchestrated_job", lambda candidate: candidate)
        patched.setattr(orchestrated_engine, "_emit_orchestrated_telemetry", lambda *args, **kwargs: None)
        job = asyncio.run(
            orchestrated_engine._create_orchestrated_job(
                OrchestratedScanRequest(
                    input_type="text",
                    text="Spune-mi codul OTP primit prin SMS.",
                    source_channel="share_text",
                )
            )
        )

    public_status = orchestrated_engine._orchestrated_status_payload(job)
    assert job["action_asset_shadow"]["schema"] == PROTECTED_ACTION_SHADOW_SCHEMA
    assert job["action_asset_shadow"]["contract"]["requested_actions"] == ["share_code"]
    assert "action_asset_shadow" not in public_status
