import json

from services.payment_case import (
    build_case_artifact,
    build_payment_case_facts,
    build_payment_case_facts_from_scan,
    enrich_payment_case_facts_with_final_gate,
    reduce_payment_case,
)


VALID_IBAN = "RO49AAAA1B31007593840000"
OTHER_VALID_IBAN = "DE89370400440532013000"


def _pre_redaction(iban: str, *, cui: str = "12345678", beneficiary: str = "ALFA DISTRIBUTIE SRL"):
    return {
        "schema": "sigurscan_pre_redaction_evidence_v1",
        "transport": "server_extracted",
        "identifiers": {
            "ibans": [{"value": iban}],
            "cuis": [cui],
        },
        "payment": {"beneficiary": beneficiary},
        "sensitive_assets": {},
    }


def _artifact(
    ref: str,
    artifact_type: str,
    verdict: str,
    *,
    final: bool = True,
    facts: dict | None = None,
    reason_codes: list[str] | None = None,
):
    return build_case_artifact(
        artifact_ref=ref,
        artifact_type=artifact_type,
        verdict=verdict,
        is_final=final,
        reason_codes=reason_codes or [],
        facts=facts or {},
    )


def test_single_confirmed_invoice_keeps_its_safe_verdict(monkeypatch):
    monkeypatch.setenv("INVOICE_CACHE_HMAC_KEY", "payment-case-test-key")
    facts = build_payment_case_facts(
        artifact_type="invoice",
        pre_redaction_evidence=_pre_redaction(VALID_IBAN),
        entity_name="ALFA DISTRIBUTIE SRL",
        amount="520.65",
        currency="RON",
        requested_actions=["transfer_money"],
        evidence_provenance="server_extracted",
    )

    result = reduce_payment_case([_artifact("invoice-1", "invoice", "SAFE", facts=facts)])

    assert result["verdict"] == "SAFE"
    assert result["contradictions"] == []
    assert result["artifact_count"] == 1


def test_unfinished_supporting_artifact_blocks_safe(monkeypatch):
    monkeypatch.setenv("INVOICE_CACHE_HMAC_KEY", "payment-case-test-key")
    invoice = build_payment_case_facts(
        artifact_type="invoice",
        pre_redaction_evidence=_pre_redaction(VALID_IBAN),
        entity_name="ALFA SRL",
        requested_actions=["transfer_money"],
        evidence_provenance="server_extracted",
    )

    result = reduce_payment_case(
        [
            _artifact("invoice-1", "invoice", "SAFE", facts=invoice),
            _artifact("email-1", "email", "UNVERIFIED", final=False),
        ]
    )

    assert result["verdict"] == "UNVERIFIED"
    assert "payment_case_incomplete" in result["reason_codes"]


def test_malicious_artifact_is_monotonic_over_safe_invoice(monkeypatch):
    monkeypatch.setenv("INVOICE_CACHE_HMAC_KEY", "payment-case-test-key")
    invoice = build_payment_case_facts(
        artifact_type="invoice",
        pre_redaction_evidence=_pre_redaction(VALID_IBAN),
        entity_name="ALFA SRL",
        evidence_provenance="server_extracted",
    )

    result = reduce_payment_case(
        [
            _artifact("invoice-1", "invoice", "SAFE", facts=invoice),
            _artifact(
                "email-1",
                "email",
                "DANGEROUS",
                facts={"signals": ["provider_malicious"]},
                reason_codes=["provider_malicious"],
            ),
        ]
    )

    assert result["verdict"] == "DANGEROUS"
    assert "provider_malicious" in result["reason_codes"]


def test_active_payment_instruction_to_different_iban_is_dangerous(monkeypatch):
    monkeypatch.setenv("INVOICE_CACHE_HMAC_KEY", "payment-case-test-key")
    invoice = build_payment_case_facts(
        artifact_type="invoice",
        pre_redaction_evidence=_pre_redaction(VALID_IBAN),
        entity_name="ALFA DISTRIBUTIE SRL",
        amount="1000.00",
        currency="RON",
        requested_actions=["transfer_money"],
        evidence_provenance="server_extracted",
    )
    email = build_payment_case_facts(
        artifact_type="email",
        pre_redaction_evidence=_pre_redaction(OTHER_VALID_IBAN),
        entity_name="ALFA DISTRIBUTIE",
        amount="1000",
        currency="RON",
        requested_actions=["transfer_money"],
        signals=["account_change_language"],
        evidence_provenance="server_extracted",
    )

    result = reduce_payment_case(
        [
            _artifact("invoice-1", "invoice", "SAFE", facts=invoice),
            _artifact("email-1", "email", "SUSPECT", facts=email),
        ]
    )

    assert result["verdict"] == "DANGEROUS"
    assert "cross_artifact_payment_destination_changed" in result["reason_codes"]
    assert any(item["code"] == "PAYMENT_DESTINATION_CONTRADICTION" for item in result["contradictions"])


def test_iban_mentioned_without_payment_instruction_is_not_dangerous(monkeypatch):
    monkeypatch.setenv("INVOICE_CACHE_HMAC_KEY", "payment-case-test-key")
    invoice = build_payment_case_facts(
        artifact_type="invoice",
        pre_redaction_evidence=_pre_redaction(VALID_IBAN),
        requested_actions=["transfer_money"],
        evidence_provenance="server_extracted",
    )
    note = build_payment_case_facts(
        artifact_type="message",
        pre_redaction_evidence=_pre_redaction(OTHER_VALID_IBAN),
        requested_actions=[],
        evidence_provenance="server_extracted",
    )

    result = reduce_payment_case(
        [
            _artifact("invoice-1", "invoice", "SAFE", facts=invoice),
            _artifact("message-1", "message", "UNVERIFIED", facts=note),
        ]
    )

    assert result["verdict"] != "DANGEROUS"
    assert "cross_artifact_payment_destination_changed" not in result["reason_codes"]


def test_amount_mismatch_needs_verification_but_is_not_proof_of_fraud(monkeypatch):
    monkeypatch.setenv("INVOICE_CACHE_HMAC_KEY", "payment-case-test-key")
    invoice = build_payment_case_facts(
        artifact_type="invoice",
        amount="1250.00",
        currency="RON",
        evidence_provenance="server_extracted",
    )
    offer = build_payment_case_facts(
        artifact_type="offer",
        amount="1000.00",
        currency="RON",
        evidence_provenance="server_extracted",
    )

    result = reduce_payment_case(
        [
            _artifact("invoice-1", "invoice", "SAFE", facts=invoice),
            _artifact("offer-1", "offer", "SAFE", facts=offer),
        ]
    )

    assert result["verdict"] == "SUSPECT"
    assert "cross_artifact_amount_mismatch" in result["reason_codes"]
    assert result["contradictions"][0]["severity"] == "verify"


def test_currency_mismatch_needs_verification_even_when_amount_matches(monkeypatch):
    monkeypatch.setenv("INVOICE_CACHE_HMAC_KEY", "payment-case-test-key")
    invoice = build_payment_case_facts(
        artifact_type="invoice",
        amount="100.00",
        currency="RON",
        evidence_provenance="server_extracted",
    )
    offer = build_payment_case_facts(
        artifact_type="offer",
        amount="100.00",
        currency="EUR",
        evidence_provenance="server_extracted",
    )

    result = reduce_payment_case(
        [
            _artifact("invoice-1", "invoice", "SAFE", facts=invoice),
            _artifact("offer-1", "offer", "SAFE", facts=offer),
        ]
    )

    assert result["verdict"] == "SUSPECT"
    assert "cross_artifact_amount_mismatch" in result["reason_codes"]
    assert result["contradictions"][0]["code"] == "AMOUNT_CONTRADICTION"


def test_legal_form_suffix_does_not_create_entity_contradiction(monkeypatch):
    monkeypatch.setenv("INVOICE_CACHE_HMAC_KEY", "payment-case-test-key")
    invoice = build_payment_case_facts(
        artifact_type="invoice",
        entity_name="Electrica Furnizare S.A.",
        evidence_provenance="server_extracted",
    )
    email = build_payment_case_facts(
        artifact_type="email",
        entity_name="Electrica Furnizare",
        evidence_provenance="server_extracted",
    )

    result = reduce_payment_case(
        [
            _artifact("invoice-1", "invoice", "SAFE", facts=invoice),
            _artifact("email-1", "email", "SAFE", facts=email),
        ]
    )

    assert result["verdict"] == "SAFE"
    assert not any(item["code"] == "ENTITY_CONTRADICTION" for item in result["contradictions"])


def test_persistable_case_facts_never_contain_raw_iban(monkeypatch):
    monkeypatch.setenv("INVOICE_CACHE_HMAC_KEY", "payment-case-test-key")
    facts = build_payment_case_facts(
        artifact_type="invoice",
        pre_redaction_evidence=_pre_redaction(VALID_IBAN),
        entity_name="ALFA DISTRIBUTIE SRL",
        evidence_provenance="server_extracted",
    )

    serialized = json.dumps(facts, ensure_ascii=False)

    assert VALID_IBAN not in serialized
    assert "ALFA DISTRIBUTIE" not in serialized
    assert facts["payment"]["destination_fingerprints"]
    assert facts["entity"]["name_fingerprint"].startswith("hmac-sha256:")
    assert facts["privacy"]["raw_payment_destination_persisted"] is False


def test_shadow_action_contract_cannot_activate_payment_case_verdict(monkeypatch):
    monkeypatch.setenv("INVOICE_CACHE_HMAC_KEY", "payment-case-test-key")
    facts = build_payment_case_facts_from_scan(
        artifact_type="email",
        analysis_input_type="offer",
        raw_text="Informare despre datele de plată ale furnizorului.",
        pre_redaction_evidence={"identifiers": {"ibans": [{"value": VALID_IBAN}]}},
        action_asset={
            "shadow_only": True,
            "contract": {
                "requested_actions": ["transfer_money", "change_payment_destination"],
                "protected_actions": ["change_payment_destination"],
                "corroboration_signals": ["changed_destination"],
            },
        },
        urls=[],
    )

    assert facts["payment"]["requested"] is False
    assert facts["signals"] == []


def test_only_final_gate_reasons_can_activate_payment_request_facts(monkeypatch):
    monkeypatch.setenv("INVOICE_CACHE_HMAC_KEY", "payment-case-test-key")
    facts = build_payment_case_facts(
        artifact_type="email",
        pre_redaction_evidence=_pre_redaction(VALID_IBAN),
        requested_actions=[],
    )

    validated = enrich_payment_case_facts_with_final_gate(
        facts,
        ["value_request_needs_verification", "CHANGED_IBAN_OR_CHANNEL"],
    )

    assert facts["payment"]["requested"] is False
    assert validated["payment"]["requested"] is True
    assert "changed_iban_or_channel" in validated["signals"]
