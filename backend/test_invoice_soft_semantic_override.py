"""InvoiceTruth owns invoice precision when generic semantic reasons are soft."""

import asyncio
import json
from pathlib import Path

from services.invoice_orchestrator import evaluate_invoice_verdict, scan_invoice
from services.invoice_truth_v4 import gate_from_invoice_truth


SAFE_CONTROLS = Path(__file__).resolve().parent / "data" / "b2b_invoice_safe_controls_ro.jsonl"


def _truth(verdict: str, primary: str = "UNCONFIRMED_DESTINATION"):
    return {"verdict": verdict, "primary_reason_code": primary}


def test_soft_semantic_high_risk_does_not_override_invoice_verify():
    base = {"label": "DANGEROUS", "risk_score": 90, "reason_codes": ["semantic_high_risk_match"]}

    out = gate_from_invoice_truth(_truth("VERIFY_BEFORE_PAYING"), base)

    assert out["label"] != "DANGEROUS"


def test_soft_semantic_high_value_does_not_override_invoice_verify():
    base = {"label": "DANGEROUS", "risk_score": 88, "reason_codes": ["semantic_high_value_request"]}

    out = gate_from_invoice_truth(_truth("VERIFY_BEFORE_PAYING"), base)

    assert out["label"] != "DANGEROUS"


def test_decisive_generic_dangerous_still_overrides_invoice_verify():
    for reason in ("provider_malicious", "sensitive_wrong_channel", "never_asks_violated:card_number"):
        base = {"label": "DANGEROUS", "risk_score": 95, "reason_codes": [reason]}

        out = gate_from_invoice_truth(_truth("VERIFY_BEFORE_PAYING"), base)

        assert out["label"] == "DANGEROUS"


def test_bec_reply_to_account_change_is_invoice_hard_conflict():
    text = (
        "From: facturi@furnizor-real.ro\n"
        "Reply-To: plata-furnizor@gmail.com\n"
        "Furnizor: TEST SRL\nCUI RO12345678\n"
        "Am schimbat contul bancar. Noul IBAN este RO33RNCB1234567890123456.\n"
        "Total 4800 RON"
    )

    result = asyncio.run(scan_invoice(text))
    verdict = evaluate_invoice_verdict(result, result.raw_text, source_channel="email")

    assert "BEC_REPLY_TO_ACCOUNT_CHANGE" in result.fraud_flags
    assert verdict["invoice_truth"]["verdict"] == "NU_PLATI"
    assert verdict["gate"]["label"] == "DANGEROUS"


def test_undisclosed_intermediary_is_invoice_hard_conflict():
    text = (
        "Factura nr. 8844\n"
        "Emitent: Service Expert SRL\n"
        "CUI: 12345678\n"
        "Total: 6200 RON\n"
        "IBAN: RO06MIDL0000000000000005\n"
        "Beneficiar plată: Procesator Rapid SRL\n"
        "Nu este necesar act adițional."
    )

    result = asyncio.run(scan_invoice(text))
    verdict = evaluate_invoice_verdict(result, result.raw_text, source_channel="email")

    assert "UNDISCLOSED_INTERMEDIARY_BENEFICIARY" in result.fraud_flags
    assert verdict["invoice_truth"]["verdict"] == "NU_PLATI"
    assert verdict["gate"]["label"] == "DANGEROUS"


def test_fragmented_iban_alone_is_not_invoice_hard_conflict():
    text = (
        "Furnizor: TEST SRL\n"
        "CUI: RO12345678\n"
        "IBAN: RO33 RNCB 1234\n"
        "5678 9012 3456\n"
        "Total 100 RON"
    )

    result = asyncio.run(scan_invoice(text))
    verdict = evaluate_invoice_verdict(result, result.raw_text, source_channel="android_native")

    assert "FRAGMENTED_IBAN_PAYMENT_TARGET" in result.fraud_flags
    assert verdict["invoice_truth"]["verdict"] != "NU_PLATI"
    assert verdict["gate"]["label"] != "DANGEROUS"


def test_b2b_safe_controls_zero_false_dangerous():
    cases = [json.loads(line) for line in SAFE_CONTROLS.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(cases) >= 50

    dangerous = []
    for case in cases:
        result = asyncio.run(scan_invoice(case["input_text"]))
        verdict = evaluate_invoice_verdict(result, result.raw_text, source_channel="android_native")
        if verdict["gate"]["label"] == "DANGEROUS":
            dangerous.append((case["id"], verdict["gate"].get("reason_codes"), result.fraud_flags))

    assert not dangerous, f"false-DANGEROUS on safe controls: {dangerous}"
