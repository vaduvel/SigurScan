from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from services.invoice_orchestrator import evaluate_invoice_verdict, scan_invoice


CORPUS_PATH = Path(__file__).resolve().parent / "data" / "eval" / "invoice_golden_corpus_v2026_06_15.json"


def _load_cases() -> list[dict]:
    with open(CORPUS_PATH, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    return data["cases"]


@pytest.fixture(autouse=True)
def _clean_invoice_golden_state(monkeypatch):
    monkeypatch.setenv("INVOICE_CACHE_HMAC_KEY", "testkey")
    from services import invoice_orchestrator as io

    io._verdict_cache.clear()
    io._cui_cache.clear()
    try:
        from services import vendor_memory as vm

        vm._memory.clear()
    except Exception:
        pass
    yield
    io._verdict_cache.clear()
    io._cui_cache.clear()


@pytest.mark.asyncio
@pytest.mark.parametrize("case", _load_cases(), ids=lambda case: case["case_id"])
async def test_invoice_golden_corpus_case(case):
    from services.anaf_cui import CuiResult
    from services import vendor_memory

    for item in case.get("vendor_memory_seed") or []:
        vendor_memory.remember_invoice_iban(item["cui"], item["iban"])

    async def fake_check_cui(cui: str):
        records = case.get("cui_records") or {}
        record = records.get(cui) or {
            "exists": True,
            "checked": True,
            "denumire": case.get("expected_fields", {}).get("emitent") or "DEMO COMPANY SRL",
            "activ": True,
            "platitor_tva": True,
            "enrolled_efactura": False,
        }
        return CuiResult(
            exists=bool(record.get("exists", True)),
            checked=bool(record.get("checked", True)),
            denumire=record.get("denumire"),
            activ=bool(record.get("activ", True)),
            data_inactivare=record.get("data_inactivare"),
            platitor_tva=bool(record.get("platitor_tva", True)),
            enrolled_efactura=bool(record.get("enrolled_efactura", False)),
            raw=None,
        )

    with patch("services.invoice_orchestrator.check_cui", new_callable=AsyncMock) as mock_cui:
        mock_cui.side_effect = fake_check_cui
        result = await scan_invoice(
            case["input"]["text"],
            links=case["input"].get("links") or [],
        )

    verdict = evaluate_invoice_verdict(
        result,
        result.raw_text,
        source_channel=case["input"].get("source_channel"),
    )
    expected_fields = case.get("expected_fields") or {}
    for field, expected in expected_fields.items():
        assert getattr(result.fields, field) == expected

    expected_flags = set(case.get("expected_flags") or [])
    assert expected_flags <= set(result.fraud_flags)

    forbidden_flags = set(case.get("forbidden_flags") or [])
    assert not (forbidden_flags & set(result.fraud_flags))

    expected_payment = case.get("expected_payment_destination")
    if expected_payment:
        payment = result.payment_destination or {}
        for field, expected in expected_payment.items():
            assert payment.get(field) == expected

    expected_labels = set(case.get("expected_gate_labels") or [])
    if expected_labels:
        assert verdict["gate"]["label"] in expected_labels

    forbidden_labels = set(case.get("forbidden_gate_labels") or [])
    assert verdict["gate"]["label"] not in forbidden_labels
