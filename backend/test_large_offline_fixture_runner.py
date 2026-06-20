from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from eval import large_offline_fixture_runner as runner


def test_structured_invoice_fixture_uses_invoice_route(monkeypatch) -> None:
    async def fake_scan_invoice(text: str, links=None):
        return SimpleNamespace(raw_text=text, links=links or [])

    def fake_evaluate_invoice_verdict(result, redacted_text: str, source_channel=None):
        return {
            "gate": {
                "label": "UNVERIFIED",
                "risk_level": "unknown",
                "risk_score": 35,
                "reason_codes": ["payment_requires_user_verification"],
                "is_final": True,
            },
            "invoice_truth": {
                "verdict": "VERIFICA_PLATA",
                "decision_status": "VERIFY_PAYMENT",
            },
        }

    def fail_generic_engine(*args, **kwargs):
        raise AssertionError("structured invoice fixture must not use generic engine")

    from services import invoice_orchestrator

    monkeypatch.setattr(invoice_orchestrator, "scan_invoice", fake_scan_invoice)
    monkeypatch.setattr(invoice_orchestrator, "evaluate_invoice_verdict", fake_evaluate_invoice_verdict)
    monkeypatch.setattr(runner.engine, "analyze", fail_generic_engine)
    monkeypatch.setattr(
        runner,
        "load_cases",
        lambda downloads_dir, zip_names: [
            {
                "source": "fixture.json",
                "id": "INV-ROUTE-01",
                "text": (
                    "Factura nr. F-100 emisa de TEST SRL CUI RO12345678 "
                    "IBAN RO00TEST000000000000001 suma 4800 RON"
                ),
                "expected": "UNVERIFIED",
                "meta": {},
            }
        ],
    )

    report = runner.run(Path("/tmp"), [])

    assert "error" not in report["rows"][0], report["rows"][0].get("error")
    assert report["rows"][0]["route"] == "invoice"
    assert report["rows"][0]["actual"] == "UNVERIFIED"
    assert report["passed"] == 1
