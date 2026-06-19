import pytest

from services.anaf_cui import CuiResult
from services.invoice_orchestrator import evaluate_invoice_verdict, scan_invoice


MGH_TEXT = """
Factura MGH 0013
Data emiterii: 06.04.2022
Termen plata: 07.04.2022
Furnizor:
MARKETING GROWTH HUB S.R.L.
CIF:
45758405
IBAN (RON):
RO42INGB0000999912242622
Total plata 200.00 RON
"""


APA_BRASOV_TEXT = """
Factura ABV 1001
Nr factura: ABV 1001
Data emiterii: 10.06.2026
Scadenta: 25.06.2026
Furnizor: COMPANIA APA BRASOV S.A.
CUI: RO1096128
IBAN: RO78BACX0000000642579002
Total plata 90.00 RON
"""


def _cui_result(*, name: str, active: bool = True, exists: bool = True) -> CuiResult:
    return CuiResult(
        exists=exists,
        checked=True,
        denumire=name,
        activ=active,
        data_inactivare=None if active else "2024-01-01",
        platitor_tva=False,
        enrolled_efactura=False,
        raw=None,
        source="anaf",
    )


@pytest.mark.asyncio
async def test_invoice_truth_keeps_clean_unknown_iban_human_clear_not_red(monkeypatch):
    async def fake_check_cui(cui: str):
        assert cui == "45758405"
        return _cui_result(name="MARKETING GROWTH HUB S.R.L.")

    monkeypatch.setattr("services.invoice_orchestrator.check_cui", fake_check_cui)

    result = await scan_invoice(MGH_TEXT)
    evaluated = evaluate_invoice_verdict(result, result.raw_text, source_channel="android_native")
    truth = evaluated["invoice_truth"]

    assert truth["schema"] == "sigurscan_invoice_truth_v4"
    assert truth["verdict"] == "VERIFY_BEFORE_PAYING"
    assert truth["decision_status"] == "ACTION_REQUIRED"
    assert truth["safe_to_pay"] is False
    assert truth["display"]["title"] == "Verifică înainte să plătești"
    assert "nu pare fraudă" in truth["display"]["message"].lower()
    assert "api" not in truth["display"]["message"].lower()
    assert "anaf" not in truth["display"]["message"].lower()
    assert any(item["code"] == "ISSUER_CONFIRMED" for item in truth["verified_items"])
    assert any(item["code"] == "IBAN_STRUCTURE_VALID" for item in truth["verified_items"])
    assert any(item["code"] == "PAYMENT_BENEFICIARY_UNCONFIRMED" for item in truth["unconfirmed_items"])
    assert truth["next_action"]["type"] == "VERIFY_BENEFICIARY_IN_BANK"
    assert truth["hard_conflicts"] == []
    assert evaluated["gate"]["label"] == "UNVERIFIED"
    assert evaluated["gate"]["risk_level"] == "unknown"


@pytest.mark.asyncio
async def test_invoice_truth_can_mark_date_confirmate_when_obligation_and_destination_are_confirmed(monkeypatch):
    async def fake_check_cui(cui: str):
        assert cui == "1096128"
        return _cui_result(name="COMPANIA APA BRASOV S.A.")

    monkeypatch.setattr("services.invoice_orchestrator.check_cui", fake_check_cui)

    result = await scan_invoice(APA_BRASOV_TEXT)
    evaluated = evaluate_invoice_verdict(result, result.raw_text, source_channel="official_portal")
    truth = evaluated["invoice_truth"]

    assert truth["verdict"] == "DATE_CONFIRMATE"
    assert truth["decision_status"] == "OK"
    assert truth["safe_to_pay"] is True
    assert truth["display"]["title"] == "Date confirmate"
    assert any(item["code"] == "PAYMENT_DESTINATION_CONFIRMED" for item in truth["verified_items"])
    assert truth["unconfirmed_items"] == []
    assert truth["next_action"]["type"] == "REVIEW_AMOUNT_THEN_PAY"
    assert evaluated["gate"]["label"] == "SAFE"


@pytest.mark.asyncio
async def test_invoice_truth_inactive_company_is_verify_not_danger_without_hard_conflict(monkeypatch):
    async def fake_check_cui(cui: str):
        assert cui == "45758405"
        return _cui_result(name="MARKETING GROWTH HUB S.R.L.", active=False)

    monkeypatch.setattr("services.invoice_orchestrator.check_cui", fake_check_cui)

    result = await scan_invoice(MGH_TEXT)
    evaluated = evaluate_invoice_verdict(result, result.raw_text, source_channel="android_native")
    truth = evaluated["invoice_truth"]

    assert truth["verdict"] == "VERIFY_BEFORE_PAYING"
    assert truth["decision_status"] == "ACTION_REQUIRED"
    assert truth["safe_to_pay"] is False
    assert any(item["code"] == "ISSUER_INACTIVE" for item in truth["unconfirmed_items"])
    assert truth["hard_conflicts"] == []
    assert evaluated["gate"]["label"] != "DANGEROUS"


@pytest.mark.asyncio
async def test_invoice_truth_weak_inactive_fallback_does_not_beat_official_payment_destination(monkeypatch):
    text = """
Factura G 2001
Furnizor: GROUPAMA ASIGURARI SA
CUI: 6291812
IBAN: RO53 BTRL 0130 1601 0065 6313
Total plata: 200.00 RON
"""

    async def fake_check_cui(cui: str):
        assert cui == "6291812"
        return CuiResult(
            exists=True,
            checked=True,
            denumire="GROUPAMA ASIGURARI SA",
            activ=False,
            data_inactivare=None,
            platitor_tva=False,
            enrolled_efactura=False,
            raw={"status": {"details": {"description": "radiată"}}},
            source="lista_firme",
        )

    monkeypatch.setattr("services.invoice_orchestrator.check_cui", fake_check_cui)

    result = await scan_invoice(text)
    evaluated = evaluate_invoice_verdict(result, result.raw_text, source_channel="android_native")
    truth = evaluated["invoice_truth"]

    assert not any("inactive" in warning.lower() for warning in result.warnings)
    assert truth["proofs"]["payment_destination"]["state"] == "OFFICIAL_REGISTRY_MATCH"
    assert truth["proofs"]["issuer_identity"]["source"] == "lista_firme"
    assert truth["proofs"]["issuer_identity"]["state"] == "CONFIRMED"
    assert not any(item["code"] == "ISSUER_INACTIVE" for item in truth["unconfirmed_items"])
    assert evaluated["gate"]["label"] == "SAFE"


@pytest.mark.asyncio
async def test_invoice_truth_qr_printed_iban_conflict_is_nu_plati(monkeypatch):
    qr_payload = (
        "BCD\n"
        "002\n"
        "1\n"
        "SCT\n"
        "MARKETING GROWTH HUB SRL\n"
        "RO49AAAA1B31007593840000\n"
        "RON200.00\n\n"
        "Factura MGH 0013"
    )

    async def fake_check_cui(cui: str):
        assert cui == "45758405"
        return _cui_result(name="MARKETING GROWTH HUB S.R.L.")

    monkeypatch.setattr("services.invoice_orchestrator.check_cui", fake_check_cui)

    result = await scan_invoice(MGH_TEXT, links=[qr_payload])
    evaluated = evaluate_invoice_verdict(result, result.raw_text, source_channel="android_native")
    truth = evaluated["invoice_truth"]

    assert truth["verdict"] == "NU_PLATI"
    assert truth["decision_status"] == "DO_NOT_PAY"
    assert truth["safe_to_pay"] is False
    assert truth["display"]["title"] == "Nu plăti"
    assert any(conflict["code"] == "VISIBLE_VS_QR_PAYMENT_HIJACK" for conflict in truth["hard_conflicts"])
    assert evaluated["gate"]["label"] == "DANGEROUS"
