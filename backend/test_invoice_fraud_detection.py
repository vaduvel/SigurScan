"""Îmbunătățiri motor factură — semnale „firmă reală + IBAN fals/complice".

Testează MOTORUL EXISTENT extins (invoice_parser + invoice_orchestrator), nu un
judecător separat. Verdictul rămâne la verdict_gate; aici verificăm că parserul
extrage mai mult și că scan_invoice emite semnalele corecte (fără fals-pozitive).
"""
import asyncio

import pytest

from services.invoice_parser import parse_invoice
from services.invoice_orchestrator import (
    scan_invoice,
    _foreign_ibans,
    _beneficiary_is_person,
    _beneficiary_mismatch,
)


class TestParserExtindere:
    def test_extrage_toate_ibanurile(self):
        f = parse_invoice("Cont RO83BTRLRONCRT0299335701 si DE89370400440532013000\nTotal 100")
        assert "RO83BTRLRONCRT0299335701" in f.all_ibans
        assert "DE89370400440532013000" in f.all_ibans

    def test_iban_primar_ramane_ro_compat(self):
        f = parse_invoice("IBAN RO83BTRLRONCRT0299335701\nTotal 100")
        assert f.iban == "RO83BTRLRONCRT0299335701"

    def test_extrage_beneficiar(self):
        f = parse_invoice("Beneficiar: Popescu Ion Marian\nIBAN RO83BTRLRONCRT0299335701")
        assert f.payment_beneficiary == "Popescu Ion Marian"

    def test_fara_iban_invalid_in_all(self):
        f = parse_invoice("cont ROXX BAD si NOTANIBAN\nTotal 5")
        assert all(len(i) >= 15 for i in f.all_ibans)


class TestDetectori:
    def test_foreign_iban(self):
        assert _foreign_ibans(["DE89370400440532013000"]) == ["DE89370400440532013000"]
        assert _foreign_ibans(["RO83BTRLRONCRT0299335701"]) == []

    def test_beneficiar_persoana(self):
        assert _beneficiary_is_person("Popescu Ion") is True
        assert _beneficiary_is_person("SC REAL SRL") is False

    def test_beneficiar_mismatch(self):
        assert _beneficiary_mismatch("Popescu Ion", "SC REAL SRL") is True
        assert _beneficiary_mismatch("SC REAL SRL", "SC REAL SRL") is False
        # PFA: nume comun emitent↔beneficiar → fără mismatch
        assert _beneficiary_mismatch("Popescu Ion", "Popescu Ion PFA") is False
        assert _beneficiary_mismatch(None, "SC REAL SRL") is False


class TestScanInvoiceSemnale:
    def _scan(self, text):
        return asyncio.get_event_loop().run_until_complete(scan_invoice(text))

    @pytest.mark.asyncio
    async def test_caz_brasov_beneficiar_persoana(self):
        r = await scan_invoice(
            "Furnizor SC REAL SRL CUI RO12345678\nBeneficiar: Popescu Ion Marian\n"
            "IBAN RO49AAAA1B31007593840000\nTotal 8500 RON"
        )
        assert "BENEFICIARY_PERSON_MISMATCH" in r.fraud_flags
        assert any("persoană fizică" in w for w in r.warnings)

    @pytest.mark.asyncio
    async def test_iban_strain(self):
        r = await scan_invoice("Furnizor SC REAL SRL\nIBAN DE89370400440532013000\nTotal 5000")
        assert "FOREIGN_IBAN" in r.fraud_flags

    @pytest.mark.asyncio
    async def test_cont_schimbat_bec(self):
        r = await scan_invoice(
            "Furnizor SC REAL SRL\nAm schimbat contul bancar, noul IBAN RO49AAAA1B31007593840000\nTotal 100"
        )
        assert "ACCOUNT_CHANGE_LANGUAGE" in r.fraud_flags

    @pytest.mark.asyncio
    async def test_factura_curata_fara_semnale(self):
        r = await scan_invoice(
            "Factura fiscala SC REAL SRL CUI RO12345678\nIBAN RO49AAAA1B31007593840000\n"
            "Total 119 RON TVA 19% Scadenta 30.06.2026"
        )
        assert r.fraud_flags == []

    @pytest.mark.asyncio
    async def test_pfa_nu_da_fals_pozitiv(self):
        # PFA legitim: beneficiar = numele PFA-ului → NU trebuie flag
        r = await scan_invoice(
            "Emitent: Popescu Ion PFA\nBeneficiar: Popescu Ion\n"
            "IBAN RO49AAAA1B31007593840000\nTotal 200"
        )
        assert "BENEFICIARY_PERSON_MISMATCH" not in r.fraud_flags


class TestMapperFusion:
    """Pilon → invoice_evidence_gate_mapper → ACELAȘI verdict_gate (un singur
    judecător). Verdictul iese din gate, nu dintr-un creier paralel."""

    @pytest.mark.asyncio
    async def test_beneficiar_persoana_da_periculos(self):
        from services.invoice_evidence_gate_mapper import evaluate_invoice_verdict
        r = await scan_invoice(
            "Furnizor SC REAL SRL\nBeneficiar: Popescu Ion Marian\n"
            "IBAN RO49AAAA1B31007593840000\nTotal 8500 RON"
        )
        _, gate = evaluate_invoice_verdict(r, r.raw_text)
        assert gate["label"] == "DANGEROUS"

    @pytest.mark.asyncio
    async def test_bec_combo_da_periculos(self):
        from services.invoice_evidence_gate_mapper import evaluate_invoice_verdict
        r = await scan_invoice(
            "Furnizor SC REAL SRL\nAm schimbat contul bancar, noul cont:\n"
            "IBAN DE89370400440532013000\nPlătiți azi altfel se suspendă\nTotal 5000"
        )
        _, gate = evaluate_invoice_verdict(r, r.raw_text)
        assert gate["label"] == "DANGEROUS"

    @pytest.mark.asyncio
    async def test_iban_strain_singur_da_suspect(self):
        from services.invoice_evidence_gate_mapper import evaluate_invoice_verdict
        r = await scan_invoice("Furnizor SC REAL SRL\nIBAN DE89370400440532013000\nTotal 5000")
        _, gate = evaluate_invoice_verdict(r, r.raw_text)
        assert gate["label"] in {"SUSPECT", "DANGEROUS"}

    @pytest.mark.asyncio
    async def test_factura_curata_nu_e_periculos(self):
        from services.invoice_evidence_gate_mapper import evaluate_invoice_verdict
        r = await scan_invoice(
            "Furnizor SC REAL SRL\nIBAN RO49AAAA1B31007593840000\n"
            "Total 119 RON TVA 19% Scadenta 30.06.2026"
        )
        _, gate = evaluate_invoice_verdict(r, r.raw_text)
        assert gate["label"] != "DANGEROUS"

    def test_mapper_pur_fara_result(self):
        # Robust la result=None (scan_invoice a eșuat) — nu crapă, dă verdict.
        from services.invoice_evidence_gate_mapper import build_invoice_bundle
        bundle = build_invoice_bundle(None, "")
        assert bundle["schema"] == "sigurscan_evidence_bundle_v2"


class TestNegativeIbanRegistry:
    """Pilon registru negativ: IBAN raportat → PERICULOS determinist (victima #2).
    Prinde fix „firmă reală + IBAN complice", unde whitelist-ul nu ajută."""

    @pytest.fixture
    def registry_with(self, tmp_path, monkeypatch):
        import json
        from services import negative_iban_registry as nir
        from services import invoice_orchestrator as io

        def _make(ibans):
            f = tmp_path / "neg.json"
            f.write_text(json.dumps({"reported_ibans": ibans}))
            monkeypatch.setenv("NEGATIVE_IBAN_REGISTRY_PATH", str(f))
            nir.reload_registry()
            io._verdict_cache.clear()  # izolare: forțează re-scan
            return nir

        yield _make
        nir.reload_registry()

    def test_is_reported_normalizat(self, registry_with):
        nir = registry_with(["RO49AAAA1B31007593840000"])
        assert nir.is_reported_fraud("RO49 AAAA 1B31 0075 9384 0000")
        assert not nir.is_reported_fraud("RO83BTRLRONCRT0299335701")

    def test_registru_gol_fara_fals_pozitiv(self, registry_with):
        nir = registry_with([])
        assert not nir.is_reported_fraud("RO49AAAA1B31007593840000")

    @pytest.mark.asyncio
    async def test_scan_flag_iban_raportat(self, registry_with):
        registry_with(["RO49AAAA1B31007593840000"])
        r = await scan_invoice("Furnizor SC ALFA SRL\nIBAN RO49AAAA1B31007593840000\nTotal 100 lei factura")
        assert "REPORTED_FRAUD_IBAN" in r.fraud_flags

    @pytest.mark.asyncio
    async def test_iban_raportat_da_periculos(self, registry_with):
        from services.invoice_evidence_gate_mapper import evaluate_invoice_verdict
        registry_with(["RO49AAAA1B31007593840000"])
        r = await scan_invoice("Furnizor SC BETA SRL\nIBAN RO49AAAA1B31007593840000\nTotal 250 lei plata")
        _, gate = evaluate_invoice_verdict(r, r.raw_text)
        assert gate["label"] == "DANGEROUS"


class TestNegativeIbanRuntimeFeed:
    """Pilon A — alimentarea registrului la runtime (ingest moderator/DNSC/comunitate).
    report_fraud_iban() → is_reported_fraud True, fără seed în fișier."""

    @pytest.fixture(autouse=True)
    def _clean(self):
        from services import negative_iban_registry as nir
        from services import invoice_orchestrator as io
        nir.reload_registry(); io._verdict_cache.clear()
        yield
        nir.reload_registry()

    def test_report_then_detected(self):
        from services import negative_iban_registry as nir
        assert nir.is_reported_fraud("RO49AAAA1B31007593840000") is False
        assert nir.report_fraud_iban("RO49 AAAA 1B31 0075 9384 0000", source="dnsc_alert") is True
        assert nir.is_reported_fraud("RO49AAAA1B31007593840000") is True  # normalizat

    def test_invalid_iban_not_reported(self):
        from services import negative_iban_registry as nir
        assert nir.report_fraud_iban("NU-E-IBAN") is False

    def test_reload_clears_runtime(self):
        from services import negative_iban_registry as nir
        nir.report_fraud_iban("RO49AAAA1B31007593840000")
        nir.reload_registry()
        assert nir.is_reported_fraud("RO49AAAA1B31007593840000") is False

    @pytest.mark.asyncio
    async def test_runtime_reported_iban_flags_scan(self):
        from services import negative_iban_registry as nir
        nir.report_fraud_iban("RO49AAAA1B31007593840000", source="community_report")
        r = await scan_invoice("Furnizor SC GAMA SRL\nIBAN RO49AAAA1B31007593840000\nTotal 999 plata factura")
        assert "REPORTED_FRAUD_IBAN" in r.fraud_flags

    def test_endpoint_admin_gated(self):
        from fastapi.testclient import TestClient
        import main as app_main
        client = TestClient(app_main.app)
        # fără admin key → 401/403 (fail closed)
        r = client.post("/v1/internal/negative-iban", json={"iban": "RO49AAAA1B31007593840000"})
        assert r.status_code in (401, 403)


class TestVendorMemory:
    """Pilon B — vendor memory: IBAN schimbat față de istoricul firmei = semnal BEC."""

    IBAN_A = "RO49AAAA1B31007593840000"
    IBAN_B = "RO83BTRLRONCRT0299335701"

    @pytest.fixture(autouse=True)
    def _clean(self):
        from services import vendor_memory as vm
        from services import invoice_orchestrator as io
        vm._memory.clear(); io._verdict_cache.clear()
        yield
        vm._memory.clear()

    @pytest.fixture
    def _no_anaf(self):
        from unittest.mock import patch, AsyncMock
        from services.anaf_cui import CuiResult
        cui = CuiResult(exists=True, checked=True, denumire="SC X SRL", activ=True,
                        data_inactivare=None, platitor_tva=True, enrolled_efactura=False, raw=None)
        with patch("services.invoice_orchestrator.check_cui", new_callable=AsyncMock) as m:
            m.return_value = cui
            yield

    @pytest.mark.asyncio
    async def test_prima_factura_memoreaza_fara_flag(self, _no_anaf):
        from services import vendor_memory as vm
        r = await scan_invoice(f"Furnizor SC X SRL CUI RO12345678\nIBAN {self.IBAN_A}\nTotal 100 luna mai")
        assert "IBAN_CHANGED_VS_HISTORY" not in r.fraud_flags
        assert self.IBAN_A in vm.known_ibans_for_cui("RO12345678")

    @pytest.mark.asyncio
    async def test_iban_schimbat_da_flag_si_suspect(self, _no_anaf):
        from services.invoice_evidence_gate_mapper import evaluate_invoice_verdict
        await scan_invoice(f"Furnizor SC X SRL CUI RO12345678\nIBAN {self.IBAN_A}\nTotal 100 luna mai")
        r2 = await scan_invoice(f"Furnizor SC X SRL CUI RO12345678\nIBAN {self.IBAN_B}\nTotal 200 luna iunie")
        assert "IBAN_CHANGED_VS_HISTORY" in r2.fraud_flags
        _, gate = evaluate_invoice_verdict(r2, r2.raw_text)
        assert gate["label"] in {"SUSPECT", "DANGEROUS"}

    @pytest.mark.asyncio
    async def test_acelasi_iban_fara_flag(self, _no_anaf):
        await scan_invoice(f"Furnizor SC X SRL CUI RO12345678\nIBAN {self.IBAN_A}\nTotal 100 luna mai")
        r2 = await scan_invoice(f"Furnizor SC X SRL CUI RO12345678\nIBAN {self.IBAN_A}\nTotal 300 luna iulie")
        assert "IBAN_CHANGED_VS_HISTORY" not in r2.fraud_flags

    @pytest.mark.asyncio
    async def test_anti_poisoning_iban_strain_nu_se_memoreaza(self, _no_anaf):
        from services import vendor_memory as vm
        # factură cu IBAN străin (semnal de fraudă) → NU se memorează
        await scan_invoice("Furnizor SC X SRL CUI RO12345678\nIBAN DE89370400440532013000\nTotal 100 mai")
        assert vm.known_ibans_for_cui("RO12345678") == set()
