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
