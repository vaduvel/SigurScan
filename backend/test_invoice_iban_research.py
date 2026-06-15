import pytest
from unittest.mock import AsyncMock, patch

from services.invoice_parser import parse_invoice
from services.invoice_orchestrator import (
    _beneficiary_is_person,
    _beneficiary_mismatch,
    _foreign_ibans,
    scan_invoice,
)


@pytest.fixture(autouse=True)
def _clean_invoice_state(monkeypatch):
    monkeypatch.setenv("INVOICE_CACHE_HMAC_KEY", "testkey")
    from services import invoice_orchestrator as io

    io._verdict_cache.clear()
    io._cui_cache.clear()
    try:
        from services import negative_iban_registry as nir

        nir.reload_registry()
    except Exception:
        pass
    try:
        from services import vendor_memory as vm

        vm._memory.clear()
    except Exception:
        pass
    yield
    io._verdict_cache.clear()


class TestInvoiceIbanParser:
    def test_collects_ro_and_foreign_ibans_without_changing_primary_ro_iban(self):
        fields = parse_invoice(
            "Furnizor: SC REAL SRL\n"
            "Cont vechi RO83BTRLRONCRT0299335701\n"
            "Cont nou DE89370400440532013000\n"
            "Total 100 RON"
        )

        assert fields.iban == "RO83BTRLRONCRT0299335701"
        assert fields.all_ibans == [
            "RO83BTRLRONCRT0299335701",
            "DE89370400440532013000",
        ]

    def test_extracts_payment_beneficiary_name(self):
        fields = parse_invoice(
            "Emitent: SC REAL SRL\n"
            "Beneficiar: Popescu Ion Marian\n"
            "IBAN RO83BTRLRONCRT0299335701"
        )

        assert fields.payment_beneficiary == "Popescu Ion Marian"

    def test_collects_spaced_iban_from_ocr(self):
        fields = parse_invoice(
            "Furnizor: SC REAL SRL\n"
            "IBAN RO49 AAAA 1B31 0075 9384 0000\n"
            "Total 100 RON"
        )

        assert fields.iban == "RO49AAAA1B31007593840000"
        assert fields.all_ibans == ["RO49AAAA1B31007593840000"]

    def test_trims_overcaptured_word_after_iban(self):
        fields = parse_invoice(
            "RETIM Ecologic Service S.A. CUI 9112229. "
            "Cont contractual RO54BRDE360SV07195093600 pentru servicii de salubritate."
        )

        assert fields.iban == "RO54BRDE360SV07195093600"
        assert fields.all_ibans == ["RO54BRDE360SV07195093600"]


class TestInvoiceIbanDetectors:
    def test_foreign_ibans_only_returns_valid_non_ro_accounts(self):
        assert _foreign_ibans(["RO83BTRLRONCRT0299335701"]) == []
        assert _foreign_ibans(["DE89370400440532013000", "NOTANIBAN"]) == [
            "DE89370400440532013000"
        ]

    def test_person_beneficiary_mismatch_allows_pfa_overlap(self):
        assert _beneficiary_is_person("Popescu Ion") is True
        assert _beneficiary_is_person("SC REAL SRL") is False
        assert _beneficiary_mismatch("Popescu Ion", "SC REAL SRL") is True
        assert _beneficiary_mismatch("Popescu Ion", "Popescu Ion PFA") is False


class TestNegativeIbanRegistry:
    @pytest.fixture
    def registry_file(self, tmp_path, monkeypatch):
        path = tmp_path / "negative_iban_registry_v1.json"
        monkeypatch.setenv("NEGATIVE_IBAN_REGISTRY_PATH", str(path))
        return path

    def test_verified_registry_entry_is_detected(self, registry_file):
        registry_file.write_text(
            """
            {
              "reported_ibans": [
                {
                  "iban": "RO49AAAA1B31007593840000",
                  "status": "verified",
                  "confidence": "high",
                  "source_kind": "dnsc_alert",
                  "source_url": "https://example.invalid/report"
                }
              ],
              "quarantine_review": [
                {"iban": "SK0711110000001329100001", "status": "unverified"}
              ]
            }
            """,
            encoding="utf-8",
        )
        from services import negative_iban_registry as nir

        nir.reload_registry()

        assert nir.is_reported_fraud("RO49 AAAA 1B31 0075 9384 0000") is True
        assert nir.is_reported_fraud("SK0711110000001329100001") is False

    def test_runtime_reports_require_valid_iban(self):
        from services import negative_iban_registry as nir

        assert nir.report_fraud_iban("NU-E-IBAN", source="community_report") is False
        assert nir.report_fraud_iban("RO49 AAAA 1B31 0075 9384 0000", source="community_report") is True
        assert nir.is_reported_fraud("RO49AAAA1B31007593840000") is True

    def test_default_seed_includes_only_structurally_valid_official_ip_office_fraud_ibans(self):
        from services import negative_iban_registry as nir

        nir.reload_registry()

        assert nir.is_reported_fraud("SK07 1111 0000 0013 2910 0001") is True
        assert nir.is_reported_fraud("ES91 2100 2020 4601 4443 9386") is False


class TestInvoiceFraudSignals:
    @pytest.mark.asyncio
    async def test_person_beneficiary_on_company_invoice_is_flagged(self):
        result = await scan_invoice(
            "Furnizor: SC REAL SRL CUI RO12345678\n"
            "Beneficiar: Popescu Ion Marian\n"
            "IBAN RO49AAAA1B31007593840000\n"
            "Total 8500 RON"
        )

        assert "BENEFICIARY_PERSON_MISMATCH" in result.fraud_flags
        assert any("persoan" in warning.lower() for warning in result.warnings)

    @pytest.mark.asyncio
    async def test_account_change_plus_foreign_iban_is_dangerous(self):
        from services.invoice_orchestrator import evaluate_invoice_verdict

        result = await scan_invoice(
            "Furnizor: SC REAL SRL\n"
            "Am schimbat contul bancar. Noul IBAN este DE89370400440532013000.\n"
            "Platiti azi pentru a evita suspendarea.\n"
            "Total 5000 RON"
        )
        verdict = evaluate_invoice_verdict(result, result.raw_text)

        assert {"ACCOUNT_CHANGE_LANGUAGE", "FOREIGN_IBAN"} <= set(result.fraud_flags)
        assert verdict["gate"]["label"] == "DANGEROUS"

    @pytest.mark.asyncio
    async def test_clean_card_payment_phrase_is_not_sensitive_data_request(self):
        result = await scan_invoice(
            "Factura fiscala SC REAL SRL CUI RO12345678\n"
            "IBAN RO49AAAA1B31007593840000\n"
            "Total 119 RON. Plata cu cardul pe portal sau virament bancar."
        )

        assert "SENSITIVE_DATA_REQUESTED" not in result.fraud_flags

    @pytest.mark.asyncio
    async def test_invoice_bank_name_does_not_trigger_bank_never_asks(self, monkeypatch):
        from services.invoice_orchestrator import evaluate_invoice_verdict

        async def fake_cui(_cui):
            return type(
                "CuiResult",
                (),
                {
                    "exists": True,
                    "checked": True,
                    "denumire": "MARKETING GROWTH HUB S.R.L.",
                    "activ": True,
                    "platitor_tva": False,
                },
            )()

        monkeypatch.setattr("services.invoice_orchestrator.check_cui", fake_cui)
        result = await scan_invoice(
            "Furnizor:\n"
            "MARKETING GROWTH HUB S.R.L.\n"
            "CIF:\n"
            "45758405\n"
            "IBAN (RON):\n"
            "R042INGB0000999912242622\n"
            "Banca:\n"
            "ING BANK NV\n"
            "Total plata 200.00 RON\n"
            "Date privind expeditia:\n"
            "CNP: -"
        )
        verdict = evaluate_invoice_verdict(result, result.raw_text, source_channel="android_native")

        assert result.fields.cui == "45758405"
        assert result.fields.iban == "RO42INGB0000999912242622"
        assert verdict["bundle"]["identity"]["violated_never_asks"] == []
        assert verdict["gate"]["label"] != "DANGEROUS"

    @pytest.mark.asyncio
    async def test_card_cvv_otp_request_on_invoice_is_dangerous(self):
        from services.invoice_orchestrator import evaluate_invoice_verdict

        result = await scan_invoice(
            "Factura restanta Digi. Pentru a evita deconectarea, confirma datele "
            "cardului, codul CVV si OTP. Total 89 lei"
        )
        verdict = evaluate_invoice_verdict(result, result.raw_text)

        assert "SENSITIVE_DATA_REQUESTED" in result.fraud_flags
        assert verdict["gate"]["label"] == "DANGEROUS"


class TestVendorIbanMemory:
    IBAN_A = "RO49AAAA1B31007593840000"
    IBAN_B = "RO83BTRLRONCRT0299335701"

    @pytest.fixture
    def anaf_ok(self):
        from services.anaf_cui import CuiResult

        cui = CuiResult(
            exists=True,
            checked=True,
            denumire="SC X SRL",
            activ=True,
            data_inactivare=None,
            platitor_tva=True,
            enrolled_efactura=False,
            raw=None,
        )
        with patch("services.invoice_orchestrator.check_cui", new_callable=AsyncMock) as mock_cui:
            mock_cui.return_value = cui
            yield

    @pytest.mark.asyncio
    async def test_clean_invoice_remembers_vendor_iban(self, anaf_ok):
        from services import vendor_memory as vm

        result = await scan_invoice(
            f"Furnizor: SC X SRL CUI RO12345678\nIBAN {self.IBAN_A}\nTotal 100 RON"
        )

        assert result.fraud_flags == []
        assert vm.known_ibans_for_cui("RO12345678") == {self.IBAN_A}

    @pytest.mark.asyncio
    async def test_changed_vendor_iban_is_flagged_but_not_memorized(self, anaf_ok):
        from services import vendor_memory as vm

        vm.remember_invoice_iban("RO12345678", self.IBAN_A)
        result = await scan_invoice(
            f"Furnizor: SC X SRL CUI RO12345678\nIBAN {self.IBAN_B}\nTotal 200 RON luna iunie"
        )

        assert "IBAN_CHANGED_VS_HISTORY" in result.fraud_flags
        assert vm.known_ibans_for_cui("RO12345678") == {self.IBAN_A}


class TestInvoiceChannelProvenance:
    def test_untrusted_channel_blocks_safe_without_creating_dangerous(self):
        from types import SimpleNamespace
        from services.invoice_orchestrator import evaluate_invoice_verdict

        result = SimpleNamespace(
            brand_match=SimpleNamespace(
                cui_matches=True,
                iban_matches=True,
                impersonation_risk=False,
                domain_matches=True,
            ),
            brand="orange",
            fraud_flags=[],
            fields=None,
            readiness=SimpleNamespace(blocks_safe_verdict=False),
            coherence=SimpleNamespace(all_ok=True, totals_match=True, dates_plausible=True),
            anaf_cui_check={"checked": True, "exists": True, "activ": True},
            iban_valid=SimpleNamespace(valid_structure=True),
        )

        official = evaluate_invoice_verdict(result, "", source_channel="android_native")
        whatsapp = evaluate_invoice_verdict(result, "", source_channel="whatsapp")

        assert official["gate"]["label"] == "SUSPECT"
        assert official["gate"]["reason_codes"] == ["value_request_needs_verification"]
        assert whatsapp["gate"]["label"] != "SAFE"
        assert whatsapp["gate"]["label"] != "DANGEROUS"

    @pytest.mark.asyncio
    async def test_active_company_with_unconfirmed_payment_iban_is_safe_with_bank_check_guidance(self):
        from services.anaf_cui import CuiResult
        from services.invoice_orchestrator import evaluate_invoice_verdict

        async def fake_check_cui(cui: str):
            return CuiResult(
                exists=True,
                checked=True,
                denumire="ATELIER DIGITAL SIBIU SRL",
                activ=True,
                data_inactivare=None,
                platitor_tva=True,
                enrolled_efactura=False,
                raw=None,
            )

        text = (
            "Furnizor: Atelier Digital Sibiu SRL\n"
            "CUI: 12345678\n"
            "IBAN: RO33RNCB1234567890123456\n"
            "Total: 100 RON\n"
            "Data: 01.06.2026\n"
            "Scadenta: 15.06.2026"
        )
        with patch("services.invoice_orchestrator.check_cui", new_callable=AsyncMock) as mock_cui:
            mock_cui.side_effect = fake_check_cui
            result = await scan_invoice(text)

        verdict = evaluate_invoice_verdict(result, result.raw_text, source_channel="android_native")

        assert verdict["bundle"]["identity"]["status"] == "coherent"
        assert result.beneficiary_name_check is not None
        assert result.beneficiary_name_check["recommended"] is True
        assert verdict["gate"]["label"] == "SAFE"
        assert verdict["gate"]["reason_codes"] == ["positive_provenance_clean"]
